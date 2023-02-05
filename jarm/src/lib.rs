use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::io;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use crate::Scanner;

    #[test]
    fn it_works() {
        let s = Scanner::new("www.salesforce.com".to_string(), 443).unwrap();
        assert_eq!(s.fingerprint(), "2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5");
    }
}

const APLN_EXTENSION: &[u8; 2] = b"\x00\x10";

// #Randomly choose a grease value
fn choose_grease() -> Vec<u8> {
    let mut rt = thread_rng();
    let h: u8 = rt.gen_range(0..15);
    let grease = vec![h * 16 + 10, h * 16 + 10];
    grease
}

fn random_bytes() -> Vec<u8> {
    let mut rng = thread_rng();
    rng.gen::<[u8; 32]>().to_vec()
}

const QUEUE: [Packets; 10] = [
    // tls1_2_forward = ["TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"]
    Packets {
        version: Version::TLS_1_2,
        cipher_list: CipherList::All,
        cipher_order: CipherOrder::Forward,
        grease: false,
        rare_apln: false,
        support: Support::TLS_1_2,
        extension_orders: ExtensionOrders::Reverse,
    },
    // tls1_2_reverse = ["TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"]
    Packets {
        version: Version::TLS_1_2,
        cipher_list: CipherList::All,
        cipher_order: CipherOrder::Reverse,
        grease: false,
        rare_apln: false,
        support: Support::TLS_1_2,
        extension_orders: ExtensionOrders::Forward,
    },
    // tls1_2_top_half = ["TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
    Packets {
        version: Version::TLS_1_2,
        cipher_list: CipherList::All,
        cipher_order: CipherOrder::Top_Half,
        grease: false,
        rare_apln: false,
        support: Support::NO_SUPPORT,
        extension_orders: ExtensionOrders::Forward,
    },
    // tls1_2_bottom_half = ["TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"]
    Packets {
        version: Version::TLS_1_2,
        cipher_list: CipherList::All,
        cipher_order: CipherOrder::Bottom_Half,
        grease: false,
        rare_apln: true,
        support: Support::NO_SUPPORT,
        extension_orders: ExtensionOrders::Forward,
    },
    // tls1_2_middle_out = ["TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"]
    Packets {
        version: Version::TLS_1_2,
        cipher_list: CipherList::All,
        cipher_order: CipherOrder::Middle_Out,
        grease: true,
        rare_apln: true,
        support: Support::NO_SUPPORT,
        extension_orders: ExtensionOrders::Reverse,
    },
    // tls1_1_middle_out = ["TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
    Packets {
        version: Version::TLS_1_1,
        cipher_list: CipherList::All,
        cipher_order: CipherOrder::Forward,
        grease: false,
        rare_apln: false,
        support: Support::NO_SUPPORT,
        extension_orders: ExtensionOrders::Forward,
    },
    // tls1_3_forward = ["TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
    Packets {
        version: Version::TLS_1_3,
        cipher_list: CipherList::All,
        cipher_order: CipherOrder::Forward,
        grease: false,
        rare_apln: false,
        support: Support::TLS_1_3,
        extension_orders: ExtensionOrders::Reverse,
    },
    // tls1_3_reverse = ["TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
    Packets {
        version: Version::TLS_1_3,
        cipher_list: CipherList::All,
        cipher_order: CipherOrder::Reverse,
        grease: false,
        rare_apln: false,
        support: Support::TLS_1_3,
        extension_orders: ExtensionOrders::Forward,
    },
    // tls1_3_invalid = ["TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
    Packets {
        version: Version::TLS_1_3,
        cipher_list: CipherList::NO1_3,
        cipher_order: CipherOrder::Forward,
        grease: false,
        rare_apln: false,
        support: Support::TLS_1_3,
        extension_orders: ExtensionOrders::Forward,
    },
    // tls1_3_middle_out = ["TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
    Packets {
        version: Version::TLS_1_3,
        cipher_list: CipherList::All,
        cipher_order: CipherOrder::Middle_Out,
        grease: true,
        rare_apln: false,
        support: Support::TLS_1_3,
        extension_orders: ExtensionOrders::Reverse,
    },
];

// #Possible versions: SSLv3, TLS_1, TLS_1.1, TLS_1.2, TLS_1.3
#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
enum Version {
    _SSL_V3,
    _TLS_1,
    TLS_1_1,
    TLS_1_2,
    TLS_1_3,
}

impl Version {
    // #Version Check
    fn hello_payload(&self) -> (Vec<u8>, Vec<u8>) {
        let mut client_hello: Vec<u8> = Vec::new();
        let mut payload = b"\x16".to_vec();
        match self {
            Version::_SSL_V3 => {
                payload.extend(b"\x03\x00");
                client_hello.extend(b"\x03\x00");
            }
            Version::_TLS_1 => {
                payload.extend(b"\x03\x01");
                client_hello.extend(b"\x03\x01");
            }
            Version::TLS_1_1 => {
                payload.extend(b"\x03\x02");
                client_hello.extend(b"\x03\x02");
            }
            Version::TLS_1_2 => {
                payload.extend(b"\x03\x03");
                client_hello.extend(b"\x03\x03");
            }
            Version::TLS_1_3 => {
                payload.extend(b"\x03\x01");
                client_hello.extend(b"\x03\x03");
            }
        }
        (client_hello, payload)
    }
}

// #Possible cipher lists: ALL, NO1.3
#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
enum CipherList {
    All,
    NO1_3,
}

impl CipherList {
    fn lists(&self) -> Vec<Vec<u8>> {
        match self {
            CipherList::All => {
                vec![
                    b"\x00\x16".to_vec(),
                    b"\x00\x33".to_vec(),
                    b"\x00\x67".to_vec(),
                    b"\xc0\x9e".to_vec(),
                    b"\xc0\xa2".to_vec(),
                    b"\x00\x9e".to_vec(),
                    b"\x00\x39".to_vec(),
                    b"\x00\x6b".to_vec(),
                    b"\xc0\x9f".to_vec(),
                    b"\xc0\xa3".to_vec(),
                    b"\x00\x9f".to_vec(),
                    b"\x00\x45".to_vec(),
                    b"\x00\xbe".to_vec(),
                    b"\x00\x88".to_vec(),
                    b"\x00\xc4".to_vec(),
                    b"\x00\x9a".to_vec(),
                    b"\xc0\x08".to_vec(),
                    b"\xc0\x09".to_vec(),
                    b"\xc0\x23".to_vec(),
                    b"\xc0\xac".to_vec(),
                    b"\xc0\xae".to_vec(),
                    b"\xc0\x2b".to_vec(),
                    b"\xc0\x0a".to_vec(),
                    b"\xc0\x24".to_vec(),
                    b"\xc0\xad".to_vec(),
                    b"\xc0\xaf".to_vec(),
                    b"\xc0\x2c".to_vec(),
                    b"\xc0\x72".to_vec(),
                    b"\xc0\x73".to_vec(),
                    b"\xcc\xa9".to_vec(),
                    b"\x13\x02".to_vec(),
                    b"\x13\x01".to_vec(),
                    b"\xcc\x14".to_vec(),
                    b"\xc0\x07".to_vec(),
                    b"\xc0\x12".to_vec(),
                    b"\xc0\x13".to_vec(),
                    b"\xc0\x27".to_vec(),
                    b"\xc0\x2f".to_vec(),
                    b"\xc0\x14".to_vec(),
                    b"\xc0\x28".to_vec(),
                    b"\xc0\x30".to_vec(),
                    b"\xc0\x60".to_vec(),
                    b"\xc0\x61".to_vec(),
                    b"\xc0\x76".to_vec(),
                    b"\xc0\x77".to_vec(),
                    b"\xcc\xa8".to_vec(),
                    b"\x13\x05".to_vec(),
                    b"\x13\x04".to_vec(),
                    b"\x13\x03".to_vec(),
                    b"\xcc\x13".to_vec(),
                    b"\xc0\x11".to_vec(),
                    b"\x00\x0a".to_vec(),
                    b"\x00\x2f".to_vec(),
                    b"\x00\x3c".to_vec(),
                    b"\xc0\x9c".to_vec(),
                    b"\xc0\xa0".to_vec(),
                    b"\x00\x9c".to_vec(),
                    b"\x00\x35".to_vec(),
                    b"\x00\x3d".to_vec(),
                    b"\xc0\x9d".to_vec(),
                    b"\xc0\xa1".to_vec(),
                    b"\x00\x9d".to_vec(),
                    b"\x00\x41".to_vec(),
                    b"\x00\xba".to_vec(),
                    b"\x00\x84".to_vec(),
                    b"\x00\xc0".to_vec(),
                    b"\x00\x07".to_vec(),
                    b"\x00\x04".to_vec(),
                    b"\x00\x05".to_vec(),
                ]
            }
            CipherList::NO1_3 => {
                vec![
                    b"\x00\x16".to_vec(),
                    b"\x00\x33".to_vec(),
                    b"\x00\x67".to_vec(),
                    b"\xc0\x9e".to_vec(),
                    b"\xc0\xa2".to_vec(),
                    b"\x00\x9e".to_vec(),
                    b"\x00\x39".to_vec(),
                    b"\x00\x6b".to_vec(),
                    b"\xc0\x9f".to_vec(),
                    b"\xc0\xa3".to_vec(),
                    b"\x00\x9f".to_vec(),
                    b"\x00\x45".to_vec(),
                    b"\x00\xbe".to_vec(),
                    b"\x00\x88".to_vec(),
                    b"\x00\xc4".to_vec(),
                    b"\x00\x9a".to_vec(),
                    b"\xc0\x08".to_vec(),
                    b"\xc0\x09".to_vec(),
                    b"\xc0\x23".to_vec(),
                    b"\xc0\xac".to_vec(),
                    b"\xc0\xae".to_vec(),
                    b"\xc0\x2b".to_vec(),
                    b"\xc0\x0a".to_vec(),
                    b"\xc0\x24".to_vec(),
                    b"\xc0\xad".to_vec(),
                    b"\xc0\xaf".to_vec(),
                    b"\xc0\x2c".to_vec(),
                    b"\xc0\x72".to_vec(),
                    b"\xc0\x73".to_vec(),
                    b"\xcc\xa9".to_vec(),
                    b"\xcc\x14".to_vec(),
                    b"\xc0\x07".to_vec(),
                    b"\xc0\x12".to_vec(),
                    b"\xc0\x13".to_vec(),
                    b"\xc0\x27".to_vec(),
                    b"\xc0\x2f".to_vec(),
                    b"\xc0\x14".to_vec(),
                    b"\xc0\x28".to_vec(),
                    b"\xc0\x30".to_vec(),
                    b"\xc0\x60".to_vec(),
                    b"\xc0\x61".to_vec(),
                    b"\xc0\x76".to_vec(),
                    b"\xc0\x77".to_vec(),
                    b"\xcc\xa8".to_vec(),
                    b"\xcc\x13".to_vec(),
                    b"\xc0\x11".to_vec(),
                    b"\x00\x0a".to_vec(),
                    b"\x00\x2f".to_vec(),
                    b"\x00\x3c".to_vec(),
                    b"\xc0\x9c".to_vec(),
                    b"\xc0\xa0".to_vec(),
                    b"\x00\x9c".to_vec(),
                    b"\x00\x35".to_vec(),
                    b"\x00\x3d".to_vec(),
                    b"\xc0\x9d".to_vec(),
                    b"\xc0\xa1".to_vec(),
                    b"\x00\x9d".to_vec(),
                    b"\x00\x41".to_vec(),
                    b"\x00\xba".to_vec(),
                    b"\x00\x84".to_vec(),
                    b"\x00\xc0".to_vec(),
                    b"\x00\x07".to_vec(),
                    b"\x00\x04".to_vec(),
                    b"\x00\x05".to_vec(),
                ]
            }
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
enum CipherOrder {
    Forward,
    Reverse,
    Top_Half,
    Bottom_Half,
    Middle_Out,
}

impl CipherOrder {
    #[allow(clippy::ptr_arg)]
    fn cipher_mung(&self, ciphers: &mut Vec<Vec<u8>>) {
        match self {
            CipherOrder::Forward => {} // nothing to do
            CipherOrder::Reverse => ciphers.reverse(),
            CipherOrder::Top_Half => {
                // Top half gets the middle cipher if needed
                let middle_one = if ciphers.len() % 2 == 1 {
                    Some(ciphers[ciphers.len() / 2].clone())
                } else {
                    None
                };
                ciphers.reverse();
                let mut range_to_drain = 0..ciphers.len() / 2;
                if ciphers.len() % 2 == 1 {
                    // Also remove the middle one if the length is odd
                    range_to_drain.end += 1;
                }
                ciphers.drain(range_to_drain);
                if let Some(x) = middle_one {
                    ciphers.insert(0, x);
                }
            }
            CipherOrder::Bottom_Half => {
                let mut range_to_drain = 0..ciphers.len() / 2;
                if ciphers.len() % 2 == 1 {
                    // Also remove the middle one if the length is odd
                    range_to_drain.end += 1;
                }
                ciphers.drain(range_to_drain);
            }
            CipherOrder::Middle_Out => {
                let middle = ciphers.len() / 2;
                let mut output = Vec::new();
                if ciphers.len() % 2 == 1 {
                    // output.append(ciphers[middle])
                    output.push(ciphers[middle].clone());

                    for i in 1..middle + 1 {
                        output.push(ciphers[middle + i].clone());
                        output.push(ciphers[middle - i].clone());
                    }
                } else {
                    for i in 1..middle + 1 {
                        output.push(ciphers[middle - 1 + i].clone());
                        output.push(ciphers[middle - i].clone());
                    }
                }
                *ciphers = output;
            }
        }
    }
}

// #Supported Versions extension: 1.2_SUPPORT, NO_SUPPORT, or 1.3_SUPPORT
#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
enum Support {
    TLS_1_2,
    TLS_1_3,
    NO_SUPPORT,
}

impl Support {
    fn lists(&self) -> Vec<Vec<u8>> {
        match self {
            Support::TLS_1_2 => {
                vec![
                    b"\x03\x01".to_vec(),
                    b"\x03\x02".to_vec(),
                    b"\x03\x03".to_vec(),
                ]
            }
            _ => {
                vec![
                    b"\x03\x01".to_vec(),
                    b"\x03\x02".to_vec(),
                    b"\x03\x03".to_vec(),
                    b"\x03\x04".to_vec(),
                ]
            }
        }
    }
}

// #Possible Extension order: FORWARD, REVERSE
#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
enum ExtensionOrders {
    Forward,
    Reverse,
}

impl ExtensionOrders {
    #[allow(clippy::ptr_arg)]
    fn cipher_mung(&self, ciphers: &mut Vec<Vec<u8>>) {
        match self {
            ExtensionOrders::Forward => {} // nothing to do
            ExtensionOrders::Reverse => {
                ciphers.reverse();
            }
        }
    }
}

// #Array format = [version,cipher_list,cipher_order,GREASE,RARE_APLN,1.3_SUPPORT,extension_orders]
struct Packets {
    version: Version,
    cipher_list: CipherList,
    cipher_order: CipherOrder,
    // #GREASE: either NO_GREASE or GREASE
    grease: bool,
    // #APLN: either APLN or RARE_APLN
    rare_apln: bool,
    support: Support,
    extension_orders: ExtensionOrders,
}

fn pack_as_unsigned_char(n: usize) -> u8 {
    if n >= 256 {
        panic!("Can't pack_as_unsigned_char {:?} as it is over 255", n)
    }
    n as u8
}

fn pack_as_unsigned_short(n: usize) -> Vec<u8> {
    vec![(n >> 8) as u8, n as u8]
}

// Convert bytes array to u32
fn to_u32_be(array: &[u8]) -> u32 {
    if array.len() != 2 {
        unimplemented!() // not needed for now
    }
    ((array[0] as u32) << 8) + (array[1] as u32)
}

impl Packets {
    fn build_packet(&self, host: &str) -> Vec<u8> {
        let (mut client_hello, mut payload) = self.version.hello_payload();

        client_hello.extend(random_bytes());

        let session_id = random_bytes();
        let session_id_length = pack_as_unsigned_char(session_id.len());
        client_hello.push(session_id_length);
        client_hello.extend(session_id);

        let cipher_choice = self.get_ciphers();

        let client_suites_length = pack_as_unsigned_short(cipher_choice.len());
        client_hello.extend(client_suites_length);
        client_hello.extend(cipher_choice);
        client_hello.push(b'\x01'); // cipher methods
        client_hello.push(b'\x00'); // compression_methods

        client_hello.extend(self.get_extensions(host));

        // Finish packet assembly
        let mut inner_length = b"\x00".to_vec();
        inner_length.extend(pack_as_unsigned_short(client_hello.len()));
        let mut handshake_protocol = b"\x01".to_vec();
        handshake_protocol.extend(inner_length);
        handshake_protocol.extend(client_hello);
        let outer_length = pack_as_unsigned_short(handshake_protocol.len());
        payload.extend(outer_length);
        payload.extend(handshake_protocol);
        payload
    }
    fn get_ciphers(&self) -> Vec<u8> {
        let mut selected_ciphers = Vec::new();
        let mut lists = self.cipher_list.lists();
        self.cipher_order.cipher_mung(&mut lists);
        if self.grease {
            lists.insert(0, choose_grease());
        }
        for x in lists {
            selected_ciphers.extend(x);
        }
        selected_ciphers
    }
    fn get_extensions(&self, host: &str) -> Vec<u8> {
        let mut extension_bytes = Vec::new();
        let mut all_extensions = Vec::new();
        if self.grease {
            all_extensions.extend(choose_grease());
            all_extensions.extend(b"\x00\x00");
        }

        all_extensions.extend(self.extension_server_name(host));

        // Other extensions
        let extended_master_secret = b"\x00\x17\x00\x00";
        all_extensions.extend(extended_master_secret);
        let max_fragment_length = b"\x00\x01\x00\x01\x01";
        all_extensions.extend(max_fragment_length);
        let renegotiation_info = b"\xff\x01\x00\x01\x00";
        all_extensions.extend(renegotiation_info);
        let supported_groups = b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19";
        all_extensions.extend(supported_groups);
        let ec_point_formats = b"\x00\x0b\x00\x02\x01\x00";
        all_extensions.extend(ec_point_formats);
        let session_ticket = b"\x00\x23\x00\x00";
        all_extensions.extend(session_ticket);

        // Application Layer Protocol Negotiation extension
        all_extensions.extend(self.apln());
        let signature_algorithms = b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01";
        all_extensions.extend(signature_algorithms);

        // Key share extension
        all_extensions.extend(self.key_share());
        let psk_key_exchange_modes = b"\x00\x2d\x00\x02\x01\x01";
        all_extensions.extend(psk_key_exchange_modes);

        if self.version == Version::TLS_1_3 || self.support == Support::TLS_1_2 {
            all_extensions.extend(self.supported_versions());
        }

        extension_bytes.extend(pack_as_unsigned_short(all_extensions.len()));
        extension_bytes.extend(all_extensions);
        extension_bytes
    }
    fn extension_server_name(&self, host: &str) -> Vec<u8> {
        let mut ext_sni = b"\x00\x00".to_vec();
        let host_length = host.len();
        let ext_sni_length = host_length + 5;
        ext_sni.extend(pack_as_unsigned_short(ext_sni_length));

        let ext_sni_length2 = host_length + 3;
        ext_sni.extend(pack_as_unsigned_short(ext_sni_length2));
        ext_sni.push(b'\x00');

        let ext_sni_length3 = host_length;
        ext_sni.extend(pack_as_unsigned_short(ext_sni_length3));

        ext_sni.extend(host.to_string().bytes());
        ext_sni
    }
    fn supported_versions(&self) -> Vec<u8> {
        let mut tls = self.support.lists();
        self.extension_orders.cipher_mung(&mut tls);
        // Assemble the extension
        let mut ext = b"\x00\x2b".to_vec();
        let mut versions = if self.grease {
            choose_grease()
        } else {
            Vec::new()
        };

        for version in tls {
            versions.extend(version);
        }
        let second_length = versions.len();
        let first_length = second_length + 1;
        ext.extend(pack_as_unsigned_short(first_length));
        ext.push(pack_as_unsigned_char(second_length));
        ext.extend(versions);
        ext
    }
    fn apln(&self) -> Vec<u8> {
        let mut ext = b"\x00\x10".to_vec();
        let mut apln: Vec<Vec<u8>> = if self.rare_apln {
            vec![
                b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39".to_vec(),
                b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30".to_vec(),
                b"\x06\x73\x70\x64\x79\x2f\x31".to_vec(),
                b"\x06\x73\x70\x64\x79\x2f\x32".to_vec(),
                b"\x06\x73\x70\x64\x79\x2f\x33".to_vec(),
                b"\x03\x68\x32\x63".to_vec(),
                b"\x02\x68\x71".to_vec(),
            ]
        } else {
            vec![
                b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39".to_vec(),
                b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30".to_vec(),
                b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x31".to_vec(),
                b"\x06\x73\x70\x64\x79\x2f\x31".to_vec(),
                b"\x06\x73\x70\x64\x79\x2f\x32".to_vec(),
                b"\x06\x73\x70\x64\x79\x2f\x33\x02\x68\x32".to_vec(),
                b"\x03\x68\x32\x63".to_vec(),
                b"\x02\x68\x71".to_vec(),
            ]
        };
        self.extension_orders.cipher_mung(&mut apln);
        // flatten the apln
        let mut all_apln = Vec::new();
        for x in apln {
            all_apln.extend(x);
        }

        let second_length = all_apln.len();
        let first_length = second_length + 2;
        ext.extend(pack_as_unsigned_short(first_length));
        ext.extend(pack_as_unsigned_short(second_length));
        ext.extend(all_apln);
        ext
    }
    fn key_share(&self) -> Vec<u8> {
        let mut ext = b"\x00\x33".to_vec();
        let mut share_ext = if self.grease {
            let mut grease_start = choose_grease();
            grease_start.extend(b"\x00\x01\x00");
            grease_start
        } else {
            Vec::new()
        };
        share_ext.extend(b"\x00\x1d"); // group
        share_ext.extend(b"\x00\x20"); // key_exchange_length
        share_ext.extend(random_bytes()); // key_exchange_length

        let second_length = share_ext.len();
        let first_length = second_length + 2;
        ext.extend(pack_as_unsigned_short(first_length));
        ext.extend(pack_as_unsigned_short(second_length));
        ext.extend(share_ext);
        ext
    }
}

#[derive(Default)]
struct Part {
    cipher: Option<String>,
    version: Option<String>,
    extensions: Extensions,
}

impl Part {
    fn get_cipher(&self) -> String {
        Part::cipher_bytes(&self.cipher.clone().unwrap_or_default())
    }
    fn get_version(&self) -> char {
        Part::version_byte(&self.version.clone().unwrap_or_default())
    }
    fn get_extensions_version(&self) -> String {
        self.extensions.get_version()
    }
    fn get_extensions_fingerprint(&self) -> String {
        self.extensions.get_fingerprint()
    }
    fn cipher_bytes(cipher: &str) -> String {
        if cipher.is_empty() {
            return "00".to_string();
        }

        let list = vec![
            b"\x00\x04",
            b"\x00\x05",
            b"\x00\x07",
            b"\x00\x0a",
            b"\x00\x16",
            b"\x00\x2f",
            b"\x00\x33",
            b"\x00\x35",
            b"\x00\x39",
            b"\x00\x3c",
            b"\x00\x3d",
            b"\x00\x41",
            b"\x00\x45",
            b"\x00\x67",
            b"\x00\x6b",
            b"\x00\x84",
            b"\x00\x88",
            b"\x00\x9a",
            b"\x00\x9c",
            b"\x00\x9d",
            b"\x00\x9e",
            b"\x00\x9f",
            b"\x00\xba",
            b"\x00\xbe",
            b"\x00\xc0",
            b"\x00\xc4",
            b"\xc0\x07",
            b"\xc0\x08",
            b"\xc0\x09",
            b"\xc0\x0a",
            b"\xc0\x11",
            b"\xc0\x12",
            b"\xc0\x13",
            b"\xc0\x14",
            b"\xc0\x23",
            b"\xc0\x24",
            b"\xc0\x27",
            b"\xc0\x28",
            b"\xc0\x2b",
            b"\xc0\x2c",
            b"\xc0\x2f",
            b"\xc0\x30",
            b"\xc0\x60",
            b"\xc0\x61",
            b"\xc0\x72",
            b"\xc0\x73",
            b"\xc0\x76",
            b"\xc0\x77",
            b"\xc0\x9c",
            b"\xc0\x9d",
            b"\xc0\x9e",
            b"\xc0\x9f",
            b"\xc0\xa0",
            b"\xc0\xa1",
            b"\xc0\xa2",
            b"\xc0\xa3",
            b"\xc0\xac",
            b"\xc0\xad",
            b"\xc0\xae",
            b"\xc0\xaf",
            b"\xcc\x13",
            b"\xcc\x14",
            b"\xcc\xa8",
            b"\xcc\xa9",
            b"\x13\x01",
            b"\x13\x02",
            b"\x13\x03",
            b"\x13\x04",
            b"\x13\x05",
        ];
        let count = match list.iter().position(|&bytes| hex::encode(bytes) == cipher) {
            None => {
                return "00".to_string();
            }
            Some(index) => index + 1,
        };

        let hex_value = hex::encode(count.to_be_bytes());
        hex_value
            .get(hex_value.len() - 2..hex_value.len())
            .unwrap_or("00")
            .to_string()
    }
    fn version_byte(version: &str) -> char {
        if version.is_empty() && version.len() < 4 {
            return '0';
        }
        if let Ok(c) = usize::from_str(&version[3..4]) {
            let option = ['a', 'b', 'c', 'd', 'e', 'f'].to_vec();
            return option[c];
        }
        '0'
    }
}

#[derive(Default)]
struct Extensions {
    version: Option<String>,
    fingerprint: Option<String>,
}

impl Extensions {
    fn get_fingerprint(&self) -> String {
        self.fingerprint.clone().unwrap_or_default()
    }
    fn get_version(&self) -> String {
        self.version.clone().unwrap_or_default()
    }
}

impl Part {
    fn new(data: Vec<u8>) -> Part {
        if (data[0] != 22) || (data[5] != 2) {
            return Part::default();
        }
        let counter = data[43] as usize;

        // Find server's selected cipher
        let start = counter + 44;
        let end = counter + 45;
        let selected_cipher = &data[start..=end];

        // Find server's selected version
        let version = &data[9..=10];
        // Extract extensions
        let extensions = Part::extract_extension_info(&data, counter);
        Part {
            cipher: Some(hex::encode(selected_cipher)),
            version: Some(hex::encode(version)),
            extensions,
        }
    }
    fn extract_extension_info(data: &[u8], counter: usize) -> Extensions {
        // Error handling
        if Part::data_has_errors(data, counter) {
            return Extensions::default();
        }

        // Collect types and value
        let mut count = 49 + (counter as u32);
        let length_start = counter + 47;
        let length_end = counter + 48;

        let length_slice: &[u8] = &data[length_start..=length_end];
        let length = to_u32_be(length_slice);
        let maximum = length + (count - 1);

        let mut types: Vec<&[u8]> = Vec::new();
        let mut values: Vec<Option<&[u8]>> = Vec::new();

        while count < maximum {
            let slice_start = count as usize;
            types.push(&data[slice_start..slice_start + 2]);

            let ext_length_start = (count + 2) as usize;
            let ext_length_end = ext_length_start + 2;
            let ext_length_slice: &[u8] = &data[ext_length_start..ext_length_end];
            let ext_length = to_u32_be(ext_length_slice);

            if ext_length == 0 {
                values.push(None); // TODO FIXME
                count += 4;
            } else {
                let value = &data[slice_start + 4..slice_start + 4 + ext_length as usize];
                values.push(Some(value));
                count += ext_length + 4
            }
        }

        // Read application_layer_protocol_negotiation
        let apln = Part::find_extension(&types, values);

        let formatted_types = Part::add_formatting_hyphen(&types);
        Extensions {
            version: Some(apln),
            fingerprint: Some(formatted_types),
        }
    }
    fn add_formatting_hyphen(types: &[&[u8]]) -> String {
        let types_hex_encoded: Vec<String> = types.iter().map(hex::encode).collect();
        types_hex_encoded.join("-")
    }
    fn find_extension(types: &[&[u8]], values: Vec<Option<&[u8]>>) -> String {
        for (i, t) in types.iter().enumerate() {
            if t == APLN_EXTENSION {
                if let Some(Some(x)) = values.get(i) {
                    if x.len() < 4 {
                        return String::new();
                    }
                    return std::str::from_utf8(&x[3..]).unwrap_or_default().to_string();
                }
            }
        }
        String::new()
    }
    fn data_has_errors(data: &[u8], counter: usize) -> bool {
        let length_start = counter + 47;
        if data[length_start] == 11 {
            return true;
        }
        if data[(counter + 50)..(counter + 53)] == b"\x0e\xac\x0b".to_vec()
            || data[(counter + 82)..(counter + 85)] == b"\x0f\xf0\x0b".to_vec()
        {
            return true;
        }
        let server_hello_length_slice: &[u8] = &data[3..5];
        let server_hello_length = to_u32_be(server_hello_length_slice);
        if (counter as u32) + 42 >= server_hello_length {
            return true;
        }
        false
    }
}

pub struct Scanner {
    host: String,
    addr: SocketAddr,
    queue: [Packets; 10],
    timeout: Duration,
}

impl Scanner {
    pub fn new(host: String, port: u16) -> Result<Self, io::Error> {
        if let Ok(mut addrs) = format!("{}:{}", host, port).to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                return Ok(Scanner {
                    host,
                    addr,
                    queue: QUEUE,
                    timeout: Duration::from_secs(30),
                });
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "socket addr error",
        ))
    }
    fn send_packet(&self, payload: Vec<u8>) -> Result<Part, io::Error> {
        let mut data = [0_u8; 1484];

        match TcpStream::connect_timeout(&self.addr, self.timeout) {
            Ok(mut stream) => {
                stream.write_all(&payload)?;
                let mut handle = stream.take(1484);
                let _read_result = handle.read(&mut data)?;
            }
            Err(e) => {
                return Err(e);
            }
        }
        let part = Part::new(Vec::from(data));
        Ok(part)
    }
    fn retrieve_parts(&self) -> Vec<Part> {
        let mut parts = Vec::new();
        for spec in &self.queue {
            let payload = spec.build_packet(&self.host);
            let part = self.send_packet(payload).unwrap_or_default();
            parts.push(part);
        }
        parts
    }

    pub fn fingerprint(&self) -> String {
        let parts = self.retrieve_parts();
        let mut fuzzy_hash = String::new();
        let mut apln_and_ext = String::new();
        for part in &parts {
            fuzzy_hash.push_str(&part.get_cipher());
            fuzzy_hash.push(part.get_version());
            apln_and_ext.push_str(&part.get_extensions_version());
            apln_and_ext.push_str(&part.get_extensions_fingerprint());
        }
        let mut hasher = Sha256::new();
        hasher.update(apln_and_ext.into_bytes());
        let sha256 = hex::encode(hasher.finalize());
        fuzzy_hash.push_str(sha256.get(0..32).unwrap_or(&["0"; 32].join("")));
        fuzzy_hash
    }
}
