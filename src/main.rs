use std::str::FromStr;
use jarm::Scanner;
use argh::FromArgs;

#[derive(Debug, Clone, FromArgs, Default)]
#[argh(description = "TLS Fingerprinting tool")]
pub struct ConfigArgs {
    /// specify an IP or domain to scan
    #[argh(option, short = 't')]
    pub target: String,
}

impl ConfigArgs {
    pub fn new() -> Self {
        let default: ConfigArgs = argh::from_env();
        default
    }
}

fn main() {
    let c = ConfigArgs::new();
    let host_port: Vec<&str> = c.target.splitn(2, ":").collect();
    if host_port.len() == 2 {
        let port = u16::from_str(&host_port[1]).unwrap_or(443);
        match Scanner::new(host_port[0].to_string(), port) {
            Ok(s) => {
                println!("{}", s.fingerprint());
            }
            Err(e) => {
                println!("{:?}", e);
            }
        }
    } else {
        match Scanner::new(c.target.to_string(), 443) {
            Ok(s) => {
                println!("{}", s.fingerprint());
            }
            Err(e) => {
                println!("{:?}", e);
            }
        }
    }
}