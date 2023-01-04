# jarm_rs

- [jarm](https://github.com/salesforce/jarm)  implemented by rust

> JARM is an active Transport Layer Security (TLS) server fingerprinting tool.

## using

```shell
➜ ~ ./jarm_rs -t blog.kali-team.cn
27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c
➜ ~ ./jarm_rs -t blog.kali-team.cn:443
27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c

```

## rust

- put in Cargo.toml:

```toml
jarm = { git = "https://github.com/emo-cat/jarm_rs" }
```

- using

```rust
use jarm::Scanner;

fn main() {
    let s = Scanner::new("www.salesforce.com".to_string(), 443).unwrap();
    println!("{}", s.fingerprint());
}
```

- output

```bash
2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5
```