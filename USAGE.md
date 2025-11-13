# Using nParser in Your Projects

## Installation from GitHub

Add to your `Cargo.toml`:

```toml
[dependencies]
# Basic usage
nparser = { git = "https://github.com/jgYro/nParser.git" }

# With all features
nparser = { git = "https://github.com/jgYro/nParser.git", features = ["full"] }

# With specific features
nparser = { git = "https://github.com/jgYro/nParser.git", features = ["serialization"] }
```

## Example Usage

```rust
use nparser::{parse_certificates_from_pem, CertificateQuery};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse certificates
    let certs = parse_certificates_from_pem("path/to/cert.pem")?;

    // Filter certificates
    let ca_certs = CertificateQuery::new()
        .is_ca_certificate()
        .public_key_size_at_least(2048);

    for cert in certs.iter().filter(|c| ca_certs.matches(c)) {
        println!("Found CA: {}", cert.subject);
    }

    Ok(())
}
```

## With Serialization

```rust
use nparser::parse_certificates_from_pem;
use serde_json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certs = parse_certificates_from_pem("cert.pem")?;

    // Export to JSON
    let json = serde_json::to_string_pretty(&certs)?;
    println!("{}", json);

    Ok(())
}
```

## Updating the Dependency

When the library is updated on GitHub, update your local copy:

```bash
cargo update -p nparser
```

Or force a fresh download:

```bash
cargo clean
cargo build
```