# nParser

A comprehensive X.509 certificate parsing library for Rust that extracts all available certificate fields with explicit handling of optional data.

## Features

- 🔍 **Complete X.509 Parsing**: Extracts all standard X.509 v1/v2/v3 certificate fields
- 🏷️ **Human-Readable OIDs**: Automatic OID-to-name translation via `oid_registry`
- 🔐 **Cryptographic Details**: Full extraction of RSA/ECC public key parameters
- 📋 **All Extensions**: Parses all standard and custom certificate extensions
- 🔎 **Flexible Querying**: Powerful certificate filtering with the specification pattern
- 🛡️ **Type Safety**: Explicit `Option<T>` types for all optional fields
- 🎯 **Zero Missing Data**: Every certificate field is captured and accessible

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
nparser = "0.2.0"
```

## Quick Start

```rust
use nparser::{parse_certificates_from_pem, CertificateInfo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse certificates from a PEM file
    let certs = parse_certificates_from_pem("/path/to/certificates.pem")?;

    for cert in certs {
        println!("Subject: {}", cert.subject);
        println!("Issuer: {}", cert.issuer);

        // Access individual subject components
        if let Some(cn) = cert.subject_common_name {
            println!("Common Name: {}", cn);
        }

        // Check certificate type
        if let Some(is_ca) = cert.is_ca {
            println!("Certificate Type: {}",
                if is_ca { "CA" } else { "End Entity" });
        }

        // Access extensions
        if let Some(san_list) = cert.subject_alternative_names {
            for san in san_list {
                println!("SAN: {} = {}", san.name_type, san.value);
            }
        }
    }
    Ok(())
}
```

## Advanced Usage

### Certificate Filtering

```rust
use nparser::{parse_certificates_from_pem, CertificateQuery};

// Find all CA certificates with RSA keys >= 2048 bits
let query = CertificateQuery::new()
    .is_ca_certificate()
    .public_key_algorithm_contains(vec!["RSA".to_string()])
    .public_key_size_at_least(2048);

let certs = parse_certificates_from_pem("/path/to/certs.pem")?;
let matching: Vec<_> = certs.iter()
    .filter(|cert| query.matches(cert))
    .collect();
```

### Parse from Memory

```rust
use nparser::parse_certificates_from_bytes;

let pem_data = b"-----BEGIN CERTIFICATE-----\n...";
let certs = parse_certificates_from_bytes(pem_data)?;
```

## Available Certificate Fields

### Core Information
- Version (X.509 v1/v2/v3)
- Serial Number
- SHA-1 and SHA-256 Fingerprints

### Subject & Issuer Details
- Full Distinguished Name
- Individual components: CN, O, OU, C, ST, L, Email

### Cryptographic Information
- **Signature**: Algorithm, parameters, and raw signature value
- **Public Key**: Algorithm, size, parameters
- **RSA Keys**: Modulus and public exponent
- **ECC Keys**: Curve identifier and point

### Extensions (All Parsed)
- Basic Constraints (CA flag, path length)
- Key Usage and Extended Key Usage
- Subject Alternative Names (DNS, Email, IP, URI)
- Authority/Subject Key Identifiers
- CRL Distribution Points
- Authority Information Access (OCSP, CA Issuers)
- Certificate Policies
- Name Constraints
- And many more...

## Examples

The repository includes several examples:

- `basic_parsing.rs` - Simple certificate parsing and field access
- `certificate_filtering.rs` - Advanced querying and filtering
- `chain_validation.rs` - Certificate chain analysis

Run examples with:

```bash
cargo run --example basic_parsing /path/to/certificate.pem
cargo run --example certificate_filtering
cargo run --example chain_validation
```

## Binary Tool

The library includes a certificate analyzer binary:

```bash
cargo install nparser
cert-analyzer /path/to/certificates.pem
```

## API Documentation

Full API documentation is available at [docs.rs/nparser](https://docs.rs/nparser)

## Features Flags

- `date-validation` - Enable certificate date validation with `chrono`
- `full` - Enable all optional features

## License

This project is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Safety

This crate uses `ring` for cryptographic operations and carefully handles all certificate parsing to prevent panics. All optional fields are explicitly marked with `Option<T>` to make missing data handling clear and safe.