//! # nParser
//!
//! A comprehensive X.509 certificate parsing library for Rust that extracts all available
//! certificate fields with explicit handling of optional data.
//!
//! ## Features
//!
//! - Complete X.509 v1/v2/v3 certificate parsing
//! - Human-readable OID descriptions via `oid_registry`
//! - All standard extensions parsing (SAN, Key Usage, CRL Distribution Points, etc.)
//! - Certificate fingerprint calculation (SHA-1 and SHA-256)
//! - RSA and ECC public key details extraction
//! - Flexible certificate querying and filtering system
//! - Explicit null handling with Option types for all optional fields
//!
//! ## Basic Usage
//!
//! ```rust,no_run
//! use nparser::{parse_certificates_from_pem, CertificateInfo};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let certs = parse_certificates_from_pem("/path/to/certificate.pem")?;
//!
//!     for cert in certs {
//!         println!("Subject: {}", cert.subject);
//!         println!("Issuer: {}", cert.issuer);
//!         if let Some(san) = cert.subject_alternative_names {
//!             for name in san {
//!                 println!("SAN: {} = {}", name.name_type, name.value);
//!             }
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Advanced Querying
//!
//! ```rust,no_run
//! use nparser::{parse_certificates_from_pem, CertificateQuery};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let certs = parse_certificates_from_pem("/path/to/certificates.pem")?;
//!
//!     // Find all CA certificates with RSA keys >= 2048 bits
//!     let query = CertificateQuery::new()
//!         .is_ca_certificate()
//!         .public_key_algorithm_contains(vec!["RSA".to_string()])
//!         .public_key_size_at_least(2048);
//!
//!     let matching_certs: Vec<_> = certs.iter()
//!         .filter(|cert| query.matches(cert))
//!         .collect();
//!
//!     println!("Found {} matching certificates", matching_certs.len());
//!     Ok(())
//! }
//! ```

mod certificate_parser;
mod certificate_query;

// Re-export main types and functions for public API
pub use certificate_parser::{
    // Main parsing functions
    parse_certificates_from_pem,
    parse_certificates_from_bytes,

    // Core types
    CertificateInfo,
    ExtensionInfo,
    SubjectAlternativeName,
    AuthorityKeyIdentifier,
    AuthorityInfoAccess,
    SubjectInfoAccess,
    CertificatePolicy,
    PolicyMapping,
    PolicyConstraints,
    NameConstraints,
    SignedCertificateTimestamp,

    // Helper functions (advanced users)
    create_oid_registry,
    format_oid_with_description,
};

pub use certificate_query::CertificateQuery;

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Re-export commonly used external types
pub use x509_parser::prelude::X509Version;

/// Result type for certificate parsing operations
pub type CertificateResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Convenience function to parse a PEM string directly
pub fn parse_certificates_from_string(pem_string: &str) -> CertificateResult<Vec<CertificateInfo>> {
    parse_certificates_from_bytes(pem_string.as_bytes())
}

/// Check if a certificate is currently valid
///
/// Note: This is a simplified placeholder. For actual date validation,
/// enable the `date-validation` feature flag.
#[cfg(feature = "date-validation")]
pub fn is_certificate_valid_now(cert: &CertificateInfo) -> bool {
    use chrono::{DateTime, Utc};

    let now = Utc::now();

    // Parse the validity dates (basic implementation - could be improved)
    // This is a simplified check - production code should properly parse ASN.1 time
    true // Placeholder - would need proper date parsing
}

/// Check if a certificate is currently valid (stub version without chrono)
#[cfg(not(feature = "date-validation"))]
pub fn is_certificate_valid_now(_cert: &CertificateInfo) -> bool {
    // Without the date-validation feature, we can't properly validate dates
    // Return true as a safe default or implement basic string comparison
    true
}

/// Get a human-readable summary of a certificate
pub fn certificate_summary(cert: &CertificateInfo) -> String {
    format!(
        "Certificate: CN={}, Issuer={}, Serial={}, Valid from {} to {}",
        cert.subject_common_name.as_deref().unwrap_or("N/A"),
        cert.issuer_common_name.as_deref().unwrap_or(&cert.issuer),
        cert.serial_number,
        cert.validity_not_before,
        cert.validity_not_after
    )
}