/// Example demonstrating the certificate filtering and querying capabilities
/// of the pem_processor library.

use nparser::{parse_certificates_from_pem, CertificateQuery, CertificateInfo};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let cert_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            "/Users/jerichogregory/Library/Python/3.13/lib/python/site-packages/certifi/cacert.pem"
                .to_string()
        });

    println!("Loading certificates from: {}", cert_path);
    let certificates = parse_certificates_from_pem(&cert_path)?;
    println!("Loaded {} certificates\n", certificates.len());

    // Example 1: Find all CA certificates
    println!("=== CA Certificates ===");
    let ca_query = CertificateQuery::new().is_ca_certificate();
    let ca_certs = filter_certificates(&certificates, &ca_query);
    println!("Found {} CA certificates", ca_certs.len());
    for cert in ca_certs.iter().take(3) {
        print_cert_summary(cert);
    }
    println!();

    // Example 2: Find certificates with RSA keys >= 4096 bits
    println!("=== Strong RSA Certificates (≥4096 bits) ===");
    let strong_rsa_query = CertificateQuery::new()
        .public_key_algorithm_contains(vec!["RSA".to_string()])
        .public_key_size_at_least(4096);
    let strong_rsa_certs = filter_certificates(&certificates, &strong_rsa_query);
    println!("Found {} certificates with RSA keys ≥4096 bits", strong_rsa_certs.len());
    for cert in strong_rsa_certs.iter().take(3) {
        print_cert_summary(cert);
    }
    println!();

    // Example 3: Find certificates with specific key usage
    println!("=== Certificates with Code Signing ===");
    let code_signing_query = CertificateQuery::new()
        .requires_key_usage(vec!["Code Signing".to_string()]);
    let code_signing_certs = filter_certificates(&certificates, &code_signing_query);
    println!("Found {} certificates with code signing capability", code_signing_certs.len());
    for cert in code_signing_certs.iter().take(3) {
        print_cert_summary(cert);
    }
    println!();

    // Example 4: Find certificates from specific organizations
    println!("=== Certificates from 'GlobalSign' ===");
    let org_query = CertificateQuery::new()
        .subject_contains("GlobalSign".to_string());
    let org_certs = filter_certificates(&certificates, &org_query);
    println!("Found {} certificates from GlobalSign", org_certs.len());
    for cert in org_certs.iter().take(3) {
        print_cert_summary(cert);
    }
    println!();

    // Example 5: Complex query - CA certificates with ECDSA and specific signature algorithms
    println!("=== CA Certificates with SHA-256 or SHA-384 ===");
    let complex_query = CertificateQuery::new()
        .is_ca_certificate()
        .signature_algorithm_contains(vec![
            "sha256".to_string(),
            "sha384".to_string(),
        ]);
    let complex_certs = filter_certificates(&certificates, &complex_query);
    println!("Found {} CA certificates with SHA-256/384", complex_certs.len());
    for cert in complex_certs.iter().take(3) {
        print_cert_summary(cert);
    }
    println!();

    // Example 6: Find certificates with Subject Alternative Names
    println!("=== Certificates with SANs ===");
    let san_certs: Vec<_> = certificates
        .iter()
        .filter(|cert| cert.subject_alternative_names.is_some())
        .collect();
    println!("Found {} certificates with Subject Alternative Names", san_certs.len());
    for cert in san_certs.iter().take(3) {
        print_cert_summary(cert);
        if let Some(sans) = &cert.subject_alternative_names {
            for san in sans.iter().take(3) {
                println!("    SAN: {} = {}", san.name_type, san.value);
            }
        }
    }

    // Statistics
    print_statistics(&certificates);

    Ok(())
}

/// Filter certificates based on a query
fn filter_certificates<'a>(
    certificates: &'a [CertificateInfo],
    query: &CertificateQuery,
) -> Vec<&'a CertificateInfo> {
    certificates
        .iter()
        .filter(|cert| query.matches(cert))
        .collect()
}

/// Print a summary of a certificate
fn print_cert_summary(cert: &CertificateInfo) {
    let cn = cert.subject_common_name.as_deref().unwrap_or("N/A");
    let key_size = cert.public_key_size
        .map(|s| format!("{} bits", s))
        .unwrap_or_else(|| "Unknown".to_string());

    println!("  - CN: {}", cn);
    println!("    Serial: {}", cert.serial_number);
    println!("    Key: {} ({})", cert.public_key_algorithm_description, key_size);
    println!("    Signature: {}", cert.signature_algorithm_description);
}

/// Print statistics about the certificate collection
fn print_statistics(certificates: &[CertificateInfo]) {
    println!("\n=== Certificate Statistics ===");

    // CA vs End Entity
    let ca_count = certificates.iter()
        .filter(|c| c.is_ca == Some(true))
        .count();
    let end_entity = certificates.iter()
        .filter(|c| c.is_ca == Some(false))
        .count();

    println!("Certificate Types:");
    println!("  CA Certificates: {}", ca_count);
    println!("  End Entity Certificates: {}", end_entity);

    // Key algorithms
    let rsa_count = certificates.iter()
        .filter(|c| c.public_key_algorithm_description.contains("RSA"))
        .count();
    let ecdsa_count = certificates.iter()
        .filter(|c| c.public_key_algorithm_description.contains("EC"))
        .count();

    println!("\nKey Algorithms:");
    println!("  RSA: {}", rsa_count);
    println!("  ECDSA: {}", ecdsa_count);

    // Key sizes for RSA
    let mut rsa_sizes = std::collections::HashMap::new();
    for cert in certificates {
        if cert.public_key_algorithm_description.contains("RSA") {
            if let Some(size) = cert.public_key_size {
                *rsa_sizes.entry(size).or_insert(0) += 1;
            }
        }
    }

    println!("\nRSA Key Sizes:");
    let mut sizes: Vec<_> = rsa_sizes.iter().collect();
    sizes.sort_by_key(|&(size, _)| size);
    for (size, count) in sizes {
        println!("  {} bits: {} certificates", size, count);
    }

    // Signature algorithms
    let sha256_count = certificates.iter()
        .filter(|c| c.signature_algorithm_description.contains("sha256"))
        .count();
    let sha384_count = certificates.iter()
        .filter(|c| c.signature_algorithm_description.contains("sha384"))
        .count();
    let sha1_count = certificates.iter()
        .filter(|c| c.signature_algorithm_description.contains("sha1"))
        .count();

    println!("\nSignature Algorithms:");
    println!("  SHA-256: {}", sha256_count);
    println!("  SHA-384: {}", sha384_count);
    println!("  SHA-1 (Legacy): {}", sha1_count);
}