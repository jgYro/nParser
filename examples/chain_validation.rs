/// Example demonstrating certificate chain validation concepts
/// Note: This is a simplified example - production use should employ
/// full path validation according to RFC 5280

use nparser::{parse_certificates_from_pem, CertificateInfo};
use std::collections::HashMap;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let cert_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            "/Users/jerichogregory/Library/Python/3.13/lib/python/site-packages/certifi/cacert.pem"
                .to_string()
        });

    println!("Loading certificate bundle from: {}", cert_path);
    let certificates = parse_certificates_from_pem(&cert_path)?;
    println!("Loaded {} certificates\n", certificates.len());

    // Build indices for quick lookup
    let subject_index = build_subject_index(&certificates);
    let ski_index = build_ski_index(&certificates);

    // Find self-signed root certificates
    let root_certs = find_root_certificates(&certificates);
    println!("Found {} self-signed root certificates", root_certs.len());

    // Find intermediate CA certificates
    let intermediate_cas = find_intermediate_cas(&certificates);
    println!("Found {} intermediate CA certificates", intermediate_cas.len());

    // Find end-entity certificates
    let end_entities = find_end_entity_certificates(&certificates);
    println!("Found {} end-entity certificates", end_entities.len());

    // Example: Try to build a chain for each non-root certificate
    println!("\n=== Certificate Chain Analysis ===");
    for cert in certificates.iter().take(10) {
        if !is_self_signed(cert) {
            println!("\nCertificate: {}", cert.subject);

            // Try to find the issuer
            if let Some(issuer) = find_issuer(cert, &certificates, &ski_index) {
                println!("  ✓ Found issuer: {}", issuer.subject);

                // Check if issuer is a root
                if is_self_signed(issuer) {
                    println!("    → Issuer is a root CA");
                } else {
                    println!("    → Issuer is an intermediate CA");
                    // Could recursively build the full chain here
                }
            } else {
                println!("  ✗ Issuer not found in bundle");
            }

            // Check certificate constraints
            check_certificate_constraints(cert);
        }
    }

    // Display trust hierarchy statistics
    display_trust_hierarchy(&certificates);

    Ok(())
}

/// Build an index of certificates by subject DN
fn build_subject_index(certs: &[CertificateInfo]) -> HashMap<String, Vec<usize>> {
    let mut index = HashMap::new();
    for (i, cert) in certs.iter().enumerate() {
        index.entry(cert.subject.clone())
            .or_insert_with(Vec::new)
            .push(i);
    }
    index
}

/// Build an index of certificates by Subject Key Identifier
fn build_ski_index(certs: &[CertificateInfo]) -> HashMap<String, usize> {
    let mut index = HashMap::new();
    for (i, cert) in certs.iter().enumerate() {
        if let Some(ref ski) = cert.subject_key_identifier {
            index.insert(ski.clone(), i);
        }
    }
    index
}

/// Check if a certificate is self-signed (root CA)
fn is_self_signed(cert: &CertificateInfo) -> bool {
    cert.subject == cert.issuer
}

/// Find all root certificates (self-signed CAs)
fn find_root_certificates(certs: &[CertificateInfo]) -> Vec<&CertificateInfo> {
    certs.iter()
        .filter(|cert| is_self_signed(cert) && cert.is_ca == Some(true))
        .collect()
}

/// Find all intermediate CA certificates
fn find_intermediate_cas(certs: &[CertificateInfo]) -> Vec<&CertificateInfo> {
    certs.iter()
        .filter(|cert| !is_self_signed(cert) && cert.is_ca == Some(true))
        .collect()
}

/// Find all end-entity certificates
fn find_end_entity_certificates(certs: &[CertificateInfo]) -> Vec<&CertificateInfo> {
    certs.iter()
        .filter(|cert| cert.is_ca == Some(false) || cert.is_ca.is_none())
        .collect()
}

/// Try to find the issuer of a certificate
fn find_issuer<'a>(
    cert: &CertificateInfo,
    all_certs: &'a [CertificateInfo],
    ski_index: &HashMap<String, usize>,
) -> Option<&'a CertificateInfo> {
    // Method 1: Use Authority Key Identifier if available
    if let Some(ref aki) = cert.authority_key_identifier {
        if let Some(ref key_id) = aki.key_identifier {
            if let Some(&idx) = ski_index.get(key_id) {
                return all_certs.get(idx);
            }
        }
    }

    // Method 2: Match by Issuer DN = Subject DN
    all_certs.iter()
        .find(|candidate| candidate.subject == cert.issuer)
}

/// Check various certificate constraints and policies
fn check_certificate_constraints(cert: &CertificateInfo) {
    let mut constraints = Vec::new();

    // Check basic constraints
    if let Some(is_ca) = cert.is_ca {
        if is_ca {
            constraints.push("CA Certificate");
            if let Some(path_len) = cert.path_length_constraint {
                constraints.push(&format!("Path Length: {}", path_len));
            }
        } else {
            constraints.push("End Entity Certificate");
        }
    }

    // Check key usage
    if let Some(ref key_usage) = cert.key_usage {
        if key_usage.contains(&"Key Cert Sign".to_string()) {
            constraints.push("Can sign certificates");
        }
        if key_usage.contains(&"CRL Sign".to_string()) {
            constraints.push("Can sign CRLs");
        }
    }

    // Check if certificate has CRL distribution points
    if cert.crl_distribution_points.is_some() {
        constraints.push("Has CRL distribution points");
    }

    // Check if certificate has OCSP responders
    if let Some(ref aia) = cert.authority_info_access {
        if aia.iter().any(|a| a.access_method.contains("OCSP")) {
            constraints.push("Has OCSP responder");
        }
    }

    if !constraints.is_empty() {
        println!("  Constraints: {}", constraints.join(", "));
    }
}

/// Display trust hierarchy statistics
fn display_trust_hierarchy(certs: &[CertificateInfo]) {
    println!("\n=== Trust Hierarchy Statistics ===");

    // Count certificates by path length constraint
    let mut path_lengths = HashMap::new();
    for cert in certs {
        if cert.is_ca == Some(true) {
            let path_len = cert.path_length_constraint.unwrap_or(999);
            *path_lengths.entry(path_len).or_insert(0) += 1;
        }
    }

    println!("\nCA Certificates by Path Length Constraint:");
    let mut lengths: Vec<_> = path_lengths.iter().collect();
    lengths.sort_by_key(|&(len, _)| len);
    for (len, count) in lengths {
        if *len == 999 {
            println!("  No constraint: {} certificates", count);
        } else {
            println!("  Path length {}: {} certificates", len, count);
        }
    }

    // Find certificates with specific extensions
    let with_san = certs.iter()
        .filter(|c| c.subject_alternative_names.is_some())
        .count();
    let with_crl = certs.iter()
        .filter(|c| c.crl_distribution_points.is_some())
        .count();
    let with_aia = certs.iter()
        .filter(|c| c.authority_info_access.is_some())
        .count();

    println!("\nCertificates with Extensions:");
    println!("  Subject Alternative Names: {}", with_san);
    println!("  CRL Distribution Points: {}", with_crl);
    println!("  Authority Info Access: {}", with_aia);

    // Key usage statistics for CA certificates
    let mut ca_key_usage = HashMap::new();
    for cert in certs {
        if cert.is_ca == Some(true) {
            if let Some(ref key_usage) = cert.key_usage {
                for usage in key_usage {
                    *ca_key_usage.entry(usage.clone()).or_insert(0) += 1;
                }
            }
        }
    }

    println!("\nCA Certificate Key Usage:");
    for (usage, count) in ca_key_usage {
        println!("  {}: {} certificates", usage, count);
    }
}