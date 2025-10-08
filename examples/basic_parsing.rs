/// Basic example demonstrating how to parse certificates from a PEM file
/// and access various certificate fields.

use nparser::{parse_certificates_from_pem, CertificateInfo};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Example path - replace with your certificate file
    let cert_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/path/to/certificate.pem".to_string());

    println!("Parsing certificates from: {}", cert_path);
    println!("{}", "=".repeat(60));

    // Parse the PEM file
    let certificates = parse_certificates_from_pem(&cert_path)?;

    println!("Found {} certificate(s)\n", certificates.len());

    // Iterate through each certificate
    for (idx, cert) in certificates.iter().enumerate() {
        println!("Certificate #{}", idx + 1);
        println!("{}", "-".repeat(40));

        // Basic information
        println!("Subject: {}", cert.subject);
        println!("Issuer: {}", cert.issuer);
        println!("Serial: {}", cert.serial_number);
        println!("Version: X.509 v{}", cert.version);

        // Subject components
        if let Some(cn) = &cert.subject_common_name {
            println!("Subject CN: {}", cn);
        }
        if let Some(org) = &cert.subject_organization {
            println!("Subject O: {}", org);
        }

        // Validity period
        println!("\nValidity:");
        println!("  Not Before: {}", cert.validity_not_before);
        println!("  Not After: {}", cert.validity_not_after);

        // Public key info
        println!("\nPublic Key:");
        println!("  Algorithm: {}", cert.public_key_algorithm_description);
        if let Some(size) = cert.public_key_size {
            println!("  Size: {} bits", size);
        }

        // RSA-specific information
        if let Some(modulus) = &cert.public_key_modulus {
            println!("  RSA Modulus (first 32 chars): {}...",
                     &modulus[..32.min(modulus.len())]);
        }
        if let Some(exponent) = &cert.public_key_exponent {
            println!("  RSA Exponent: {}", exponent);
        }

        // Certificate type
        if let Some(is_ca) = cert.is_ca {
            println!("\nCertificate Type: {}",
                     if is_ca { "CA Certificate" } else { "End Entity Certificate" });

            if is_ca {
                if let Some(path_len) = cert.path_length_constraint {
                    println!("  Path Length Constraint: {}", path_len);
                }
            }
        }

        // Key usage
        if let Some(key_usage) = &cert.key_usage {
            println!("\nKey Usage:");
            for usage in key_usage {
                println!("  - {}", usage);
            }
        }

        // Extended key usage
        if let Some(eku) = &cert.extended_key_usage {
            println!("\nExtended Key Usage:");
            for usage in eku {
                println!("  - {}", usage);
            }
        }

        // Subject Alternative Names
        if let Some(san_list) = &cert.subject_alternative_names {
            println!("\nSubject Alternative Names:");
            for san in san_list {
                println!("  {} = {}", san.name_type, san.value);
            }
        }

        // Authority Information Access
        if let Some(aia) = &cert.authority_info_access {
            println!("\nAuthority Information Access:");
            for access in aia {
                println!("  {} -> {}", access.access_method, access.access_location);
            }
        }

        // CRL Distribution Points
        if let Some(crls) = &cert.crl_distribution_points {
            println!("\nCRL Distribution Points:");
            for crl in crls {
                println!("  - {}", crl);
            }
        }

        // Fingerprints
        println!("\nFingerprints:");
        if let Some(sha1) = &cert.sha1_fingerprint {
            println!("  SHA-1: {}", sha1);
        }
        if let Some(sha256) = &cert.sha256_fingerprint {
            println!("  SHA-256: {}", sha256);
        }

        println!("\n");
    }

    Ok(())
}

// Helper function to display certificate summary
fn display_certificate_summary(cert: &CertificateInfo) {
    let cn = cert.subject_common_name.as_deref().unwrap_or("Unknown");
    let org = cert.subject_organization.as_deref().unwrap_or("Unknown");

    println!("Certificate for {} ({})", cn, org);

    if let Some(is_ca) = cert.is_ca {
        let cert_type = if is_ca { "CA" } else { "End Entity" };
        println!("  Type: {}", cert_type);
    }

    if let Some(size) = cert.public_key_size {
        println!("  Key Size: {} bits", size);
    }
}