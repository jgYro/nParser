/// Example demonstrating serialization of certificate data to JSON
/// Requires the "serialization" feature flag

#[cfg(not(feature = "serialization"))]
fn main() {
    eprintln!("This example requires the 'serialization' feature.");
    eprintln!("Run with: cargo run --example serialization --features serialization");
}

#[cfg(feature = "serialization")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nparser::{parse_certificates_from_pem, CertificateInfo};
    use serde_json;
    use std::fs;

    let cert_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            "/Users/jerichogregory/Library/Python/3.13/lib/python/site-packages/certifi/cacert.pem"
                .to_string()
        });

    println!("Loading certificates from: {}", cert_path);
    let certificates = parse_certificates_from_pem(&cert_path)?;
    println!("Loaded {} certificates\n", certificates.len());

    // Example 1: Serialize a single certificate to JSON
    if let Some(first_cert) = certificates.first() {
        println!("=== Serializing First Certificate to JSON ===");
        let json = serde_json::to_string_pretty(first_cert)?;
        println!("JSON representation (truncated):");
        for line in json.lines().take(20) {
            println!("{}", line);
        }
        println!("... [truncated]\n");

        // Save to file
        let output_file = "certificate.json";
        fs::write(output_file, &json)?;
        println!("Full certificate saved to: {}\n", output_file);
    }

    // Example 2: Serialize all certificates to a compact JSON array
    println!("=== Serializing All Certificates ===");
    let all_json = serde_json::to_string(&certificates)?;
    println!("Total JSON size: {} bytes", all_json.len());

    // Save all certificates
    let output_file = "all_certificates.json";
    fs::write(output_file, &all_json)?;
    println!("All certificates saved to: {}\n", output_file);

    // Example 3: Serialize a subset of certificate fields
    println!("=== Creating Certificate Summary ===");
    let summaries: Vec<CertificateSummary> = certificates
        .iter()
        .map(|cert| CertificateSummary {
            subject_cn: cert.subject_common_name.clone(),
            issuer_cn: cert.issuer_common_name.clone(),
            serial: cert.serial_number.clone(),
            is_ca: cert.is_ca,
            key_algorithm: cert.public_key_algorithm_description.clone(),
            key_size: cert.public_key_size,
            sha256_fingerprint: cert.sha256_fingerprint.clone(),
        })
        .collect();

    let summary_json = serde_json::to_string_pretty(&summaries)?;
    println!("Certificate summaries (first 3):");
    for summary in summaries.iter().take(3) {
        println!("  - CN: {:?}, CA: {:?}, Key: {} ({:?} bits)",
                 summary.subject_cn.as_deref().unwrap_or("N/A"),
                 summary.is_ca,
                 summary.key_algorithm,
                 summary.key_size);
    }

    // Save summaries
    let output_file = "certificate_summaries.json";
    fs::write(output_file, summary_json)?;
    println!("\nSummaries saved to: {}\n", output_file);

    // Example 4: Deserialize back from JSON
    println!("=== Deserializing from JSON ===");
    let json_data = fs::read_to_string("certificate.json")?;
    let deserialized: CertificateInfo = serde_json::from_str(&json_data)?;
    println!("Successfully deserialized certificate:");
    println!("  Subject: {}", deserialized.subject);
    println!("  Serial: {}", deserialized.serial_number);

    // Verify it matches the original
    if let Some(first_cert) = certificates.first() {
        if first_cert == &deserialized {
            println!("  ✓ Deserialized certificate matches the original!");
        } else {
            println!("  ✗ Warning: Deserialized certificate differs from original");
        }
    }

    // Example 5: Export to different formats
    println!("\n=== Export Statistics ===");
    let stats = CertificateStats::from_certificates(&certificates);

    // As JSON
    let stats_json = serde_json::to_string_pretty(&stats)?;
    fs::write("certificate_stats.json", stats_json)?;
    println!("Statistics exported to certificate_stats.json");

    // Display stats
    println!("\nCertificate Statistics:");
    println!("  Total: {}", stats.total_count);
    println!("  CA Certificates: {}", stats.ca_count);
    println!("  RSA Certificates: {}", stats.rsa_count);
    println!("  ECC Certificates: {}", stats.ecc_count);
    println!("  Average Key Size: {} bits", stats.average_key_size);

    Ok(())
}

#[cfg(feature = "serialization")]
#[derive(serde::Serialize, serde::Deserialize)]
struct CertificateSummary {
    subject_cn: Option<String>,
    issuer_cn: Option<String>,
    serial: String,
    is_ca: Option<bool>,
    key_algorithm: String,
    key_size: Option<usize>,
    sha256_fingerprint: Option<String>,
}

#[cfg(feature = "serialization")]
#[derive(serde::Serialize, serde::Deserialize)]
struct CertificateStats {
    total_count: usize,
    ca_count: usize,
    end_entity_count: usize,
    rsa_count: usize,
    ecc_count: usize,
    average_key_size: usize,
    unique_issuers: usize,
}

#[cfg(feature = "serialization")]
impl CertificateStats {
    fn from_certificates(certs: &[nparser::CertificateInfo]) -> Self {
        use std::collections::HashSet;

        let ca_count = certs.iter().filter(|c| c.is_ca == Some(true)).count();
        let end_entity_count = certs.iter().filter(|c| c.is_ca == Some(false)).count();
        let rsa_count = certs.iter()
            .filter(|c| c.public_key_algorithm_description.contains("RSA"))
            .count();
        let ecc_count = certs.iter()
            .filter(|c| c.public_key_algorithm_description.contains("EC"))
            .count();

        let total_key_size: usize = certs.iter()
            .filter_map(|c| c.public_key_size)
            .sum();
        let key_count = certs.iter()
            .filter(|c| c.public_key_size.is_some())
            .count();
        let average_key_size = if key_count > 0 {
            total_key_size / key_count
        } else {
            0
        };

        let unique_issuers: HashSet<_> = certs.iter()
            .map(|c| &c.issuer)
            .collect();

        CertificateStats {
            total_count: certs.len(),
            ca_count,
            end_entity_count,
            rsa_count,
            ecc_count,
            average_key_size,
            unique_issuers: unique_issuers.len(),
        }
    }
}