use pem_processor::parse_certificates_from_pem;

fn main() {
    let path =
        "/Users/jerichogregory/Library/Python/3.13/lib/python/site-packages/certifi/cacert.pem";

    match parse_certificates_from_pem(&path) {
        Ok(cert_infos) => {
            println!("Certificate Bundle Analysis for: {}", path);
            println!("Found {} certificate(s)\n", cert_infos.len());

            for (i, cert_info) in cert_infos.iter().enumerate() {
                println!("=== Certificate {} ===", i + 1);
                println!("Subject: {}", cert_info.subject);
                println!("Issuer: {}", cert_info.issuer);
                println!("Serial Number: {}", cert_info.serial_number);
                println!(
                    "Signature Algorithm: {}",
                    cert_info.signature_algorithm_description
                );
                if let Some(ref params) = cert_info.signature_params {
                    println!("Signature Parameters: {}", params);
                }
                println!(
                    "Public Key Algorithm: {}",
                    cert_info.public_key_algorithm_description
                );
                if let Some(size) = cert_info.public_key_size {
                    println!("Public Key Size: {} bits", size);
                }
                println!("Valid From: {}", cert_info.validity_not_before);
                println!("Valid To: {}", cert_info.validity_not_after);
                println!("Is CA: {}", cert_info.is_ca);

                if !cert_info.key_usage.is_empty() {
                    println!("Key Usage: {}", cert_info.key_usage.join(", "));
                }

                if !cert_info.extended_key_usage.is_empty() {
                    println!(
                        "Extended Key Usage: {}",
                        cert_info.extended_key_usage.join(", ")
                    );
                }

                if !cert_info.extensions.is_empty() {
                    println!("Extensions:");
                    for ext in &cert_info.extensions {
                        let critical_marker = if ext.critical { " (CRITICAL)" } else { "" };
                        println!("  - {}{}", ext.oid_description, critical_marker);
                    }
                }

                println!();
            }
        }
        Err(e) => {
            eprintln!("Error processing certificate: {}", e);
        }
    }
}
