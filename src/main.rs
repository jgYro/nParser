use nparser::parse_certificates_from_pem;

fn main() {
    let path =
        "/Users/jerichogregory/Library/Python/3.13/lib/python/site-packages/certifi/cacert.pem";

    match parse_certificates_from_pem(&path) {
        Ok(cert_infos) => {
            println!("Certificate Bundle Analysis for: {}", path);
            println!("Found {} certificate(s)\n", cert_infos.len());

            for (i, cert_info) in cert_infos.iter().enumerate() {
                println!("{}", "=".repeat(80));
                println!("CERTIFICATE #{} of {}", i + 1, cert_infos.len());
                println!("{}\n", "=".repeat(80));

                // Core Certificate Information
                println!("[ CORE INFORMATION ]");
                println!("  Version: X.509 v{}", cert_info.version);
                println!("  Serial Number: {}", cert_info.serial_number);

                // Fingerprints
                if let Some(ref sha1) = cert_info.sha1_fingerprint {
                    println!("  SHA-1 Fingerprint: {}", sha1);
                }
                if let Some(ref sha256) = cert_info.sha256_fingerprint {
                    println!("  SHA-256 Fingerprint: {}", sha256);
                }
                println!();

                // Subject Information
                println!("[ SUBJECT ]");
                println!("  Full DN: {}", cert_info.subject);
                if let Some(ref cn) = cert_info.subject_common_name {
                    println!("  Common Name (CN): {}", cn);
                }
                if let Some(ref o) = cert_info.subject_organization {
                    println!("  Organization (O): {}", o);
                }
                if let Some(ref ou) = cert_info.subject_organizational_unit {
                    println!("  Organizational Unit (OU): {}", ou);
                }
                if let Some(ref c) = cert_info.subject_country {
                    println!("  Country (C): {}", c);
                }
                if let Some(ref st) = cert_info.subject_state_province {
                    println!("  State/Province (ST): {}", st);
                }
                if let Some(ref l) = cert_info.subject_locality {
                    println!("  Locality (L): {}", l);
                }
                if let Some(ref email) = cert_info.subject_email {
                    println!("  Email: {}", email);
                }
                println!();

                // Issuer Information
                println!("[ ISSUER ]");
                println!("  Full DN: {}", cert_info.issuer);
                if let Some(ref cn) = cert_info.issuer_common_name {
                    println!("  Common Name (CN): {}", cn);
                }
                if let Some(ref o) = cert_info.issuer_organization {
                    println!("  Organization (O): {}", o);
                }
                if let Some(ref ou) = cert_info.issuer_organizational_unit {
                    println!("  Organizational Unit (OU): {}", ou);
                }
                if let Some(ref c) = cert_info.issuer_country {
                    println!("  Country (C): {}", c);
                }
                if let Some(ref st) = cert_info.issuer_state_province {
                    println!("  State/Province (ST): {}", st);
                }
                if let Some(ref l) = cert_info.issuer_locality {
                    println!("  Locality (L): {}", l);
                }
                if let Some(ref email) = cert_info.issuer_email {
                    println!("  Email: {}", email);
                }
                println!();

                // Validity Period
                println!("[ VALIDITY PERIOD ]");
                println!("  Not Before: {}", cert_info.validity_not_before);
                println!("  Not After: {}", cert_info.validity_not_after);
                println!();

                // Signature Algorithm
                println!("[ SIGNATURE ]");
                println!("  Algorithm: {}", cert_info.signature_algorithm);
                println!("  Algorithm Description: {}", cert_info.signature_algorithm_description);
                if let Some(ref params) = cert_info.signature_params {
                    println!("  Parameters: {}", params);
                }
                println!("  Signature Value: {} bytes", cert_info.signature_value.len());
                println!();

                // Public Key Information
                println!("[ PUBLIC KEY ]");
                println!("  Algorithm: {}", cert_info.public_key_algorithm);
                println!("  Algorithm Description: {}", cert_info.public_key_algorithm_description);
                if let Some(size) = cert_info.public_key_size {
                    println!("  Key Size: {} bits", size);
                }
                if let Some(ref params) = cert_info.public_key_params {
                    println!("  Parameters: {}", params);
                }

                // RSA-specific details
                if let Some(ref modulus) = cert_info.public_key_modulus {
                    println!("  RSA Modulus: {}...", &modulus[..32.min(modulus.len())]);
                }
                if let Some(ref exponent) = cert_info.public_key_exponent {
                    println!("  RSA Exponent: {}", exponent);
                }

                // ECC-specific details
                if let Some(ref curve) = cert_info.public_key_curve {
                    println!("  EC Curve: {}", curve);
                }
                if let Some(ref point) = cert_info.public_key_point {
                    println!("  EC Point: {}...", &point[..32.min(point.len())]);
                }

                println!("  Raw Public Key: {} bytes", cert_info.public_key_raw.len());
                println!();

                // Extensions
                println!("[ EXTENSIONS ]");

                // Basic Constraints
                if let Some(is_ca) = cert_info.is_ca {
                    println!("  Basic Constraints:");
                    println!("    CA: {}", is_ca);
                    if let Some(path_len) = cert_info.path_length_constraint {
                        println!("    Path Length Constraint: {}", path_len);
                    }
                }

                // Key Usage
                if let Some(ref key_usage) = cert_info.key_usage {
                    if !key_usage.is_empty() {
                        println!("  Key Usage:");
                        for usage in key_usage {
                            println!("    - {}", usage);
                        }
                    }
                }

                // Extended Key Usage
                if let Some(ref extended_key_usage) = cert_info.extended_key_usage {
                    if !extended_key_usage.is_empty() {
                        println!("  Extended Key Usage:");
                        for usage in extended_key_usage {
                            println!("    - {}", usage);
                        }
                    }
                }

                // Subject Alternative Names
                if let Some(ref sans) = cert_info.subject_alternative_names {
                    if !sans.is_empty() {
                        println!("  Subject Alternative Names:");
                        for san in sans {
                            println!("    - {} = {}", san.name_type, san.value);
                        }
                    }
                }

                // Issuer Alternative Names
                if let Some(ref ians) = cert_info.issuer_alternative_names {
                    if !ians.is_empty() {
                        println!("  Issuer Alternative Names:");
                        for ian in ians {
                            println!("    - {}", ian);
                        }
                    }
                }

                // Key Identifiers
                if let Some(ref ski) = cert_info.subject_key_identifier {
                    println!("  Subject Key Identifier: {}", ski);
                }

                if let Some(ref aki) = cert_info.authority_key_identifier {
                    println!("  Authority Key Identifier:");
                    if let Some(ref ki) = aki.key_identifier {
                        println!("    Key ID: {}", ki);
                    }
                    if let Some(ref issuers) = aki.authority_cert_issuer {
                        println!("    Cert Issuers:");
                        for issuer in issuers {
                            println!("      - {}", issuer);
                        }
                    }
                    if let Some(ref serial) = aki.authority_cert_serial {
                        println!("    Cert Serial: {}", serial);
                    }
                }

                // CRL Distribution Points
                if let Some(ref cdps) = cert_info.crl_distribution_points {
                    if !cdps.is_empty() {
                        println!("  CRL Distribution Points:");
                        for cdp in cdps {
                            println!("    - {}", cdp);
                        }
                    }
                }

                // Authority Info Access
                if let Some(ref aia) = cert_info.authority_info_access {
                    if !aia.is_empty() {
                        println!("  Authority Information Access:");
                        for access in aia {
                            println!("    - {}: {}", access.access_method, access.access_location);
                        }
                    }
                }

                // Certificate Policies
                if let Some(ref policies) = cert_info.certificate_policies {
                    if !policies.is_empty() {
                        println!("  Certificate Policies:");
                        for policy in policies {
                            println!("    - Policy ID: {}", policy.policy_identifier);
                            if let Some(ref qualifiers) = policy.policy_qualifiers {
                                for qualifier in qualifiers {
                                    println!("      Qualifier: {}", qualifier);
                                }
                            }
                        }
                    }
                }

                // Policy Mappings
                if let Some(ref mappings) = cert_info.policy_mappings {
                    if !mappings.is_empty() {
                        println!("  Policy Mappings:");
                        for mapping in mappings {
                            println!("    - Issuer Domain: {} -> Subject Domain: {}",
                                     mapping.issuer_domain_policy,
                                     mapping.subject_domain_policy);
                        }
                    }
                }

                // Policy Constraints
                if let Some(ref constraints) = cert_info.policy_constraints {
                    println!("  Policy Constraints:");
                    if let Some(explicit) = constraints.require_explicit_policy {
                        println!("    Require Explicit Policy: {}", explicit);
                    }
                    if let Some(inhibit) = constraints.inhibit_policy_mapping {
                        println!("    Inhibit Policy Mapping: {}", inhibit);
                    }
                }

                // Name Constraints
                if let Some(ref nc) = cert_info.name_constraints {
                    println!("  Name Constraints:");
                    if let Some(ref permitted) = nc.permitted_subtrees {
                        println!("    Permitted:");
                        for subtree in permitted {
                            println!("      - {}", subtree);
                        }
                    }
                    if let Some(ref excluded) = nc.excluded_subtrees {
                        println!("    Excluded:");
                        for subtree in excluded {
                            println!("      - {}", subtree);
                        }
                    }
                }

                // Inhibit Any Policy
                if let Some(iap) = cert_info.inhibit_any_policy {
                    println!("  Inhibit Any Policy: {}", iap);
                }

                // Freshest CRL
                if let Some(ref fcrl) = cert_info.freshest_crl {
                    if !fcrl.is_empty() {
                        println!("  Freshest CRL:");
                        for crl in fcrl {
                            println!("    - {}", crl);
                        }
                    }
                }

                // Subject Info Access
                if let Some(ref sia) = cert_info.subject_info_access {
                    if !sia.is_empty() {
                        println!("  Subject Information Access:");
                        for access in sia {
                            println!("    - {}: {}", access.access_method, access.access_location);
                        }
                    }
                }

                // Certificate Transparency
                if let Some(ref scts) = cert_info.ct_precert_scts {
                    if !scts.is_empty() {
                        println!("  Certificate Transparency SCTs:");
                        for sct in scts {
                            println!("    - Version: {}, Log ID: {}, Timestamp: {}, Algorithm: {}",
                                     sct.version, sct.log_id, sct.timestamp, sct.signature_algorithm);
                        }
                    }
                }

                // All Extensions Summary
                if !cert_info.extensions.is_empty() {
                    println!("\n  All Extensions Summary:");
                    for ext in &cert_info.extensions {
                        let critical_marker = if ext.critical { " [CRITICAL]" } else { "" };
                        println!("    - {} ({}){}",
                                 ext.oid_description,
                                 ext.oid,
                                 critical_marker);
                        if ext.raw_value.len() > 0 {
                            println!("      Raw value: {} bytes", ext.raw_value.len());
                        }
                    }
                }

                println!();

                // Raw Certificate Data
                println!("[ RAW DATA ]");
                println!("  DER Encoded Size: {} bytes", cert_info.der_encoded.len());

                println!("\n");
            }

            // Summary Statistics
            println!("{}", "=".repeat(80));
            println!("SUMMARY STATISTICS");
            println!("{}", "=".repeat(80));

            let ca_count = cert_infos.iter().filter(|c| c.is_ca == Some(true)).count();
            let end_entity_count = cert_infos.iter().filter(|c| c.is_ca == Some(false)).count();
            let unknown_ca_count = cert_infos.iter().filter(|c| c.is_ca.is_none()).count();

            println!("Total Certificates: {}", cert_infos.len());
            println!("CA Certificates: {}", ca_count);
            println!("End Entity Certificates: {}", end_entity_count);
            if unknown_ca_count > 0 {
                println!("Unknown CA Status: {}", unknown_ca_count);
            }

            // Collect unique algorithms
            let mut sig_algorithms = std::collections::HashSet::new();
            let mut key_algorithms = std::collections::HashSet::new();

            for cert in &cert_infos {
                sig_algorithms.insert(&cert.signature_algorithm_description);
                key_algorithms.insert(&cert.public_key_algorithm_description);
            }

            println!("\nSignature Algorithms Used:");
            for alg in sig_algorithms {
                println!("  - {}", alg);
            }

            println!("\nPublic Key Algorithms Used:");
            for alg in key_algorithms {
                println!("  - {}", alg);
            }
        }
        Err(e) => {
            eprintln!("Error processing certificate: {}", e);
        }
    }
}