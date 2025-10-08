use pem_processor::{CertificateQuery, parse_certificates_from_pem};

#[test]
fn test_real_certificate_filtering_rsa_4096() {
    let path =
        "/Users/jerichogregory/Library/Python/3.13/lib/python/site-packages/certifi/cacert.pem";

    // Parse actual certificates
    let certs = parse_certificates_from_pem(path).expect("Failed to parse certificates");
    assert!(!certs.is_empty(), "Should have parsed certificates");

    // Query for RSA certificates with 4096-bit keys
    let query = CertificateQuery::new()
        .public_key_algorithm_contains(vec!["rsa".to_string()])
        .public_key_size_at_least(4096);

    let matching_certs: Vec<_> = certs.iter().filter(|cert| query.matches(cert)).collect();

    println!(
        "Found {} RSA certificates with >= 4096-bit keys",
        matching_certs.len()
    );
    assert!(
        !matching_certs.is_empty(),
        "Should find some 4096-bit RSA certificates"
    );

    // Verify all matches are actually RSA and >= 4096 bits
    for cert in matching_certs {
        assert!(
            cert.public_key_algorithm_description
                .to_lowercase()
                .contains("rsa")
        );
        assert!(cert.public_key_size.unwrap_or(0) >= 4096);
    }
}

#[test]
fn test_real_certificate_filtering_ca_certificates() {
    let path =
        "/Users/jerichogregory/Library/Python/3.13/lib/python/site-packages/certifi/cacert.pem";

    let certs = parse_certificates_from_pem(path).expect("Failed to parse certificates");

    // Query for CA certificates
    let query = CertificateQuery::new().is_ca_certificate();

    let ca_certs: Vec<_> = certs.iter().filter(|cert| query.matches(cert)).collect();

    println!("Found {} CA certificates", ca_certs.len());
    // Most certificates in cacert.pem should be CA certificates
    assert!(
        ca_certs.len() > certs.len() / 2,
        "Most certificates should be CA certificates"
    );

    // Verify all matches are actually CAs
    for cert in ca_certs {
        assert!(cert.is_ca, "Certificate should be a CA");
    }
}

#[test]
fn test_real_certificate_filtering_sha256_signatures() {
    let path =
        "/Users/jerichogregory/Library/Python/3.13/lib/python/site-packages/certifi/cacert.pem";

    let certs = parse_certificates_from_pem(path).expect("Failed to parse certificates");

    // Query for SHA-256 signed certificates
    let query = CertificateQuery::new().signature_algorithm_contains(vec!["sha256".to_string()]);

    let sha256_certs: Vec<_> = certs.iter().filter(|cert| query.matches(cert)).collect();

    println!("Found {} SHA-256 signed certificates", sha256_certs.len());
    assert!(
        !sha256_certs.is_empty(),
        "Should find some SHA-256 certificates"
    );

    // Verify all matches contain SHA-256
    for cert in sha256_certs {
        assert!(
            cert.signature_algorithm_description
                .to_lowercase()
                .contains("sha256")
        );
    }
}

#[test]
fn test_real_certificate_filtering_globalsign() {
    let path =
        "/Users/jerichogregory/Library/Python/3.13/lib/python/site-packages/certifi/cacert.pem";

    let certs = parse_certificates_from_pem(path).expect("Failed to parse certificates");

    // Query for GlobalSign certificates
    let query = CertificateQuery::new().subject_contains("GlobalSign".to_string());

    let globalsign_certs: Vec<_> = certs.iter().filter(|cert| query.matches(cert)).collect();

    println!("Found {} GlobalSign certificates", globalsign_certs.len());
    assert!(
        !globalsign_certs.is_empty(),
        "Should find GlobalSign certificates"
    );

    // Verify all matches contain GlobalSign in subject
    for cert in globalsign_certs {
        assert!(cert.subject.contains("GlobalSign"));
    }
}

#[test]
fn test_real_certificate_complex_query() {
    let path =
        "/Users/jerichogregory/Library/Python/3.13/lib/python/site-packages/certifi/cacert.pem";

    let certs = parse_certificates_from_pem(path).expect("Failed to parse certificates");

    // Complex query: RSA CA certificates with >= 2048-bit keys and Key Cert Sign capability
    let query = CertificateQuery::new()
        .public_key_algorithm_contains(vec!["rsa".to_string()])
        .public_key_size_at_least(2048)
        .is_ca_certificate()
        .requires_key_usage(vec!["Key Cert Sign".to_string()]);

    let matching_certs: Vec<_> = certs.iter().filter(|cert| query.matches(cert)).collect();

    println!(
        "Found {} certificates matching complex criteria",
        matching_certs.len()
    );
    assert!(
        !matching_certs.is_empty(),
        "Should find certificates matching complex criteria"
    );

    // Verify all conditions are met
    for cert in matching_certs {
        assert!(
            cert.public_key_algorithm_description
                .to_lowercase()
                .contains("rsa")
        );
        assert!(cert.public_key_size.unwrap_or(0) >= 2048);
        assert!(cert.is_ca);
        assert!(cert.key_usage.contains(&"Key Cert Sign".to_string()));
    }
}
