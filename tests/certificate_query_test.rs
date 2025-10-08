use pem_processor::{CertificateInfo, CertificateQuery, ExtensionInfo};

fn create_test_rsa_cert() -> CertificateInfo {
    CertificateInfo {
        subject: "C=US, O=TestCorp, CN=Test RSA Certificate".to_string(),
        issuer: "C=US, O=TestCorp, CN=Test RSA CA".to_string(),
        serial_number: "123456".to_string(),
        signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
        signature_algorithm_description: "sha256WithRSAEncryption (1.2.840.113549.1.1.11)"
            .to_string(),
        signature_params: Some("NULL".to_string()),
        public_key_algorithm: "1.2.840.113549.1.1.1".to_string(),
        public_key_algorithm_description: "rsaEncryption (1.2.840.113549.1.1.1)".to_string(),
        public_key_size: Some(2048),
        validity_not_before: "Jan  1 00:00:00 2024 +00:00".to_string(),
        validity_not_after: "Jan  1 00:00:00 2025 +00:00".to_string(),
        is_ca: true,
        key_usage: vec!["Key Cert Sign".to_string(), "CRL Sign".to_string()],
        extended_key_usage: vec![],
        extensions: vec![
            ExtensionInfo {
                oid: "2.5.29.15".to_string(),
                oid_description: "keyUsage (2.5.29.15)".to_string(),
                critical: true,
            },
            ExtensionInfo {
                oid: "2.5.29.19".to_string(),
                oid_description: "basicConstraints (2.5.29.19)".to_string(),
                critical: true,
            },
        ],
    }
}

fn create_test_ecc_cert() -> CertificateInfo {
    CertificateInfo {
        subject: "C=US, O=TestCorp, CN=Test ECC Certificate".to_string(),
        issuer: "C=US, O=TestCorp, CN=Test ECC CA".to_string(),
        serial_number: "789012".to_string(),
        signature_algorithm: "1.2.840.10045.4.3.3".to_string(),
        signature_algorithm_description: "ecdsa-with-SHA384 (1.2.840.10045.4.3.3)".to_string(),
        signature_params: None,
        public_key_algorithm: "1.2.840.10045.2.1".to_string(),
        public_key_algorithm_description: "id-ecPublicKey (1.2.840.10045.2.1)".to_string(),
        public_key_size: Some(384),
        validity_not_before: "Jan  1 00:00:00 2024 +00:00".to_string(),
        validity_not_after: "Jan  1 00:00:00 2026 +00:00".to_string(),
        is_ca: false,
        key_usage: vec!["Digital Signature".to_string()],
        extended_key_usage: vec!["Server Authentication".to_string()],
        extensions: vec![ExtensionInfo {
            oid: "2.5.29.15".to_string(),
            oid_description: "keyUsage (2.5.29.15)".to_string(),
            critical: true,
        }],
    }
}

#[test]
fn test_certificate_query_new() {
    let query = CertificateQuery::new();
    assert!(query.public_key_algorithm_contains.is_none());
    assert!(query.public_key_size_min.is_none());
    assert!(query.is_ca.is_none());
}

#[test]
fn test_matches_empty_query() {
    let query = CertificateQuery::new();
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert)); // Empty query matches everything
}

#[test]
fn test_public_key_algorithm_contains_match() {
    let query = CertificateQuery::new().public_key_algorithm_contains(vec!["rsa".to_string()]);
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_public_key_algorithm_contains_no_match() {
    let query = CertificateQuery::new().public_key_algorithm_contains(vec!["ecc".to_string()]);
    let cert = create_test_rsa_cert();
    assert!(!query.matches(&cert));
}

#[test]
fn test_public_key_algorithm_contains_case_insensitive() {
    let query = CertificateQuery::new().public_key_algorithm_contains(vec!["RSA".to_string()]);
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_public_key_algorithm_contains_multiple_match() {
    let query = CertificateQuery::new()
        .public_key_algorithm_contains(vec!["rsa".to_string(), "dsa".to_string()]);
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert)); // Should match because RSA is in the list
}

#[test]
fn test_public_key_size_at_least_match() {
    let query = CertificateQuery::new().public_key_size_at_least(2048);
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_public_key_size_at_least_no_match() {
    let query = CertificateQuery::new().public_key_size_at_least(4096);
    let cert = create_test_rsa_cert(); // Has 2048-bit key
    assert!(!query.matches(&cert));
}

#[test]
fn test_public_key_size_exact_match() {
    let query = CertificateQuery {
        public_key_size_exact: Some(2048),
        ..Default::default()
    };
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_public_key_size_exact_no_match() {
    let query = CertificateQuery {
        public_key_size_exact: Some(1024),
        ..Default::default()
    };
    let cert = create_test_rsa_cert();
    assert!(!query.matches(&cert));
}

#[test]
fn test_is_ca_certificate_match() {
    let query = CertificateQuery::new().is_ca_certificate();
    let cert = create_test_rsa_cert(); // is_ca = true
    assert!(query.matches(&cert));
}

#[test]
fn test_is_ca_certificate_no_match() {
    let query = CertificateQuery::new().is_ca_certificate();
    let cert = create_test_ecc_cert(); // is_ca = false
    assert!(!query.matches(&cert));
}

#[test]
fn test_subject_contains_match() {
    let query = CertificateQuery::new().subject_contains("TestCorp".to_string());
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_subject_contains_no_match() {
    let query = CertificateQuery::new().subject_contains("AnotherCorp".to_string());
    let cert = create_test_rsa_cert();
    assert!(!query.matches(&cert));
}

#[test]
fn test_requires_key_usage_match() {
    let query = CertificateQuery::new().requires_key_usage(vec!["Key Cert Sign".to_string()]);
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_requires_key_usage_no_match() {
    let query = CertificateQuery::new().requires_key_usage(vec!["Email Protection".to_string()]);
    let cert = create_test_rsa_cert();
    assert!(!query.matches(&cert));
}

#[test]
fn test_requires_key_usage_multiple_match() {
    let query = CertificateQuery::new()
        .requires_key_usage(vec!["Key Cert Sign".to_string(), "CRL Sign".to_string()]);
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_requires_key_usage_multiple_partial_match() {
    let query = CertificateQuery::new().requires_key_usage(vec![
        "Key Cert Sign".to_string(),
        "Email Protection".to_string(),
    ]);
    let cert = create_test_rsa_cert(); // Has Key Cert Sign but not Email Protection
    assert!(!query.matches(&cert));
}

#[test]
fn test_signature_algorithm_contains_match() {
    let query = CertificateQuery::new().signature_algorithm_contains(vec!["sha256".to_string()]);
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_signature_algorithm_contains_no_match() {
    let query = CertificateQuery::new().signature_algorithm_contains(vec!["md5".to_string()]);
    let cert = create_test_rsa_cert();
    assert!(!query.matches(&cert));
}

#[test]
fn test_complex_query_match() {
    let query = CertificateQuery::new()
        .public_key_algorithm_contains(vec!["rsa".to_string()])
        .public_key_size_at_least(2048)
        .is_ca_certificate()
        .subject_contains("TestCorp".to_string())
        .signature_algorithm_contains(vec!["sha256".to_string()]);

    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_complex_query_partial_match() {
    let query = CertificateQuery::new()
        .public_key_algorithm_contains(vec!["rsa".to_string()])
        .public_key_size_at_least(4096) // This will fail - cert has 2048
        .is_ca_certificate()
        .subject_contains("TestCorp".to_string());

    let cert = create_test_rsa_cert();
    assert!(!query.matches(&cert)); // Fails because key size is too small
}

#[test]
fn test_has_extensions_containing_match() {
    let query = CertificateQuery {
        has_extensions_containing: Some(vec!["2.5.29.15".to_string()]), // keyUsage
        ..Default::default()
    };
    let cert = create_test_rsa_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_has_extensions_containing_no_match() {
    let query = CertificateQuery {
        has_extensions_containing: Some(vec!["1.3.6.1.5.5.7.1.1".to_string()]), // authorityInfoAccess
        ..Default::default()
    };
    let cert = create_test_rsa_cert();
    assert!(!query.matches(&cert));
}

#[test]
fn test_ecc_certificate_matching() {
    let query = CertificateQuery::new()
        .public_key_algorithm_contains(vec!["ec".to_string()])
        .signature_algorithm_contains(vec!["ecdsa".to_string()]);

    let cert = create_test_ecc_cert();
    assert!(query.matches(&cert));
}

#[test]
fn test_non_ca_certificate_filtering() {
    let query = CertificateQuery {
        is_ca: Some(false),
        ..Default::default()
    };

    let cert = create_test_ecc_cert(); // is_ca = false
    assert!(query.matches(&cert));

    let ca_cert = create_test_rsa_cert(); // is_ca = true
    assert!(!query.matches(&ca_cert));
}
