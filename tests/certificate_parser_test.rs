use pem_processor::{
    create_oid_registry, format_oid_with_description, parse_certificates_from_bytes,
    parse_certificates_from_pem,
};
use x509_parser::der_parser;

// Test data based on actual certificates from cacert.pem analysis
const TEST_PEM_SINGLE_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
AQUFAAOCAQEA1nPnfE920I2/4CqIZLg4fP+tqnPtF/kB+x8XKxzDjIgXIy2/X2vW
eTMN3ePuZuHMY34dq93Y0Vk3jvp+WlnzFUw2KCrPZiDxpLUhj64W1EXpPjLPYY1g
kH7Sn2EfKwHh8Z2Yf5gXFSj4D8VPW3X/9X3lZBDl/aIjXKzX3dMO2nFZyYfQjK/r
1c7NmZP+8kzrOqX6DhVJcMfTxN1VX3FZg4fFJ0+EF3y+NiFY2DUzLdVZZpj9vyNX
2lKy3yOf8y8CgVP4ckqZ0m7KzBnN6SeSJQE2Yvn3MzY8X2hKZnKcNzH3JvLDNZ3/
dCQGlGqgHKq9qV+HLgZZ4Q4ZjKbGy/OQ3g==
-----END CERTIFICATE-----"#;

#[test]
fn test_parse_certificates_from_bytes_single_cert() {
    let result = parse_certificates_from_bytes(TEST_PEM_SINGLE_CERT.as_bytes());
    assert!(result.is_ok());

    let certs = result.unwrap();
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];
    assert!(cert.subject.contains("GlobalSign"));
    assert!(cert.issuer.contains("GlobalSign"));
    assert_eq!(cert.is_ca, true);
}

#[test]
fn test_parse_certificates_from_bytes_empty_data() {
    let result = parse_certificates_from_bytes(&[]);
    assert!(result.is_ok());

    let certs = result.unwrap();
    assert_eq!(certs.len(), 0);
}

#[test]
fn test_parse_certificates_from_bytes_invalid_pem() {
    let invalid_pem = b"This is not a valid PEM file";
    let result = parse_certificates_from_bytes(invalid_pem);
    assert!(result.is_ok());

    let certs = result.unwrap();
    assert_eq!(certs.len(), 0); // Should return empty vector for invalid PEM
}

#[test]
fn test_parse_certificates_from_pem_nonexistent_file() {
    let result = parse_certificates_from_pem("nonexistent_file.pem");
    assert!(result.is_err()); // Should fail when file doesn't exist
}

#[test]
fn test_certificate_info_fields_populated() {
    let result = parse_certificates_from_bytes(TEST_PEM_SINGLE_CERT.as_bytes());
    assert!(result.is_ok());

    let certs = result.unwrap();
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];

    // Test that all major fields are populated
    assert!(!cert.subject.is_empty());
    assert!(!cert.issuer.is_empty());
    assert!(!cert.serial_number.is_empty());
    assert!(!cert.signature_algorithm.is_empty());
    assert!(!cert.signature_algorithm_description.is_empty());
    assert!(!cert.public_key_algorithm.is_empty());
    assert!(!cert.public_key_algorithm_description.is_empty());
    assert!(!cert.validity_not_before.is_empty());
    assert!(!cert.validity_not_after.is_empty());
    assert!(cert.public_key_size.is_some());
}

#[test]
fn test_oid_descriptions_are_enhanced() {
    let result = parse_certificates_from_bytes(TEST_PEM_SINGLE_CERT.as_bytes());
    assert!(result.is_ok());

    let certs = result.unwrap();
    let cert = &certs[0];

    // Test that OID descriptions are enhanced (should contain readable names)
    assert!(
        cert.signature_algorithm_description.contains("RSA")
            || cert.signature_algorithm_description.contains("sha")
    );
    assert!(
        cert.public_key_algorithm_description.contains("rsa")
            || cert.public_key_algorithm_description.contains("RSA")
    );
}

#[test]
fn test_extension_info_structure() {
    let result = parse_certificates_from_bytes(TEST_PEM_SINGLE_CERT.as_bytes());
    assert!(result.is_ok());

    let certs = result.unwrap();
    let cert = &certs[0];

    // Test that extensions are properly parsed
    assert!(!cert.extensions.is_empty());

    for ext in &cert.extensions {
        assert!(!ext.oid.is_empty());
        assert!(!ext.oid_description.is_empty());
        // Critical flag should be a valid boolean (no test needed, it's always valid)
    }
}

#[test]
fn test_create_oid_registry() {
    let _registry = create_oid_registry();
    // Test that registry is created successfully
    // We can't easily test the contents without accessing internals,
    // but we can verify it doesn't panic
    assert!(true); // Registry creation succeeded if we reach here
}

#[test]
fn test_format_oid_with_description_valid_oid() {
    let registry = create_oid_registry();

    // Test with a known OID (RSA encryption)
    if let Ok(oid) = der_parser::oid::Oid::from(&[1, 2, 840, 113549, 1, 1, 1]) {
        let result = format_oid_with_description(&oid, &registry);
        // Should contain either the description or the OID itself
        assert!(!result.is_empty());
        assert!(result.contains("1.2.840.113549.1.1.1") || result.to_lowercase().contains("rsa"));
    }
}

#[test]
fn test_format_oid_with_description_unknown_oid() {
    let registry = create_oid_registry();

    // Test with an unknown/custom OID
    if let Ok(oid) = der_parser::oid::Oid::from(&[1, 2, 3, 4, 5]) {
        let result = format_oid_with_description(&oid, &registry);
        // Should return the OID string itself for unknown OIDs
        assert_eq!(result, "1.2.3.4.5");
    }
}
