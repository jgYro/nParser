use std::fs;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub signature_algorithm: String,
    pub signature_params: Option<String>,
    pub public_key_algorithm: String,
    pub public_key_size: Option<usize>,
    pub validity_not_before: String,
    pub validity_not_after: String,
    pub is_ca: bool,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
}

/// Parses a PEM file containing one or more X.509 certificates and returns detailed information.
///
/// PEM files can contain multiple certificates for several reasons:
/// - Certificate chains (Root CA → Intermediate CA → End certificate)
/// - Certificate bundles (like cacert.pem with trusted root CAs)
/// - Multiple certificates for different purposes
///
/// # Arguments
/// * `pem_path` - Path to the PEM file to parse
///
/// # Returns
/// * `Ok(Vec<CertificateInfo>)` - Vector of parsed certificate information
/// * `Err(Box<dyn std::error::Error>)` - Parse error
pub fn parse_certificates_from_pem(
    pem_path: &str,
) -> Result<Vec<CertificateInfo>, Box<dyn std::error::Error>> {
    let pem_data = fs::read(pem_path)?;
    let mut cert_infos = Vec::new();

    // Parse all certificates in the PEM file
    let mut remaining = &pem_data[..];

    while !remaining.is_empty() {
        match parse_x509_pem(remaining) {
            Ok((rest, pem)) => {
                remaining = rest;

                let cert = pem.parse_x509()?;

                // Extract basic certificate information
                let subject = cert.subject.to_string();
                let issuer = cert.issuer.to_string();
                let serial_number = format!("{:x}", cert.serial);

                // Signature algorithm details
                let sig_alg = &cert.signature_algorithm;
                let signature_algorithm = sig_alg.algorithm.to_string();
                let signature_params = sig_alg.parameters.as_ref().map(|p| {
                    // For RSA signatures, parameters are typically NULL (empty)
                    if p.data.is_empty() && p.header.tag().0 == 5 {
                        "NULL".to_string()
                    } else {
                        format!("Present ({} bytes)", p.data.len())
                    }
                });

                // Public key information
                let public_key_algorithm = cert.public_key().algorithm.algorithm.to_string();
                let public_key_size = match cert.public_key().parsed() {
                    Ok(key) => match key {
                        PublicKey::RSA(rsa) => Some(rsa.key_size()),
                        PublicKey::EC(ec) => Some(ec.key_size()),
                        _ => None,
                    },
                    Err(_) => None,
                };

                // Validity period
                let validity_not_before = cert.validity.not_before.to_string();
                let validity_not_after = cert.validity.not_after.to_string();

                // Extensions
                let mut is_ca = false;
                let mut key_usage = Vec::new();
                let mut extended_key_usage = Vec::new();

                for ext in cert.extensions() {
                    if ext.oid == x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS {
                        if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
                            is_ca = bc.ca;
                        }
                    } else if ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE {
                        if let ParsedExtension::KeyUsage(usage) = ext.parsed_extension() {
                            if usage.digital_signature() {
                                key_usage.push("Digital Signature".to_string());
                            }
                            if usage.non_repudiation() {
                                key_usage.push("Non Repudiation".to_string());
                            }
                            if usage.key_encipherment() {
                                key_usage.push("Key Encipherment".to_string());
                            }
                            if usage.data_encipherment() {
                                key_usage.push("Data Encipherment".to_string());
                            }
                            if usage.key_agreement() {
                                key_usage.push("Key Agreement".to_string());
                            }
                            if usage.key_cert_sign() {
                                key_usage.push("Key Cert Sign".to_string());
                            }
                            if usage.crl_sign() {
                                key_usage.push("CRL Sign".to_string());
                            }
                            if usage.encipher_only() {
                                key_usage.push("Encipher Only".to_string());
                            }
                            if usage.decipher_only() {
                                key_usage.push("Decipher Only".to_string());
                            }
                        }
                    } else if ext.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE
                    {
                        if let ParsedExtension::ExtendedKeyUsage(usage) = ext.parsed_extension() {
                            for oid in &usage.other {
                                extended_key_usage.push(oid.to_string());
                            }
                            if usage.server_auth {
                                extended_key_usage.push("Server Authentication".to_string());
                            }
                            if usage.client_auth {
                                extended_key_usage.push("Client Authentication".to_string());
                            }
                            if usage.code_signing {
                                extended_key_usage.push("Code Signing".to_string());
                            }
                            if usage.email_protection {
                                extended_key_usage.push("Email Protection".to_string());
                            }
                            if usage.time_stamping {
                                extended_key_usage.push("Time Stamping".to_string());
                            }
                            if usage.ocsp_signing {
                                extended_key_usage.push("OCSP Signing".to_string());
                            }
                        }
                    }
                }

                cert_infos.push(CertificateInfo {
                    subject,
                    issuer,
                    serial_number,
                    signature_algorithm,
                    signature_params,
                    public_key_algorithm,
                    public_key_size,
                    validity_not_before,
                    validity_not_after,
                    is_ca,
                    key_usage,
                    extended_key_usage,
                });
            }
            Err(_) => break,
        }
    }

    Ok(cert_infos)
}

/// Parses X.509 certificates from PEM data (bytes) and returns detailed information.
///
/// This function works with raw certificate data rather than reading from a file.
///
/// # Arguments
/// * `pem_data` - Raw PEM data as bytes
///
/// # Returns
/// * `Ok(Vec<CertificateInfo>)` - Vector of parsed certificate information
/// * `Err(Box<dyn std::error::Error>)` - Parse error
pub fn parse_certificates_from_bytes(
    pem_data: &[u8],
) -> Result<Vec<CertificateInfo>, Box<dyn std::error::Error>> {
    let mut cert_infos = Vec::new();
    let mut remaining = pem_data;

    while !remaining.is_empty() {
        match parse_x509_pem(remaining) {
            Ok((rest, pem)) => {
                remaining = rest;

                let cert = pem.parse_x509()?;

                // Extract basic certificate information
                let subject = cert.subject.to_string();
                let issuer = cert.issuer.to_string();
                let serial_number = format!("{:x}", cert.serial);

                // Signature algorithm details
                let sig_alg = &cert.signature_algorithm;
                let signature_algorithm = sig_alg.algorithm.to_string();
                let signature_params = sig_alg.parameters.as_ref().map(|p| {
                    // For RSA signatures, parameters are typically NULL (empty)
                    if p.data.is_empty() && p.header.tag().0 == 5 {
                        "NULL".to_string()
                    } else {
                        format!("Present ({} bytes)", p.data.len())
                    }
                });

                // Public key information
                let public_key_algorithm = cert.public_key().algorithm.algorithm.to_string();
                let public_key_size = match cert.public_key().parsed() {
                    Ok(key) => match key {
                        PublicKey::RSA(rsa) => Some(rsa.key_size()),
                        PublicKey::EC(ec) => Some(ec.key_size()),
                        _ => None,
                    },
                    Err(_) => None,
                };

                // Validity period
                let validity_not_before = cert.validity.not_before.to_string();
                let validity_not_after = cert.validity.not_after.to_string();

                // Extensions
                let mut is_ca = false;
                let mut key_usage = Vec::new();
                let mut extended_key_usage = Vec::new();

                for ext in cert.extensions() {
                    if ext.oid == x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS {
                        if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
                            is_ca = bc.ca;
                        }
                    } else if ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE {
                        if let ParsedExtension::KeyUsage(usage) = ext.parsed_extension() {
                            if usage.digital_signature() {
                                key_usage.push("Digital Signature".to_string());
                            }
                            if usage.non_repudiation() {
                                key_usage.push("Non Repudiation".to_string());
                            }
                            if usage.key_encipherment() {
                                key_usage.push("Key Encipherment".to_string());
                            }
                            if usage.data_encipherment() {
                                key_usage.push("Data Encipherment".to_string());
                            }
                            if usage.key_agreement() {
                                key_usage.push("Key Agreement".to_string());
                            }
                            if usage.key_cert_sign() {
                                key_usage.push("Key Cert Sign".to_string());
                            }
                            if usage.crl_sign() {
                                key_usage.push("CRL Sign".to_string());
                            }
                            if usage.encipher_only() {
                                key_usage.push("Encipher Only".to_string());
                            }
                            if usage.decipher_only() {
                                key_usage.push("Decipher Only".to_string());
                            }
                        }
                    } else if ext.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE
                    {
                        if let ParsedExtension::ExtendedKeyUsage(usage) = ext.parsed_extension() {
                            for oid in &usage.other {
                                extended_key_usage.push(oid.to_string());
                            }
                            if usage.server_auth {
                                extended_key_usage.push("Server Authentication".to_string());
                            }
                            if usage.client_auth {
                                extended_key_usage.push("Client Authentication".to_string());
                            }
                            if usage.code_signing {
                                extended_key_usage.push("Code Signing".to_string());
                            }
                            if usage.email_protection {
                                extended_key_usage.push("Email Protection".to_string());
                            }
                            if usage.time_stamping {
                                extended_key_usage.push("Time Stamping".to_string());
                            }
                            if usage.ocsp_signing {
                                extended_key_usage.push("OCSP Signing".to_string());
                            }
                        }
                    }
                }

                cert_infos.push(CertificateInfo {
                    subject,
                    issuer,
                    serial_number,
                    signature_algorithm,
                    signature_params,
                    public_key_algorithm,
                    public_key_size,
                    validity_not_before,
                    validity_not_after,
                    is_ca,
                    key_usage,
                    extended_key_usage,
                });
            }
            Err(_) => break,
        }
    }

    Ok(cert_infos)
}
