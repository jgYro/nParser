use ::oid_registry::{OidRegistry, format_oid};
use std::fs;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::X509Name;
use std::collections::HashMap;

/// Creates an OID registry with crypto and X.509 features enabled
pub fn create_oid_registry() -> OidRegistry<'static> {
    OidRegistry::default().with_crypto().with_x509()
}

/// Formats an OID with its human-readable description if available
pub fn format_oid_with_description(oid: &der_parser::oid::Oid, registry: &OidRegistry) -> String {
    // Convert der_parser::Oid to oid_registry::Oid
    if let Ok(oid_reg) = <::oid_registry::Oid as std::str::FromStr>::from_str(&oid.to_string()) {
        format_oid(&oid_reg, registry)
    } else {
        oid.to_string()
    }
}

/// Extract individual components from an X509Name
fn extract_name_components(name: &X509Name) -> HashMap<String, String> {
    let mut components = HashMap::new();

    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid_str = attr.attr_type().to_string();
            let value = attr.attr_value().as_str().unwrap_or("").to_string();

            // Map common OIDs to field names
            match oid_str.as_str() {
                "2.5.4.3" => { components.insert("CN".to_string(), value.clone()); },
                "2.5.4.10" => { components.insert("O".to_string(), value.clone()); },
                "2.5.4.11" => { components.insert("OU".to_string(), value.clone()); },
                "2.5.4.6" => { components.insert("C".to_string(), value.clone()); },
                "2.5.4.8" => { components.insert("ST".to_string(), value.clone()); },
                "2.5.4.7" => { components.insert("L".to_string(), value.clone()); },
                "1.2.840.113549.1.9.1" => { components.insert("emailAddress".to_string(), value); },
                "2.5.4.5" => { components.insert("serialNumber".to_string(), value); },
                "2.5.4.4" => { components.insert("SN".to_string(), value); },
                "2.5.4.42" => { components.insert("GN".to_string(), value); },
                "2.5.4.12" => { components.insert("title".to_string(), value); },
                "2.5.4.43" => { components.insert("initials".to_string(), value); },
                "2.5.4.44" => { components.insert("generationQualifier".to_string(), value); },
                "2.5.4.46" => { components.insert("dnQualifier".to_string(), value); },
                "2.5.4.65" => { components.insert("pseudonym".to_string(), value); },
                "0.9.2342.19200300.100.1.25" => { components.insert("DC".to_string(), value); },
                _ => { components.insert(oid_str, value); }
            }
        }
    }

    components
}

/// Calculate SHA-1 fingerprint of certificate
fn calculate_sha1_fingerprint(der_data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, der_data);
    let mut hex = String::new();
    for byte in digest.as_ref() {
        write!(&mut hex, "{:02X}", byte).unwrap();
    }
    hex
}

/// Calculate SHA-256 fingerprint of certificate
fn calculate_sha256_fingerprint(der_data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = ring::digest::digest(&ring::digest::SHA256, der_data);
    let mut hex = String::new();
    for byte in digest.as_ref() {
        write!(&mut hex, "{:02X}", byte).unwrap();
    }
    hex
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct CertificateInfo {
    // Core certificate fields
    pub version: i32,
    pub serial_number: String,

    // Subject and Issuer
    pub subject: String,
    pub subject_common_name: Option<String>,
    pub subject_organization: Option<String>,
    pub subject_organizational_unit: Option<String>,
    pub subject_country: Option<String>,
    pub subject_state_province: Option<String>,
    pub subject_locality: Option<String>,
    pub subject_email: Option<String>,

    pub issuer: String,
    pub issuer_common_name: Option<String>,
    pub issuer_organization: Option<String>,
    pub issuer_organizational_unit: Option<String>,
    pub issuer_country: Option<String>,
    pub issuer_state_province: Option<String>,
    pub issuer_locality: Option<String>,
    pub issuer_email: Option<String>,

    // Validity
    pub validity_not_before: String,
    pub validity_not_after: String,

    // Signature
    pub signature_algorithm: String,
    pub signature_algorithm_description: String,
    pub signature_params: Option<String>,
    pub signature_value: Vec<u8>,

    // Public Key
    pub public_key_algorithm: String,
    pub public_key_algorithm_description: String,
    pub public_key_size: Option<usize>,
    pub public_key_params: Option<String>,
    pub public_key_raw: Vec<u8>,
    pub public_key_modulus: Option<String>,  // For RSA
    pub public_key_exponent: Option<String>, // For RSA
    pub public_key_curve: Option<String>,    // For ECC
    pub public_key_point: Option<String>,    // For ECC

    // Extensions - Standard
    pub is_ca: Option<bool>,
    pub path_length_constraint: Option<u32>,
    pub key_usage: Option<Vec<String>>,
    pub extended_key_usage: Option<Vec<String>>,
    pub subject_alternative_names: Option<Vec<SubjectAlternativeName>>,
    pub issuer_alternative_names: Option<Vec<String>>,
    pub subject_key_identifier: Option<String>,
    pub authority_key_identifier: Option<AuthorityKeyIdentifier>,
    pub crl_distribution_points: Option<Vec<String>>,
    pub authority_info_access: Option<Vec<AuthorityInfoAccess>>,
    pub certificate_policies: Option<Vec<CertificatePolicy>>,
    pub policy_mappings: Option<Vec<PolicyMapping>>,
    pub policy_constraints: Option<PolicyConstraints>,
    pub name_constraints: Option<NameConstraints>,
    pub inhibit_any_policy: Option<u32>,
    pub freshest_crl: Option<Vec<String>>,
    pub subject_info_access: Option<Vec<SubjectInfoAccess>>,
    pub ct_precert_scts: Option<Vec<SignedCertificateTimestamp>>,

    // All extensions (raw)
    pub extensions: Vec<ExtensionInfo>,

    // Certificate fingerprints
    pub sha1_fingerprint: Option<String>,
    pub sha256_fingerprint: Option<String>,

    // Raw certificate data
    pub der_encoded: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtensionInfo {
    pub oid: String,
    pub oid_description: String,
    pub critical: bool,
    pub raw_value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct SubjectAlternativeName {
    pub name_type: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthorityKeyIdentifier {
    pub key_identifier: Option<String>,
    pub authority_cert_issuer: Option<Vec<String>>,
    pub authority_cert_serial: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthorityInfoAccess {
    pub access_method: String,
    pub access_location: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct SubjectInfoAccess {
    pub access_method: String,
    pub access_location: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct CertificatePolicy {
    pub policy_identifier: String,
    pub policy_qualifiers: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyMapping {
    pub issuer_domain_policy: String,
    pub subject_domain_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyConstraints {
    pub require_explicit_policy: Option<u32>,
    pub inhibit_policy_mapping: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct NameConstraints {
    pub permitted_subtrees: Option<Vec<String>>,
    pub excluded_subtrees: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedCertificateTimestamp {
    pub version: u8,
    pub log_id: String,
    pub timestamp: String,
    pub signature_algorithm: String,
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
    parse_certificates_from_bytes(&pem_data)
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

    // Create OID registry for enhanced descriptions
    let oid_registry = create_oid_registry();

    while !remaining.is_empty() {
        match parse_x509_pem(remaining) {
            Ok((rest, pem)) => {
                remaining = rest;

                let cert = pem.parse_x509()?;
                let der_data = &pem.contents;

                // Extract certificate version
                let version = match cert.version {
                    X509Version::V1 => 1,
                    X509Version::V2 => 2,
                    X509Version::V3 => 3,
                    _ => 0, // Unknown version
                };

                // Extract subject components
                let subject = cert.subject.to_string();
                let subject_components = extract_name_components(&cert.subject);
                let subject_common_name = subject_components.get("CN").cloned();
                let subject_organization = subject_components.get("O").cloned();
                let subject_organizational_unit = subject_components.get("OU").cloned();
                let subject_country = subject_components.get("C").cloned();
                let subject_state_province = subject_components.get("ST").cloned();
                let subject_locality = subject_components.get("L").cloned();
                let subject_email = subject_components.get("emailAddress").cloned();

                // Extract issuer components
                let issuer = cert.issuer.to_string();
                let issuer_components = extract_name_components(&cert.issuer);
                let issuer_common_name = issuer_components.get("CN").cloned();
                let issuer_organization = issuer_components.get("O").cloned();
                let issuer_organizational_unit = issuer_components.get("OU").cloned();
                let issuer_country = issuer_components.get("C").cloned();
                let issuer_state_province = issuer_components.get("ST").cloned();
                let issuer_locality = issuer_components.get("L").cloned();
                let issuer_email = issuer_components.get("emailAddress").cloned();

                // Serial number
                let serial_number = format!("{:x}", cert.serial);

                // Validity period
                let validity_not_before = cert.validity.not_before.to_string();
                let validity_not_after = cert.validity.not_after.to_string();

                // Signature algorithm details
                let sig_alg = &cert.signature_algorithm;
                let signature_algorithm = sig_alg.algorithm.to_string();
                let signature_algorithm_description =
                    format_oid_with_description(&sig_alg.algorithm, &oid_registry);
                let signature_params = sig_alg.parameters.as_ref().map(|p| {
                    if p.data.is_empty() && p.header.tag().0 == 5 {
                        "NULL".to_string()
                    } else {
                        format!("Present ({} bytes)", p.data.len())
                    }
                });
                let signature_value = cert.signature_value.data.to_vec();

                // Public key information
                let public_key_algorithm = cert.public_key().algorithm.algorithm.to_string();
                let public_key_algorithm_description = format_oid_with_description(
                    &cert.public_key().algorithm.algorithm,
                    &oid_registry,
                );
                let public_key_raw = cert.public_key().subject_public_key.data.to_vec();
                let public_key_params = cert.public_key().algorithm.parameters.as_ref().map(|p| {
                    if p.data.is_empty() && p.header.tag().0 == 5 {
                        "NULL".to_string()
                    } else {
                        format!("{:?}", p)
                    }
                });

                // Extract public key details based on algorithm
                let mut public_key_size = None;
                let mut public_key_modulus = None;
                let mut public_key_exponent = None;
                let public_key_curve = None;
                let mut public_key_point = None;

                match cert.public_key().parsed() {
                    Ok(key) => match key {
                        PublicKey::RSA(rsa) => {
                            public_key_size = Some(rsa.key_size());
                            public_key_modulus = Some(hex::encode(rsa.modulus));
                            public_key_exponent = Some(hex::encode(rsa.exponent));
                        }
                        PublicKey::EC(ec) => {
                            public_key_size = Some(ec.key_size());
                            // EC curve information is typically in the algorithm parameters
                            // The ECPoint struct doesn't have an algorithm() method
                            public_key_point = Some(hex::encode(ec.data()));
                        }
                        PublicKey::DSA(_dsa) => {
                            // DSA key details if needed
                        }
                        _ => {}
                    },
                    Err(_) => {}
                }

                // Process extensions
                let mut is_ca = None;
                let mut path_length_constraint = None;
                let mut key_usage = None;
                let mut extended_key_usage = None;
                let mut subject_alternative_names = None;
                let mut issuer_alternative_names = None;
                let mut subject_key_identifier = None;
                let mut authority_key_identifier = None;
                let mut crl_distribution_points = None;
                let mut authority_info_access = None;
                let mut certificate_policies = None;
                let mut policy_mappings = None;
                let mut policy_constraints = None;
                let mut name_constraints = None;
                let mut inhibit_any_policy = None;
                let freshest_crl = None;
                let subject_info_access = None;
                let ct_precert_scts = None;

                let mut extensions = Vec::new();

                for ext in cert.extensions() {
                    // Add raw extension info
                    extensions.push(ExtensionInfo {
                        oid: ext.oid.to_string(),
                        oid_description: format_oid_with_description(&ext.oid, &oid_registry),
                        critical: ext.critical,
                        raw_value: ext.value.to_vec(),
                    });

                    // Process specific extensions
                    match ext.parsed_extension() {
                        ParsedExtension::BasicConstraints(bc) => {
                            is_ca = Some(bc.ca);
                            path_length_constraint = bc.path_len_constraint;
                        }
                        ParsedExtension::KeyUsage(usage) => {
                            let mut usages = Vec::new();
                            if usage.digital_signature() { usages.push("Digital Signature".to_string()); }
                            if usage.non_repudiation() { usages.push("Non Repudiation".to_string()); }
                            if usage.key_encipherment() { usages.push("Key Encipherment".to_string()); }
                            if usage.data_encipherment() { usages.push("Data Encipherment".to_string()); }
                            if usage.key_agreement() { usages.push("Key Agreement".to_string()); }
                            if usage.key_cert_sign() { usages.push("Key Cert Sign".to_string()); }
                            if usage.crl_sign() { usages.push("CRL Sign".to_string()); }
                            if usage.encipher_only() { usages.push("Encipher Only".to_string()); }
                            if usage.decipher_only() { usages.push("Decipher Only".to_string()); }
                            if !usages.is_empty() {
                                key_usage = Some(usages);
                            }
                        }
                        ParsedExtension::ExtendedKeyUsage(usage) => {
                            let mut usages = Vec::new();
                            if usage.server_auth { usages.push("Server Authentication".to_string()); }
                            if usage.client_auth { usages.push("Client Authentication".to_string()); }
                            if usage.code_signing { usages.push("Code Signing".to_string()); }
                            if usage.email_protection { usages.push("Email Protection".to_string()); }
                            if usage.time_stamping { usages.push("Time Stamping".to_string()); }
                            if usage.ocsp_signing { usages.push("OCSP Signing".to_string()); }
                            for oid in &usage.other {
                                usages.push(format_oid_with_description(oid, &oid_registry));
                            }
                            if !usages.is_empty() {
                                extended_key_usage = Some(usages);
                            }
                        }
                        ParsedExtension::SubjectAlternativeName(san) => {
                            let mut names = Vec::new();
                            for name in &san.general_names {
                                let (name_type, value) = match name {
                                    GeneralName::DNSName(dns) => ("DNS".to_string(), dns.to_string()),
                                    GeneralName::RFC822Name(email) => ("Email".to_string(), email.to_string()),
                                    GeneralName::URI(uri) => ("URI".to_string(), uri.to_string()),
                                    GeneralName::IPAddress(ip) => {
                                        let ip_str = if ip.len() == 4 {
                                            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                                        } else if ip.len() == 16 {
                                            // IPv6
                                            format!("IPv6:{:?}", ip)
                                        } else {
                                            hex::encode(ip)
                                        };
                                        ("IP".to_string(), ip_str)
                                    }
                                    GeneralName::DirectoryName(dn) => ("DirectoryName".to_string(), format!("{:?}", dn)),
                                    GeneralName::RegisteredID(oid) => ("RegisteredID".to_string(), oid.to_string()),
                                    GeneralName::OtherName(oid, _) => ("OtherName".to_string(), oid.to_string()),
                                    _ => ("Unknown".to_string(), "Unknown".to_string()),
                                };
                                names.push(SubjectAlternativeName { name_type, value });
                            }
                            if !names.is_empty() {
                                subject_alternative_names = Some(names);
                            }
                        }
                        ParsedExtension::IssuerAlternativeName(ian) => {
                            let mut names = Vec::new();
                            for name in &ian.general_names {
                                let value = match name {
                                    GeneralName::DNSName(dns) => dns.to_string(),
                                    GeneralName::RFC822Name(email) => email.to_string(),
                                    GeneralName::URI(uri) => uri.to_string(),
                                    _ => format!("{:?}", name),
                                };
                                names.push(value);
                            }
                            if !names.is_empty() {
                                issuer_alternative_names = Some(names);
                            }
                        }
                        ParsedExtension::SubjectKeyIdentifier(ski) => {
                            subject_key_identifier = Some(hex::encode(&ski.0));
                        }
                        ParsedExtension::AuthorityKeyIdentifier(aki) => {
                            authority_key_identifier = Some(AuthorityKeyIdentifier {
                                key_identifier: aki.key_identifier.as_ref().map(|ki| hex::encode(&ki.0)),
                                authority_cert_issuer: aki.authority_cert_issuer.as_ref().map(|aci| {
                                    aci.iter().map(|gn| format!("{:?}", gn)).collect()
                                }),
                                authority_cert_serial: aki.authority_cert_serial.as_ref().map(|s| hex::encode(s)),
                            });
                        }
                        ParsedExtension::CRLDistributionPoints(cdp) => {
                            let mut points = Vec::new();
                            for point in &cdp.points {
                                if let Some(dp_name) = &point.distribution_point {
                                    match dp_name {
                                        DistributionPointName::FullName(names) => {
                                            for name in names {
                                                if let GeneralName::URI(uri) = name {
                                                    points.push(uri.to_string());
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            if !points.is_empty() {
                                crl_distribution_points = Some(points);
                            }
                        }
                        ParsedExtension::AuthorityInfoAccess(aia) => {
                            let mut access_info = Vec::new();
                            for desc in &aia.accessdescs {
                                let method = format_oid_with_description(&desc.access_method, &oid_registry);
                                let location = match &desc.access_location {
                                    GeneralName::URI(uri) => uri.to_string(),
                                    _ => format!("{:?}", desc.access_location),
                                };
                                access_info.push(AuthorityInfoAccess {
                                    access_method: method,
                                    access_location: location,
                                });
                            }
                            if !access_info.is_empty() {
                                authority_info_access = Some(access_info);
                            }
                        }
                        ParsedExtension::InhibitAnyPolicy(iap) => {
                            inhibit_any_policy = Some(iap.skip_certs);
                        }
                        ParsedExtension::PolicyConstraints(pc) => {
                            policy_constraints = Some(PolicyConstraints {
                                require_explicit_policy: pc.require_explicit_policy,
                                inhibit_policy_mapping: pc.inhibit_policy_mapping,
                            });
                        }
                        ParsedExtension::PolicyMappings(pm) => {
                            let mut mappings = Vec::new();
                            for mapping in &pm.mappings {
                                mappings.push(PolicyMapping {
                                    issuer_domain_policy: mapping.issuer_domain_policy.to_string(),
                                    subject_domain_policy: mapping.subject_domain_policy.to_string(),
                                });
                            }
                            if !mappings.is_empty() {
                                policy_mappings = Some(mappings);
                            }
                        }
                        ParsedExtension::CertificatePolicies(cp) => {
                            let mut policies = Vec::new();
                            for policy in cp {
                                let qualifiers = if let Some(pq) = &policy.policy_qualifiers {
                                    Some(pq.iter().map(|q| format!("{:?}", q)).collect())
                                } else {
                                    None
                                };
                                policies.push(CertificatePolicy {
                                    policy_identifier: policy.policy_id.to_string(),
                                    policy_qualifiers: qualifiers,
                                });
                            }
                            if !policies.is_empty() {
                                certificate_policies = Some(policies);
                            }
                        }
                        ParsedExtension::NameConstraints(nc) => {
                            let permitted = nc.permitted_subtrees.as_ref().map(|trees| {
                                trees.iter().map(|tree| format!("{:?}", tree.base)).collect()
                            });
                            let excluded = nc.excluded_subtrees.as_ref().map(|trees| {
                                trees.iter().map(|tree| format!("{:?}", tree.base)).collect()
                            });
                            name_constraints = Some(NameConstraints {
                                permitted_subtrees: permitted,
                                excluded_subtrees: excluded,
                            });
                        }
                        _ => {}
                    }
                }

                // Calculate fingerprints
                let sha1_fingerprint = Some(calculate_sha1_fingerprint(der_data));
                let sha256_fingerprint = Some(calculate_sha256_fingerprint(der_data));

                cert_infos.push(CertificateInfo {
                    // Core fields
                    version,
                    serial_number,

                    // Subject
                    subject,
                    subject_common_name,
                    subject_organization,
                    subject_organizational_unit,
                    subject_country,
                    subject_state_province,
                    subject_locality,
                    subject_email,

                    // Issuer
                    issuer,
                    issuer_common_name,
                    issuer_organization,
                    issuer_organizational_unit,
                    issuer_country,
                    issuer_state_province,
                    issuer_locality,
                    issuer_email,

                    // Validity
                    validity_not_before,
                    validity_not_after,

                    // Signature
                    signature_algorithm,
                    signature_algorithm_description,
                    signature_params,
                    signature_value,

                    // Public key
                    public_key_algorithm,
                    public_key_algorithm_description,
                    public_key_size,
                    public_key_params,
                    public_key_raw,
                    public_key_modulus,
                    public_key_exponent,
                    public_key_curve,
                    public_key_point,

                    // Extensions
                    is_ca,
                    path_length_constraint,
                    key_usage,
                    extended_key_usage,
                    subject_alternative_names,
                    issuer_alternative_names,
                    subject_key_identifier,
                    authority_key_identifier,
                    crl_distribution_points,
                    authority_info_access,
                    certificate_policies,
                    policy_mappings,
                    policy_constraints,
                    name_constraints,
                    inhibit_any_policy,
                    freshest_crl,
                    subject_info_access,
                    ct_precert_scts,

                    // Raw extensions
                    extensions,

                    // Fingerprints
                    sha1_fingerprint,
                    sha256_fingerprint,

                    // Raw data
                    der_encoded: der_data.to_vec(),
                });
            }
            Err(_) => break,
        }
    }

    Ok(cert_infos)
}
