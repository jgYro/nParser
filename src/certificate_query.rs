use crate::CertificateInfo;
use std::collections::HashSet;

/// A specification pattern implementation for filtering X.509 certificates.
///
/// This struct allows you to define search criteria that certificates must match.
/// Only specified (non-None) fields are used for filtering. All specified conditions
/// must be true for a certificate to match.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize, serde::Deserialize))]
pub struct CertificateQuery {
    /// Match certificates where public key algorithm description contains ANY of these substrings (case-insensitive)
    pub public_key_algorithm_contains: Option<Vec<String>>,

    /// Match certificates where signature algorithm description contains ANY of these substrings (case-insensitive)
    pub signature_algorithm_contains: Option<Vec<String>>,

    /// Match certificates with public key size >= this value
    pub public_key_size_min: Option<usize>,

    /// Match certificates with public key size <= this value
    pub public_key_size_max: Option<usize>,

    /// Match certificates with exact public key size
    pub public_key_size_exact: Option<usize>,

    /// Match certificates based on CA status
    pub is_ca: Option<bool>,

    /// Match certificates where subject contains this substring (case-insensitive)
    pub subject_contains: Option<String>,

    /// Match certificates where issuer contains this substring (case-insensitive)
    pub issuer_contains: Option<String>,

    /// Match certificates with exact serial number
    pub serial_number_exact: Option<String>,

    /// Match certificates that expire after this date (string comparison)
    pub expires_after: Option<String>,

    /// Match certificates that expire before this date (string comparison)
    pub expires_before: Option<String>,

    /// Match certificates that have ALL of these key usages
    pub requires_key_usage: Option<Vec<String>>,

    /// Match certificates that have extensions containing ANY of these OID substrings
    pub has_extensions_containing: Option<Vec<String>>,
}

impl CertificateQuery {
    /// Create a new empty query specification.
    pub fn new() -> Self {
        Default::default()
    }

    /// Match certificates where public key algorithm contains any of the specified substrings.
    pub fn public_key_algorithm_contains(mut self, algorithms: Vec<String>) -> Self {
        self.public_key_algorithm_contains = Some(algorithms);
        self
    }

    /// Match certificates with minimum public key size.
    pub fn public_key_size_at_least(mut self, min_size: usize) -> Self {
        self.public_key_size_min = Some(min_size);
        self
    }

    /// Match only CA certificates.
    pub fn is_ca_certificate(mut self) -> Self {
        self.is_ca = Some(true);
        self
    }

    /// Match certificates where subject contains the specified substring.
    pub fn subject_contains(mut self, pattern: String) -> Self {
        self.subject_contains = Some(pattern);
        self
    }

    /// Match certificates that have all specified key usages.
    pub fn requires_key_usage(mut self, usages: Vec<String>) -> Self {
        self.requires_key_usage = Some(usages);
        self
    }

    /// Match certificates where signature algorithm contains any of the specified substrings.
    pub fn signature_algorithm_contains(mut self, algorithms: Vec<String>) -> Self {
        self.signature_algorithm_contains = Some(algorithms);
        self
    }

    /// Returns true if the certificate matches ALL specified criteria.
    ///
    /// Unspecified criteria (None values) are ignored. The certificate must satisfy
    /// every specified condition to be considered a match.
    pub fn matches(&self, cert: &CertificateInfo) -> bool {
        // Public key algorithm filtering (OR logic within the list)
        if let Some(ref algorithms) = self.public_key_algorithm_contains {
            let matches_any = algorithms.iter().any(|alg| {
                cert.public_key_algorithm_description
                    .to_lowercase()
                    .contains(&alg.to_lowercase())
            });
            if !matches_any {
                return false;
            }
        }

        // Signature algorithm filtering (OR logic within the list)
        if let Some(ref algorithms) = self.signature_algorithm_contains {
            let matches_any = algorithms.iter().any(|alg| {
                cert.signature_algorithm_description
                    .to_lowercase()
                    .contains(&alg.to_lowercase())
            });
            if !matches_any {
                return false;
            }
        }

        // Public key size constraints
        if let Some(size) = cert.public_key_size {
            if let Some(min_size) = self.public_key_size_min {
                if size < min_size {
                    return false;
                }
            }
            if let Some(max_size) = self.public_key_size_max {
                if size > max_size {
                    return false;
                }
            }
            if let Some(exact_size) = self.public_key_size_exact {
                if size != exact_size {
                    return false;
                }
            }
        } else {
            // Certificate has no public key size info
            if self.public_key_size_min.is_some()
                || self.public_key_size_max.is_some()
                || self.public_key_size_exact.is_some()
            {
                return false; // Size requirements can't be satisfied
            }
        }

        // Boolean filters
        if let Some(expected_ca) = self.is_ca {
            if cert.is_ca != Some(expected_ca) {
                return false;
            }
        }

        // String pattern matching
        if let Some(ref subject_pattern) = self.subject_contains {
            if !cert
                .subject
                .to_lowercase()
                .contains(&subject_pattern.to_lowercase())
            {
                return false;
            }
        }

        if let Some(ref issuer_pattern) = self.issuer_contains {
            if !cert
                .issuer
                .to_lowercase()
                .contains(&issuer_pattern.to_lowercase())
            {
                return false;
            }
        }

        if let Some(ref serial) = self.serial_number_exact {
            if cert.serial_number != *serial {
                return false;
            }
        }

        // Date filtering (string comparison - basic implementation)
        if let Some(ref expires_after) = self.expires_after {
            if cert.validity_not_after <= *expires_after {
                return false;
            }
        }

        if let Some(ref expires_before) = self.expires_before {
            if cert.validity_not_after >= *expires_before {
                return false;
            }
        }

        // Key usage requirements (ALL must be present)
        if let Some(ref required_usages) = self.requires_key_usage {
            if let Some(ref key_usage) = cert.key_usage {
                let cert_usages: HashSet<String> = key_usage.iter().cloned().collect();
                for required in required_usages {
                    if !cert_usages.contains(required) {
                        return false;
                    }
                }
            } else {
                // Certificate has no key usage but we require some
                return false;
            }
        }

        // Extension requirements (ANY specified pattern must match ANY extension)
        if let Some(ref required_extensions) = self.has_extensions_containing {
            let cert_extensions: Vec<String> =
                cert.extensions.iter().map(|ext| ext.oid.clone()).collect();

            let has_required = required_extensions.iter().any(|required_pattern| {
                cert_extensions
                    .iter()
                    .any(|ext_oid| ext_oid.contains(required_pattern))
            });

            if !has_required {
                return false;
            }
        }

        true // All specified criteria matched
    }
}
