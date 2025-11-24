//! X.509 certificate utilities for Sigstore
//!
//! This module provides utilities for parsing and extracting information
//! from X.509 certificates used in Sigstore bundles.

use crate::error::{Error, Result};
use crate::SigningScheme;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

/// Information extracted from a certificate
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Identity from SAN extension (email or URI)
    pub identity: Option<String>,
    /// Issuer from certificate
    pub issuer: Option<String>,
    /// Not valid before (Unix timestamp)
    pub not_before: i64,
    /// Not valid after (Unix timestamp)
    pub not_after: i64,
    /// Public key bytes (raw bytes from SubjectPublicKeyInfo)
    pub public_key_bytes: Vec<u8>,
    /// Signing scheme derived from the public key algorithm
    pub signing_scheme: SigningScheme,
}

/// Parse certificate information from DER-encoded certificate
pub fn parse_certificate_info(cert_der: &[u8]) -> Result<CertificateInfo> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::InvalidCertificate(format!("failed to parse certificate: {}", e)))?;

    // Extract validity times
    let not_before = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs() as i64;
    let not_after = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64;

    // Extract public key in SPKI (SubjectPublicKeyInfo) DER format
    // This is required by aws-lc-rs UnparsedPublicKey, which expects the full SPKI,
    // not just the raw key bytes
    let public_key_info = &cert.tbs_certificate.subject_public_key_info;
    let public_key_bytes = public_key_info
        .to_der()
        .map_err(|e| Error::InvalidCertificate(format!("failed to encode SPKI: {}", e)))?;

    // Determine signing scheme from algorithm OID and parameters
    // Note: This is a best-effort attempt. For certificates used only for
    // chain validation (not signature verification), we default to P-256.
    let signing_scheme = match public_key_info.algorithm.oid.to_string().as_str() {
        "1.2.840.10045.2.1" => {
            // id-ecPublicKey - need to check curve parameter
            if let Some(params) = &public_key_info.algorithm.parameters {
                use x509_cert::der::Decode;
                // Try to decode the parameters as an OID
                match const_oid::ObjectIdentifier::from_der(params.value()) {
                    Ok(curve_oid) => match curve_oid.to_string().as_str() {
                        "1.2.840.10045.3.1.7" => SigningScheme::EcdsaP256Sha256, // secp256r1 (P-256)
                        "1.3.132.0.34" => SigningScheme::EcdsaP384Sha384, // secp384r1 (P-384)
                        _ => {
                            // Unknown EC curve - default to P-256 for compatibility
                            SigningScheme::EcdsaP256Sha256
                        }
                    },
                    Err(_) => {
                        // Failed to parse curve OID - default to P-256 for compatibility
                        SigningScheme::EcdsaP256Sha256
                    }
                }
            } else {
                // EC key missing curve parameters - default to P-256 for compatibility
                SigningScheme::EcdsaP256Sha256
            }
        }
        "1.2.840.113549.1.1.1" => {
            // rsaEncryption - default to RSA PKCS#1 SHA-256
            // We can't determine padding from the certificate alone
            SigningScheme::RsaPkcs1Sha256
        }
        "1.3.101.112" => SigningScheme::Ed25519, // id-Ed25519
        _ => {
            // Unknown algorithm - default to P-256 for compatibility
            SigningScheme::EcdsaP256Sha256
        }
    };

    // Extract identity from SAN extension
    let identity = extract_san_identity(&cert)?;

    // TODO: Extract issuer from certificate
    let issuer = None;

    Ok(CertificateInfo {
        identity,
        issuer,
        not_before,
        not_after,
        public_key_bytes,
        signing_scheme,
    })
}

/// Extract identity from Subject Alternative Name (SAN) extension
///
/// This extracts the email address or URI from the SAN extension.
/// The SAN extension has OID 2.5.29.17 and can contain various types:
/// - 0x81: rfc822Name (email)
/// - 0x86: uniformResourceIdentifier (URI)
pub fn extract_san_identity(cert: &Certificate) -> Result<Option<String>> {
    let extensions = match &cert.tbs_certificate.extensions {
        Some(exts) => exts,
        None => return Ok(None),
    };

    for ext in extensions.iter() {
        // Subject Alternative Name OID: 2.5.29.17
        if ext.extn_id.to_string() == "2.5.29.17" {
            let san_bytes = ext.extn_value.as_bytes();

            // Try to find email (0x81 tag for rfc822Name)
            if let Some(email) = extract_tagged_value(san_bytes, 0x81) {
                return Ok(Some(email));
            }

            // Try to find URI (0x86 tag for uniformResourceIdentifier)
            if let Some(uri) = extract_tagged_value(san_bytes, 0x86) {
                return Ok(Some(uri));
            }
        }
    }

    Ok(None)
}

/// Extract a tagged value from ASN.1 bytes
///
/// This is a simple parser that looks for a specific ASN.1 tag and extracts
/// the value. The format is:
/// - tag (1 byte)
/// - length (1 byte for short form)
/// - value (length bytes)
fn extract_tagged_value(bytes: &[u8], tag: u8) -> Option<String> {
    // Find the position of the tag
    let tag_pos = bytes.iter().position(|&b| b == tag)?;

    // Make sure there's room for length byte
    if tag_pos + 1 >= bytes.len() {
        return None;
    }

    let remaining = &bytes[tag_pos + 1..];
    if remaining.is_empty() {
        return None;
    }

    let len = remaining[0] as usize;

    // Make sure we have enough bytes
    if remaining.len() <= len {
        return None;
    }

    // Extract the value
    String::from_utf8(remaining[1..=len].to_vec()).ok()
}

/// Convert PEM-encoded certificate to DER
pub fn der_from_pem(pem: &str) -> Result<Vec<u8>> {
    const BEGIN_MARKER: &str = "-----BEGIN CERTIFICATE-----";
    const END_MARKER: &str = "-----END CERTIFICATE-----";

    let start = pem
        .find(BEGIN_MARKER)
        .ok_or_else(|| Error::InvalidCertificate("missing PEM BEGIN marker".to_string()))?;

    let end = pem
        .find(END_MARKER)
        .ok_or_else(|| Error::InvalidCertificate("missing PEM END marker".to_string()))?;

    // Extract the base64 content between markers
    let pem_content = &pem[start + BEGIN_MARKER.len()..end];

    // Remove whitespace
    let clean_content: String = pem_content.chars().filter(|c| !c.is_whitespace()).collect();

    // Decode base64
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &clean_content)
        .map_err(|e| Error::InvalidCertificate(format!("failed to decode PEM: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tagged_value() {
        // Create a simple ASN.1 sequence with an email tag (0x81)
        let mut bytes = vec![0x30, 12]; // SEQUENCE
        bytes.push(0x81); // rfc822Name tag
        bytes.push(16); // length
        bytes.extend_from_slice(b"test@example.com");

        let result = extract_tagged_value(&bytes, 0x81);
        assert_eq!(result, Some("test@example.com".to_string()));
    }

    #[test]
    fn test_extract_tagged_value_not_found() {
        let bytes = vec![0x30, 0x10, 0x82, 5, b't', b'e', b's', b't'];
        let result = extract_tagged_value(&bytes, 0x81);
        assert_eq!(result, None);
    }

    #[test]
    fn test_der_from_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----";
        let result = der_from_pem(pem);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"abcd");
    }

    #[test]
    fn test_der_from_pem_invalid() {
        let pem = "not a pem";
        let result = der_from_pem(pem);
        assert!(result.is_err());
    }
}
