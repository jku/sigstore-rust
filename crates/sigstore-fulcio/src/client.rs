//! Fulcio client for certificate operations

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sigstore_crypto::KeyPair;
use sigstore_oidc::IdentityToken;
use sigstore_types::{DerCertificate, SignatureBytes};

/// A client for interacting with Fulcio
pub struct FulcioClient {
    /// Base URL of the Fulcio instance
    url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl FulcioClient {
    /// Create a new Fulcio client
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Create a client for the public Sigstore Fulcio instance
    pub fn public() -> Self {
        Self::new("https://fulcio.sigstore.dev")
    }

    /// Create a client for the Sigstore staging Fulcio instance
    pub fn staging() -> Self {
        Self::new("https://fulcio.sigstage.dev")
    }

    /// Get the OIDC configuration (supported issuers)
    pub async fn get_configuration(&self) -> Result<Configuration> {
        let url = format!("{}/api/v2/configuration", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get configuration: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))
    }

    /// Request a signing certificate
    ///
    /// This method handles the complete certificate request flow:
    /// 1. Extracts the public key from the key pair
    /// 2. Creates a proof of possession by signing the identity
    /// 3. Sends the request to Fulcio
    ///
    /// # Arguments
    /// * `identity_token` - The OIDC identity token
    /// * `key_pair` - The key pair (public key will be extracted, private key used for proof)
    pub async fn create_signing_certificate(
        &self,
        identity_token: &IdentityToken,
        key_pair: &KeyPair,
    ) -> Result<SigningCertificate> {
        let url = format!("{}/api/v2/signingCert", self.url);

        // Extract public key and convert to PEM for the API
        let public_key_pem = key_pair
            .public_key_der()
            .map_err(|e| Error::Api(format!("failed to export public key: {}", e)))?
            .to_pem();

        // Create proof of possession by signing the identity (email or subject)
        let proof_of_possession = key_pair
            .sign(identity_token.identity().as_bytes())
            .map_err(|e| Error::Api(format!("failed to create proof of possession: {}", e)))?;

        let request = CreateSigningCertificateRequest {
            credentials: Credentials {
                oidc_identity_token: identity_token.raw().to_string(),
            },
            public_key_request: PublicKeyRequest {
                public_key: PublicKeyData {
                    algorithm: String::new(), // Not needed for PEM (contains algorithm info)
                    content: public_key_pem,
                },
                proof_of_possession: proof_of_possession.into(),
            },
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api(format!(
                "failed to create signing certificate: {} - {}",
                status, body
            )));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))
    }

    /// Get the trust bundle (CA certificates)
    pub async fn get_trust_bundle(&self) -> Result<TrustBundle> {
        let url = format!("{}/api/v2/trustBundle", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get trust bundle: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))
    }
}

/// OIDC configuration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    /// List of supported OIDC issuers
    pub issuers: Vec<OIDCIssuer>,
}

/// OIDC issuer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OIDCIssuer {
    /// Issuer URL
    pub issuer_url: String,
    /// Audience
    pub audience: String,
    /// Challenge claim
    #[serde(default)]
    pub challenge_claim: Option<String>,
    /// SPIFFE trust domain
    #[serde(default)]
    pub spiffe_trust_domain: Option<String>,
}

/// Request to create a signing certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSigningCertificateRequest {
    /// OIDC credentials
    pub credentials: Credentials,
    /// Public key request
    pub public_key_request: PublicKeyRequest,
}

/// OIDC credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    /// OIDC identity token
    pub oidc_identity_token: String,
}

/// Public key request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyRequest {
    /// Public key
    pub public_key: PublicKeyData,
    /// Proof of possession (signature)
    pub proof_of_possession: SignatureBytes,
}

/// Public key data for API requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyData {
    /// Algorithm (ECDSA, RSA, ED25519) - optional when using PEM format
    pub algorithm: String,
    /// PEM or DER-encoded key content
    pub content: String,
}

/// Signing certificate response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificate {
    /// Certificate chain
    #[serde(default)]
    pub signed_certificate_embedded_sct: Option<CertificateChain>,
    /// Certificate with detached SCT
    #[serde(default)]
    pub signed_certificate_detached_sct: Option<CertificateWithSCT>,
}

/// Certificate chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChain {
    /// Chain of certificates (PEM encoded)
    pub chain: ChainContent,
}

/// Chain content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainContent {
    /// Certificates in the chain
    pub certificates: Vec<String>,
}

/// Certificate with detached SCT
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateWithSCT {
    /// Certificate chain
    pub chain: ChainContent,
    /// Signed certificate timestamp
    pub signed_certificate_timestamp: String,
}

/// Trust bundle response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBundle {
    /// Certificate chains
    pub chains: Vec<CertificateChain>,
}

impl SigningCertificate {
    /// Get the raw PEM certificates from whichever variant is present
    fn pem_certificates(&self) -> Option<&Vec<String>> {
        self.signed_certificate_embedded_sct
            .as_ref()
            .map(|c| &c.chain.certificates)
            .or_else(|| {
                self.signed_certificate_detached_sct
                    .as_ref()
                    .map(|c| &c.chain.certificates)
            })
    }

    /// Get the leaf certificate as a type-safe DerCertificate
    ///
    /// This parses the PEM-encoded certificate and returns it as a DerCertificate,
    /// which is more suitable for use with other sigstore APIs.
    pub fn leaf_certificate(&self) -> Result<DerCertificate> {
        let pem = self
            .pem_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| Error::Api("No certificate in response".to_string()))?;

        DerCertificate::from_pem(pem)
            .map_err(|e| Error::Api(format!("Invalid certificate PEM: {e}")))
    }

    /// Get all certificates in the chain as type-safe DerCertificates
    ///
    /// This parses all PEM-encoded certificates and returns them as DerCertificates.
    pub fn certificate_chain(&self) -> Result<Vec<DerCertificate>> {
        self.pem_certificates()
            .ok_or_else(|| Error::Api("No certificate chain in response".to_string()))?
            .iter()
            .map(|pem| {
                DerCertificate::from_pem(pem)
                    .map_err(|e| Error::Api(format!("Invalid certificate PEM: {e}")))
            })
            .collect()
    }
}
