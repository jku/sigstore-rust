//! TSA client for RFC 3161 Time-Stamp Protocol

use crate::asn1::{AlgorithmIdentifier, Asn1MessageImprint, TimeStampReq, TimeStampResp};
use crate::error::{Error, Result};
use sigstore_types::Sha256Hash;

/// A client for interacting with a Time-Stamp Authority
pub struct TimestampClient {
    /// Base URL of the TSA
    url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl TimestampClient {
    /// Create a new TSA client
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Create a client for the Sigstore TSA
    pub fn sigstore() -> Self {
        Self::new("https://timestamp.sigstore.dev/api/v1/timestamp")
    }

    /// Create a client for the FreeTSA service
    pub fn freetsa() -> Self {
        Self::new("https://freetsa.org/tsr")
    }

    /// Request a timestamp for the given digest
    ///
    /// # Arguments
    /// * `digest` - The hash digest to timestamp
    /// * `algorithm` - The hash algorithm used
    ///
    /// # Returns
    /// The raw timestamp token (DER-encoded CMS SignedData)
    async fn timestamp(&self, digest: &[u8], algorithm: AlgorithmIdentifier) -> Result<Vec<u8>> {
        // Build the timestamp request
        let imprint = Asn1MessageImprint::new(algorithm, digest.to_vec());
        let request = TimeStampReq::new(imprint);

        // Encode to DER
        let request_der = request
            .to_der()
            .map_err(|e| Error::Asn1(format!("failed to encode request: {}", e)))?;

        // Send HTTP request
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/timestamp-query")
            .body(request_der)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Http(format!(
                "TSA returned status {}",
                response.status()
            )));
        }

        // Get response bytes
        let response_bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        // Parse the response
        let tsr = TimeStampResp::from_der_bytes(&response_bytes)
            .map_err(|e| Error::Asn1(format!("failed to decode response: {}", e)))?;

        if !tsr.is_success() {
            return Err(Error::InvalidResponse(format!(
                "TSA returned status {:?}",
                tsr.status.status_enum()
            )));
        }

        // Return the full response bytes (TimeStampResp) as required by Sigstore bundle
        Ok(response_bytes.to_vec())
    }

    /// Request a timestamp for a SHA-256 digest
    pub async fn timestamp_sha256(&self, digest: &Sha256Hash) -> Result<Vec<u8>> {
        self.timestamp(digest.as_bytes(), AlgorithmIdentifier::sha256())
            .await
    }
}

/// Convenience function to get a timestamp from the Sigstore TSA
pub async fn timestamp_sigstore(digest: &Sha256Hash) -> Result<Vec<u8>> {
    TimestampClient::sigstore().timestamp_sha256(digest).await
}
