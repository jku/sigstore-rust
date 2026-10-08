//! `rustls-webpki` signature verification algorithms backed by `sigstore-crypto`.
//!
//! This module bridges `sigstore-crypto`'s active cryptographic backend to
//! [`rustls_pki_types::SignatureVerificationAlgorithm`], allowing `rustls-webpki`
//! to verify X.509 certificate chains without depending on `aws-lc-rs` directly.

use crate::signing::SigningScheme;
use crate::verification::VerificationKey;
use rustls_pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};
use sigstore_types::SignatureBytes;

#[derive(Debug)]
struct WebpkiVerificationAlg {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    scheme: SigningScheme,
}

impl SignatureVerificationAlgorithm for WebpkiVerificationAlg {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = VerificationKey::from_raw_bytes(public_key.to_vec(), self.scheme);
        key.verify(message, &SignatureBytes::from_bytes(signature))
            .map_err(|_| InvalidSignature)
    }
}

/// ECDSA P-256 with SHA-256 verification algorithm for `webpki`.
pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    scheme: SigningScheme::EcdsaP256Sha256,
};

/// ECDSA P-256 with SHA-384 verification algorithm for `webpki`.
pub static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    scheme: SigningScheme::EcdsaP256Sha384,
};

/// ECDSA P-384 with SHA-256 verification algorithm for `webpki`.
pub static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    scheme: SigningScheme::EcdsaP384Sha256,
};

/// ECDSA P-384 with SHA-384 verification algorithm for `webpki`.
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    scheme: SigningScheme::EcdsaP384Sha384,
};

/// Ed25519 verification algorithm for `webpki`.
pub static ED25519: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
    scheme: SigningScheme::Ed25519,
};

/// RSA PKCS#1 v1.5 (2048–8192 bits) with SHA-256 verification algorithm for `webpki`.
pub static RSA_PKCS1_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm =
    &WebpkiVerificationAlg {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PKCS1_SHA256,
        scheme: SigningScheme::RsaPkcs1Sha256,
    };

/// RSA PKCS#1 v1.5 (2048–8192 bits) with SHA-384 verification algorithm for `webpki`.
pub static RSA_PKCS1_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm =
    &WebpkiVerificationAlg {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PKCS1_SHA384,
        scheme: SigningScheme::RsaPkcs1Sha384,
    };

/// RSA PKCS#1 v1.5 (2048–8192 bits) with SHA-512 verification algorithm for `webpki`.
pub static RSA_PKCS1_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm =
    &WebpkiVerificationAlg {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PKCS1_SHA512,
        scheme: SigningScheme::RsaPkcs1Sha512,
    };

/// RSA-PSS (2048–8192 bits) with SHA-256 verification algorithm for `webpki`.
pub static RSA_PSS_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    scheme: SigningScheme::RsaPssSha256,
};

/// RSA-PSS (2048–8192 bits) with SHA-384 verification algorithm for `webpki`.
pub static RSA_PSS_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    scheme: SigningScheme::RsaPssSha384,
};

/// RSA-PSS (2048–8192 bits) with SHA-512 verification algorithm for `webpki`.
pub static RSA_PSS_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    scheme: SigningScheme::RsaPssSha512,
};

/// All X.509 signature verification algorithms supported by `sigstore-crypto` for `rustls-webpki`.
pub static WEBPKI_VERIFICATION_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    ECDSA_P256_SHA256,
    ECDSA_P256_SHA384,
    ECDSA_P384_SHA256,
    ECDSA_P384_SHA384,
    ED25519,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PSS_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512,
];
