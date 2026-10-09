//! `aws-lc-rs` cryptographic backend implementation.

use crate::error::{Error, Result};
use crate::signing::SigningScheme;
use aws_lc_rs::{
    digest::{self, Context, Digest, SHA256, SHA384, SHA512},
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, KeyPair as AwsKeyPair, UnparsedPublicKey, VerificationAlgorithm,
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA384_ASN1,
        ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519, ML_DSA_44, ML_DSA_65, ML_DSA_87,
        RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
        RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
    },
};
use der::Decode as _;
use sigstore_types::HashAlgorithm;

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&SHA256, data);
    let mut result = [0u8; 32];
    result.copy_from_slice(digest.as_ref());
    result
}

pub(crate) fn sha384(data: &[u8]) -> Vec<u8> {
    digest::digest(&SHA384, data).as_ref().to_vec()
}

pub(crate) fn sha512(data: &[u8]) -> [u8; 64] {
    let digest = digest::digest(&SHA512, data);
    let mut result = [0u8; 64];
    result.copy_from_slice(digest.as_ref());
    result
}

pub(crate) struct DigestContext(Context);

impl DigestContext {
    pub(crate) fn new(algorithm: HashAlgorithm) -> Result<Self> {
        let backend = match algorithm {
            HashAlgorithm::Sha2256 => &SHA256,
            HashAlgorithm::Sha2384 => &SHA384,
            HashAlgorithm::Sha2512 => &SHA512,
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "cannot compute {algorithm} digests"
                )))
            }
        };
        Ok(Self(Context::new(backend)))
    }

    pub(crate) fn new_sha256() -> Self {
        Self(Context::new(&SHA256))
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub(crate) fn finalize_vec(self) -> Vec<u8> {
        self.0.finish().as_ref().to_vec()
    }

    pub(crate) fn finalize_sha256(self) -> [u8; 32] {
        let digest = self.0.finish();
        let mut result = [0u8; 32];
        result.copy_from_slice(digest.as_ref());
        result
    }
}

pub(crate) struct EcdsaP256KeyPair(EcdsaKeyPair);

impl EcdsaP256KeyPair {
    pub(crate) fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| Error::KeyGeneration("failed to generate ECDSA P-256 key".to_string()))?;
        Self::from_pkcs8_der(pkcs8.as_ref())
    }

    pub(crate) fn from_pkcs8_der(pkcs8: &[u8]) -> Result<Self> {
        // Ensure outer DER has no trailing bytes before parsing.
        der::asn1::AnyRef::from_der(pkcs8).map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        Ok(Self(kp))
    }

    pub(crate) fn public_key_bytes(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    pub(crate) fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let digest = Digest::import_less_safe(digest, &SHA256)
            .map_err(|_| Error::Signing("invalid SHA-256 digest".to_string()))?;
        let sig = self
            .0
            .sign_digest(&digest)
            .map_err(|_| Error::Signing("the cryptographic backend failed to sign".to_string()))?;
        Ok(sig.as_ref().to_vec())
    }
}

fn verification_algorithm(scheme: SigningScheme) -> &'static dyn VerificationAlgorithm {
    match scheme {
        SigningScheme::EcdsaP256Sha256 => &ECDSA_P256_SHA256_ASN1,
        SigningScheme::EcdsaP256Sha384 => &ECDSA_P256_SHA384_ASN1,
        SigningScheme::EcdsaP384Sha256 => &ECDSA_P384_SHA256_ASN1,
        SigningScheme::EcdsaP384Sha384 => &ECDSA_P384_SHA384_ASN1,
        SigningScheme::Ed25519 => &ED25519,
        SigningScheme::RsaPssSha256 => &RSA_PSS_2048_8192_SHA256,
        SigningScheme::RsaPssSha384 => &RSA_PSS_2048_8192_SHA384,
        SigningScheme::RsaPssSha512 => &RSA_PSS_2048_8192_SHA512,
        SigningScheme::RsaPkcs1Sha256 => &RSA_PKCS1_2048_8192_SHA256,
        SigningScheme::RsaPkcs1Sha384 => &RSA_PKCS1_2048_8192_SHA384,
        SigningScheme::RsaPkcs1Sha512 => &RSA_PKCS1_2048_8192_SHA512,
        SigningScheme::MlDsa44 => &ML_DSA_44,
        SigningScheme::MlDsa65 => &ML_DSA_65,
        SigningScheme::MlDsa87 => &ML_DSA_87,
    }
}

pub(crate) fn verify_raw(
    scheme: SigningScheme,
    pubkey_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    match scheme {
        SigningScheme::EcdsaP256Sha256 | SigningScheme::EcdsaP384Sha256 => {
            verify_prehashed(scheme, pubkey_bytes, &sha256(data), signature)
        }
        SigningScheme::EcdsaP256Sha384 | SigningScheme::EcdsaP384Sha384 => {
            verify_prehashed(scheme, pubkey_bytes, &sha384(data), signature)
        }
        _ => {
            let key = UnparsedPublicKey::new(verification_algorithm(scheme), pubkey_bytes);
            key.verify(data, signature).map_err(|_| ())
        }
    }
}

pub(crate) fn verify_prehashed(
    scheme: SigningScheme,
    pubkey_bytes: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let aws_algo = match scheme.hash_algorithm() {
        Some(HashAlgorithm::Sha2256) => &SHA256,
        Some(HashAlgorithm::Sha2384) => &SHA384,
        Some(HashAlgorithm::Sha2512) => &SHA512,
        _ => return Err(()),
    };
    let aws_digest = Digest::import_less_safe(digest, aws_algo).map_err(|_| ())?;
    let key = UnparsedPublicKey::new(verification_algorithm(scheme), pubkey_bytes);
    key.verify_digest(&aws_digest, signature).map_err(|_| ())
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use aws_lc_rs::{
        rsa::KeySize,
        signature::{
            Ed25519KeyPair, PqdsaKeyPair, RsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING,
            ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
        },
    };
    use sigstore_types::{DerPublicKey, SignatureBytes};

    pub(crate) fn generate_p256_pkcs8() -> Vec<u8> {
        let rng = SystemRandom::new();
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    pub(crate) fn sign_p384_sha384(data: &[u8]) -> (Vec<u8>, SignatureBytes) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let sig = SignatureBytes::new(kp.sign(&rng, data).unwrap().as_ref().to_vec());
        (kp.public_key().as_ref().to_vec(), sig)
    }

    pub(crate) fn sign_ed25519(data: &[u8]) -> (Vec<u8>, SignatureBytes) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let sig = SignatureBytes::new(kp.sign(data).as_ref().to_vec());
        (kp.public_key().as_ref().to_vec(), sig)
    }

    pub(crate) fn sign_mldsa(
        scheme: SigningScheme,
        seed: &[u8; 32],
        data: &[u8],
    ) -> (Vec<u8>, SignatureBytes) {
        let alg = match scheme {
            SigningScheme::MlDsa44 => &ML_DSA_44_SIGNING,
            SigningScheme::MlDsa65 => &ML_DSA_65_SIGNING,
            SigningScheme::MlDsa87 => &ML_DSA_87_SIGNING,
            _ => panic!("unsupported ML-DSA signing scheme"),
        };
        let kp = PqdsaKeyPair::from_seed(alg, seed).unwrap();
        let mut sig = vec![0u8; alg.signature_len()];
        let sig_len = kp.sign(data, &mut sig).unwrap();
        sig.truncate(sig_len);
        (kp.public_key().as_ref().to_vec(), SignatureBytes::new(sig))
    }

    pub(crate) fn sign_rsa(
        data: &[u8],
        hash_alg: HashAlgorithm,
    ) -> (DerPublicKey, SignatureBytes, SignatureBytes) {
        let rng = SystemRandom::new();
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let bare = DerPublicKey::new(key.public_key().as_ref().to_vec());
        let (pkcs1_enc, pss_enc) = match hash_alg {
            HashAlgorithm::Sha2256 => (&RSA_PKCS1_SHA256, &RSA_PSS_SHA256),
            HashAlgorithm::Sha2384 => (&RSA_PKCS1_SHA384, &RSA_PSS_SHA384),
            HashAlgorithm::Sha2512 => (&RSA_PKCS1_SHA512, &RSA_PSS_SHA512),
            _ => panic!("unsupported RSA hash algorithm"),
        };
        let mut pkcs1_buf = vec![0u8; key.public_modulus_len()];
        key.sign(pkcs1_enc, &rng, data, &mut pkcs1_buf).unwrap();
        let mut pss_buf = vec![0u8; key.public_modulus_len()];
        key.sign(pss_enc, &rng, data, &mut pss_buf).unwrap();
        (
            bare,
            SignatureBytes::new(pkcs1_buf),
            SignatureBytes::new(pss_buf),
        )
    }
}
