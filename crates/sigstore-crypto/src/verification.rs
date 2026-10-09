//! Signature verification

use crate::error::{Error, Result};
use crate::signing::{KeyAlgorithm, SigningScheme};
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1};
use const_oid::ObjectIdentifier;
use der::Decode;
use sigstore_types::{DerPublicKey, HashAlgorithm, SignatureBytes};
use spki::SubjectPublicKeyInfoRef;

/// id-Ed25519: 1.3.101.112 (RFC 8410)
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// id-ml-dsa-44: 2.16.840.1.101.3.4.3.17 (FIPS 204)
const ID_ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
/// id-ml-dsa-65: 2.16.840.1.101.3.4.3.18 (FIPS 204)
const ID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
/// id-ml-dsa-87: 2.16.840.1.101.3.4.3.19 (FIPS 204)
const ID_ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

impl KeyAlgorithm {
    /// Resolve an SPKI algorithm with checked ASN.1 parameters.
    pub fn from_spki(key: &DerPublicKey) -> Result<Self> {
        let spki = SubjectPublicKeyInfoRef::try_from(key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid SPKI: {e}")))?;
        key_algorithm(&spki)
    }
}

fn key_algorithm(spki: &SubjectPublicKeyInfoRef<'_>) -> Result<KeyAlgorithm> {
    if spki.subject_public_key.as_bytes().is_none() {
        return Err(Error::InvalidKey(
            "public key BIT STRING has unused bits".into(),
        ));
    }
    let algorithm = &spki.algorithm;
    match algorithm.oid {
        ID_EC_PUBLIC_KEY => match algorithm.parameters_oid() {
            Ok(SECP_256_R_1) => Ok(KeyAlgorithm::EcdsaP256),
            Ok(SECP_384_R_1) => Ok(KeyAlgorithm::EcdsaP384),
            _ => Err(Error::InvalidKey(
                "unsupported or invalid EC curve parameters".into(),
            )),
        },
        RSA_ENCRYPTION => {
            if algorithm.parameters.is_some_and(|params| !params.is_null()) {
                return Err(Error::InvalidKey(
                    "RSA parameters must be NULL or absent".into(),
                ));
            }
            RsaPublicKey::from_der(spki.subject_public_key.raw_bytes())
                .map_err(|e| Error::InvalidKey(format!("invalid RSA public key: {e}")))?;
            Ok(KeyAlgorithm::Rsa)
        }
        // RFC 8410 and FIPS 204 require the parameters to be absent.
        ID_ED25519 => without_parameters(algorithm, KeyAlgorithm::Ed25519),
        ID_ML_DSA_44 => without_parameters(algorithm, KeyAlgorithm::MlDsa44),
        ID_ML_DSA_65 => without_parameters(algorithm, KeyAlgorithm::MlDsa65),
        ID_ML_DSA_87 => without_parameters(algorithm, KeyAlgorithm::MlDsa87),
        oid => Err(Error::InvalidKey(format!(
            "unsupported key algorithm OID: {oid}"
        ))),
    }
}

/// Accept `key_algorithm` only if the SPKI algorithm carries no parameters.
fn without_parameters(
    algorithm: &spki::AlgorithmIdentifierRef<'_>,
    key_algorithm: KeyAlgorithm,
) -> Result<KeyAlgorithm> {
    if algorithm.parameters.is_some() {
        return Err(Error::InvalidKey(format!(
            "{key_algorithm:?} public keys must not have algorithm parameters"
        )));
    }
    Ok(key_algorithm)
}

#[derive(der::Sequence)]
#[allow(dead_code)]
pub(crate) struct RsaPublicKey<'a> {
    modulus: der::asn1::UintRef<'a>,
    public_exponent: der::asn1::UintRef<'a>,
}

/// A public key for verification
pub struct VerificationKey {
    /// Raw public key bytes (format depends on scheme)
    bytes: Vec<u8>,
    /// The scheme to use for verification
    scheme: SigningScheme,
}

impl VerificationKey {
    /// Create a verification key from a DER-encoded SPKI public key
    ///
    /// This parses the SubjectPublicKeyInfo structure and extracts the raw
    /// public key bytes needed for verification.
    pub fn from_spki_with_scheme(key: &DerPublicKey, scheme: SigningScheme) -> Result<Self> {
        let spki = SubjectPublicKeyInfoRef::try_from(key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid SPKI: {e}")))?;

        if key_algorithm(&spki)? != scheme.key_algorithm() {
            return Err(Error::InvalidKey(format!(
                "SPKI algorithm does not match {}",
                scheme.name()
            )));
        }
        let raw_bytes = spki.subject_public_key.raw_bytes().to_vec();

        Ok(Self {
            bytes: raw_bytes,
            scheme,
        })
    }

    /// Create a verification key from a DER-encoded SPKI public key,
    /// detecting the signing scheme from the SPKI algorithm identifier.
    pub fn from_spki(key: &DerPublicKey) -> Result<Self> {
        let spki = SubjectPublicKeyInfoRef::try_from(key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid SPKI: {e}")))?;

        let scheme = key_algorithm(&spki)?.default_signing_scheme();

        Ok(Self {
            bytes: spki.subject_public_key.raw_bytes().to_vec(),
            scheme,
        })
    }

    /// Create a verification key from DER key material.
    ///
    /// SPKI is preferred. For RSA schemes this also accepts the bare PKCS#1
    /// `RSAPublicKey` encoding used by some Sigstore trusted roots.
    pub fn from_der(key: &DerPublicKey, scheme: SigningScheme) -> Result<Self> {
        match Self::from_spki_with_scheme(key, scheme) {
            Ok(key) => Ok(key),
            Err(_) if scheme.key_algorithm() == KeyAlgorithm::Rsa => {
                // Do not reinterpret an incompatible/malformed SPKI as a bare
                // RSA key: PKCS#1 must actually decode as two INTEGER fields.
                RsaPublicKey::from_der(key.as_bytes())
                    .map_err(|e| Error::InvalidKey(format!("invalid RSA public key: {e}")))?;
                Ok(Self {
                    bytes: key.as_bytes().to_vec(),
                    scheme,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Get the raw public key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the signing scheme
    pub fn scheme(&self) -> SigningScheme {
        self.scheme
    }

    /// Verify a signature over data
    pub fn verify(&self, data: impl AsRef<[u8]>, signature: &SignatureBytes) -> Result<()> {
        self.verify_inner(data.as_ref(), signature.as_bytes())
    }

    fn verify_inner(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        crate::backend::verify_raw(self.scheme, &self.bytes, data, signature)
            .map_err(|()| Error::Verification(format!("{} signature invalid", self.scheme.name())))
    }

    /// Verify a signature over prehashed data
    ///
    /// This is used for hashedrekord verification where the signature is over
    /// a pre-computed hash of the artifact, not the artifact itself.
    pub fn verify_prehashed(&self, digest: &[u8], signature: &SignatureBytes) -> Result<()> {
        let expected_len: usize = match self.scheme.hash_algorithm() {
            Some(HashAlgorithm::Sha2256) => 32,
            Some(HashAlgorithm::Sha2384) => 48,
            Some(HashAlgorithm::Sha2512) => 64,
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "Scheme {:?} does not support prehashed mode",
                    self.scheme
                )));
            }
        };

        if digest.len() != expected_len {
            return Err(Error::Verification(format!(
                "Failed to import digest: len={}, algo_expected_len={}",
                digest.len(),
                expected_len
            )));
        }

        crate::backend::verify_prehashed(self.scheme, &self.bytes, digest, signature.as_bytes())
            .map_err(|()| Error::Verification(format!("{} signature invalid", self.scheme.name())))
    }
}

/// Verify a signature using the specified scheme
///
/// This is a convenience function that creates a temporary `VerificationKey`.
/// For repeated verifications with the same key, prefer using `VerificationKey` directly.
///
/// # Arguments
/// * `public_key` - DER-encoded SPKI public key
/// * `data` - Data that was signed
/// * `signature` - The signature to verify
/// * `scheme` - The signing scheme used
pub fn verify_signature(
    public_key: &DerPublicKey,
    data: &[u8],
    signature: &SignatureBytes,
    scheme: SigningScheme,
) -> Result<()> {
    VerificationKey::from_der(public_key, scheme)?.verify(data, signature)
}

/// Verify a signature over prehashed data using the specified scheme
///
/// This is used for hashedrekord verification where the signature is over
/// a pre-computed hash of the artifact, not the artifact itself.
///
/// # Arguments
/// * `public_key` - DER-encoded SPKI public key
/// * `digest` - Pre-computed hash of the artifact
/// * `signature` - The signature to verify
/// * `scheme` - The signing scheme used
pub fn verify_signature_prehashed(
    public_key: &DerPublicKey,
    digest: &[u8],
    signature: &SignatureBytes,
    scheme: SigningScheme,
) -> Result<()> {
    VerificationKey::from_der(public_key, scheme)?.verify_prehashed(digest, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::KeyPair;

    #[test]
    fn test_verify_ecdsa_p256() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data";
        let sig = kp.sign(data).unwrap();

        let pubkey = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki_with_scheme(&pubkey, kp.default_scheme()).unwrap();
        assert!(vk.verify(data, &sig).is_ok());
    }

    #[test]
    fn test_verify_bad_signature() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data";
        let bad_sig = SignatureBytes::new(vec![0u8; 64]);

        let pubkey = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki_with_scheme(&pubkey, kp.default_scheme()).unwrap();
        assert!(vk.verify(data, &bad_sig).is_err());
    }

    #[test]
    fn test_verify_wrong_data() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data";
        let sig = kp.sign(data).unwrap();

        let pubkey = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki_with_scheme(&pubkey, kp.default_scheme()).unwrap();
        assert!(vk.verify(b"wrong data", &sig).is_err());
    }

    #[test]
    fn test_verify_prehashed_ecdsa_p256() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data to prehash";
        let sig = kp.sign(data).unwrap();
        let digest = crate::hash::sha256(data);

        let pubkey = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki_with_scheme(&pubkey, kp.default_scheme()).unwrap();
        assert!(vk.verify_prehashed(digest.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn test_verify_prehashed_unsupported() {
        // Construct a VerificationKey directly with Ed25519 which doesn't support prehashed
        let vk = VerificationKey {
            bytes: vec![0u8; 32],
            scheme: SigningScheme::Ed25519,
        };
        let dummy_digest = vec![0u8; 32];
        let dummy_sig = SignatureBytes::new(vec![0u8; 64]);

        let result = vk.verify_prehashed(&dummy_digest, &dummy_sig);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::UnsupportedAlgorithm(_)
        ));
    }

    /// A standard P-384/SHA-384 signature verifies via `EcdsaP384Sha384` (raw and
    /// prehashed), while the mismatched `EcdsaP384Sha256` scheme fails closed.
    #[test]
    fn test_verify_p384_sha384_roundtrip_and_mismatch_fails_closed() {
        let data = b"artifact signed with a P-384 key";
        let (raw_pubkey, sig) = crate::backend::test_support::sign_p384_sha384(data);

        // Standard pairing: verifies over raw artifact and SHA-384 prehash.
        let public_key = spki_der(ID_EC_PUBLIC_KEY, Some(SECP_384_R_1), &raw_pubkey);
        let vk384 = VerificationKey::from_spki(&public_key).unwrap();
        assert_eq!(
            KeyAlgorithm::from_spki(&public_key).unwrap(),
            KeyAlgorithm::EcdsaP384
        );
        assert!(VerificationKey::from_spki_with_scheme(
            &public_key,
            SigningScheme::EcdsaP256Sha256
        )
        .is_err());
        assert!(vk384.verify(data, &sig).is_ok());
        let sha384 = crate::hash::sha384(data);
        assert!(vk384.verify_prehashed(&sha384, &sig).is_ok());

        // Mismatched hash must fail closed.
        let vk256 =
            VerificationKey::from_spki_with_scheme(&public_key, SigningScheme::EcdsaP384Sha256)
                .unwrap();
        let sha256 = crate::hash::sha256(data);
        assert!(vk256.verify(data, &sig).is_err());
        assert!(vk256.verify_prehashed(sha256.as_bytes(), &sig).is_err());
    }

    fn spki_der(
        oid: ObjectIdentifier,
        curve: Option<ObjectIdentifier>,
        key_bytes: &[u8],
    ) -> DerPublicKey {
        use der::{asn1::BitString, Encode as _};
        use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid,
                parameters: curve.map(|c| der::Any::encode_from(&c).unwrap()),
            },
            subject_public_key: BitString::from_bytes(key_bytes).unwrap(),
        };
        DerPublicKey::new(spki.to_der().unwrap())
    }

    #[test]
    fn test_from_spki_ecdsa_p256_roundtrip() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"checkpoint-style message";
        let sig = kp.sign(data).unwrap();

        let pubkey = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki(&pubkey).unwrap();
        assert_eq!(vk.scheme(), SigningScheme::EcdsaP256Sha256);
        assert!(vk.verify(data, &sig).is_ok());
    }

    #[test]
    fn test_from_spki_ed25519_roundtrip() {
        let data = b"checkpoint-style message";
        let (raw_pubkey, sig) = crate::backend::test_support::sign_ed25519(data);
        let pubkey = spki_der(ID_ED25519, None, &raw_pubkey);

        let vk = VerificationKey::from_spki(&pubkey).unwrap();
        assert_eq!(vk.scheme(), SigningScheme::Ed25519);
        assert!(vk.verify(data, &sig).is_ok());
    }

    #[test]
    fn rsa_autodetection_and_explicit_schemes_share_checked_parsing() {
        let data = b"rsa verification test message";
        let digest = crate::hash::sha256(data);
        let (bare, pkcs1_sig, pss_sig) =
            crate::backend::test_support::sign_rsa(data, HashAlgorithm::Sha2256);

        let spki = spki_der(RSA_ENCRYPTION, None, bare.as_bytes());
        let vk_pkcs1 = VerificationKey::from_spki(&spki).unwrap();
        assert_eq!(vk_pkcs1.scheme(), SigningScheme::RsaPkcs1Sha256);
        assert!(vk_pkcs1.verify(data, &pkcs1_sig).is_ok());
        assert!(vk_pkcs1
            .verify_prehashed(digest.as_bytes(), &pkcs1_sig)
            .is_ok());
        assert!(vk_pkcs1.verify(data, &pss_sig).is_err());

        let vk_pss = VerificationKey::from_der(&bare, SigningScheme::RsaPssSha256).unwrap();
        assert!(vk_pss.verify(data, &pss_sig).is_ok());
        assert!(vk_pss.verify_prehashed(digest.as_bytes(), &pss_sig).is_ok());
        assert!(vk_pss.verify(data, &pkcs1_sig).is_err());

        assert!(VerificationKey::from_spki_with_scheme(&spki, SigningScheme::RsaPssSha256).is_ok());
        assert!(VerificationKey::from_der(&spki, SigningScheme::Ed25519).is_err());
        let bad_parameters = spki_der(ID_ED25519, Some(SECP_256_R_1), &[0; 32]);
        assert!(VerificationKey::from_spki(&bad_parameters).is_err());
        assert!(
            VerificationKey::from_spki_with_scheme(&bad_parameters, SigningScheme::Ed25519)
                .is_err()
        );
        assert!(VerificationKey::from_der(&bad_parameters, SigningScheme::RsaPkcs1Sha256).is_err());
    }

    #[test]
    fn test_key_algorithm_parameter_rules() {
        use der::asn1::AnyRef;

        // A DER RSAPublicKey with two INTEGER fields, sufficient for parsing.
        let key_bytes = &[0x30, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x03];
        for (oid, expected) in [
            (ID_EC_PUBLIC_KEY, KeyAlgorithm::EcdsaP256),
            (RSA_ENCRYPTION, KeyAlgorithm::Rsa),
            (ID_ED25519, KeyAlgorithm::Ed25519),
            (ID_ML_DSA_44, KeyAlgorithm::MlDsa44),
            (ID_ML_DSA_65, KeyAlgorithm::MlDsa65),
            (ID_ML_DSA_87, KeyAlgorithm::MlDsa87),
        ] {
            let key = spki_der(oid, Some(SECP_256_R_1), key_bytes);
            let mut spki = SubjectPublicKeyInfoRef::try_from(key.as_bytes()).unwrap();
            let curve = spki.algorithm.parameters;
            for (parameters, valid) in [
                (curve, oid == ID_EC_PUBLIC_KEY),
                (None, oid != ID_EC_PUBLIC_KEY),
                (Some(AnyRef::NULL), oid == RSA_ENCRYPTION),
            ] {
                spki.algorithm.parameters = parameters;
                let result = key_algorithm(&spki);
                if valid {
                    assert_eq!(result.unwrap(), expected);
                } else {
                    assert!(matches!(result, Err(Error::InvalidKey(_))), "{oid}");
                }
            }
        }
    }

    #[test]
    fn test_from_spki_rejects_malformed_key() {
        let garbage = DerPublicKey::new(vec![0x30, 0x03, 0x01, 0x01, 0xff]);
        assert!(matches!(
            VerificationKey::from_spki(&garbage),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn test_from_spki_rejects_malformed_rsa() {
        // rsaEncryption: 1.2.840.113549.1.1.1
        let rsa_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        let key = spki_der(rsa_oid, None, &[0u8; 16]);
        assert!(matches!(
            VerificationKey::from_spki(&key),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn test_from_spki_rejects_unsupported_ec_curve() {
        let unsupported_curve = ObjectIdentifier::new_unwrap("1.3.132.0.35");
        let key = spki_der(ID_EC_PUBLIC_KEY, Some(unsupported_curve), &[0u8; 133]);
        assert!(matches!(
            VerificationKey::from_spki(&key),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn rsa_sha384_and_sha512_streaming_and_prehashed() {
        let data = b"rsa sha384 and sha512 verification test message";
        let digest256 = crate::hash::sha256(data);
        let digest384 = crate::hash::sha384(data);
        let digest512 = crate::hash::sha512(data);

        let (bare384, pkcs1_384, pss_384) =
            crate::backend::test_support::sign_rsa(data, HashAlgorithm::Sha2384);
        let spki384 = spki_der(RSA_ENCRYPTION, None, bare384.as_bytes());

        let vk_pkcs1_384 =
            VerificationKey::from_spki_with_scheme(&spki384, SigningScheme::RsaPkcs1Sha384)
                .unwrap();
        assert!(vk_pkcs1_384.verify(data, &pkcs1_384).is_ok());
        assert!(vk_pkcs1_384
            .verify_prehashed(&digest384, &pkcs1_384)
            .is_ok());
        assert!(vk_pkcs1_384
            .verify_prehashed(digest256.as_bytes(), &pkcs1_384)
            .is_err());
        assert!(vk_pkcs1_384.verify(data, &pss_384).is_err());

        // Cross-hash check: SHA-384 PKCS#1 signature must be rejected under SHA-256 and SHA-512 schemes
        let vk_pkcs1_256_on_384_key =
            VerificationKey::from_spki_with_scheme(&spki384, SigningScheme::RsaPkcs1Sha256)
                .unwrap();
        assert!(vk_pkcs1_256_on_384_key.verify(data, &pkcs1_384).is_err());
        assert!(vk_pkcs1_256_on_384_key
            .verify_prehashed(digest256.as_bytes(), &pkcs1_384)
            .is_err());

        let vk_pss_384 =
            VerificationKey::from_spki_with_scheme(&spki384, SigningScheme::RsaPssSha384).unwrap();
        assert!(vk_pss_384.verify(data, &pss_384).is_ok());
        assert!(vk_pss_384.verify_prehashed(&digest384, &pss_384).is_ok());
        assert!(vk_pss_384
            .verify_prehashed(digest256.as_bytes(), &pss_384)
            .is_err());
        assert!(vk_pss_384.verify(data, &pkcs1_384).is_err());

        let (bare512, pkcs1_512, pss_512) =
            crate::backend::test_support::sign_rsa(data, HashAlgorithm::Sha2512);
        let spki512 = spki_der(RSA_ENCRYPTION, None, bare512.as_bytes());

        let vk_pkcs1_512 =
            VerificationKey::from_spki_with_scheme(&spki512, SigningScheme::RsaPkcs1Sha512)
                .unwrap();
        assert!(vk_pkcs1_512.verify(data, &pkcs1_512).is_ok());
        assert!(vk_pkcs1_512
            .verify_prehashed(digest512.as_bytes(), &pkcs1_512)
            .is_ok());
        assert!(vk_pkcs1_512
            .verify_prehashed(&digest384, &pkcs1_512)
            .is_err());

        let vk_pss_512 =
            VerificationKey::from_spki_with_scheme(&spki512, SigningScheme::RsaPssSha512).unwrap();
        assert!(vk_pss_512.verify(data, &pss_512).is_ok());
        assert!(vk_pss_512
            .verify_prehashed(digest512.as_bytes(), &pss_512)
            .is_ok());
        assert!(vk_pss_512.verify_prehashed(&digest384, &pss_512).is_err());
    }

    #[test]
    fn mldsa_44_65_87_verify_and_cross_scheme_rejection() {
        let seed = [0x5au8; 32];
        let data = b"ml-dsa post-quantum verification test message";

        for (oid, scheme, other_scheme) in [
            (ID_ML_DSA_44, SigningScheme::MlDsa44, SigningScheme::MlDsa65),
            (ID_ML_DSA_65, SigningScheme::MlDsa65, SigningScheme::MlDsa87),
            (ID_ML_DSA_87, SigningScheme::MlDsa87, SigningScheme::MlDsa44),
        ] {
            let (raw_pk, sig) = crate::backend::test_support::sign_mldsa(scheme, &seed, data);
            let spki = spki_der(oid, None, &raw_pk);

            let vk = VerificationKey::from_spki(&spki).unwrap();
            assert_eq!(vk.scheme(), scheme);
            assert!(vk.verify(data, &sig).is_ok());
            assert!(vk.verify(b"wrong message", &sig).is_err());

            let mut bad_sig_bytes = sig.as_bytes().to_vec();
            bad_sig_bytes[0] ^= 0x01;
            let bad_sig = SignatureBytes::new(bad_sig_bytes);
            assert!(vk.verify(data, &bad_sig).is_err());

            // ML-DSA is pure (not prehashed) in sigstore-crypto
            let digest = crate::hash::sha256(data);
            assert!(matches!(
                vk.verify_prehashed(digest.as_bytes(), &sig),
                Err(Error::UnsupportedAlgorithm(_))
            ));

            // Cross-scheme rejection
            assert!(VerificationKey::from_spki_with_scheme(&spki, other_scheme).is_err());
        }
    }

    #[test]
    fn ed25519_rfc8032_static_test_vector() {
        // RFC 8032 §7.1 TEST 2 (1-byte message 0x72)
        let raw_pk: [u8; 32] = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];
        let sig_bytes: [u8; 64] = [
            0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64,
            0x25, 0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23,
            0xeb, 0xdb, 0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f,
            0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
            0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
        ];
        let spki = spki_der(ID_ED25519, None, &raw_pk);
        let vk = VerificationKey::from_spki(&spki).unwrap();
        let sig = SignatureBytes::new(sig_bytes.to_vec());
        assert!(vk.verify([0x72], &sig).is_ok());
        assert!(vk.verify([0x73], &sig).is_err());
    }

    #[test]
    fn test_ec_compressed_point_rejected() {
        // Compressed SEC1 point prefix (0x02) must be rejected by both backends.
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        let spki = spki_der(ID_EC_PUBLIC_KEY, Some(SECP_256_R_1), &compressed);
        let vk = VerificationKey::from_spki(&spki).unwrap();
        let dummy_sig = SignatureBytes::new(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        assert!(vk.verify(b"msg", &dummy_sig).is_err());
        let digest = crate::hash::sha256(b"msg");
        assert!(vk.verify_prehashed(digest.as_bytes(), &dummy_sig).is_err());
    }

    #[cfg(all(feature = "aws-lc-rs", feature = "boring"))]
    #[test]
    fn cross_backend_signature_interoperability() {
        let data = b"cross-backend interoperability test payload";
        let digest256 = crate::aws_lc::sha256(data);
        assert_eq!(digest256, crate::boring::sha256(data));
        let digest384 = crate::aws_lc::sha384(data);
        assert_eq!(digest384, crate::boring::sha384(data));
        let digest512 = crate::aws_lc::sha512(data);
        assert_eq!(digest512, crate::boring::sha512(data));

        // 1. ECDSA P-256 PKCS#8 + signing cross-verification
        for pkcs8 in [
            crate::aws_lc::test_support::generate_p256_pkcs8(),
            crate::boring::test_support::generate_p256_pkcs8(),
        ] {
            let aws_kp = crate::aws_lc::EcdsaP256KeyPair::from_pkcs8_der(&pkcs8).unwrap();
            let bor_kp = crate::boring::EcdsaP256KeyPair::from_pkcs8_der(&pkcs8).unwrap();
            assert_eq!(aws_kp.public_key_bytes(), bor_kp.public_key_bytes());

            let aws_sig = aws_kp.sign_digest(&digest256).unwrap();
            let bor_sig = bor_kp.sign_digest(&digest256).unwrap();

            assert!(crate::boring::verify_raw(
                SigningScheme::EcdsaP256Sha256,
                aws_kp.public_key_bytes(),
                data,
                &aws_sig
            )
            .is_ok());
            assert!(crate::aws_lc::verify_raw(
                SigningScheme::EcdsaP256Sha256,
                bor_kp.public_key_bytes(),
                data,
                &bor_sig
            )
            .is_ok());
        }

        // 2. ECDSA P-384 cross-verification
        let (p384_aws_pk, p384_aws_sig) = crate::aws_lc::test_support::sign_p384_sha384(data);
        assert!(crate::boring::verify_raw(
            SigningScheme::EcdsaP384Sha384,
            &p384_aws_pk,
            data,
            p384_aws_sig.as_bytes()
        )
        .is_ok());
        let (p384_bor_pk, p384_bor_sig) = crate::boring::test_support::sign_p384_sha384(data);
        assert!(crate::aws_lc::verify_raw(
            SigningScheme::EcdsaP384Sha384,
            &p384_bor_pk,
            data,
            p384_bor_sig.as_bytes()
        )
        .is_ok());

        // 3. Ed25519 cross-verification
        let (ed_aws_pk, ed_aws_sig) = crate::aws_lc::test_support::sign_ed25519(data);
        assert!(crate::boring::verify_raw(
            SigningScheme::Ed25519,
            &ed_aws_pk,
            data,
            ed_aws_sig.as_bytes()
        )
        .is_ok());
        let (ed_bor_pk, ed_bor_sig) = crate::boring::test_support::sign_ed25519(data);
        assert!(crate::aws_lc::verify_raw(
            SigningScheme::Ed25519,
            &ed_bor_pk,
            data,
            ed_bor_sig.as_bytes()
        )
        .is_ok());

        // 4. RSA PKCS#1 v1.5 and PSS (SHA-256, SHA-384, SHA-512) streaming & prehashed
        for (hash_alg, digest, pkcs1_scheme, pss_scheme) in [
            (
                HashAlgorithm::Sha2256,
                &digest256[..],
                SigningScheme::RsaPkcs1Sha256,
                SigningScheme::RsaPssSha256,
            ),
            (
                HashAlgorithm::Sha2384,
                &digest384[..],
                SigningScheme::RsaPkcs1Sha384,
                SigningScheme::RsaPssSha384,
            ),
            (
                HashAlgorithm::Sha2512,
                &digest512[..],
                SigningScheme::RsaPkcs1Sha512,
                SigningScheme::RsaPssSha512,
            ),
        ] {
            let (aws_rsa_pk, aws_pkcs1, aws_pss) =
                crate::aws_lc::test_support::sign_rsa(data, hash_alg);
            assert!(crate::boring::verify_raw(
                pkcs1_scheme,
                aws_rsa_pk.as_bytes(),
                data,
                aws_pkcs1.as_bytes()
            )
            .is_ok());
            assert!(crate::boring::verify_prehashed(
                pkcs1_scheme,
                aws_rsa_pk.as_bytes(),
                digest,
                aws_pkcs1.as_bytes()
            )
            .is_ok());
            assert!(crate::boring::verify_raw(
                pss_scheme,
                aws_rsa_pk.as_bytes(),
                data,
                aws_pss.as_bytes()
            )
            .is_ok());
            assert!(crate::boring::verify_prehashed(
                pss_scheme,
                aws_rsa_pk.as_bytes(),
                digest,
                aws_pss.as_bytes()
            )
            .is_ok());

            let (bor_rsa_pk, bor_pkcs1, bor_pss) =
                crate::boring::test_support::sign_rsa(data, hash_alg);
            assert!(crate::aws_lc::verify_raw(
                pkcs1_scheme,
                bor_rsa_pk.as_bytes(),
                data,
                bor_pkcs1.as_bytes()
            )
            .is_ok());
            assert!(crate::aws_lc::verify_prehashed(
                pkcs1_scheme,
                bor_rsa_pk.as_bytes(),
                digest,
                bor_pkcs1.as_bytes()
            )
            .is_ok());
            assert!(crate::aws_lc::verify_raw(
                pss_scheme,
                bor_rsa_pk.as_bytes(),
                data,
                bor_pss.as_bytes()
            )
            .is_ok());
            assert!(crate::aws_lc::verify_prehashed(
                pss_scheme,
                bor_rsa_pk.as_bytes(),
                digest,
                bor_pss.as_bytes()
            )
            .is_ok());
        }

        // 5. ML-DSA-44/65/87 cross-verification (and deterministic key derivation check)
        let seed = [0x7bu8; 32];
        for scheme in [
            SigningScheme::MlDsa44,
            SigningScheme::MlDsa65,
            SigningScheme::MlDsa87,
        ] {
            let (aws_pk, aws_sig) = crate::aws_lc::test_support::sign_mldsa(scheme, &seed, data);
            let (bor_pk, bor_sig) = crate::boring::test_support::sign_mldsa(scheme, &seed, data);
            assert_eq!(aws_pk, bor_pk);
            assert!(crate::boring::verify_raw(scheme, &aws_pk, data, aws_sig.as_bytes()).is_ok());
            assert!(crate::aws_lc::verify_raw(scheme, &bor_pk, data, bor_sig.as_bytes()).is_ok());
        }
    }
}
