//! Signature verification

use crate::error::{Error, Result};
use crate::signing::{KeyAlgorithm, SigningScheme};
#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA384_ASN1, ECDSA_P384_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1, ED25519, ML_DSA_44, ML_DSA_65, ML_DSA_87, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512, RSA_PSS_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
};
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1};
use const_oid::ObjectIdentifier;
use der::Decode;
use sigstore_types::{DerPublicKey, SignatureBytes};
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
struct RsaPublicKey<'a> {
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

    /// Create a verification key from raw `subjectPublicKey` bit-string bytes
    /// and a known signing scheme.
    pub(crate) fn from_raw_bytes(bytes: Vec<u8>, scheme: SigningScheme) -> Self {
        Self { bytes, scheme }
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

    #[cfg(feature = "aws-lc-rs")]
    fn verify_inner(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        match self.scheme {
            SigningScheme::EcdsaP256Sha256 => {
                let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("ECDSA P-256 SHA-256 signature invalid".to_string())
                })
            }
            SigningScheme::EcdsaP256Sha384 => {
                let key = UnparsedPublicKey::new(&ECDSA_P256_SHA384_ASN1, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("ECDSA P-256 SHA-384 signature invalid".to_string())
                })
            }
            SigningScheme::EcdsaP384Sha256 => {
                let key = UnparsedPublicKey::new(&ECDSA_P384_SHA256_ASN1, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("ECDSA P-384 SHA-256 signature invalid".to_string())
                })
            }
            SigningScheme::EcdsaP384Sha384 => {
                let key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("ECDSA P-384 SHA-384 signature invalid".to_string())
                })
            }
            SigningScheme::Ed25519 => {
                let key = UnparsedPublicKey::new(&ED25519, &self.bytes);
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("Ed25519 signature invalid".to_string()))
            }
            SigningScheme::RsaPssSha256 => {
                let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PSS SHA-256 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPssSha384 => {
                let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PSS SHA-384 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPssSha512 => {
                let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PSS SHA-512 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPkcs1Sha256 => {
                let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PKCS#1 SHA-256 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPkcs1Sha384 => {
                let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PKCS#1 SHA-384 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPkcs1Sha512 => {
                let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PKCS#1 SHA-512 signature invalid".to_string())
                })
            }
            SigningScheme::MlDsa44 => {
                let key = UnparsedPublicKey::new(&ML_DSA_44, &self.bytes);
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("ML-DSA-44 signature invalid".to_string()))
            }
            SigningScheme::MlDsa65 => {
                let key = UnparsedPublicKey::new(&ML_DSA_65, &self.bytes);
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("ML-DSA-65 signature invalid".to_string()))
            }
            SigningScheme::MlDsa87 => {
                let key = UnparsedPublicKey::new(&ML_DSA_87, &self.bytes);
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("ML-DSA-87 signature invalid".to_string()))
            }
        }
    }

    #[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
    fn verify_inner(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        use boring::hash::{hash, MessageDigest};
        use boring::nid::Nid;

        match self.scheme {
            SigningScheme::EcdsaP256Sha256 => {
                let digest = hash(MessageDigest::sha256(), data)
                    .map_err(|_| Error::Verification("ECDSA P-256 SHA-256 signature invalid".into()))?;
                boring_verify_ecdsa_digest(Nid::X9_62_PRIME256V1, &self.bytes, &digest, signature)
                    .map_err(|_| Error::Verification("ECDSA P-256 SHA-256 signature invalid".into()))
            }
            SigningScheme::EcdsaP256Sha384 => {
                let digest = hash(MessageDigest::sha384(), data)
                    .map_err(|_| Error::Verification("ECDSA P-256 SHA-384 signature invalid".into()))?;
                boring_verify_ecdsa_digest(Nid::X9_62_PRIME256V1, &self.bytes, &digest, signature)
                    .map_err(|_| Error::Verification("ECDSA P-256 SHA-384 signature invalid".into()))
            }
            SigningScheme::EcdsaP384Sha256 => {
                let digest = hash(MessageDigest::sha256(), data)
                    .map_err(|_| Error::Verification("ECDSA P-384 SHA-256 signature invalid".into()))?;
                boring_verify_ecdsa_digest(Nid::SECP384R1, &self.bytes, &digest, signature)
                    .map_err(|_| Error::Verification("ECDSA P-384 SHA-256 signature invalid".into()))
            }
            SigningScheme::EcdsaP384Sha384 => {
                let digest = hash(MessageDigest::sha384(), data)
                    .map_err(|_| Error::Verification("ECDSA P-384 SHA-384 signature invalid".into()))?;
                boring_verify_ecdsa_digest(Nid::SECP384R1, &self.bytes, &digest, signature)
                    .map_err(|_| Error::Verification("ECDSA P-384 SHA-384 signature invalid".into()))
            }
            SigningScheme::Ed25519 => boring_verify_ed25519(&self.bytes, data, signature)
                .map_err(|_| Error::Verification("Ed25519 signature invalid".into())),
            SigningScheme::RsaPssSha256 => {
                boring_verify_rsa(&self.bytes, MessageDigest::sha256(), true, data, signature)
                    .map_err(|_| Error::Verification("RSA PSS SHA-256 signature invalid".into()))
            }
            SigningScheme::RsaPssSha384 => {
                boring_verify_rsa(&self.bytes, MessageDigest::sha384(), true, data, signature)
                    .map_err(|_| Error::Verification("RSA PSS SHA-384 signature invalid".into()))
            }
            SigningScheme::RsaPssSha512 => {
                boring_verify_rsa(&self.bytes, MessageDigest::sha512(), true, data, signature)
                    .map_err(|_| Error::Verification("RSA PSS SHA-512 signature invalid".into()))
            }
            SigningScheme::RsaPkcs1Sha256 => {
                boring_verify_rsa(&self.bytes, MessageDigest::sha256(), false, data, signature)
                    .map_err(|_| Error::Verification("RSA PKCS#1 SHA-256 signature invalid".into()))
            }
            SigningScheme::RsaPkcs1Sha384 => {
                boring_verify_rsa(&self.bytes, MessageDigest::sha384(), false, data, signature)
                    .map_err(|_| Error::Verification("RSA PKCS#1 SHA-384 signature invalid".into()))
            }
            SigningScheme::RsaPkcs1Sha512 => {
                boring_verify_rsa(&self.bytes, MessageDigest::sha512(), false, data, signature)
                    .map_err(|_| Error::Verification("RSA PKCS#1 SHA-512 signature invalid".into()))
            }
            SigningScheme::MlDsa44 => {
                let key = boring::mldsa::MlDsaPublicKey::from_slice(
                    boring::mldsa::Algorithm::MlDsa44,
                    &self.bytes,
                )
                .map_err(|_| Error::Verification("ML-DSA-44 signature invalid".into()))?;
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("ML-DSA-44 signature invalid".into()))
            }
            SigningScheme::MlDsa65 => {
                let key = boring::mldsa::MlDsaPublicKey::from_slice(
                    boring::mldsa::Algorithm::MlDsa65,
                    &self.bytes,
                )
                .map_err(|_| Error::Verification("ML-DSA-65 signature invalid".into()))?;
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("ML-DSA-65 signature invalid".into()))
            }
            SigningScheme::MlDsa87 => {
                let key = boring::mldsa::MlDsaPublicKey::from_slice(
                    boring::mldsa::Algorithm::MlDsa87,
                    &self.bytes,
                )
                .map_err(|_| Error::Verification("ML-DSA-87 signature invalid".into()))?;
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("ML-DSA-87 signature invalid".into()))
            }
        }
    }

    /// Verify a signature over prehashed data
    ///
    /// This is used for hashedrekord verification where the signature is over
    /// a pre-computed hash of the artifact, not the artifact itself.
    pub fn verify_prehashed(&self, digest: &[u8], signature: &SignatureBytes) -> Result<()> {
        #[cfg(feature = "aws-lc-rs")]
        {
            use aws_lc_rs::digest::{Digest, SHA256, SHA384, SHA512};
            use aws_lc_rs::signature::VerificationAlgorithm;

            // Determine the expected hash algorithm and ASN.1 algorithm from the SigningScheme
            let (aws_algo, asn1_algo): (
                &aws_lc_rs::digest::Algorithm,
                &'static dyn VerificationAlgorithm,
            ) = match self.scheme {
                SigningScheme::EcdsaP256Sha256 => (&SHA256, &ECDSA_P256_SHA256_ASN1),
                SigningScheme::EcdsaP256Sha384 => (&SHA384, &ECDSA_P256_SHA384_ASN1),
                SigningScheme::EcdsaP384Sha256 => (&SHA256, &ECDSA_P384_SHA256_ASN1),
                SigningScheme::EcdsaP384Sha384 => (&SHA384, &ECDSA_P384_SHA384_ASN1),
                SigningScheme::RsaPssSha256 => (&SHA256, &RSA_PSS_2048_8192_SHA256),
                SigningScheme::RsaPssSha384 => (&SHA384, &RSA_PSS_2048_8192_SHA384),
                SigningScheme::RsaPssSha512 => (&SHA512, &RSA_PSS_2048_8192_SHA512),
                SigningScheme::RsaPkcs1Sha256 => (&SHA256, &RSA_PKCS1_2048_8192_SHA256),
                SigningScheme::RsaPkcs1Sha384 => (&SHA384, &RSA_PKCS1_2048_8192_SHA384),
                SigningScheme::RsaPkcs1Sha512 => (&SHA512, &RSA_PKCS1_2048_8192_SHA512),
                _ => {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Scheme {:?} does not support prehashed mode",
                        self.scheme
                    )));
                }
            };

            let aws_digest = Digest::import_less_safe(digest, aws_algo).map_err(|_| {
                Error::Verification(format!(
                    "Failed to import digest: len={}, algo_expected_len={}",
                    digest.len(),
                    aws_algo.output_len
                ))
            })?;

            let key = UnparsedPublicKey::new(asn1_algo, &self.bytes);
            key.verify_digest(&aws_digest, signature.as_bytes())
                .map_err(|e| Error::Verification(format!("Signature invalid: {}", e)))
        }

        #[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
        {
            use boring::hash::MessageDigest;
            use boring::nid::Nid;

            let expected_len: usize = match self.scheme {
                SigningScheme::EcdsaP256Sha256
                | SigningScheme::EcdsaP384Sha256
                | SigningScheme::RsaPssSha256
                | SigningScheme::RsaPkcs1Sha256 => 32,
                SigningScheme::EcdsaP256Sha384
                | SigningScheme::EcdsaP384Sha384
                | SigningScheme::RsaPssSha384
                | SigningScheme::RsaPkcs1Sha384 => 48,
                SigningScheme::RsaPssSha512 | SigningScheme::RsaPkcs1Sha512 => 64,
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

            let sig = signature.as_bytes();
            let res = match self.scheme {
                SigningScheme::EcdsaP256Sha256 | SigningScheme::EcdsaP256Sha384 => {
                    boring_verify_ecdsa_digest(Nid::X9_62_PRIME256V1, &self.bytes, digest, sig)
                }
                SigningScheme::EcdsaP384Sha256 | SigningScheme::EcdsaP384Sha384 => {
                    boring_verify_ecdsa_digest(Nid::SECP384R1, &self.bytes, digest, sig)
                }
                SigningScheme::RsaPkcs1Sha256
                | SigningScheme::RsaPkcs1Sha384
                | SigningScheme::RsaPkcs1Sha512 => {
                    boring_verify_rsa_pkcs1_prehashed(&self.bytes, digest, sig)
                }
                SigningScheme::RsaPssSha256 => {
                    boring_verify_rsa_pss_prehashed(&self.bytes, MessageDigest::sha256(), digest, sig)
                }
                SigningScheme::RsaPssSha384 => {
                    boring_verify_rsa_pss_prehashed(&self.bytes, MessageDigest::sha384(), digest, sig)
                }
                SigningScheme::RsaPssSha512 => {
                    boring_verify_rsa_pss_prehashed(&self.bytes, MessageDigest::sha512(), digest, sig)
                }
                _ => unreachable!(),
            };

            res.map_err(|_| Error::Verification("Signature invalid".to_string()))
        }
    }
}

#[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
fn boring_verify_ecdsa_digest(
    curve: boring::nid::Nid,
    pubkey_bytes: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    if pubkey_bytes.first() != Some(&0x04) {
        return Err(());
    }
    let group = boring::ec::EcGroup::from_curve_name(curve).map_err(|_| ())?;
    let mut ctx = boring::bn::BigNumContext::new().map_err(|_| ())?;
    let point = boring::ec::EcPoint::from_bytes(&group, pubkey_bytes, &mut ctx).map_err(|_| ())?;
    let ec_key = boring::ec::EcKey::from_public_key(&group, &point).map_err(|_| ())?;
    ec_key.check_key().map_err(|_| ())?;

    let sig = boring::ecdsa::EcdsaSig::from_der(signature).map_err(|_| ())?;
    // Require canonical ASN.1 DER with no trailing bytes.
    if sig.to_der().map_err(|_| ())? != signature {
        return Err(());
    }
    if sig.verify(digest, &ec_key).map_err(|_| ())? {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
fn boring_verify_ed25519(
    pubkey_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    if pubkey_bytes.len() != 32 || signature.len() != 64 {
        return Err(());
    }
    // RFC 8410 SubjectPublicKeyInfo prefix for a 32-byte Ed25519 public key.
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&ED25519_SPKI_PREFIX);
    spki.extend_from_slice(pubkey_bytes);

    let pkey = boring::pkey::PKey::public_key_from_der(&spki).map_err(|_| ())?;
    let mut verifier = boring::sign::Verifier::new_without_digest(&pkey).map_err(|_| ())?;
    if verifier.verify_oneshot(signature, data).map_err(|_| ())? {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
fn boring_parse_rsa_public_key(
    pubkey_bytes: &[u8],
) -> std::result::Result<boring::rsa::Rsa<boring::pkey::Public>, ()> {
    RsaPublicKey::from_der(pubkey_bytes).map_err(|_| ())?;
    let rsa = boring::rsa::Rsa::public_key_from_der_pkcs1(pubkey_bytes).map_err(|_| ())?;
    let bits = rsa.n().num_bits();
    if !(2048..=8192).contains(&bits) {
        return Err(());
    }
    Ok(rsa)
}

#[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
fn boring_verify_rsa(
    pubkey_bytes: &[u8],
    md: boring::hash::MessageDigest,
    pss: bool,
    data: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let rsa = boring_parse_rsa_public_key(pubkey_bytes)?;
    let pkey = boring::pkey::PKey::from_rsa(rsa).map_err(|_| ())?;
    let mut verifier = boring::sign::Verifier::new(md, &pkey).map_err(|_| ())?;
    if pss {
        verifier
            .set_rsa_padding(boring::rsa::Padding::PKCS1_PSS)
            .map_err(|_| ())?;
        verifier.set_rsa_mgf1_md(md).map_err(|_| ())?;
        verifier
            .set_rsa_pss_saltlen(boring::sign::RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|_| ())?;
    }
    verifier.update(data).map_err(|_| ())?;
    if verifier.verify(signature).map_err(|_| ())? {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
fn boring_verify_rsa_pkcs1_prehashed(
    pubkey_bytes: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let rsa = boring_parse_rsa_public_key(pubkey_bytes)?;
    if signature.len() != rsa.size() as usize {
        return Err(());
    }
    let mut decrypted = vec![0u8; rsa.size() as usize];
    let len = rsa
        .public_decrypt(signature, &mut decrypted, boring::rsa::Padding::PKCS1)
        .map_err(|_| ())?;
    let digest_info = &decrypted[..len];

    // RFC 8017 §9.2 DER DigestInfo prefixes (with NULL parameters and with absent parameters).
    let (prefix_with_null, prefix_without_null): (&[u8], &[u8]) = match digest.len() {
        32 => (
            &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            &[
                0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x04, 0x20,
            ],
        ),
        48 => (
            &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            &[
                0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x04, 0x30,
            ],
        ),
        64 => (
            &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
            &[
                0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x04, 0x40,
            ],
        ),
        _ => return Err(()),
    };

    let matches_prefix = |prefix: &[u8]| {
        digest_info.len() == prefix.len() + digest.len()
            && &digest_info[..prefix.len()] == prefix
            && &digest_info[prefix.len()..] == digest
    };

    if matches_prefix(prefix_with_null) || matches_prefix(prefix_without_null) {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
fn boring_verify_rsa_pss_prehashed(
    pubkey_bytes: &[u8],
    md: boring::hash::MessageDigest,
    digest: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let rsa = boring_parse_rsa_public_key(pubkey_bytes)?;
    let mod_len = rsa.size() as usize;
    if signature.len() != mod_len {
        return Err(());
    }
    let mut em_buf = vec![0u8; mod_len];
    let len = rsa
        .public_decrypt(signature, &mut em_buf, boring::rsa::Padding::NONE)
        .map_err(|_| ())?;
    if len != mod_len {
        return Err(());
    }

    // RFC 8017 §9.1.2 EMSA-PSS-VERIFY with sLen = hLen and MGF1(md).
    let mod_bits = rsa.n().num_bits() as usize;
    let em_bits = mod_bits.checked_sub(1).ok_or(())?;
    let em_len = em_bits.div_ceil(8);
    let em = if em_len < mod_len {
        if em_buf[..mod_len - em_len].iter().any(|&b| b != 0) {
            return Err(());
        }
        &em_buf[mod_len - em_len..]
    } else {
        &em_buf[..]
    };

    let h_len = digest.len();
    let s_len = h_len;
    if em_len < h_len + s_len + 2 || em[em_len - 1] != 0xbc {
        return Err(());
    }

    let db_len = em_len - h_len - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..em_len - 1];

    let top_zero_bits = 8 * em_len - em_bits;
    let top_mask = 0xffu8 >> top_zero_bits;
    if masked_db[0] & !top_mask != 0 {
        return Err(());
    }

    // MGF1 (RFC 8017 §B.2.1)
    let mut db = Vec::with_capacity(db_len);
    let mut counter: u32 = 0;
    while db.len() < db_len {
        let mut hasher = boring::hash::Hasher::new(md).map_err(|_| ())?;
        hasher.update(h).map_err(|_| ())?;
        hasher.update(&counter.to_be_bytes()).map_err(|_| ())?;
        let mask_chunk = hasher.finish().map_err(|_| ())?;
        for &b in mask_chunk.as_ref() {
            if db.len() < db_len {
                db.push(masked_db[db.len()] ^ b);
            }
        }
        counter += 1;
    }
    db[0] &= top_mask;

    let zero_pad_len = em_len - h_len - s_len - 2;
    if db[..zero_pad_len].iter().any(|&b| b != 0) || db[zero_pad_len] != 0x01 {
        return Err(());
    }

    let salt = &db[zero_pad_len + 1..];
    let mut h_prime_hasher = boring::hash::Hasher::new(md).map_err(|_| ())?;
    h_prime_hasher.update(&[0u8; 8]).map_err(|_| ())?;
    h_prime_hasher.update(digest).map_err(|_| ())?;
    h_prime_hasher.update(salt).map_err(|_| ())?;
    let h_prime = h_prime_hasher.finish().map_err(|_| ())?;

    if h_prime.as_ref() == h {
        Ok(())
    } else {
        Err(())
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

        #[cfg(feature = "aws-lc-rs")]
        let (raw_pubkey, sig) = {
            use aws_lc_rs::rand::SystemRandom;
            use aws_lc_rs::signature::{
                EcdsaKeyPair, KeyPair as AwsKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING,
            };

            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
            let kp =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
            let sig = SignatureBytes::new(kp.sign(&rng, data).unwrap().as_ref().to_vec());
            (kp.public_key().as_ref().to_vec(), sig)
        };

        #[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
        let (raw_pubkey, sig) = {
            let group =
                boring::ec::EcGroup::from_curve_name(boring::nid::Nid::SECP384R1).unwrap();
            let ec_key = boring::ec::EcKey::generate(&group).unwrap();
            let mut ctx = boring::bn::BigNumContext::new().unwrap();
            let raw_pubkey = ec_key
                .public_key()
                .to_bytes(&group, boring::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)
                .unwrap();
            let pkey = boring::pkey::PKey::from_ec_key(ec_key).unwrap();
            let mut signer =
                boring::sign::Signer::new(boring::hash::MessageDigest::sha384(), &pkey).unwrap();
            signer.update(data).unwrap();
            let sig = SignatureBytes::new(signer.sign_to_vec().unwrap());
            (raw_pubkey, sig)
        };

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

        #[cfg(feature = "aws-lc-rs")]
        let (pubkey, sig) = {
            use aws_lc_rs::rand::SystemRandom;
            use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as AwsKeyPair};

            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
            let sig = SignatureBytes::new(kp.sign(data).as_ref().to_vec());
            let pubkey = spki_der(ID_ED25519, None, kp.public_key().as_ref());
            (pubkey, sig)
        };

        #[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
        let (pubkey, sig) = {
            let pkey = boring::pkey::PKey::generate(boring::pkey::Id::ED25519).unwrap();
            let mut signer = boring::sign::Signer::new_without_digest(&pkey).unwrap();
            let sig = SignatureBytes::new(signer.sign_oneshot_to_vec(data).unwrap());
            let pubkey = DerPublicKey::new(pkey.public_key_to_der().unwrap());
            (pubkey, sig)
        };

        let vk = VerificationKey::from_spki(&pubkey).unwrap();
        assert_eq!(vk.scheme(), SigningScheme::Ed25519);
        assert!(vk.verify(data, &sig).is_ok());
    }

    #[test]
    fn rsa_autodetection_and_explicit_schemes_share_checked_parsing() {
        let data = b"rsa verification test message";
        let digest = crate::hash::sha256(data);

        #[cfg(feature = "aws-lc-rs")]
        let (bare, pkcs1_sig, pss_sig) = {
            use aws_lc_rs::{
                rand::SystemRandom,
                rsa::KeySize,
                signature::{
                    KeyPair as _, RsaKeyPair, RSA_PKCS1_SHA256, RSA_PSS_SHA256,
                },
            };
            let rng = SystemRandom::new();
            let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
            let bare = DerPublicKey::new(key.public_key().as_ref().to_vec());
            let mut pkcs1_buf = vec![0u8; key.public_modulus_len()];
            key.sign(&RSA_PKCS1_SHA256, &rng, data, &mut pkcs1_buf)
                .unwrap();
            let mut pss_buf = vec![0u8; key.public_modulus_len()];
            key.sign(&RSA_PSS_SHA256, &rng, data, &mut pss_buf)
                .unwrap();
            (
                bare,
                SignatureBytes::new(pkcs1_buf),
                SignatureBytes::new(pss_buf),
            )
        };

        #[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
        let (bare, pkcs1_sig, pss_sig) = {
            let rsa = boring::rsa::Rsa::generate(2048).unwrap();
            let bare = DerPublicKey::new(rsa.public_key_to_der_pkcs1().unwrap());
            let pkey = boring::pkey::PKey::from_rsa(rsa).unwrap();
            let mut pkcs1_signer =
                boring::sign::Signer::new(boring::hash::MessageDigest::sha256(), &pkey).unwrap();
            pkcs1_signer.update(data).unwrap();
            let pkcs1_sig = SignatureBytes::new(pkcs1_signer.sign_to_vec().unwrap());

            let mut pss_signer =
                boring::sign::Signer::new(boring::hash::MessageDigest::sha256(), &pkey).unwrap();
            pss_signer
                .set_rsa_padding(boring::rsa::Padding::PKCS1_PSS)
                .unwrap();
            pss_signer
                .set_rsa_mgf1_md(boring::hash::MessageDigest::sha256())
                .unwrap();
            pss_signer
                .set_rsa_pss_saltlen(boring::sign::RsaPssSaltlen::DIGEST_LENGTH)
                .unwrap();
            pss_signer.update(data).unwrap();
            let pss_sig = SignatureBytes::new(pss_signer.sign_to_vec().unwrap());
            (bare, pkcs1_sig, pss_sig)
        };

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
}
