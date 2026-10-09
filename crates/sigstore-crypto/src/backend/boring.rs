//! `boring` (BoringSSL) cryptographic backend implementation.

use crate::error::{Error, Result};
use crate::signing::SigningScheme;
use crate::verification::RsaPublicKey;
use boring::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::{hash, Hasher, MessageDigest},
    mldsa::{Algorithm as MlDsaAlgorithm, MlDsaPublicKey},
    nid::Nid,
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Verifier},
};
use der::Decode as _;
use sigstore_types::HashAlgorithm;

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = hash(MessageDigest::sha256(), data).expect("SHA-256 hashing failed");
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

pub(crate) fn sha384(data: &[u8]) -> Vec<u8> {
    hash(MessageDigest::sha384(), data)
        .expect("SHA-384 hashing failed")
        .to_vec()
}

pub(crate) fn sha512(data: &[u8]) -> [u8; 64] {
    let digest = hash(MessageDigest::sha512(), data).expect("SHA-512 hashing failed");
    let mut result = [0u8; 64];
    result.copy_from_slice(&digest);
    result
}

fn message_digest(algorithm: HashAlgorithm) -> Result<MessageDigest> {
    match algorithm {
        HashAlgorithm::Sha2256 => Ok(MessageDigest::sha256()),
        HashAlgorithm::Sha2384 => Ok(MessageDigest::sha384()),
        HashAlgorithm::Sha2512 => Ok(MessageDigest::sha512()),
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "cannot compute {algorithm} digests"
        ))),
    }
}

pub(crate) struct DigestContext(Hasher);

impl DigestContext {
    pub(crate) fn new(algorithm: HashAlgorithm) -> Result<Self> {
        let md = message_digest(algorithm)?;
        let hasher = Hasher::new(md).map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;
        Ok(Self(hasher))
    }

    pub(crate) fn new_sha256() -> Self {
        Self(Hasher::new(MessageDigest::sha256()).expect("SHA-256 hasher initialization failed"))
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("hasher update failed");
    }

    pub(crate) fn finalize_vec(mut self) -> Vec<u8> {
        self.0.finish().expect("hasher finish failed").to_vec()
    }

    pub(crate) fn finalize_sha256(mut self) -> [u8; 32] {
        let digest = self.0.finish().expect("hasher finish failed");
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest);
        result
    }
}

pub(crate) struct EcdsaP256KeyPair {
    ec_key: EcKey<Private>,
    public_key_bytes: Vec<u8>,
}

impl EcdsaP256KeyPair {
    pub(crate) fn generate() -> Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|_| Error::KeyGeneration("failed to generate ECDSA P-256 key".to_string()))?;
        let ec_key = EcKey::generate(&group)
            .map_err(|_| Error::KeyGeneration("failed to generate ECDSA P-256 key".to_string()))?;
        Self::from_ec_key(ec_key)
    }

    pub(crate) fn from_pkcs8_der(pkcs8: &[u8]) -> Result<Self> {
        // BoringSSL's `d2i_PKCS8_PRIV_KEY_INFO` ignores trailing bytes; verify
        // that `pkcs8` is a single complete DER element first.
        der::asn1::AnyRef::from_der(pkcs8).map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        let pkey = PKey::private_key_from_pkcs8(pkcs8)
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        let ec_key = pkey
            .ec_key()
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        if ec_key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err(Error::InvalidKeyFormat(
                "expected ECDSA P-256 private key".to_string(),
            ));
        }
        ec_key
            .check_key()
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        Self::from_ec_key(ec_key)
    }

    fn from_ec_key(ec_key: EcKey<Private>) -> Result<Self> {
        let mut ctx = BigNumContext::new().map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        let public_key_bytes = ec_key
            .public_key()
            .to_bytes(ec_key.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        Ok(Self {
            ec_key,
            public_key_bytes,
        })
    }

    pub(crate) fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }

    pub(crate) fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let sig = EcdsaSig::sign(digest, &self.ec_key)
            .map_err(|_| Error::Signing("the cryptographic backend failed to sign".to_string()))?;
        sig.to_der()
            .map_err(|_| Error::Signing("the cryptographic backend failed to sign".to_string()))
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
        SigningScheme::Ed25519 => verify_ed25519(pubkey_bytes, data, signature),
        SigningScheme::RsaPssSha256 => {
            verify_rsa(pubkey_bytes, MessageDigest::sha256(), true, data, signature)
        }
        SigningScheme::RsaPssSha384 => {
            verify_rsa(pubkey_bytes, MessageDigest::sha384(), true, data, signature)
        }
        SigningScheme::RsaPssSha512 => {
            verify_rsa(pubkey_bytes, MessageDigest::sha512(), true, data, signature)
        }
        SigningScheme::RsaPkcs1Sha256 => verify_rsa(
            pubkey_bytes,
            MessageDigest::sha256(),
            false,
            data,
            signature,
        ),
        SigningScheme::RsaPkcs1Sha384 => verify_rsa(
            pubkey_bytes,
            MessageDigest::sha384(),
            false,
            data,
            signature,
        ),
        SigningScheme::RsaPkcs1Sha512 => verify_rsa(
            pubkey_bytes,
            MessageDigest::sha512(),
            false,
            data,
            signature,
        ),
        SigningScheme::MlDsa44 => {
            let key = MlDsaPublicKey::from_slice(MlDsaAlgorithm::MlDsa44, pubkey_bytes)
                .map_err(|_| ())?;
            key.verify(data, signature).map_err(|_| ())
        }
        SigningScheme::MlDsa65 => {
            let key = MlDsaPublicKey::from_slice(MlDsaAlgorithm::MlDsa65, pubkey_bytes)
                .map_err(|_| ())?;
            key.verify(data, signature).map_err(|_| ())
        }
        SigningScheme::MlDsa87 => {
            let key = MlDsaPublicKey::from_slice(MlDsaAlgorithm::MlDsa87, pubkey_bytes)
                .map_err(|_| ())?;
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
    let hash_alg = scheme.hash_algorithm().ok_or(())?;
    match scheme {
        SigningScheme::EcdsaP256Sha256 | SigningScheme::EcdsaP256Sha384 => {
            verify_ecdsa_digest(Nid::X9_62_PRIME256V1, pubkey_bytes, digest, signature)
        }
        SigningScheme::EcdsaP384Sha256 | SigningScheme::EcdsaP384Sha384 => {
            verify_ecdsa_digest(Nid::SECP384R1, pubkey_bytes, digest, signature)
        }
        SigningScheme::RsaPkcs1Sha256
        | SigningScheme::RsaPkcs1Sha384
        | SigningScheme::RsaPkcs1Sha512 => {
            verify_rsa_pkcs1_prehashed(pubkey_bytes, hash_alg, digest, signature)
        }
        SigningScheme::RsaPssSha256 | SigningScheme::RsaPssSha384 | SigningScheme::RsaPssSha512 => {
            let md = message_digest(hash_alg).map_err(|_| ())?;
            verify_rsa_pss_prehashed(pubkey_bytes, md, digest, signature)
        }
        _ => Err(()),
    }
}

fn verify_ecdsa_digest(
    curve: Nid,
    pubkey_bytes: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    if pubkey_bytes.first() != Some(&0x04) {
        return Err(());
    }
    let group = EcGroup::from_curve_name(curve).map_err(|_| ())?;
    let mut ctx = BigNumContext::new().map_err(|_| ())?;
    let point = EcPoint::from_bytes(&group, pubkey_bytes, &mut ctx).map_err(|_| ())?;
    let ec_key = EcKey::from_public_key(&group, &point).map_err(|_| ())?;
    ec_key.check_key().map_err(|_| ())?;

    let sig = EcdsaSig::from_der(signature).map_err(|_| ())?;
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

fn verify_ed25519(
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

    let pkey = PKey::public_key_from_der(&spki).map_err(|_| ())?;
    let mut verifier = Verifier::new_without_digest(&pkey).map_err(|_| ())?;
    if verifier.verify_oneshot(signature, data).map_err(|_| ())? {
        Ok(())
    } else {
        Err(())
    }
}

fn parse_rsa_public_key(pubkey_bytes: &[u8]) -> std::result::Result<Rsa<Public>, ()> {
    RsaPublicKey::from_der(pubkey_bytes).map_err(|_| ())?;
    let rsa = Rsa::public_key_from_der_pkcs1(pubkey_bytes).map_err(|_| ())?;
    let bits = rsa.n().num_bits();
    if !(2048..=8192).contains(&bits) {
        return Err(());
    }
    Ok(rsa)
}

fn verify_rsa(
    pubkey_bytes: &[u8],
    md: MessageDigest,
    pss: bool,
    data: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let rsa = parse_rsa_public_key(pubkey_bytes)?;
    let pkey = PKey::from_rsa(rsa).map_err(|_| ())?;
    let mut verifier = Verifier::new(md, &pkey).map_err(|_| ())?;
    if pss {
        verifier
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|_| ())?;
        verifier.set_rsa_mgf1_md(md).map_err(|_| ())?;
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|_| ())?;
    }
    verifier.update(data).map_err(|_| ())?;
    if verifier.verify(signature).map_err(|_| ())? {
        Ok(())
    } else {
        Err(())
    }
}

fn verify_rsa_pkcs1_prehashed(
    pubkey_bytes: &[u8],
    hash_alg: HashAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let rsa = parse_rsa_public_key(pubkey_bytes)?;
    if signature.len() != rsa.size() as usize {
        return Err(());
    }
    let mut decrypted = vec![0u8; rsa.size() as usize];
    let len = rsa
        .public_decrypt(signature, &mut decrypted, Padding::PKCS1)
        .map_err(|_| ())?;
    verify_emsa_pkcs1_digest_info(&decrypted[..len], hash_alg, digest)
}

/// Check that the PKCS#1 v1.5 unpadded `DigestInfo` matches the expected hash
/// algorithm OID prefix (RFC 8017 §9.2) and `digest`.
pub(crate) fn verify_emsa_pkcs1_digest_info(
    digest_info: &[u8],
    hash_alg: HashAlgorithm,
    digest: &[u8],
) -> std::result::Result<(), ()> {
    // RFC 8017 §9.2 DER DigestInfo prefixes (with NULL parameters and with absent parameters).
    let (expected_len, prefix_with_null, prefix_without_null): (usize, &[u8], &[u8]) =
        match hash_alg {
            HashAlgorithm::Sha2256 => (
                32,
                &[
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                ],
                &[
                    0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x01, 0x04, 0x20,
                ],
            ),
            HashAlgorithm::Sha2384 => (
                48,
                &[
                    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
                ],
                &[
                    0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x02, 0x04, 0x30,
                ],
            ),
            HashAlgorithm::Sha2512 => (
                64,
                &[
                    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
                ],
                &[
                    0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x03, 0x04, 0x40,
                ],
            ),
            _ => return Err(()),
        };

    if digest.len() != expected_len {
        return Err(());
    }

    let matches_prefix = |prefix: &[u8]| {
        digest_info.len() == prefix.len() + digest.len()
            && boring::memcmp::eq(&digest_info[..prefix.len()], prefix)
            && boring::memcmp::eq(&digest_info[prefix.len()..], digest)
    };

    if matches_prefix(prefix_with_null) || matches_prefix(prefix_without_null) {
        Ok(())
    } else {
        Err(())
    }
}

fn verify_rsa_pss_prehashed(
    pubkey_bytes: &[u8],
    md: MessageDigest,
    digest: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let rsa = parse_rsa_public_key(pubkey_bytes)?;
    let mod_len = rsa.size() as usize;
    if signature.len() != mod_len {
        return Err(());
    }
    let mut em_buf = vec![0u8; mod_len];
    let len = rsa
        .public_decrypt(signature, &mut em_buf, Padding::NONE)
        .map_err(|_| ())?;
    if len != mod_len {
        return Err(());
    }
    let mod_bits = rsa.n().num_bits() as usize;
    verify_emsa_pss(&em_buf, mod_bits, md, digest)
}

/// Verify RFC 8017 §9.1.2 `EMSA-PSS-VERIFY` with `sLen = hLen` and `MGF1(md)`.
pub(crate) fn verify_emsa_pss(
    em_buf: &[u8],
    mod_bits: usize,
    md: MessageDigest,
    digest: &[u8],
) -> std::result::Result<(), ()> {
    let mod_len = em_buf.len();
    let em_bits = mod_bits.checked_sub(1).ok_or(())?;
    let em_len = em_bits.div_ceil(8);
    if em_len > mod_len {
        return Err(());
    }
    let em = if em_len < mod_len {
        if em_buf[..mod_len - em_len].iter().any(|&b| b != 0) {
            return Err(());
        }
        &em_buf[mod_len - em_len..]
    } else {
        em_buf
    };

    let h_len = md.size();
    if digest.len() != h_len {
        return Err(());
    }
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
        let mut hasher = Hasher::new(md).map_err(|_| ())?;
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
    let mut h_prime_hasher = Hasher::new(md).map_err(|_| ())?;
    h_prime_hasher.update(&[0u8; 8]).map_err(|_| ())?;
    h_prime_hasher.update(digest).map_err(|_| ())?;
    h_prime_hasher.update(salt).map_err(|_| ())?;
    let h_prime = h_prime_hasher.finish().map_err(|_| ())?;

    if boring::memcmp::eq(h_prime.as_ref(), h) {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use boring::{pkey::Id, sign::Signer};
    use sigstore_types::{DerPublicKey, SignatureBytes};

    pub(crate) fn generate_p256_pkcs8() -> Vec<u8> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        pkey.private_key_to_der_pkcs8().unwrap()
    }

    pub(crate) fn sign_p384_sha384(data: &[u8]) -> (Vec<u8>, SignatureBytes) {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let raw_pubkey = ec_key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
        signer.update(data).unwrap();
        let sig = SignatureBytes::new(signer.sign_to_vec().unwrap());
        (raw_pubkey, sig)
    }

    pub(crate) fn sign_ed25519(data: &[u8]) -> (Vec<u8>, SignatureBytes) {
        let pkey = PKey::generate(Id::ED25519).unwrap();
        let mut signer = Signer::new_without_digest(&pkey).unwrap();
        let sig = SignatureBytes::new(signer.sign_oneshot_to_vec(data).unwrap());
        let spki = pkey.public_key_to_der().unwrap();
        // Last 32 bytes of RFC 8410 Ed25519 SPKI are the raw public key.
        let raw_pubkey = spki[spki.len() - 32..].to_vec();
        (raw_pubkey, sig)
    }

    pub(crate) fn sign_rsa(
        data: &[u8],
        hash_alg: HashAlgorithm,
    ) -> (DerPublicKey, SignatureBytes, SignatureBytes) {
        let rsa = Rsa::generate(2048).unwrap();
        let bare = DerPublicKey::new(rsa.public_key_to_der_pkcs1().unwrap());
        let pkey = PKey::from_rsa(rsa).unwrap();
        let md = message_digest(hash_alg).unwrap();

        let mut pkcs1_signer = Signer::new(md, &pkey).unwrap();
        pkcs1_signer.update(data).unwrap();
        let pkcs1_sig = SignatureBytes::new(pkcs1_signer.sign_to_vec().unwrap());

        let mut pss_signer = Signer::new(md, &pkey).unwrap();
        pss_signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        pss_signer.set_rsa_mgf1_md(md).unwrap();
        pss_signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .unwrap();
        pss_signer.update(data).unwrap();
        let pss_sig = SignatureBytes::new(pss_signer.sign_to_vec().unwrap());

        (bare, pkcs1_sig, pss_sig)
    }
}
