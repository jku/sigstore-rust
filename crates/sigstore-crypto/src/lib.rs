//! Cryptographic primitives for Sigstore
//!
//! This crate provides key generation, signing, and verification functionality
//! using `aws-lc-rs` (default) or `boring` as the cryptographic backend.

#![warn(missing_docs)]

#[cfg(not(any(feature = "aws-lc-rs", feature = "boring")))]
compile_error!("Either feature \"aws-lc-rs\" or \"boring\" must be enabled for sigstore-crypto.");

#[cfg(feature = "aws-lc-rs")]
#[path = "backend/aws_lc.rs"]
mod backend;

#[cfg(all(feature = "boring", not(feature = "aws-lc-rs")))]
#[path = "backend/boring.rs"]
mod backend;

pub mod checkpoint;
pub mod error;
pub mod hash;
pub mod keyring;
pub mod signing;
pub mod verification;
pub mod webpki;
pub mod x509;

pub use checkpoint::{compute_key_hint, Checkpoint, CheckpointSignature, CheckpointVerifyExt};
pub use error::{Error, Result};
pub use hash::{
    hash_async_reader, hash_reader, hash_reader_yielding, hash_yielding, sha256, sha256_reader,
    sha384, sha512, ArtifactHasher, HashUpdate, Sha256Hasher,
};
pub use keyring::Keyring;
pub use signing::{KeyAlgorithm, KeyPair, SigningScheme};
pub use verification::{verify_signature, verify_signature_prehashed, VerificationKey};
pub use webpki::WEBPKI_VERIFICATION_ALGS;
pub use x509::{
    parse_certificate_info, CertificateInfo, DeprecatedGitHubClaims, FulcioCiClaims, SubjectAltName,
};
