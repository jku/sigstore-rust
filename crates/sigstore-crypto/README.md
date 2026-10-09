# sigstore-crypto

Cryptographic primitives for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides key generation, signing, verification, hashing, and `rustls-webpki` signature verification algorithms for the Sigstore ecosystem, using either `aws-lc-rs` (default) or `boring` (BoringSSL) as the cryptographic backend.

## Cargo Features

- `aws-lc-rs` *(default)* — Use [`aws-lc-rs`](https://github.com/aws/aws-lc-rs) as the cryptographic backend.
- `boring` — Use [`boring`](https://github.com/cloudflare/boring) (BoringSSL) as the cryptographic backend:
  ```toml
  [dependencies]
  sigstore-crypto = { version = "0.14", default-features = false, features = ["boring"] }
  ```

## Supported Algorithms

| Algorithm | Key Generation | Signing | Verification |
|-----------|---------------|---------|--------------|
| ECDSA P-256 (SHA-256 / SHA-384) | Yes (P-256) | Yes (SHA-256) | Yes |
| ECDSA P-384 (SHA-256 / SHA-384) | No | No | Yes |
| Ed25519 | No | No | Yes |
| RSA PKCS#1 v1.5 & PSS (2048–8192 bits, SHA-256 / 384 / 512) | No | No | Yes |
| ML-DSA-44 / ML-DSA-65 / ML-DSA-87 (FIPS 204) | No | No | Yes |

## Usage

```rust
use sigstore_crypto::{KeyAlgorithm, KeyPair, SigningScheme, verify_signature};

// Generate a new ECDSA P-256 key pair
let keypair = KeyPair::generate(KeyAlgorithm::EcdsaP256)?;

// Sign data
let signature = keypair.sign(b"message")?;

// Verify a signature
verify_signature(
    &keypair.public_key_der()?,
    b"message",
    &signature,
    SigningScheme::EcdsaP256Sha256,
)?;
```

## Related Crates

This crate provides cryptographic operations for:

- [`sigstore-verify`](../sigstore-verify) - Signature verification
- [`sigstore-sign`](../sigstore-sign) - Signature creation

## License

Apache-2.0
