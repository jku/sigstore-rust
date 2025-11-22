//! Rekor transparency log entry validation
//!
//! This module handles validation of different Rekor entry types against
//! bundle content to ensure consistency.

use crate::error::{Error, Result};
use base64::Engine;
use sigstore_rekor::body::RekorEntryBody;
use sigstore_types::{Bundle, SignatureContent, TransparencyLogEntry};

/// Verify DSSE envelope matches Rekor entry (for DSSE bundles)
pub fn verify_dsse_entries(bundle: &Bundle) -> Result<()> {
    let envelope = match &bundle.content {
        SignatureContent::DsseEnvelope(env) => env,
        _ => return Ok(()), // Not a DSSE bundle
    };

    for entry in &bundle.verification_material.tlog_entries {
        if entry.kind_version.kind == "dsse" {
            match entry.kind_version.version.as_str() {
                "0.0.1" => verify_dsse_v001(entry, envelope)?,
                "0.0.2" => verify_dsse_v002(entry, envelope)?,
                _ => {} // Unknown version, skip
            }
        }
    }

    Ok(())
}

/// Verify DSSE v0.0.1 entry
///
/// NOTE: This does NOT verify the envelope hash.
/// The envelope hash in DSSE v0.0.1 entries cannot be reliably verified because:
/// 1. The hash is computed over uncanonicalized JSON during submission to Rekor
/// 2. JSON serialization can vary (field ordering, whitespace) between implementations
/// 3. We cannot reproduce the exact JSON representation that was originally submitted
///
/// Instead, we verify:
/// - Payload hash (hash of envelope.payload bytes)
/// - Signatures list matches between entry and envelope
fn verify_dsse_v001(
    entry: &TransparencyLogEntry,
    envelope: &sigstore_types::DsseEnvelope,
) -> Result<()> {
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body,
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (expected_hash, rekor_signatures) = match &body {
        RekorEntryBody::DsseV001(dsse_body) => (
            &dsse_body.spec.payload_hash.value,
            &dsse_body.spec.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected DSSE v0.0.1 body, got different type".to_string(),
            ))
        }
    };

    // Verify payload hash (v0.0.1 uses hex encoding)
    let payload_bytes = envelope
        .payload
        .decode()
        .map_err(|e| Error::Verification(format!("failed to decode DSSE payload: {}", e)))?;
    let payload_hash = sigstore_crypto::sha256(&payload_bytes);
    let payload_hash_hex = hex::encode(payload_hash);

    if &payload_hash_hex != expected_hash {
        return Err(Error::Verification(format!(
            "DSSE payload hash mismatch: computed {}, expected {}",
            payload_hash_hex, expected_hash
        )));
    }

    // Verify that the signatures in the bundle match what's in Rekor
    // This prevents signature substitution attacks
    if envelope.signatures.len() != rekor_signatures.len() {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has {}, Rekor entry has {}",
            envelope.signatures.len(),
            rekor_signatures.len()
        )));
    }

    // Check that each signature in the bundle exists in the Rekor entry
    for bundle_sig in &envelope.signatures {
        let mut found = false;
        for rekor_sig in rekor_signatures {
            if bundle_sig.sig == rekor_sig.signature {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::Verification(
                "DSSE signature in bundle does not match any signature in Rekor entry".to_string(),
            ));
        }
    }

    Ok(())
}

/// Verify DSSE v0.0.2 entry (payload hash and signature validation)
fn verify_dsse_v002(
    entry: &TransparencyLogEntry,
    envelope: &sigstore_types::DsseEnvelope,
) -> Result<()> {
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body,
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (expected_hash, rekor_signatures) = match &body {
        RekorEntryBody::DsseV002(dsse_body) => (
            &dsse_body.spec.dsse_v002.payload_hash.digest,
            &dsse_body.spec.dsse_v002.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected DSSE v0.0.2 body, got different type".to_string(),
            ))
        }
    };

    // Compute actual payload hash
    let payload_bytes = envelope
        .payload
        .decode()
        .map_err(|e| Error::Verification(format!("failed to decode DSSE payload: {}", e)))?;
    let payload_hash = sigstore_crypto::sha256(&payload_bytes);
    let payload_hash_b64 = base64::engine::general_purpose::STANDARD.encode(payload_hash);

    // Compare hashes
    if &payload_hash_b64 != expected_hash {
        return Err(Error::Verification(format!(
            "DSSE payload hash mismatch: computed {}, expected {}",
            payload_hash_b64, expected_hash
        )));
    }

    // Verify that the signatures in the bundle match what's in Rekor
    // This prevents signature substitution attacks
    // We need to ensure that the signature lists match (same count and content)

    if envelope.signatures.len() != rekor_signatures.len() {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has {}, Rekor entry has {}",
            envelope.signatures.len(),
            rekor_signatures.len()
        )));
    }

    // Check that each signature in the bundle exists in the Rekor entry
    for bundle_sig in &envelope.signatures {
        let mut found = false;
        for rekor_sig in rekor_signatures {
            if bundle_sig.sig == rekor_sig.content {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::Verification(
                "DSSE signature in bundle does not match any signature in Rekor entry".to_string(),
            ));
        }
    }

    Ok(())
}

/// Verify DSSE payload matches what's in Rekor (for intoto entries)
pub fn verify_intoto_entries(bundle: &Bundle) -> Result<()> {
    let envelope = match &bundle.content {
        SignatureContent::DsseEnvelope(env) => env,
        _ => return Ok(()), // Not a DSSE bundle
    };

    for entry in &bundle.verification_material.tlog_entries {
        if entry.kind_version.kind == "intoto" {
            verify_intoto_v002(entry, envelope)?;
        }
    }

    Ok(())
}

/// Verify intoto v0.0.2 entry
fn verify_intoto_v002(
    entry: &TransparencyLogEntry,
    envelope: &sigstore_types::DsseEnvelope,
) -> Result<()> {
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body,
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (rekor_payload_b64, rekor_signatures) = match &body {
        RekorEntryBody::IntotoV002(intoto_body) => (
            &intoto_body.spec.content.envelope.payload,
            &intoto_body.spec.content.envelope.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected Intoto v0.0.2 body, got different type".to_string(),
            ))
        }
    };

    // The Rekor entry has the payload double-base64-encoded, decode it once
    let rekor_payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(rekor_payload_b64)
        .map_err(|e| Error::Verification(format!("failed to decode Rekor payload: {}", e)))?;

    let rekor_payload = String::from_utf8(rekor_payload_bytes)
        .map_err(|e| Error::Verification(format!("Rekor payload not valid UTF-8: {}", e)))?;

    // Compare with bundle payload
    if envelope.payload != rekor_payload {
        return Err(Error::Verification(
            "DSSE payload in bundle does not match intoto Rekor entry".to_string(),
        ));
    }

    // Validate that the signatures match
    let mut found_match = false;
    for bundle_sig in &envelope.signatures {
        for rekor_sig in rekor_signatures {
            // The Rekor signature is also double-base64-encoded, decode it once
            let rekor_sig_decoded = base64::engine::general_purpose::STANDARD
                .decode(&rekor_sig.sig)
                .map_err(|e| {
                    Error::Verification(format!("failed to decode Rekor signature: {}", e))
                })?;

            let rekor_sig_content = String::from_utf8(rekor_sig_decoded).map_err(|e| {
                Error::Verification(format!("Rekor signature not valid UTF-8: {}", e))
            })?;

            if bundle_sig.sig == rekor_sig_content {
                found_match = true;
                break;
            }
        }
        if found_match {
            break;
        }
    }

    if !found_match {
        return Err(Error::Verification(
            "DSSE signature in bundle does not match intoto Rekor entry".to_string(),
        ));
    }

    Ok(())
}
