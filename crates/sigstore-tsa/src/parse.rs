//! RFC 3161 timestamp parsing utilities
//!
//! This module provides utilities for parsing RFC 3161 timestamp tokens
//! and extracting the timestamp value using the RustCrypto ecosystem.

use crate::asn1::{PkiStatus, TimeStampResp, TstInfo};
use crate::error::{Error, Result};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use x509_cert::der::{Decode, Encode};

/// OID for SignedData (1.2.840.113549.1.7.2)
const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// OID for TSTInfo (1.2.840.113549.1.9.16.1.4)
const ID_CT_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

/// Parse RFC 3161 timestamp token and extract TSTInfo, SignedData, and token bytes
///
/// This is the core parsing function used by both `parse_timestamp()` and
/// `verify_timestamp_response()` to avoid duplication.
///
/// # Arguments
///
/// * `timestamp_bytes` - The RFC 3161 timestamp token bytes (DER encoded)
///
/// # Returns
///
/// Returns a tuple of:
/// - `TstInfo`: The parsed timestamp info structure
/// - `SignedData`: The CMS SignedData container (needed for verification)
/// - `Vec<u8>`: The token bytes (needed for signature verification)
pub(crate) fn parse_timestamp_token(
    timestamp_bytes: &[u8],
) -> Result<(TstInfo, SignedData, Vec<u8>)> {
    // Try to parse as TimeStampResp first, if that fails, try as ContentInfo
    let (content_info, token_bytes) = match TimeStampResp::from_der(timestamp_bytes) {
        Ok(resp) => {
            // Check status
            if resp.status.status != PkiStatus::Granted as u8
                && resp.status.status != PkiStatus::GrantedWithMods as u8
            {
                return Err(Error::Parse(format!(
                    "Timestamp request not granted: status {}",
                    resp.status.status
                )));
            }

            // Extract the timestamp token
            let token_any = resp
                .time_stamp_token
                .ok_or_else(|| Error::Parse("TimeStampResp missing timeStampToken".to_string()))?;

            // Convert to DER bytes and parse as ContentInfo
            let bytes = token_any
                .to_der()
                .map_err(|e| Error::Parse(format!("failed to encode token: {}", e)))?;

            let content_info = ContentInfo::from_der(&bytes)
                .map_err(|e| Error::Parse(format!("failed to decode ContentInfo: {}", e)))?;

            (content_info, bytes)
        }
        Err(_) => {
            // Try as ContentInfo directly
            let content_info = ContentInfo::from_der(timestamp_bytes)
                .map_err(|e| Error::Parse(format!("failed to decode TimeStampToken: {}", e)))?;
            (content_info, timestamp_bytes.to_vec())
        }
    };

    // Verify content type is SignedData
    if content_info.content_type.to_string() != ID_SIGNED_DATA {
        return Err(Error::Parse(format!(
            "ContentInfo content type is not SignedData: {}",
            content_info.content_type
        )));
    }

    // Decode SignedData from the content
    let signed_data_der = content_info
        .content
        .to_der()
        .map_err(|e| Error::Parse(format!("failed to encode SignedData content: {}", e)))?;

    let signed_data = SignedData::from_der(&signed_data_der)
        .map_err(|e| Error::Parse(format!("failed to decode SignedData: {}", e)))?;

    // Verify the content type inside SignedData is TSTInfo
    if signed_data.encap_content_info.econtent_type.to_string() != ID_CT_TST_INFO {
        return Err(Error::Parse(format!(
            "Encapsulated content type is not TSTInfo: {}",
            signed_data.encap_content_info.econtent_type
        )));
    }

    // Extract the TSTInfo
    let tst_info_any = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| Error::Parse("Missing encapsulated content".to_string()))?;

    // Parse TSTInfo from the content bytes
    let tst_info = TstInfo::from_der(tst_info_any.value())
        .map_err(|e| Error::Parse(format!("failed to decode TSTInfo: {}", e)))?;

    Ok((tst_info, signed_data, token_bytes))
}

/// Parse an RFC 3161 timestamp response to extract the timestamp
///
/// This extracts the GeneralizedTime from TSTInfo in the timestamp response
/// using proper DER parsing from the RustCrypto ecosystem.
///
/// The structure is parsed using these crates:
/// - `cms`: Handles the outer SignedData wrapper (RFC 5652)
/// - `x509-cert`: Handles certificates and standard X.509 types
/// - `der`: The core parsing engine
///
/// # Arguments
///
/// * `timestamp_bytes` - The RFC 3161 timestamp token bytes (DER encoded)
///
/// # Returns
///
/// Returns the timestamp as a Unix timestamp (seconds since epoch)
pub fn parse_timestamp(timestamp_bytes: &[u8]) -> Result<i64> {
    let (tst_info, _signed_data, _token_bytes) = parse_timestamp_token(timestamp_bytes)?;

    // Extract the timestamp using GeneralizedTime's built-in conversion
    let system_time = tst_info.gen_time.to_system_time();
    let unix_duration = system_time
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Parse("timestamp before Unix epoch".to_string()))?;

    Ok(unix_duration.as_secs() as i64)
}

/// Parse a GeneralizedTime string to Unix timestamp
///
/// This function is provided for compatibility but is generally not needed
/// when using the proper DER parsing approach, which handles GeneralizedTime
/// conversion automatically.
///
/// Format: YYYYMMDDHHMMSSz or YYYYMMDDHHMMSS.fffZ
#[deprecated(
    since = "0.1.0",
    note = "Use TstInfo::gen_time.to_system_time() instead when parsing DER-encoded timestamps"
)]
pub fn parse_generalized_time(time_str: &str) -> Result<i64> {
    // Remove trailing 'Z' if present
    let time_str = time_str.trim_end_matches('Z').trim_end_matches('z');

    // Split on '.' to separate fractional seconds if present
    let parts: Vec<&str> = time_str.split('.').collect();
    let base_time = parts[0];

    // Ensure we have at least 14 characters (YYYYMMDDHHmmss)
    if base_time.len() < 14 {
        return Err(Error::Parse(format!(
            "invalid GeneralizedTime format: {}",
            time_str
        )));
    }

    // Parse components
    let year: i32 = base_time[0..4]
        .parse()
        .map_err(|_| Error::Parse("invalid year in GeneralizedTime".to_string()))?;
    let month: u32 = base_time[4..6]
        .parse()
        .map_err(|_| Error::Parse("invalid month in GeneralizedTime".to_string()))?;
    let day: u32 = base_time[6..8]
        .parse()
        .map_err(|_| Error::Parse("invalid day in GeneralizedTime".to_string()))?;
    let hour: u32 = base_time[8..10]
        .parse()
        .map_err(|_| Error::Parse("invalid hour in GeneralizedTime".to_string()))?;
    let minute: u32 = base_time[10..12]
        .parse()
        .map_err(|_| Error::Parse("invalid minute in GeneralizedTime".to_string()))?;
    let second: u32 = base_time[12..14]
        .parse()
        .map_err(|_| Error::Parse("invalid second in GeneralizedTime".to_string()))?;

    // Create NaiveDateTime
    use chrono::{NaiveDate, TimeZone};
    let naive_date = NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| Error::Parse(format!("invalid date: {}-{}-{}", year, month, day)))?;

    let naive_datetime = naive_date
        .and_hms_opt(hour, minute, second)
        .ok_or_else(|| Error::Parse(format!("invalid time: {}:{}:{}", hour, minute, second)))?;

    // Convert to UTC timestamp
    let datetime = chrono::Utc.from_utc_datetime(&naive_datetime);
    Ok(datetime.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_parse_generalized_time() {
        // Standard format
        let result = parse_generalized_time("20231215120000Z");
        assert!(result.is_ok());

        // Format without Z
        let result = parse_generalized_time("20231215120000");
        assert!(result.is_ok());

        // With fractional seconds
        let result = parse_generalized_time("20231215120000.123Z");
        assert!(result.is_ok());
    }

    #[test]
    #[allow(deprecated)]
    fn test_parse_generalized_time_invalid() {
        // Too short
        let result = parse_generalized_time("2023");
        assert!(result.is_err());

        // Invalid date
        let result = parse_generalized_time("20231332120000Z");
        assert!(result.is_err());
    }
}
