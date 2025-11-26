//! Verification implementation modules
//!
//! This module contains the refactored verification logic, broken down into
//! manageable submodules for better maintainability.

pub(crate) mod hashedrekord;
pub(crate) mod helpers;
pub(crate) mod rekor;
pub(crate) mod sct;
pub(crate) mod tlog;

// Re-export for use within parent verify.rs
pub use hashedrekord::verify_hashedrekord_entries;
pub use rekor::{verify_dsse_entries, verify_intoto_entries};
