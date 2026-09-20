#![deny(unsafe_op_in_unsafe_fn)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const TOKEN_EVIDENCE_SCHEMA_VERSION: &str = "aiw.dev/token-evidence/v0alpha1";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenEvidence {
    pub schema_version: String,
    pub process_id: u32,
    pub token_type: TokenType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonation_level: Option<ImpersonationLevel>,
    pub is_app_container: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_container_sid: Option<String>,
    pub user_sid: String,
    pub integrity: IntegrityEvidence,
    pub elevation_type: ElevationType,
    pub is_elevated: bool,
    pub capabilities: Vec<SidAndAttributes>,
    pub restricted_sid_count: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TokenType {
    Primary,
    Impersonation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ImpersonationLevel {
    Anonymous,
    Identification,
    Impersonation,
    Delegation,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntegrityEvidence {
    pub sid: String,
    pub rid: u32,
    pub level: IntegrityLevel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    ProtectedProcess,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ElevationType {
    Default,
    Full,
    Limited,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SidAndAttributes {
    pub sid: String,
    pub attributes: u32,
}

#[derive(Debug, Error)]
pub enum TokenEvidenceError {
    #[error("Windows access-token evidence is only available on Windows")]
    UnsupportedPlatform,
    #[error("{operation} failed: {message}")]
    WindowsApi {
        operation: &'static str,
        message: String,
    },
    #[error("{operation} returned malformed token data: {detail}")]
    MalformedTokenData {
        operation: &'static str,
        detail: &'static str,
    },
}

pub fn collect_current_process_token() -> Result<TokenEvidence, TokenEvidenceError> {
    platform::collect_current_process_token()
}

/// Collects token evidence for the exact Windows process handle supplied by
/// the caller. The process ID is obtained from that same handle; this API
/// never reopens a process by PID. A non-process handle is rejected.
#[cfg(windows)]
pub fn collect_process_token(
    process: std::os::windows::io::BorrowedHandle<'_>,
) -> Result<TokenEvidence, TokenEvidenceError> {
    platform::collect_process_token(process)
}

pub fn classify_integrity_rid(rid: u32) -> IntegrityLevel {
    match rid {
        0x0000..=0x0fff => IntegrityLevel::Untrusted,
        0x1000..=0x1fff => IntegrityLevel::Low,
        0x2000..=0x20ff => IntegrityLevel::Medium,
        0x2100..=0x2fff => IntegrityLevel::MediumPlus,
        0x3000..=0x3fff => IntegrityLevel::High,
        0x4000..=0x4fff => IntegrityLevel::System,
        0x5000..=0x5fff => IntegrityLevel::ProtectedProcess,
        _ => IntegrityLevel::Unknown,
    }
}

#[cfg(windows)]
mod platform;

#[cfg(not(windows))]
mod platform {
    use super::{TokenEvidence, TokenEvidenceError};

    pub(super) fn collect_current_process_token() -> Result<TokenEvidence, TokenEvidenceError> {
        Err(TokenEvidenceError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_rids_map_to_documented_bands() {
        assert_eq!(classify_integrity_rid(0x0000), IntegrityLevel::Untrusted);
        assert_eq!(classify_integrity_rid(0x1000), IntegrityLevel::Low);
        assert_eq!(classify_integrity_rid(0x2000), IntegrityLevel::Medium);
        assert_eq!(classify_integrity_rid(0x2100), IntegrityLevel::MediumPlus);
        assert_eq!(classify_integrity_rid(0x3000), IntegrityLevel::High);
        assert_eq!(classify_integrity_rid(0x4000), IntegrityLevel::System);
        assert_eq!(
            classify_integrity_rid(0x5000),
            IntegrityLevel::ProtectedProcess
        );
        assert_eq!(classify_integrity_rid(0x6000), IntegrityLevel::Unknown);
    }

    #[cfg(windows)]
    #[test]
    fn current_process_token_can_be_collected() {
        let evidence = collect_current_process_token().expect("current token should be queryable");
        assert_eq!(evidence.schema_version, TOKEN_EVIDENCE_SCHEMA_VERSION);
        assert!(!evidence.user_sid.is_empty());
        assert!(!evidence.integrity.sid.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn borrowed_current_process_handle_matches_current_collector_essentials() {
        use std::os::windows::io::BorrowedHandle;
        use windows::Win32::System::Threading::GetCurrentProcess;

        // SAFETY: The pseudo-handle is valid for the current process for the
        // duration of this call and is not owned or closed by BorrowedHandle.
        let process = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess().0.cast()) };
        let from_handle =
            collect_process_token(process).expect("current process handle is queryable");
        let current = collect_current_process_token().expect("current token is queryable");
        assert_eq!(from_handle.process_id, current.process_id);
        assert_eq!(from_handle.user_sid, current.user_sid);
        assert_eq!(from_handle.integrity, current.integrity);
        assert_eq!(from_handle.is_app_container, current.is_app_container);
    }

    #[cfg(windows)]
    #[test]
    fn non_process_borrowed_handle_is_rejected() {
        use std::os::windows::io::AsHandle as _;

        let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        assert!(collect_process_token(file.as_handle()).is_err());
    }
}
