//! Closed 7-Zip assessment identity; no commands, paths or arbitrary policies.
use crate::WindowsVersionObservation;
use crate::paired_controls::{ControlEvidenceOrigin, control_digest, control_hash};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SEVENZIP_PROFILE_REVISION: &str = "aiw.dev/sevenzip-archive-pair/v0alpha1";
pub const SEVENZIP_VERSION: &str = "26.05";
pub const SEVENZIP_INSTALLER_SHA256: &str =
    "fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0";
pub const SEVENZIP_INSTALLER_SIZE_BYTES: u64 = 1_663_506;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipProfile {
    pub revision: String,
    pub source_sha256: String,
    pub installer_sha256: String,
    pub installer_size_bytes: u64,
    pub agent_sha256: String,
    pub agent_size_bytes: u64,
    pub launcher_sha256: String,
    pub launcher_size_bytes: u64,
    pub origin: ControlEvidenceOrigin,
    pub expected_windows: WindowsVersionObservation,
    pub expected_host_windows: WindowsVersionObservation,
    pub policy: SevenZipPolicy,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SevenZipPolicy {
    ClassicAppContainerNoCapabilitiesReadInputWriteOutput,
}
impl SevenZipProfile {
    pub fn validate(&self) -> Result<(), String> {
        self.validate_historical()?;
        if self.source_sha256 != seven_zip_source_sha256() {
            return Err(
                "7-Zip source changed; prepare and approve a fresh plan before Start".into(),
            );
        }
        Ok(())
    }
    /// Retained reads/recovery do not require today's compiler source hash.
    /// Accept only this closed revision; unknown future revisions fail closed.
    pub fn validate_historical(&self) -> Result<(), String> {
        self.expected_windows.validate()?;
        self.expected_host_windows.validate()?;
        if self.revision != SEVENZIP_PROFILE_REVISION
            || !control_hash(&self.source_sha256)
            || self.installer_sha256 != SEVENZIP_INSTALLER_SHA256
            || self.installer_size_bytes != SEVENZIP_INSTALLER_SIZE_BYTES
            || !control_hash(&self.agent_sha256)
            || self.agent_sha256 != self.launcher_sha256
            || self.agent_size_bytes != self.launcher_size_bytes
            || self.agent_size_bytes == 0
            || self.agent_size_bytes > 128 * 1024 * 1024
            || self.expected_windows.observer_architecture != "x86_64"
            || self.expected_host_windows.observer_architecture != "x86_64"
        {
            return Err("7-Zip fixed installer, executable roles, exact x64 environments or revision rejected".into());
        }
        Ok(())
    }
    pub fn approved_host_windows(&self) -> &WindowsVersionObservation {
        &self.expected_host_windows
    }
    pub fn hash(&self) -> Result<String, String> {
        self.validate_historical()?;
        control_digest(self)
    }
}

pub fn seven_zip_source_sha256() -> String {
    let sources = [
        include_str!("sevenzip.rs"),
        include_str!("../../aiw-provider-wsb/src/sevenzip.rs"),
        include_str!("../../aiw-windows-platform/src/control_appcontainer/research_sevenzip.rs"),
        include_str!("../../aiw-windows-platform/src/guest_document/paired_inputs/sevenzip.rs"),
        include_str!("../../aiw-windows-platform/src/control_appcontainer.rs"),
        include_str!("../../aiw-windows-platform/src/guest_document/paired_inputs.rs"),
        include_str!("../../aiw-windows-platform/src/guest_document.rs"),
        include_str!("../../aiw-windows-platform/src/guest_msi.rs"),
        include_str!("../../aiw-windows-platform/src/guest_standard_user.rs"),
        include_str!("../../aiw-guest-agent/src/main.rs"),
        include_str!("../../aiw-windows-platform/src/guest_sevenzip.rs"),
        include_str!("../../aiw-guest-agent/src/sevenzip.rs"),
    ];
    let mut digest = Sha256::new();
    for source in sources {
        digest.update((source.len() as u64).to_le_bytes());
        digest.update(source.as_bytes());
    }
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> SevenZipProfile {
        SevenZipProfile {
            revision: SEVENZIP_PROFILE_REVISION.into(),
            source_sha256: seven_zip_source_sha256(),
            installer_sha256: SEVENZIP_INSTALLER_SHA256.into(),
            installer_size_bytes: SEVENZIP_INSTALLER_SIZE_BYTES,
            agent_sha256: "a".repeat(64),
            agent_size_bytes: 100,
            launcher_sha256: "a".repeat(64),
            launcher_size_bytes: 100,
            origin: ControlEvidenceOrigin::SyntheticRehearsal,
            expected_windows: crate::paired_controls::parse_guest_windows("10.0.26100.2").unwrap(),
            expected_host_windows: crate::paired_controls::parse_guest_windows("10.0.26300.1")
                .unwrap(),
            policy: SevenZipPolicy::ClassicAppContainerNoCapabilitiesReadInputWriteOutput,
        }
    }
    #[test]
    fn sevenzip_profile_binds_each_environment_installer_source_and_roles() {
        let value = profile();
        value.validate().unwrap();
        let original = value.hash().unwrap();
        let mut drift = value.clone();
        drift.expected_windows.revision += 1;
        assert_ne!(original, drift.hash().unwrap());
        drift = value.clone();
        drift.expected_host_windows.revision += 1;
        assert_ne!(original, drift.hash().unwrap());
        for case in 0..7 {
            let mut invalid = value.clone();
            match case {
                0 => invalid.installer_sha256 = "b".repeat(64),
                1 => invalid.installer_size_bytes += 1,
                2 => invalid.launcher_sha256 = "b".repeat(64),
                3 => invalid.launcher_size_bytes += 1,
                4 => invalid.agent_size_bytes = 0,
                5 => invalid.expected_windows.observer_architecture = "aarch64".into(),
                _ => invalid.revision = "future".into(),
            }
            assert!(invalid.validate_historical().is_err());
        }
    }
    #[test]
    fn sevenzip_historical_read_preserves_source_identity_without_authorizing_dispatch() {
        let mut value = profile();
        value.source_sha256 = "b".repeat(64);
        let before = value.hash().unwrap();
        value.validate_historical().unwrap();
        assert!(value.validate().is_err());
        let raw = serde_json::to_vec(&value).unwrap();
        let restored: SevenZipProfile = serde_json::from_slice(&raw).unwrap();
        assert_eq!(before, restored.hash().unwrap());
        let mut unknown = serde_json::to_value(value).unwrap();
        unknown["policy"] = serde_json::json!("fullTrustFallback");
        assert!(serde_json::from_value::<SevenZipProfile>(unknown).is_err());
    }
}
