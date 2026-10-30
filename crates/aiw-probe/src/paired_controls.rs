//! Closed identities for the project-owned paired control, not an executable interface.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PAIRED_CONTROL_REVISION: &str = "aiw.dev/paired-file-registry-child/v0alpha1";
pub const PAIRED_CONTROL_PLAN_SCHEMA: &str = "aiw.dev/run-plan/v0alpha7";
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ControlEvidenceOrigin {
    NativeWorker,
    SyntheticRehearsal,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedControlProfile {
    pub revision: String,
    pub source_sha256: String,
    pub fixture_sha256: String,
    pub fixture_size_bytes: u64,
    pub launcher_sha256: String,
    pub launcher_size_bytes: u64,
    pub origin: ControlEvidenceOrigin,
    pub expected_windows: crate::WindowsVersionObservation,
    pub policy: PairedControlPolicy,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum PairedControlPolicy {
    ClassicAppContainerNoCapabilitiesFixedChildOutputGrant,
}
impl PairedControlProfile {
    /// New preparation/dispatch must enroll the current fixed source bytes.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_historical()?;
        if self.source_sha256 != paired_control_source_sha256() {
            return Err(
                "Paired source revision changed; prepare and approve a fresh plan before Start"
                    .into(),
            );
        }
        Ok(())
    }
    /// Structural historical identity only. This preserves exact-session cleanup
    /// and retained reporting; it never authorizes a fresh dispatch.
    pub fn validate_historical(&self) -> Result<(), String> {
        self.expected_windows.validate()?;
        if self.expected_windows.observer_architecture != "x86_64"
            || self.revision != PAIRED_CONTROL_REVISION
            || !control_hash(&self.source_sha256)
            || !control_hash(&self.fixture_sha256)
            || !control_hash(&self.launcher_sha256)
            || self.fixture_sha256 != self.launcher_sha256
            || self.fixture_size_bytes != self.launcher_size_bytes
            || self.fixture_size_bytes == 0
            || self.fixture_size_bytes > 128 * 1024 * 1024
            || self.launcher_size_bytes == 0
            || self.launcher_size_bytes > 128 * 1024 * 1024
        {
            return Err("Paired controls require the current fixed source revision and bounded exact executable commitments".into());
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<String, String> {
        self.validate_historical()?;
        control_digest(self)
    }
}
/// The launcher never accepts caller arguments; these sources define its entire
/// permitted case/resource/policy surface. Build enrollment must bind its binaries.
pub fn paired_control_source_sha256() -> String {
    let sources = [
        include_str!("paired_controls.rs"),
        include_str!("../../aiw-provider-wsb/src/paired_controls.rs"),
        include_str!("../../aiw-control-fixture/src/main.rs"),
        include_str!("../../aiw-control-fixture/src/lib.rs"),
        include_str!("../../aiw-control-appcontainer/src/main.rs"),
        include_str!("../../aiw-windows-platform/src/control_appcontainer.rs"),
        include_str!("../../aiw-windows-platform/src/control_registry.rs"),
        include_str!("../../aiw-windows-platform/src/guest_paired_controls.rs"),
        include_str!("../../aiw-windows-platform/src/guest_document/paired_controls.rs"),
        include_str!("../../aiw-windows-platform/src/guest_standard_user.rs"),
        include_str!("../../aiw-windows-platform/src/guest_msi.rs"),
        include_str!("../../aiw-windows-platform/src/guest_document.rs"),
        include_str!("../../aiw-guest-agent/src/main.rs"),
    ];
    let mut digest = Sha256::new();
    for source in sources {
        digest.update((source.len() as u64).to_le_bytes());
        digest.update(source.as_bytes());
    }
    hex::encode(digest.finalize())
}
pub fn control_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn control_digest(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_value(value).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(
        aiw_evidence::canonical_json_bytes(&bytes).map_err(|e| e.to_string())?,
    )))
}
