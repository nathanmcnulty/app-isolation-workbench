#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PROBED_TOOLS: &[&str] = &[
    "wsl.exe",
    "WindowsSandbox.exe",
    "wsb.exe",
    "MakeAppx.exe",
    "SignTool.exe",
    "wpr.exe",
    "wpa.exe",
    "gh.exe",
    "cargo.exe",
    "pwsh.exe",
];

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostProbe {
    pub schema_version: String,
    pub os: String,
    pub os_family: String,
    pub process_architecture: String,
    pub environment_architecture: BTreeMap<String, String>,
    pub discovered_tools: BTreeMap<String, Option<String>>,
    pub limitations: Vec<String>,
}

/// A deliberately conservative state.  `Unknown` and `NeedsElevation` are
/// blockers for provider execution; neither is interpreted as support.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReadinessState {
    Available,
    Missing,
    Unknown,
    NeedsElevation,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BinaryIdentity {
    pub canonical_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub version: Option<String>,
    pub signature_status: ReadinessState,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsPackageIdentity {
    pub name: String,
    pub full_name: String,
    pub family_name: String,
    pub publisher: String,
    pub publisher_id: String,
    pub version: String,
    pub architecture: String,
    pub signature_kind: String,
    pub status_ok: bool,
    pub install_location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogTrustIdentity {
    pub trust_kind: String,
    pub catalog_path: String,
    pub catalog_sha256: String,
    pub catalog_file_identity: WindowsFileIdentity,
    pub member_tag: String,
    pub trust_policy: String,
    pub verification_status: ReadinessState,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsFileIdentity {
    pub final_path: String,
    pub volume_serial_number: String,
    pub file_id: String,
}

pub const WINDOWS_WORKSPACE_SCHEMA_VERSION: &str = "aiw.dev/workspace-binding-evidence/v0alpha1";
pub const WINDOWS_WORKSPACE_SECURITY_POLICY: &str = "owner-system-full-control-protected-v1";
pub const WINDOWS_SYSTEM_SID: &str = "S-1-5-18";
pub const DISCARD_INTENT_BINDING_SCHEMA_VERSION: &str =
    "aiw.dev/wsb-discard-intent-binding/v0alpha1";
pub const DISCARD_INTENT_BINDING_POLICY_VERSION: &str = "owner-system-protected-single-file-v1";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceBindingEvidence {
    pub schema_version: String,
    pub policy: String,
    pub security_policy_sha256: String,
    pub owner_sid: String,
    pub dacl_protected: bool,
    pub allowed_sids: Vec<String>,
    pub parent: WindowsFileIdentity,
    pub root: WindowsFileIdentity,
    pub tools: WindowsFileIdentity,
    pub output: WindowsFileIdentity,
}

impl WorkspaceBindingEvidence {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != WINDOWS_WORKSPACE_SCHEMA_VERSION
            || self.policy != WINDOWS_WORKSPACE_SECURITY_POLICY
            || !self.dacl_protected
            || !valid_sid_text(&self.owner_sid)
            || self.owner_sid == WINDOWS_SYSTEM_SID
            || self.security_policy_sha256 != workspace_policy_hash(&self.owner_sid)
        {
            return Err("workspace policy binding is invalid");
        }
        if self.allowed_sids.len() != 2
            || !self
                .allowed_sids
                .iter()
                .any(|sid| sid == WINDOWS_SYSTEM_SID)
            || !self.allowed_sids.iter().any(|sid| sid == &self.owner_sid)
        {
            return Err("workspace allowlist is not owner-and-SYSTEM only");
        }
        for identity in [&self.parent, &self.root, &self.tools, &self.output] {
            if identity.final_path.is_empty()
                || identity.final_path.len() > 32_767
                || !fixed_hex(&identity.volume_serial_number, 16)
                || !fixed_hex(&identity.file_id, 32)
            {
                return Err("workspace file identity is invalid");
            }
        }
        let identities = [&self.parent, &self.root, &self.tools, &self.output];
        for (index, left) in identities.iter().enumerate() {
            if identities[index + 1..].iter().any(|right| {
                left.volume_serial_number == right.volume_serial_number
                    && left.file_id == right.file_id
            }) {
                return Err("workspace directory identities are not distinct");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardIntentStableId {
    pub volume_serial_number: String,
    pub file_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardIntentEaEntry {
    pub name: String,
    pub flags: u8,
    pub value_length: u16,
    pub value_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardIntentEaBinding {
    /// Bounded native query response length retained for diagnostics only.
    /// Identity is established by the canonical entries and digest below.
    pub queried_bytes: u32,
    pub entries: Vec<DiscardIntentEaEntry>,
    pub canonical_sha256: String,
}

/// Portable evidence required to reopen one exact staged or final authority.
/// EA values are never serialized; only bounded metadata and value hashes are
/// retained.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardIntentBindingEvidence {
    pub schema_version: String,
    pub policy_version: String,
    pub run_id: String,
    pub owner_sid: String,
    pub store_key: String,
    pub final_path: String,
    pub staging_leaf: String,
    pub parent_id: DiscardIntentStableId,
    pub intent_id: DiscardIntentStableId,
    pub intent_size: u64,
    pub intent_sha256: String,
    pub intent_ea: DiscardIntentEaBinding,
}

impl DiscardIntentBindingEvidence {
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn owner_sid(&self) -> &str {
        &self.owner_sid
    }
    pub fn store_key(&self) -> &str {
        &self.store_key
    }
    pub fn final_path(&self) -> &str {
        &self.final_path
    }
    pub fn parent_id(&self) -> &DiscardIntentStableId {
        &self.parent_id
    }
    pub fn intent_id(&self) -> &DiscardIntentStableId {
        &self.intent_id
    }
    pub fn intent_size(&self) -> u64 {
        self.intent_size
    }
    pub fn intent_sha256(&self) -> &str {
        &self.intent_sha256
    }
    pub fn intent_ea(&self) -> &DiscardIntentEaBinding {
        &self.intent_ea
    }
}

impl DiscardIntentStableId {
    pub fn volume_serial_number(&self) -> &str {
        &self.volume_serial_number
    }
    pub fn file_id(&self) -> &str {
        &self.file_id
    }
}

impl DiscardIntentEaBinding {
    pub fn queried_bytes(&self) -> u32 {
        self.queried_bytes
    }
    pub fn entries(&self) -> &[DiscardIntentEaEntry] {
        &self.entries
    }
    pub fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }
}

impl DiscardIntentEaEntry {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn flags(&self) -> u8 {
        self.flags
    }
    pub fn value_length(&self) -> u16 {
        self.value_length
    }
    pub fn value_sha256(&self) -> &str {
        &self.value_sha256
    }
}

#[must_use]
pub fn workspace_policy_hash(owner_sid: &str) -> String {
    let semantic = format!(
        "policy={WINDOWS_WORKSPACE_SECURITY_POLICY}\nowner={owner_sid}\nallow={owner_sid}:full:object-container-inherit\nallow={WINDOWS_SYSTEM_SID}:full:object-container-inherit\n"
    );
    hex::encode(Sha256::digest(semantic.as_bytes()))
}

fn fixed_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_sid_text(value: &str) -> bool {
    if value.len() < 7 || value.len() > 184 {
        return false;
    }
    let Some(components) = value.strip_prefix("S-1-") else {
        return false;
    };
    let components = components.split('-').collect::<Vec<_>>();
    !components.is_empty()
        && components.len() <= 17
        && components.iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && component.parse::<u64>().is_ok()
        })
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxCliProtocol {
    pub cli_version: String,
    pub protocol: String,
    pub list_schema: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxReadiness {
    pub schema_version: String,
    pub supported: bool,
    pub os_build: Option<u32>,
    pub process_architecture: String,
    pub virtualization: ReadinessState,
    pub sandbox_feature: ReadinessState,
    pub provider_binary: Option<BinaryIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_package: Option<WindowsPackageIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_trust: Option<CatalogTrustIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_file_identity: Option<WindowsFileIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_protocol: Option<WindowsSandboxCliProtocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_execution_alias: Option<String>,
    pub current_sessions: ReadinessState,
    #[serde(default)]
    pub current_session_ids: Vec<String>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[must_use]
pub fn probe_host() -> HostProbe {
    let environment_architecture = ["PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432"]
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|value| (key.to_owned(), value)))
        .collect();
    let discovered_tools = PROBED_TOOLS
        .iter()
        .map(|name| {
            (
                name.trim_end_matches(".exe").to_owned(),
                find_command(name).map(|path| path.to_string_lossy().into_owned()),
            )
        })
        .collect();

    HostProbe {
        schema_version: "aiw.dev/host-probe/v0alpha1".to_owned(),
        os: env::consts::OS.to_owned(),
        os_family: env::consts::FAMILY.to_owned(),
        process_architecture: env::consts::ARCH.to_owned(),
        environment_architecture,
        discovered_tools,
        limitations: vec![
            "This bootstrap probe discovers paths only; it does not verify Windows features, exports, versions, tokens, or effective isolation backends."
                .to_owned(),
        ],
    }
}

/// Read-only readiness assessment for the W1 Windows Sandbox provider.
///
/// It intentionally does not enable features, start providers, elevate, or
/// infer success from a binary being discoverable.  Feature and session state
/// require provider-specific inspection and remain a hard blocker until a
/// later approved capability probe can establish them.
#[must_use]
pub fn assess_windows_sandbox() -> WindowsSandboxReadiness {
    WindowsSandboxReadiness {
        schema_version: "aiw.dev/windows-sandbox-readiness/v0alpha1".to_owned(),
        supported: false,
        os_build: None,
        process_architecture: "unknown".to_owned(),
        virtualization: ReadinessState::Unknown,
        sandbox_feature: ReadinessState::Unknown,
        provider_binary: None,
        provider_package: None,
        catalog_trust: None,
        provider_file_identity: None,
        cli_protocol: None,
        app_execution_alias: None,
        current_sessions: ReadinessState::Unknown,
        current_session_ids: Vec::new(),
        blockers: vec!["AIW_WINDOWS_PLATFORM_UNAVAILABLE: trusted Windows platform/package verification is not implemented.".to_owned()],
        warnings: vec![
            "This assessment is read-only and never trusts PATH, environment state, shell utilities, or App Execution Aliases as execution authority."
                .to_owned(),
            "A discovered provider binary is not a signature, feature, session, or containment proof."
                .to_owned(),
        ],
    }
}

#[must_use]
pub fn measure_binary_identity(path: &Path) -> Option<BinaryIdentity> {
    let canonical_path = path.canonicalize().ok()?;
    let metadata = canonical_path.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let mut file = File::open(&canonical_path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let canonical_display = canonical_path.to_string_lossy();
    let canonical_path = canonical_display
        .strip_prefix("\\\\?\\")
        .unwrap_or(&canonical_display)
        .to_owned();
    Some(BinaryIdentity {
        canonical_path,
        sha256: hex::encode(digest.finalize()),
        size_bytes: metadata.len(),
        version: None,
        signature_status: ReadinessState::Unknown,
    })
}

/// Production package/alias/handle/signature verification belongs to the
/// future native platform boundary. This placeholder deliberately grants no
/// executable identity authority.
#[must_use]
pub fn measure_windows_sandbox_binary(_path: &Path) -> Option<BinaryIdentity> {
    None
}

#[must_use]
pub fn find_command(name: &str) -> Option<PathBuf> {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        return candidate.is_file().then(|| candidate.to_path_buf());
    }

    let path = env::var_os("PATH")?;
    let has_extension = candidate.extension().is_some();
    let extensions = if cfg!(windows) && !has_extension {
        env::var_os("PATHEXT")
            .map(|value| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|item| !item.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![".COM".to_owned(), ".EXE".to_owned()])
    } else {
        vec![String::new()]
    };

    for directory in env::split_paths(&path) {
        for extension in &extensions {
            let path = directory.join(format!("{name}{extension}"));
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_has_an_explicit_limitation() {
        let probe = probe_host();
        assert_eq!(probe.schema_version, "aiw.dev/host-probe/v0alpha1");
        assert!(!probe.limitations.is_empty());
        assert!(probe.discovered_tools.contains_key("cargo"));
    }

    #[test]
    fn impossible_tool_is_not_found() {
        assert!(find_command("aiw-this-tool-does-not-exist-8f197f32").is_none());
    }

    #[test]
    fn workspace_binding_contract_rejects_policy_and_identity_tampering() {
        let owner = "S-1-5-21-1".to_owned();
        let identity = |path: &str, marker: u8| WindowsFileIdentity {
            final_path: path.to_owned(),
            volume_serial_number: "0".repeat(16),
            file_id: format!("{marker:032x}"),
        };
        let evidence = WorkspaceBindingEvidence {
            schema_version: WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
            policy: WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
            security_policy_sha256: workspace_policy_hash(&owner),
            owner_sid: owner.clone(),
            dacl_protected: true,
            allowed_sids: vec![WINDOWS_SYSTEM_SID.to_owned(), owner],
            parent: identity("C:\\AIW", 1),
            root: identity("C:\\AIW\\run", 2),
            tools: identity("C:\\AIW\\run\\tools", 3),
            output: identity("C:\\AIW\\run\\output", 4),
        };
        evidence.validate().unwrap();
        assert_eq!(evidence.security_policy_sha256.len(), 64);

        let mut tampered = evidence.clone();
        tampered.dacl_protected = false;
        assert!(tampered.validate().is_err());
        let mut tampered = evidence.clone();
        tampered.output.file_id = tampered.root.file_id.clone();
        assert!(tampered.validate().is_err());
        let mut tampered = evidence;
        tampered.allowed_sids.push("S-1-5-32-544".to_owned());
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn sandbox_assessment_fails_closed_when_capabilities_are_unverified() {
        let readiness = assess_windows_sandbox();
        assert_eq!(
            readiness.schema_version,
            "aiw.dev/windows-sandbox-readiness/v0alpha1"
        );
        assert!(!readiness.supported);
        assert!(!readiness.blockers.is_empty());
        assert_eq!(readiness.sandbox_feature, ReadinessState::Unknown);
    }
}
