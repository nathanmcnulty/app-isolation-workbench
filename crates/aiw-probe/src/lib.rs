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
