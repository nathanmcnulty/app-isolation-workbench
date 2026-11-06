//! Closed, non-executing ProcessContainer contract, separate from the legacy pin.
//! A supported probe is request capability evidence, never enforcement evidence.
use aiw_windows_command_line::join_arguments;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ADAPTER_SCHEMA: &str = "aiw.dev/fixed-sevenzip-mxc/v0alpha1";
pub const RELEASE: &str = "1.0.1";
pub const SOURCE_REVISION: &str = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2";
pub const CONTRACT_VERSION: &str = "1.0.0";
pub const RUNTIME_DLL_SHA256: &str =
    "bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c";
pub const RUNTIME_DLL_SIZE: u64 = 6_123_320;
pub const RELEASE_ARCHIVE_SHA256: &str =
    "0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9";
pub const RELEASE_ARCHIVE_SIZE: u64 = 542_051_775;
pub const WORK_ROOT: &str = r"C:\AIW\SevenZip\Work\Mxc";
pub const INPUT_ROOT: &str = r"C:\AIW\SevenZip\Work\Mxc\Input";
pub const OUTPUT_ROOT: &str = r"C:\AIW\SevenZip\Work\Mxc\Output";
pub const EXTRACTED_ROOT: &str = r"C:\AIW\SevenZip\Work\Mxc\Output\Extracted";
pub const ARCHIVE_PATH: &str = r"C:\AIW\SevenZip\Work\Mxc\Output\archive.7z";
pub const DENIED_PATH: &str = r"C:\AIW\SevenZip\Denied.txt";
pub const APP_ROOT: &str = r"C:\AIW\SevenZip\App";
pub const APP_IMAGE: &str = r"C:\AIW\SevenZip\App\7z.exe";
pub const CONTROL_IMAGE: &str = r"C:\AIW\SevenZip\sevenzip_assessment.exe";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FixedOperation {
    Driver,
    Boundary,
    Create,
    Test,
    Extract,
}

/// These roles must be separately implemented/reviewed before native dispatch.
/// The existing classic AppContainer boundary role targets a different subtree.
impl FixedOperation {
    fn command(self) -> String {
        let (image, arguments): (&str, Vec<&str>) = match self {
            Self::Driver => (CONTROL_IMAGE, vec!["--mxc-driver-control"]),
            Self::Boundary => (CONTROL_IMAGE, vec!["--mxc-boundary-control"]),
            Self::Create => (
                APP_IMAGE,
                vec![
                    "a",
                    "-t7z",
                    "-mx=1",
                    "-y",
                    ARCHIVE_PATH,
                    r"C:\AIW\SevenZip\Work\Mxc\Input\*",
                ],
            ),
            Self::Test => (APP_IMAGE, vec!["t", "-y", ARCHIVE_PATH]),
            Self::Extract => (
                APP_IMAGE,
                vec![
                    "x",
                    "-y",
                    r"-oC:\AIW\SevenZip\Work\Mxc\Output\Extracted",
                    ARCHIVE_PATH,
                ],
            ),
        };
        join_arguments(std::iter::once(image).chain(arguments))
    }
}

/// No caller commands, paths, grants, modes or timeouts are accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedRequest {
    operation: FixedOperation,
    json: String,
    sha256: String,
}

impl FixedRequest {
    pub fn new(operation: FixedOperation) -> Result<Self, ContractError> {
        // Input is a sibling of mutable Output. Never grant RW on WORK_ROOT:
        // neither overlap precedence nor parent DELETE_CHILD is assumed safe.
        let value = json!({
            "version": CONTRACT_VERSION,
            "containment": "processcontainer",
            "containerId": "AIW.SevenZip.Mxc.v0alpha1",
            "lifecycle": {"destroyOnExit": true, "preservePolicy": false},
            "process": {
                "commandLine": operation.command(),
                "cwd": OUTPUT_ROOT,
                "timeout": 30_000,
                "env": ["SYSTEMROOT=C:\\Windows", "LOCALAPPDATA=C:\\AIW\\SevenZip\\Work\\Mxc\\Output"],
                "inheritDefaultEnv": false
            },
            "filesystem": {
                "readonlyPaths": [APP_ROOT, CONTROL_IMAGE, INPUT_ROOT],
                "readwritePaths": [OUTPUT_ROOT],
                "deniedPaths": [DENIED_PATH]
            },
            "fallback": {"allowDaclMutation": false},
            "network": {
                "egress": {"default": "deny", "allow": [], "deny": []},
                "ingress": {"default": "deny", "hostLoopback": "deny"}
            },
            "ui": {"disable": true, "clipboard": "none", "injection": false},
            "processContainer": {
                "leastPrivilege": false,
                "capabilities": [],
                "learningMode": false,
                "ui": {"isolation": "container", "desktopSystemControl": false,
                       "systemSettings": "none", "ime": false}
            },
            "telemetry": {"enabled": false}
        });
        let json = serde_json::to_string(&value)?;
        let sha256 = hex::encode(Sha256::digest(json.as_bytes()));
        Ok(Self {
            operation,
            json,
            sha256,
        })
    }

    pub fn operation(&self) -> FixedOperation {
        self.operation
    }
    pub fn json(&self) -> &str {
        &self.json
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("MXC JSON contract rejected: {0}")]
    Json(#[from] serde_json::Error),
    #[error("MXC probe output exceeds its bounded contract")]
    ProbeBounds,
    #[error("MXC probe request identity differs from the exact fixed request")]
    RequestBinding,
}

/// Exact v1.0.1 backend output. Unknown/additional fields require adoption review.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeOutput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs_dacl_augmentation: Option<bool>,
    pub warnings: Vec<String>,
    pub probes: ProbeFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeFacts {
    pub base_container_api_present: bool,
    pub native_capture_available: bool,
    pub guarded_capture_available: bool,
    pub bfscfg_present: bool,
    pub bfs_compiled_in: bool,
    pub base_container_supports_deny_paths: bool,
    pub base_container_supports_enumerate_paths: bool,
    pub base_container_supports_ingress_host_loopback_allow: bool,
    pub base_container_supports_identityless_loopback_proxy: bool,
    pub isolation_session_available: bool,
    pub hyperlight_available: bool,
    pub ui_capabilities: UiCapabilitySupport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UiCapabilitySupport {
    pub can_block_clipboard_read: bool,
    pub can_block_clipboard_write: bool,
    pub can_block_input_injection: bool,
    pub can_block_input_method_changes: bool,
    pub can_block_external_ui_objects: bool,
    pub can_block_global_ui_namespace: bool,
    pub can_block_desktop_switching: bool,
    pub can_block_logoff_or_shutdown: bool,
    pub can_block_system_parameter_changes: bool,
    pub can_block_display_settings_changes: bool,
}

impl UiCapabilitySupport {
    fn all_blocked(&self) -> bool {
        self.can_block_clipboard_read
            && self.can_block_clipboard_write
            && self.can_block_input_injection
            && self.can_block_input_method_changes
            && self.can_block_external_ui_objects
            && self.can_block_global_ui_namespace
            && self.can_block_desktop_switching
            && self.can_block_logoff_or_shutdown
            && self.can_block_system_parameter_changes
            && self.can_block_display_settings_changes
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ProbeDisposition {
    Unavailable,
    Refused,
    SupportedForRequest,
}

/// Adapter-bound observation, not an upstream cryptographic attestation.
/// The trusted ABI caller must hash the same held request bytes it actually
/// supplied. No probe result authorizes native execution or proves enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundProbe {
    pub operation: FixedOperation,
    pub request_sha256: String,
    pub disposition: ProbeDisposition,
    pub output: ProbeOutput,
}

pub fn parse_probe(
    request: &FixedRequest,
    supplied_request_sha256: &str,
    bytes: &[u8],
) -> Result<BoundProbe, ContractError> {
    if supplied_request_sha256 != request.sha256() {
        return Err(ContractError::RequestBinding);
    }
    if bytes.len() > 65_536 {
        return Err(ContractError::ProbeBounds);
    }
    let output: ProbeOutput = serde_json::from_slice(bytes)?;
    if output.warnings.len() > 32
        || output.warnings.iter().any(|s| s.len() > 2048)
        || output.error.as_ref().is_some_and(|s| s.len() > 2048)
        || output.tier.as_ref().is_some_and(|s| s.len() > 64)
    {
        return Err(ContractError::ProbeBounds);
    }
    let disposition = if !output.probes.base_container_api_present
        && output.tier.is_none()
        && output.needs_dacl_augmentation.is_none()
        && output.error.is_some()
        && output.warnings.is_empty()
    {
        ProbeDisposition::Unavailable
    } else if output.error.is_some()
        || output.tier.as_deref() != Some("base-container")
        || output.needs_dacl_augmentation != Some(false)
        || output.probes.bfs_compiled_in
        || output.probes.bfscfg_present
        || !output.warnings.is_empty()
        || !output.probes.base_container_api_present
        || !output.probes.base_container_supports_deny_paths
        || !output.probes.ui_capabilities.all_blocked()
    {
        ProbeDisposition::Refused
    } else {
        ProbeDisposition::SupportedForRequest
    };
    Ok(BoundProbe {
        operation: request.operation(),
        request_sha256: request.sha256().into(),
        disposition,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn runtime_manifest_matches_exact_official_contract_without_advancing_legacy_pin() {
        let pin: Value =
            serde_json::from_str(include_str!("../../../third-party/mxc-process-pin.json"))
                .unwrap();
        assert_eq!(pin["release"], RELEASE);
        assert_eq!(pin["commit"], SOURCE_REVISION);
        assert_eq!(pin["contractVersion"], CONTRACT_VERSION);
        assert_eq!(pin["runtime"]["sha256"], RUNTIME_DLL_SHA256);
        assert_eq!(pin["runtime"]["sizeBytes"], RUNTIME_DLL_SIZE);
        assert_eq!(pin["releaseArchive"]["sha256"], RELEASE_ARCHIVE_SHA256);
        assert_eq!(pin["releaseArchive"]["sizeBytes"], RELEASE_ARCHIVE_SIZE);
        assert_eq!(pin["integrationMode"], "fixed-json-c-abi-capability-trial");
        assert_eq!(pin["nativeValidation"], "pending");
        assert_ne!(crate::MXC_COMMIT, SOURCE_REVISION);
    }

    fn supported() -> Value {
        json!({"tier":"base-container","needsDaclAugmentation":false,"warnings":[],
            "probes":{"baseContainerApiPresent":true,"nativeCaptureAvailable":false,
            "guardedCaptureAvailable":false,"bfscfgPresent":false,"bfsCompiledIn":false,
            "baseContainerSupportsDenyPaths":true,"baseContainerSupportsEnumeratePaths":false,
            "baseContainerSupportsIngressHostLoopbackAllow":false,
            "baseContainerSupportsIdentitylessLoopbackProxy":false,
            "isolationSessionAvailable":false,"hyperlightAvailable":false,
            "uiCapabilities":{"canBlockClipboardRead":true,"canBlockClipboardWrite":true,
            "canBlockInputInjection":true,"canBlockInputMethodChanges":true,
            "canBlockExternalUiObjects":true,"canBlockGlobalUiNamespace":true,
            "canBlockDesktopSwitching":true,"canBlockLogoffOrShutdown":true,
            "canBlockSystemParameterChanges":true,"canBlockDisplaySettingsChanges":true}}})
    }

    fn classify(value: &Value) -> Result<BoundProbe, ContractError> {
        let request = FixedRequest::new(FixedOperation::Driver).unwrap();
        parse_probe(
            &request,
            request.sha256(),
            &serde_json::to_vec(value).unwrap(),
        )
    }

    #[test]
    fn fixed_policy_has_separate_input_output_and_no_execution_fallback() {
        for operation in [
            FixedOperation::Driver,
            FixedOperation::Boundary,
            FixedOperation::Create,
            FixedOperation::Test,
            FixedOperation::Extract,
        ] {
            let r = FixedRequest::new(operation).unwrap();
            let v: Value = serde_json::from_str(r.json()).unwrap();
            assert_eq!(v["fallback"]["allowDaclMutation"], false);
            assert_eq!(v["filesystem"]["readwritePaths"], json!([OUTPUT_ROOT]));
            assert_eq!(
                v["filesystem"]["readonlyPaths"],
                json!([APP_ROOT, CONTROL_IMAGE, INPUT_ROOT])
            );
            assert_eq!(v["filesystem"]["deniedPaths"], json!([DENIED_PATH]));
            assert_eq!(v["processContainer"]["capabilities"], json!([]));
            assert_eq!(v["processContainer"]["learningMode"], false);
            assert_eq!(v["processContainer"]["leastPrivilege"], false);
            assert!(v["processContainer"].get("captureDenials").is_none());
            assert_eq!(v["telemetry"]["enabled"], false);
            assert_eq!(v["network"]["egress"]["default"], "deny");
            assert_eq!(v["network"]["ingress"]["hostLoopback"], "deny");
            assert_eq!(
                v["ui"],
                json!({"disable":true,"clipboard":"none","injection":false})
            );
            assert_eq!(r.sha256(), hex::encode(Sha256::digest(r.json().as_bytes())));
        }
    }

    #[test]
    fn request_binding_rejects_reuse_for_a_different_operation() {
        let driver = FixedRequest::new(FixedOperation::Driver).unwrap();
        let create = FixedRequest::new(FixedOperation::Create).unwrap();
        assert_ne!(driver.sha256(), create.sha256());
        assert!(matches!(
            parse_probe(&create, driver.sha256(), b"{}"),
            Err(ContractError::RequestBinding)
        ));
        assert_eq!(
            classify(&supported()).unwrap().disposition,
            ProbeDisposition::SupportedForRequest
        );
    }

    #[test]
    fn fallback_warnings_missing_controls_and_detector_errors_are_refused() {
        for (pointer, value) in [
            ("/tier", json!("appcontainer-bfs")),
            ("/tier", json!("appcontainer-dacl")),
            ("/needsDaclAugmentation", json!(true)),
            ("/probes/bfsCompiledIn", json!(true)),
            ("/probes/baseContainerSupportsDenyPaths", json!(false)),
            (
                "/probes/uiCapabilities/canBlockInputMethodChanges",
                json!(false),
            ),
            ("/warnings", json!(["degraded"])),
        ] {
            let mut v = supported();
            *v.pointer_mut(pointer).unwrap() = value;
            assert_eq!(
                classify(&v).unwrap().disposition,
                ProbeDisposition::Refused,
                "{pointer}"
            );
        }
        let mut v = supported();
        v["error"] = json!("policy cannot be enforced");
        assert_eq!(classify(&v).unwrap().disposition, ProbeDisposition::Refused);
        v.as_object_mut().unwrap().remove("tier");
        v.as_object_mut().unwrap().remove("needsDaclAugmentation");
        v["probes"]["baseContainerApiPresent"] = json!(false);
        assert_eq!(
            classify(&v).unwrap().disposition,
            ProbeDisposition::Unavailable
        );
    }

    #[test]
    fn strict_probe_parser_rejects_unknown_missing_types_and_oversize() {
        let mut v = supported();
        v["newField"] = json!(true);
        assert!(classify(&v).is_err());
        let mut v = supported();
        v["probes"]["newField"] = json!(true);
        assert!(classify(&v).is_err());
        let mut v = supported();
        v["probes"]["uiCapabilities"]["newField"] = json!(true);
        assert!(classify(&v).is_err());
        let mut v = supported();
        v["probes"].as_object_mut().unwrap().remove("bfsCompiledIn");
        assert!(classify(&v).is_err());
        let mut v = supported();
        v["needsDaclAugmentation"] = json!("false");
        assert!(classify(&v).is_err());
        let mut v = supported();
        v["warnings"] = json!(["x".repeat(2049)]);
        assert!(matches!(classify(&v), Err(ContractError::ProbeBounds)));
        let r = FixedRequest::new(FixedOperation::Driver).unwrap();
        assert!(matches!(
            parse_probe(&r, r.sha256(), &vec![b' '; 65537]),
            Err(ContractError::ProbeBounds)
        ));
    }
}
