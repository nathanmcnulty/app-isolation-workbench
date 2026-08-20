#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use aiw_windows_command_line::join_arguments;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MXC_REPOSITORY: &str = "https://github.com/microsoft/mxc";
pub const MXC_COMMIT: &str = "c4a3ab668e85b221b2c77e5e43876ed4e40598ad";
pub const MXC_CONTRACT_VERSION: &str = "0.8.0-alpha";
pub const MXC_PLAN_SCHEMA_VERSION: &str = "aiw.dev/mxc-golden-probe-plan/v0alpha1";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MxcGoldenProbePlan {
    pub schema_version: String,
    pub workspace_root: String,
    pub binary: String,
    pub container_id: String,
    pub backend: MxcBackend,
    pub probe_executable: String,
    pub probe_output: String,
    pub readonly_paths: Vec<String>,
    pub readwrite_paths: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum MxcBackend {
    #[serde(rename = "processcontainer")]
    ProcessContainer,
    #[serde(rename = "windows_sandbox")]
    WindowsSandbox,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MxcInvocationPlan {
    pub schema_version: String,
    pub pin: MxcPin,
    pub backend: MxcBackend,
    pub config_sha256: String,
    pub config: Value,
    pub config_base64: String,
    pub dry_run: ProcessInvocation,
    pub execution: ProcessInvocation,
    pub requires_human_approval: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MxcPin {
    pub repository: String,
    pub commit: String,
    pub contract_version: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessInvocation {
    pub executable: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MxcCapabilityProbePlan {
    pub schema_version: String,
    pub pin: MxcPin,
    pub invocation: ProcessInvocation,
    pub may_recover_orphaned_dacl_state: bool,
    pub warning: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MxcPlanError {
    #[error("unsupported AIW MXC plan schema version: {0}")]
    UnsupportedSchemaVersion(String),
    #[error("{field} must be a deterministic absolute drive path without traversal: {value}")]
    UnsafePath { field: String, value: String },
    #[error("containerId must contain 1-64 ASCII letters, digits, dots, underscores, or hyphens")]
    InvalidContainerId,
    #[error("timeoutMs must be between 1 and 3,600,000")]
    InvalidTimeout,
    #[error("read-only and read-write policy paths must be unique and non-overlapping")]
    ConflictingPaths,
    #[error(
        "the golden probe contract requires exactly one read-only tools root and one read-write output root"
    )]
    InvalidPolicyShape,
    #[error("filesystem policy path must be strictly below workspaceRoot: {0}")]
    PolicyOutsideWorkspace(String),
    #[error("the probe executable must be below a read-only policy path")]
    ProbeOutsideReadonlyPath,
    #[error("the probe output must be below a read-write policy path")]
    OutputOutsideReadwritePath,
    #[error("could not serialize the pinned MXC config: {0}")]
    Serialization(String),
}

pub fn plan_golden_probe(plan: &MxcGoldenProbePlan) -> Result<MxcInvocationPlan, MxcPlanError> {
    validate_plan(plan)?;
    let command_line = join_arguments([
        plan.probe_executable.as_str(),
        "--output",
        plan.probe_output.as_str(),
    ]);

    let config = MxcRequest {
        version: MXC_CONTRACT_VERSION,
        container_id: &plan.container_id,
        containment: plan.backend,
        process: MxcProcess {
            command_line,
            cwd: parent_path(&plan.probe_output),
            timeout: plan.timeout_ms,
        },
        filesystem: MxcFilesystem {
            readwrite_paths: &plan.readwrite_paths,
            readonly_paths: &plan.readonly_paths,
        },
        fallback: (plan.backend == MxcBackend::ProcessContainer).then_some(MxcFallback {
            allow_dacl_mutation: false,
        }),
        network: MxcNetwork {
            default_policy: "block",
            enforcement_mode: (plan.backend == MxcBackend::ProcessContainer).then_some("both"),
            allow_local_network: (plan.backend == MxcBackend::ProcessContainer).then_some(false),
        },
        ui: (plan.backend == MxcBackend::ProcessContainer).then_some(MxcUi {
            disable: true,
            clipboard: "none",
            injection: false,
        }),
        process_container: (plan.backend == MxcBackend::ProcessContainer).then_some(
            MxcProcessContainer {
                least_privilege: true,
                learning_mode: false,
                capabilities: Vec::new(),
            },
        ),
    };
    let config_bytes = serde_json::to_vec(&config)
        .map_err(|error| MxcPlanError::Serialization(error.to_string()))?;
    let config_value = serde_json::from_slice(&config_bytes)
        .map_err(|error| MxcPlanError::Serialization(error.to_string()))?;
    let config_base64 = BASE64.encode(&config_bytes);
    let execution_arguments = vec![
        "--experimental".to_owned(),
        "--config-base64".to_owned(),
        config_base64.clone(),
    ];
    let dry_run_arguments = vec![
        "--experimental".to_owned(),
        "--dry-run".to_owned(),
        "--config-base64".to_owned(),
        config_base64.clone(),
    ];

    let mut warnings = vec![
        "MXC is pinned by commit because the 0.8.0-alpha development contract can change without notice."
            .to_owned(),
        "The execution invocation is a plan only and requires separate human approval."
            .to_owned(),
    ];
    if plan.backend == MxcBackend::WindowsSandbox {
        warnings.push(
            "Windows Sandbox supports one VM per logon session; one-shot teardown is best-effort after a launcher hard-kill."
                .to_owned(),
        );
    } else {
        warnings.push(
            "allowDaclMutation is explicitly false; hosts requiring MXC Tier 3 must fail instead of changing path DACLs."
                .to_owned(),
        );
    }

    Ok(MxcInvocationPlan {
        schema_version: "aiw.dev/mxc-invocation-plan/v0alpha1".to_owned(),
        pin: current_pin(),
        backend: plan.backend,
        config_sha256: hex::encode(Sha256::digest(&config_bytes)),
        config: config_value,
        config_base64,
        dry_run: ProcessInvocation {
            executable: plan.binary.clone(),
            arguments: dry_run_arguments,
        },
        execution: ProcessInvocation {
            executable: plan.binary.clone(),
            arguments: execution_arguments,
        },
        requires_human_approval: true,
        warnings,
    })
}

pub fn plan_capability_probe(binary: &str) -> Result<MxcCapabilityProbePlan, MxcPlanError> {
    validate_absolute_drive_path("binary", binary)?;
    Ok(MxcCapabilityProbePlan {
        schema_version: "aiw.dev/mxc-capability-probe-plan/v0alpha1".to_owned(),
        pin: current_pin(),
        invocation: ProcessInvocation {
            executable: binary.to_owned(),
            arguments: vec!["--experimental".to_owned(), "--probe".to_owned()],
        },
        may_recover_orphaned_dacl_state: true,
        warning: "At the pinned MXC commit, wxc-exec performs best-effort orphaned DACL recovery before its --probe fast path. Treat this invocation as potentially host-mutating."
            .to_owned(),
    })
}

pub fn current_pin() -> MxcPin {
    MxcPin {
        repository: MXC_REPOSITORY.to_owned(),
        commit: MXC_COMMIT.to_owned(),
        contract_version: MXC_CONTRACT_VERSION.to_owned(),
    }
}

fn validate_plan(plan: &MxcGoldenProbePlan) -> Result<(), MxcPlanError> {
    if plan.schema_version != MXC_PLAN_SCHEMA_VERSION {
        return Err(MxcPlanError::UnsupportedSchemaVersion(
            plan.schema_version.clone(),
        ));
    }
    validate_absolute_drive_path("binary", &plan.binary)?;
    validate_absolute_drive_path("workspaceRoot", &plan.workspace_root)?;
    validate_absolute_drive_path("probeExecutable", &plan.probe_executable)?;
    validate_absolute_drive_path("probeOutput", &plan.probe_output)?;
    if plan.container_id.is_empty()
        || plan.container_id.len() > 64
        || !plan
            .container_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(MxcPlanError::InvalidContainerId);
    }
    if !(1..=3_600_000).contains(&plan.timeout_ms) {
        return Err(MxcPlanError::InvalidTimeout);
    }
    if plan.readonly_paths.len() != 1 || plan.readwrite_paths.len() != 1 {
        return Err(MxcPlanError::InvalidPolicyShape);
    }

    let mut paths = BTreeSet::new();
    for (field, values) in [
        ("readonlyPaths", &plan.readonly_paths),
        ("readwritePaths", &plan.readwrite_paths),
    ] {
        for value in values {
            validate_absolute_drive_path(field, value)?;
            if !path_is_below(value, &plan.workspace_root) {
                return Err(MxcPlanError::PolicyOutsideWorkspace(value.clone()));
            }
            if !paths.insert(normalize_path(value)) {
                return Err(MxcPlanError::ConflictingPaths);
            }
        }
    }
    let normalized = paths.iter().collect::<Vec<_>>();
    for (index, left) in normalized.iter().enumerate() {
        for right in &normalized[index + 1..] {
            if path_is_below(left, right) || path_is_below(right, left) {
                return Err(MxcPlanError::ConflictingPaths);
            }
        }
    }
    if !plan
        .readonly_paths
        .iter()
        .any(|parent| path_is_below(&plan.probe_executable, parent))
    {
        return Err(MxcPlanError::ProbeOutsideReadonlyPath);
    }
    if !plan
        .readwrite_paths
        .iter()
        .any(|parent| path_is_below(&plan.probe_output, parent))
    {
        return Err(MxcPlanError::OutputOutsideReadwritePath);
    }
    if normalize_path(&parent_path(&plan.probe_output)) != normalize_path(&plan.readwrite_paths[0])
    {
        return Err(MxcPlanError::OutputOutsideReadwritePath);
    }
    Ok(())
}

fn validate_absolute_drive_path(field: &str, value: &str) -> Result<(), MxcPlanError> {
    let bytes = value.as_bytes();
    let valid_prefix =
        bytes.len() >= 4 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    let invalid = !valid_prefix
        || value.contains(['\0', '\r', '\n', '\t', '/', '%', '&', '!', '^', '(', ')'])
        || value.split('\\').skip(1).any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || segment.ends_with([' ', '.'])
                || segment
                    .chars()
                    .any(|character| matches!(character, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
        });
    if invalid {
        return Err(MxcPlanError::UnsafePath {
            field: field.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn normalize_path(value: &str) -> String {
    value.trim_end_matches('\\').to_ascii_lowercase()
}

fn path_is_below(path: &str, parent: &str) -> bool {
    let path = normalize_path(path);
    let mut parent = normalize_path(parent);
    parent.push('\\');
    path.starts_with(&parent)
}

fn parent_path(value: &str) -> String {
    value
        .rsplit_once('\\')
        .map_or_else(|| value.to_owned(), |(parent, _)| parent.to_owned())
}

const fn default_timeout_ms() -> u32 {
    60_000
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MxcRequest<'a> {
    version: &'static str,
    container_id: &'a str,
    containment: MxcBackend,
    process: MxcProcess,
    filesystem: MxcFilesystem<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback: Option<MxcFallback>,
    network: MxcNetwork,
    #[serde(skip_serializing_if = "Option::is_none")]
    ui: Option<MxcUi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_container: Option<MxcProcessContainer>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MxcProcess {
    command_line: String,
    cwd: String,
    timeout: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MxcFilesystem<'a> {
    readwrite_paths: &'a [String],
    readonly_paths: &'a [String],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MxcFallback {
    allow_dacl_mutation: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MxcNetwork {
    default_policy: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    enforcement_mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_local_network: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MxcUi {
    disable: bool,
    clipboard: &'static str,
    injection: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MxcProcessContainer {
    least_privilege: bool,
    learning_mode: bool,
    capabilities: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_plan(backend: MxcBackend) -> MxcGoldenProbePlan {
        MxcGoldenProbePlan {
            schema_version: MXC_PLAN_SCHEMA_VERSION.to_owned(),
            workspace_root: "C:\\AIW".to_owned(),
            binary: "C:\\AIW\\MXC\\wxc-exec.exe".to_owned(),
            container_id: "aiw-golden-probe-001".to_owned(),
            backend,
            probe_executable: "C:\\AIW\\Tools\\aiw-golden-probe.exe".to_owned(),
            probe_output: "C:\\AIW\\Output\\token.json".to_owned(),
            readonly_paths: vec!["C:\\AIW\\Tools".to_owned()],
            readwrite_paths: vec!["C:\\AIW\\Output".to_owned()],
            timeout_ms: 60_000,
        }
    }

    #[test]
    fn process_container_plan_refuses_dacl_fallback() {
        let result = plan_golden_probe(&valid_plan(MxcBackend::ProcessContainer))
            .expect("valid plan should render");
        assert_eq!(result.pin.commit, MXC_COMMIT);
        assert_eq!(
            result.config_sha256,
            "2e4e4990856209b85e993e0232ef9e2bdd0a2dfdbb9679734702751a5c01f15d"
        );
        assert_eq!(result.config["version"], MXC_CONTRACT_VERSION);
        assert_eq!(result.config["containment"], "processcontainer");
        assert_eq!(result.config["fallback"]["allowDaclMutation"], false);
        assert_eq!(result.config["network"]["defaultPolicy"], "block");
        assert_eq!(result.config["processContainer"]["leastPrivilege"], true);
        assert!(result.dry_run.arguments.contains(&"--dry-run".to_owned()));
        assert!(!result.execution.arguments.contains(&"--dry-run".to_owned()));
    }

    #[test]
    fn windows_sandbox_omits_process_container_policy() {
        let result = plan_golden_probe(&valid_plan(MxcBackend::WindowsSandbox))
            .expect("valid plan should render");
        assert_eq!(result.config["containment"], "windows_sandbox");
        assert!(result.config.get("fallback").is_none());
        assert!(result.config.get("ui").is_none());
        assert!(result.config.get("processContainer").is_none());
        assert!(result.config["network"].get("enforcementMode").is_none());
        assert!(result.config["network"].get("allowLocalNetwork").is_none());
    }

    #[test]
    fn capability_probe_discloses_pre_probe_recovery() {
        let result =
            plan_capability_probe("C:\\AIW\\MXC\\wxc-exec.exe").expect("path should be valid");
        assert!(result.may_recover_orphaned_dacl_state);
        assert_eq!(result.invocation.arguments, ["--experimental", "--probe"]);
    }

    #[test]
    fn rejects_overlapping_policy_roots_and_misdirected_output() {
        let mut plan = valid_plan(MxcBackend::ProcessContainer);
        plan.readwrite_paths = vec!["C:\\AIW\\Tools\\Output".to_owned()];
        assert_eq!(
            plan_golden_probe(&plan),
            Err(MxcPlanError::ConflictingPaths)
        );

        let mut plan = valid_plan(MxcBackend::ProcessContainer);
        plan.probe_output = "C:\\Other\\token.json".to_owned();
        assert_eq!(
            plan_golden_probe(&plan),
            Err(MxcPlanError::OutputOutsideReadwritePath)
        );

        let mut plan = valid_plan(MxcBackend::ProcessContainer);
        plan.readonly_paths = vec!["C:\\Outside\\Tools".to_owned()];
        assert_eq!(
            plan_golden_probe(&plan),
            Err(MxcPlanError::PolicyOutsideWorkspace(
                "C:\\Outside\\Tools".to_owned()
            ))
        );
    }
}
