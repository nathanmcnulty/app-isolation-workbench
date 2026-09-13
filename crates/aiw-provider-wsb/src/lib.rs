#![forbid(unsafe_code)]

mod application_token;
mod bambu_artifact;
pub use bambu_artifact::{BambuExportArtifact, verify_bambu_export};
mod bambu_export;
mod imported_bambu;
pub use bambu_export::{
    BAMBU_EXPORT_ARTIFACT_PATH, BAMBU_MAX_ARTIFACT_BYTES, BAMBU_STUDIO_EXPORT_OUTPUT_PATH,
    BambuExportCompileError, CompiledBambuExportScenario, compile_bambu_studio_export_scenario,
};
pub use imported_bambu::{
    BAMBU_SCENARIO_EVENT, BambuExecutionStage, BambuScenarioStatus,
    IMPORTED_BAMBU_GUEST_REQUEST_SCHEMA_VERSION, IMPORTED_BAMBU_SCENARIO_RESULT_SCHEMA_VERSION,
    ImportedBambuGuestRequest, ImportedBambuRequestError, ImportedBambuScenarioResult,
    verify_bambu_scenario_evidence,
};
mod bambu_scenario;
mod completion;
mod failure_snapshots;
mod imported_msi;
mod product_registration;
mod registry_observations;
mod runtime_context;
mod scenario;
mod stage_progress;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use aiw_windows_command_line::join_arguments;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use application_token::{
    ImportedMsiApplicationToken, MSI_APPLICATION_TOKEN_EVENT, MSI_APPLICATION_TOKEN_SCHEMA,
    verify_msi_application_token,
};
pub use bambu_scenario::{
    BAMBU_STUDIO_APPLICATION_SHA256, BAMBU_STUDIO_ENTRYPOINT_ID, BAMBU_STUDIO_ENTRYPOINT_PATH,
    BAMBU_STUDIO_INFO_FIXTURE_PATH, BAMBU_STUDIO_INFO_FIXTURE_SHA256, BAMBU_STUDIO_INFO_PROFILE,
    BAMBU_STUDIO_INSTALLED_PATH, BAMBU_STUDIO_STAGED_INSTALLER_PATH, BambuScenarioCompileError,
    COMPILED_BAMBU_SCENARIO_SCHEMA_VERSION, CompiledBambuScenario,
    compile_bambu_studio_info_scenario,
};

pub use completion::{
    CompletionArtifact, CompletionArtifactExpectation, CompletionStatus,
    WINDOWS_SANDBOX_COMPLETION_EXPECTATION_SCHEMA_VERSION,
    WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION,
    WINDOWS_SANDBOX_COMPLETION_VERIFICATION_SCHEMA_VERSION, WindowsSandboxCompletionError,
    WindowsSandboxCompletionExpectation, WindowsSandboxCompletionReceipt,
    WindowsSandboxCompletionVerification, verify_completion_receipt,
};
pub use failure_snapshots::{
    FailedSnapshotPhase, IMPORTED_MSI_FAILED_SNAPSHOTS_EVENT,
    IMPORTED_MSI_FAILED_SNAPSHOTS_SCHEMA_VERSION, ImportedMsiFailedSnapshots,
    verify_msi_failed_snapshots,
};
pub use imported_msi::{
    IMPORTED_MSI_DOCUMENT_SCENARIO_RESULT_SCHEMA_VERSION,
    IMPORTED_MSI_GUEST_REQUEST_SCHEMA_VERSION, IMPORTED_MSI_SCENARIO_RESULT_SCHEMA_VERSION,
    ImportedMsiDocumentTransferResult, ImportedMsiGuestRequest, ImportedMsiRequestError,
    ImportedMsiScenarioResult, ImportedMsiScenarioStatus,
};
pub use product_registration::{
    IMPORTED_MSI_PRODUCT_REGISTRATION_EVENT, IMPORTED_MSI_PRODUCT_REGISTRATION_SCHEMA_VERSION,
    ImportedMsiProductRegistrationEvidence, MsiMachineProductState, validate_msi_product_code,
    verify_msi_product_registration_evidence,
};
pub use registry_observations::{
    ApplicationRegistryRoot, ApplicationRegistrySnapshot, IMPORTED_MSI_REGISTRY_EVENT,
    IMPORTED_MSI_REGISTRY_SCHEMA, IMPORTED_MSI_REGISTRY_SCHEMA_VERSION,
    ImportedMsiRegistryEvidence, RegistryCaptureIssue, RegistryCaptureIssueReason,
    RegistryDiffKind, RegistryKeyDiff, RegistryKeyEntry, RegistryScope, RegistrySnapshotDiff,
    RegistryValueDiff, RegistryValueEntry, RegistryView, diff_registry_snapshots,
    verify_msi_registry_evidence,
};
pub use runtime_context::{
    IMPORTED_MSI_RUNTIME_CONTEXT_EVENT, IMPORTED_MSI_RUNTIME_CONTEXT_SCHEMA,
    IMPORTED_MSI_RUNTIME_CONTEXT_SCHEMA_VERSION, ImportedMsiRuntimeContext,
    STANDARD_USER_ACCOUNT_NAME, STANDARD_USER_PROFILE_PATH, StandardUserRuntimeContext,
    verify_imported_msi_runtime_context, verify_msi_runtime_context,
};
pub use scenario::{
    COMPILED_MSI_INTERACTIVE_DOCUMENT_SCENARIO_SCHEMA_VERSION, CompiledMsiScenario,
    FixedDocumentExercise, INTERACTIVE_DOCUMENT_INPUT_PATH, INTERACTIVE_DOCUMENT_OUTPUT_PATH,
    InteractiveDocumentTransfer, MAX_INTERACTIVE_DOCUMENT_BYTES,
    NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE, ScenarioCompileError,
    compile_notepad_plus_plus_msi_scenario, compile_notepad_plus_plus_msi_scenario_with_document,
};
pub use stage_progress::{
    IMPORTED_MSI_FAILED_ATTEMPT_SCHEMA, IMPORTED_MSI_FAILED_ATTEMPT_SCHEMA_VERSION,
    IMPORTED_MSI_STAGE_PROGRESS_EVENT, IMPORTED_MSI_STAGE_PROGRESS_SCHEMA,
    IMPORTED_MSI_STAGE_PROGRESS_SCHEMA_VERSION, ImportedMsiFailedAttempt, ImportedMsiStageProgress,
    MsiExecutionStage, MsiStageResult, MsiStageStatus, verify_imported_msi_stage_progress,
};

pub const WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION: &str = "aiw.dev/windows-sandbox-plan/v0alpha1";
pub const WINDOWS_SANDBOX_CLI_LIFECYCLE_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-cli-lifecycle/v0alpha2";
pub const WINDOWS_SANDBOX_CLI_INTERFACE: &str = "microsoft.windows-sandbox-cli/2025-01-24";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxPlan {
    pub schema_version: String,
    pub workspace_root: String,
    pub mappings: Vec<MappedFolder>,
    pub probe: GoldenProbe,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MappedFolder {
    pub purpose: MappingPurpose,
    pub host_folder: String,
    pub sandbox_folder: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MappingPurpose {
    Input,
    Tools,
    Output,
}

impl MappingPurpose {
    const fn read_only(self) -> bool {
        !matches!(self, Self::Output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoldenProbe {
    pub executable: String,
    /// The immutable fixed-function guest-agent request.  Legacy planner use
    /// can omit it, but W1 execution requires it and never falls back to an
    /// arbitrary logon command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderedWindowsSandboxConfig {
    pub schema_version: String,
    pub security_profile: String,
    pub sha256: String,
    pub xml: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxCliLifecyclePlan {
    pub schema_version: String,
    pub interface: String,
    pub sandbox_id: String,
    pub rendered_config: RenderedWindowsSandboxConfig,
    pub start: ProcessInvocation,
    pub list: ProcessInvocation,
    pub connect: ProcessInvocation,
    pub stop: ProcessInvocation,
    pub guest_execution: GuestExecutionContract,
    pub output_observation: OutputObservationContract,
    pub requires_human_approval: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessInvocation {
    pub executable: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestExecutionContract {
    pub trigger: String,
    pub account: String,
    pub uses_exec_command: bool,
    pub permits_system_context: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputObservationContract {
    pub channel: String,
    pub host_folder: String,
    pub sandbox_folder: String,
    pub expected_host_artifact: String,
    pub expected_guest_artifact: String,
    pub guest_write_access: bool,
    pub process_io_available: bool,
    pub dynamic_share_required: bool,
    pub artifact_is_completion_receipt: bool,
    pub separate_completion_receipt_required: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WindowsSandboxPlanError {
    #[error("unsupported plan schema version: {0}")]
    UnsupportedSchemaVersion(String),
    #[error("{field} must be a deterministic absolute drive path without traversal: {value}")]
    UnsafePath { field: String, value: String },
    #[error("duplicate mapped {field}, ignoring Windows path case: {value}")]
    DuplicateMapping { field: &'static str, value: String },
    #[error("mapped host folder must be strictly below workspaceRoot: {0}")]
    MappingOutsideWorkspace(String),
    #[error("exactly one tools mapping and one output mapping are required")]
    RequiredMappings,
    #[error("the golden probe executable must be inside the tools mapping")]
    ProbeOutsideTools,
    #[error("the golden probe output must be inside the output mapping")]
    OutputOutsideMapping,
    #[error("MemoryInMB must be at least 2048 when specified")]
    InsufficientMemory,
    #[error("mapped host folder does not exist or is not a directory: {0}")]
    MissingHostFolder(String),
    #[error("the writable output folder must initially be empty: {0}")]
    NonEmptyOutputFolder(String),
    #[error("mapped host folder roots must not be symbolic links or reparse points: {0}")]
    ReparsePointHostFolder(String),
    #[error("the mapped golden probe must exist as an ordinary file: {0}")]
    MissingProbeExecutable(String),
    #[error("mapped host folders resolve to duplicate or nested locations: {0}")]
    OverlappingCanonicalHostFolders(String),
    #[error("could not inspect mapped host folder {path}: {message}")]
    HostInspection { path: String, message: String },
    #[error("wsbCliPath must be an absolute drive path whose final component is wsb.exe")]
    InvalidCliPath,
    #[error("sandboxId must be a canonical UUID without braces")]
    InvalidSandboxId,
}

pub fn plan_cli_lifecycle(
    wsb_cli_path: &str,
    sandbox_id: &str,
    plan: &WindowsSandboxPlan,
) -> Result<WindowsSandboxCliLifecyclePlan, WindowsSandboxPlanError> {
    validate_absolute_drive_path("wsbCliPath", wsb_cli_path)
        .map_err(|_| WindowsSandboxPlanError::InvalidCliPath)?;
    if !wsb_cli_path
        .rsplit('\\')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("wsb.exe"))
    {
        return Err(WindowsSandboxPlanError::InvalidCliPath);
    }
    if !is_canonical_uuid(sandbox_id) {
        return Err(WindowsSandboxPlanError::InvalidSandboxId);
    }

    let rendered_config = render_config(plan)?;
    let output = plan
        .mappings
        .iter()
        .find(|mapping| mapping.purpose == MappingPurpose::Output)
        .expect("render_config requires exactly one output mapping");
    let guest_root = output.sandbox_folder.trim_end_matches('\\');
    let relative_artifact = &plan.probe.output[guest_root.len() + 1..];
    let expected_host_artifact = format!(
        "{}\\{}",
        output.host_folder.trim_end_matches('\\'),
        relative_artifact
    );
    let sandbox_id = sandbox_id.to_ascii_lowercase();

    Ok(WindowsSandboxCliLifecyclePlan {
        schema_version: WINDOWS_SANDBOX_CLI_LIFECYCLE_SCHEMA_VERSION.to_owned(),
        interface: WINDOWS_SANDBOX_CLI_INTERFACE.to_owned(),
        sandbox_id: sandbox_id.clone(),
        start: ProcessInvocation {
            executable: wsb_cli_path.to_owned(),
            arguments: vec![
                "start".to_owned(),
                "--raw".to_owned(),
                "--id".to_owned(),
                sandbox_id.clone(),
                "--config".to_owned(),
                rendered_config.xml.clone(),
            ],
        },
        list: ProcessInvocation {
            executable: wsb_cli_path.to_owned(),
            arguments: vec!["list".to_owned(), "--raw".to_owned()],
        },
        connect: ProcessInvocation {
            executable: wsb_cli_path.to_owned(),
            arguments: vec![
                "connect".to_owned(),
                "--raw".to_owned(),
                "--id".to_owned(),
                sandbox_id.clone(),
            ],
        },
        stop: ProcessInvocation {
            executable: wsb_cli_path.to_owned(),
            arguments: vec![
                "stop".to_owned(),
                "--raw".to_owned(),
                "--id".to_owned(),
                sandbox_id,
            ],
        },
        guest_execution: GuestExecutionContract {
            trigger: "preconfiguredLogonCommand".to_owned(),
            account: "WDAGUtilityAccount".to_owned(),
            uses_exec_command: false,
            permits_system_context: false,
        },
        output_observation: OutputObservationContract {
            channel: "preconfiguredMappedFolder".to_owned(),
            host_folder: output.host_folder.clone(),
            sandbox_folder: output.sandbox_folder.clone(),
            expected_host_artifact,
            expected_guest_artifact: plan.probe.output.clone(),
            guest_write_access: true,
            process_io_available: false,
            dynamic_share_required: false,
            artifact_is_completion_receipt: false,
            separate_completion_receipt_required: true,
        },
        rendered_config,
        requires_human_approval: true,
        warnings: vec![
            "This output is an inspectable plan only; it does not launch, connect, or stop Windows Sandbox."
                .to_owned(),
            "The Windows Sandbox CLI is an early interface delivered with the Store-updated app; record the resolved binary identity and app version at execution time."
                .to_owned(),
            "The CLI does not expose guest process I/O. The mapped output artifact is untrusted evidence, not a run-completion receipt."
                .to_owned(),
            "Do not add folders with wsb share or run the guest agent with wsb exec --run-as System; both would change the reviewed trust contract."
                .to_owned(),
            "Windows Sandbox supports one running instance per user session; orchestration must serialize runs and verify the returned sandbox ID."
                .to_owned(),
            "The CLI-created environment is explicitly connected so the configured user logon and LogonCommand occur before receipt observation."
                .to_owned(),
        ],
    })
}

pub fn render_config(
    plan: &WindowsSandboxPlan,
) -> Result<RenderedWindowsSandboxConfig, WindowsSandboxPlanError> {
    validate_plan(plan)?;

    let mut xml = String::from("<Configuration>\n");
    xml.push_str("  <vGPU>Disable</vGPU>\n");
    xml.push_str("  <Networking>Disable</Networking>\n");
    xml.push_str("  <AudioInput>Disable</AudioInput>\n");
    xml.push_str("  <VideoInput>Disable</VideoInput>\n");
    xml.push_str("  <ProtectedClient>Enable</ProtectedClient>\n");
    xml.push_str("  <PrinterRedirection>Disable</PrinterRedirection>\n");
    xml.push_str("  <ClipboardRedirection>Disable</ClipboardRedirection>\n");
    if let Some(memory_mb) = plan.memory_mb {
        let _ = writeln!(xml, "  <MemoryInMB>{memory_mb}</MemoryInMB>");
    }
    xml.push_str("  <MappedFolders>\n");
    for mapping in &plan.mappings {
        xml.push_str("    <MappedFolder>\n");
        let _ = writeln!(
            xml,
            "      <HostFolder>{}</HostFolder>",
            escape_xml(&mapping.host_folder)
        );
        let _ = writeln!(
            xml,
            "      <SandboxFolder>{}</SandboxFolder>",
            escape_xml(&mapping.sandbox_folder)
        );
        let _ = writeln!(
            xml,
            "      <ReadOnly>{}</ReadOnly>",
            mapping.purpose.read_only()
        );
        xml.push_str("    </MappedFolder>\n");
    }
    xml.push_str("  </MappedFolders>\n");
    xml.push_str("  <LogonCommand>\n");
    let command = match &plan.probe.request {
        Some(request) => join_arguments([plan.probe.executable.as_str(), "--request", request]),
        None => join_arguments([
            plan.probe.executable.as_str(),
            "--output",
            plan.probe.output.as_str(),
        ]),
    };
    let _ = writeln!(xml, "    <Command>{}</Command>", escape_xml(&command));
    xml.push_str("  </LogonCommand>\n");
    xml.push_str("</Configuration>\n");

    let sha256 = hex::encode(Sha256::digest(xml.as_bytes()));
    Ok(RenderedWindowsSandboxConfig {
        schema_version: "aiw.dev/rendered-windows-sandbox/v0alpha1".to_owned(),
        security_profile: "aiw-direct-wsb-hardened-v0alpha1".to_owned(),
        sha256,
        xml,
        warnings: vec![
            "The output mapping is host-writable by sandboxed code; treat every returned artifact as untrusted input."
                .to_owned(),
            "Windows Sandbox runs one instance per host session and destroys guest-local state when closed."
                .to_owned(),
        ],
    })
}

pub fn validate_host_mappings(plan: &WindowsSandboxPlan) -> Result<(), WindowsSandboxPlanError> {
    validate_plan(plan)?;
    let workspace_path = Path::new(&plan.workspace_root);
    let workspace_metadata = fs::symlink_metadata(workspace_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            WindowsSandboxPlanError::MissingHostFolder(plan.workspace_root.clone())
        } else {
            WindowsSandboxPlanError::HostInspection {
                path: plan.workspace_root.clone(),
                message: error.to_string(),
            }
        }
    })?;
    if !workspace_metadata.is_dir()
        || workspace_metadata.file_type().is_symlink()
        || has_reparse_point(&workspace_metadata)
    {
        return Err(WindowsSandboxPlanError::ReparsePointHostFolder(
            plan.workspace_root.clone(),
        ));
    }
    let canonical_workspace = fs::canonicalize(workspace_path).map_err(|error| {
        WindowsSandboxPlanError::HostInspection {
            path: plan.workspace_root.clone(),
            message: error.to_string(),
        }
    })?;
    let canonical_workspace =
        normalize_path(&canonical_workspace.to_string_lossy().replace("\\\\?\\", ""));
    let mut canonical_paths: Vec<String> = Vec::new();
    for mapping in &plan.mappings {
        let path = Path::new(&mapping.host_folder);
        let link_metadata = fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                WindowsSandboxPlanError::MissingHostFolder(mapping.host_folder.clone())
            } else {
                WindowsSandboxPlanError::HostInspection {
                    path: mapping.host_folder.clone(),
                    message: error.to_string(),
                }
            }
        })?;
        if link_metadata.file_type().is_symlink() || has_reparse_point(&link_metadata) {
            return Err(WindowsSandboxPlanError::ReparsePointHostFolder(
                mapping.host_folder.clone(),
            ));
        }
        let metadata =
            fs::metadata(path).map_err(|error| WindowsSandboxPlanError::HostInspection {
                path: mapping.host_folder.clone(),
                message: error.to_string(),
            })?;
        if !metadata.is_dir() {
            return Err(WindowsSandboxPlanError::MissingHostFolder(
                mapping.host_folder.clone(),
            ));
        }
        let canonical =
            fs::canonicalize(path).map_err(|error| WindowsSandboxPlanError::HostInspection {
                path: mapping.host_folder.clone(),
                message: error.to_string(),
            })?;
        let canonical = normalize_path(&canonical.to_string_lossy().replace("\\\\?\\", ""));
        if !is_path_below(&canonical, &canonical_workspace) {
            return Err(WindowsSandboxPlanError::MappingOutsideWorkspace(
                mapping.host_folder.clone(),
            ));
        }
        if canonical_paths.iter().any(|existing| {
            existing == &canonical
                || is_path_below(&canonical, existing)
                || is_path_below(existing, &canonical)
        }) {
            return Err(WindowsSandboxPlanError::OverlappingCanonicalHostFolders(
                mapping.host_folder.clone(),
            ));
        }
        canonical_paths.push(canonical);
        if mapping.purpose == MappingPurpose::Output {
            let mut entries =
                fs::read_dir(path).map_err(|error| WindowsSandboxPlanError::HostInspection {
                    path: mapping.host_folder.clone(),
                    message: error.to_string(),
                })?;
            if entries
                .next()
                .transpose()
                .map_err(|error| WindowsSandboxPlanError::HostInspection {
                    path: mapping.host_folder.clone(),
                    message: error.to_string(),
                })?
                .is_some()
            {
                return Err(WindowsSandboxPlanError::NonEmptyOutputFolder(
                    mapping.host_folder.clone(),
                ));
            }
        }
    }

    let tools = plan
        .mappings
        .iter()
        .find(|mapping| mapping.purpose == MappingPurpose::Tools)
        .expect("validate_plan requires exactly one tools mapping");
    let guest_root = tools.sandbox_folder.trim_end_matches('\\');
    let relative = &plan.probe.executable[guest_root.len() + 1..];
    let probe_host_path = relative.split('\\').fold(
        Path::new(&tools.host_folder).to_path_buf(),
        |path, segment| path.join(segment),
    );
    let probe_metadata = fs::symlink_metadata(&probe_host_path).map_err(|_| {
        WindowsSandboxPlanError::MissingProbeExecutable(
            probe_host_path.to_string_lossy().into_owned(),
        )
    })?;
    if !probe_metadata.is_file()
        || probe_metadata.file_type().is_symlink()
        || has_reparse_point(&probe_metadata)
    {
        return Err(WindowsSandboxPlanError::MissingProbeExecutable(
            probe_host_path.to_string_lossy().into_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn has_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn has_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

pub fn validate_plan(plan: &WindowsSandboxPlan) -> Result<(), WindowsSandboxPlanError> {
    if plan.schema_version != WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION {
        return Err(WindowsSandboxPlanError::UnsupportedSchemaVersion(
            plan.schema_version.clone(),
        ));
    }
    validate_host_path("workspaceRoot", &plan.workspace_root)?;
    if plan.memory_mb.is_some_and(|value| value < 2048) {
        return Err(WindowsSandboxPlanError::InsufficientMemory);
    }
    validate_guest_path("probe.executable", &plan.probe.executable)?;
    if let Some(request) = &plan.probe.request {
        validate_guest_path("probe.request", request)?;
    }
    validate_guest_path("probe.output", &plan.probe.output)?;
    if !plan.probe.executable.to_ascii_lowercase().ends_with(".exe")
        || !plan.probe.output.to_ascii_lowercase().ends_with(".json")
    {
        return Err(WindowsSandboxPlanError::UnsafePath {
            field: "probe".to_owned(),
            value: format!("{} -> {}", plan.probe.executable, plan.probe.output),
        });
    }

    let mut host_paths = BTreeSet::new();
    let mut sandbox_paths = BTreeSet::new();
    let mut tools = Vec::new();
    let mut outputs = Vec::new();
    for (index, mapping) in plan.mappings.iter().enumerate() {
        validate_host_path(
            &format!("mappings[{index}].hostFolder"),
            &mapping.host_folder,
        )?;
        if !is_path_below(&mapping.host_folder, &plan.workspace_root) {
            return Err(WindowsSandboxPlanError::MappingOutsideWorkspace(
                mapping.host_folder.clone(),
            ));
        }
        validate_guest_path(
            &format!("mappings[{index}].sandboxFolder"),
            &mapping.sandbox_folder,
        )?;
        if !host_paths.insert(normalize_path(&mapping.host_folder)) {
            return Err(WindowsSandboxPlanError::DuplicateMapping {
                field: "host folder",
                value: mapping.host_folder.clone(),
            });
        }
        if !sandbox_paths.insert(normalize_path(&mapping.sandbox_folder)) {
            return Err(WindowsSandboxPlanError::DuplicateMapping {
                field: "sandbox folder",
                value: mapping.sandbox_folder.clone(),
            });
        }
        match mapping.purpose {
            MappingPurpose::Tools => tools.push(mapping),
            MappingPurpose::Output => outputs.push(mapping),
            MappingPurpose::Input => {}
        }
    }
    if tools.len() != 1 || outputs.len() != 1 {
        return Err(WindowsSandboxPlanError::RequiredMappings);
    }
    if !is_path_below(&plan.probe.executable, &tools[0].sandbox_folder) {
        return Err(WindowsSandboxPlanError::ProbeOutsideTools);
    }
    if let Some(request) = &plan.probe.request {
        if !is_path_below(request, &tools[0].sandbox_folder)
            || !request.to_ascii_lowercase().ends_with(".json")
        {
            return Err(WindowsSandboxPlanError::ProbeOutsideTools);
        }
    }
    if !is_path_below(&plan.probe.output, &outputs[0].sandbox_folder) {
        return Err(WindowsSandboxPlanError::OutputOutsideMapping);
    }
    Ok(())
}

fn validate_host_path(field: &str, value: &str) -> Result<(), WindowsSandboxPlanError> {
    validate_absolute_drive_path(field, value)?;
    if value.len() <= 3 {
        return Err(WindowsSandboxPlanError::UnsafePath {
            field: field.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_guest_path(field: &str, value: &str) -> Result<(), WindowsSandboxPlanError> {
    validate_absolute_drive_path(field, value)
}

fn validate_absolute_drive_path(field: &str, value: &str) -> Result<(), WindowsSandboxPlanError> {
    let bytes = value.as_bytes();
    let valid_prefix =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
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
        return Err(WindowsSandboxPlanError::UnsafePath {
            field: field.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn normalize_path(value: &str) -> String {
    value.trim_end_matches('\\').to_ascii_lowercase()
}

fn is_path_below(path: &str, parent: &str) -> bool {
    let path = normalize_path(path);
    let mut prefix = normalize_path(parent);
    prefix.push('\\');
    path.starts_with(&prefix)
}

pub(crate) fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn escape_xml(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_plan() -> WindowsSandboxPlan {
        WindowsSandboxPlan {
            schema_version: WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.to_owned(),
            workspace_root: "C:\\AIW Host".to_owned(),
            mappings: vec![
                MappedFolder {
                    purpose: MappingPurpose::Tools,
                    host_folder: "C:\\AIW Host\\Tools".to_owned(),
                    sandbox_folder: "C:\\AIW\\Tools".to_owned(),
                },
                MappedFolder {
                    purpose: MappingPurpose::Output,
                    host_folder: "C:\\AIW Host\\Output".to_owned(),
                    sandbox_folder: "C:\\AIW\\Output".to_owned(),
                },
            ],
            probe: GoldenProbe {
                executable: "C:\\AIW\\Tools\\aiw-golden-probe.exe".to_owned(),
                request: None,
                output: "C:\\AIW\\Output\\token.json".to_owned(),
            },
            memory_mb: Some(4096),
        }
    }

    #[test]
    fn renders_hardened_config_and_hash() {
        let rendered = render_config(&valid_plan()).expect("plan should render");
        let expected = [
            "<Configuration>",
            "  <vGPU>Disable</vGPU>",
            "  <Networking>Disable</Networking>",
            "  <AudioInput>Disable</AudioInput>",
            "  <VideoInput>Disable</VideoInput>",
            "  <ProtectedClient>Enable</ProtectedClient>",
            "  <PrinterRedirection>Disable</PrinterRedirection>",
            "  <ClipboardRedirection>Disable</ClipboardRedirection>",
            "  <MemoryInMB>4096</MemoryInMB>",
            "  <MappedFolders>",
            "    <MappedFolder>",
            "      <HostFolder>C:\\AIW Host\\Tools</HostFolder>",
            "      <SandboxFolder>C:\\AIW\\Tools</SandboxFolder>",
            "      <ReadOnly>true</ReadOnly>",
            "    </MappedFolder>",
            "    <MappedFolder>",
            "      <HostFolder>C:\\AIW Host\\Output</HostFolder>",
            "      <SandboxFolder>C:\\AIW\\Output</SandboxFolder>",
            "      <ReadOnly>false</ReadOnly>",
            "    </MappedFolder>",
            "  </MappedFolders>",
            "  <LogonCommand>",
            "    <Command>C:\\AIW\\Tools\\aiw-golden-probe.exe --output C:\\AIW\\Output\\token.json</Command>",
            "  </LogonCommand>",
            "</Configuration>",
            "",
        ]
        .join("\n");
        assert_eq!(rendered.xml, expected);
        assert_eq!(rendered.sha256.len(), 64);
    }

    #[test]
    fn plans_cli_lifecycle_without_exec_or_dynamic_share() {
        let lifecycle = plan_cli_lifecycle(
            "C:\\AIW\\SystemTools\\wsb.exe",
            "12345678-1234-ABCD-9876-1234567890AB",
            &valid_plan(),
        )
        .expect("valid lifecycle should render");

        assert_eq!(
            lifecycle.schema_version,
            WINDOWS_SANDBOX_CLI_LIFECYCLE_SCHEMA_VERSION
        );
        assert_eq!(lifecycle.interface, WINDOWS_SANDBOX_CLI_INTERFACE);
        assert_eq!(lifecycle.sandbox_id, "12345678-1234-abcd-9876-1234567890ab");
        assert_eq!(lifecycle.start.arguments[0], "start");
        assert_eq!(lifecycle.list.arguments, ["list", "--raw"]);
        assert_eq!(lifecycle.stop.arguments[0], "stop");
        assert!(!lifecycle.guest_execution.uses_exec_command);
        assert!(!lifecycle.guest_execution.permits_system_context);
        assert!(!lifecycle.output_observation.dynamic_share_required);
        assert!(!lifecycle.output_observation.process_io_available);
        assert!(!lifecycle.output_observation.artifact_is_completion_receipt);
        assert!(
            lifecycle
                .output_observation
                .separate_completion_receipt_required
        );
        assert_eq!(
            lifecycle.output_observation.expected_host_artifact,
            "C:\\AIW Host\\Output\\token.json"
        );
        assert!(
            lifecycle
                .start
                .arguments
                .contains(&lifecycle.rendered_config.xml)
        );
        for invocation in [&lifecycle.start, &lifecycle.list, &lifecycle.stop] {
            assert!(
                !invocation
                    .arguments
                    .iter()
                    .any(|argument| { matches!(argument.as_str(), "exec" | "share" | "System") })
            );
        }
    }

    #[test]
    fn rejects_ambiguous_cli_paths_and_sandbox_ids() {
        assert_eq!(
            plan_cli_lifecycle(
                "wsb.exe",
                "12345678-1234-abcd-9876-1234567890ab",
                &valid_plan()
            ),
            Err(WindowsSandboxPlanError::InvalidCliPath)
        );
        assert_eq!(
            plan_cli_lifecycle(
                "C:\\AIW\\SystemTools\\other.exe",
                "12345678-1234-abcd-9876-1234567890ab",
                &valid_plan()
            ),
            Err(WindowsSandboxPlanError::InvalidCliPath)
        );
        assert_eq!(
            plan_cli_lifecycle(
                "C:\\AIW\\SystemTools\\wsb.exe",
                "{12345678-1234-abcd-9876-1234567890ab}",
                &valid_plan()
            ),
            Err(WindowsSandboxPlanError::InvalidSandboxId)
        );
    }

    #[test]
    fn rejects_traversal_environment_expansion_and_misdirected_probe() {
        let mut plan = valid_plan();
        plan.mappings[0].host_folder = "%USERPROFILE%\\Tools".to_owned();
        assert!(matches!(
            validate_plan(&plan),
            Err(WindowsSandboxPlanError::UnsafePath { .. })
        ));

        let mut plan = valid_plan();
        plan.probe.output = "C:\\AIW\\Tools\\stolen.json".to_owned();
        assert_eq!(
            validate_plan(&plan),
            Err(WindowsSandboxPlanError::OutputOutsideMapping)
        );

        let mut plan = valid_plan();
        plan.workspace_root = "C:\\Other Workspace".to_owned();
        assert_eq!(
            validate_plan(&plan),
            Err(WindowsSandboxPlanError::MappingOutsideWorkspace(
                "C:\\AIW Host\\Tools".to_owned()
            ))
        );
    }

    #[test]
    fn escapes_xml_metacharacters_in_paths() {
        assert_eq!(
            escape_xml("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[cfg(windows)]
    #[test]
    fn host_validation_requires_probe_and_empty_output() {
        let root = std::env::temp_dir().join(format!(
            "aiw-wsb-validation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should follow epoch")
                .as_nanos()
        ));
        let tools = root.join("tools");
        let output = root.join("output");
        fs::create_dir_all(&tools).expect("tools directory should be created");
        fs::create_dir_all(&output).expect("output directory should be created");
        fs::write(tools.join("aiw-golden-probe.exe"), b"test")
            .expect("probe fixture should be created");

        let mut plan = valid_plan();
        plan.workspace_root = root.to_string_lossy().into_owned();
        plan.mappings[0].host_folder = tools.to_string_lossy().into_owned();
        plan.mappings[1].host_folder = output.to_string_lossy().into_owned();
        validate_host_mappings(&plan).expect("ordinary roots and empty output should pass");

        fs::write(output.join("unexpected.txt"), b"untrusted")
            .expect("output fixture should be created");
        assert!(matches!(
            validate_host_mappings(&plan),
            Err(WindowsSandboxPlanError::NonEmptyOutputFolder(_))
        ));

        fs::remove_dir_all(&root).expect("test fixture should be removed");
    }
}

#[cfg(test)]
mod application_token_tests;

mod runtime_observations;
pub use runtime_observations::{
    ApplicationFileEntry, ApplicationFileRoot, ApplicationFilesystemSnapshot,
    DOCUMENT_EXERCISE_PATH, DOCUMENT_EXPECTED_TEXT, DOCUMENT_INITIAL_TEXT, FilesystemCaptureIssue,
    FilesystemCaptureIssueReason, FilesystemDiffKind, FilesystemSnapshotDiff,
    FilesystemSnapshotDiffResult, FunctionalExercise, IMPORTED_MSI_BEHAVIOR_EVENT,
    IMPORTED_MSI_BEHAVIOR_SCHEMA, IMPORTED_MSI_BEHAVIOR_SCHEMA_VERSION,
    ImportedMsiBehaviorEvidence, STANDARD_USER_DOCUMENT_EXERCISE_PATH, diff_filesystem_snapshots,
    verify_imported_msi_behavior,
};

pub use application_token::MAX_APPLICATION_EVIDENCE_BYTES;
