//! Non-executing Windows Sandbox preparation contracts.
//!
//! Preparation binds a fresh protected workspace, a fixed guest agent, the
//! currently trusted provider observation, and a hardened Sandbox plan into a
//! current run plan. It cannot approve a run or acquire, start, connect, stop,
//! or recover a Windows Sandbox provider lease.

use std::path::Path;

use aiw_evidence::canonical_json_bytes;
pub use aiw_orchestrator::WsbPlanningImportReceipt;
#[cfg(windows)]
use aiw_orchestrator::{PendingRunDisposition, RecoveryStatus, RunLayout, WsbPlanningImportStatus};
use aiw_orchestrator::{PlannedAction, RunLifecycleKind, RunPlan, project_revision_hash};
use aiw_probe::{
    BinaryIdentity, CatalogTrustIdentity, ReadinessState, WindowsFileIdentity,
    WindowsPackageIdentity, WindowsSandboxCliProtocol, WindowsSandboxReadiness,
    WorkspaceBindingEvidence,
};
use aiw_provider_wsb::{
    GoldenProbe, MappedFolder, MappingPurpose, WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION,
    WindowsSandboxPlan, validate_plan,
};
use aiw_schema::{Project, validate_project_for_planning};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const WSB_PREPARATION_RECEIPT_SCHEMA_VERSION: &str = "aiw.dev/wsb-preparation-receipt/v0alpha1";
pub const WSB_PLANNING_IMPORT_RESULT_SCHEMA_VERSION: &str =
    "aiw.dev/wsb-planning-import-result/v0alpha1";

const READINESS_SCHEMA: &str = "aiw.dev/windows-sandbox-readiness/v0alpha2";
const PINNED_CLI_VERSION: &str = "0.8.107.0";
const PINNED_CLI_PROTOCOL: &str = "windowsSandboxCli/v0.8.107.0";
const PINNED_LIST_SCHEMA: &str = "WindowsSandboxEnvironments/Id";
const GUEST_AGENT_FILE: &str = "aiw-guest-agent.exe";
const GUEST_TOOLS: &str = r"C:\AIW\Tools";
const GUEST_OUTPUT: &str = r"C:\AIW\Output";
const GUEST_AGENT: &str = r"C:\AIW\Tools\aiw-guest-agent.exe";
const GUEST_REQUEST: &str = r"C:\AIW\Tools\request.json";
const GUEST_TOKEN: &str = r"C:\AIW\Output\token.json";
const WSB_PLAN_FILE: &str = "wsb-plan.json";
const RUN_PLAN_FILE: &str = "plan.json";
const RECEIPT_FILE: &str = "preparation.json";
const TRUST_DELTA_START: &str =
    "starts a separately approved hardened Windows Sandbox golden probe";
const TRUST_DELTA_MAPPINGS: &str =
    "maps fixed guest tools read-only and treats writable output as untrusted";

#[derive(Debug, Clone, Copy, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WsbPreparationStatus {
    PendingApproval,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WsbPlanningImportDisposition {
    Imported,
    AlreadyImported,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbPlanningImportResult {
    pub schema_version: String,
    pub run_id: String,
    pub disposition: WsbPlanningImportDisposition,
    pub receipt: WsbPlanningImportReceipt,
}

impl WsbPlanningImportResult {
    pub fn validate(&self) -> Result<(), WsbPreparationError> {
        if self.schema_version != WSB_PLANNING_IMPORT_RESULT_SCHEMA_VERSION
            || self.run_id != self.receipt.run_id
        {
            return Err(WsbPreparationError::Contract(
                "planning import result is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbPreparationReceipt {
    pub schema_version: String,
    pub run_id: String,
    pub created_at: String,
    pub status: WsbPreparationStatus,
    pub project_id: String,
    pub project_revision_sha256: String,
    pub workspace: WorkspaceBindingEvidence,
    pub workspace_identity_sha256: String,
    pub readiness_schema_version: String,
    pub provider: BinaryIdentity,
    pub provider_package: WindowsPackageIdentity,
    pub provider_catalog: CatalogTrustIdentity,
    pub provider_file_identity: WindowsFileIdentity,
    pub provider_protocol: WindowsSandboxCliProtocol,
    pub guest_agent: BinaryIdentity,
    pub wsb_plan_relative_path: String,
    pub wsb_plan_sha256: String,
    pub run_plan_relative_path: String,
    pub run_plan_sha256: String,
    pub approval_required: bool,
    pub provider_acquired: bool,
    pub provider_mutated: bool,
}

impl WsbPreparationReceipt {
    pub fn validate(&self) -> Result<(), WsbPreparationError> {
        if self.schema_version != WSB_PREPARATION_RECEIPT_SCHEMA_VERSION
            || self.status != WsbPreparationStatus::PendingApproval
            || self.run_id.is_empty()
            || self.created_at.is_empty()
            || self.project_id.is_empty()
            || self.readiness_schema_version != READINESS_SCHEMA
            || self.wsb_plan_relative_path != WSB_PLAN_FILE
            || self.run_plan_relative_path != RUN_PLAN_FILE
            || !self.approval_required
            || self.provider_acquired
            || self.provider_mutated
        {
            return Err(WsbPreparationError::Contract(
                "preparation receipt state or fixed artifact contract is invalid".to_owned(),
            ));
        }
        for value in [
            &self.project_revision_sha256,
            &self.workspace_identity_sha256,
            &self.provider.sha256,
            &self.provider_catalog.catalog_sha256,
            &self.guest_agent.sha256,
            &self.wsb_plan_sha256,
            &self.run_plan_sha256,
        ] {
            require_hash(value)?;
        }
        self.workspace
            .validate()
            .map_err(|detail| WsbPreparationError::Workspace(detail.to_owned()))?;
        validate_workspace_hierarchy(&self.workspace)?;
        validate_guest_agent(&self.workspace, &self.guest_agent)?;
        let workspace_leaf = provider_path(&self.workspace.root.final_path)
            .trim_end_matches(['\\', '/'])
            .replace('/', "\\")
            .rsplit('\\')
            .next()
            .unwrap_or_default()
            .to_owned();
        if workspace_leaf != self.run_id {
            return Err(WsbPreparationError::Contract(
                "receipt run ID does not match the exact workspace leaf".to_owned(),
            ));
        }
        if canonical_hash(&self.workspace)? != self.workspace_identity_sha256
            || self.provider.signature_status != ReadinessState::Available
            || self.provider.version.as_deref() != Some(PINNED_CLI_VERSION)
            || self.provider_package.architecture != "x64"
            || self.provider_package.signature_kind != "store"
            || !self.provider_package.status_ok
            || self.provider_catalog.verification_status != ReadinessState::Available
            || normalized_windows_path(&self.provider.canonical_path)
                != normalized_windows_path(&self.provider_file_identity.final_path)
        {
            return Err(WsbPreparationError::Contract(
                "receipt identity bindings are inconsistent".to_owned(),
            ));
        }
        require_pinned_protocol(&self.provider_protocol)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PreparedWsbArtifacts {
    pub run_plan: RunPlan,
    pub wsb_plan: WindowsSandboxPlan,
    pub receipt: WsbPreparationReceipt,
}

impl PreparedWsbArtifacts {
    pub fn validate(&self) -> Result<(), WsbPreparationError> {
        self.receipt.validate()?;
        validate_fixed_wsb_plan(&self.wsb_plan, &self.receipt.workspace)?;
        if self.run_plan.run_id != self.receipt.run_id
            || self.run_plan.project_id != self.receipt.project_id
            || self.run_plan.project_revision_hash != self.receipt.project_revision_sha256
            || self.run_plan.lifecycle != RunLifecycleKind::Assessment
            || self.run_plan.created_at != self.receipt.created_at
            || self.run_plan.trust_deltas
                != [
                    TRUST_DELTA_START.to_owned(),
                    TRUST_DELTA_MAPPINGS.to_owned(),
                ]
            || self
                .run_plan
                .hash()
                .map_err(|error| WsbPreparationError::Contract(error.to_string()))?
                != self.receipt.run_plan_sha256
            || canonical_hash(&self.wsb_plan)? != self.receipt.wsb_plan_sha256
        {
            return Err(WsbPreparationError::Contract(
                "published plans do not match the preparation receipt".to_owned(),
            ));
        }
        let matching_action = match self.run_plan.actions.as_slice() {
            [
                PlannedAction::AssessHost,
                PlannedAction::PrepareWorkspace,
                PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                    sandbox_plan_sha256,
                    provider_sha256,
                    guest_agent_sha256,
                    workspace,
                    workspace_identity_sha256,
                },
                PlannedAction::CollectEvidence,
            ] => {
                sandbox_plan_sha256 == &self.receipt.wsb_plan_sha256
                    && provider_sha256 == &self.receipt.provider.sha256
                    && guest_agent_sha256 == &self.receipt.guest_agent.sha256
                    && workspace.as_ref() == &self.receipt.workspace
                    && workspace_identity_sha256 == &self.receipt.workspace_identity_sha256
            }
            _ => false,
        };
        if !matching_action {
            return Err(WsbPreparationError::Contract(
                "run plan does not contain the receipt-bound Windows Sandbox action".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum WsbPreparationError {
    #[error("project is not valid for planning: {0}")]
    Project(String),
    #[error("Windows Sandbox readiness is not sufficient for preparation: {0}")]
    Readiness(String),
    #[error("workspace binding is invalid: {0}")]
    Workspace(String),
    #[error("guest-agent identity is invalid: {0}")]
    GuestAgent(String),
    #[error("preparation contract is invalid: {0}")]
    Contract(String),
    #[error("preparation bundle could not be published: {0}")]
    Persistence(String),
    #[error("new workspace was preserved at {workspace_path}: {detail}")]
    WorkspacePreserved {
        workspace_path: String,
        detail: String,
    },
}

pub fn build_wsb_preparation(
    run_id: &str,
    project: &Project,
    readiness: &WindowsSandboxReadiness,
    workspace: &WorkspaceBindingEvidence,
    guest_agent: &BinaryIdentity,
    created_at: &str,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    validate_request_contract(run_id, project, created_at)?;
    let trusted = require_readiness(readiness)?;
    let provider = trusted.provider.clone();
    workspace
        .validate()
        .map_err(|detail| WsbPreparationError::Workspace(detail.to_owned()))?;
    validate_workspace_hierarchy(workspace)?;
    validate_guest_agent(workspace, guest_agent)?;

    let workspace_identity_sha256 = canonical_hash(workspace)?;
    let wsb_plan = WindowsSandboxPlan {
        schema_version: WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.to_owned(),
        workspace_root: provider_path(&workspace.root.final_path),
        mappings: vec![
            MappedFolder {
                purpose: MappingPurpose::Tools,
                host_folder: provider_path(&workspace.tools.final_path),
                sandbox_folder: GUEST_TOOLS.to_owned(),
            },
            MappedFolder {
                purpose: MappingPurpose::Output,
                host_folder: provider_path(&workspace.output.final_path),
                sandbox_folder: GUEST_OUTPUT.to_owned(),
            },
        ],
        probe: GoldenProbe {
            executable: GUEST_AGENT.to_owned(),
            request: Some(GUEST_REQUEST.to_owned()),
            output: GUEST_TOKEN.to_owned(),
        },
        memory_mb: Some(2048),
    };
    validate_plan(&wsb_plan).map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    let wsb_plan_sha256 = canonical_hash(&wsb_plan)?;
    let project_revision_sha256 = project_revision_hash(project)
        .map_err(|error| WsbPreparationError::Project(error.to_string()))?;
    let run_plan = RunPlan::new(
        run_id,
        &project.metadata.name,
        &project_revision_sha256,
        RunLifecycleKind::Assessment,
        created_at,
        vec![
            PlannedAction::AssessHost,
            PlannedAction::PrepareWorkspace,
            PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                sandbox_plan_sha256: wsb_plan_sha256.clone(),
                provider_sha256: provider.sha256.clone(),
                guest_agent_sha256: guest_agent.sha256.clone(),
                workspace: Box::new(workspace.clone()),
                workspace_identity_sha256: workspace_identity_sha256.clone(),
            },
            PlannedAction::CollectEvidence,
        ],
        vec![
            TRUST_DELTA_START.to_owned(),
            TRUST_DELTA_MAPPINGS.to_owned(),
        ],
    )
    .map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    let run_plan_sha256 = run_plan
        .hash()
        .map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    let provider_protocol = readiness
        .cli_protocol
        .clone()
        .ok_or_else(|| WsbPreparationError::Readiness("CLI protocol is absent".to_owned()))?;
    let receipt = WsbPreparationReceipt {
        schema_version: WSB_PREPARATION_RECEIPT_SCHEMA_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        created_at: created_at.to_owned(),
        status: WsbPreparationStatus::PendingApproval,
        project_id: project.metadata.name.clone(),
        project_revision_sha256,
        workspace: workspace.clone(),
        workspace_identity_sha256,
        readiness_schema_version: readiness.schema_version.clone(),
        provider,
        provider_package: trusted.package.clone(),
        provider_catalog: trusted.catalog.clone(),
        provider_file_identity: trusted.file_identity.clone(),
        provider_protocol,
        guest_agent: guest_agent.clone(),
        wsb_plan_relative_path: WSB_PLAN_FILE.to_owned(),
        wsb_plan_sha256,
        run_plan_relative_path: RUN_PLAN_FILE.to_owned(),
        run_plan_sha256,
        approval_required: true,
        provider_acquired: false,
        provider_mutated: false,
    };
    let artifacts = PreparedWsbArtifacts {
        run_plan,
        wsb_plan,
        receipt,
    };
    artifacts.validate()?;
    Ok(artifacts)
}

fn validate_request_contract(
    run_id: &str,
    project: &Project,
    created_at: &str,
) -> Result<(), WsbPreparationError> {
    let project_issues = validate_project_for_planning(project);
    if !project_issues.is_empty() {
        return Err(WsbPreparationError::Project(format!(
            "{} validation issue(s)",
            project_issues.len()
        )));
    }
    if run_id.is_empty()
        || run_id.len() > 128
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || created_at.is_empty()
        || created_at.len() > 4096
    {
        return Err(WsbPreparationError::Contract(
            "run ID or creation time is outside its fixed bound".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) struct TrustedReadiness<'a> {
    pub(crate) provider: &'a BinaryIdentity,
    pub(crate) package: &'a WindowsPackageIdentity,
    pub(crate) catalog: &'a CatalogTrustIdentity,
    pub(crate) file_identity: &'a WindowsFileIdentity,
}

pub(crate) fn require_readiness(
    readiness: &WindowsSandboxReadiness,
) -> Result<TrustedReadiness<'_>, WsbPreparationError> {
    if readiness.schema_version != READINESS_SCHEMA
        || !readiness.supported
        || readiness.current_sessions != ReadinessState::Available
        || !readiness.current_session_ids.is_empty()
        || !readiness.blockers.is_empty()
    {
        return Err(WsbPreparationError::Readiness(
            "provider is unsupported, blocked, or has current sessions".to_owned(),
        ));
    }
    let provider = readiness.provider_binary.as_ref().ok_or_else(|| {
        WsbPreparationError::Readiness("trusted provider identity is absent".to_owned())
    })?;
    if provider.signature_status != ReadinessState::Available
        || provider.version.as_deref() != Some(PINNED_CLI_VERSION)
        || provider.size_bytes == 0
        || !provider
            .canonical_path
            .to_ascii_lowercase()
            .ends_with("\\wsb.exe")
    {
        return Err(WsbPreparationError::Readiness(
            "provider binary identity is not trusted and pinned".to_owned(),
        ));
    }
    require_hash(&provider.sha256)?;
    let protocol = readiness
        .cli_protocol
        .as_ref()
        .ok_or_else(|| WsbPreparationError::Readiness("CLI protocol is absent".to_owned()))?;
    require_pinned_protocol(protocol)?;
    let package = readiness.provider_package.as_ref().ok_or_else(|| {
        WsbPreparationError::Readiness("trusted Store package identity is absent".to_owned())
    })?;
    let catalog = readiness.catalog_trust.as_ref().ok_or_else(|| {
        WsbPreparationError::Readiness("trusted catalog identity is absent".to_owned())
    })?;
    let file_identity = readiness.provider_file_identity.as_ref().ok_or_else(|| {
        WsbPreparationError::Readiness("held provider file identity is absent".to_owned())
    })?;
    if package.architecture != "x64"
        || package.signature_kind != "store"
        || !package.status_ok
        || catalog.verification_status != ReadinessState::Available
        || normalized_windows_path(&provider.canonical_path)
            != normalized_windows_path(&file_identity.final_path)
    {
        return Err(WsbPreparationError::Readiness(
            "Store package, catalog, or held provider identity is not trusted".to_owned(),
        ));
    }
    Ok(TrustedReadiness {
        provider,
        package,
        catalog,
        file_identity,
    })
}

#[cfg(windows)]
pub(crate) fn require_current_readiness_matches_receipt(
    receipt: &WsbPreparationReceipt,
) -> Result<(), WsbPreparationError> {
    let readiness = aiw_windows_platform::assess_windows_sandbox();
    let trusted = require_readiness(&readiness)?;
    if trusted.provider != &receipt.provider
        || trusted.package != &receipt.provider_package
        || trusted.catalog != &receipt.provider_catalog
        || trusted.file_identity != &receipt.provider_file_identity
        || readiness.cli_protocol.as_ref() != Some(&receipt.provider_protocol)
    {
        return Err(WsbPreparationError::Readiness(
            "provider identity or protocol drifted since preparation".to_owned(),
        ));
    }
    Ok(())
}

fn require_pinned_protocol(
    protocol: &WindowsSandboxCliProtocol,
) -> Result<(), WsbPreparationError> {
    if protocol.cli_version != PINNED_CLI_VERSION
        || protocol.protocol != PINNED_CLI_PROTOCOL
        || protocol.list_schema != PINNED_LIST_SCHEMA
    {
        return Err(WsbPreparationError::Readiness(
            "Windows Sandbox CLI protocol does not match the pinned contract".to_owned(),
        ));
    }
    Ok(())
}

fn validate_workspace_hierarchy(
    workspace: &WorkspaceBindingEvidence,
) -> Result<(), WsbPreparationError> {
    let parent = normalized_windows_path(&workspace.parent.final_path);
    let root = normalized_windows_path(&workspace.root.final_path);
    let tools = normalized_windows_path(&workspace.tools.final_path);
    let output = normalized_windows_path(&workspace.output.final_path);
    if parent.is_empty()
        || root.rsplit_once('\\').map(|value| value.0) != Some(parent.as_str())
        || tools != format!("{root}\\tools")
        || output != format!("{root}\\output")
        || workspace.parent.volume_serial_number != workspace.root.volume_serial_number
        || workspace.root.volume_serial_number != workspace.tools.volume_serial_number
        || workspace.root.volume_serial_number != workspace.output.volume_serial_number
    {
        return Err(WsbPreparationError::Workspace(
            "workspace paths or volumes do not form the fixed parent/root/tools/output hierarchy"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_guest_agent(
    workspace: &WorkspaceBindingEvidence,
    guest_agent: &BinaryIdentity,
) -> Result<(), WsbPreparationError> {
    require_hash(&guest_agent.sha256)?;
    let expected = format!(
        "{}\\{}",
        normalized_windows_path(&workspace.tools.final_path),
        GUEST_AGENT_FILE
    );
    if guest_agent.size_bytes == 0
        || guest_agent.version.is_some()
        || guest_agent.signature_status != ReadinessState::Unknown
        || normalized_windows_path(&guest_agent.canonical_path) != expected
    {
        return Err(WsbPreparationError::GuestAgent(
            "staged identity is not the fixed non-empty tools/aiw-guest-agent.exe".to_owned(),
        ));
    }
    Ok(())
}

fn validate_fixed_wsb_plan(
    plan: &WindowsSandboxPlan,
    workspace: &WorkspaceBindingEvidence,
) -> Result<(), WsbPreparationError> {
    validate_plan(plan).map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    let fixed = plan.memory_mb == Some(2048)
        && plan.workspace_root == provider_path(&workspace.root.final_path)
        && plan.probe.executable == GUEST_AGENT
        && plan.probe.request.as_deref() == Some(GUEST_REQUEST)
        && plan.probe.output == GUEST_TOKEN
        && matches!(
            plan.mappings.as_slice(),
            [
                MappedFolder {
                    purpose: MappingPurpose::Tools,
                    host_folder: tools_host,
                    sandbox_folder: tools_guest,
                },
                MappedFolder {
                    purpose: MappingPurpose::Output,
                    host_folder: output_host,
                    sandbox_folder: output_guest,
                },
            ] if tools_host == &provider_path(&workspace.tools.final_path)
                && tools_guest == GUEST_TOOLS
                && output_host == &provider_path(&workspace.output.final_path)
                && output_guest == GUEST_OUTPUT
        );
    if !fixed {
        return Err(WsbPreparationError::Contract(
            "Windows Sandbox plan differs from the fixed preparation profile".to_owned(),
        ));
    }
    Ok(())
}

fn require_hash(value: &str) -> Result<(), WsbPreparationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(WsbPreparationError::Contract(
            "identity hash is not lowercase SHA-256".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_hash(value: &impl Serialize) -> Result<String, WsbPreparationError> {
    let value = serde_json::to_value(value)
        .map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn provider_path(value: &str) -> String {
    value.strip_prefix(r"\\?\").unwrap_or(value).to_owned()
}

fn normalized_windows_path(value: &str) -> String {
    provider_path(value)
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_ascii_lowercase()
}

#[cfg(windows)]
pub fn prepare_windows_sandbox_bundle(
    run_id: &str,
    project: &Project,
    guest_agent_source: &Path,
    expected_guest_agent_sha256: &str,
    workspace_parent: &Path,
    workspace_leaf: &str,
    created_at: &str,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    use aiw_windows_platform::{HeldRunWorkspace, WorkspaceError, assess_windows_sandbox};

    validate_request_contract(run_id, project, created_at)?;
    if workspace_leaf != run_id {
        return Err(WsbPreparationError::Contract(
            "workspace leaf must exactly match the run ID".to_owned(),
        ));
    }
    let mut held_guest_agent =
        open_guest_agent_source(guest_agent_source, expected_guest_agent_sha256)?;
    let readiness = assess_windows_sandbox();
    require_readiness(&readiness)?;

    let workspace = match HeldRunWorkspace::create(workspace_parent, workspace_leaf) {
        Ok(value) => value,
        Err(WorkspaceError::PartialWorkspace { path, detail }) => {
            return Err(WsbPreparationError::WorkspacePreserved {
                workspace_path: path,
                detail,
            });
        }
        Err(error) => return Err(WsbPreparationError::Workspace(error.to_string())),
    };
    let workspace_path = workspace.root_path().to_string_lossy().into_owned();
    let result: Result<PreparedWsbArtifacts, WsbPreparationError> = (|| {
        workspace
            .revalidate()
            .map_err(|error| WsbPreparationError::Workspace(error.to_string()))?;
        ensure_empty_directory(&workspace.output_path())?;
        require_tools_allowlist(&workspace.tools_path())?;
        let (_held_agent, guest_agent) = stage_guest_agent(&mut held_guest_agent, &workspace)?;
        require_tools_allowlist(&workspace.tools_path())?;
        let artifacts = build_wsb_preparation(
            run_id,
            project,
            &readiness,
            workspace.evidence(),
            &guest_agent,
            created_at,
        )?;
        workspace
            .revalidate()
            .map_err(|error| WsbPreparationError::Workspace(error.to_string()))?;
        ensure_empty_directory(&workspace.output_path())?;
        let staged = stage_bundle(&workspace, &artifacts)?;
        workspace
            .revalidate()
            .map_err(|error| WsbPreparationError::Workspace(error.to_string()))?;
        ensure_empty_directory(&workspace.output_path())?;
        require_tools_allowlist(&workspace.tools_path())?;
        require_workspace_allowlist(workspace.root_path(), PreparationWorkspaceState::Building)?;
        complete_bundle(&workspace, &artifacts, staged)?;
        Ok(artifacts)
    })();
    result.map_err(|error| WsbPreparationError::WorkspacePreserved {
        workspace_path,
        detail: error.to_string(),
    })
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum PreparationWorkspaceState {
    Building,
    Prepared,
    Imported,
    Revoking,
}

#[cfg(windows)]
pub(crate) struct HeldVerifiedWsbPreparation {
    pub(crate) artifacts: PreparedWsbArtifacts,
    receipt_file: std::fs::File,
    run_plan_file: std::fs::File,
    wsb_plan_file: std::fs::File,
    _held_agent: HeldGuestAgentSource,
    workspace: aiw_windows_platform::HeldRunWorkspace,
}

#[cfg(windows)]
impl HeldVerifiedWsbPreparation {
    pub(crate) fn workspace(&self) -> &aiw_windows_platform::HeldRunWorkspace {
        &self.workspace
    }

    fn revalidate(&mut self, state: PreparationWorkspaceState) -> Result<(), WsbPreparationError> {
        self.workspace
            .revalidate()
            .map_err(|error| WsbPreparationError::Workspace(error.to_string()))?;
        ensure_empty_directory(&self.workspace.output_path())?;
        require_tools_allowlist(&self.workspace.tools_path())?;
        require_workspace_allowlist(self.workspace.root_path(), state)?;
        let receipt: WsbPreparationReceipt = read_json_bounded(&mut self.receipt_file)?;
        let run_plan: RunPlan = read_json_bounded(&mut self.run_plan_file)?;
        let wsb_plan: WindowsSandboxPlan = read_json_bounded(&mut self.wsb_plan_file)?;
        if receipt != self.artifacts.receipt
            || run_plan != self.artifacts.run_plan
            || wsb_plan != self.artifacts.wsb_plan
        {
            return Err(WsbPreparationError::Persistence(
                "held preparation artifacts changed during verification".to_owned(),
            ));
        }
        if matches!(
            state,
            PreparationWorkspaceState::Imported | PreparationWorkspaceState::Revoking
        ) {
            require_importable_runs_allowlist(
                self.workspace.root_path(),
                &self.artifacts.receipt.run_id,
                &self.artifacts.receipt.run_plan_sha256,
            )?;
        }
        self.artifacts.validate()
    }

    pub(crate) fn revalidate_imported(&mut self) -> Result<(), WsbPreparationError> {
        self.revalidate(PreparationWorkspaceState::Imported)
    }

    pub(crate) fn revalidate_revoking(&mut self) -> Result<(), WsbPreparationError> {
        self.revalidate(PreparationWorkspaceState::Revoking)
    }
}

#[cfg(windows)]
pub(crate) fn open_verified_windows_sandbox_preparation(
    workspace_root: &Path,
    project: &Project,
    expected_guest_agent_sha256: &str,
    allow_imported: bool,
    allow_revoking: bool,
) -> Result<HeldVerifiedWsbPreparation, WsbPreparationError> {
    use aiw_windows_platform::{HeldRunWorkspace, assess_windows_sandbox};

    let mut receipt_file = open_bundle_file(&workspace_root.join(RECEIPT_FILE))?;
    let receipt: WsbPreparationReceipt = read_json_bounded(&mut receipt_file)?;
    receipt.validate()?;
    require_hash(expected_guest_agent_sha256).map_err(|_| {
        WsbPreparationError::GuestAgent(
            "expected guest-agent identity is not lowercase SHA-256".to_owned(),
        )
    })?;
    if receipt.guest_agent.sha256 != expected_guest_agent_sha256 {
        return Err(WsbPreparationError::GuestAgent(
            "receipt guest-agent identity differs from the independently expected hash".to_owned(),
        ));
    }
    if normalized_windows_path(&workspace_root.to_string_lossy())
        != normalized_windows_path(&receipt.workspace.root.final_path)
    {
        return Err(WsbPreparationError::Workspace(
            "supplied workspace does not match the receipt-bound root".to_owned(),
        ));
    }
    validate_request_contract(&receipt.run_id, project, &receipt.created_at)?;
    if project_revision_hash(project)
        .map_err(|error| WsbPreparationError::Project(error.to_string()))?
        != receipt.project_revision_sha256
    {
        return Err(WsbPreparationError::Project(
            "project revision differs from the preparation receipt".to_owned(),
        ));
    }
    if receipt.project_id != project.metadata.name {
        return Err(WsbPreparationError::Project(
            "project identity differs from the preparation receipt".to_owned(),
        ));
    }
    let workspace = HeldRunWorkspace::reopen_bound(&receipt.workspace)
        .map_err(|error| WsbPreparationError::Workspace(error.to_string()))?;
    workspace
        .revalidate()
        .map_err(|error| WsbPreparationError::Workspace(error.to_string()))?;
    ensure_empty_directory(&workspace.output_path())?;
    require_tools_allowlist(&workspace.tools_path())?;
    let state = if workspace.root_path().join("runs").exists() {
        if !allow_imported {
            return Err(WsbPreparationError::Contract(
                "preparation has already entered authoritative run state".to_owned(),
            ));
        }
        if allow_revoking {
            PreparationWorkspaceState::Revoking
        } else {
            PreparationWorkspaceState::Imported
        }
    } else {
        PreparationWorkspaceState::Prepared
    };
    require_workspace_allowlist(workspace.root_path(), state)?;

    let mut run_plan_file = open_bundle_file(&workspace.root_path().join(RUN_PLAN_FILE))?;
    let mut wsb_plan_file = open_bundle_file(&workspace.root_path().join(WSB_PLAN_FILE))?;
    let run_plan: RunPlan = read_json_bounded(&mut run_plan_file)?;
    let wsb_plan: WindowsSandboxPlan = read_json_bounded(&mut wsb_plan_file)?;
    let agent_path = workspace.tools_path().join(GUEST_AGENT_FILE);
    let held_agent = open_guest_agent_source(&agent_path, expected_guest_agent_sha256)?;
    if held_agent.size_bytes != receipt.guest_agent.size_bytes {
        return Err(WsbPreparationError::GuestAgent(
            "staged guest-agent size differs from the preparation receipt".to_owned(),
        ));
    }
    let observed = PreparedWsbArtifacts {
        run_plan,
        wsb_plan,
        receipt,
    };
    observed.validate()?;
    if matches!(
        state,
        PreparationWorkspaceState::Imported | PreparationWorkspaceState::Revoking
    ) {
        require_importable_runs_allowlist(
            workspace.root_path(),
            &observed.receipt.run_id,
            &observed.receipt.run_plan_sha256,
        )?;
    }

    let readiness = assess_windows_sandbox();
    let trusted = require_readiness(&readiness)?;
    if trusted.provider != &observed.receipt.provider
        || trusted.package != &observed.receipt.provider_package
        || trusted.catalog != &observed.receipt.provider_catalog
        || trusted.file_identity != &observed.receipt.provider_file_identity
        || readiness.cli_protocol.as_ref() != Some(&observed.receipt.provider_protocol)
    {
        return Err(WsbPreparationError::Readiness(
            "provider identity drifted since preparation".to_owned(),
        ));
    }
    let mut held = HeldVerifiedWsbPreparation {
        artifacts: observed,
        receipt_file,
        run_plan_file,
        wsb_plan_file,
        _held_agent: held_agent,
        workspace,
    };
    held.revalidate(state)?;
    Ok(held)
}

#[cfg(windows)]
pub fn verify_windows_sandbox_preparation(
    workspace_root: &Path,
    project: &Project,
    expected_guest_agent_sha256: &str,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    Ok(open_verified_windows_sandbox_preparation(
        workspace_root,
        project,
        expected_guest_agent_sha256,
        false,
        false,
    )?
    .artifacts)
}

#[cfg(windows)]
pub fn import_windows_sandbox_preparation(
    workspace_root: &Path,
    project: &Project,
    expected_guest_agent_sha256: &str,
    imported_at: &str,
) -> Result<WsbPlanningImportResult, WsbPreparationError> {
    if imported_at.is_empty() {
        return Err(WsbPreparationError::Contract(
            "planning import timestamp must not be empty".to_owned(),
        ));
    }
    let mut held = open_verified_windows_sandbox_preparation(
        workspace_root,
        project,
        expected_guest_agent_sha256,
        true,
        false,
    )?;
    let run_id = held.artifacts.receipt.run_id.clone();
    let receipt = WsbPlanningImportReceipt {
        schema_version: aiw_orchestrator::WSB_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION.to_owned(),
        run_id: run_id.clone(),
        imported_at: imported_at.to_owned(),
        status: WsbPlanningImportStatus::PendingApproval,
        project_revision_sha256: held.artifacts.receipt.project_revision_sha256.clone(),
        workspace_root: held.artifacts.receipt.workspace.root.final_path.clone(),
        workspace_identity_sha256: held.artifacts.receipt.workspace_identity_sha256.clone(),
        preparation_receipt_sha256: canonical_hash(&held.artifacts.receipt)?,
        run_plan_sha256: held.artifacts.receipt.run_plan_sha256.clone(),
        windows_sandbox_plan_sha256: held.artifacts.receipt.wsb_plan_sha256.clone(),
        guest_agent_sha256: held.artifacts.receipt.guest_agent.sha256.clone(),
        provider_sha256: held.artifacts.receipt.provider.sha256.clone(),
        run_root: held.artifacts.receipt.workspace.root.final_path.clone(),
        journal_sequence: 1,
        approval_present: false,
        provider_acquired: false,
        provider_mutated: false,
    };
    receipt
        .validate_for_plan(&held.artifacts.run_plan)
        .map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    let layout = RunLayout::new(held.workspace.root_path(), &run_id)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    let disposition = layout
        .create_or_verify_pending_wsb_import_bound(
            &held.workspace,
            &held.artifacts.run_plan,
            &receipt,
        )
        .map_err(|error| WsbPreparationError::Persistence(format!("{error}: {}", error.detail)))?;
    require_imported_runs_allowlist(held.workspace.root_path(), &run_id)?;
    held.revalidate(PreparationWorkspaceState::Imported)?;
    if layout
        .read_plan()
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?
        != held.artifacts.run_plan
        || !matches!(
            layout
                .status()
                .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?,
            RecoveryStatus::PendingApproval {
                last_sequence: 1,
                ..
            }
        )
        || layout.approval_path().exists()
        || layout.cancellation_path().exists()
        || layout.result_path().exists()
        || layout.run_dir().join("wsb-session-transaction").exists()
    {
        return Err(WsbPreparationError::Contract(
            "imported run is not the pristine pending-approval state".to_owned(),
        ));
    }
    let result = WsbPlanningImportResult {
        schema_version: WSB_PLANNING_IMPORT_RESULT_SCHEMA_VERSION.to_owned(),
        run_id,
        disposition: match disposition {
            PendingRunDisposition::Created => WsbPlanningImportDisposition::Imported,
            PendingRunDisposition::AlreadyPresent => WsbPlanningImportDisposition::AlreadyImported,
        },
        receipt,
    };
    result.validate()?;
    held.revalidate(PreparationWorkspaceState::Imported)?;
    Ok(result)
}

#[cfg(windows)]
fn stage_guest_agent(
    source: &mut HeldGuestAgentSource,
    workspace: &aiw_windows_platform::HeldRunWorkspace,
) -> Result<(std::fs::File, BinaryIdentity), WsbPreparationError> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    const MAX_GUEST_AGENT_BYTES: u64 = 128 * 1024 * 1024;

    let created = workspace
        .create_tools_file_new(GUEST_AGENT_FILE)
        .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
    let destination_canonical = created.final_path().to_owned();
    let mut destination = created.into_file();
    let mut source_digest = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source
            .file
            .read(&mut buffer)
            .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
        if count == 0 {
            break;
        }
        copied = copied.saturating_add(count as u64);
        if copied > MAX_GUEST_AGENT_BYTES {
            return Err(WsbPreparationError::GuestAgent(
                "source exceeded the guest-agent size bound while copying".to_owned(),
            ));
        }
        source_digest.update(&buffer[..count]);
        destination
            .write_all(&buffer[..count])
            .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
    }
    if copied == 0 || copied != source.size_bytes {
        return Err(WsbPreparationError::GuestAgent(
            "source size drifted while staging".to_owned(),
        ));
    }
    destination
        .sync_all()
        .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
    let mut staged_digest = Sha256::new();
    loop {
        let count = destination
            .read(&mut buffer)
            .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
        if count == 0 {
            break;
        }
        staged_digest.update(&buffer[..count]);
    }
    let source_sha256 = hex::encode(source_digest.finalize());
    let staged_sha256 = hex::encode(staged_digest.finalize());
    if source_sha256 != source.sha256 || source_sha256 != staged_sha256 {
        return Err(WsbPreparationError::GuestAgent(
            "staged guest agent differs from the held source bytes".to_owned(),
        ));
    }
    let destination_metadata = destination
        .metadata()
        .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
    if !destination_metadata.is_file()
        || destination_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || destination_metadata.len() != copied
    {
        return Err(WsbPreparationError::GuestAgent(
            "staged guest agent identity is not an ordinary fixed file".to_owned(),
        ));
    }
    Ok((
        destination,
        BinaryIdentity {
            canonical_path: provider_path(&destination_canonical.to_string_lossy()),
            sha256: staged_sha256,
            size_bytes: copied,
            version: None,
            signature_status: ReadinessState::Unknown,
        },
    ))
}

#[cfg(windows)]
struct HeldGuestAgentSource {
    file: std::fs::File,
    size_bytes: u64,
    sha256: String,
}

#[cfg(windows)]
fn open_guest_agent_source(
    source_path: &Path,
    expected_sha256: &str,
) -> Result<HeldGuestAgentSource, WsbPreparationError> {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const MAX_GUEST_AGENT_BYTES: u64 = 128 * 1024 * 1024;
    require_hash(expected_sha256).map_err(|_| {
        WsbPreparationError::GuestAgent(
            "expected guest-agent identity is not lowercase SHA-256".to_owned(),
        )
    })?;
    if !source_path.is_absolute() {
        return Err(WsbPreparationError::GuestAgent(
            "source must be an absolute path".to_owned(),
        ));
    }
    let supplied_metadata = std::fs::symlink_metadata(source_path)
        .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
    if !supplied_metadata.is_file()
        || supplied_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || supplied_metadata.len() == 0
        || supplied_metadata.len() > MAX_GUEST_AGENT_BYTES
    {
        return Err(WsbPreparationError::GuestAgent(
            "source must be a bounded non-empty ordinary non-reparse file".to_owned(),
        ));
    }
    let canonical = source_path
        .canonicalize()
        .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
    if normalized_windows_path(&source_path.to_string_lossy())
        != normalized_windows_path(&canonical.to_string_lossy())
    {
        return Err(WsbPreparationError::GuestAgent(
            "source must be supplied by its canonical path".to_owned(),
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&canonical)
        .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() == 0
        || metadata.len() > MAX_GUEST_AGENT_BYTES
    {
        return Err(WsbPreparationError::GuestAgent(
            "held source is not a bounded non-empty ordinary non-reparse file".to_owned(),
        ));
    }
    let mut digest = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
        if count == 0 {
            break;
        }
        copied = copied.saturating_add(count as u64);
        if copied > MAX_GUEST_AGENT_BYTES {
            return Err(WsbPreparationError::GuestAgent(
                "held source exceeded the guest-agent size bound".to_owned(),
            ));
        }
        digest.update(&buffer[..count]);
    }
    let sha256 = hex::encode(digest.finalize());
    if copied != metadata.len() || sha256 != expected_sha256 {
        return Err(WsbPreparationError::GuestAgent(
            "held source does not match the expected guest-agent identity".to_owned(),
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| WsbPreparationError::GuestAgent(error.to_string()))?;
    Ok(HeldGuestAgentSource {
        file,
        size_bytes: copied,
        sha256,
    })
}

#[cfg(windows)]
fn ensure_empty_directory(path: &Path) -> Result<(), WsbPreparationError> {
    let mut entries = std::fs::read_dir(path)
        .map_err(|error| WsbPreparationError::Workspace(error.to_string()))?;
    if entries.next().is_some() {
        return Err(WsbPreparationError::Workspace(
            "workspace output directory is not empty".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn require_tools_allowlist(path: &Path) -> Result<(), WsbPreparationError> {
    let mut observed = std::fs::read_dir(path)
        .map_err(|error| WsbPreparationError::Workspace(error.to_string()))?
        .map(|entry| {
            entry
                .map_err(|error| WsbPreparationError::Workspace(error.to_string()))?
                .file_name()
                .into_string()
                .map_err(|_| {
                    WsbPreparationError::Workspace("tools entry name is not Unicode".to_owned())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    observed.sort();
    if !observed.is_empty() && observed.as_slice() != [GUEST_AGENT_FILE] {
        return Err(WsbPreparationError::Workspace(
            "tools directory contains entries outside the fixed preparation allowlist".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
struct StagedPreparationFiles {
    run_plan: std::fs::File,
    wsb_plan: std::fs::File,
}

#[cfg(windows)]
fn stage_bundle(
    workspace: &aiw_windows_platform::HeldRunWorkspace,
    artifacts: &PreparedWsbArtifacts,
) -> Result<StagedPreparationFiles, WsbPreparationError> {
    let mut run_plan = write_json_new(
        workspace.create_root_file_new(RUN_PLAN_FILE),
        &artifacts.run_plan,
    )?;
    let mut wsb_plan = write_json_new(
        workspace.create_root_file_new(WSB_PLAN_FILE),
        &artifacts.wsb_plan,
    )?;
    let observed_run_plan: RunPlan = read_json_bounded(&mut run_plan)?;
    let observed_wsb_plan: WindowsSandboxPlan = read_json_bounded(&mut wsb_plan)?;
    if observed_run_plan != artifacts.run_plan || observed_wsb_plan != artifacts.wsb_plan {
        return Err(WsbPreparationError::Persistence(
            "held preparation plans differ from their intended contents".to_owned(),
        ));
    }
    Ok(StagedPreparationFiles { run_plan, wsb_plan })
}

#[cfg(windows)]
fn complete_bundle(
    workspace: &aiw_windows_platform::HeldRunWorkspace,
    artifacts: &PreparedWsbArtifacts,
    staged: StagedPreparationFiles,
) -> Result<(), WsbPreparationError> {
    require_workspace_allowlist(workspace.root_path(), PreparationWorkspaceState::Building)?;
    let _held_plans = staged;
    // This create-new, synced receipt is the final fallible publication step.
    // Any earlier error leaves no completeness marker; an interrupted final
    // write leaves an invalid receipt rather than a successful preparation.
    let _held_receipt = write_json_new(
        workspace.create_root_file_new(RECEIPT_FILE),
        &artifacts.receipt,
    )?;
    Ok(())
}

#[cfg(windows)]
fn read_json_bounded<T: for<'de> Deserialize<'de>>(
    file: &mut std::fs::File,
) -> Result<T, WsbPreparationError> {
    use std::io::{Read, Seek, SeekFrom};
    const MAX_BUNDLE_ARTIFACT: u64 = 1024 * 1024;
    let metadata = file
        .metadata()
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    if !metadata.is_file() || metadata.len() > MAX_BUNDLE_ARTIFACT {
        return Err(WsbPreparationError::Persistence(
            "held bundle artifact is non-ordinary or oversized".to_owned(),
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    let mut bytes = Vec::with_capacity((metadata.len() + 1) as usize);
    file.take(MAX_BUNDLE_ARTIFACT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    if bytes.len() as u64 > MAX_BUNDLE_ARTIFACT {
        return Err(WsbPreparationError::Persistence(
            "held bundle artifact exceeded its size bound".to_owned(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))
}

#[cfg(windows)]
fn open_bundle_file(path: &Path) -> Result<std::fs::File, WsbPreparationError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    let file = OpenOptions::new()
        .read(true)
        .share_mode(0x0000_0001)
        .custom_flags(0x0020_0000)
        .open(path)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    if !metadata.is_file() || metadata.file_attributes() & 0x0400 != 0 {
        return Err(WsbPreparationError::Persistence(
            "preparation artifact is not an ordinary non-reparse file".to_owned(),
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn write_json_new(
    created: Result<
        aiw_windows_platform::CreatedWorkspaceFile,
        aiw_windows_platform::WorkspaceError,
    >,
    value: &impl Serialize,
) -> Result<std::fs::File, WsbPreparationError> {
    use std::io::Write;
    use std::os::windows::fs::MetadataExt;

    const MAX_BUNDLE_ARTIFACT: usize = 1024 * 1024;
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_BUNDLE_ARTIFACT {
        return Err(WsbPreparationError::Persistence(
            "bundle artifact exceeds its size bound".to_owned(),
        ));
    }
    let mut file = created
        .map(aiw_windows_platform::CreatedWorkspaceFile::into_file)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    if !metadata.is_file() || metadata.file_attributes() & 0x0400 != 0 {
        return Err(WsbPreparationError::Persistence(
            "created bundle artifact is not an ordinary file".to_owned(),
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn require_workspace_allowlist(
    root: &Path,
    state: PreparationWorkspaceState,
) -> Result<(), WsbPreparationError> {
    let mut expected = vec!["output", "plan.json", "tools", "wsb-plan.json"];
    if matches!(
        state,
        PreparationWorkspaceState::Prepared
            | PreparationWorkspaceState::Imported
            | PreparationWorkspaceState::Revoking
    ) {
        expected.push("preparation.json");
    }
    if matches!(
        state,
        PreparationWorkspaceState::Imported | PreparationWorkspaceState::Revoking
    ) {
        expected.push("runs");
    }
    expected.sort();
    let mut observed = std::fs::read_dir(root)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?
        .map(|entry| {
            entry
                .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?
                .file_name()
                .into_string()
                .map_err(|_| {
                    WsbPreparationError::Persistence(
                        "workspace entry name is not Unicode".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    observed.sort();
    if observed != expected {
        return Err(WsbPreparationError::Persistence(
            "workspace contains entries outside the fixed preparation allowlist".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn require_imported_runs_allowlist(root: &Path, run_id: &str) -> Result<(), WsbPreparationError> {
    let runs = root.join("runs");
    require_non_reparse_directory(&runs)?;
    let mut entries = std::fs::read_dir(&runs)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?
        .map(|entry| {
            entry
                .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?
                .file_name()
                .into_string()
                .map_err(|_| {
                    WsbPreparationError::Persistence(
                        "run storage entry name is not Unicode".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    let mut expected = vec![".locks".to_owned(), run_id.to_owned()];
    expected.sort();
    if entries != expected {
        return Err(WsbPreparationError::Persistence(
            "run storage contains entries outside the exact imported-run allowlist".to_owned(),
        ));
    }
    require_non_reparse_directory(&runs.join(".locks"))?;
    require_non_reparse_directory(&runs.join(run_id))?;
    require_run_locks_allowlist(&runs, run_id)
}

#[cfg(windows)]
fn require_importable_runs_allowlist(
    root: &Path,
    run_id: &str,
    plan_sha256: &str,
) -> Result<(), WsbPreparationError> {
    let runs = root.join("runs");
    require_non_reparse_directory(&runs)?;
    let mut entries = std::fs::read_dir(&runs)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?
        .map(|entry| {
            entry
                .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?
                .file_name()
                .into_string()
                .map_err(|_| {
                    WsbPreparationError::Persistence(
                        "run storage entry name is not Unicode".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    let stage = format!(".import-{run_id}-{plan_sha256}");
    let mut allowed = [
        vec![".locks".to_owned()],
        vec![".locks".to_owned(), run_id.to_owned()],
        vec![".locks".to_owned(), stage],
    ];
    for expected in &mut allowed {
        expected.sort();
    }
    if !allowed.iter().any(|expected| expected == &entries) {
        return Err(WsbPreparationError::Persistence(
            "run storage is neither pristine, exactly staged, nor exactly imported".to_owned(),
        ));
    }
    require_non_reparse_directory(&runs.join(".locks"))?;
    if let Some(entry) = entries.iter().find(|entry| entry.as_str() != ".locks") {
        require_non_reparse_directory(&runs.join(entry))?;
    }
    require_run_locks_allowlist(&runs, run_id)
}

#[cfg(windows)]
fn require_run_locks_allowlist(runs: &Path, run_id: &str) -> Result<(), WsbPreparationError> {
    let mut locks = std::fs::read_dir(runs.join(".locks"))
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?
        .map(|entry| {
            entry
                .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?
                .file_name()
                .into_string()
                .map_err(|_| {
                    WsbPreparationError::Persistence(
                        "run lock entry name is not Unicode".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    locks.sort();
    if locks != [format!("{run_id}.lock")] {
        return Err(WsbPreparationError::Persistence(
            "run lock storage differs from the exact imported-run allowlist".to_owned(),
        ));
    }
    require_non_reparse_file(&runs.join(".locks").join(format!("{run_id}.lock")))?;
    Ok(())
}

#[cfg(windows)]
fn require_non_reparse_directory(path: &Path) -> Result<(), WsbPreparationError> {
    use std::os::windows::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & 0x0400 != 0
    {
        return Err(WsbPreparationError::Persistence(
            "run storage contains a non-directory or reparse entry".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn require_non_reparse_file(path: &Path) -> Result<(), WsbPreparationError> {
    use std::os::windows::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| WsbPreparationError::Persistence(error.to_string()))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & 0x0400 != 0
    {
        return Err(WsbPreparationError::Persistence(
            "run lock storage contains a non-file or reparse entry".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiw_probe::{
        WINDOWS_SYSTEM_SID, WINDOWS_WORKSPACE_SCHEMA_VERSION, WINDOWS_WORKSPACE_SECURITY_POLICY,
        WindowsFileIdentity, workspace_policy_hash,
    };

    fn project() -> Project {
        serde_yaml::from_str(include_str!("../../../examples/minimal.aiw.yaml")).unwrap()
    }

    fn identity(path: &str, id: char) -> WindowsFileIdentity {
        WindowsFileIdentity {
            final_path: path.to_owned(),
            volume_serial_number: "1".repeat(16),
            file_id: id.to_string().repeat(32),
        }
    }

    fn workspace() -> WorkspaceBindingEvidence {
        let owner = "S-1-5-21-1";
        WorkspaceBindingEvidence {
            schema_version: WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
            policy: WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
            security_policy_sha256: workspace_policy_hash(owner),
            owner_sid: owner.to_owned(),
            dacl_protected: true,
            allowed_sids: vec![WINDOWS_SYSTEM_SID.to_owned(), owner.to_owned()],
            parent: identity(r"C:\AIW", '1'),
            root: identity(r"C:\AIW\run-one", '2'),
            tools: identity(r"C:\AIW\run-one\tools", '3'),
            output: identity(r"C:\AIW\run-one\output", '4'),
        }
    }

    fn readiness() -> WindowsSandboxReadiness {
        WindowsSandboxReadiness {
            schema_version: READINESS_SCHEMA.to_owned(),
            supported: true,
            os_build: Some(26_100),
            process_architecture: "x86_64".to_owned(),
            virtualization: ReadinessState::Available,
            sandbox_feature: ReadinessState::Available,
            provider_binary: Some(BinaryIdentity {
                canonical_path: r"C:\Program Files\WindowsApps\wsb.exe".to_owned(),
                sha256: "a".repeat(64),
                size_bytes: 100,
                version: Some(PINNED_CLI_VERSION.to_owned()),
                signature_status: ReadinessState::Available,
            }),
            provider_package: Some(WindowsPackageIdentity {
                name: "MicrosoftWindows.WindowsSandbox".to_owned(),
                full_name: "MicrosoftWindows.WindowsSandbox_1.0.0.0_x64".to_owned(),
                family_name: "MicrosoftWindows.WindowsSandbox_8wekyb3d8bbwe".to_owned(),
                publisher: "CN=Microsoft Corporation".to_owned(),
                publisher_id: "8wekyb3d8bbwe".to_owned(),
                version: "1.0.0.0".to_owned(),
                architecture: "x64".to_owned(),
                signature_kind: "store".to_owned(),
                status_ok: true,
                install_location: r"C:\Program Files\WindowsApps".to_owned(),
            }),
            catalog_trust: Some(CatalogTrustIdentity {
                trust_kind: "catalogMember".to_owned(),
                catalog_path: r"C:\Program Files\WindowsApps\AppxMetadata\CodeIntegrity.cat"
                    .to_owned(),
                catalog_sha256: "c".repeat(64),
                catalog_file_identity: WindowsFileIdentity {
                    final_path: r"C:\Program Files\WindowsApps\AppxMetadata\CodeIntegrity.cat"
                        .to_owned(),
                    volume_serial_number: "2".repeat(16),
                    file_id: "5".repeat(32),
                },
                member_tag: "wsb.exe".to_owned(),
                trust_policy: "WinVerifyTrust".to_owned(),
                verification_status: ReadinessState::Available,
            }),
            provider_file_identity: Some(WindowsFileIdentity {
                final_path: r"C:\Program Files\WindowsApps\wsb.exe".to_owned(),
                volume_serial_number: "2".repeat(16),
                file_id: "6".repeat(32),
            }),
            cli_protocol: Some(WindowsSandboxCliProtocol {
                cli_version: PINNED_CLI_VERSION.to_owned(),
                protocol: PINNED_CLI_PROTOCOL.to_owned(),
                list_schema: PINNED_LIST_SCHEMA.to_owned(),
            }),
            app_execution_alias: None,
            current_sessions: ReadinessState::Available,
            current_session_ids: vec![],
            blockers: vec![],
            warnings: vec![],
        }
    }

    fn guest() -> BinaryIdentity {
        BinaryIdentity {
            canonical_path: r"C:\AIW\run-one\tools\aiw-guest-agent.exe".to_owned(),
            sha256: "b".repeat(64),
            size_bytes: 200,
            version: None,
            signature_status: ReadinessState::Unknown,
        }
    }

    #[cfg(windows)]
    struct TempDir(std::path::PathBuf);

    #[cfg(windows)]
    impl TempDir {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};

            static NEXT: AtomicU64 = AtomicU64::new(1);
            let path = std::env::temp_dir().join(format!(
                "aiw-preparation-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    #[cfg(windows)]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn builds_only_the_fixed_pending_approval_contract() {
        let artifacts = build_wsb_preparation(
            "run-one",
            &project(),
            &readiness(),
            &workspace(),
            &guest(),
            "2026-08-29T00:00:00Z",
        )
        .unwrap();
        assert_eq!(
            artifacts.receipt.status,
            WsbPreparationStatus::PendingApproval
        );
        assert!(artifacts.receipt.approval_required);
        assert!(!artifacts.receipt.provider_acquired);
        assert!(!artifacts.receipt.provider_mutated);
        assert_eq!(artifacts.wsb_plan.mappings.len(), 2);
        assert_eq!(
            artifacts.wsb_plan.mappings[0].purpose,
            MappingPurpose::Tools
        );
        assert_eq!(
            artifacts.wsb_plan.mappings[1].purpose,
            MappingPurpose::Output
        );
        assert_eq!(artifacts.wsb_plan.probe.executable, GUEST_AGENT);
        assert_eq!(
            artifacts.wsb_plan.probe.request.as_deref(),
            Some(GUEST_REQUEST)
        );
        assert_eq!(artifacts.wsb_plan.probe.output, GUEST_TOKEN);
        assert!(matches!(
            artifacts.run_plan.actions.as_slice(),
            [
                PlannedAction::AssessHost,
                PlannedAction::PrepareWorkspace,
                PlannedAction::ExecuteWindowsSandboxGoldenProbe { .. },
                PlannedAction::CollectEvidence
            ]
        ));
        assert_eq!(
            artifacts.receipt.run_plan_sha256,
            artifacts.run_plan.hash().unwrap()
        );
        artifacts.receipt.validate().unwrap();
    }

    #[test]
    fn strict_receipt_rejects_unknown_fields_and_mutation_claims() {
        let artifacts = build_wsb_preparation(
            "run-one",
            &project(),
            &readiness(),
            &workspace(),
            &guest(),
            "now",
        )
        .unwrap();
        let mut value = serde_json::to_value(&artifacts.receipt).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WsbPreparationReceipt>(value).is_err());
        let mut receipt = artifacts.receipt;
        receipt.provider_acquired = true;
        assert!(receipt.validate().is_err());

        let mut false_agent = build_wsb_preparation(
            "run-one",
            &project(),
            &readiness(),
            &workspace(),
            &guest(),
            "now",
        )
        .unwrap()
        .receipt;
        false_agent.guest_agent.canonical_path = r"C:\AIW\run-one\tools\other.exe".to_owned();
        assert!(false_agent.validate().is_err());
        let mut false_provenance = build_wsb_preparation(
            "run-one",
            &project(),
            &readiness(),
            &workspace(),
            &guest(),
            "now",
        )
        .unwrap()
        .receipt;
        false_provenance.guest_agent.signature_status = ReadinessState::Available;
        assert!(false_provenance.validate().is_err());
        let mut false_run = build_wsb_preparation(
            "run-one",
            &project(),
            &readiness(),
            &workspace(),
            &guest(),
            "now",
        )
        .unwrap()
        .receipt;
        false_run.run_id = "different-run".to_owned();
        assert!(false_run.validate().is_err());
    }

    #[test]
    fn prepared_artifacts_bind_lifecycle_time_and_fixed_trust_deltas() {
        let artifacts = build_wsb_preparation(
            "run-one",
            &project(),
            &readiness(),
            &workspace(),
            &guest(),
            "now",
        )
        .unwrap();
        let mut lifecycle = artifacts.clone();
        lifecycle.run_plan.lifecycle = RunLifecycleKind::Launch;
        assert!(lifecycle.validate().is_err());
        let mut created_at = artifacts.clone();
        created_at.run_plan.created_at = "later".to_owned();
        assert!(created_at.validate().is_err());
        let mut trust = artifacts;
        trust.run_plan.trust_deltas = vec![TRUST_DELTA_START.to_owned()];
        assert!(trust.validate().is_err());
    }

    #[test]
    fn planning_import_result_is_strict_and_plan_bound() {
        let artifacts = build_wsb_preparation(
            "run-one",
            &project(),
            &readiness(),
            &workspace(),
            &guest(),
            "now",
        )
        .unwrap();
        let receipt = WsbPlanningImportReceipt {
            schema_version: aiw_orchestrator::WSB_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION.to_owned(),
            run_id: artifacts.run_plan.run_id.clone(),
            imported_at: "later".to_owned(),
            status: aiw_orchestrator::WsbPlanningImportStatus::PendingApproval,
            project_revision_sha256: artifacts.run_plan.project_revision_hash.clone(),
            workspace_root: artifacts.receipt.workspace.root.final_path.clone(),
            workspace_identity_sha256: artifacts.receipt.workspace_identity_sha256.clone(),
            preparation_receipt_sha256: canonical_hash(&artifacts.receipt).unwrap(),
            run_plan_sha256: artifacts.receipt.run_plan_sha256.clone(),
            windows_sandbox_plan_sha256: artifacts.receipt.wsb_plan_sha256.clone(),
            guest_agent_sha256: artifacts.receipt.guest_agent.sha256.clone(),
            provider_sha256: artifacts.receipt.provider.sha256.clone(),
            run_root: artifacts.receipt.workspace.root.final_path.clone(),
            journal_sequence: 1,
            approval_present: false,
            provider_acquired: false,
            provider_mutated: false,
        };
        receipt.validate_for_plan(&artifacts.run_plan).unwrap();
        let result = WsbPlanningImportResult {
            schema_version: WSB_PLANNING_IMPORT_RESULT_SCHEMA_VERSION.to_owned(),
            run_id: artifacts.run_plan.run_id.clone(),
            disposition: WsbPlanningImportDisposition::Imported,
            receipt,
        };
        result.validate().unwrap();
        let mut value = serde_json::to_value(result).unwrap();
        value["providerStarted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WsbPlanningImportResult>(value).is_err());
    }

    #[test]
    fn rejects_provider_protocol_sessions_workspace_and_agent_drift() {
        let mut active = readiness();
        active.current_session_ids.push("foreign".to_owned());
        assert!(
            build_wsb_preparation(
                "run-one",
                &project(),
                &active,
                &workspace(),
                &guest(),
                "now"
            )
            .is_err()
        );

        let mut protocol = readiness();
        protocol.cli_protocol.as_mut().unwrap().cli_version = "changed".to_owned();
        assert!(
            build_wsb_preparation(
                "run-one",
                &project(),
                &protocol,
                &workspace(),
                &guest(),
                "now"
            )
            .is_err()
        );

        let mut moved = workspace();
        moved.output.final_path = r"C:\AIW\elsewhere".to_owned();
        assert!(
            build_wsb_preparation("run-one", &project(), &readiness(), &moved, &guest(), "now")
                .is_err()
        );

        let mut changed_agent = guest();
        changed_agent.canonical_path = r"C:\AIW\run-one\tools\other.exe".to_owned();
        assert!(
            build_wsb_preparation(
                "run-one",
                &project(),
                &readiness(),
                &workspace(),
                &changed_agent,
                "now"
            )
            .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn expected_hash_holds_the_exact_guest_agent_source() {
        use std::os::windows::fs::symlink_file;

        let temp = TempDir::new("agent");
        let source = temp.0.join("agent.exe");
        std::fs::write(&source, b"fixed guest agent").unwrap();
        let expected = hex::encode(Sha256::digest(b"fixed guest agent"));
        let held = open_guest_agent_source(&source, &expected).unwrap();
        assert_eq!(held.sha256, expected);
        drop(held);
        assert!(open_guest_agent_source(&source, &"0".repeat(64)).is_err());

        let link = temp.0.join("agent-link.exe");
        if symlink_file(&source, &link).is_ok() {
            assert!(open_guest_agent_source(&link, &expected).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn receipt_is_absent_until_exact_bundle_completion() {
        let artifacts = build_wsb_preparation(
            "run-one",
            &project(),
            &readiness(),
            &workspace(),
            &guest(),
            "now",
        )
        .unwrap();

        let rejected = TempDir::new("bundle-rejected");
        let rejected_workspace =
            aiw_windows_platform::HeldRunWorkspace::create(&rejected.0, "workspace").unwrap();
        let staged = stage_bundle(&rejected_workspace, &artifacts).unwrap();
        std::fs::write(
            rejected_workspace.root_path().join("unexpected.txt"),
            b"unexpected",
        )
        .unwrap();
        assert!(complete_bundle(&rejected_workspace, &artifacts, staged).is_err());
        assert!(!rejected_workspace.root_path().join(RECEIPT_FILE).exists());

        let accepted = TempDir::new("bundle-accepted");
        let accepted_workspace =
            aiw_windows_platform::HeldRunWorkspace::create(&accepted.0, "workspace").unwrap();
        let staged = stage_bundle(&accepted_workspace, &artifacts).unwrap();
        assert!(!accepted_workspace.root_path().join(RECEIPT_FILE).exists());
        complete_bundle(&accepted_workspace, &artifacts, staged).unwrap();
        assert!(accepted_workspace.root_path().join(RECEIPT_FILE).is_file());
        require_workspace_allowlist(
            accepted_workspace.root_path(),
            PreparationWorkspaceState::Prepared,
        )
        .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn tools_allowlist_rejects_every_extra_entry() {
        let temp = TempDir::new("tools-allowlist");
        require_tools_allowlist(&temp.0).unwrap();
        std::fs::write(temp.0.join(GUEST_AGENT_FILE), b"agent").unwrap();
        require_tools_allowlist(&temp.0).unwrap();
        std::fs::write(temp.0.join("side-loaded.dll"), b"extra").unwrap();
        assert!(require_tools_allowlist(&temp.0).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn importable_run_storage_accepts_only_exact_recovery_shapes() {
        let temp = TempDir::new("importable-runs");
        let runs = temp.0.join("runs");
        std::fs::create_dir(&runs).unwrap();
        std::fs::create_dir(runs.join(".locks")).unwrap();
        std::fs::write(runs.join(".locks/run-one.lock"), b"").unwrap();
        require_importable_runs_allowlist(&temp.0, "run-one", &"a".repeat(64)).unwrap();

        let stage = runs.join(format!(".import-run-one-{}", "a".repeat(64)));
        std::fs::create_dir(&stage).unwrap();
        require_importable_runs_allowlist(&temp.0, "run-one", &"a".repeat(64)).unwrap();
        std::fs::write(runs.join("unrelated"), b"preserve").unwrap();
        assert!(require_importable_runs_allowlist(&temp.0, "run-one", &"a".repeat(64)).is_err());
        assert_eq!(std::fs::read(runs.join("unrelated")).unwrap(), b"preserve");
        std::fs::remove_file(runs.join("unrelated")).unwrap();

        std::fs::create_dir(runs.join("run-two")).unwrap();
        assert!(require_importable_runs_allowlist(&temp.0, "run-one", &"a".repeat(64)).is_err());
        std::fs::remove_dir(runs.join("run-two")).unwrap();

        std::fs::write(runs.join(".locks/run-two.lock"), b"").unwrap();
        assert!(require_importable_runs_allowlist(&temp.0, "run-one", &"a".repeat(64)).is_err());
        assert_eq!(
            std::fs::read(runs.join(".locks/run-two.lock")).unwrap(),
            b""
        );
    }
}
