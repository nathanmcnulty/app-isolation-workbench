#![forbid(unsafe_code)]
#![allow(dead_code, unused_imports)] // Test-only execution kernel pending native platform boundary.

//! Narrow execution boundary for W1 Windows Sandbox golden token probes.
//!
//! This module does not expose a process launcher for callers. Its private
//! test kernel accepts a previously approved typed action, validates current
//! identities again, then invokes only preconstructed `wsb list`, `start`,
//! exact-ID `connect`, and exact-ID `stop` argument arrays. It has no shell, elevation, command,
//! script, URL, or arbitrary policy API.

mod assessment_report;
mod report_set;
#[cfg(windows)]
pub use report_set::report_windows_sandbox_msi_set;
pub use report_set::{
    ReportSetFailureEvidence, ReportSetFileChanges, ReportSetFunctions, ReportSetRegistryChanges,
    ReportSetUnavailableReason, WSB_MSI_REPORT_SET_INPUT_SCHEMA, WSB_MSI_REPORT_SET_SCHEMA,
    WsbMsiReportSet, WsbMsiReportSetEntry, WsbMsiReportSetInput, WsbMsiReportSetResult,
    WsbMsiReportSetRow, WsbMsiReportSetSummary,
};
#[cfg(windows)]
mod discard;
mod preparation;
pub use assessment_report::{
    AssessmentEvidenceGap, FailureProgressEvidence, UnverifiedGuestDiagnostic,
    VerifiedMsiFailureProgress, WsbMsiAssessmentReport, WsbMsiRunReport, WsbMsiUnsuccessfulReport,
};
#[cfg(windows)]
pub use assessment_report::{report_windows_sandbox_msi, report_windows_sandbox_msi_run};
mod session;

pub use preparation::{
    PreparedWsbArtifacts, WSB_MSI_PREPARATION_RECEIPT_SCHEMA_VERSION,
    WSB_PLANNING_IMPORT_RESULT_SCHEMA_VERSION, WSB_PREPARATION_RECEIPT_SCHEMA_VERSION,
    WsbMsiApplication, WsbPlanningImportDisposition, WsbPlanningImportReceipt,
    WsbPlanningImportResult, WsbPreparationError, WsbPreparationReceipt, WsbPreparationStatus,
    build_wsb_msi_preparation, build_wsb_preparation,
};

#[cfg(windows)]
pub use preparation::{
    WsbMsiPreparationInput, import_windows_sandbox_preparation, prepare_windows_sandbox_bundle,
    prepare_windows_sandbox_msi_bundle, verify_windows_sandbox_preparation,
};

pub use session::{
    SESSION_TRANSACTION_SCHEMA_VERSION, SessionRecoveryBinding, SessionTransaction,
    SessionTransactionState, SessionTransition,
};

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use aiw_orchestrator::{
    ApprovalRecord, PlannedAction, RunEvent, RunEventKind, RunLayout, RunOutcome, RunPlan,
    RunResult, project_revision_hash,
};
use aiw_probe::{BinaryIdentity, WindowsSandboxReadiness, WorkspaceBindingEvidence};
use aiw_provider_wsb::{
    CompletionArtifactExpectation, MappingPurpose, WindowsSandboxCliLifecyclePlan,
    WindowsSandboxCompletionExpectation, WindowsSandboxPlan, plan_cli_lifecycle, render_config,
    validate_host_mappings, verify_completion_receipt,
};
use aiw_schema::Project;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use session::{SessionBinding, TransactionStore};

const MAX_PROVIDER_OUTPUT: usize = 64 * 1024;
const MAX_PROVIDER_ERROR: usize = 64 * 1024;
const MAX_GUEST_FAILURE_DIAGNOSTIC: u64 = 16 * 1024;
const GUEST_REQUEST_SCHEMA: &str = "aiw.dev/wsb-golden-probe-request/v0alpha1";
const READINESS_SCHEMA: &str = "aiw.dev/windows-sandbox-readiness/v0alpha2";
pub const WSB_SESSION_STATUS_SCHEMA_VERSION: &str = "aiw.dev/wsb-session-status/v0alpha1";
pub const WSB_RECOVERY_RESULT_SCHEMA_VERSION: &str = "aiw.dev/wsb-recovery-result/v0alpha1";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbGoldenProbeStart {
    pub schema_version: String,
    pub run_root: String,
    pub project_path: String,
    pub wsb_plan: WindowsSandboxPlan,
    pub provider: BinaryIdentity,
    pub guest_agent: BinaryIdentity,
    pub workspace: WorkspaceBindingEvidence,
    pub workspace_identity_sha256: String,
    pub timeout_seconds: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msi: Option<WsbMsiApplication>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbGoldenProbeExecution {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub provider_sha256: String,
    pub config_sha256: String,
    pub request_sha256: String,
    pub receipt_sha256: String,
    pub evidence_root_hash: String,
    pub workspace: WorkspaceBindingEvidence,
    pub workspace_identity_sha256: String,
    pub cleanup_complete: bool,
    #[serde(skip)]
    scenario: Option<aiw_provider_wsb::ImportedMsiScenarioResult>,
    #[serde(skip)]
    application_token: Option<aiw_provider_wsb::ImportedMsiApplicationToken>,
    #[serde(skip)]
    behavior: Option<aiw_provider_wsb::ImportedMsiBehaviorEvidence>,
    #[serde(skip)]
    standard_user_context: Option<aiw_provider_wsb::ImportedMsiRuntimeContext>,
    #[serde(skip)]
    registry_evidence: Option<aiw_provider_wsb::ImportedMsiRegistryEvidence>,
}

/// Common receipt-correlated lifecycle result. Application observations remain
/// untrusted evidence and do not establish containment.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbImportedMsiExecution {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub provider_sha256: String,
    pub config_sha256: String,
    pub request_sha256: String,
    pub receipt_sha256: String,
    pub evidence_root_hash: String,
    pub workspace: WorkspaceBindingEvidence,
    pub workspace_identity_sha256: String,
    pub cleanup_complete: bool,
    pub scenario: aiw_provider_wsb::ImportedMsiScenarioResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_token: Option<aiw_provider_wsb::ImportedMsiApplicationToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavior: Option<aiw_provider_wsb::ImportedMsiBehaviorEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard_user_context: Option<aiw_provider_wsb::ImportedMsiRuntimeContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_evidence: Option<aiw_provider_wsb::ImportedMsiRegistryEvidence>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum WsbApprovedExecution {
    GoldenProbe(WsbGoldenProbeExecution),
    ImportedMsi(WsbImportedMsiExecution),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Fixed provider-process boundary used by the native adapter and deterministic tests.
trait ProcessBoundary {
    fn invoke(
        &self,
        executable: &Path,
        arguments: &[String],
        timeout_seconds: u32,
    ) -> Result<ProcessResult, RunnerError>;
}

#[derive(Debug, Error, Clone)]
pub enum RunnerError {
    #[error("approved Windows Sandbox preparation is invalid: {0}")]
    Preparation(String),
    #[error("Windows Sandbox readiness is not sufficient: {0}")]
    Readiness(String),
    #[error("approved W1 plan is missing or does not bind the current inputs")]
    ApprovalBinding,
    #[error("provider invocation failed: {0}")]
    Process(String),
    #[error("provider returned malformed or unexpected JSON")]
    ProviderJson,
    #[error("provider output exceeded its fixed bound")]
    ProviderOutputTooLarge,
    #[error("a pre-existing, unknown, or mismatched Windows Sandbox session was observed")]
    SessionConflict,
    #[error("the Windows Sandbox provider did not complete the requested operation")]
    ProviderFailure,
    #[error("a revalidated path, binary, output root, or rendered configuration drifted")]
    Drift,
    #[error("the run was cancelled before or during provider execution")]
    Cancelled,
    #[error("completion receipt verification failed: {0}")]
    Receipt(String),
    #[error("run journal update failed: {0}")]
    Journal(String),
    #[error("Windows Sandbox provider lease is currently held by another AIW run")]
    LeaseUnavailable,
    #[error("provider session recovery is required: {0}")]
    RecoveryRequired(String),
    #[error("provider session transaction is invalid: {0}")]
    Transaction(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WsbSessionDisposition {
    None,
    Clean,
    RecoveryRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbSessionStatus {
    pub schema_version: String,
    pub run_id: String,
    pub status: WsbSessionDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_state: Option<SessionTransactionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbRecoveryResult {
    pub schema_version: String,
    pub run_id: String,
    pub session_id: String,
    pub state: SessionTransactionState,
    pub provider_cleanup_verified: bool,
    pub workspace_cleanup_verified: bool,
    pub terminalizable: bool,
    pub mutex_was_abandoned: bool,
    pub start_provider_sha256: String,
    pub recovery_provider_sha256: String,
    pub provider_drifted: bool,
    pub session_ids_before: Vec<String>,
    pub session_ids_after: Vec<String>,
    pub reason_code: String,
}

/// Observe persisted Windows Sandbox provider state without creating, deleting,
/// repairing, or otherwise mutating run files.
pub fn observe_wsb_session_status(layout: &RunLayout) -> Result<WsbSessionStatus, RunnerError> {
    let observation = session::observe_transaction(layout)?;
    let Some(transaction) = observation.transaction else {
        return Ok(WsbSessionStatus {
            schema_version: WSB_SESSION_STATUS_SCHEMA_VERSION.to_owned(),
            run_id: layout.run_id().to_owned(),
            status: if observation.directory_present {
                WsbSessionDisposition::RecoveryRequired
            } else {
                WsbSessionDisposition::None
            },
            current_state: None,
            reason_code: observation
                .directory_present
                .then(|| "transaction-directory-empty".to_owned()),
        });
    };
    if transaction.run_id != layout.run_id() {
        return Err(RunnerError::Transaction(
            "session transaction belongs to a different run".to_owned(),
        ));
    }
    let core_status = layout.status().map_err(journal_error)?;
    if matches!(
        core_status,
        aiw_orchestrator::RecoveryStatus::PendingApproval { .. }
            | aiw_orchestrator::RecoveryStatus::RecoveryRequired { .. }
    ) {
        return Err(RunnerError::Transaction(
            "session transaction is not covered by committed approved run state".to_owned(),
        ));
    }
    let plan = layout.read_plan().map_err(journal_error)?;
    let plan_hash = plan.hash().map_err(journal_error)?;
    let provider_bindings: Vec<(&str, &WorkspaceBindingEvidence, &str)> = plan
        .actions
        .iter()
        .filter_map(|action| match action {
            PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                provider_sha256,
                workspace,
                workspace_identity_sha256,
                ..
            }
            | PlannedAction::ExecuteWindowsSandboxImportedMsiScenario {
                provider_sha256,
                workspace,
                workspace_identity_sha256,
                ..
            } => Some((
                provider_sha256.as_str(),
                workspace.as_ref(),
                workspace_identity_sha256.as_str(),
            )),
            _ => None,
        })
        .collect();
    let binding_matches = match provider_bindings.as_slice() {
        [(provider_sha256, workspace, workspace_identity_sha256)] => canonical_hash(workspace)
            .is_ok_and(|computed| {
                computed == *workspace_identity_sha256
                    && *provider_sha256 == transaction.provider_sha256
                    && *workspace_identity_sha256 == transaction.workspace_identity_sha256
            }),
        _ => false,
    };
    if transaction.plan_hash != plan_hash
        || transaction.project_revision_hash != plan.project_revision_hash
        || !binding_matches
    {
        return Err(RunnerError::Transaction(
            "session transaction does not match the persisted approved plan".to_owned(),
        ));
    }
    let transition = transaction
        .transitions
        .last()
        .expect("validated transactions contain a transition");
    let clean = !observation.pending_present
        && transition.state == SessionTransactionState::CleanupVerified
        && transaction.recovery.is_some();
    Ok(WsbSessionStatus {
        schema_version: WSB_SESSION_STATUS_SCHEMA_VERSION.to_owned(),
        run_id: layout.run_id().to_owned(),
        status: if clean {
            WsbSessionDisposition::Clean
        } else {
            WsbSessionDisposition::RecoveryRequired
        },
        current_state: Some(transition.state),
        reason_code: Some(if observation.pending_present {
            "transaction-staging-present".to_owned()
        } else if transaction.recovery.is_none()
            && transition.state == SessionTransactionState::CleanupVerified
        {
            "legacy-request-location-unavailable".to_owned()
        } else {
            transition.reason_code.clone()
        }),
    })
}

trait LeaseGuard {}
impl<T> LeaseGuard for T {}

trait LeaseBoundary {
    fn try_acquire(&self) -> Result<Box<dyn LeaseGuard + '_>, RunnerError>;
}

trait WorkspaceBoundary {
    fn evidence(&self) -> &WorkspaceBindingEvidence;
    fn revalidate(&self) -> Result<(), RunnerError>;
}

#[cfg(windows)]
impl WorkspaceBoundary for aiw_windows_platform::HeldRunWorkspace {
    fn evidence(&self) -> &WorkspaceBindingEvidence {
        self.evidence()
    }

    fn revalidate(&self) -> Result<(), RunnerError> {
        self.revalidate().map_err(|_| RunnerError::Drift)
    }
}

#[cfg(windows)]
struct NativeWsbProcess {
    state: std::sync::Mutex<NativeWsbState>,
    plan: WindowsSandboxPlan,
}

#[cfg(windows)]
struct NativeWsbState {
    lease: aiw_windows_platform::WindowsSandboxExecutionLease,
    started_id: Option<String>,
}

#[cfg(windows)]
impl ProcessBoundary for NativeWsbProcess {
    fn invoke(
        &self,
        executable: &Path,
        arguments: &[String],
        timeout_seconds: u32,
    ) -> Result<ProcessResult, RunnerError> {
        if timeout_seconds == 0 {
            return Err(RunnerError::Process(
                "native provider timeout must be nonzero".to_owned(),
            ));
        }
        let requested_timeout = Duration::from_secs(u64::from(timeout_seconds));
        let read_timeout = requested_timeout.min(Duration::from_secs(15));
        let mutation_timeout = requested_timeout.min(Duration::from_secs(120));
        let mut state = self.state.lock().map_err(|_| {
            RunnerError::Process("native provider adapter lock was poisoned".to_owned())
        })?;
        let expected = state
            .lease
            .readiness()
            .provider_binary
            .as_ref()
            .ok_or_else(|| RunnerError::Process("native provider identity absent".to_owned()))?;
        if !executable
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.canonical_path)
        {
            return Err(RunnerError::Process(
                "runner executable did not match native authority".to_owned(),
            ));
        }
        match arguments {
            [list, raw] if list == "list" && raw == "--raw" => {
                let observed = state
                    .lease
                    .list_with_timeout(read_timeout)
                    .map_err(native_invocation_error)?;
                process_json_result(serde_json::json!({
                    "WindowsSandboxEnvironments": observed.session_ids.into_iter().map(|id| serde_json::json!({"Id": id})).collect::<Vec<_>>()
                }))
            }
            [start, raw, id_flag, id, config_flag, xml]
                if start == "start"
                    && raw == "--raw"
                    && id_flag == "--id"
                    && config_flag == "--config" =>
            {
                let rendered = render_config(&self.plan)
                    .map_err(|error| RunnerError::Process(error.to_string()))?;
                if rendered.xml != *xml {
                    return Err(RunnerError::Process(
                        "runner XML did not match the internally rendered typed plan".to_owned(),
                    ));
                }
                let id = aiw_windows_platform::CanonicalSandboxId::parse(id)
                    .map_err(|error| RunnerError::Process(error.to_string()))?;
                state.started_id = Some(id.as_str().to_owned());
                let observed = state
                    .lease
                    .start_with_timeout(&id, &self.plan, mutation_timeout)
                    .map_err(native_invocation_error)?;
                process_json_result(serde_json::json!({"Id": observed.session_id}))
            }
            [stop, raw, id_flag, id] if stop == "stop" && raw == "--raw" && id_flag == "--id" => {
                let id = aiw_windows_platform::CanonicalSandboxId::parse(id)
                    .map_err(|error| RunnerError::Process(error.to_string()))?;
                if state.started_id.as_deref() != Some(id.as_str()) {
                    return Err(RunnerError::SessionConflict);
                }
                state
                    .lease
                    .stop_owned_with_timeout(mutation_timeout)
                    .map_err(native_invocation_error)?;
                state.started_id = None;
                Ok(ProcessResult {
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                })
            }
            [connect, raw, id_flag, id]
                if connect == "connect" && raw == "--raw" && id_flag == "--id" =>
            {
                let id = aiw_windows_platform::CanonicalSandboxId::parse(id)
                    .map_err(|error| RunnerError::Process(error.to_string()))?;
                if state.started_id.as_deref() != Some(id.as_str()) {
                    return Err(RunnerError::SessionConflict);
                }
                state
                    .lease
                    .connect_owned_with_timeout(mutation_timeout)
                    .map_err(native_invocation_error)?;
                Ok(ProcessResult {
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                })
            }
            _ => Err(RunnerError::Process(
                "native adapter rejected an unexpected provider operation".to_owned(),
            )),
        }
    }
}

#[cfg(windows)]
fn native_invocation_error(
    error: aiw_windows_platform::WindowsSandboxInvocationError,
) -> RunnerError {
    match error {
        aiw_windows_platform::WindowsSandboxInvocationError::LeaseUnavailable => {
            RunnerError::LeaseUnavailable
        }
        aiw_windows_platform::WindowsSandboxInvocationError::RecoveryRequired => {
            RunnerError::RecoveryRequired(
                "the native provider lease was abandoned before this start".to_owned(),
            )
        }
        error => RunnerError::Process(error.to_string()),
    }
}

fn process_json_result(value: serde_json::Value) -> Result<ProcessResult, RunnerError> {
    Ok(ProcessResult {
        exit_code: 0,
        stdout: serde_json::to_vec(&value).map_err(|_| RunnerError::ProviderJson)?,
        stderr: vec![],
    })
}

#[cfg(windows)]
#[derive(Default)]
struct AlreadyHeldProviderLease;

#[cfg(windows)]
impl LeaseBoundary for AlreadyHeldProviderLease {
    fn try_acquire(&self) -> Result<Box<dyn LeaseGuard + '_>, RunnerError> {
        Ok(Box::new(()))
    }
}

/// Execute the one approved W1 provider operation.  A success means lifecycle
/// and receipt correlation succeeded, not that containment has been proven.
pub(crate) fn execute_wsb_golden_probe(
    request: &WsbGoldenProbeStart,
    readiness: &WindowsSandboxReadiness,
    layout: &RunLayout,
    process: &impl ProcessBoundary,
    lease: &impl LeaseBoundary,
    workspace: &impl WorkspaceBoundary,
) -> Result<WsbGoldenProbeExecution, RunnerError> {
    let _lease = lease.try_acquire()?;
    if cancellation_requested(layout)? {
        record_prestart_failure(layout, RunnerError::Cancelled)?;
        return Err(RunnerError::Cancelled);
    }
    let context = prepare_execution(request, readiness, layout, true)?;
    revalidate_workspace(request, workspace)?;
    let store = TransactionStore::new(layout, context.binding.clone());
    if store.load_current()?.is_some() {
        return Err(RunnerError::RecoveryRequired(
            "an earlier provider attempt must be recovered first".to_owned(),
        ));
    }
    let provider_path = Path::new(&request.provider.canonical_path);
    let before = list_sessions(
        process,
        provider_path,
        &context.lifecycle,
        request.timeout_seconds,
    )?;
    if !before.is_empty() {
        return Err(RunnerError::SessionConflict);
    }
    prepare_request_artifact(&context.request_path, &context.guest_request)?;
    if cancellation_requested(layout)? {
        remove_owned_request(&context.request_path, &context.guest_request)?;
        record_prestart_failure(layout, RunnerError::Cancelled)?;
        return Err(RunnerError::Cancelled);
    }

    // The intent is durable before the call. A crash or lost start response
    // therefore means "may have started" and is recoverable by exact ID.
    if let Err(error) = revalidate_workspace(request, workspace) {
        remove_owned_request(&context.request_path, &context.guest_request)?;
        record_prestart_failure(layout, error.clone())?;
        return Err(error);
    }
    store.create("approved-start")?;
    let operation = run_attempt(request, layout, process, &context, &store);
    let cleanup = finalize_attempt(
        request,
        process,
        &context,
        &store,
        false,
        operation.as_ref().err(),
    );
    if let Err(error) = cleanup {
        if matches!(error, RunnerError::RecoveryRequired(_)) {
            return Err(error);
        }
        record_terminal_failure(layout, error.clone())?;
        return Err(error);
    }
    if let Err(error) = operation {
        record_terminal_failure(layout, error.clone())?;
        return Err(error);
    }

    // Guest artifacts are interpreted only after exact-session absence and
    // provider quiescence have been established under the held lease.
    if let Err(error) = revalidate_workspace(request, workspace) {
        record_terminal_failure(layout, error.clone())?;
        return Err(error);
    }
    let verification = verify_completion_receipt(&context.output_root, &context.completion)
        .map_err(|error| RunnerError::Receipt(error.to_string()));
    let verification = match verification {
        Ok(value) if value.successful => value,
        Ok(_) => {
            let error = RunnerError::Receipt("guest reported failure".to_owned());
            record_terminal_failure(layout, error.clone())?;
            return Err(error);
        }
        Err(error) => {
            record_terminal_failure(layout, error.clone())?;
            return Err(error);
        }
    };
    if cancellation_requested(layout)? {
        record_terminal_failure(layout, RunnerError::Cancelled)?;
        return Err(RunnerError::Cancelled);
    }
    let scenario = (|| -> Result<_, RunnerError> {
        Ok(match &context.guest_request {
            ExecutionGuestRequest::ImportedMsi(expected) => {
                let observed: aiw_provider_wsb::ImportedMsiScenarioResult = read_bounded_json(
                    &context.output_root.join("scenario-result.json"),
                    64 * 1024,
                )?;
                observed
                    .validate_for_request(expected)
                    .map_err(|e| RunnerError::Receipt(e.to_string()))?;
                let evidence_bytes = read_bounded_bytes(
                    &context.output_root.join("evidence.jsonl"),
                    aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64,
                )?;
                let token = aiw_provider_wsb::verify_msi_application_token(
                    &evidence_bytes,
                    &verification.evidence_root_hash,
                    expected,
                    &observed,
                )
                .map_err(RunnerError::Receipt)?;
                let standard_user_context = aiw_provider_wsb::verify_msi_runtime_context(
                    &evidence_bytes,
                    &verification.evidence_root_hash,
                    expected,
                    &observed,
                    token.as_ref(),
                )
                .map_err(RunnerError::Receipt)?;
                let registry_evidence = aiw_provider_wsb::verify_msi_registry_evidence(
                    &evidence_bytes,
                    &verification.evidence_root_hash,
                    expected,
                    &observed,
                    standard_user_context.as_ref(),
                )
                .map_err(RunnerError::Receipt)?;
                let behavior = aiw_provider_wsb::verify_imported_msi_behavior(
                    &evidence_bytes,
                    &verification.evidence_root_hash,
                    expected,
                    &observed,
                )
                .map_err(RunnerError::Receipt)?;
                let stages = aiw_provider_wsb::verify_imported_msi_stage_progress(
                    &evidence_bytes,
                    &verification.evidence_root_hash,
                    expected,
                )
                .map_err(RunnerError::Receipt)?;
                if stages
                    .as_ref()
                    .is_some_and(|progress| !progress.successful())
                {
                    return Err(RunnerError::Receipt(
                        "successful result has failed stage progress".to_owned(),
                    ));
                }
                (
                    Some(observed),
                    token,
                    behavior,
                    standard_user_context,
                    registry_evidence,
                )
            }
            ExecutionGuestRequest::Golden(_) => (None, None, None, None, None),
        })
    })();
    let (scenario, application_token, behavior, standard_user_context, registry_evidence) =
        match scenario {
            Ok(value) => value,
            Err(error) => {
                record_terminal_failure(layout, error.clone())?;
                return Err(error);
            }
        };
    let result = RunResult::new(
        context.plan.run_id.clone(),
        RunOutcome::InsufficientEvidence,
        "provider-time-not-trusted",
        Some(verification.evidence_root_hash.clone()),
        true,
        "Approved Windows Sandbox lifecycle completed; containment conclusions require host-side process, token, trace, and canary evidence.",
    )
    .map_err(journal_error)?;
    layout.write_result(&result).map_err(journal_error)?;
    Ok(WsbGoldenProbeExecution {
        schema_version: "aiw.dev/wsb-golden-probe-execution/v0alpha2".to_owned(),
        run_id: context.plan.run_id,
        sandbox_id: context.binding.session_id,
        provider_sha256: request.provider.sha256.clone(),
        config_sha256: context.binding.config_sha256,
        request_sha256: context.guest_request.digest().to_owned(),
        receipt_sha256: verification.receipt_sha256,
        evidence_root_hash: verification.evidence_root_hash,
        workspace: request.workspace.clone(),
        workspace_identity_sha256: request.workspace_identity_sha256.clone(),
        cleanup_complete: true,
        scenario,
        application_token,
        behavior,
        standard_user_context,
        registry_evidence,
    })
}

/// Starts only the fixed golden probe described by an imported, approved
/// preparation. Provider, workspace, mappings, agent and session authority are
/// derived from persisted evidence; callers cannot supply an executable,
/// provider path, session ID, command, or policy fragment.
#[cfg(windows)]
pub fn start_approved_windows_sandbox_golden_probe(
    workspace_root: &Path,
    project_path: &Path,
    project: &Project,
    expected_guest_agent_sha256: &str,
    timeout_seconds: u32,
) -> Result<WsbGoldenProbeExecution, RunnerError> {
    match start_approved_windows_sandbox_inner(
        workspace_root,
        project_path,
        project,
        expected_guest_agent_sha256,
        timeout_seconds,
        false,
    )? {
        WsbApprovedExecution::GoldenProbe(result) => Ok(result),
        WsbApprovedExecution::ImportedMsi(_) => Err(RunnerError::ApprovalBinding),
    }
}

#[cfg(windows)]
pub fn start_approved_windows_sandbox(
    workspace_root: &Path,
    project_path: &Path,
    project: &Project,
    expected_guest_agent_sha256: &str,
    timeout_seconds: u32,
) -> Result<WsbApprovedExecution, RunnerError> {
    start_approved_windows_sandbox_inner(
        workspace_root,
        project_path,
        project,
        expected_guest_agent_sha256,
        timeout_seconds,
        true,
    )
}

#[cfg(windows)]
fn start_approved_windows_sandbox_inner(
    workspace_root: &Path,
    project_path: &Path,
    project: &Project,
    expected_guest_agent_sha256: &str,
    timeout_seconds: u32,
    allow_msi: bool,
) -> Result<WsbApprovedExecution, RunnerError> {
    let mut held = preparation::open_verified_windows_sandbox_preparation(
        workspace_root,
        project,
        expected_guest_agent_sha256,
        true,
        false,
    )
    .map_err(|error| RunnerError::Preparation(error.to_string()))?;
    held.revalidate_imported()
        .map_err(|error| RunnerError::Preparation(error.to_string()))?;
    let artifacts = held.artifacts.clone();
    if artifacts.receipt.msi.is_some() && !allow_msi {
        return Err(RunnerError::ApprovalBinding);
    }
    let layout = RunLayout::new(held.workspace().root_path(), &artifacts.receipt.run_id)
        .map_err(journal_error)?;
    if layout.read_plan().map_err(journal_error)? != artifacts.run_plan {
        return Err(RunnerError::ApprovalBinding);
    }

    let request = WsbGoldenProbeStart {
        schema_version: if artifacts.receipt.msi.is_some() {
            "aiw.dev/wsb-imported-msi-start/v0alpha1"
        } else {
            "aiw.dev/wsb-golden-probe-start/v0alpha2"
        }
        .to_owned(),
        run_root: artifacts.receipt.workspace.root.final_path.clone(),
        project_path: project_path.to_string_lossy().into_owned(),
        wsb_plan: artifacts.wsb_plan.clone(),
        provider: artifacts.receipt.provider.clone(),
        guest_agent: artifacts.receipt.guest_agent.clone(),
        workspace: artifacts.receipt.workspace.clone(),
        workspace_identity_sha256: artifacts.receipt.workspace_identity_sha256.clone(),
        timeout_seconds,
        msi: artifacts.receipt.msi.clone(),
    };
    let approval = layout.read_approval().map_err(journal_error)?;
    if !matches!(
        layout.status().map_err(journal_error)?,
        aiw_orchestrator::RecoveryStatus::Ready { .. }
    ) {
        return Err(RunnerError::ApprovalBinding);
    }
    ensure_approval(&artifacts.run_plan, &approval, &request)?;

    let native_lease =
        aiw_windows_platform::acquire_windows_sandbox(&artifacts.receipt.provider.sha256)
            .map_err(native_invocation_error)?;
    let readiness = native_lease.readiness().clone();
    let process = NativeWsbProcess {
        state: std::sync::Mutex::new(NativeWsbState {
            lease: native_lease,
            started_id: None,
        }),
        plan: artifacts.wsb_plan,
    };
    let result = execute_wsb_golden_probe(
        &request,
        &readiness,
        &layout,
        &process,
        &AlreadyHeldProviderLease,
        held.workspace(),
    )?;
    if request.msi.is_some() {
        let scenario = result.scenario.ok_or(RunnerError::Drift)?;
        Ok(WsbApprovedExecution::ImportedMsi(WsbImportedMsiExecution {
            schema_version: if result.registry_evidence.is_some() {
                "aiw.dev/wsb-imported-msi-execution/v0alpha5"
            } else if result.standard_user_context.is_some() {
                "aiw.dev/wsb-imported-msi-execution/v0alpha4"
            } else if result.behavior.is_some() {
                "aiw.dev/wsb-imported-msi-execution/v0alpha3"
            } else if result.application_token.is_some() {
                "aiw.dev/wsb-imported-msi-execution/v0alpha2"
            } else {
                "aiw.dev/wsb-imported-msi-execution/v0alpha1"
            }
            .to_owned(),
            run_id: result.run_id,
            sandbox_id: result.sandbox_id,
            provider_sha256: result.provider_sha256,
            config_sha256: result.config_sha256,
            request_sha256: result.request_sha256,
            receipt_sha256: result.receipt_sha256,
            evidence_root_hash: result.evidence_root_hash,
            workspace: result.workspace,
            workspace_identity_sha256: result.workspace_identity_sha256,
            cleanup_complete: result.cleanup_complete,
            scenario,
            application_token: result.application_token,
            behavior: result.behavior,
            standard_user_context: result.standard_user_context,
            registry_evidence: result.registry_evidence,
        }))
    } else {
        Ok(WsbApprovedExecution::GoldenProbe(result))
    }
}

/// Reconciles one persisted Windows Sandbox transaction. The caller supplies
/// only the run layout; every mutable target is recovered from hash-bound local
/// state and revalidated while the exact workspace handles are held.
#[cfg(windows)]
pub fn recover_windows_sandbox(layout: &RunLayout) -> Result<WsbRecoveryResult, RunnerError> {
    use aiw_windows_platform::{
        CanonicalSandboxId, HeldRunWorkspace, WsbRecoveryDisposition,
        acquire_windows_sandbox_recovery,
    };

    let inspection = session::inspect_for_recovery(layout)?;
    let transaction = inspection.transaction.clone().ok_or_else(|| {
        RunnerError::Transaction("no provider session transaction exists".to_owned())
    })?;
    if transaction.run_id != layout.run_id() {
        return Err(RunnerError::Transaction(
            "session transaction belongs to a different run".to_owned(),
        ));
    }
    let workspace_evidence = recovery_workspace(layout, &transaction)?;
    let workspace = HeldRunWorkspace::reopen_bound(&workspace_evidence)
        .map_err(|error| RunnerError::RecoveryRequired(error.to_string()))?;
    workspace
        .revalidate()
        .map_err(|error| RunnerError::RecoveryRequired(error.to_string()))?;

    let repeated = session::inspect_for_recovery(layout)?;
    if repeated != inspection {
        return Err(RunnerError::RecoveryRequired(
            "session transaction changed while workspace authority was acquired".to_owned(),
        ));
    }
    let store = TransactionStore::resume_from(layout, &transaction)?;
    store.verify_inspection(&inspection)?;

    let session_id =
        CanonicalSandboxId::parse(&transaction.session_id).map_err(native_recovery_error)?;
    let mut provider = acquire_windows_sandbox_recovery(&transaction.provider_sha256, session_id)
        .map_err(native_recovery_error)?;
    store.discard_pending_after_authority(&inspection)?;

    if transaction.current_state() == SessionTransactionState::CleanupVerified {
        let observed = provider
            .verify_bound_absent()
            .map_err(native_recovery_error)?;
        let legacy = transaction.recovery.is_none();
        if !legacy {
            remove_recovery_request(&workspace, &transaction)
                .map_err(|error| RunnerError::RecoveryRequired(error.to_string()))?;
        }
        workspace
            .revalidate()
            .map_err(|error| RunnerError::RecoveryRequired(error.to_string()))?;
        if !legacy {
            terminalize_verified_wsb_recovery(layout, &store)?;
        }
        return Ok(WsbRecoveryResult {
            schema_version: WSB_RECOVERY_RESULT_SCHEMA_VERSION.to_owned(),
            run_id: transaction.run_id,
            session_id: transaction.session_id,
            state: SessionTransactionState::CleanupVerified,
            provider_cleanup_verified: true,
            workspace_cleanup_verified: !legacy,
            terminalizable: !legacy,
            mutex_was_abandoned: provider.mutex_was_abandoned(),
            start_provider_sha256: provider.start_provider_sha256().to_owned(),
            recovery_provider_sha256: provider.recovery_provider_sha256().to_owned(),
            provider_drifted: provider.provider_drifted(),
            session_ids_before: observed.session_ids.clone(),
            session_ids_after: observed.session_ids,
            reason_code: if legacy {
                "legacy-request-location-unavailable"
            } else {
                "already-clean"
            }
            .to_owned(),
        });
    }

    if transaction.current_state() == SessionTransactionState::StartIntent {
        store.transition(SessionTransactionState::Unknown, "start-outcome-unknown")?;
    }
    let state = store
        .load_current()?
        .ok_or_else(|| RunnerError::Transaction("session transaction disappeared".to_owned()))?
        .current_state();
    if matches!(
        state,
        SessionTransactionState::Active
            | SessionTransactionState::Unknown
            | SessionTransactionState::RecoveryRequired
    ) {
        store.transition(
            SessionTransactionState::CleanupIntent,
            "recovery-cleanup-attempt",
        )?;
    }

    let observed = provider.reconcile().map_err(native_recovery_error)?;
    workspace
        .revalidate()
        .map_err(|error| RunnerError::RecoveryRequired(error.to_string()))?;
    let legacy = transaction.recovery.is_none();
    if legacy {
        store.transition(
            SessionTransactionState::RecoveryRequired,
            "legacy-request-location-unavailable",
        )?;
    } else if let Err(error) = remove_recovery_request(&workspace, &transaction) {
        let _ = store.transition(
            SessionTransactionState::RecoveryRequired,
            "request-cleanup-unverified",
        );
        return Err(RunnerError::RecoveryRequired(error.to_string()));
    } else {
        workspace
            .revalidate()
            .map_err(|error| RunnerError::RecoveryRequired(error.to_string()))?;
        store.transition(
            SessionTransactionState::CleanupVerified,
            "recovery-cleanup-verified",
        )?;
    }
    let final_transaction = store
        .load_current()?
        .ok_or_else(|| RunnerError::Transaction("session transaction disappeared".to_owned()))?;
    let final_state = final_transaction.current_state();
    if !legacy {
        terminalize_verified_wsb_recovery(layout, &store)?;
    }
    Ok(WsbRecoveryResult {
        schema_version: WSB_RECOVERY_RESULT_SCHEMA_VERSION.to_owned(),
        run_id: final_transaction.run_id,
        session_id: final_transaction.session_id,
        state: final_state,
        provider_cleanup_verified: true,
        workspace_cleanup_verified: !legacy,
        terminalizable: !legacy,
        mutex_was_abandoned: observed.mutex_was_abandoned,
        start_provider_sha256: observed.start_provider_sha256,
        recovery_provider_sha256: observed.recovery_provider_sha256,
        provider_drifted: observed.provider_drifted,
        session_ids_before: observed.session_ids_before,
        session_ids_after: observed.session_ids_after,
        reason_code: if legacy {
            "legacy-request-location-unavailable".to_owned()
        } else {
            match observed.disposition {
                WsbRecoveryDisposition::AlreadyAbsent => "exact-session-already-absent".to_owned(),
                WsbRecoveryDisposition::Stopped => "exact-session-stopped".to_owned(),
            }
        },
    })
}

#[cfg(windows)]
fn recovery_workspace(
    layout: &RunLayout,
    transaction: &SessionTransaction,
) -> Result<WorkspaceBindingEvidence, RunnerError> {
    let plan = layout.read_plan().map_err(journal_error)?;
    if plan.hash().map_err(journal_error)? != transaction.plan_hash
        || plan.run_id != transaction.run_id
        || plan.project_revision_hash != transaction.project_revision_hash
    {
        return Err(RunnerError::Transaction(
            "session transaction does not match the persisted run plan".to_owned(),
        ));
    }
    let bindings: Vec<(&str, &WorkspaceBindingEvidence, &str)> = plan
        .actions
        .iter()
        .filter_map(|action| match action {
            PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                provider_sha256,
                workspace,
                workspace_identity_sha256,
                ..
            }
            | PlannedAction::ExecuteWindowsSandboxImportedMsiScenario {
                provider_sha256,
                workspace,
                workspace_identity_sha256,
                ..
            } => Some((
                provider_sha256.as_str(),
                workspace.as_ref(),
                workspace_identity_sha256.as_str(),
            )),
            _ => None,
        })
        .collect();
    let [(provider_sha256, workspace, workspace_hash)] = bindings.as_slice() else {
        return Err(RunnerError::Transaction(
            "persisted run plan does not contain one recovery binding".to_owned(),
        ));
    };
    if *provider_sha256 != transaction.provider_sha256
        || *workspace_hash != transaction.workspace_identity_sha256
        || canonical_hash(workspace)? != transaction.workspace_identity_sha256
        || transaction
            .recovery
            .as_ref()
            .is_some_and(|recovery| &recovery.workspace != *workspace)
    {
        return Err(RunnerError::Transaction(
            "session transaction recovery binding differs from the run plan".to_owned(),
        ));
    }
    Ok((*workspace).clone())
}

#[cfg(windows)]
fn remove_recovery_request(
    workspace: &aiw_windows_platform::HeldRunWorkspace,
    transaction: &SessionTransaction,
) -> Result<(), RunnerError> {
    let recovery = transaction
        .recovery
        .as_ref()
        .ok_or_else(|| RunnerError::Transaction("session recovery binding is absent".to_owned()))?;
    let path = workspace.tools_path().join(&recovery.request_relative_path);
    if path
        .parent()
        .is_none_or(|parent| parent != workspace.tools_path())
    {
        return Err(RunnerError::Drift);
    }
    if !recovery_request_present(&path)? {
        return Ok(());
    }
    ensure_ordinary_file(&path)?;
    let current: ExecutionGuestRequest = read_bounded_json(&path, 64 * 1024)?;
    current.validate()?;
    let (run_id, sandbox_id, config_sha256) = current.binding();
    if current.digest() != transaction.request_sha256
        || request_hash(&current)? != transaction.request_sha256
        || run_id != transaction.run_id
        || sandbox_id != transaction.session_id
        || config_sha256 != transaction.config_sha256
    {
        return Err(RunnerError::Drift);
    }
    fs::remove_file(path).map_err(|_| RunnerError::Drift)
}

fn recovery_request_present(path: &Path) -> Result<bool, RunnerError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && !has_reparse_point(&metadata) =>
        {
            Ok(true)
        }
        Ok(_) => Err(RunnerError::Drift),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(RunnerError::Drift),
    }
}

#[cfg(windows)]
fn native_recovery_error(
    error: aiw_windows_platform::WindowsSandboxInvocationError,
) -> RunnerError {
    use aiw_windows_platform::WindowsSandboxInvocationError;
    match error {
        WindowsSandboxInvocationError::LeaseUnavailable => RunnerError::LeaseUnavailable,
        WindowsSandboxInvocationError::RecoveryRequired => {
            RunnerError::RecoveryRequired(error.to_string())
        }
        WindowsSandboxInvocationError::Protocol(detail)
            if detail.contains("cleaned transaction UUID is present again") =>
        {
            RunnerError::SessionConflict
        }
        other => RunnerError::RecoveryRequired(other.to_string()),
    }
}

#[cfg(test)]
pub(crate) fn recover_wsb_session(
    request: &WsbGoldenProbeStart,
    readiness: &WindowsSandboxReadiness,
    layout: &RunLayout,
    process: &impl ProcessBoundary,
    lease: &impl LeaseBoundary,
) -> Result<SessionTransaction, RunnerError> {
    let _lease = lease.try_acquire()?;
    let context = prepare_execution(request, readiness, layout, false)?;
    let store = TransactionStore::new(layout, context.binding.clone());
    let transaction = store.load_for_recovery()?.ok_or_else(|| {
        RunnerError::Transaction("no provider session transaction exists".to_owned())
    })?;
    if transaction.current_state() != SessionTransactionState::CleanupVerified {
        finalize_attempt(request, process, &context, &store, true, None)?;
    } else {
        remove_owned_request(&context.request_path, &context.guest_request)?;
    }
    terminalize_verified_wsb_recovery(layout, &store)?;
    store
        .load_for_recovery()?
        .ok_or_else(|| RunnerError::Transaction("recovered transaction disappeared".to_owned()))
}

struct ExecutionContext {
    plan: RunPlan,
    lifecycle: WindowsSandboxCliLifecyclePlan,
    output_root: PathBuf,
    request_path: PathBuf,
    guest_request: ExecutionGuestRequest,
    completion: WindowsSandboxCompletionExpectation,
    binding: SessionBinding,
}

fn prepare_execution(
    request: &WsbGoldenProbeStart,
    readiness: &WindowsSandboxReadiness,
    layout: &RunLayout,
    require_empty_output: bool,
) -> Result<ExecutionContext, RunnerError> {
    validate_start(request, readiness)?;
    if request.timeout_seconds == 0
        || request.timeout_seconds > 3600
        || request.run_root != request.wsb_plan.workspace_root
    {
        return Err(RunnerError::Drift);
    }
    let plan = layout.read_plan().map_err(journal_error)?;
    let approval = layout.read_approval().map_err(journal_error)?;
    if require_empty_output
        && !matches!(
            layout.status().map_err(journal_error)?,
            aiw_orchestrator::RecoveryStatus::Ready { .. }
        )
    {
        return Err(RunnerError::ApprovalBinding);
    }
    ensure_approval(&plan, &approval, request)?;
    revalidate_project_revision(&plan, Path::new(&request.project_path))?;
    revalidate_identity(&request.provider)?;
    revalidate_identity(&request.guest_agent)?;
    if require_empty_output {
        validate_host_mappings(&request.wsb_plan).map_err(|_| RunnerError::Drift)?;
    } else {
        validate_recovery_mappings(&request.wsb_plan)?;
    }
    let rendered = render_config(&request.wsb_plan).map_err(|_| RunnerError::Drift)?;
    let session_id = deterministic_sandbox_id(&plan.run_id);
    let lifecycle = plan_cli_lifecycle(
        &request.provider.canonical_path,
        &session_id,
        &request.wsb_plan,
    )
    .map_err(|_| RunnerError::Drift)?;
    if lifecycle.rendered_config.sha256 != rendered.sha256 {
        return Err(RunnerError::Drift);
    }
    let output = mapping(&request.wsb_plan, MappingPurpose::Output).ok_or(RunnerError::Drift)?;
    let tools = mapping(&request.wsb_plan, MappingPurpose::Tools).ok_or(RunnerError::Drift)?;
    validate_workspace_paths(request, tools, output)?;
    let agent_path =
        guest_to_host(tools, &request.wsb_plan.probe.executable).ok_or(RunnerError::Drift)?;
    revalidate_mapped_identity(&agent_path, &request.guest_agent)?;
    let guest_request_path = request
        .wsb_plan
        .probe
        .request
        .as_ref()
        .ok_or(RunnerError::ApprovalBinding)?;
    let request_path = guest_to_host(tools, guest_request_path).ok_or(RunnerError::Drift)?;
    let request_relative_path = request_path
        .strip_prefix(Path::new(&tools.host_folder))
        .map_err(|_| RunnerError::Drift)?
        .components()
        .map(|component| component.as_os_str().to_str().ok_or(RunnerError::Drift))
        .collect::<Result<Vec<_>, _>>()?
        .join("/");
    if !request_relative_path.is_ascii()
        || request_relative_path.contains('\\')
        || !aiw_schema::is_safe_relative_path(&request_relative_path)
    {
        return Err(RunnerError::Drift);
    }
    let guest_request = if let Some(msi) = &request.msi {
        revalidate_identity(&msi.staged_payload)?;
        ExecutionGuestRequest::ImportedMsi(Box::new(
            aiw_provider_wsb::ImportedMsiGuestRequest::new(
                &plan.run_id,
                &session_id,
                &rendered.sha256,
                &request.guest_agent.sha256,
                msi.scenario.clone(),
                &msi.staged_payload.sha256,
                msi.staged_payload.size_bytes,
                &msi.import_receipt_sha256,
            )
            .map_err(|e| RunnerError::Preparation(e.to_string()))?,
        ))
    } else {
        ExecutionGuestRequest::Golden(Box::new(GuestRequest::new(
            &plan.run_id,
            &session_id,
            &rendered.sha256,
            &request.guest_agent.sha256,
            &output.sandbox_folder,
        )?))
    };
    let mut completion = completion_expectation(
        &plan.run_id,
        &session_id,
        &rendered.sha256,
        &request.guest_agent.sha256,
        guest_request.digest(),
    );
    if request.msi.is_some() {
        completion.artifacts[0].path = "scenario-result.json".to_owned();
        completion.artifacts[0].role = aiw_evidence::ArtifactRole::ScenarioResults;
        completion.artifacts[1].maximum_bytes =
            aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64;
    }
    let binding = SessionBinding {
        run_id: plan.run_id.clone(),
        plan_hash: plan.hash().map_err(journal_error)?,
        project_revision_hash: plan.project_revision_hash.clone(),
        provider_sha256: request.provider.sha256.clone(),
        config_sha256: rendered.sha256,
        session_id,
        request_sha256: guest_request.digest().to_owned(),
        workspace_identity_sha256: request.workspace_identity_sha256.clone(),
        recovery: Some(SessionRecoveryBinding {
            workspace: request.workspace.clone(),
            request_relative_path,
            provider_protocol: readiness
                .cli_protocol
                .clone()
                .ok_or_else(|| RunnerError::Readiness("CLI protocol is unavailable".to_owned()))?,
        }),
    };
    Ok(ExecutionContext {
        plan,
        lifecycle,
        output_root: PathBuf::from(&output.host_folder),
        request_path,
        guest_request,
        completion,
        binding,
    })
}

fn run_attempt(
    request: &WsbGoldenProbeStart,
    layout: &RunLayout,
    process: &impl ProcessBoundary,
    context: &ExecutionContext,
    store: &TransactionStore<'_>,
) -> Result<(), RunnerError> {
    let provider = Path::new(&request.provider.canonical_path);
    let started = process.invoke(
        provider,
        &context.lifecycle.start.arguments,
        request.timeout_seconds,
    );
    let started_id = match started.and_then(|result| {
        ensure_success(&result)?;
        response_id(&result.stdout)
    }) {
        Ok(id) if id == context.binding.session_id => {
            store.transition(SessionTransactionState::Active, "start-confirmed")?;
            id
        }
        Ok(_) => {
            store.transition(SessionTransactionState::Unknown, "start-id-mismatch")?;
            return Err(RunnerError::SessionConflict);
        }
        Err(error) => {
            store.transition(SessionTransactionState::Unknown, "start-response-lost")?;
            return Err(error);
        }
    };
    debug_assert_eq!(started_id, context.binding.session_id);
    let current = list_sessions(
        process,
        provider,
        &context.lifecycle,
        request.timeout_seconds,
    )?;
    if current.len() != 1 || current[0].id != context.binding.session_id {
        return Err(RunnerError::SessionConflict);
    }
    if cancellation_requested(layout)? {
        return Err(RunnerError::Cancelled);
    }
    connect_exact_session(
        process,
        provider,
        &context.lifecycle,
        &context.binding.session_id,
        request.timeout_seconds,
    )?;
    progress(
        layout,
        "W1 Windows Sandbox session identity reconciled and user logon connected",
    )?;
    wait_for_receipt(layout, &context.output_root, request.timeout_seconds)
}

fn finalize_attempt(
    request: &WsbGoldenProbeStart,
    process: &impl ProcessBoundary,
    context: &ExecutionContext,
    store: &TransactionStore<'_>,
    recovering: bool,
    operation_error: Option<&RunnerError>,
) -> Result<(), RunnerError> {
    let mut state_error = prepare_cleanup_transaction(store);
    let provider = Path::new(&request.provider.canonical_path);
    let first = list_sessions(
        process,
        provider,
        &context.lifecycle,
        request.timeout_seconds,
    );
    let mut observation_error = first.as_ref().err().cloned();
    let unrelated_observed = first.as_ref().is_ok_and(|sessions| {
        sessions
            .iter()
            .any(|session| session.id != context.binding.session_id)
    });
    let should_stop = match &first {
        Ok(sessions) => sessions
            .iter()
            .any(|session| session.id == context.binding.session_id),
        Err(_) => true,
    };
    if should_stop {
        if let Err(error) = stop_exact_session(
            process,
            provider,
            &context.lifecycle,
            &context.binding.session_id,
            request.timeout_seconds,
        ) {
            observation_error.get_or_insert(error);
        }
    }
    let final_sessions = list_sessions(
        process,
        provider,
        &context.lifecycle,
        request.timeout_seconds,
    );
    let physically_verified = !unrelated_observed
        && final_sessions
            .as_ref()
            .is_ok_and(|sessions| sessions.is_empty());
    if physically_verified {
        if let Err(error) = remove_owned_request(&context.request_path, &context.guest_request) {
            let _ = store.transition(
                SessionTransactionState::RecoveryRequired,
                "request-cleanup-unverified",
            );
            return Err(RunnerError::RecoveryRequired(error.to_string()));
        }
        if let Err(error) = store.transition(
            SessionTransactionState::CleanupVerified,
            if recovering {
                "recovery-cleanup-verified"
            } else {
                "cleanup-verified"
            },
        ) {
            state_error.get_or_insert(error);
        }
        if let Some(error) = state_error {
            return Err(RunnerError::RecoveryRequired(error.to_string()));
        }
        if recovering {
            return Ok(());
        }
        if let Some(error) = observation_error {
            return Err(error);
        }
        return Ok(());
    }

    let reason = if unrelated_observed
        || final_sessions.as_ref().is_ok_and(|sessions| {
            sessions
                .iter()
                .any(|session| session.id != context.binding.session_id)
        }) {
        "unrelated-session-observed"
    } else if final_sessions.as_ref().is_ok_and(|sessions| {
        sessions
            .iter()
            .any(|session| session.id == context.binding.session_id)
    }) {
        "bound-session-still-present"
    } else {
        "cleanup-state-unverified"
    };
    if state_error.is_none() {
        if let Err(error) = store.transition(SessionTransactionState::RecoveryRequired, reason) {
            state_error = Some(error);
        }
    }
    let detail = match (
        operation_error,
        observation_error.as_ref(),
        state_error.as_ref(),
    ) {
        (Some(error), _, _) => error.to_string(),
        (_, Some(error), _) => error.to_string(),
        (_, _, Some(error)) => error.to_string(),
        _ => reason.to_owned(),
    };
    Err(RunnerError::RecoveryRequired(detail))
}

fn prepare_cleanup_transaction(store: &TransactionStore<'_>) -> Option<RunnerError> {
    let current = match store.load_current() {
        Ok(Some(transaction)) => transaction,
        Ok(None) => {
            return Some(RunnerError::Transaction(
                "session transaction disappeared during cleanup".to_owned(),
            ));
        }
        Err(error) => return Some(error),
    };
    let current = match current.current_state() {
        SessionTransactionState::StartIntent => store
            .transition(SessionTransactionState::Unknown, "start-outcome-unknown")
            .map(|transaction| transaction.current_state()),
        state => Ok(state),
    };
    let current = match current {
        Ok(state) => state,
        Err(error) => return Some(error),
    };
    match current {
        SessionTransactionState::Active
        | SessionTransactionState::Unknown
        | SessionTransactionState::RecoveryRequired => store
            .transition(SessionTransactionState::CleanupIntent, "cleanup-attempt")
            .err(),
        SessionTransactionState::CleanupIntent | SessionTransactionState::CleanupVerified => None,
        SessionTransactionState::StartIntent => Some(RunnerError::Transaction(
            "session transaction did not advance from start intent".to_owned(),
        )),
    }
}

/// Called under the provider lease only after fresh exact-session absence and
/// held workspace/request cleanup checks. Persisted cleanup alone is not proof.
fn terminalize_verified_wsb_recovery(
    layout: &RunLayout,
    store: &TransactionStore<'_>,
) -> Result<(), RunnerError> {
    let transaction = store.load_current()?.ok_or_else(|| {
        RunnerError::RecoveryRequired("session cleanup transaction is missing".to_owned())
    })?;
    if transaction.current_state() != SessionTransactionState::CleanupVerified
        || transaction.recovery.is_none()
    {
        return Err(RunnerError::RecoveryRequired(
            "complete workspace-bound session cleanup is required before terminalization"
                .to_owned(),
        ));
    }
    // Repair an interrupted terminal publication before deciding whether a
    // result is missing. An already committed result is immutable on retry.
    let cancelled = match layout.recovery_status().map_err(journal_error)? {
        aiw_orchestrator::RecoveryStatus::Terminal { .. } => return Ok(()),
        aiw_orchestrator::RecoveryStatus::Ready { .. } => false,
        aiw_orchestrator::RecoveryStatus::CancellationRequested { .. } => true,
        _ => {
            return Err(RunnerError::RecoveryRequired(
                "committed approved run state is required before terminalization".to_owned(),
            ));
        }
    };
    let result = RunResult::new(
        layout.run_id(),
        if cancelled { RunOutcome::Cancelled } else { RunOutcome::Failed },
        "recovery-time-not-trusted",
        None,
        true,
        "Windows Sandbox recovery verified exact-session and request cleanup; interrupted completion processing does not establish a completed assessment.",
    )
    .map_err(journal_error)?;
    layout.write_result(&result).map_err(journal_error)
}

fn record_prestart_failure(layout: &RunLayout, error: RunnerError) -> Result<(), RunnerError> {
    if session::observe_transaction(layout)?.directory_present {
        return Err(RunnerError::RecoveryRequired(
            "an earlier provider attempt must be recovered before recording a pre-start failure"
                .to_owned(),
        ));
    }
    record_failure_result(layout, error, false)
}

fn record_terminal_failure(layout: &RunLayout, error: RunnerError) -> Result<(), RunnerError> {
    record_failure_result(layout, error, true)
}

fn record_failure_result(
    layout: &RunLayout,
    error: RunnerError,
    provider_cleanup_verified: bool,
) -> Result<(), RunnerError> {
    match layout.status().map_err(journal_error)? {
        aiw_orchestrator::RecoveryStatus::Terminal { .. } => return Ok(()),
        aiw_orchestrator::RecoveryStatus::RecoveryRequired { .. } => {
            return Err(RunnerError::Journal(
                "run journal recovery is required before a terminal result".to_owned(),
            ));
        }
        _ => {}
    }
    let cancelled = cancellation_requested(layout)? || matches!(error, RunnerError::Cancelled);
    let result = RunResult::new(
        layout.run_id(),
        if cancelled {
            RunOutcome::Cancelled
        } else {
            RunOutcome::Failed
        },
        "provider-time-not-trusted",
        None,
        provider_cleanup_verified,
        if !provider_cleanup_verified {
            "Windows Sandbox W1 run stopped before provider start; no exact-session cleanup was performed by this attempt."
        } else if cancelled {
            "Windows Sandbox W1 run was cancelled after exact-session cleanup was verified."
        } else {
            "Windows Sandbox W1 run failed after exact-session cleanup was verified."
        },
    )
    .map_err(journal_error)?;
    layout.write_result(&result).map_err(journal_error)
}

fn list_sessions(
    process: &impl ProcessBoundary,
    provider: &Path,
    lifecycle: &WindowsSandboxCliLifecyclePlan,
    timeout_seconds: u32,
) -> Result<Vec<ObservedSession>, RunnerError> {
    let result = process.invoke(provider, &lifecycle.list.arguments, timeout_seconds)?;
    sessions(result)
}

fn stop_exact_session(
    process: &impl ProcessBoundary,
    provider: &Path,
    lifecycle: &WindowsSandboxCliLifecyclePlan,
    expected_id: &str,
    timeout_seconds: u32,
) -> Result<(), RunnerError> {
    let result = process.invoke(provider, &lifecycle.stop.arguments, timeout_seconds)?;
    ensure_success(&result)?;
    if result.stdout.len() > MAX_PROVIDER_OUTPUT {
        return Err(RunnerError::ProviderOutputTooLarge);
    }
    if !result.stdout.is_empty() || !result.stderr.is_empty() || !valid_uuid(expected_id) {
        return Err(RunnerError::ProviderJson);
    }
    Ok(())
}

fn connect_exact_session(
    process: &impl ProcessBoundary,
    provider: &Path,
    lifecycle: &WindowsSandboxCliLifecyclePlan,
    expected_id: &str,
    timeout_seconds: u32,
) -> Result<(), RunnerError> {
    if lifecycle.sandbox_id != expected_id || !valid_uuid(expected_id) {
        return Err(RunnerError::SessionConflict);
    }
    let result = process.invoke(provider, &lifecycle.connect.arguments, timeout_seconds)?;
    ensure_success(&result)?;
    if !result.stdout.is_empty() || !result.stderr.is_empty() {
        return Err(RunnerError::ProviderJson);
    }
    Ok(())
}

fn prepare_request_artifact(
    path: &Path,
    expected: &ExecutionGuestRequest,
) -> Result<(), RunnerError> {
    expected.validate()?;
    let pending = request_pending_path(path)?;
    if pending.exists() {
        validate_staging_file(&pending)?;
        fs::remove_file(&pending).map_err(|_| RunnerError::Drift)?;
    }
    if path.exists() {
        let current: ExecutionGuestRequest = read_bounded_json(path, 64 * 1024)?;
        if current != *expected || request_hash(&current)? != current.digest() {
            return Err(RunnerError::Drift);
        }
        ensure_ordinary_file(path)?;
        fs::remove_file(path).map_err(|_| RunnerError::Drift)?;
    }
    publish_request(path, &pending, expected)
}

fn publish_request(
    path: &Path,
    pending: &Path,
    expected: &ExecutionGuestRequest,
) -> Result<(), RunnerError> {
    let mut bytes = serde_json::to_vec(expected).map_err(|_| RunnerError::Drift)?;
    bytes.push(b'\n');
    if bytes.len() > 64 * 1024 {
        return Err(RunnerError::Drift);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(pending)
        .map_err(|_| RunnerError::Drift)?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| RunnerError::Drift)?;
    fs::hard_link(pending, path).map_err(|_| RunnerError::Drift)?;
    ensure_ordinary_file(path)?;
    fs::remove_file(pending).map_err(|_| RunnerError::Drift)
}

fn remove_owned_request(path: &Path, expected: &ExecutionGuestRequest) -> Result<(), RunnerError> {
    let pending = request_pending_path(path)?;
    if pending.exists() {
        validate_staging_file(&pending)?;
        fs::remove_file(&pending).map_err(|_| RunnerError::Drift)?;
    }
    if !path.exists() {
        return Ok(());
    }
    ensure_ordinary_file(path)?;
    let current: ExecutionGuestRequest = read_bounded_json(path, 64 * 1024)?;
    if current != *expected || request_hash(&current)? != current.digest() {
        return Err(RunnerError::Drift);
    }
    fs::remove_file(path).map_err(|_| RunnerError::Drift)
}

fn request_pending_path(path: &Path) -> Result<PathBuf, RunnerError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(RunnerError::Drift)?;
    Ok(path.with_file_name(format!("{name}.pending")))
}

fn validate_staging_file(path: &Path) -> Result<(), RunnerError> {
    ensure_ordinary_file(path)?;
    let metadata = fs::metadata(path).map_err(|_| RunnerError::Drift)?;
    if metadata.len() > 64 * 1024 {
        return Err(RunnerError::Drift);
    }
    Ok(())
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    maximum: u64,
) -> Result<T, RunnerError> {
    let bytes = read_bounded_bytes(path, maximum)?;
    serde_json::from_slice(&bytes).map_err(|_| RunnerError::Drift)
}

fn read_bounded_bytes(path: &Path, maximum: u64) -> Result<Vec<u8>, RunnerError> {
    ensure_ordinary_file(path)?;
    let metadata = fs::metadata(path).map_err(|_| RunnerError::Drift)?;
    if metadata.len() > maximum {
        return Err(RunnerError::Drift);
    }
    let file = File::open(path).map_err(|_| RunnerError::Drift)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RunnerError::Drift)?;
    if bytes.len() as u64 > maximum {
        return Err(RunnerError::Drift);
    }
    Ok(bytes)
}

fn validate_recovery_mappings(plan: &WindowsSandboxPlan) -> Result<(), RunnerError> {
    render_config(plan).map_err(|_| RunnerError::Drift)?;
    let workspace = Path::new(&plan.workspace_root)
        .canonicalize()
        .map_err(|_| RunnerError::Drift)?;
    ensure_ordinary_directory(&workspace)?;
    for mapping in &plan.mappings {
        let path = Path::new(&mapping.host_folder)
            .canonicalize()
            .map_err(|_| RunnerError::Drift)?;
        ensure_ordinary_directory(&path)?;
        if !path.starts_with(&workspace) || path == workspace {
            return Err(RunnerError::Drift);
        }
    }
    Ok(())
}

fn revalidate_mapped_identity(path: &Path, identity: &BinaryIdentity) -> Result<(), RunnerError> {
    let current = path.canonicalize().map_err(|_| RunnerError::Drift)?;
    let display = current.to_string_lossy();
    let display = display.strip_prefix("\\\\?\\").unwrap_or(&display);
    if !display.eq_ignore_ascii_case(&identity.canonical_path) {
        return Err(RunnerError::Drift);
    }
    revalidate_identity(identity)
}

fn ensure_ordinary_directory(path: &Path) -> Result<(), RunnerError> {
    ensure_no_reparse_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| RunnerError::Drift)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
        return Err(RunnerError::Drift);
    }
    Ok(())
}

fn ensure_ordinary_file(path: &Path) -> Result<(), RunnerError> {
    ensure_no_reparse_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| RunnerError::Drift)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
        return Err(RunnerError::Drift);
    }
    Ok(())
}

fn ensure_no_reparse_components(path: &Path) -> Result<(), RunnerError> {
    for component in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if component.as_os_str().is_empty() || !component.exists() {
            continue;
        }
        let metadata = fs::symlink_metadata(component).map_err(|_| RunnerError::Drift)?;
        if metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
            return Err(RunnerError::Drift);
        }
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
const fn has_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuestRequest {
    schema_version: String,
    run_id: String,
    sandbox_id: String,
    config_sha256: String,
    request_sha256: String,
    agent_sha256: String,
    output_root: String,
    token_path: String,
    evidence_log_path: String,
    receipt_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
enum ExecutionGuestRequest {
    Golden(Box<GuestRequest>),
    ImportedMsi(Box<aiw_provider_wsb::ImportedMsiGuestRequest>),
}

impl ExecutionGuestRequest {
    fn digest(&self) -> &str {
        match self {
            Self::Golden(v) => &v.request_sha256,
            Self::ImportedMsi(v) => &v.request_sha256,
        }
    }
    fn binding(&self) -> (&str, &str, &str) {
        match self {
            Self::Golden(v) => (&v.run_id, &v.sandbox_id, &v.config_sha256),
            Self::ImportedMsi(v) => (&v.run_id, &v.sandbox_id, &v.config_sha256),
        }
    }
    fn validate(&self) -> Result<(), RunnerError> {
        match self {
            Self::Golden(v) => {
                if v.schema_version != GUEST_REQUEST_SCHEMA
                    || v.token_path != "token.json"
                    || v.evidence_log_path != "evidence.jsonl"
                    || v.receipt_path != "completion.json"
                    || request_hash(v)? != v.request_sha256
                {
                    return Err(RunnerError::Drift);
                }
                Ok(())
            }
            Self::ImportedMsi(v) => v.validate().map_err(|_| RunnerError::Drift),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuestFailureDiagnostic {
    schema_version: String,
    code: String,
    summary: String,
}

impl GuestRequest {
    fn new(
        run_id: &str,
        sandbox_id: &str,
        config_sha256: &str,
        agent_sha256: &str,
        output_root: &str,
    ) -> Result<Self, RunnerError> {
        let mut value = Self {
            schema_version: GUEST_REQUEST_SCHEMA.to_owned(),
            run_id: run_id.to_owned(),
            sandbox_id: sandbox_id.to_owned(),
            config_sha256: config_sha256.to_owned(),
            request_sha256: String::new(),
            agent_sha256: agent_sha256.to_owned(),
            output_root: output_root.to_owned(),
            token_path: "token.json".to_owned(),
            evidence_log_path: "evidence.jsonl".to_owned(),
            receipt_path: "completion.json".to_owned(),
        };
        value.request_sha256 = request_hash(&value)?;
        Ok(value)
    }
}

fn request_hash(value: &impl Serialize) -> Result<String, RunnerError> {
    let mut json = serde_json::to_value(value).map_err(|_| RunnerError::Drift)?;
    json["requestSha256"] = serde_json::Value::String(String::new());
    let bytes = aiw_evidence::canonical_json_bytes(&json).map_err(|_| RunnerError::Drift)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn ensure_approval(
    plan: &RunPlan,
    approval: &ApprovalRecord,
    request: &WsbGoldenProbeStart,
) -> Result<(), RunnerError> {
    if approval.run_id != plan.run_id || approval.plan_hash != plan.hash().map_err(journal_error)? {
        return Err(RunnerError::ApprovalBinding);
    }
    if !matches!(
        plan.actions.as_slice(),
        [
            PlannedAction::AssessHost,
            PlannedAction::PrepareWorkspace,
            PlannedAction::ExecuteWindowsSandboxGoldenProbe { .. }
                | PlannedAction::ExecuteWindowsSandboxImportedMsiScenario { .. },
            PlannedAction::CollectEvidence,
        ]
    ) {
        return Err(RunnerError::ApprovalBinding);
    }
    match (&plan.actions[2], &request.msi) {
        (PlannedAction::ExecuteWindowsSandboxGoldenProbe { .. }, None) => {}
        (
            PlannedAction::ExecuteWindowsSandboxImportedMsiScenario {
                import_receipt_sha256,
                application_sha256,
                scenario_sha256,
                ..
            },
            Some(msi),
        ) if import_receipt_sha256 == &msi.import_receipt_sha256
            && application_sha256 == &msi.staged_payload.sha256
            && scenario_sha256 == &msi.scenario_sha256 =>
        {
            msi.validate(&request.workspace)
                .map_err(|_| RunnerError::ApprovalBinding)?;
        }
        _ => return Err(RunnerError::ApprovalBinding),
    }
    let wsb_hash = canonical_hash(&request.wsb_plan)?;
    let workspace_hash = canonical_hash(&request.workspace)?;
    let exact = plan
        .actions
        .iter()
        .filter_map(|action| match action {
            PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
            }
            | PlannedAction::ExecuteWindowsSandboxImportedMsiScenario {
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
                ..
            } => Some((
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    if exact.len() != 1
        || exact[0].0 != &wsb_hash
        || exact[0].1 != &request.provider.sha256
        || exact[0].2 != &request.guest_agent.sha256
        || exact[0].3.as_ref() != &request.workspace
        || exact[0].4 != &workspace_hash
        || request.workspace_identity_sha256 != workspace_hash
    {
        return Err(RunnerError::ApprovalBinding);
    }
    Ok(())
}

fn validate_start(
    request: &WsbGoldenProbeStart,
    readiness: &WindowsSandboxReadiness,
) -> Result<(), RunnerError> {
    let schema = if request.msi.is_some() {
        "aiw.dev/wsb-imported-msi-start/v0alpha1"
    } else {
        "aiw.dev/wsb-golden-probe-start/v0alpha2"
    };
    if request.schema_version != schema
        || request.workspace.validate().is_err()
        || !fixed_lower_hex(&request.workspace_identity_sha256, 64)
        || canonical_hash(&request.workspace).ok().as_ref()
            != Some(&request.workspace_identity_sha256)
        || readiness.schema_version != READINESS_SCHEMA
        || !readiness.supported
        || readiness.os_build.is_none_or(|build| build < 26_100)
        || readiness.process_architecture != "x86_64"
        || readiness.virtualization != aiw_probe::ReadinessState::Available
        || readiness.sandbox_feature != aiw_probe::ReadinessState::Available
        || readiness.current_sessions != aiw_probe::ReadinessState::Available
    {
        return Err(RunnerError::Readiness(readiness.blockers.join(" ")));
    }
    let reported = readiness
        .provider_binary
        .as_ref()
        .ok_or_else(|| RunnerError::Readiness("provider identity is unavailable".to_owned()))?;
    if reported.signature_status != aiw_probe::ReadinessState::Available
        || !reported
            .canonical_path
            .eq_ignore_ascii_case(&request.provider.canonical_path)
        || reported.sha256 != request.provider.sha256
        || !Path::new(&request.provider.canonical_path)
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("wsb.exe"))
    {
        return Err(RunnerError::Readiness(
            "provider identity, signature, or basename is not approved".to_owned(),
        ));
    }
    let package = readiness.provider_package.as_ref();
    let catalog = readiness.catalog_trust.as_ref();
    let file = readiness.provider_file_identity.as_ref();
    let protocol = readiness.cli_protocol.as_ref();
    if package.is_none_or(|value| {
        value.name != "MicrosoftWindows.WindowsSandbox"
            || value.family_name != "MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy"
            || value.publisher_id != "cw5n1h2txyewy"
            || value.architecture != "x64"
            || value.signature_kind != "store"
            || !value.status_ok
    }) || catalog.is_none_or(|value| {
        value.trust_kind != "catalogMember"
            || value.verification_status != aiw_probe::ReadinessState::Available
            || value.trust_policy != "cacheOnlyWholeChainExcludeRoot"
    }) || file.is_none_or(|value| {
        !value
            .final_path
            .eq_ignore_ascii_case(&reported.canonical_path)
            || !fixed_lower_hex(&value.volume_serial_number, 8)
            || !fixed_lower_hex(&value.file_id, 16)
    }) || protocol.is_none_or(|value| {
        value.cli_version != "0.8.107.0"
            || value.protocol != "windowsSandboxCli/v0.8.107.0"
            || value.list_schema != "WindowsSandboxEnvironments/Id"
    }) {
        return Err(RunnerError::Readiness(
            "required package, catalog, file, or CLI protocol authority is absent".to_owned(),
        ));
    }
    Ok(())
}

fn revalidate_workspace(
    request: &WsbGoldenProbeStart,
    workspace: &impl WorkspaceBoundary,
) -> Result<(), RunnerError> {
    if workspace.evidence() != &request.workspace {
        return Err(RunnerError::Drift);
    }
    workspace.revalidate()
}

fn validate_workspace_paths(
    request: &WsbGoldenProbeStart,
    tools: &aiw_provider_wsb::MappedFolder,
    output: &aiw_provider_wsb::MappedFolder,
) -> Result<(), RunnerError> {
    let evidence = &request.workspace;
    if !same_windows_path(&request.run_root, &evidence.root.final_path)
        || !same_windows_path(&tools.host_folder, &evidence.tools.final_path)
        || !same_windows_path(&output.host_folder, &evidence.output.final_path)
        || !Path::new(&evidence.root.final_path)
            .parent()
            .is_some_and(|path| same_windows_path(path, &evidence.parent.final_path))
        || !Path::new(&evidence.tools.final_path)
            .parent()
            .is_some_and(|path| same_windows_path(path, &evidence.root.final_path))
        || !Path::new(&evidence.output.final_path)
            .parent()
            .is_some_and(|path| same_windows_path(path, &evidence.root.final_path))
    {
        return Err(RunnerError::Drift);
    }
    Ok(())
}

fn same_windows_path(left: impl AsRef<Path>, right: impl AsRef<Path>) -> bool {
    fn normalize(path: &Path) -> String {
        let value = path.to_string_lossy();
        value
            .strip_prefix("\\\\?\\")
            .unwrap_or(&value)
            .trim_end_matches(['\\', '/'])
            .to_owned()
    }
    normalize(left.as_ref()).eq_ignore_ascii_case(&normalize(right.as_ref()))
}

fn fixed_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn cancellation_requested(layout: &RunLayout) -> Result<bool, RunnerError> {
    Ok(matches!(
        layout.status().map_err(journal_error)?,
        aiw_orchestrator::RecoveryStatus::CancellationRequested { .. }
    ))
}

fn revalidate_project_revision(plan: &RunPlan, path: &Path) -> Result<(), RunnerError> {
    ensure_no_reparse_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| RunnerError::Drift)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16 * 1024 * 1024
    {
        return Err(RunnerError::Drift);
    }
    let file = File::open(path).map_err(|_| RunnerError::Drift)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RunnerError::Drift)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(RunnerError::Drift);
    }
    let project: Project = match path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => serde_json::from_slice(&bytes).map_err(|_| RunnerError::Drift)?,
        Some("yaml") | Some("yml") => {
            serde_yaml::from_slice(&bytes).map_err(|_| RunnerError::Drift)?
        }
        _ => return Err(RunnerError::Drift),
    };
    if project.metadata.name != plan.project_id
        || project_revision_hash(&project).map_err(journal_error)? != plan.project_revision_hash
    {
        return Err(RunnerError::Drift);
    }
    Ok(())
}

fn canonical_hash(value: &impl Serialize) -> Result<String, RunnerError> {
    let value = serde_json::to_value(value).map_err(|_| RunnerError::Drift)?;
    let bytes = aiw_evidence::canonical_json_bytes(&value).map_err(|_| RunnerError::Drift)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn revalidate_identity(identity: &BinaryIdentity) -> Result<(), RunnerError> {
    let path = Path::new(&identity.canonical_path);
    ensure_no_reparse_components(path)?;
    let current = path.canonicalize().map_err(|_| RunnerError::Drift)?;
    let current_display = current.to_string_lossy();
    let current_display = current_display
        .strip_prefix("\\\\?\\")
        .unwrap_or(&current_display);
    if !current_display.eq_ignore_ascii_case(&identity.canonical_path) {
        return Err(RunnerError::Drift);
    }
    let mut file = File::open(path).map_err(|_| RunnerError::Drift)?;
    let metadata = file.metadata().map_err(|_| RunnerError::Drift)?;
    if !metadata.is_file() || metadata.len() != identity.size_bytes {
        return Err(RunnerError::Drift);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| RunnerError::Drift)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if hex::encode(digest.finalize()) != identity.sha256 {
        return Err(RunnerError::Drift);
    }
    ensure_no_reparse_components(path)?;
    Ok(())
}

fn mapping(
    plan: &WindowsSandboxPlan,
    purpose: MappingPurpose,
) -> Option<&aiw_provider_wsb::MappedFolder> {
    plan.mappings.iter().find(|item| item.purpose == purpose)
}
fn guest_to_host(mapping: &aiw_provider_wsb::MappedFolder, guest: &str) -> Option<PathBuf> {
    let root = mapping.sandbox_folder.trim_end_matches('\\');
    let relative = guest.strip_prefix(root)?.strip_prefix('\\')?;
    if relative.contains(['/', ':'])
        || relative
            .split('\\')
            .any(|value| value.is_empty() || matches!(value, "." | ".."))
    {
        return None;
    }
    Some(
        relative
            .split('\\')
            .fold(PathBuf::from(&mapping.host_folder), |path, segment| {
                path.join(segment)
            }),
    )
}
fn completion_expectation(
    run_id: &str,
    sandbox_id: &str,
    config: &str,
    agent: &str,
    request: &str,
) -> WindowsSandboxCompletionExpectation {
    WindowsSandboxCompletionExpectation {
        schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_COMPLETION_EXPECTATION_SCHEMA_VERSION
            .to_owned(),
        run_id: run_id.to_owned(),
        sandbox_id: sandbox_id.to_owned(),
        config_sha256: config.to_owned(),
        request_sha256: request.to_owned(),
        agent_sha256: agent.to_owned(),
        receipt_path: "completion.json".to_owned(),
        evidence_log_path: "evidence.jsonl".to_owned(),
        content_declaration: aiw_evidence::ContentDeclaration::NoKnownSecrets,
        artifacts: vec![
            CompletionArtifactExpectation {
                path: "token.json".to_owned(),
                role: aiw_evidence::ArtifactRole::TokenEvidence,
                sensitivity: aiw_evidence::DataSensitivity::Internal,
                media_type: "application/json".to_owned(),
                maximum_bytes: 1024 * 1024,
            },
            CompletionArtifactExpectation {
                path: "evidence.jsonl".to_owned(),
                role: aiw_evidence::ArtifactRole::EvidenceLog,
                sensitivity: aiw_evidence::DataSensitivity::Internal,
                media_type: "application/x-ndjson".to_owned(),
                maximum_bytes: 1024 * 1024,
            },
        ],
    }
}
fn progress(layout: &RunLayout, detail: &str) -> Result<(), RunnerError> {
    layout
        .append_event(
            RunEvent::new(RunEventKind::Progress, "provider-time-not-trusted", detail)
                .map_err(journal_error)?,
        )
        .map_err(journal_error)
        .map(|_| ())
}
fn bounded_process_result(result: ProcessResult) -> Result<ProcessResult, RunnerError> {
    if result.stdout.len() > MAX_PROVIDER_OUTPUT || result.stderr.len() > MAX_PROVIDER_ERROR {
        return Err(RunnerError::ProviderOutputTooLarge);
    }
    Ok(result)
}
fn ensure_success(result: &ProcessResult) -> Result<(), RunnerError> {
    bounded_process_result(result.clone())?;
    if result.exit_code == 0 && result.stderr.is_empty() {
        Ok(())
    } else {
        Err(RunnerError::ProviderFailure)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartResponse {
    #[serde(rename = "Id")]
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListResponse {
    #[serde(rename = "WindowsSandboxEnvironments")]
    sessions: Vec<SessionResponse>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionResponse {
    #[serde(rename = "Id")]
    id: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedSession {
    id: String,
}
fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}
fn response_id(bytes: &[u8]) -> Result<String, RunnerError> {
    if bytes.len() > MAX_PROVIDER_OUTPUT {
        return Err(RunnerError::ProviderOutputTooLarge);
    }
    let response: StartResponse =
        serde_json::from_slice(bytes).map_err(|_| RunnerError::ProviderJson)?;
    if !valid_uuid(&response.id) {
        return Err(RunnerError::ProviderJson);
    }
    Ok(response.id.to_ascii_lowercase())
}
fn sessions(bytes: ProcessResult) -> Result<Vec<ObservedSession>, RunnerError> {
    ensure_success(&bytes)?;
    if bytes.stdout.len() > MAX_PROVIDER_OUTPUT {
        return Err(RunnerError::ProviderOutputTooLarge);
    }
    let response: ListResponse =
        serde_json::from_slice(&bytes.stdout).map_err(|_| RunnerError::ProviderJson)?;
    if response.sessions.len() > 16 {
        return Err(RunnerError::ProviderOutputTooLarge);
    }
    let mut ids = std::collections::BTreeSet::new();
    response
        .sessions
        .into_iter()
        .map(|session| {
            if !valid_uuid(&session.id) {
                return Err(RunnerError::ProviderJson);
            }
            let id = session.id.to_ascii_lowercase();
            if !ids.insert(id.clone()) {
                return Err(RunnerError::ProviderJson);
            }
            Ok(ObservedSession { id })
        })
        .collect()
}
#[cfg(test)]
fn bounded_json(bytes: &[u8]) -> Result<serde_json::Value, RunnerError> {
    if bytes.len() > MAX_PROVIDER_OUTPUT {
        return Err(RunnerError::ProviderOutputTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| RunnerError::ProviderJson)
}
fn wait_for_receipt(
    layout: &RunLayout,
    output_root: &Path,
    timeout_seconds: u32,
) -> Result<(), RunnerError> {
    let receipt = output_root.join("completion.json");
    let failure = output_root.join("guest-failure.json");
    let deadline = Instant::now() + Duration::from_secs(u64::from(timeout_seconds));
    loop {
        if cancellation_requested(layout)? {
            return Err(RunnerError::Cancelled);
        }
        if receipt.exists() {
            return Ok(());
        }
        if failure.exists() {
            let detail = read_guest_failure_diagnostic(&failure)
                .unwrap_or_else(|_| "guest failure diagnostic was rejected".to_owned());
            return Err(RunnerError::Receipt(detail));
        }
        if Instant::now() >= deadline {
            return Err(RunnerError::ProviderFailure);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn read_guest_failure_diagnostic(path: &Path) -> Result<String, RunnerError> {
    parse_guest_failure_diagnostic(&read_bounded_bytes(path, MAX_GUEST_FAILURE_DIAGNOSTIC)?)
}

fn parse_guest_failure_diagnostic(bytes: &[u8]) -> Result<String, RunnerError> {
    if bytes.len() as u64 > MAX_GUEST_FAILURE_DIAGNOSTIC {
        return Err(RunnerError::Drift);
    }
    let diagnostic: GuestFailureDiagnostic =
        serde_json::from_slice(bytes).map_err(|_| RunnerError::Drift)?;
    if diagnostic.schema_version != "aiw.dev/wsb-guest-failure/v0alpha1"
        || diagnostic.code != "AIW_GUEST_AGENT_FAILED"
        || diagnostic.summary.is_empty()
        || diagnostic.summary.chars().count() > 2048
    {
        return Err(RunnerError::Drift);
    }
    Ok(diagnostic
        .summary
        .chars()
        .map(|value| if value.is_control() { ' ' } else { value })
        .collect())
}
fn deterministic_sandbox_id(run_id: &str) -> String {
    let hash = Sha256::digest(format!("aiw-wsb-v1:{run_id}").as_bytes());
    let hex = hex::encode(hash);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
fn journal_error(error: aiw_orchestrator::AiwError) -> RunnerError {
    RunnerError::Journal(error.code.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::{BTreeMap, VecDeque},
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Root(PathBuf, bool);
    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aiw-w1-runner-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let canonical = fs::canonicalize(path).unwrap();
            let display = canonical.to_string_lossy();
            Self(
                PathBuf::from(display.strip_prefix("\\\\?\\").unwrap_or(&display)),
                false,
            )
        }

        fn preserve_on_drop(&mut self) {
            self.1 = true;
        }

        fn allow_cleanup(&mut self) {
            self.1 = false;
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            if !self.1 {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    type StartAction = Box<dyn FnOnce() + Send>;

    struct FakeProcess {
        results: Mutex<VecDeque<Result<ProcessResult, RunnerError>>>,
        start_action: Mutex<Option<StartAction>>,
        call_actions: Mutex<BTreeMap<u64, StartAction>>,
        connect_result: Mutex<Option<Result<ProcessResult, RunnerError>>>,
        calls: AtomicU64,
    }
    impl FakeProcess {
        fn new(results: Vec<Result<ProcessResult, RunnerError>>) -> Self {
            Self {
                results: Mutex::new(results.into()),
                start_action: Mutex::new(None),
                call_actions: Mutex::new(BTreeMap::new()),
                connect_result: Mutex::new(None),
                calls: AtomicU64::new(0),
            }
        }

        fn with_start_action(self, action: StartAction) -> Self {
            *self.start_action.lock().unwrap() = Some(action);
            self
        }

        fn with_call_action(self, call: u64, action: StartAction) -> Self {
            self.call_actions.lock().unwrap().insert(call, action);
            self
        }

        fn with_connect_result(self, result: Result<ProcessResult, RunnerError>) -> Self {
            *self.connect_result.lock().unwrap() = Some(result);
            self
        }
    }
    impl ProcessBoundary for FakeProcess {
        fn invoke(
            &self,
            _executable: &Path,
            arguments: &[String],
            _timeout_seconds: u32,
        ) -> Result<ProcessResult, RunnerError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(action) = self.call_actions.lock().unwrap().remove(&call) {
                action();
            }
            if arguments.first().is_some_and(|value| value == "start") {
                if let Some(action) = self.start_action.lock().unwrap().take() {
                    action();
                }
            }
            if arguments.first().is_some_and(|value| value == "connect") {
                return self
                    .connect_result
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or(Ok(ProcessResult {
                        exit_code: 0,
                        stdout: vec![],
                        stderr: vec![],
                    }));
            }
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(RunnerError::ProviderFailure))
        }
    }

    #[derive(Default)]
    struct TestLease(Mutex<()>);
    impl LeaseBoundary for TestLease {
        fn try_acquire(&self) -> Result<Box<dyn LeaseGuard + '_>, RunnerError> {
            self.0
                .try_lock()
                .map(|guard| Box::new(guard) as Box<dyn LeaseGuard>)
                .map_err(|_| RunnerError::LeaseUnavailable)
        }
    }

    struct TestWorkspace {
        evidence: WorkspaceBindingEvidence,
        calls: AtomicU64,
        fail_on_call: Option<u64>,
    }

    impl TestWorkspace {
        fn for_start(start: &WsbGoldenProbeStart) -> Self {
            Self {
                evidence: start.workspace.clone(),
                calls: AtomicU64::new(0),
                fail_on_call: None,
            }
        }
    }

    impl WorkspaceBoundary for TestWorkspace {
        fn evidence(&self) -> &WorkspaceBindingEvidence {
            &self.evidence
        }

        fn revalidate(&self) -> Result<(), RunnerError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_on_call == Some(call) {
                Err(RunnerError::Drift)
            } else {
                Ok(())
            }
        }
    }

    fn execute_wsb_golden_probe(
        request: &WsbGoldenProbeStart,
        readiness: &WindowsSandboxReadiness,
        layout: &RunLayout,
        process: &impl ProcessBoundary,
        lease: &impl LeaseBoundary,
    ) -> Result<WsbGoldenProbeExecution, RunnerError> {
        let workspace = TestWorkspace::for_start(request);
        super::execute_wsb_golden_probe(request, readiness, layout, process, lease, &workspace)
    }

    fn successful_json(value: serde_json::Value) -> Result<ProcessResult, RunnerError> {
        Ok(ProcessResult {
            exit_code: 0,
            stdout: serde_json::to_vec(&value).unwrap(),
            stderr: vec![],
        })
    }

    fn empty_list() -> Result<ProcessResult, RunnerError> {
        successful_json(serde_json::json!({"WindowsSandboxEnvironments":[]}))
    }

    fn list_with(id: &str, _state: &str) -> Result<ProcessResult, RunnerError> {
        successful_json(serde_json::json!({"WindowsSandboxEnvironments":[{"Id":id}]}))
    }

    fn started(id: &str) -> Result<ProcessResult, RunnerError> {
        successful_json(serde_json::json!({"Id":id}))
    }

    fn stopped(_id: &str) -> Result<ProcessResult, RunnerError> {
        Ok(ProcessResult {
            exit_code: 0,
            stdout: vec![],
            stderr: vec![],
        })
    }
    fn identity(path: &Path) -> BinaryIdentity {
        aiw_probe::measure_binary_identity(path).unwrap()
    }

    fn workspace_evidence(root: &Path, tools: &Path, output: &Path) -> WorkspaceBindingEvidence {
        let owner = "S-1-5-21-1".to_owned();
        let identity = |path: &Path, marker: u8| aiw_probe::WindowsFileIdentity {
            final_path: path.to_string_lossy().into_owned(),
            volume_serial_number: "0".repeat(16),
            file_id: format!("{marker:032x}"),
        };
        let evidence = WorkspaceBindingEvidence {
            schema_version: aiw_probe::WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
            policy: aiw_probe::WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
            security_policy_sha256: aiw_probe::workspace_policy_hash(&owner),
            owner_sid: owner.clone(),
            dacl_protected: true,
            allowed_sids: vec![aiw_probe::WINDOWS_SYSTEM_SID.to_owned(), owner],
            parent: identity(root.parent().unwrap(), 1),
            root: identity(root, 2),
            tools: identity(tools, 3),
            output: identity(output, 4),
        };
        evidence.validate().unwrap();
        evidence
    }
    fn setup() -> (
        Root,
        RunLayout,
        WsbGoldenProbeStart,
        WindowsSandboxReadiness,
    ) {
        let root = Root::new();
        let tools = root.0.join("tools");
        let output = root.0.join("output");
        let project_path = root.0.join("project.yaml");
        let project_source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("examples")
            .join("minimal.aiw.yaml");
        fs::copy(project_source, &project_path).unwrap();
        let project: Project = serde_yaml::from_slice(&fs::read(&project_path).unwrap()).unwrap();
        fs::create_dir(&tools).unwrap();
        fs::create_dir(&output).unwrap();
        let agent = tools.join("agent.exe");
        let provider = root.0.join("wsb.exe");
        fs::write(&agent, b"guest-agent").unwrap();
        fs::write(&provider, b"provider").unwrap();
        let wsb_plan = WindowsSandboxPlan {
            schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.to_owned(),
            workspace_root: root.0.to_string_lossy().into_owned(),
            mappings: vec![
                aiw_provider_wsb::MappedFolder {
                    purpose: MappingPurpose::Tools,
                    host_folder: tools.to_string_lossy().into_owned(),
                    sandbox_folder: "C:\\AIW\\Tools".to_owned(),
                },
                aiw_provider_wsb::MappedFolder {
                    purpose: MappingPurpose::Output,
                    host_folder: output.to_string_lossy().into_owned(),
                    sandbox_folder: "C:\\AIW\\Output".to_owned(),
                },
            ],
            probe: aiw_provider_wsb::GoldenProbe {
                executable: "C:\\AIW\\Tools\\agent.exe".to_owned(),
                request: Some("C:\\AIW\\Tools\\request.json".to_owned()),
                output: "C:\\AIW\\Output\\token.json".to_owned(),
            },
            memory_mb: Some(2048),
        };
        let mut provider_identity = identity(&provider);
        provider_identity.signature_status = aiw_probe::ReadinessState::Available;
        let workspace = workspace_evidence(&root.0, &tools, &output);
        let workspace_identity_sha256 = canonical_hash(&workspace).unwrap();
        let start = WsbGoldenProbeStart {
            schema_version: "aiw.dev/wsb-golden-probe-start/v0alpha2".to_owned(),
            run_root: wsb_plan.workspace_root.clone(),
            project_path: project_path.to_string_lossy().into_owned(),
            provider: provider_identity,
            guest_agent: identity(&agent),
            workspace,
            workspace_identity_sha256,
            wsb_plan,
            timeout_seconds: 1,
            msi: None,
        };
        let plan = RunPlan::new(
            "w1-run",
            project.metadata.name.clone(),
            project_revision_hash(&project).unwrap(),
            aiw_orchestrator::RunLifecycleKind::Assessment,
            "now",
            vec![
                PlannedAction::AssessHost,
                PlannedAction::PrepareWorkspace,
                PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                    sandbox_plan_sha256: canonical_hash(&start.wsb_plan).unwrap(),
                    provider_sha256: start.provider.sha256.clone(),
                    guest_agent_sha256: start.guest_agent.sha256.clone(),
                    workspace: Box::new(start.workspace.clone()),
                    workspace_identity_sha256: canonical_hash(&start.workspace).unwrap(),
                },
                PlannedAction::CollectEvidence,
            ],
            vec!["starts an approved Windows Sandbox golden probe".to_owned()],
        )
        .unwrap();
        let layout = RunLayout::new(&root.0, "w1-run").unwrap();
        let receipt = aiw_orchestrator::WsbPlanningImportReceipt {
            schema_version: aiw_orchestrator::WSB_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION.to_owned(),
            run_id: plan.run_id.clone(),
            imported_at: "now".to_owned(),
            status: aiw_orchestrator::WsbPlanningImportStatus::PendingApproval,
            project_revision_sha256: plan.project_revision_hash.clone(),
            workspace_root: start.workspace.root.final_path.clone(),
            workspace_identity_sha256: start.workspace_identity_sha256.clone(),
            preparation_receipt_sha256: "d".repeat(64),
            run_plan_sha256: plan.hash().unwrap(),
            windows_sandbox_plan_sha256: canonical_hash(&start.wsb_plan).unwrap(),
            guest_agent_sha256: start.guest_agent.sha256.clone(),
            provider_sha256: start.provider.sha256.clone(),
            run_root: start.workspace.root.final_path.clone(),
            journal_sequence: 1,
            approval_present: false,
            provider_acquired: false,
            provider_mutated: false,
        };
        layout
            .create_or_verify_pending_wsb_import(&plan, &receipt)
            .unwrap();
        layout
            .write_approval(&ApprovalRecord::for_plan(&plan, "admin", "now").unwrap())
            .unwrap();
        let ready = WindowsSandboxReadiness {
            schema_version: READINESS_SCHEMA.to_owned(),
            supported: true,
            os_build: Some(26100),
            process_architecture: "x86_64".to_owned(),
            virtualization: aiw_probe::ReadinessState::Available,
            sandbox_feature: aiw_probe::ReadinessState::Available,
            provider_binary: Some(start.provider.clone()),
            provider_package: Some(aiw_probe::WindowsPackageIdentity {
                name: "MicrosoftWindows.WindowsSandbox".to_owned(),
                full_name: "MicrosoftWindows.WindowsSandbox_0.8.107.0_x64__cw5n1h2txyewy"
                    .to_owned(),
                family_name: "MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy".to_owned(),
                publisher:
                    "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                        .to_owned(),
                publisher_id: "cw5n1h2txyewy".to_owned(),
                version: "0.8.107.0".to_owned(),
                architecture: "x64".to_owned(),
                signature_kind: "store".to_owned(),
                status_ok: true,
                install_location: root.0.to_string_lossy().into_owned(),
            }),
            catalog_trust: Some(aiw_probe::CatalogTrustIdentity {
                trust_kind: "catalogMember".to_owned(),
                catalog_path: root
                    .0
                    .join("CodeIntegrity.cat")
                    .to_string_lossy()
                    .into_owned(),
                catalog_sha256: "0".repeat(64),
                catalog_file_identity: aiw_probe::WindowsFileIdentity {
                    final_path: root
                        .0
                        .join("CodeIntegrity.cat")
                        .to_string_lossy()
                        .into_owned(),
                    volume_serial_number: "00000000".to_owned(),
                    file_id: "0000000000000000".to_owned(),
                },
                member_tag: "0".repeat(64),
                trust_policy: "cacheOnlyWholeChainExcludeRoot".to_owned(),
                verification_status: aiw_probe::ReadinessState::Available,
            }),
            provider_file_identity: Some(aiw_probe::WindowsFileIdentity {
                final_path: start.provider.canonical_path.clone(),
                volume_serial_number: "00000000".to_owned(),
                file_id: "0000000000000000".to_owned(),
            }),
            cli_protocol: Some(aiw_probe::WindowsSandboxCliProtocol {
                cli_version: "0.8.107.0".to_owned(),
                protocol: "windowsSandboxCli/v0.8.107.0".to_owned(),
                list_schema: "WindowsSandboxEnvironments/Id".to_owned(),
            }),
            app_execution_alias: None,
            current_sessions: aiw_probe::ReadinessState::Available,
            current_session_ids: vec![],
            blockers: vec![],
            warnings: vec![],
        };
        (root, layout, start, ready)
    }

    fn request_for(start: &WsbGoldenProbeStart) -> GuestRequest {
        let rendered = render_config(&start.wsb_plan).unwrap();
        let output = mapping(&start.wsb_plan, MappingPurpose::Output).unwrap();
        GuestRequest::new(
            "w1-run",
            &deterministic_sandbox_id("w1-run"),
            &rendered.sha256,
            &start.guest_agent.sha256,
            &output.sandbox_folder,
        )
        .unwrap()
    }

    fn request_path(start: &WsbGoldenProbeStart) -> PathBuf {
        let tools = mapping(&start.wsb_plan, MappingPurpose::Tools).unwrap();
        guest_to_host(tools, start.wsb_plan.probe.request.as_ref().unwrap()).unwrap()
    }

    fn write_valid_completion(start: &WsbGoldenProbeStart) {
        let rendered = render_config(&start.wsb_plan).unwrap();
        let request = request_for(start);
        let output = PathBuf::from(
            &mapping(&start.wsb_plan, MappingPurpose::Output)
                .unwrap()
                .host_folder,
        );
        let token = b"{\"goldenTokenProbe\":true}\n".to_vec();
        publish_test_file(&output.join("token.json"), &token);

        let mut evidence = aiw_evidence::EvidenceLog::new();
        evidence
            .append(aiw_evidence::EvidenceEvent {
                observed_utc: "guest-time-not-trusted".to_owned(),
                kind: "goldenTokenProbe".to_owned(),
                source: "test-guest-agent".to_owned(),
                payload: serde_json::json!({"collected":true}),
            })
            .unwrap();
        let mut evidence_bytes = Vec::new();
        for record in evidence.records() {
            serde_json::to_writer(&mut evidence_bytes, record).unwrap();
            evidence_bytes.push(b'\n');
        }
        publish_test_file(&output.join("evidence.jsonl"), &evidence_bytes);
        let artifact = |path: &str,
                        role: aiw_evidence::ArtifactRole,
                        media_type: &str,
                        bytes: &[u8]| aiw_provider_wsb::CompletionArtifact {
            path: path.to_owned(),
            role,
            media_type: media_type.to_owned(),
            size_bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        let receipt = aiw_provider_wsb::WindowsSandboxCompletionReceipt {
            schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION
                .to_owned(),
            run_id: "w1-run".to_owned(),
            sandbox_id: deterministic_sandbox_id("w1-run"),
            config_sha256: rendered.sha256,
            request_sha256: request.request_sha256,
            agent_sha256: start.guest_agent.sha256.clone(),
            status: aiw_provider_wsb::CompletionStatus::Succeeded,
            exit_code: 0,
            evidence_root_hash: evidence.manifest().unwrap().root_hash,
            artifacts: vec![
                artifact(
                    "token.json",
                    aiw_evidence::ArtifactRole::TokenEvidence,
                    "application/json",
                    &token,
                ),
                artifact(
                    "evidence.jsonl",
                    aiw_evidence::ArtifactRole::EvidenceLog,
                    "application/x-ndjson",
                    &evidence_bytes,
                ),
            ],
        };
        let mut receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        receipt_bytes.push(b'\n');
        publish_test_file(&output.join("completion.json"), &receipt_bytes);
    }

    fn publish_test_file(path: &Path, bytes: &[u8]) {
        let name = path.file_name().unwrap().to_string_lossy();
        let pending = path.with_file_name(format!("{name}.pending"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        fs::hard_link(&pending, path).unwrap();
        fs::remove_file(pending).unwrap();
    }

    fn success_process(start: &WsbGoldenProbeStart) -> FakeProcess {
        let id = deterministic_sandbox_id("w1-run");
        let output_start = start.clone();
        FakeProcess::new(vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ])
        .with_start_action(Box::new(move || write_valid_completion(&output_start)))
    }

    #[test]
    fn bounded_provider_json_rejects_malformed_and_oversized_data() {
        assert!(matches!(
            bounded_json(b"not-json"),
            Err(RunnerError::ProviderJson)
        ));
        assert!(matches!(
            bounded_json(&vec![b' '; MAX_PROVIDER_OUTPUT + 1]),
            Err(RunnerError::ProviderOutputTooLarge)
        ));
    }

    #[test]
    fn guest_failure_diagnostic_is_bounded_strict_and_sanitized() {
        let (_root, layout, start, _readiness) = setup();
        let output = PathBuf::from(
            &mapping(&start.wsb_plan, MappingPurpose::Output)
                .unwrap()
                .host_folder,
        );
        let failure = output.join("guest-failure.json");
        fs::write(
            &failure,
            vec![b'a'; (MAX_GUEST_FAILURE_DIAGNOSTIC + 1) as usize],
        )
        .unwrap();
        assert!(matches!(
            wait_for_receipt(&layout, &output, 0),
            Err(RunnerError::Receipt(detail)) if detail == "guest failure diagnostic was rejected"
        ));
        fs::remove_file(&failure).unwrap();
        fs::write(
            &failure,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": "aiw.dev/wsb-guest-failure/v0alpha1",
                "code": "AIW_GUEST_AGENT_FAILED",
                "summary": "bounded\r\ndetail"
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            wait_for_receipt(&layout, &output, 0),
            Err(RunnerError::Receipt(detail)) if detail == "bounded  detail"
        ));
    }
    #[test]
    fn deterministic_session_id_is_uuid_shaped() {
        let id = deterministic_sandbox_id("run-one");
        assert_eq!(id.len(), 36);
        assert_eq!(id, deterministic_sandbox_id("run-one"));
    }

    #[cfg(windows)]
    #[test]
    fn native_provider_coordination_errors_preserve_recovery_semantics() {
        assert!(matches!(
            native_invocation_error(
                aiw_windows_platform::WindowsSandboxInvocationError::LeaseUnavailable
            ),
            RunnerError::LeaseUnavailable
        ));
        assert!(matches!(
            native_invocation_error(
                aiw_windows_platform::WindowsSandboxInvocationError::RecoveryRequired
            ),
            RunnerError::RecoveryRequired(_)
        ));
    }

    #[test]
    fn session_status_is_validated_and_observational() {
        let (_root, layout, start, readiness) = setup();
        let absent = observe_wsb_session_status(&layout).unwrap();
        assert_eq!(absent.status, WsbSessionDisposition::None);

        let context = prepare_execution(&start, &readiness, &layout, false).unwrap();
        let store = TransactionStore::new(&layout, context.binding);
        store.create("approved-start").unwrap();
        let active = observe_wsb_session_status(&layout).unwrap();
        assert_eq!(active.status, WsbSessionDisposition::RecoveryRequired);
        assert_eq!(
            active.current_state,
            Some(SessionTransactionState::StartIntent)
        );
        store
            .transition(SessionTransactionState::Unknown, "start-response-lost")
            .unwrap();
        store
            .transition(SessionTransactionState::CleanupIntent, "cleanup-attempt")
            .unwrap();
        store
            .transition(SessionTransactionState::CleanupVerified, "cleanup-verified")
            .unwrap();
        let clean = observe_wsb_session_status(&layout).unwrap();
        assert_eq!(clean.status, WsbSessionDisposition::Clean);

        let directory = layout.run_dir().join("wsb-session-transaction");
        let pending = directory.join("00000000000000000005.json.pending");
        fs::write(&pending, b"interrupted").unwrap();
        let before = fs::read(&pending).unwrap();
        let recovery = observe_wsb_session_status(&layout).unwrap();
        assert_eq!(recovery.status, WsbSessionDisposition::RecoveryRequired);
        assert_eq!(fs::read(pending).unwrap(), before);

        fs::remove_file(layout.approval_path()).unwrap();
        assert!(matches!(
            observe_wsb_session_status(&layout),
            Err(RunnerError::Journal(_))
        ));
    }
    #[test]
    fn guest_mapping_cannot_escape_tools_root() {
        let mapping = aiw_provider_wsb::MappedFolder {
            purpose: MappingPurpose::Tools,
            host_folder: "C:\\root\\tools".to_owned(),
            sandbox_folder: "C:\\AIW\\Tools".to_owned(),
        };
        assert!(guest_to_host(&mapping, "C:\\AIW\\Tools\\request.json").is_some());
        assert!(guest_to_host(&mapping, "C:\\AIW\\Tools\\..\\out.json").is_none());
    }

    #[test]
    fn recovery_request_absence_requires_exact_not_found() {
        let root = Root::new();
        let missing = root.0.join("missing-request.json");
        assert!(!recovery_request_present(&missing).unwrap());

        let directory = root.0.join("request-directory");
        fs::create_dir(&directory).unwrap();
        assert!(matches!(
            recovery_request_present(&directory),
            Err(RunnerError::Drift)
        ));

        let dangling = root.0.join("dangling-request.json");
        #[cfg(windows)]
        let link_created =
            std::os::windows::fs::symlink_file(root.0.join("absent-target.json"), &dangling)
                .is_ok();
        #[cfg(unix)]
        let link_created = {
            std::os::unix::fs::symlink(root.0.join("absent-target.json"), &dangling).unwrap();
            true
        };
        if link_created {
            assert!(matches!(
                recovery_request_present(&dangling),
                Err(RunnerError::Drift)
            ));
        }
    }

    #[test]
    fn refuses_preexisting_unknown_session_before_start() {
        let (_root, layout, start, readiness) = setup();
        let other = "11111111-1111-1111-1111-111111111111";
        let fake = FakeProcess::new(vec![list_with(other, "running")]);
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::SessionConflict), "{error:?}");
        assert!(!request_path(&start).exists());
    }

    #[test]
    fn malformed_and_duplicate_provider_responses_fail_closed() {
        let (_root, layout, start, readiness) = setup();
        let malformed =
            FakeProcess::new(vec![successful_json(serde_json::json!({"unexpected":[]}))]);
        let error = execute_wsb_golden_probe(
            &start,
            &readiness,
            &layout,
            &malformed,
            &TestLease::default(),
        )
        .unwrap_err();
        assert!(matches!(error, RunnerError::ProviderJson), "{error:?}");

        let id = deterministic_sandbox_id("w1-run");
        let duplicate = sessions(
            successful_json(serde_json::json!({"WindowsSandboxEnvironments":[
                {"Id":id},{"Id":id}
            ]}))
            .unwrap(),
        );
        assert!(matches!(duplicate, Err(RunnerError::ProviderJson)));
    }

    #[test]
    fn malformed_start_response_is_cleaned_before_failure_is_terminal() {
        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let fake = FakeProcess::new(vec![
            empty_list(),
            successful_json(serde_json::json!({"Id":id,"unexpected":true})),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ]);
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::ProviderJson));
        let context = prepare_execution(&start, &readiness, &layout, false).unwrap();
        let transaction = TransactionStore::new(&layout, context.binding)
            .load_current()
            .unwrap()
            .unwrap();
        assert_eq!(
            transaction.current_state(),
            SessionTransactionState::CleanupVerified
        );
        assert!(layout.result_path().exists());
    }

    #[test]
    fn mismatched_session_is_never_stopped() {
        let (_root, layout, start, readiness) = setup();
        let other = "11111111-1111-1111-1111-111111111111";
        let fake = FakeProcess::new(vec![
            empty_list(),
            started(other),
            list_with(other, "running"),
            list_with(other, "running"),
        ]);
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::RecoveryRequired(_)));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 4);
        assert!(!layout.result_path().exists());
    }

    #[test]
    fn true_fake_end_to_end_success_verifies_receipt_after_cleanup() {
        let (_root, layout, start, readiness) = setup();
        let fake = success_process(&start);
        let execution =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap();
        assert!(execution.cleanup_complete);
        assert_eq!(execution.workspace, start.workspace);
        assert_eq!(
            execution.workspace_identity_sha256,
            start.workspace_identity_sha256
        );
        assert!(!request_path(&start).exists());
        let store = TransactionStore::new(
            &layout,
            prepare_execution(&start, &readiness, &layout, false)
                .unwrap()
                .binding,
        );
        let transaction = store.load_current().unwrap().unwrap();
        assert_eq!(
            transaction.current_state(),
            SessionTransactionState::CleanupVerified
        );
        assert!(layout.result_path().exists());
    }

    #[test]
    fn workspace_approval_and_live_guard_drift_fail_before_provider_start() {
        let (_root, layout, mut start, readiness) = setup();
        start.workspace.output.file_id = "9".repeat(32);
        start.workspace_identity_sha256 = canonical_hash(&start.workspace).unwrap();
        let none = FakeProcess::new(vec![]);
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &none, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::ApprovalBinding));
        assert_eq!(none.calls.load(Ordering::SeqCst), 0);

        let (_root, layout, start, readiness) = setup();
        let none = FakeProcess::new(vec![]);
        let workspace = TestWorkspace {
            evidence: start.workspace.clone(),
            calls: AtomicU64::new(0),
            fail_on_call: Some(1),
        };
        let error = super::execute_wsb_golden_probe(
            &start,
            &readiness,
            &layout,
            &none,
            &TestLease::default(),
            &workspace,
        )
        .unwrap_err();
        assert!(matches!(error, RunnerError::Drift));
        assert_eq!(none.calls.load(Ordering::SeqCst), 0);
        assert!(!layout.run_dir().join("wsb-session-transaction").exists());

        let (_root, layout, start, readiness) = setup();
        let none = FakeProcess::new(vec![empty_list()]);
        let workspace = TestWorkspace {
            evidence: start.workspace.clone(),
            calls: AtomicU64::new(0),
            fail_on_call: Some(2),
        };
        let error = super::execute_wsb_golden_probe(
            &start,
            &readiness,
            &layout,
            &none,
            &TestLease::default(),
            &workspace,
        )
        .unwrap_err();
        assert!(matches!(error, RunnerError::Drift));
        assert_eq!(none.calls.load(Ordering::SeqCst), 1);
        assert!(!request_path(&start).exists());
        assert!(!layout.run_dir().join("wsb-session-transaction").exists());
        let result = layout.read_result().unwrap();
        assert_eq!(result.outcome, RunOutcome::Failed);
        assert!(!result.cleanup_complete);
        assert!(result.summary.contains("before provider start"));

        let (_root, layout, start, readiness) = setup();
        let fake = success_process(&start);
        let workspace = TestWorkspace {
            evidence: start.workspace.clone(),
            calls: AtomicU64::new(0),
            fail_on_call: Some(3),
        };
        let error = super::execute_wsb_golden_probe(
            &start,
            &readiness,
            &layout,
            &fake,
            &TestLease::default(),
            &workspace,
        )
        .unwrap_err();
        assert!(matches!(error, RunnerError::Drift));
        assert_eq!(
            observe_wsb_session_status(&layout).unwrap().status,
            WsbSessionDisposition::Clean
        );
        assert!(layout.result_path().exists());
    }

    #[test]
    fn runner_timeout_stops_and_confirms_absence_before_terminal_failure() {
        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let fake = FakeProcess::new(vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ]);
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::ProviderFailure));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 7);
        assert_eq!(
            observe_wsb_session_status(&layout).unwrap().status,
            WsbSessionDisposition::Clean
        );
        assert!(layout.result_path().exists());
    }

    #[test]
    fn post_start_list_failure_is_cleaned_before_result() {
        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let fake = FakeProcess::new(vec![
            empty_list(),
            started(&id),
            Err(RunnerError::ProviderFailure),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ]);
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::ProviderFailure));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 6);
        assert_eq!(
            observe_wsb_session_status(&layout).unwrap().status,
            WsbSessionDisposition::Clean
        );
        assert!(layout.result_path().exists());
    }

    #[test]
    fn connect_failure_is_cleaned_before_result() {
        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let fake = FakeProcess::new(vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ])
        .with_connect_result(Err(RunnerError::ProviderFailure));
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::ProviderFailure));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 7);
        assert_eq!(
            observe_wsb_session_status(&layout).unwrap().status,
            WsbSessionDisposition::Clean
        );
        assert!(layout.result_path().exists());
    }

    #[test]
    fn invalid_receipt_and_unexpected_output_fail_after_cleanup() {
        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let output = PathBuf::from(
            &mapping(&start.wsb_plan, MappingPurpose::Output)
                .unwrap()
                .host_folder,
        );
        let invalid = FakeProcess::new(vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ])
        .with_start_action(Box::new(move || {
            publish_test_file(&output.join("completion.json"), b"{}\n");
        }));
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &invalid, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::Receipt(_)));
        assert_eq!(
            observe_wsb_session_status(&layout).unwrap().status,
            WsbSessionDisposition::Clean
        );

        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let completion_start = start.clone();
        let output = PathBuf::from(
            &mapping(&start.wsb_plan, MappingPurpose::Output)
                .unwrap()
                .host_folder,
        );
        let unexpected = FakeProcess::new(vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ])
        .with_start_action(Box::new(move || {
            write_valid_completion(&completion_start);
            publish_test_file(&output.join("unexpected.bin"), b"unexpected");
        }));
        let error = execute_wsb_golden_probe(
            &start,
            &readiness,
            &layout,
            &unexpected,
            &TestLease::default(),
        )
        .unwrap_err();
        assert!(matches!(error, RunnerError::Receipt(_)));
        assert_eq!(
            observe_wsb_session_status(&layout).unwrap().status,
            WsbSessionDisposition::Clean
        );
    }

    #[test]
    fn final_verification_and_result_follow_stop_and_absence() {
        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let completion_start = start.clone();
        let output = PathBuf::from(
            &mapping(&start.wsb_plan, MappingPurpose::Output)
                .unwrap()
                .host_folder,
        );
        let gate = output.join("verification-gate.tmp");
        let gate_for_start = gate.clone();
        let result_at_stop = layout.result_path();
        let result_at_absence = layout.result_path();
        let fake = FakeProcess::new(vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ])
        .with_start_action(Box::new(move || {
            write_valid_completion(&completion_start);
            publish_test_file(&gate_for_start, b"blocks-early-verification");
        }))
        .with_call_action(
            5,
            Box::new(move || assert!(!result_at_stop.exists(), "result preceded exact stop")),
        )
        .with_call_action(
            6,
            Box::new(move || {
                assert!(!result_at_absence.exists(), "result preceded final absence");
                fs::remove_file(&gate).unwrap();
            }),
        );
        execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
            .unwrap();
        assert!(layout.result_path().exists());
    }

    #[test]
    fn start_success_with_response_loss_requires_then_completes_recovery() {
        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let failed = FakeProcess::new(vec![
            empty_list(),
            Err(RunnerError::ProviderFailure),
            list_with(&id, "running"),
            Err(RunnerError::ProviderFailure),
            list_with(&id, "running"),
        ]);
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &failed, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::RecoveryRequired(_)));
        assert!(!layout.result_path().exists());

        let recovery =
            FakeProcess::new(vec![list_with(&id, "running"), stopped(&id), empty_list()]);
        let transaction = recover_wsb_session(
            &start,
            &readiness,
            &layout,
            &recovery,
            &TestLease::default(),
        )
        .unwrap();
        assert_eq!(
            transaction.current_state(),
            SessionTransactionState::CleanupVerified
        );
        assert!(!request_path(&start).exists());
        assert!(layout.result_path().exists());
    }

    #[test]
    fn stop_failure_requires_recovery_before_output_is_trusted() {
        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let output_start = start.clone();
        let failed = FakeProcess::new(vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            Err(RunnerError::ProviderFailure),
            list_with(&id, "running"),
        ])
        .with_start_action(Box::new(move || write_valid_completion(&output_start)));
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &failed, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::RecoveryRequired(_)));
        assert!(!layout.result_path().exists());

        let recovery =
            FakeProcess::new(vec![list_with(&id, "running"), stopped(&id), empty_list()]);
        recover_wsb_session(
            &start,
            &readiness,
            &layout,
            &recovery,
            &TestLease::default(),
        )
        .unwrap();
        assert!(layout.result_path().exists());
    }

    #[test]
    fn verified_recovery_terminalizes_interrupted_completion_without_trusting_guest_output() {
        for cancelled in [false, true] {
            let (_root, layout, start, readiness) = setup();
            let context = prepare_execution(&start, &readiness, &layout, false).unwrap();
            let store = TransactionStore::new(&layout, context.binding);
            store.create("approved-start").unwrap();
            store
                .transition(SessionTransactionState::Active, "started")
                .unwrap();
            store
                .transition(SessionTransactionState::CleanupIntent, "cleanup-attempt")
                .unwrap();
            store
                .transition(SessionTransactionState::CleanupVerified, "cleanup-verified")
                .unwrap();
            // A crash after cleanup can leave unprocessed guest artifacts.
            let output = context.output_root.join("completion.json");
            fs::write(&output, b"untrusted incomplete guest output").unwrap();
            if cancelled {
                layout.request_cancellation("admin", "now").unwrap();
            }
            terminalize_verified_wsb_recovery(&layout, &store).unwrap();
            let result = layout.read_result().unwrap();
            assert_eq!(
                result.outcome,
                if cancelled {
                    RunOutcome::Cancelled
                } else {
                    RunOutcome::Failed
                }
            );
            assert!(result.cleanup_complete);
            assert!(result.evidence_root.is_none());
            assert_eq!(result.completed_at, "recovery-time-not-trusted");
            assert!(matches!(
                layout.status().unwrap(),
                aiw_orchestrator::RecoveryStatus::Terminal { .. }
            ));
            let journal_before = fs::read(layout.journal_path()).unwrap();
            let result_before = fs::read(layout.result_path()).unwrap();
            terminalize_verified_wsb_recovery(&layout, &store).unwrap();
            assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_before);
            assert_eq!(fs::read(layout.result_path()).unwrap(), result_before);
            assert_eq!(
                fs::read(output).unwrap(),
                b"untrusted incomplete guest output"
            );
        }
    }

    #[test]
    fn recovery_terminalization_requires_complete_current_authority() {
        for legacy in [false, true] {
            let (_root, layout, start, readiness) = setup();
            let mut context = prepare_execution(&start, &readiness, &layout, false).unwrap();
            if legacy {
                context.binding.recovery = None;
            }
            let store = TransactionStore::new(&layout, context.binding);
            assert!(terminalize_verified_wsb_recovery(&layout, &store).is_err());
            if legacy {
                store.seed_legacy_for_test().unwrap();
            } else {
                store.create("approved-start").unwrap();
            }
            assert!(terminalize_verified_wsb_recovery(&layout, &store).is_err());
            store
                .transition(SessionTransactionState::Active, "started")
                .unwrap();
            assert!(terminalize_verified_wsb_recovery(&layout, &store).is_err());
            store
                .transition(SessionTransactionState::CleanupIntent, "cleanup-attempt")
                .unwrap();
            assert!(terminalize_verified_wsb_recovery(&layout, &store).is_err());
            assert!(!layout.result_path().exists());
            store
                .transition(SessionTransactionState::CleanupVerified, "cleanup-verified")
                .unwrap();
            if legacy {
                assert!(terminalize_verified_wsb_recovery(&layout, &store).is_err());
                assert!(!layout.result_path().exists());
                let status = observe_wsb_session_status(&layout).unwrap();
                assert_eq!(status.status, WsbSessionDisposition::RecoveryRequired);
                assert_eq!(
                    status.reason_code.as_deref(),
                    Some("legacy-request-location-unavailable")
                );
            } else {
                terminalize_verified_wsb_recovery(&layout, &store).unwrap();
            }
        }
    }

    #[test]
    fn recovery_preserves_an_existing_terminal_result() {
        let (_root, layout, start, readiness) = setup();
        execute_wsb_golden_probe(
            &start,
            &readiness,
            &layout,
            &success_process(&start),
            &TestLease::default(),
        )
        .unwrap();
        let context = prepare_execution(&start, &readiness, &layout, false).unwrap();
        let store = TransactionStore::new(&layout, context.binding);
        let result_before = fs::read(layout.result_path()).unwrap();
        let journal_before = fs::read(layout.journal_path()).unwrap();
        terminalize_verified_wsb_recovery(&layout, &store).unwrap();
        assert_eq!(fs::read(layout.result_path()).unwrap(), result_before);
        assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_before);
        assert_eq!(
            layout.read_result().unwrap().outcome,
            RunOutcome::InsufficientEvidence
        );
    }

    #[test]
    fn prestart_cancellation_does_not_claim_exact_session_cleanup() {
        let (_root, layout, start, readiness) = setup();
        layout.request_cancellation("admin", "now").unwrap();
        let none = FakeProcess::new(vec![]);
        assert!(matches!(
            execute_wsb_golden_probe(&start, &readiness, &layout, &none, &TestLease::default()),
            Err(RunnerError::Cancelled)
        ));
        assert_eq!(none.calls.load(Ordering::SeqCst), 0);
        assert!(!layout.run_dir().join("wsb-session-transaction").exists());
        let result = layout.read_result().unwrap();
        assert_eq!(result.outcome, RunOutcome::Cancelled);
        assert!(!result.cleanup_complete);
        assert!(result.summary.contains("before provider start"));
    }

    #[test]
    fn prestart_cancellation_cannot_finalize_an_earlier_provider_attempt() {
        let (_root, layout, start, readiness) = setup();
        let context = prepare_execution(&start, &readiness, &layout, false).unwrap();
        let store = TransactionStore::new(&layout, context.binding);
        store.create("approved-start").unwrap();
        store
            .transition(SessionTransactionState::Active, "started")
            .unwrap();
        layout.request_cancellation("admin", "now").unwrap();
        let none = FakeProcess::new(vec![]);
        assert!(matches!(
            execute_wsb_golden_probe(&start, &readiness, &layout, &none, &TestLease::default()),
            Err(RunnerError::RecoveryRequired(_))
        ));
        assert_eq!(none.calls.load(Ordering::SeqCst), 0);
        assert!(!layout.result_path().exists());
        assert_eq!(
            store.load_current().unwrap().unwrap().current_state(),
            SessionTransactionState::Active
        );
    }

    #[test]
    fn cancellation_after_start_still_performs_exact_cleanup() {
        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let cancel_layout = layout.clone();
        let fake = FakeProcess::new(vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ])
        .with_start_action(Box::new(move || {
            cancel_layout.request_cancellation("admin", "now").unwrap();
        }));
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::Cancelled));
        let result: RunResult = read_bounded_json(&layout.result_path(), 64 * 1024).unwrap();
        assert_eq!(result.outcome, RunOutcome::Cancelled);
        assert!(result.cleanup_complete);
    }

    #[test]
    fn run_journal_failure_after_start_does_not_skip_provider_cleanup() {
        let (_root, layout, start, readiness) = setup();
        let id = deterministic_sandbox_id("w1-run");
        let journal = layout.journal_path();
        let fake = FakeProcess::new(vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ])
        .with_start_action(Box::new(move || {
            let mut file = OpenOptions::new().append(true).open(journal).unwrap();
            file.write_all(b"corrupt\n").unwrap();
            file.sync_all().unwrap();
        }));
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(matches!(error, RunnerError::Journal(_)));
        assert!(matches!(
            prepare_execution(&start, &readiness, &layout, false),
            Err(RunnerError::Journal(_))
        ));
        let directory = layout.run_dir().join("wsb-session-transaction");
        let last = fs::read_dir(directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|value| value == "json")
            })
            .max_by_key(|entry| entry.file_name())
            .unwrap()
            .path();
        let transaction: SessionTransaction = read_bounded_json(&last, 64 * 1024).unwrap();
        assert_eq!(
            transaction.current_state(),
            SessionTransactionState::CleanupVerified
        );
        assert!(!request_path(&start).exists());
    }

    #[test]
    fn validated_request_and_staging_are_cleaned_on_retry() {
        let (_root, layout, start, readiness) = setup();
        let request = request_for(&start);
        let path = request_path(&start);
        let pending = request_pending_path(&path).unwrap();
        publish_request(
            &path,
            &pending,
            &ExecutionGuestRequest::Golden(Box::new(request)),
        )
        .unwrap();
        fs::write(&pending, b"partial").unwrap();
        let fake = success_process(&start);
        execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
            .unwrap();
        assert!(!path.exists());
        assert!(!pending.exists());
    }

    #[test]
    fn concurrent_provider_lease_refuses_a_second_run() {
        let lease = Arc::new(TestLease::default());
        let held = lease.try_acquire().unwrap();
        std::thread::scope(|scope| {
            let lease = Arc::clone(&lease);
            scope.spawn(move || {
                assert!(matches!(
                    lease.try_acquire(),
                    Err(RunnerError::LeaseUnavailable)
                ));
            });
        });
        drop(held);
        assert!(lease.try_acquire().is_ok());
    }

    #[test]
    fn transaction_rejects_foreign_binding_and_requires_pending_recovery() {
        let (_root, layout, start, readiness) = setup();
        let context = prepare_execution(&start, &readiness, &layout, false).unwrap();
        let store = TransactionStore::new(&layout, context.binding.clone());
        store.create("approved-start").unwrap();

        let mut foreign = context.binding;
        foreign.provider_sha256 = "f".repeat(64);
        let foreign_store = TransactionStore::new(&layout, foreign);
        assert!(matches!(
            foreign_store.load_current(),
            Err(RunnerError::Transaction(_))
        ));

        let directory = layout.run_dir().join("wsb-session-transaction");
        let pending = directory.join("00000000000000000002.json.pending");
        fs::write(&pending, b"partial").unwrap();
        assert!(matches!(
            store.load_current(),
            Err(RunnerError::RecoveryRequired(_))
        ));
        let inspection = store.inspect_for_recovery().unwrap();
        let recovered = store.verify_inspection(&inspection).unwrap();
        assert_eq!(
            recovered.current_state(),
            SessionTransactionState::StartIntent
        );
        assert!(pending.exists());
        store.discard_pending_after_authority(&inspection).unwrap();
        assert!(!pending.exists());
    }

    #[test]
    fn transaction_loader_rejects_oversized_or_rewritten_snapshot() {
        let (_root, layout, start, readiness) = setup();
        let context = prepare_execution(&start, &readiness, &layout, false).unwrap();
        let store = TransactionStore::new(&layout, context.binding);
        store.create("approved-start").unwrap();
        let path = layout
            .run_dir()
            .join("wsb-session-transaction")
            .join("00000000000000000001.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["providerSha256"] = serde_json::Value::String("e".repeat(64));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            store.load_current(),
            Err(RunnerError::Transaction(_))
        ));

        fs::write(&path, vec![b'x'; 64 * 1024 + 1]).unwrap();
        assert!(matches!(
            store.load_current(),
            Err(RunnerError::Transaction(_))
        ));
    }

    #[test]
    fn drift_cancellation_timeout_and_stop_failure_are_not_success() {
        let (_root, layout, mut start, readiness) = setup();
        start.provider.sha256 = "0".repeat(64);
        let none = FakeProcess::new(vec![]);
        assert!(
            execute_wsb_golden_probe(&start, &readiness, &layout, &none, &TestLease::default())
                .is_err()
        );

        let (_root, layout, start, readiness) = setup();
        layout.request_cancellation("admin", "now").unwrap();
        let none = FakeProcess::new(vec![empty_list()]);
        assert!(matches!(
            execute_wsb_golden_probe(&start, &readiness, &layout, &none, &TestLease::default()),
            Err(RunnerError::Cancelled)
        ));

        assert!(matches!(
            ensure_success(&ProcessResult {
                exit_code: 1,
                stdout: vec![],
                stderr: vec![]
            }),
            Err(RunnerError::ProviderFailure)
        ));
        let root = Root::new();
        assert!(
            wait_for_receipt(&RunLayout::new(&root.0, "missing").unwrap(), &root.0, 0).is_err()
        );
    }

    #[test]
    fn project_revision_is_revalidated_before_provider_start() {
        let (_root, layout, start, readiness) = setup();
        let path = Path::new(&start.project_path);
        let original = fs::read_to_string(path).unwrap();
        fs::write(
            path,
            original.replace("endpoint-engineering", "changed-owner"),
        )
        .unwrap();
        let none = FakeProcess::new(vec![]);
        assert!(matches!(
            execute_wsb_golden_probe(&start, &readiness, &layout, &none, &TestLease::default()),
            Err(RunnerError::Drift)
        ));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "starts a real hardened Windows Sandbox golden probe; set AIW_RUN_LIVE_WSB_GOLDEN=1 and AIW_LIVE_GUEST_AGENT"]
    fn live_native_golden_probe_receipt_and_cleanup() {
        live_native_probe(false);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "starts a real hardened Sandbox and recovers before result publication; set AIW_RUN_LIVE_WSB_GOLDEN=1 and AIW_LIVE_GUEST_AGENT"]
    fn live_native_recovery_after_cleanup_before_result() {
        live_native_probe(true);
    }

    #[cfg(windows)]
    fn live_native_probe(interrupt_after_cleanup: bool) {
        if std::env::var("AIW_RUN_LIVE_WSB_GOLDEN").as_deref() != Ok("1") {
            return;
        }
        let agent_source = PathBuf::from(
            std::env::var_os("AIW_LIVE_GUEST_AGENT")
                .expect("AIW_LIVE_GUEST_AGENT must name the built guest agent"),
        );
        let readiness = aiw_windows_platform::assess_windows_sandbox();
        assert!(readiness.supported, "{:?}", readiness.blockers);
        assert!(readiness.current_session_ids.is_empty());
        let provider = readiness.provider_binary.clone().unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let run_id = format!("w1-live-{}-{nonce}", std::process::id());
        let workspace_parent = std::env::temp_dir().canonicalize().unwrap();
        let project_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/minimal.aiw.yaml")
            .canonicalize()
            .unwrap();
        let project: Project = serde_yaml::from_slice(&fs::read(&project_path).unwrap()).unwrap();
        let agent_hash = identity(&agent_source).sha256;
        let artifacts = prepare_windows_sandbox_bundle(
            &run_id,
            &project,
            &agent_source,
            &agent_hash,
            &workspace_parent,
            &run_id,
            "host-time-not-trusted",
        )
        .unwrap();
        let root_path = PathBuf::from(&artifacts.receipt.workspace.root.final_path);
        import_windows_sandbox_preparation(
            &root_path,
            &project,
            &agent_hash,
            "host-time-not-trusted",
        )
        .unwrap();
        let layout = RunLayout::new(&root_path, &run_id).unwrap();
        layout
            .write_approval(
                &ApprovalRecord::for_plan(
                    &artifacts.run_plan,
                    "live-test-user",
                    "host-time-not-trusted",
                )
                .unwrap(),
            )
            .unwrap();
        let workspace =
            aiw_windows_platform::HeldRunWorkspace::reopen_bound(&artifacts.receipt.workspace)
                .unwrap();
        let output = workspace.output_path();
        let start = WsbGoldenProbeStart {
            schema_version: "aiw.dev/wsb-golden-probe-start/v0alpha2".to_owned(),
            run_root: artifacts.receipt.workspace.root.final_path.clone(),
            project_path: project_path.to_string_lossy().into_owned(),
            wsb_plan: artifacts.wsb_plan,
            provider,
            guest_agent: artifacts.receipt.guest_agent,
            workspace: artifacts.receipt.workspace,
            workspace_identity_sha256: artifacts.receipt.workspace_identity_sha256,
            timeout_seconds: 180,
            msi: None,
        };
        let native = NativeWsbProcess {
            state: Mutex::new(NativeWsbState {
                lease: aiw_windows_platform::acquire_windows_sandbox(&start.provider.sha256)
                    .unwrap(),
                started_id: None,
            }),
            plan: start.wsb_plan.clone(),
        };
        eprintln!(
            "AIW live recovery state: workspace={} sandboxId={}",
            root_path.display(),
            deterministic_sandbox_id(&run_id)
        );
        if interrupt_after_cleanup {
            // Exercise the real attempt and cleanup, then deliberately omit result
            // publication to model process loss at the CleanupVerified boundary.
            let context = prepare_execution(&start, &readiness, &layout, true).unwrap();
            let store = TransactionStore::new(&layout, context.binding.clone());
            prepare_request_artifact(&context.request_path, &context.guest_request).unwrap();
            revalidate_workspace(&start, &workspace).unwrap();
            store.create("approved-start").unwrap();
            let operation = run_attempt(&start, &layout, &native, &context, &store);
            finalize_attempt(
                &start,
                &native,
                &context,
                &store,
                false,
                operation.as_ref().err(),
            )
            .unwrap();
            operation.unwrap();
            assert!(!layout.result_path().exists());
            drop(native);
            let recovered = super::recover_windows_sandbox(&layout).unwrap();
            assert!(recovered.provider_cleanup_verified && recovered.workspace_cleanup_verified);
            assert!(recovered.terminalizable);
            let result = layout.read_result().unwrap();
            assert_eq!(result.outcome, RunOutcome::Failed);
            assert!(result.evidence_root.is_none());
            assert!(result.cleanup_complete);
            let result_bytes = fs::read(layout.result_path()).unwrap();
            let journal_bytes = fs::read(layout.journal_path()).unwrap();
            super::recover_windows_sandbox(&layout).unwrap();
            assert_eq!(fs::read(layout.result_path()).unwrap(), result_bytes);
            assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_bytes);
            drop(layout);
            drop(workspace);
            fs::remove_dir_all(root_path).unwrap();
            return;
        }

        let execution = super::execute_wsb_golden_probe(
            &start,
            &readiness,
            &layout,
            &native,
            &TestLease::default(),
            &workspace,
        )
        .unwrap();
        assert!(execution.cleanup_complete);
        assert_eq!(
            execution.workspace_identity_sha256,
            start.workspace_identity_sha256
        );
        assert!(output.join("token.json").is_file());
        assert!(output.join("evidence.jsonl").is_file());
        assert!(output.join("completion.json").is_file());
        assert_eq!(
            layout.read_result().unwrap().outcome,
            RunOutcome::InsufficientEvidence
        );
        assert!(
            native
                .state
                .lock()
                .unwrap()
                .lease
                .list()
                .unwrap()
                .session_ids
                .is_empty()
        );
        drop(native);
        let recovered = super::recover_windows_sandbox(&layout).unwrap();
        assert_eq!(recovered.state, SessionTransactionState::CleanupVerified);
        assert!(recovered.provider_cleanup_verified);
        assert!(recovered.workspace_cleanup_verified);
        assert!(recovered.terminalizable);
        assert_eq!(recovered.reason_code, "already-clean");
        drop(layout);
        drop(workspace);
        fs::remove_dir_all(root_path).unwrap();
    }

    fn fake_msi_import_receipt(
        scenario: &aiw_provider_wsb::CompiledMsiScenario,
        size_bytes: u64,
    ) -> aiw_probe::ApplicationFileImportReceipt {
        let sha256 = scenario.application_sha256.clone();
        let identity = |path: &str, marker: char| aiw_probe::WindowsFileIdentity {
            final_path: path.to_owned(),
            volume_serial_number: "0".repeat(16),
            file_id: marker.to_string().repeat(32),
        };
        let intake_root = identity(r"C:\AIW\intake-one", '1');
        let source_directory = identity(r"C:\AIW\intake-one\source", '2');
        let payload = identity(r"C:\AIW\intake-one\source\payload.msi", '3');
        let receipt = identity(r"C:\AIW\intake-one\import-receipt.json", '4');
        let eas = aiw_probe::ApplicationFileEaAuthority {
            entries: vec![],
            canonical_sha256: "0".repeat(64),
        };
        aiw_probe::ApplicationFileImportReceipt {
            schema_version: aiw_probe::APPLICATION_FILE_IMPORT_RECEIPT_SCHEMA.to_owned(),
            download_metadata_archive: None,
            intake_id: "intake-one".to_owned(),
            source_kind: aiw_probe::ApplicationInspectionKind::Msi,
            source: aiw_probe::ApplicationFileAuthority {
                schema_version: aiw_probe::APPLICATION_FILE_AUTHORITY_SCHEMA.to_owned(),
                identity: identity(r"C:\source\application.msi", '5'),
                size_bytes,
                sha256: sha256.clone(),
                link_count: 1,
                only_unnamed_data_stream: true,
                download_metadata: Vec::new(),
            },
            intake_root,
            intake_root_eas: eas.clone(),
            source_directory,
            source_directory_eas: eas.clone(),
            payload_relative_path: "source/payload.msi".to_owned(),
            payload,
            payload_eas: eas,
            receipt,
            size_bytes,
            sha256,
        }
    }

    fn setup_msi() -> (
        Root,
        RunLayout,
        WsbGoldenProbeStart,
        WindowsSandboxReadiness,
    ) {
        let (root, old_layout, mut start, readiness) = setup();
        let project_path = PathBuf::from(&start.project_path);
        let project_source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("examples")
            .join("notepad-plus-plus-msi.aiw.yaml");
        fs::copy(project_source, &project_path).unwrap();
        let mut project: Project =
            serde_yaml::from_slice(&fs::read(&project_path).unwrap()).unwrap();

        let msi_path = root.0.join("tools").join("application.msi");
        let msi_bytes = b"deterministic MSI fixture";
        fs::write(&msi_path, msi_bytes).unwrap();
        let msi_sha256 = hex::encode(Sha256::digest(msi_bytes));
        if let aiw_schema::ApplicationSource::Msi(source) = &mut project.application {
            source.sha256 = msi_sha256;
        } else {
            panic!("MSI fixture did not contain an MSI application source");
        }
        fs::write(&project_path, serde_yaml::to_string(&project).unwrap()).unwrap();
        let staged_payload = identity(&msi_path);
        let staged_path = msi_path.to_string_lossy().into_owned();
        let scenario = aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario(
            &project,
            "install-launch-close",
        )
        .unwrap();
        let import_receipt = fake_msi_import_receipt(&scenario, msi_bytes.len() as u64);
        let import_receipt_sha256 =
            hex::encode(Sha256::digest(serde_json::to_vec(&import_receipt).unwrap()));
        let msi = WsbMsiApplication {
            import_receipt,
            import_receipt_sha256,
            scenario_sha256: canonical_hash(&scenario).unwrap(),
            scenario,
            staged_payload: BinaryIdentity {
                canonical_path: staged_path.clone(),
                sha256: staged_payload.sha256.clone(),
                size_bytes: staged_payload.size_bytes,
                version: None,
                signature_status: aiw_probe::ReadinessState::Unknown,
            },
            staged_identity: aiw_probe::WindowsFileIdentity {
                final_path: staged_path,
                volume_serial_number: start.workspace.tools.volume_serial_number.clone(),
                file_id: "9".repeat(32),
            },
        };
        start.schema_version = "aiw.dev/wsb-imported-msi-start/v0alpha1".to_owned();
        start.wsb_plan.probe.output = r"C:\AIW\Output\scenario-result.json".to_owned();
        start.msi = Some(msi.clone());

        drop(old_layout);
        fs::remove_dir_all(root.0.join("runs")).unwrap();
        let plan = RunPlan::new(
            "w1-run",
            project.metadata.name.clone(),
            project_revision_hash(&project).unwrap(),
            aiw_orchestrator::RunLifecycleKind::Assessment,
            "now",
            vec![
                PlannedAction::AssessHost,
                PlannedAction::PrepareWorkspace,
                PlannedAction::ExecuteWindowsSandboxImportedMsiScenario {
                    sandbox_plan_sha256: canonical_hash(&start.wsb_plan).unwrap(),
                    provider_sha256: start.provider.sha256.clone(),
                    guest_agent_sha256: start.guest_agent.sha256.clone(),
                    workspace: Box::new(start.workspace.clone()),
                    workspace_identity_sha256: start.workspace_identity_sha256.clone(),
                    import_receipt_sha256: msi.import_receipt_sha256.clone(),
                    application_sha256: msi.staged_payload.sha256.clone(),
                    scenario_sha256: msi.scenario_sha256.clone(),
                },
                PlannedAction::CollectEvidence,
            ],
            vec![
                "installs and exercises the approved imported MSI in Windows Sandbox".to_owned(),
                "maps fixed guest tools read-only and treats writable output as untrusted"
                    .to_owned(),
            ],
        )
        .unwrap();
        let layout = RunLayout::new(&root.0, "w1-run").unwrap();
        let receipt = aiw_orchestrator::WsbPlanningImportReceipt {
            schema_version: aiw_orchestrator::WSB_MSI_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION
                .to_owned(),
            run_id: plan.run_id.clone(),
            imported_at: "now".to_owned(),
            status: aiw_orchestrator::WsbPlanningImportStatus::PendingApproval,
            project_revision_sha256: plan.project_revision_hash.clone(),
            workspace_root: start.workspace.root.final_path.clone(),
            workspace_identity_sha256: start.workspace_identity_sha256.clone(),
            preparation_receipt_sha256: "d".repeat(64),
            run_plan_sha256: plan.hash().unwrap(),
            windows_sandbox_plan_sha256: canonical_hash(&start.wsb_plan).unwrap(),
            guest_agent_sha256: start.guest_agent.sha256.clone(),
            provider_sha256: start.provider.sha256.clone(),
            run_root: start.workspace.root.final_path.clone(),
            journal_sequence: 1,
            approval_present: false,
            provider_acquired: false,
            provider_mutated: false,
        };
        layout
            .create_or_verify_pending_wsb_import(&plan, &receipt)
            .unwrap();
        layout
            .write_approval(&ApprovalRecord::for_plan(&plan, "admin", "now").unwrap())
            .unwrap();
        (root, layout, start, readiness)
    }

    fn msi_request_for(start: &WsbGoldenProbeStart) -> aiw_provider_wsb::ImportedMsiGuestRequest {
        let rendered = render_config(&start.wsb_plan).unwrap();
        let msi = start.msi.as_ref().unwrap();
        aiw_provider_wsb::ImportedMsiGuestRequest::new(
            "w1-run",
            deterministic_sandbox_id("w1-run"),
            &rendered.sha256,
            &start.guest_agent.sha256,
            msi.scenario.clone(),
            &msi.staged_payload.sha256,
            msi.staged_payload.size_bytes,
            &msi.import_receipt_sha256,
        )
        .unwrap()
    }

    fn registry_snapshot(include_install: bool) -> aiw_provider_wsb::ApplicationRegistrySnapshot {
        use aiw_provider_wsb::{
            ApplicationRegistryRoot as Root, RegistryKeyEntry, RegistryValueEntry,
            RegistryView as View,
        };
        let mut keys = vec![
            RegistryKeyEntry {
                root: Root::MachineApplication,
                view: View::Registry64,
                path: String::new(),
            },
            RegistryKeyEntry {
                root: Root::MachineApplication,
                view: View::Registry32,
                path: String::new(),
            },
            RegistryKeyEntry {
                root: Root::UserApplication,
                view: View::Registry64,
                path: String::new(),
            },
            RegistryKeyEntry {
                root: Root::UserApplication,
                view: View::Registry32,
                path: String::new(),
            },
        ];
        let mut values = Vec::new();
        if include_install {
            keys.insert(
                1,
                RegistryKeyEntry {
                    root: Root::MachineApplication,
                    view: View::Registry64,
                    path: "Install".to_owned(),
                },
            );
            values.push(RegistryValueEntry {
                root: Root::MachineApplication,
                view: View::Registry64,
                path: "Install".to_owned(),
                name: "DisplayName".to_owned(),
                value_type: 1,
                size_bytes: 20,
                sha256: "a".repeat(64),
            });
        }
        aiw_provider_wsb::ApplicationRegistrySnapshot {
            keys,
            values,
            absent_roots: vec![],
            issues: vec![],
        }
    }

    #[derive(Clone, Copy)]
    enum RegistryFixture {
        Valid,
        Missing,
        Tampered,
    }

    fn write_valid_msi_completion(
        start: &WsbGoldenProbeStart,
        scenario_result: aiw_provider_wsb::ImportedMsiScenarioResult,
        include_behavior: bool,
        registry_fixture: RegistryFixture,
    ) {
        let rendered = render_config(&start.wsb_plan).unwrap();
        let request = msi_request_for(start);
        let output = PathBuf::from(
            &mapping(&start.wsb_plan, MappingPurpose::Output)
                .unwrap()
                .host_folder,
        );
        let scenario_bytes = serde_json::to_vec(&scenario_result).unwrap();
        publish_test_file(&output.join("scenario-result.json"), &scenario_bytes);

        let mut evidence = aiw_evidence::EvidenceLog::new();
        evidence
            .append(aiw_evidence::EvidenceEvent {
                observed_utc: "guest-time-not-trusted".to_owned(),
                kind: "importedMsiScenario".to_owned(),
                source: "test-guest-agent".to_owned(),
                payload: serde_json::json!({"completed":true}),
            })
            .unwrap();
        let valid_result =
            aiw_provider_wsb::ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
        let token = aiw_provider_wsb::ImportedMsiApplicationToken::new(
            &request,
            &valid_result,
            serde_json::from_value(serde_json::json!({
                "schemaVersion": "aiw.dev/token-evidence/v0alpha1",
                "processId": 42, "tokenType": "primary", "isAppContainer": false,
                "userSid": "S-1-5-21-1-2-3-1001",
                "integrity": {"sid": "S-1-16-8192", "rid": 8192, "level": "medium"},
                "elevationType": "default", "isElevated": false,
                "capabilities": [], "restrictedSidCount": 0
            }))
            .unwrap(),
        )
        .unwrap();
        evidence
            .append(aiw_evidence::EvidenceEvent {
                observed_utc: "guest-time-not-trusted".to_owned(),
                kind: aiw_provider_wsb::MSI_APPLICATION_TOKEN_EVENT.to_owned(),
                source: "aiw-guest-agent".to_owned(),
                payload: serde_json::to_value(&token).unwrap(),
            })
            .unwrap();
        let runtime = if request.scenario.requires_standard_user() {
            let runtime = aiw_provider_wsb::ImportedMsiRuntimeContext::new(
                &request,
                &valid_result,
                &token,
                aiw_provider_wsb::StandardUserRuntimeContext {
                    user_sid: token.token.user_sid.clone(),
                    profile_path: r"C:\Users\AiwStandardUser".to_owned(),
                    roaming_app_data: r"C:\Users\AiwStandardUser\AppData\Roaming".to_owned(),
                    local_app_data: r"C:\Users\AiwStandardUser\AppData\Local".to_owned(),
                    administrators_enabled: false,
                },
            )
            .unwrap();
            evidence
                .append(aiw_evidence::EvidenceEvent {
                    observed_utc: "guest-time-not-trusted".to_owned(),
                    kind: aiw_provider_wsb::IMPORTED_MSI_RUNTIME_CONTEXT_EVENT.to_owned(),
                    source: "aiw-guest-agent".to_owned(),
                    payload: serde_json::to_value(&runtime).unwrap(),
                })
                .unwrap();
            Some(runtime)
        } else {
            None
        };
        if request.scenario.requires_registry_observations()
            && !matches!(registry_fixture, RegistryFixture::Missing)
        {
            let mut registry = aiw_provider_wsb::ImportedMsiRegistryEvidence::new(
                &request,
                &valid_result,
                runtime
                    .as_ref()
                    .expect("v5 profile requires standard-user runtime"),
                registry_snapshot(false),
                registry_snapshot(true),
                registry_snapshot(true),
            )
            .unwrap();
            if matches!(registry_fixture, RegistryFixture::Tampered) {
                registry.user_sid = "S-1-5-21-foreign".to_owned();
            }
            evidence
                .append(aiw_evidence::EvidenceEvent {
                    observed_utc: "guest-time-not-trusted".to_owned(),
                    kind: aiw_provider_wsb::IMPORTED_MSI_REGISTRY_EVENT.to_owned(),
                    source: "aiw-guest-agent".to_owned(),
                    payload: serde_json::to_value(registry).unwrap(),
                })
                .unwrap();
        }
        if include_behavior && request.scenario.requires_application_exercise() {
            let empty = aiw_provider_wsb::ApplicationFilesystemSnapshot {
                entries: vec![],
                issues: vec![],
            };
            let expected = hex::encode(Sha256::digest(
                aiw_provider_wsb::DOCUMENT_EXPECTED_TEXT.as_bytes(),
            ));
            let behavior = aiw_provider_wsb::ImportedMsiBehaviorEvidence {
                schema_version: aiw_provider_wsb::IMPORTED_MSI_BEHAVIOR_SCHEMA.to_owned(),
                run_id: request.run_id.clone(),
                sandbox_id: request.sandbox_id.clone(),
                request_sha256: request.request_sha256.clone(),
                scenario_sha256: request.scenario_sha256.clone(),
                functional_exercise: aiw_provider_wsb::FunctionalExercise {
                    opened_document: true,
                    saved_document: true,
                    expected_sha256: expected.clone(),
                    observed_sha256: expected,
                },
                before_install: empty.clone(),
                after_install: empty.clone(),
                after_exercise: empty,
            };
            evidence
                .append(aiw_evidence::EvidenceEvent {
                    observed_utc: "guest-time-not-trusted".to_owned(),
                    kind: aiw_provider_wsb::IMPORTED_MSI_BEHAVIOR_EVENT.to_owned(),
                    source: "aiw-guest-agent".to_owned(),
                    payload: serde_json::to_value(behavior).unwrap(),
                })
                .unwrap();
        }
        let mut evidence_bytes = Vec::new();
        for record in evidence.records() {
            serde_json::to_writer(&mut evidence_bytes, record).unwrap();
            evidence_bytes.push(b'\n');
        }
        publish_test_file(&output.join("evidence.jsonl"), &evidence_bytes);
        let artifact = |path: &str,
                        role: aiw_evidence::ArtifactRole,
                        media_type: &str,
                        bytes: &[u8]| aiw_provider_wsb::CompletionArtifact {
            path: path.to_owned(),
            role,
            media_type: media_type.to_owned(),
            size_bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        let receipt = aiw_provider_wsb::WindowsSandboxCompletionReceipt {
            schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION
                .to_owned(),
            run_id: "w1-run".to_owned(),
            sandbox_id: deterministic_sandbox_id("w1-run"),
            config_sha256: rendered.sha256,
            request_sha256: request.request_sha256,
            agent_sha256: start.guest_agent.sha256.clone(),
            status: aiw_provider_wsb::CompletionStatus::Succeeded,
            exit_code: 0,
            evidence_root_hash: evidence.manifest().unwrap().root_hash,
            artifacts: vec![
                artifact(
                    "scenario-result.json",
                    aiw_evidence::ArtifactRole::ScenarioResults,
                    "application/json",
                    &scenario_bytes,
                ),
                artifact(
                    "evidence.jsonl",
                    aiw_evidence::ArtifactRole::EvidenceLog,
                    "application/x-ndjson",
                    &evidence_bytes,
                ),
            ],
        };
        let mut receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        receipt_bytes.push(b'\n');
        publish_test_file(&output.join("completion.json"), &receipt_bytes);
    }

    fn successful_msi_process(
        start: &WsbGoldenProbeStart,
        scenario_result: aiw_provider_wsb::ImportedMsiScenarioResult,
    ) -> FakeProcess {
        let id = deterministic_sandbox_id("w1-run");
        let output_start = start.clone();
        FakeProcess::new(vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            stopped(&id),
            empty_list(),
        ])
        .with_start_action(Box::new(move || {
            write_valid_msi_completion(&output_start, scenario_result, true, RegistryFixture::Valid)
        }))
    }

    #[test]
    fn imported_msi_missing_required_behavior_fails_after_verified_cleanup() {
        let (_root, layout, start, readiness) = setup_msi();
        let request = msi_request_for(&start);
        let valid =
            aiw_provider_wsb::ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
        let output_start = start.clone();
        let fake =
            successful_msi_process(&start, valid.clone()).with_start_action(Box::new(move || {
                write_valid_msi_completion(&output_start, valid, false, RegistryFixture::Valid);
            }));
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(
            matches!(error, RunnerError::Receipt(detail) if detail.contains("requires functional exercise evidence"))
        );
        assert_eq!(
            observe_wsb_session_status(&layout).unwrap().status,
            WsbSessionDisposition::Clean
        );
        assert!(!request_path(&start).exists());
        let result = layout.read_result().unwrap();
        assert_eq!(result.outcome, RunOutcome::Failed);
        assert!(result.cleanup_complete);
        assert!(result.evidence_root.is_none());
    }

    #[test]
    fn imported_msi_mismatched_scenario_result_fails_after_exact_cleanup() {
        let (_root, layout, start, readiness) = setup_msi();
        let request = msi_request_for(&start);
        let mut mismatched =
            aiw_provider_wsb::ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
        mismatched.scenario_id = "other-scenario".to_owned();
        let fake = successful_msi_process(&start, mismatched);
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(matches!(
            error,
            RunnerError::Receipt(detail)
                if detail == "imported MSI scenario result is not bound to the approved request"
        ));
        assert_eq!(
            observe_wsb_session_status(&layout).unwrap().status,
            WsbSessionDisposition::Clean
        );
        assert!(!request_path(&start).exists());
        let result = layout.read_result().unwrap();
        assert_eq!(result.outcome, RunOutcome::Failed);
        assert!(result.cleanup_complete);
        assert!(result.evidence_root.is_none());
    }

    #[test]
    fn imported_msi_v5_rejects_missing_or_tampered_registry_evidence_after_cleanup() {
        for fixture in [RegistryFixture::Missing, RegistryFixture::Tampered] {
            let (_root, layout, start, readiness) = setup_msi();
            let request = msi_request_for(&start);
            assert!(request.scenario.requires_registry_observations());
            let valid =
                aiw_provider_wsb::ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
            let id = deterministic_sandbox_id("w1-run");
            let output_start = start.clone();
            let fake = FakeProcess::new(vec![
                empty_list(),
                started(&id),
                list_with(&id, "running"),
                list_with(&id, "running"),
                stopped(&id),
                empty_list(),
            ])
            .with_start_action(Box::new(move || {
                write_valid_msi_completion(&output_start, valid, true, fixture)
            }));
            let error =
                execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                    .unwrap_err();
            assert!(matches!(error, RunnerError::Receipt(_)));
            assert_eq!(
                observe_wsb_session_status(&layout).unwrap().status,
                WsbSessionDisposition::Clean
            );
            let result = layout.read_result().unwrap();
            assert_eq!(result.outcome, RunOutcome::Failed);
            assert!(result.cleanup_complete);
            assert!(result.evidence_root.is_none());
        }
    }

    #[test]
    fn imported_msi_validated_request_and_staging_are_cleaned_on_retry() {
        let (_root, layout, start, readiness) = setup_msi();
        let request = msi_request_for(&start);
        let path = request_path(&start);
        let pending = request_pending_path(&path).unwrap();
        publish_request(
            &path,
            &pending,
            &ExecutionGuestRequest::ImportedMsi(Box::new(request.clone())),
        )
        .unwrap();
        fs::write(&pending, b"partial").unwrap();
        let valid =
            aiw_provider_wsb::ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
        let fake = successful_msi_process(&start, valid);
        let execution =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap();
        assert!(execution.cleanup_complete);
        assert_eq!(
            execution
                .application_token
                .as_ref()
                .unwrap()
                .token
                .process_id,
            42
        );
        assert!(execution.registry_evidence.is_some());
        assert!(!path.exists());
        assert!(!pending.exists());
        assert_eq!(
            layout.read_result().unwrap().outcome,
            RunOutcome::InsufficientEvidence
        );
    }
}

#[cfg(all(test, windows))]
mod live_msi_recovery_tests;

mod assessment_report_markdown;
