//! Retained paired observations. No provider lease, execution, repair or recovery.
use super::*;
use crate::sevenzip_report_output::read_sevenzip_output;
use aiw_provider_wsb::sevenzip::{
    SevenZipComparison, SevenZipRequest, SevenZipResult, verify_sevenzip_evidence,
};

#[derive(Clone, Copy)]
pub(super) enum SevenZipExecutionProvenance {
    ApprovalUnavailable,
    ApprovedWithoutDispatch,
    ApprovedDispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SevenZipReportEvidenceStatus {
    Verified,
    DriverIncomplete,
    Absent,
    Rejected,
}
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SevenZipRunReport {
    pub schema_version: String,
    pub run_id: String,
    pub request_sha256: String,
    pub project_revision_sha256: String,
    pub profile: aiw_probe::SevenZipProfile,
    pub recorded_outcome: Option<RunOutcome>,
    /// Historical exact-session receipt only, never a fresh provider observation.
    pub recorded_cleanup_verified: Option<bool>,
    pub evidence_status: SevenZipReportEvidenceStatus,
    pub receipt_sha256: Option<String>,
    pub evidence_root_hash: Option<String>,
    pub observations: Option<SevenZipResult>,
    pub comparison: Option<SevenZipComparison>,
    pub function_deltas: Option<aiw_core::ComparisonReport>,
    pub evidence_gaps: Vec<String>,
}

#[cfg(windows)]
pub fn report_windows_sandbox_sevenzip(
    root: &Path,
    run_id: &str,
    project: &Project,
    expected_agent: &str,
) -> Result<SevenZipRunReport, RunnerError> {
    if !aiw_schema::validate_project_for_planning(project).is_empty() {
        return Err(RunnerError::ApprovalBinding);
    }
    let layout = RunLayout::new(root, run_id).map_err(journal_error)?;
    let before = layout.retained_snapshot().map_err(journal_error)?;
    let receipt: WsbPreparationReceipt =
        read_bounded_json(&root.join("preparation.json"), 1024 * 1024)?;
    let held = aiw_windows_platform::HeldRunWorkspace::reopen_bound(&receipt.workspace)
        .map_err(|e| RunnerError::Preparation(e.to_string()))?;
    if !same_windows_path(
        root.canonicalize().map_err(|_| RunnerError::Drift)?,
        held.root_path(),
    ) {
        return Err(RunnerError::Drift);
    }
    let files = ["preparation.json", "plan.json", "wsb-plan.json"]
        .into_iter()
        .map(|leaf| {
            held.reopen_root_file_readonly(leaf)
                .map_err(|_| RunnerError::Drift)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if read_bounded_json::<WsbPreparationReceipt>(&root.join("preparation.json"), 1024 * 1024)?
        != receipt
    {
        return Err(RunnerError::Drift);
    }
    let artifacts = PreparedWsbArtifacts {
        receipt,
        run_plan: read_bounded_json(&root.join("plan.json"), 1024 * 1024)?,
        wsb_plan: read_bounded_json(&root.join("wsb-plan.json"), 1024 * 1024)?,
    };
    artifacts
        .validate_historical()
        .map_err(|e| RunnerError::Preparation(e.to_string()))?;
    let controls = artifacts
        .receipt
        .seven_zip
        .as_ref()
        .ok_or(RunnerError::ApprovalBinding)?;
    let import: WsbPlanningImportReceipt = read_bounded_json(
        &layout.run_dir().join("wsb-planning-import.json"),
        1024 * 1024,
    )?;
    if artifacts.run_plan != before.plan
        || artifacts.receipt.run_id != run_id
        || artifacts.receipt.guest_agent.sha256 != expected_agent
        || artifacts.receipt.project_revision_sha256
            != project_revision_hash(project).map_err(journal_error)?
        || import.preparation_receipt_sha256 != canonical_hash(&artifacts.receipt)?
    {
        return Err(RunnerError::ApprovalBinding);
    }
    // Reopen the retained inputs, never the current build/provider or an old
    // executable's source workspace. This cannot authorize a fresh dispatch.
    let role_files = preparation::sevenzip::open_sevenzip_files(&held, &artifacts.receipt)
        .map_err(|_| RunnerError::Drift)?;
    let agent_file = held
        .reopen_tools_file_readonly("aiw-guest-agent.exe")
        .map_err(|_| RunnerError::Drift)?;
    let agent = aiw_windows_platform::HeldApplicationFile::open(agent_file.final_path())
        .map_err(|_| RunnerError::Drift)?;
    if agent_file.identity() != &agent.observation().identity
        || agent.observation().sha256 != expected_agent
        || agent.observation().size_bytes != artifacts.receipt.guest_agent.size_bytes
    {
        return Err(RunnerError::Drift);
    }
    let config = render_config(&artifacts.wsb_plan).map_err(|_| RunnerError::Drift)?;
    let request = SevenZipRequest::from_retained_binding(
        run_id,
        &deterministic_sandbox_id(run_id),
        &config.sha256,
        expected_agent,
        controls.profile.clone(),
    )
    .map_err(RunnerError::Receipt)?;
    let inspection = session::inspect_for_recovery(&layout)?;
    let mut cleanup = None;
    if let Some(transaction) = &inspection.transaction {
        let recovery = transaction.recovery.as_ref().ok_or(RunnerError::Drift)?;
        if before.approval.is_none()
            || transaction.run_id != run_id
            || transaction.plan_hash != before.plan.hash().map_err(journal_error)?
            || transaction.project_revision_hash != artifacts.receipt.project_revision_sha256
            || transaction.provider_sha256 != artifacts.receipt.provider.sha256
            || transaction.workspace_identity_sha256 != artifacts.receipt.workspace_identity_sha256
            || transaction.session_id != request.sandbox_id
            || transaction.config_sha256 != request.config_sha256
            || transaction.request_sha256 != request.request_sha256
            || recovery.workspace != artifacts.receipt.workspace
            || recovery.provider_protocol != artifacts.receipt.provider_protocol
            || recovery.request_relative_path != "request.json"
        {
            return Err(RunnerError::Drift);
        }
        if !inspection.pending_present()
            && transaction.current_state() == SessionTransactionState::CleanupVerified
            && start_settled(transaction)
            && !recovery_request_present(&held.tools_path().join("request.json"))?
            && !recovery_request_present(&held.tools_path().join("request.json.pending"))?
        {
            cleanup = Some(true);
        }
    }
    let outcome = match &before.status {
        aiw_orchestrator::RecoveryStatus::Terminal { result, .. } => Some(result.outcome),
        _ => None,
    };
    if let aiw_orchestrator::RecoveryStatus::Terminal { result, .. } = &before.status {
        if result.cleanup_complete && cleanup != Some(true) {
            return Err(RunnerError::Drift);
        }
        if !result.cleanup_complete {
            cleanup = None;
        }
    }
    let report = read_sevenzip_output(
        &held.output_path(),
        &request,
        cleanup,
        outcome,
        if before.approval.is_none() {
            SevenZipExecutionProvenance::ApprovalUnavailable
        } else if inspection.transaction.is_none() {
            SevenZipExecutionProvenance::ApprovedWithoutDispatch
        } else {
            SevenZipExecutionProvenance::ApprovedDispatch
        },
        &artifacts.receipt.project_revision_sha256,
    )?;
    if let aiw_orchestrator::RecoveryStatus::Terminal { result, .. } = &before.status
        && result.outcome == RunOutcome::InsufficientEvidence
        && (!matches!(
            report.evidence_status,
            SevenZipReportEvidenceStatus::Verified | SevenZipReportEvidenceStatus::DriverIncomplete
        ) || result.evidence_root != report.evidence_root_hash)
    {
        return Err(RunnerError::Drift);
    }

    held.revalidate().map_err(|_| RunnerError::Drift)?;
    for file in &files {
        file.revalidate().map_err(|_| RunnerError::Drift)?;
    }
    for (file, source) in &role_files {
        file.revalidate().map_err(|_| RunnerError::Drift)?;
        source.revalidate().map_err(|_| RunnerError::Drift)?;
    }
    agent_file.revalidate().map_err(|_| RunnerError::Drift)?;
    agent.revalidate().map_err(|_| RunnerError::Drift)?;
    if layout.retained_snapshot().map_err(journal_error)? != before
        || session::inspect_for_recovery(&layout)? != inspection
        || read_bounded_json::<WsbPreparationReceipt>(&root.join("preparation.json"), 1024 * 1024)?
            != artifacts.receipt
    {
        return Err(RunnerError::Drift);
    }
    Ok(report)
}
