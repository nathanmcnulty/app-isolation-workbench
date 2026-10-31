//! Retained paired observations. No provider lease, execution, repair or recovery.
use super::*;
use aiw_provider_wsb::paired_controls::{
    PairedControlDriverFailure, verify_paired_controls_evidence,
    verify_paired_driver_failure_evidence,
};
use aiw_provider_wsb::{PairedControlComparison, PairedControlResult, PairedControlsRequest};

#[derive(Clone, Copy)]
pub(super) enum PairedExecutionProvenance {
    ApprovalUnavailable,
    ApprovedWithoutDispatch,
    ApprovedDispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum PairedReportEvidenceStatus {
    Verified,
    DriverIncomplete,
    Absent,
    Rejected,
}
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PairedControlRunReport {
    pub schema_version: String,
    pub run_id: String,
    pub request_sha256: String,
    pub project_revision_sha256: String,
    pub profile: aiw_probe::PairedControlProfile,
    pub recorded_outcome: Option<RunOutcome>,
    /// Historical exact-session receipt only, never a fresh provider observation.
    pub recorded_cleanup_verified: Option<bool>,
    pub evidence_status: PairedReportEvidenceStatus,
    pub receipt_sha256: Option<String>,
    pub evidence_root_hash: Option<String>,
    pub observations: Option<PairedControlResult>,
    pub driver_failure: Option<PairedControlDriverFailure>,
    pub comparison: Option<PairedControlComparison>,
    pub evidence_gaps: Vec<String>,
}

#[cfg(windows)]
pub fn report_windows_sandbox_paired_controls(
    root: &Path,
    run_id: &str,
    project: &Project,
    expected_agent: &str,
) -> Result<PairedControlRunReport, RunnerError> {
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
        .paired_controls
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
    let role_files = preparation::paired::open_control_files(&held, &artifacts.receipt)
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
    let request = PairedControlsRequest::from_retained_binding(
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
    let report = read_paired_output(
        &held.output_path(),
        &request,
        cleanup,
        outcome,
        if before.approval.is_none() {
            PairedExecutionProvenance::ApprovalUnavailable
        } else if inspection.transaction.is_none() {
            PairedExecutionProvenance::ApprovedWithoutDispatch
        } else {
            PairedExecutionProvenance::ApprovedDispatch
        },
        &artifacts.receipt.project_revision_sha256,
    )?;
    if let aiw_orchestrator::RecoveryStatus::Terminal { result, .. } = &before.status
        && result.outcome == RunOutcome::InsufficientEvidence
        && (report.evidence_status != PairedReportEvidenceStatus::Verified
            || result.evidence_root != report.evidence_root_hash)
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

// Shared output reader used by the protected native retained reader and offline
// rehearsal. Its caller supplies already-verified approval/request provenance.
pub(super) fn read_paired_output(
    output: &Path,
    request: &PairedControlsRequest,
    cleanup: Option<bool>,
    outcome: Option<RunOutcome>,
    provenance: PairedExecutionProvenance,
    revision: &str,
) -> Result<PairedControlRunReport, RunnerError> {
    request.validate().map_err(RunnerError::Receipt)?;
    let mut report = PairedControlRunReport {
        schema_version: "aiw.dev/paired-control-run-report/v0alpha1".into(),
        run_id: request.run_id.clone(),
        request_sha256: request.request_sha256.clone(),
        project_revision_sha256: revision.into(),
        profile: request.profile.clone(),
        recorded_outcome: outcome,
        recorded_cleanup_verified: cleanup,
        evidence_status: PairedReportEvidenceStatus::Absent,
        receipt_sha256: None,
        evidence_root_hash: None,
        observations: None,
        driver_failure: None,
        comparison: None,
        evidence_gaps: vec![
            "General application compatibility is unmeasured".into(),
            "Network, endpoint and host containment are unmeasured".into(),
            "Cleanup is historical; viewing makes no current-state claim".into(),
        ],
    };
    match provenance {
        PairedExecutionProvenance::ApprovalUnavailable => {
            report
                .evidence_gaps
                .push("Committed approval unavailable; no execution evidence accepted".into());
            return Ok(report);
        }
        PairedExecutionProvenance::ApprovedWithoutDispatch => {
            report.evidence_gaps.push(
                "Approval recorded; Sandbox dispatch not committed; fixed control cases remain unmeasured".into(),
            );
            return Ok(report);
        }
        PairedExecutionProvenance::ApprovedDispatch => {}
    }
    let mut expectation = completion_expectation(
        &request.run_id,
        &request.sandbox_id,
        &request.config_sha256,
        &request.agent_sha256,
        &request.request_sha256,
    );
    expectation.artifacts[0].path = "scenario-result.json".into();
    expectation.artifacts[0].role = aiw_evidence::ArtifactRole::ScenarioResults;
    expectation.artifacts[0].maximum_bytes = 64 * 1024;
    expectation.artifacts[1].maximum_bytes =
        aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64;
    let verified = match verify_completion_receipt(output, &expectation) {
        Ok(value) => value,
        Err(_) => {
            report.evidence_status = match fs::symlink_metadata(output.join("completion.json")) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    PairedReportEvidenceStatus::Absent
                }
                _ => PairedReportEvidenceStatus::Rejected,
            };
            return Ok(report);
        }
    };
    let bytes = read_bounded_bytes(
        &output.join("evidence.jsonl"),
        aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64,
    )?;
    let observation = (|| {
        if verified.successful {
            let observed: PairedControlResult =
                read_bounded_json(&output.join("scenario-result.json"), 64 * 1024)?;
            verify_paired_controls_evidence(
                &bytes,
                &verified.evidence_root_hash,
                request,
                &observed,
            )
            .map_err(RunnerError::Receipt)?;
            let eligibility_cleanup = if outcome == Some(RunOutcome::InsufficientEvidence) {
                cleanup
            } else {
                None
            };
            if outcome != Some(RunOutcome::InsufficientEvidence) {
                report.evidence_gaps.push(
                    "No committed completed assessment; retained observations remain inconclusive"
                        .into(),
                );
            }
            report.comparison = Some(
                observed
                    .compare(request, eligibility_cleanup)
                    .map_err(RunnerError::Receipt)?,
            );
            report.observations = Some(observed);
            report.evidence_status = PairedReportEvidenceStatus::Verified;
        } else {
            let failure: PairedControlDriverFailure =
                read_bounded_json(&output.join("scenario-result.json"), 64 * 1024)?;
            verify_paired_driver_failure_evidence(
                &bytes,
                &verified.evidence_root_hash,
                request,
                &failure,
            )
            .map_err(RunnerError::Receipt)?;
            report.driver_failure = Some(failure);
            report.evidence_status = PairedReportEvidenceStatus::DriverIncomplete;
        }
        Ok::<_, RunnerError>(())
    })();
    if observation.is_err() {
        report.evidence_status = PairedReportEvidenceStatus::Rejected;
        report.comparison = None;
        report.observations = None;
        report.driver_failure = None;
        return Ok(report);
    }
    report.receipt_sha256 = Some(verified.receipt_sha256);
    report.evidence_root_hash = Some(verified.evidence_root_hash);
    Ok(report)
}
