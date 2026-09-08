use super::*;

/// Reverified, historical candidate observations. This is not a comparison or
/// a recommendation and does not claim the provider is currently absent.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbMsiAssessmentReport {
    pub schema_version: String,
    pub run_id: String,
    pub project_revision_sha256: String,
    pub outcome: RunOutcome,
    pub recorded_cleanup_verified: bool,
    pub receipt_sha256: String,
    pub evidence_root_hash: String,
    pub scenario: aiw_provider_wsb::ImportedMsiScenarioResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_token: Option<aiw_provider_wsb::ImportedMsiApplicationToken>,
    pub requested_assertions: aiw_schema::Assertions,
    pub requested_isolation: aiw_schema::IsolationIntent,
    pub unmeasured_scenarios: Vec<String>,
    pub missing_evidence: Vec<AssessmentEvidenceGap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentEvidenceGap {
    OrdinaryBaseline,
    IndependentHostMeasurements,
    FilesystemRegistryChanges,
    NetworkUiIpcObservations,
    PersistenceResidue,
    DescendantCoverage,
    OfflineCanary,
    EffectiveBackendVerification,
    CaptureCompleteness,
    TargetToken,
}

fn evidence_gaps(project: &Project) -> Vec<AssessmentEvidenceGap> {
    use AssessmentEvidenceGap::*;
    let mut gaps = vec![
        OrdinaryBaseline,
        IndependentHostMeasurements,
        FilesystemRegistryChanges,
        NetworkUiIpcObservations,
        PersistenceResidue,
    ];
    if project.isolation_intent.require_descendant_coverage
        || project.assertions.require_expected_child_coverage
    {
        gaps.push(DescendantCoverage);
    }
    if project.assertions.require_offline_canary_denied {
        gaps.push(OfflineCanary);
    }
    if project.assertions.require_effective_backend_match {
        gaps.push(EffectiveBackendVerification);
    }
    if project.assertions.fail_on_evidence_truncation {
        gaps.push(CaptureCompleteness);
    }
    if project.assertions.require_target_token_evidence {
        gaps.push(TargetToken);
    }
    gaps
}

/// Read-only verification of a retained completed MSI workspace. Does not use
/// start/recovery APIs, acquire a provider lease, repair a journal, or require
/// that the original intake or current provider binary still exist.
#[cfg(windows)]
pub fn report_windows_sandbox_msi(
    root: &Path,
    run_id: &str,
    project: &Project,
    expected_guest_agent_sha256: &str,
) -> Result<WsbMsiAssessmentReport, RunnerError> {
    if !aiw_schema::validate_project_for_planning(project).is_empty() {
        return Err(RunnerError::ApprovalBinding);
    }
    let layout = RunLayout::new(root, run_id).map_err(journal_error)?;
    let before = layout.completed_snapshot().map_err(journal_error)?;
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
    let root_files = ["preparation.json", "plan.json", "wsb-plan.json"]
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
        .validate()
        .map_err(|e| RunnerError::Preparation(e.to_string()))?;
    let import: WsbPlanningImportReceipt = read_bounded_json(
        &layout.run_dir().join("wsb-planning-import.json"),
        1024 * 1024,
    )?;
    if artifacts.run_plan != before.plan
        || artifacts.receipt.run_id != run_id
        || artifacts.receipt.guest_agent.sha256 != expected_guest_agent_sha256
        || artifacts.receipt.project_revision_sha256
            != aiw_orchestrator::project_revision_hash(project).map_err(journal_error)?
        || import.preparation_receipt_sha256 != canonical_hash(&artifacts.receipt)?
        || before.result.outcome != RunOutcome::InsufficientEvidence
        || !before.result.cleanup_complete
    {
        return Err(RunnerError::ApprovalBinding);
    }
    let inspection = session::inspect_for_recovery(&layout)?;
    let transaction = inspection.transaction.as_ref().ok_or(RunnerError::Drift)?;
    let recovery = transaction.recovery.as_ref().ok_or(RunnerError::Drift)?;
    if inspection.pending_present()
        || transaction.current_state() != SessionTransactionState::CleanupVerified
        || transaction.run_id != run_id
        || transaction.plan_hash != artifacts.run_plan.hash().map_err(journal_error)?
        || transaction.project_revision_hash != artifacts.receipt.project_revision_sha256
        || transaction.provider_sha256 != artifacts.receipt.provider.sha256
        || transaction.workspace_identity_sha256 != artifacts.receipt.workspace_identity_sha256
        || recovery.workspace != artifacts.receipt.workspace
        || recovery.provider_protocol != artifacts.receipt.provider_protocol
        || recovery.request_relative_path != "request.json"
        || recovery_request_present(&held.tools_path().join("request.json"))?
        || recovery_request_present(&held.tools_path().join("request.json.pending"))?
    {
        return Err(RunnerError::Drift);
    }
    let msi = artifacts
        .receipt
        .msi
        .as_ref()
        .ok_or(RunnerError::ApprovalBinding)?;
    let compiled = aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario(
        project,
        &msi.scenario.scenario_id,
    )
    .map_err(|e| RunnerError::Preparation(e.to_string()))?;
    // Legacy snapshots keep their original semantics; validate against today's
    // identical action sequence while preserving their explicit evidence version.
    let mut historical = compiled;
    historical.schema_version = msi.scenario.schema_version.clone();
    historical.profile = msi.scenario.profile.clone();
    historical
        .validate()
        .map_err(|e| RunnerError::Preparation(e.to_string()))?;
    if historical != msi.scenario {
        return Err(RunnerError::ApprovalBinding);
    }
    let msi_file = held
        .reopen_tools_file_readonly("application.msi")
        .map_err(|_| RunnerError::Drift)?;
    let msi_observed = aiw_windows_platform::HeldApplicationFile::open(msi_file.final_path())
        .map_err(|_| RunnerError::Drift)?;
    let agent_file = held
        .reopen_tools_file_readonly("aiw-guest-agent.exe")
        .map_err(|_| RunnerError::Drift)?;
    let agent_observed = aiw_windows_platform::HeldApplicationFile::open(agent_file.final_path())
        .map_err(|_| RunnerError::Drift)?;
    if msi_file.identity() != &msi.staged_identity
        || msi_observed.observation().identity != msi.staged_identity
        || msi_observed.observation().sha256 != msi.staged_payload.sha256
        || msi_observed.observation().size_bytes != msi.staged_payload.size_bytes
        || agent_file.identity() != &agent_observed.observation().identity
        || agent_observed.observation().sha256 != expected_guest_agent_sha256
        || agent_observed.observation().size_bytes != artifacts.receipt.guest_agent.size_bytes
    {
        return Err(RunnerError::Drift);
    }
    let config = render_config(&artifacts.wsb_plan).map_err(|_| RunnerError::Drift)?;
    let request = aiw_provider_wsb::ImportedMsiGuestRequest::new(
        run_id,
        deterministic_sandbox_id(run_id),
        &config.sha256,
        expected_guest_agent_sha256,
        msi.scenario.clone(),
        &msi.staged_payload.sha256,
        msi.staged_payload.size_bytes,
        &msi.import_receipt_sha256,
    )
    .map_err(|e| RunnerError::Receipt(e.to_string()))?;
    if transaction.session_id != request.sandbox_id
        || transaction.config_sha256 != request.config_sha256
        || transaction.request_sha256 != request.request_sha256
    {
        return Err(RunnerError::Drift);
    }
    let mut expectation = completion_expectation(
        run_id,
        &request.sandbox_id,
        &config.sha256,
        expected_guest_agent_sha256,
        &request.request_sha256,
    );
    expectation.artifacts[0].path = "scenario-result.json".to_owned();
    expectation.artifacts[0].role = aiw_evidence::ArtifactRole::ScenarioResults;
    use std::os::windows::fs::OpenOptionsExt;
    let output_files = ["completion.json", "scenario-result.json", "evidence.jsonl"]
        .into_iter()
        .map(|leaf| {
            let path = held.output_path().join(leaf);
            ensure_ordinary_file(&path)?;
            OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(path)
                .map_err(|_| RunnerError::Drift)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let verified = verify_completion_receipt(held.output_path(), &expectation)
        .map_err(|e| RunnerError::Receipt(e.to_string()))?;
    if !verified.successful
        || before.result.evidence_root.as_deref() != Some(&verified.evidence_root_hash)
    {
        return Err(RunnerError::Receipt(
            "completion differs from committed result".to_owned(),
        ));
    }
    let scenario: aiw_provider_wsb::ImportedMsiScenarioResult =
        read_bounded_json(&held.output_path().join("scenario-result.json"), 64 * 1024)?;
    scenario
        .validate_for_request(&request)
        .map_err(|e| RunnerError::Receipt(e.to_string()))?;
    let application_token = aiw_provider_wsb::verify_msi_application_token(
        &read_bounded_bytes(&held.output_path().join("evidence.jsonl"), 1024 * 1024)?,
        &verified.evidence_root_hash,
        &request,
        &scenario,
    )
    .map_err(RunnerError::Receipt)?;
    // Re-read commitments to reject concurrent changes without repairing them.
    held.revalidate().map_err(|_| RunnerError::Drift)?;
    for file in &root_files {
        file.revalidate().map_err(|_| RunnerError::Drift)?;
    }
    msi_file.revalidate().map_err(|_| RunnerError::Drift)?;
    msi_observed.revalidate().map_err(|_| RunnerError::Drift)?;
    agent_file.revalidate().map_err(|_| RunnerError::Drift)?;
    agent_observed
        .revalidate()
        .map_err(|_| RunnerError::Drift)?;
    let _retained_outputs = output_files;
    if layout.completed_snapshot().map_err(journal_error)? != before
        || session::inspect_for_recovery(&layout)? != inspection
        || read_bounded_json::<WsbPreparationReceipt>(&root.join("preparation.json"), 1024 * 1024)?
            != artifacts.receipt
    {
        return Err(RunnerError::Drift);
    }
    Ok(WsbMsiAssessmentReport {
        schema_version: "aiw.dev/wsb-msi-assessment-report/v0alpha1".to_owned(),
        run_id: run_id.to_owned(),
        project_revision_sha256: artifacts.receipt.project_revision_sha256,
        outcome: RunOutcome::InsufficientEvidence,
        recorded_cleanup_verified: true,
        receipt_sha256: verified.receipt_sha256,
        evidence_root_hash: verified.evidence_root_hash,
        missing_evidence: evidence_gaps(project),
        unmeasured_scenarios: project
            .scenarios
            .iter()
            .filter(|s| s.id != scenario.scenario_id)
            .map(|s| s.id.clone())
            .collect(),
        scenario,
        application_token,
        requested_assertions: project.assertions.clone(),
        requested_isolation: project.isolation_intent.clone(),
    })
}
