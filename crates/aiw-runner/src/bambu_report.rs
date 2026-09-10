use super::*;

#[cfg(windows)]
pub fn report_windows_sandbox_bambu_run(
    root: &Path,
    run_id: &str,
    project: &Project,
    expected_guest_agent_sha256: &str,
) -> Result<WsbBambuRunReport, RunnerError> {
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
        || !matches!(
            before.result.outcome,
            RunOutcome::InsufficientEvidence | RunOutcome::Failed | RunOutcome::Cancelled
        )
        || (before.result.outcome != RunOutcome::InsufficientEvidence
            && before.result.evidence_root.is_some())
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
    let bambu = artifacts
        .receipt
        .bambu
        .as_ref()
        .ok_or(RunnerError::ApprovalBinding)?;
    if aiw_provider_wsb::compile_bambu_studio_export_scenario(project, &bambu.scenario.scenario_id)
        .map_err(|e| RunnerError::Preparation(e.to_string()))?
        != bambu.scenario
    {
        return Err(RunnerError::ApprovalBinding);
    }
    let bambu_file = held
        .reopen_tools_file_readonly("application.exe")
        .map_err(|_| RunnerError::Drift)?;
    let bambu_observed = aiw_windows_platform::HeldApplicationFile::open(bambu_file.final_path())
        .map_err(|_| RunnerError::Drift)?;
    let agent_file = held
        .reopen_tools_file_readonly("aiw-guest-agent.exe")
        .map_err(|_| RunnerError::Drift)?;
    let agent_observed = aiw_windows_platform::HeldApplicationFile::open(agent_file.final_path())
        .map_err(|_| RunnerError::Drift)?;
    if bambu_file.identity() != &bambu.staged_identity
        || bambu_observed.observation().identity != bambu.staged_identity
        || bambu_observed.observation().sha256 != bambu.staged_payload.sha256
        || bambu_observed.observation().size_bytes != bambu.staged_payload.size_bytes
        || agent_file.identity() != &agent_observed.observation().identity
        || agent_observed.observation().sha256 != expected_guest_agent_sha256
        || agent_observed.observation().size_bytes != artifacts.receipt.guest_agent.size_bytes
    {
        return Err(RunnerError::Drift);
    }
    let config = render_config(&artifacts.wsb_plan).map_err(|_| RunnerError::Drift)?;
    let request = aiw_provider_wsb::ImportedBambuGuestRequest::new(
        run_id,
        deterministic_sandbox_id(run_id),
        &config.sha256,
        expected_guest_agent_sha256,
        bambu.scenario.clone(),
        &bambu.staged_payload.sha256,
        bambu.staged_payload.size_bytes,
        &bambu.import_receipt_sha256,
    )
    .map_err(|e| RunnerError::Receipt(e.to_string()))?;
    if transaction.session_id != request.sandbox_id
        || transaction.config_sha256 != request.config_sha256
        || transaction.request_sha256 != request.request_sha256
    {
        return Err(RunnerError::Drift);
    }
    // Keep input handles alive through both report paths and recheck commitments.
    let revalidate = || -> Result<(), RunnerError> {
        held.revalidate().map_err(|_| RunnerError::Drift)?;
        for file in &root_files {
            file.revalidate().map_err(|_| RunnerError::Drift)?;
        }
        bambu_file.revalidate().map_err(|_| RunnerError::Drift)?;
        bambu_observed
            .revalidate()
            .map_err(|_| RunnerError::Drift)?;
        agent_file.revalidate().map_err(|_| RunnerError::Drift)?;
        agent_observed
            .revalidate()
            .map_err(|_| RunnerError::Drift)?;
        if layout.completed_snapshot().map_err(journal_error)? != before
            || session::inspect_for_recovery(&layout)? != inspection
            || read_bounded_json::<WsbPreparationReceipt>(
                &root.join("preparation.json"),
                1024 * 1024,
            )? != artifacts.receipt
        {
            return Err(RunnerError::Drift);
        }
        Ok(())
    };
    let mut expectation = completion_expectation(
        run_id,
        &request.sandbox_id,
        &request.config_sha256,
        expected_guest_agent_sha256,
        &request.request_sha256,
    );
    expectation.artifacts[0].path = "scenario-result.json".to_owned();
    expectation.artifacts[0].role = aiw_evidence::ArtifactRole::ScenarioResults;
    expectation.artifacts[1].maximum_bytes =
        aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64;
    add_bambu_artifact_expectation(&mut expectation);
    let mut report = WsbBambuRunReport {
        schema_version: "aiw.dev/wsb-bambu-run-report/v0alpha1".to_owned(),
        run_id: run_id.to_owned(),
        project_revision_sha256: artifacts.receipt.project_revision_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        outcome: before.result.outcome,
        recorded_cleanup_verified: true,
        evidence_status: BambuReportEvidenceStatus::Absent,
        receipt_sha256: None,
        evidence_root_hash: None,
        scenario: None,
        artifact: None,
        missing_evidence: vec![
            "ordinary baseline".to_owned(),
            "application-level isolation comparison".to_owned(),
            "descendant boundary and denial canaries".to_owned(),
            "filesystem and registry changes".to_owned(),
            "slicing, printer and cloud workflows".to_owned(),
        ],
    };
    match verify_bambu_output(&held.output_path(), &expectation, &request) {
        Ok((verified, scenario, artifact)) => {
            if (report.outcome == RunOutcome::InsufficientEvidence) != scenario.successful()
                || (scenario.successful()
                    && before.result.evidence_root.as_deref() != Some(&verified.evidence_root_hash))
            {
                return Err(RunnerError::Drift);
            }
            report.evidence_status = BambuReportEvidenceStatus::Verified;
            report.receipt_sha256 = Some(verified.receipt_sha256);
            report.evidence_root_hash = Some(verified.evidence_root_hash);
            report.scenario = Some(scenario);
            report.artifact = artifact;
        }
        Err(error) if report.outcome == RunOutcome::InsufficientEvidence => return Err(error),
        Err(_) => {
            report.evidence_status =
                match fs::symlink_metadata(held.output_path().join("completion.json")) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        BambuReportEvidenceStatus::Absent
                    }
                    _ => BambuReportEvidenceStatus::Rejected,
                };
        }
    }
    revalidate()?;
    Ok(report)
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum BambuReportEvidenceStatus {
    Verified,
    Absent,
    Rejected,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbBambuRunReport {
    pub schema_version: String,
    pub run_id: String,
    pub project_revision_sha256: String,
    pub request_sha256: String,
    pub outcome: RunOutcome,
    pub recorded_cleanup_verified: bool,
    pub evidence_status: BambuReportEvidenceStatus,
    pub receipt_sha256: Option<String>,
    pub evidence_root_hash: Option<String>,
    pub scenario: Option<aiw_provider_wsb::ImportedBambuScenarioResult>,
    pub artifact: Option<aiw_provider_wsb::BambuExportArtifact>,
    pub missing_evidence: Vec<String>,
}

pub(crate) fn add_bambu_artifact_expectation(
    expectation: &mut WindowsSandboxCompletionExpectation,
) {
    expectation.artifacts.push(CompletionArtifactExpectation {
        path: aiw_provider_wsb::BAMBU_EXPORT_ARTIFACT_PATH.to_owned(),
        role: aiw_evidence::ArtifactRole::ScenarioResults,
        sensitivity: aiw_evidence::DataSensitivity::Internal,
        media_type: "model/3mf".to_owned(),
        maximum_bytes: aiw_provider_wsb::BAMBU_MAX_ARTIFACT_BYTES,
    });
}

pub(crate) fn verify_bambu_output(
    output: &Path,
    expectation: &WindowsSandboxCompletionExpectation,
    request: &aiw_provider_wsb::ImportedBambuGuestRequest,
) -> Result<
    (
        aiw_provider_wsb::WindowsSandboxCompletionVerification,
        aiw_provider_wsb::ImportedBambuScenarioResult,
        Option<aiw_provider_wsb::BambuExportArtifact>,
    ),
    RunnerError,
> {
    let _held = [
        "completion.json",
        "scenario-result.json",
        "evidence.jsonl",
        aiw_provider_wsb::BAMBU_EXPORT_ARTIFACT_PATH,
    ]
    .into_iter()
    .map(|leaf| {
        let path = output.join(leaf);
        ensure_ordinary_file(&path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(1).custom_flags(0x00200000);
        }
        options.open(path).map_err(|_| RunnerError::Drift)
    })
    .collect::<Result<Vec<_>, _>>()?;
    let verified = verify_completion_receipt(output, expectation)
        .map_err(|e| RunnerError::Receipt(e.to_string()))?;
    let scenario: aiw_provider_wsb::ImportedBambuScenarioResult =
        read_bounded_json(&output.join("scenario-result.json"), 64 * 1024)?;
    let evidence = read_bounded_bytes(
        &output.join("evidence.jsonl"),
        aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64,
    )?;
    aiw_provider_wsb::verify_bambu_scenario_evidence(
        &evidence,
        &verified.evidence_root_hash,
        request,
        &scenario,
    )
    .map_err(RunnerError::Receipt)?;
    if scenario.successful() != verified.successful {
        return Err(RunnerError::Drift);
    }
    let model = read_bounded_bytes(
        &output.join(aiw_provider_wsb::BAMBU_EXPORT_ARTIFACT_PATH),
        aiw_provider_wsb::BAMBU_MAX_ARTIFACT_BYTES,
    )?;
    let artifact = if scenario.successful() {
        let artifact =
            aiw_provider_wsb::verify_bambu_export(&model).map_err(RunnerError::Receipt)?;
        if scenario.artifact_sha256.as_deref() != Some(&artifact.sha256)
            || scenario.artifact_size_bytes != Some(artifact.size_bytes)
        {
            return Err(RunnerError::Drift);
        }
        Some(artifact)
    } else {
        if !model.is_empty() {
            return Err(RunnerError::Receipt(
                "failed Bambu artifact placeholder must be empty".to_owned(),
            ));
        }
        None
    };
    Ok((verified, scenario, artifact))
}

pub fn render_bambu_run_report_markdown(report: &WsbBambuRunReport) -> String {
    let mut text = format!(
        "# Bambu Studio Sandbox report\n\nRun: `{}`\n\nOutcome: `{:?}`. Recorded cleanup verified: {}. Evidence: `{:?}`.\n\n",
        report.run_id, report.outcome, report.recorded_cleanup_verified, report.evidence_status
    );
    if let Some(scenario) = &report.scenario {
        text.push_str(&format!(
            "Completed stages: `{:?}`. Failed stage: `{:?}`.\n\n",
            scenario.completed_stages, scenario.failed_stage
        ));
        if let Some(artifact) = &report.artifact {
            text.push_str(&format!("Verified STL-to-3MF export: {} vertices, {} triangles, {} bytes. SHA-256: `{}`.\n\n", artifact.vertex_count, artifact.triangle_count, artifact.size_bytes, artifact.sha256));
        }
    }
    text.push_str("This is an in-worker application workflow observation; it does not establish application-level isolation or general compatibility.\n\nUnmeasured:\n\n");
    for gap in &report.missing_evidence {
        text.push_str(&format!("- {gap}\n"));
    }
    text
}
