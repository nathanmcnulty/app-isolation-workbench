//! Read-only admission of retained generic assessments. No provider acquisition.
use super::*;
use aiw_provider_wsb::{
    assessment_evidence::VerifiedAssessmentEvidence,
    assessment_observation::ApplicationAssessmentResult,
    assessment_request::ApplicationAssessmentGuestRequest,
};

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GenericAssessmentProgressDiagnostic {
    pub complete_records: usize,
    pub terminal_present: bool,
    pub trailing_incomplete: bool,
    pub recorded_step_indices: Vec<usize>,
    pub created_process_steps: Vec<usize>,
    pub observed_root_exits: Vec<(usize, u32)>,
    /// Creation was recorded before Resume; this never proves code ran.
    pub pending_launch_step: Option<usize>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GenericApplicationRunReport {
    pub schema_version: String,
    pub run_id: String,
    pub project_revision_sha256: String,
    pub semantic_sha256: String,
    pub source_manifest_sha256: String,
    pub guest_agent_sha256: String,
    pub provider_sha256: String,
    pub mode: aiw_provider_wsb::assessment::AssessmentMode,
    /// Reviewed expected context. Observed role and sessions must independently
    /// pass the signed native evidence reducer; this field is not observation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_context: Option<aiw_provider_wsb::assessment_request::AssessmentExecutionContext>,
    pub windows: Option<aiw_probe::WindowsVersionObservation>,
    /// Historical recorded cleanup; reading never observes current provider state.
    pub recorded_cleanup_verified: Option<bool>,
    pub recorded_outcome: Option<RunOutcome>,
    pub evidence_status: String,
    pub receipt_sha256: Option<String>,
    pub evidence_root_hash: Option<String>,
    pub evidence: Option<VerifiedAssessmentEvidence>,
    pub diagnostic_progress: Option<GenericAssessmentProgressDiagnostic>,
    pub gaps: Vec<String>,
}

#[cfg(windows)]
pub fn report_windows_sandbox_application_assessment(
    root: &Path,
    run_id: &str,
    project: &Project,
    expected_agent: &str,
) -> Result<GenericApplicationRunReport, RunnerError> {
    let layout = RunLayout::new(root, run_id).map_err(journal_error)?;
    let before = layout.retained_snapshot().map_err(journal_error)?;
    let receipt: WsbPreparationReceipt =
        read_bounded_json(&root.join("preparation.json"), 2 * 1024 * 1024)?;
    let held = aiw_windows_platform::HeldRunWorkspace::reopen_bound(&receipt.workspace)
        .map_err(|_| RunnerError::Drift)?;
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
    let artifacts = PreparedWsbArtifacts {
        receipt,
        run_plan: read_bounded_json(&root.join("plan.json"), 2 * 1024 * 1024)?,
        wsb_plan: read_bounded_json(&root.join("wsb-plan.json"), 2 * 1024 * 1024)?,
    };
    artifacts
        .validate_historical()
        .map_err(|e| RunnerError::Preparation(e.to_string()))?;
    if read_bounded_json::<WsbPreparationReceipt>(&root.join("preparation.json"), 2 * 1024 * 1024)?
        != artifacts.receipt
    {
        return Err(RunnerError::Drift);
    }
    let assessment = artifacts
        .receipt
        .application_assessment
        .as_ref()
        .ok_or(RunnerError::ApprovalBinding)?;
    assessment
        .validate_project(project)
        .map_err(|e| RunnerError::Preparation(e.to_string()))?;
    let import: WsbPlanningImportReceipt = read_bounded_json(
        &layout.run_dir().join("wsb-planning-import.json"),
        1024 * 1024,
    )?;
    if before.plan != artifacts.run_plan
        || artifacts.receipt.run_id != run_id
        || artifacts.receipt.guest_agent.sha256 != expected_agent
        || artifacts.receipt.project_revision_sha256
            != project_revision_hash(project).map_err(journal_error)?
        || import.preparation_receipt_sha256 != canonical_hash(&artifacts.receipt)?
    {
        return Err(RunnerError::ApprovalBinding);
    }
    let content =
        preparation::application_assessment::open_application_files(&held, &artifacts.receipt)
            .map_err(|_| RunnerError::Drift)?;
    let agent_file = held
        .reopen_tools_file_readonly("aiw-guest-agent.exe")
        .map_err(|_| RunnerError::Drift)?;
    let agent = aiw_windows_platform::HeldApplicationFile::open(agent_file.final_path())
        .map_err(|_| RunnerError::Drift)?;
    if agent.observation().identity != *agent_file.identity()
        || agent.observation().sha256 != expected_agent
        || agent.observation().size_bytes != artifacts.receipt.guest_agent.size_bytes
    {
        return Err(RunnerError::Drift);
    }
    if matches!(
        before.plan.schema.as_str(),
        aiw_orchestrator::APPLICATION_ASSESSMENT_RUN_PLAN_SCHEMA
            | aiw_orchestrator::HISTORICAL_APPLICATION_ASSESSMENT_PLAN_V3
    ) {
        let inspection = session::inspect_for_recovery(&layout)?;
        let report = report_authenticated(
            &held,
            &layout,
            &artifacts,
            &before,
            &inspection,
            expected_agent,
        )?;
        content.revalidate().map_err(|_| RunnerError::Drift)?;
        agent_file.revalidate().map_err(|_| RunnerError::Drift)?;
        agent.revalidate().map_err(|_| RunnerError::Drift)?;
        for file in files {
            file.revalidate().map_err(|_| RunnerError::Drift)?;
        }
        held.revalidate().map_err(|_| RunnerError::Drift)?;
        if layout.retained_snapshot().map_err(journal_error)? != before
            || session::inspect_for_recovery(&layout)? != inspection
        {
            return Err(RunnerError::Drift);
        }
        return Ok(report);
    }
    let config = render_config(&artifacts.wsb_plan).map_err(|_| RunnerError::Drift)?;
    let request = ApplicationAssessmentGuestRequest::new(
        run_id.into(),
        deterministic_sandbox_id(run_id),
        config.sha256,
        expected_agent.into(),
        artifacts.receipt.project_revision_sha256.clone(),
        assessment.compiled.clone(),
    )
    .map_err(RunnerError::Receipt)?;
    let inspection = session::inspect_for_recovery(&layout)?;
    let mut cleanup = None;
    if let Some(transaction) = &inspection.transaction {
        let recovery = transaction.recovery.as_ref().ok_or(RunnerError::Drift)?;
        if before.approval.is_none()
            || transaction.run_id != run_id
            || transaction.plan_hash != before.plan.hash().map_err(journal_error)?
            || transaction.project_revision_hash != request.project_revision_sha256
            || transaction.provider_sha256 != artifacts.receipt.provider.sha256
            || transaction.workspace_identity_sha256 != artifacts.receipt.workspace_identity_sha256
            || transaction.session_id != request.sandbox_id
            || transaction.config_sha256 != request.config_sha256
            || transaction.request_sha256 != request.request_sha256
            || recovery.workspace != artifacts.receipt.workspace
            || recovery.provider_protocol != artifacts.receipt.provider_protocol
            || recovery.request_relative_path != "assessment-request.json"
        {
            return Err(RunnerError::Drift);
        }
        if !inspection.pending_present()
            && transaction.current_state() == SessionTransactionState::CleanupVerified
            && start_settled(transaction)
            && !recovery_request_present(&held.tools_path().join("assessment-request.json"))?
            && !recovery_request_present(
                &held.tools_path().join("assessment-request.json.pending"),
            )?
        {
            cleanup = Some(true);
        }
    }
    let outcome = match &before.status {
        aiw_orchestrator::RecoveryStatus::Terminal { result, .. } => {
            if result.cleanup_complete && cleanup != Some(true) {
                return Err(RunnerError::Drift);
            }
            if !result.cleanup_complete {
                cleanup = None;
            }
            Some(result.outcome)
        }
        _ => None,
    };
    let mut report = GenericApplicationRunReport {
        schema_version: "aiw.dev/generic-application-run-report/v0alpha1".into(), run_id: run_id.into(), project_revision_sha256: request.project_revision_sha256.clone(),
        semantic_sha256: request.assessment.semantic_sha256.clone(), source_manifest_sha256: request.assessment.portable_manifest_sha256.clone(), guest_agent_sha256: expected_agent.into(), provider_sha256: artifacts.receipt.provider.sha256.clone(), mode: request.assessment.mode,
        execution_context: None, windows: None, recorded_cleanup_verified: cleanup, recorded_outcome: outcome, evidence_status: "notRun".into(), receipt_sha256: None, evidence_root_hash: None, evidence: None, diagnostic_progress: None,
        gaps: vec!["Only the declared portable CLI workflow is in scope; descendants, DLLs, network denial and general compatibility remain unmeasured".into(), "Cleanup is historical; this read does not inspect or acquire the provider".into()],
    };
    if before.approval.is_some() && inspection.transaction.is_some() {
        let output = held.output_path();
        let completion_present = match fs::symlink_metadata(output.join("completion.json")) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(RunnerError::Drift),
        };
        if completion_present {
            let custody = hold_application_output(&output)?;
            let mut expectation = completion_expectation(
                &request.run_id,
                &request.sandbox_id,
                &request.config_sha256,
                expected_agent,
                &request.request_sha256,
            );
            expectation.artifacts[0].path = "assessment-result.json".into();
            expectation.artifacts[0].role = aiw_evidence::ArtifactRole::ScenarioResults;
            expectation.artifacts[0].maximum_bytes = 16 * 1024 * 1024;
            expectation.artifacts[1].maximum_bytes = 1024 * 1024;
            add_application_progress_expectation(&output, &mut expectation)?;
            let verification = verify_completion_receipt(&output, &expectation)
                .map_err(|e| RunnerError::Receipt(e.to_string()))?;
            let observed: ApplicationAssessmentResult =
                read_bounded_json(&output.join("assessment-result.json"), 16 * 1024 * 1024)?;
            let bytes = read_bounded_bytes(&output.join("evidence.jsonl"), 1024 * 1024)?;
            let evidence = aiw_provider_wsb::assessment_evidence::verify_assessment_evidence(
                &bytes,
                &verification.evidence_root_hash,
                &request,
                &observed,
            )
            .map_err(RunnerError::Receipt)?;
            verify_application_progress_output(&output, &request, &observed)?;
            if verification.successful != observed.native.driver_completed {
                return Err(RunnerError::Drift);
            }
            if evidence.coverage.collector_write_denied != Some(true) {
                report.gaps.push("Collector mutation-denial checks did not establish the required boundary; application dispatch is blocked, not an application incompatibility finding.".into());
            }
            if evidence.coverage.collector_unimpersonated != Some(true) {
                report.gaps.push("The required elevated collector thread identity was not established; execution evidence remains incomplete.".into());
            }
            if !evidence.driver_complete {
                report.gaps.push("Native setup, observation or cleanup is incomplete. The protected raw result retains the exact failed stage and native diagnostic; this report gives no comparison eligibility.".into());
            }
            report.windows = observed.native.windows;
            report.evidence_status = "verified".into();
            report.receipt_sha256 = Some(verification.receipt_sha256);
            report.evidence_root_hash = Some(verification.evidence_root_hash);
            report.evidence = Some(evidence);
            for file in custody {
                file.revalidate().map_err(|_| RunnerError::Drift)?;
            }
        } else {
            report.evidence_status = "incompletePublication".into();
            report.gaps.push("Completion is absent; retained progress is diagnostic only and cannot establish compatibility. A recorded creation precedes Resume and does not prove application code ran.".into());
            let path = output.join("assessment-progress.jsonl");
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(RunnerError::Drift),
                Ok(_) => {
                    let held_progress = aiw_windows_platform::HeldApplicationFile::open_bounded(
                        &path,
                        16 * 1024 * 1024,
                    )
                    .map_err(|_| RunnerError::Drift)?;
                    let bytes = read_bounded_bytes(&path, 16 * 1024 * 1024)?;
                    let prefix = aiw_provider_wsb::assessment_evidence::parse_assessment_progress(
                        &bytes, &request,
                    )
                    .map_err(RunnerError::Receipt)?;
                    let steps = &prefix.result.native.steps;
                    report.diagnostic_progress = Some(GenericAssessmentProgressDiagnostic {
                        complete_records: prefix.records,
                        terminal_present: prefix.terminal_present,
                        trailing_incomplete: prefix.trailing_incomplete,
                        recorded_step_indices: steps.iter().map(|s| s.index).collect(),
                        created_process_steps: steps
                            .iter()
                            .filter(|s| s.process.is_some())
                            .map(|s| s.index)
                            .collect(),
                        observed_root_exits: steps
                            .iter()
                            .filter_map(|s| {
                                s.process
                                    .as_ref()
                                    .and_then(|p| p.exit_code.map(|code| (s.index, code)))
                            })
                            .collect(),
                        pending_launch_step: prefix.pending_launch.map(|p| p.index),
                    });
                    held_progress.revalidate().map_err(|_| RunnerError::Drift)?;
                }
            }
        }
    }
    if let aiw_orchestrator::RecoveryStatus::Terminal { result, .. } = &before.status
        && result.outcome == RunOutcome::InsufficientEvidence
        && result.evidence_root != report.evidence_root_hash
    {
        return Err(RunnerError::Drift);
    }
    content.revalidate().map_err(|_| RunnerError::Drift)?;
    agent_file.revalidate().map_err(|_| RunnerError::Drift)?;
    agent.revalidate().map_err(|_| RunnerError::Drift)?;
    for file in files {
        file.revalidate().map_err(|_| RunnerError::Drift)?;
    }
    held.revalidate().map_err(|_| RunnerError::Drift)?;
    if layout.retained_snapshot().map_err(journal_error)? != before
        || session::inspect_for_recovery(&layout)? != inspection
    {
        return Err(RunnerError::Drift);
    }
    Ok(report)
}

#[cfg(windows)]
fn report_authenticated(
    held: &aiw_windows_platform::HeldRunWorkspace,
    layout: &RunLayout,
    artifacts: &PreparedWsbArtifacts,
    before: &aiw_orchestrator::RetainedRunSnapshot,
    inspection: &session::SessionRecoveryInspection,
    expected_agent: &str,
) -> Result<GenericApplicationRunReport, RunnerError> {
    let assessment = artifacts
        .receipt
        .application_assessment
        .as_ref()
        .ok_or(RunnerError::Drift)?;
    let mut report=GenericApplicationRunReport{
        schema_version:if before.plan.schema == aiw_orchestrator::APPLICATION_ASSESSMENT_RUN_PLAN_SCHEMA { "aiw.dev/generic-application-run-report/v0alpha3" } else { "aiw.dev/generic-application-run-report/v0alpha2" }.into(),run_id:layout.run_id().into(),
        project_revision_sha256:artifacts.receipt.project_revision_sha256.clone(),semantic_sha256:assessment.compiled.semantic_sha256.clone(),
        source_manifest_sha256:assessment.compiled.portable_manifest_sha256.clone(),guest_agent_sha256:expected_agent.into(),
        provider_sha256:artifacts.receipt.provider.sha256.clone(),mode:assessment.compiled.mode,windows:None,
        execution_context: (before.plan.schema == aiw_orchestrator::APPLICATION_ASSESSMENT_RUN_PLAN_SCHEMA).then_some(aiw_provider_wsb::assessment_request::AssessmentExecutionContext::SYSTEM0),
        recorded_cleanup_verified:None,recorded_outcome:None,evidence_status:"notRun".into(),receipt_sha256:None,evidence_root_hash:None,evidence:None,diagnostic_progress:None,
        gaps:vec!["Only declared portable CLI facts are in scope; descendants, DLLs, network denial and general compatibility remain unmeasured.".into(),"Cleanup is historical; retained Read never queries the provider or regenerates keys.".into(),"Execution origin requires this trusted local approved Start anchor; imported self-chosen keys establish internal integrity only.".into()],
    };
    if let aiw_orchestrator::RecoveryStatus::Terminal { result, .. } = &before.status {
        report.recorded_outcome = Some(result.outcome);
    }
    if let Some(tx) = &inspection.transaction {
        let descriptor =
            assessment_channel_host::validate_recovery_authority(held, layout, &before.plan, tx)?;
        if descriptor.request.assessment != assessment.compiled
            || descriptor.request.agent_sha256 != expected_agent
        {
            return Err(RunnerError::ApprovalBinding);
        }
        let recovery = tx.recovery.as_ref().ok_or(RunnerError::Drift)?;
        if recovery.workspace != artifacts.receipt.workspace
            || recovery.provider_protocol != artifacts.receipt.provider_protocol
            || recovery.request_relative_path != "assessment-request.json"
        {
            return Err(RunnerError::ApprovalBinding);
        }
        if !inspection.pending_present()
            && tx.current_state() == SessionTransactionState::CleanupVerified
            && start_settled(tx)
            && !recovery_request_present(&held.tools_path().join("assessment-request.json"))?
            && !recovery_request_present(
                &held.tools_path().join("assessment-request.json.pending"),
            )?
        {
            report.recorded_cleanup_verified = Some(true);
        }
        match assessment_channel_host::verify_completed(held, layout, &before.plan, tx) {
            Ok(auth) => {
                if auth.verification.successful != auth.observed.native.driver_completed {
                    return Err(RunnerError::Drift);
                }
                if !auth.evidence.driver_complete {
                    report.gaps.push("Authenticated collector setup, observation or cleanup is incomplete; this is not application incompatibility.".into());
                }
                report.windows = auth.observed.native.windows;
                report.evidence_status = "authenticatedLocalStart".into();
                report.receipt_sha256 = Some(auth.verification.receipt_sha256);
                report.evidence_root_hash = Some(auth.verification.evidence_root_hash);
                report.evidence = Some(auth.evidence);
            }
            Err(_) => {
                report.evidence_status = "incompleteOrUnauthenticatedPublication".into();
                report.gaps.push("A complete terminal and all artifact bytes could not be authenticated against the committed local latch; raw publication grants no function or isolation credit.".into());
                match assessment_channel_host::verify_prefix(held,layout,&before.plan,tx) {
                    Ok(Some(prefix))=>{
                        let steps=&prefix.result.native.steps;
                        report.diagnostic_progress=Some(GenericAssessmentProgressDiagnostic{
                            complete_records:prefix.records,terminal_present:prefix.terminal_present,trailing_incomplete:prefix.trailing_incomplete,
                            recorded_step_indices:steps.iter().map(|s|s.index).collect(),created_process_steps:steps.iter().filter(|s|s.process.is_some()).map(|s|s.index).collect(),
                            observed_root_exits:steps.iter().filter_map(|s|s.process.as_ref().and_then(|p|p.exit_code.map(|code|(s.index,code)))).collect(),pending_launch_step:prefix.pending_launch.map(|p|p.index),
                        });
                        report.gaps.push("Authenticated partial progress is diagnostic only; creation is recorded before Resume and does not prove application code ran.".into());
                    }
                    Ok(None)=>{},Err(_)=>report.gaps.push("Retained progress could not be authenticated; no partial native facts admitted.".into()),
                }
            }
        }
    } else if layout
        .run_dir()
        .join(aiw_orchestrator::APPLICATION_CHANNEL_START_INTENT_FILE)
        .exists()
    {
        report.evidence_status = "incompleteStart".into();
        report.gaps.push("Start intent was consumed without a committed execution transaction. It cannot generate a replacement key or retry this run.".into());
    }
    if let aiw_orchestrator::RecoveryStatus::Terminal { result, .. } = &before.status {
        if result.cleanup_complete && report.recorded_cleanup_verified != Some(true) {
            return Err(RunnerError::Drift);
        }
        if !result.cleanup_complete {
            report.recorded_cleanup_verified = None;
        }
        if result.evidence_root != report.evidence_root_hash && result.evidence_root.is_some() {
            report.gaps.push("The recorded terminal evidence root could not be revalidated against the current retained bytes.".into());
            report.evidence = None;
            report.windows = None;
            report.evidence_status = "incompleteOrUnauthenticatedPublication".into();
        }
    }
    Ok(report)
}
