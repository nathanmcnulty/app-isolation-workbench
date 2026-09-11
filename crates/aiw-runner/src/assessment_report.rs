use super::*;

#[cfg(windows)]
fn verify_historical_scenario(
    project: &Project,
    recorded: &aiw_provider_wsb::CompiledMsiScenario,
) -> Result<(), RunnerError> {
    let compiled =
        aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario(project, &recorded.scenario_id)
            .map_err(|e| RunnerError::Preparation(e.to_string()))?;
    // Legacy snapshots keep their original semantics; validate against today's
    // identical action sequence while preserving their explicit evidence version.
    let mut historical = compiled;
    historical.schema_version = recorded.schema_version.clone();
    historical.profile = recorded.profile.clone();
    if !historical.requires_application_exercise() {
        historical.document_exercise = None;
    } else if !historical.requires_standard_user() {
        historical
            .document_exercise
            .as_mut()
            .expect("compiler includes fixed exercise")
            .document_path = aiw_provider_wsb::DOCUMENT_EXERCISE_PATH.to_owned();
    }
    historical
        .validate()
        .map_err(|e| RunnerError::Preparation(e.to_string()))?;
    if &historical != recorded {
        return Err(RunnerError::ApprovalBinding);
    }
    Ok(())
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_metadata_policy: Option<aiw_probe::DownloadMetadataPolicy>,
    pub receipt_sha256: String,
    pub evidence_root_hash: String,
    pub scenario: aiw_provider_wsb::ImportedMsiScenarioResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_token: Option<aiw_provider_wsb::ImportedMsiApplicationToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard_user_context: Option<aiw_provider_wsb::ImportedMsiRuntimeContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavior: Option<aiw_provider_wsb::ImportedMsiBehaviorEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage_progress: Option<aiw_provider_wsb::ImportedMsiStageProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_file_changes: Option<aiw_provider_wsb::FilesystemSnapshotDiffResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exercise_file_changes: Option<aiw_provider_wsb::FilesystemSnapshotDiffResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_evidence: Option<aiw_provider_wsb::ImportedMsiRegistryEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_registration: Option<aiw_provider_wsb::ImportedMsiProductRegistrationEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_registry_changes: Option<aiw_provider_wsb::RegistrySnapshotDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exercise_registry_changes: Option<aiw_provider_wsb::RegistrySnapshotDiff>,
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

/// Terminal run report. Unsuccessful attempts never contain accepted application evidence.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "reportKind", content = "report", rename_all = "camelCase")]
pub enum WsbMsiRunReport {
    CompletedAssessment(Box<WsbMsiAssessmentReport>),
    UnsuccessfulAttempt(Box<WsbMsiUnsuccessfulReport>),
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbMsiUnsuccessfulReport {
    pub schema_version: String,
    pub run_id: String,
    pub project_revision_sha256: String,
    pub outcome: RunOutcome,
    pub recorded_cleanup_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_metadata_policy: Option<aiw_probe::DownloadMetadataPolicy>,
    pub session_id: String,
    pub request_sha256: String,
    pub installer_sha256: String,
    pub guest_agent_sha256: String,
    pub scenario_sha256: String,
    pub lifecycle: Vec<SessionTransition>,
    pub guest_diagnostic: UnverifiedGuestDiagnostic,
    pub failure_progress: FailureProgressEvidence,
}

/// Correlated failed-run observations; never an accepted compatibility verdict.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "status", content = "evidence", rename_all = "camelCase")]
pub enum FailureProgressEvidence {
    Absent,
    Rejected,
    Verified(Box<VerifiedMsiFailureProgress>),
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedMsiFailureProgress {
    pub receipt_sha256: String,
    pub evidence_root_hash: String,
    pub attempt: aiw_provider_wsb::ImportedMsiFailedAttempt,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<aiw_provider_wsb::ImportedMsiFailedSnapshots>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_file_changes: Option<aiw_provider_wsb::FilesystemSnapshotDiffResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exercise_file_changes: Option<aiw_provider_wsb::FilesystemSnapshotDiffResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_registry_changes: Option<aiw_provider_wsb::RegistrySnapshotDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exercise_registry_changes: Option<aiw_provider_wsb::RegistrySnapshotDiff>,
}

/// This optional file has no completion receipt or evidence-chain binding.
/// Its contents cannot establish a completed stage or application incompatibility.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum UnverifiedGuestDiagnostic {
    Absent,
    Rejected,
    Available { summary: String },
}

#[cfg(windows)]
pub fn report_windows_sandbox_msi(
    root: &Path,
    run_id: &str,
    project: &Project,
    expected_guest_agent_sha256: &str,
) -> Result<WsbMsiAssessmentReport, RunnerError> {
    match report_windows_sandbox_msi_run(root, run_id, project, expected_guest_agent_sha256)? {
        WsbMsiRunReport::CompletedAssessment(report) => Ok(*report),
        WsbMsiRunReport::UnsuccessfulAttempt(_) => Err(RunnerError::Receipt(
            "run has no accepted assessment; use report-wsb-msi-run for unsuccessful attempt diagnostics".to_owned(),
        )),
    }
}

/// Read-only verification of a terminal MSI attempt with recorded exact cleanup.
/// Interrupted, pre-start, or pending-recovery attempts are rejected. Does not use
/// start/recovery APIs, acquire a provider lease, repair a journal, or require
/// that the original intake or current provider binary still exist.
#[cfg(windows)]
pub fn report_windows_sandbox_msi_run(
    root: &Path,
    run_id: &str,
    project: &Project,
    expected_guest_agent_sha256: &str,
) -> Result<WsbMsiRunReport, RunnerError> {
    report_windows_sandbox_msi_run_bound(root, run_id, project, expected_guest_agent_sha256, None)
}

#[cfg(windows)]
pub(crate) fn report_windows_sandbox_msi_run_bound(
    root: &Path, run_id: &str, project: &Project, expected_guest_agent_sha256: &str, expected: Option<(&aiw_probe::ApplicationFileImportReceipt, &aiw_provider_wsb::CompiledMsiScenario)>,
) -> Result<WsbMsiRunReport, RunnerError> {
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
    let msi = artifacts
        .receipt
        .msi
        .as_ref()
        .ok_or(RunnerError::ApprovalBinding)?;
    verify_historical_scenario(project, &msi.scenario)?;
    if let Some((receipt, scenario)) = expected { if &msi.import_receipt != receipt || &msi.scenario != scenario { return Err(RunnerError::ApprovalBinding); } }
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
    // Keep input handles alive through both report paths and recheck commitments.
    let revalidate = || -> Result<(), RunnerError> {
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
        &config.sha256,
        expected_guest_agent_sha256,
        &request.request_sha256,
    );
    expectation.artifacts[0].path = "scenario-result.json".to_owned();
    expectation.artifacts[0].role = aiw_evidence::ArtifactRole::ScenarioResults;
    expectation.artifacts[1].maximum_bytes =
        aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64;
    if matches!(
        before.result.outcome,
        RunOutcome::Failed | RunOutcome::Cancelled
    ) {
        let (guest_diagnostic, _diagnostic_handle) =
            read_unverified_diagnostic(&held.output_path().join("guest-failure.json"));
        let failure_progress = read_failure_progress(&held.output_path(), &expectation, &request);
        revalidate()?;
        return Ok(WsbMsiRunReport::UnsuccessfulAttempt(Box::new(
            WsbMsiUnsuccessfulReport {
                schema_version: if failure_progress_has_snapshots(&failure_progress) {
                    "aiw.dev/wsb-msi-unsuccessful-report/v0alpha4"
                } else if msi.import_receipt.download_metadata_archive.is_some() {
                    "aiw.dev/wsb-msi-unsuccessful-report/v0alpha3"
                } else {
                    "aiw.dev/wsb-msi-unsuccessful-report/v0alpha2"
                }
                .to_owned(),
                run_id: run_id.to_owned(),
                project_revision_sha256: artifacts.receipt.project_revision_sha256.clone(),
                outcome: before.result.outcome,
                recorded_cleanup_verified: true,
                download_metadata_policy: msi
                    .import_receipt
                    .download_metadata_archive
                    .as_ref()
                    .map(|archive| archive.policy.clone()),
                session_id: transaction.session_id.clone(),
                request_sha256: request.request_sha256.clone(),
                installer_sha256: msi.staged_payload.sha256.clone(),
                guest_agent_sha256: expected_guest_agent_sha256.to_owned(),
                scenario_sha256: request.scenario_sha256.clone(),
                lifecycle: transaction.transitions.clone(),
                guest_diagnostic,
                failure_progress,
            },
        )));
    }
    use std::os::windows::fs::OpenOptionsExt;
    let _output_files = ["completion.json", "scenario-result.json", "evidence.jsonl"]
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
    let evidence_bytes = read_bounded_bytes(
        &held.output_path().join("evidence.jsonl"),
        aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64,
    )?;
    let application_token = aiw_provider_wsb::verify_msi_application_token(
        &evidence_bytes,
        &verified.evidence_root_hash,
        &request,
        &scenario,
    )
    .map_err(RunnerError::Receipt)?;
    let standard_user_context = aiw_provider_wsb::verify_msi_runtime_context(
        &evidence_bytes,
        &verified.evidence_root_hash,
        &request,
        &scenario,
        application_token.as_ref(),
    )
    .map_err(RunnerError::Receipt)?;
    let registry_evidence = aiw_provider_wsb::verify_msi_registry_evidence(
        &evidence_bytes,
        &verified.evidence_root_hash,
        &request,
        &scenario,
        standard_user_context.as_ref(),
    )
    .map_err(RunnerError::Receipt)?;
    let product_registration = aiw_provider_wsb::verify_msi_product_registration_evidence(
        &evidence_bytes,
        &verified.evidence_root_hash,
        &request,
        &scenario,
    )
    .map_err(RunnerError::Receipt)?;
    let behavior = aiw_provider_wsb::verify_imported_msi_behavior(
        &evidence_bytes,
        &verified.evidence_root_hash,
        &request,
        &scenario,
    )
    .map_err(RunnerError::Receipt)?;
    let stage_progress = aiw_provider_wsb::verify_imported_msi_stage_progress(
        &evidence_bytes,
        &verified.evidence_root_hash,
        &request,
    )
    .map_err(RunnerError::Receipt)?;
    if stage_progress
        .as_ref()
        .is_some_and(|progress| !progress.successful())
    {
        return Err(RunnerError::Receipt(
            "successful assessment has failed stage progress".to_owned(),
        ));
    }
    let installation_file_changes = behavior
        .as_ref()
        .map(|value| {
            aiw_provider_wsb::diff_filesystem_snapshots(&value.before_install, &value.after_install)
        })
        .transpose()
        .map_err(RunnerError::Receipt)?;
    let exercise_file_changes = behavior
        .as_ref()
        .map(|value| {
            aiw_provider_wsb::diff_filesystem_snapshots(&value.after_install, &value.after_exercise)
        })
        .transpose()
        .map_err(RunnerError::Receipt)?;
    let installation_registry_changes = registry_evidence
        .as_ref()
        .map(|value| {
            aiw_provider_wsb::diff_registry_snapshots(&value.before_install, &value.after_install)
        })
        .transpose()
        .map_err(RunnerError::Receipt)?;
    let exercise_registry_changes = registry_evidence
        .as_ref()
        .map(|value| {
            aiw_provider_wsb::diff_registry_snapshots(&value.after_install, &value.after_exercise)
        })
        .transpose()
        .map_err(RunnerError::Receipt)?;
    revalidate()?;
    Ok(WsbMsiRunReport::CompletedAssessment(Box::new(
        WsbMsiAssessmentReport {
            schema_version: if product_registration.is_some() {
                "aiw.dev/wsb-msi-assessment-report/v0alpha7"
            } else if registry_evidence.is_some() {
                "aiw.dev/wsb-msi-assessment-report/v0alpha6"
            } else if standard_user_context.is_some() {
                "aiw.dev/wsb-msi-assessment-report/v0alpha5"
            } else if msi.import_receipt.download_metadata_archive.is_some() {
                "aiw.dev/wsb-msi-assessment-report/v0alpha4"
            } else if stage_progress.is_some() {
                "aiw.dev/wsb-msi-assessment-report/v0alpha3"
            } else if behavior.is_some() {
                "aiw.dev/wsb-msi-assessment-report/v0alpha2"
            } else {
                "aiw.dev/wsb-msi-assessment-report/v0alpha1"
            }
            .to_owned(),
            run_id: run_id.to_owned(),
            project_revision_sha256: artifacts.receipt.project_revision_sha256,
            outcome: RunOutcome::InsufficientEvidence,
            recorded_cleanup_verified: true,
            download_metadata_policy: msi
                .import_receipt
                .download_metadata_archive
                .as_ref()
                .map(|archive| archive.policy.clone()),
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
            standard_user_context,
            behavior,
            stage_progress,
            installation_file_changes,
            exercise_file_changes,
            registry_evidence,
            product_registration,
            installation_registry_changes,
            exercise_registry_changes,
            requested_assertions: project.assertions.clone(),
            requested_isolation: project.isolation_intent.clone(),
        },
    )))
}

/// Hold an ordinary diagnostic file without following a final reparse point.
/// The message remains unverified even if it parses; malformed output does not
/// prevent reporting independently validated lifecycle records.
#[cfg(windows)]
fn read_unverified_diagnostic(path: &Path) -> (UnverifiedGuestDiagnostic, Option<File>) {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let mut file = match OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)
    {
        // FILE_FLAG_OPEN_REPARSE_POINT
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (UnverifiedGuestDiagnostic::Absent, None);
        }
        Err(_) => return (UnverifiedGuestDiagnostic::Rejected, None),
    };
    let parsed = (|| {
        let metadata = file.metadata().map_err(|_| RunnerError::Drift)?;
        if !metadata.is_file()
            || metadata.file_attributes() & 0x400 != 0
            || metadata.len() > MAX_GUEST_FAILURE_DIAGNOSTIC
        {
            return Err(RunnerError::Drift);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_GUEST_FAILURE_DIAGNOSTIC + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RunnerError::Drift)?;
        parse_guest_failure_diagnostic(&bytes)
    })();
    let diagnostic = match parsed {
        Ok(summary) => UnverifiedGuestDiagnostic::Available { summary },
        Err(_) => UnverifiedGuestDiagnostic::Rejected,
    };
    (diagnostic, Some(file))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn historical_profiles_preserve_fixed_paths_and_reject_changed_semantics() {
        let project: Project = serde_yaml::from_str(include_str!(
            "../../../examples/notepad-plus-plus-msi.aiw.yaml"
        ))
        .unwrap();
        let current = aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario(
            &project,
            "install-launch-close",
        )
        .unwrap();
        for version in 1..=4 {
            let mut recorded = current.clone();
            recorded.schema_version =
                format!("aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha{version}");
            recorded.profile =
                format!("aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha{version}");
            if version < 3 {
                recorded.document_exercise = None;
            } else if version == 3 {
                recorded.document_exercise.as_mut().unwrap().document_path =
                    aiw_provider_wsb::DOCUMENT_EXERCISE_PATH.to_owned();
            }
            let before = recorded.canonical_sha256().unwrap();
            verify_historical_scenario(&project, &recorded).unwrap();
            assert_eq!(recorded.canonical_sha256().unwrap(), before);
            let mut changed = recorded.clone();
            changed.application_sha256 = "0".repeat(64);
            assert!(verify_historical_scenario(&project, &changed).is_err());
            if let Some(exercise) = recorded.document_exercise.as_mut() {
                exercise.document_path = r"C:\foreign\document.txt".to_owned();
                assert!(verify_historical_scenario(&project, &recorded).is_err());
            }
        }
    }

    #[test]
    fn unverified_diagnostic_is_bounded_ordinary_and_held_readonly() {
        let path = std::env::temp_dir().join(format!(
            "aiw-attempt-diagnostic-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(matches!(
            read_unverified_diagnostic(&path).0,
            UnverifiedGuestDiagnostic::Absent
        ));
        let mut created = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        created.write_all(br#"{"schemaVersion":"aiw.dev/wsb-guest-failure/v0alpha1","code":"AIW_GUEST_AGENT_FAILED","summary":"stage\n<script>|[link](url)"}"#).unwrap();
        drop(created);
        let (diagnostic, handle) = read_unverified_diagnostic(&path);
        assert!(
            matches!(diagnostic, UnverifiedGuestDiagnostic::Available { ref summary } if summary == "stage <script>|[link](url)")
        );
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());
        drop(handle);
        fs::write(&path, vec![b'x'; MAX_GUEST_FAILURE_DIAGNOSTIC as usize + 1]).unwrap();
        assert!(matches!(
            read_unverified_diagnostic(&path).0,
            UnverifiedGuestDiagnostic::Rejected
        ));
        fs::write(&path, b"{}").unwrap();
        assert!(matches!(
            read_unverified_diagnostic(&path).0,
            UnverifiedGuestDiagnostic::Rejected
        ));
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(matches!(
            read_unverified_diagnostic(&path).0,
            UnverifiedGuestDiagnostic::Rejected
        ));
        fs::remove_dir(&path).unwrap();
    }
}

#[cfg(windows)]
fn read_failure_progress(
    output: &Path,
    expectation: &WindowsSandboxCompletionExpectation,
    request: &aiw_provider_wsb::ImportedMsiGuestRequest,
) -> FailureProgressEvidence {
    match fs::symlink_metadata(output.join("completion.json")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return FailureProgressEvidence::Absent;
        }
        Err(_) => return FailureProgressEvidence::Rejected,
        Ok(_) => {}
    }
    match verify_failed_msi_progress(output, expectation, request) {
        Ok(verified) => FailureProgressEvidence::Verified(Box::new(verified)),
        Err(_) => FailureProgressEvidence::Rejected,
    }
}

#[cfg(windows)]
fn verify_failed_msi_progress(
    output: &Path,
    expectation: &WindowsSandboxCompletionExpectation,
    request: &aiw_provider_wsb::ImportedMsiGuestRequest,
) -> Result<VerifiedMsiFailureProgress, RunnerError> {
    use std::os::windows::fs::OpenOptionsExt;
    // Keep all receipt-bound bytes immutable through parsing and comparison.
    let _files = ["completion.json", "scenario-result.json", "evidence.jsonl"]
        .into_iter()
        .map(|leaf| {
            let path = output.join(leaf);
            ensure_ordinary_file(&path)?;
            OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x00200000)
                .open(path)
                .map_err(|_| RunnerError::Drift)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let verified = verify_completion_receipt(output, expectation)
        .map_err(|e| RunnerError::Receipt(e.to_string()))?;
    if verified.successful || verified.status != aiw_provider_wsb::CompletionStatus::Failed {
        return Err(RunnerError::Receipt(
            "unsuccessful report requires a failed receipt".to_owned(),
        ));
    }
    let attempt: aiw_provider_wsb::ImportedMsiFailedAttempt =
        read_bounded_json(&output.join("scenario-result.json"), 64 * 1024)?;
    attempt
        .validate_for_request(request)
        .map_err(RunnerError::Receipt)?;
    let bytes = read_bounded_bytes(
        &output.join("evidence.jsonl"),
        aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64,
    )?;
    let progress = aiw_provider_wsb::verify_imported_msi_stage_progress(
        &bytes,
        &verified.evidence_root_hash,
        request,
    )
    .map_err(RunnerError::Receipt)?;
    if progress.as_ref() != Some(&attempt.progress) {
        return Err(RunnerError::Receipt(
            "failed artifact and evidence progress differ".to_owned(),
        ));
    }
    let snapshots = aiw_provider_wsb::verify_msi_failed_snapshots(
        &bytes,
        &verified.evidence_root_hash,
        request,
        &attempt,
    )
    .map_err(RunnerError::Receipt)?;
    let (
        installation_file_changes,
        exercise_file_changes,
        installation_registry_changes,
        exercise_registry_changes,
    ) = match snapshots.as_ref() {
        Some(value) => (
            value
                .before_install
                .as_ref()
                .zip(value.after_install.as_ref())
                .map(|(before, after)| {
                    aiw_provider_wsb::diff_filesystem_snapshots(&before.files, &after.files)
                })
                .transpose()
                .map_err(RunnerError::Receipt)?,
            value
                .after_install
                .as_ref()
                .zip(value.after_exercise.as_ref())
                .map(|(before, after)| {
                    aiw_provider_wsb::diff_filesystem_snapshots(&before.files, &after.files)
                })
                .transpose()
                .map_err(RunnerError::Receipt)?,
            value
                .before_install
                .as_ref()
                .zip(value.after_install.as_ref())
                .map(|(before, after)| {
                    aiw_provider_wsb::diff_registry_snapshots(&before.registry, &after.registry)
                })
                .transpose()
                .map_err(RunnerError::Receipt)?,
            value
                .after_install
                .as_ref()
                .zip(value.after_exercise.as_ref())
                .map(|(before, after)| {
                    aiw_provider_wsb::diff_registry_snapshots(&before.registry, &after.registry)
                })
                .transpose()
                .map_err(RunnerError::Receipt)?,
        ),
        None => (None, None, None, None),
    };
    Ok(VerifiedMsiFailureProgress {
        receipt_sha256: verified.receipt_sha256,
        evidence_root_hash: verified.evidence_root_hash,
        attempt,
        snapshots,
        installation_file_changes,
        exercise_file_changes,
        installation_registry_changes,
        exercise_registry_changes,
    })
}

#[cfg(windows)]
fn failure_progress_has_snapshots(progress: &FailureProgressEvidence) -> bool {
    matches!(progress, FailureProgressEvidence::Verified(value) if value.snapshots.is_some())
}

#[cfg(all(test, windows))]
mod failure_progress_tests {
    use super::*;
    use aiw_evidence::{ArtifactRole, EvidenceEvent, EvidenceLog};
    use aiw_provider_wsb::{
        ApplicationFileEntry, ApplicationFileRoot, ApplicationFilesystemSnapshot,
        ApplicationRegistryRoot, ApplicationRegistrySnapshot, CompletionArtifact, CompletionStatus,
        FailedSnapshotPhase, ImportedMsiFailedAttempt, ImportedMsiFailedSnapshots,
        ImportedMsiGuestRequest, MsiExecutionStage, MsiStageResult, MsiStageStatus, RegistryScope,
        RegistryView, StandardUserRuntimeContext, WindowsSandboxCompletionReceipt,
    };

    #[test]
    fn failed_progress_requires_bound_receipt_matching_artifacts_and_failed_status() {
        let project: Project = serde_yaml::from_str(include_str!(
            "../../../examples/notepad-plus-plus-msi.aiw.yaml"
        ))
        .unwrap();
        let scenario = aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario(
            &project,
            "install-launch-close",
        )
        .unwrap();
        let request = ImportedMsiGuestRequest::new(
            "failed-stage-test",
            "12345678-1234-abcd-9876-1234567890ab",
            "a".repeat(64),
            "b".repeat(64),
            scenario.clone(),
            &scenario.application_sha256,
            1024,
            "c".repeat(64),
        )
        .unwrap();
        let root = std::env::temp_dir().join(format!(
            "aiw-failed-progress-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let stages = MsiExecutionStage::ORDERED
            .into_iter()
            .enumerate()
            .map(|(index, stage)| MsiStageResult {
                stage,
                status: if index < 6 {
                    MsiStageStatus::Passed
                } else if index == 6 {
                    MsiStageStatus::Failed
                } else {
                    MsiStageStatus::NotReached
                },
            })
            .collect();
        let attempt =
            ImportedMsiFailedAttempt::new(&request, stages, "fixed editor mismatch").unwrap();
        let empty_registry = || ApplicationRegistrySnapshot {
            keys: vec![],
            values: vec![],
            absent_roots: [
                (
                    ApplicationRegistryRoot::MachineApplication,
                    RegistryView::Registry64,
                ),
                (
                    ApplicationRegistryRoot::MachineApplication,
                    RegistryView::Registry32,
                ),
                (
                    ApplicationRegistryRoot::UserApplication,
                    RegistryView::Registry64,
                ),
                (
                    ApplicationRegistryRoot::UserApplication,
                    RegistryView::Registry32,
                ),
            ]
            .into_iter()
            .map(|(root, view)| RegistryScope { root, view })
            .collect(),
            issues: vec![],
        };
        let before_install = FailedSnapshotPhase {
            files: ApplicationFilesystemSnapshot {
                entries: vec![],
                issues: vec![],
            },
            registry: empty_registry(),
        };
        let after_install = FailedSnapshotPhase {
            files: ApplicationFilesystemSnapshot {
                entries: vec![ApplicationFileEntry {
                    root: ApplicationFileRoot::Installation,
                    path: "installed.txt".to_owned(),
                    size_bytes: 1,
                    sha256: "a".repeat(64),
                }],
                issues: vec![],
            },
            registry: empty_registry(),
        };
        let snapshots = ImportedMsiFailedSnapshots {
            schema_version: aiw_provider_wsb::IMPORTED_MSI_FAILED_SNAPSHOTS_SCHEMA_VERSION
                .to_owned(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            capture_context: Some(StandardUserRuntimeContext {
                user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
                profile_path: r"C:\Users\AiwStandardUser".to_owned(),
                roaming_app_data: r"C:\Users\AiwStandardUser\AppData\Roaming".to_owned(),
                local_app_data: r"C:\Users\AiwStandardUser\AppData\Local".to_owned(),
                administrators_enabled: false,
            }),
            before_install: Some(before_install),
            after_install: Some(after_install),
            after_exercise: None,
        };
        snapshots.validate_for(&request, &attempt).unwrap();
        let mut log = EvidenceLog::new();
        log.append(EvidenceEvent {
            observed_utc: "untrusted-time".to_owned(),
            kind: aiw_provider_wsb::IMPORTED_MSI_STAGE_PROGRESS_EVENT.to_owned(),
            source: "aiw-guest-agent".to_owned(),
            payload: serde_json::to_value(&attempt.progress).unwrap(),
        })
        .unwrap();
        log.append(EvidenceEvent {
            observed_utc: "untrusted-time".to_owned(),
            kind: aiw_provider_wsb::IMPORTED_MSI_FAILED_SNAPSHOTS_EVENT.to_owned(),
            source: "aiw-guest-agent".to_owned(),
            payload: serde_json::to_value(&snapshots).unwrap(),
        })
        .unwrap();
        let mut bytes = Vec::new();
        for record in log.records() {
            serde_json::to_writer(&mut bytes, record).unwrap();
            bytes.push(b'\n');
        }
        fs::write(root.join("evidence.jsonl"), &bytes).unwrap();
        fs::write(
            root.join("scenario-result.json"),
            serde_json::to_vec(&attempt).unwrap(),
        )
        .unwrap();
        let artifacts = [
            (
                "scenario-result.json",
                ArtifactRole::ScenarioResults,
                "application/json",
            ),
            (
                "evidence.jsonl",
                ArtifactRole::EvidenceLog,
                "application/x-ndjson",
            ),
        ]
        .into_iter()
        .map(|(path, role, media_type)| {
            let bytes = fs::read(root.join(path)).unwrap();
            CompletionArtifact {
                path: path.to_owned(),
                role,
                media_type: media_type.to_owned(),
                size_bytes: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(bytes)),
            }
        })
        .collect();
        let mut receipt = WindowsSandboxCompletionReceipt {
            schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION
                .to_owned(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            config_sha256: request.config_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            agent_sha256: request.agent_sha256.clone(),
            status: CompletionStatus::Failed,
            exit_code: 1,
            evidence_root_hash: log.manifest().unwrap().root_hash,
            artifacts,
        };
        let mut expectation = completion_expectation(
            &request.run_id,
            &request.sandbox_id,
            &request.config_sha256,
            &request.agent_sha256,
            &request.request_sha256,
        );
        expectation.artifacts[0].path = "scenario-result.json".to_owned();
        expectation.artifacts[0].role = ArtifactRole::ScenarioResults;
        fs::write(
            root.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        let verified = verify_failed_msi_progress(&root, &expectation, &request).unwrap();
        assert_eq!(verified.attempt, attempt);
        assert_eq!(
            verified.attempt.progress.stages[6].status,
            MsiStageStatus::Failed
        );
        assert!(verified.snapshots.is_some());
        assert!(verified.installation_file_changes.is_some());
        assert_eq!(
            verified
                .installation_file_changes
                .as_ref()
                .unwrap()
                .diffs
                .len(),
            1
        );
        assert!(verified.exercise_file_changes.is_none());
        assert!(verified.installation_registry_changes.is_some());
        assert!(verified.exercise_registry_changes.is_none());
        let snapshot_receipt = receipt.clone();
        let snapshot_bytes = bytes.clone();
        assert!(matches!(
            read_failure_progress(&root, &expectation, &request),
            FailureProgressEvidence::Verified(_)
        ));
        let mut legacy_log = EvidenceLog::new();
        legacy_log
            .append(EvidenceEvent {
                observed_utc: "untrusted-time".to_owned(),
                kind: aiw_provider_wsb::IMPORTED_MSI_STAGE_PROGRESS_EVENT.to_owned(),
                source: "aiw-guest-agent".to_owned(),
                payload: serde_json::to_value(&attempt.progress).unwrap(),
            })
            .unwrap();
        let mut legacy_bytes = Vec::new();
        for record in legacy_log.records() {
            serde_json::to_writer(&mut legacy_bytes, record).unwrap();
            legacy_bytes.push(b'\n');
        }
        fs::write(root.join("evidence.jsonl"), &legacy_bytes).unwrap();
        receipt.evidence_root_hash = legacy_log.manifest().unwrap().root_hash;
        receipt.artifacts[1].size_bytes = legacy_bytes.len() as u64;
        receipt.artifacts[1].sha256 = hex::encode(Sha256::digest(&legacy_bytes));
        fs::write(
            root.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        let legacy_verified = verify_failed_msi_progress(&root, &expectation, &request).unwrap();
        assert!(legacy_verified.snapshots.is_none());
        assert!(legacy_verified.installation_file_changes.is_none());
        assert!(legacy_verified.installation_registry_changes.is_none());
        fs::write(root.join("evidence.jsonl"), &snapshot_bytes).unwrap();
        receipt = snapshot_receipt.clone();
        fs::write(
            root.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        let mut missing_after_install = snapshots.clone();
        missing_after_install.after_install = None;
        let mut missing_log = EvidenceLog::new();
        missing_log
            .append(EvidenceEvent {
                observed_utc: "untrusted-time".to_owned(),
                kind: aiw_provider_wsb::IMPORTED_MSI_STAGE_PROGRESS_EVENT.to_owned(),
                source: "aiw-guest-agent".to_owned(),
                payload: serde_json::to_value(&attempt.progress).unwrap(),
            })
            .unwrap();
        missing_log
            .append(EvidenceEvent {
                observed_utc: "untrusted-time".to_owned(),
                kind: aiw_provider_wsb::IMPORTED_MSI_FAILED_SNAPSHOTS_EVENT.to_owned(),
                source: "aiw-guest-agent".to_owned(),
                payload: serde_json::to_value(&missing_after_install).unwrap(),
            })
            .unwrap();
        let mut missing_bytes = Vec::new();
        for record in missing_log.records() {
            serde_json::to_writer(&mut missing_bytes, record).unwrap();
            missing_bytes.push(b'\n');
        }
        fs::write(root.join("evidence.jsonl"), &missing_bytes).unwrap();
        receipt.evidence_root_hash = missing_log.manifest().unwrap().root_hash;
        receipt.artifacts[1].size_bytes = missing_bytes.len() as u64;
        receipt.artifacts[1].sha256 = hex::encode(Sha256::digest(&missing_bytes));
        fs::write(
            root.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            read_failure_progress(&root, &expectation, &request),
            FailureProgressEvidence::Rejected
        ));
        fs::write(root.join("evidence.jsonl"), &snapshot_bytes).unwrap();
        receipt = snapshot_receipt;
        fs::write(
            root.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        fs::write(root.join("evidence.jsonl"), b"tampered").unwrap();
        assert!(matches!(
            read_failure_progress(&root, &expectation, &request),
            FailureProgressEvidence::Rejected
        ));
        fs::write(root.join("evidence.jsonl"), &bytes).unwrap();
        receipt.status = CompletionStatus::Succeeded;
        receipt.exit_code = 0;
        fs::write(
            root.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        assert!(verify_failed_msi_progress(&root, &expectation, &request).is_err());
        receipt.status = CompletionStatus::Failed;
        receipt.exit_code = 1;
        fs::write(
            root.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        fs::write(root.join("guest-failure.json"), b"unexpected").unwrap();
        assert!(verify_failed_msi_progress(&root, &expectation, &request).is_err());
        for name in [
            "guest-failure.json",
            "completion.json",
            "scenario-result.json",
            "evidence.jsonl",
        ] {
            fs::remove_file(root.join(name)).unwrap();
        }
        fs::remove_dir(&root).unwrap();
    }
}

