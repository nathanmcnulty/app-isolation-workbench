//! Application-neutral services shared by CLI and desktop. Preview and prepare
//! never approve, acquire a provider or execute an application.
use super::*;
use aiw_provider_wsb::assessment::{
    AssessmentBlocker, AssessmentSettings, CompiledAssessment, compile_assessment,
};

pub const APPLICATION_PREVIEW_SCHEMA: &str = "aiw.dev/application-assessment-preview/v0alpha1";
pub const APPLICATION_RUN_SCHEMA: &str = "aiw.dev/application-assessment-workflow/v0alpha1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationAssessmentPreview {
    pub schema_version: String,
    pub application_display_name: String,
    pub project_revision_sha256: String,
    pub source_manifest: Option<aiw_probe::PortableContentManifest>,
    pub compiled: Option<CompiledAssessment>,
    pub blockers: Vec<AssessmentBlocker>,
    pub provider_calls: u32,
    pub application_executions: u32,
}

pub fn preview_from_manifest(
    project: &Project,
    settings: &AssessmentSettings,
    manifest: &aiw_probe::PortableContentManifest,
) -> Result<ApplicationAssessmentPreview> {
    let result = compile_assessment(project, settings, manifest);
    Ok(ApplicationAssessmentPreview {
        schema_version: APPLICATION_PREVIEW_SCHEMA.into(),
        application_display_name: project.metadata.display_name.clone(),
        project_revision_sha256: aiw_orchestrator::project_revision_hash(project)?,
        source_manifest: Some(manifest.clone()),
        compiled: result.as_ref().ok().cloned(),
        blockers: result.err().unwrap_or_default(),
        provider_calls: 0,
        application_executions: 0,
    })
}

#[cfg(windows)]
pub fn preview(
    project: &Project,
    settings: &AssessmentSettings,
    source: &Path,
) -> Result<ApplicationAssessmentPreview> {
    if !matches!(project.application, ApplicationSource::PortableDirectory(_)) {
        return Ok(ApplicationAssessmentPreview {
            schema_version: APPLICATION_PREVIEW_SCHEMA.into(),
            application_display_name: project.metadata.display_name.clone(),
            project_revision_sha256: aiw_orchestrator::project_revision_hash(project)?,
            source_manifest: None,
            compiled: None,
            blockers: vec![AssessmentBlocker {
                code: aiw_provider_wsb::assessment::AssessmentBlockerCode::UnsupportedSource,
                field: "application".into(),
                message: "the first generic execution capability supports portable-directory staging; installer preparation is not implemented".into(),
            }],
            provider_calls: 0,
            application_executions: 0,
        });
    }
    let held = aiw_windows_platform::HeldPortableDirectory::open(source)
        .map_err(|error| anyhow!("portable source inspection refused: {error}"))?;
    let preview = preview_from_manifest(project, settings, held.manifest())?;
    held.revalidate()
        .map_err(|error| anyhow!("portable source changed during preview: {error}"))?;
    Ok(preview)
}

#[cfg(not(windows))]
pub fn preview(
    _: &Project,
    _: &AssessmentSettings,
    _: &Path,
) -> Result<ApplicationAssessmentPreview> {
    bail!("protected application source preview requires Windows; no execution was attempted")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationAssessmentRun {
    pub schema_version: String,
    pub run_id: String,
    pub workspace: PathBuf,
    pub evidence_root: PathBuf,
    pub project_path: PathBuf,
    pub project_revision_sha256: String,
    pub plan_sha256: String,
    pub assessment_sha256: String,
    pub agent_sha256: String,
}

impl ApplicationAssessmentRun {
    pub fn validate(&self) -> Result<RunLayout> {
        let (layout, _) = self.validate_with_plan()?;
        Ok(layout)
    }

    fn validate_with_plan(&self) -> Result<(RunLayout, aiw_orchestrator::RunPlan)> {
        if self.schema_version != APPLICATION_RUN_SCHEMA
            || !self.workspace.is_absolute()
            || !self.evidence_root.is_absolute()
            || !self.project_path.is_absolute()
            || !valid_sha256(&self.plan_sha256)
            || !valid_sha256(&self.assessment_sha256)
            || !valid_sha256(&self.agent_sha256)
            || !locator_parents_match(&self.workspace, &self.evidence_root, &self.project_path)
        {
            bail!("generic assessment run locator is invalid");
        }
        let layout = RunLayout::new(&self.workspace, &self.run_id)?;
        let snapshot = layout.retained_snapshot()?;
        if snapshot.plan.hash()? != self.plan_sha256
            || snapshot.plan.project_revision_hash != self.project_revision_sha256
        {
            bail!("generic assessment plan differs from retained locator");
        }
        let action = snapshot
            .plan
            .actions
            .get(2)
            .ok_or_else(|| anyhow!("generic assessment action is absent"))?;
        let aiw_orchestrator::PlannedAction::ExecuteWindowsSandboxApplicationAssessment {
            assessment_sha256,
            guest_agent_sha256,
            workspace,
            ..
        } = action
        else {
            bail!("retained action is not a generic application assessment");
        };
        if assessment_sha256 != &self.assessment_sha256
            || guest_agent_sha256 != &self.agent_sha256
            || normalized_path(&workspace.root.final_path)
                != normalized_path(&self.workspace.to_string_lossy())
        {
            bail!("generic assessment source, tool or workspace binding changed");
        }
        Ok((layout, snapshot.plan))
    }

    pub fn project(&self) -> Result<Project> {
        let project: Project =
            serde_yaml::from_slice(&read_file_bounded(&self.project_path, MAX_CONFIG_BYTES)?)?;
        if aiw_orchestrator::project_revision_hash(&project)? != self.project_revision_sha256 {
            bail!("retained assessment project changed");
        }
        Ok(project)
    }
}

/// Windows canonicalize returns extended disk paths, whereas held workspace
/// identities use ordinary DOS paths. Only remove that exact disk prefix:
/// this does not resolve paths, fold case, accept aliases, or establish identity.
fn disk_locator_path(path: &Path) -> &Path {
    if let Some(text) = path.to_str() {
        let bytes = text.as_bytes();
        if text.starts_with(r"\\?\")
            && bytes.len() >= 7
            && bytes[4].is_ascii_alphabetic()
            && bytes[5] == b':'
            && bytes[6] == b'\\'
        {
            return Path::new(&text[4..]);
        }
    }
    path
}

fn locator_parents_match(workspace: &Path, evidence_root: &Path, project_path: &Path) -> bool {
    let evidence_root = disk_locator_path(evidence_root);
    disk_locator_path(workspace).parent() == Some(evidence_root)
        && disk_locator_path(project_path).parent() == Some(evidence_root)
}

fn normalized_path(value: &str) -> String {
    value
        .strip_prefix(r"\\?\")
        .unwrap_or(value)
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_ascii_lowercase()
}

pub struct PreparedApplicationAssessment {
    pub run: ApplicationAssessmentRun,
    pub review: ApprovalReview,
    #[cfg(windows)]
    receipt_retention: Option<ReplayPackageReceiptRetention>,
}

#[cfg(windows)]
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
enum ReplayPackageReceiptRetention {
    Retained,
    Failed,
}

#[cfg(windows)]
impl PreparedApplicationAssessment {
    pub fn replay_package_output(&self) -> serde_json::Value {
        let mut output = serde_json::json!({
            "run": self.run,
            "recipe": self.review.recipe,
            "plan": self.review.plan,
            "proposedApproval": self.review.proposed_approval,
            "approvalRecorded": false,
            "executionStarted": false,
        });
        if let Some(retention) = self.receipt_retention {
            output["receiptRetention"] = serde_json::json!(retention);
        }
        output
    }

    fn finish_replay_preparation(mut self, manifest_sha256: Option<&str>) -> Self {
        self.receipt_retention =
            manifest_sha256.map(
                |digest| match retain_replay_package_preparation(&self, digest) {
                    Ok(()) => ReplayPackageReceiptRetention::Retained,
                    Err(_) => ReplayPackageReceiptRetention::Failed,
                },
            );
        self
    }
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
pub fn prepare_for_review(
    project: &Project,
    settings: &AssessmentSettings,
    source: &Path,
    inputs: &std::collections::BTreeMap<String, PathBuf>,
    agent_source: &Path,
    agent_sha256: &str,
    evidence_parent: &Path,
    identity: &str,
) -> Result<PreparedApplicationAssessment> {
    if identity.trim().is_empty() || !valid_sha256(agent_sha256) {
        bail!("operator and independently enrolled first-party agent identity are required");
    }
    let preview = preview(project, settings, source)?;
    if !preview.blockers.is_empty() {
        bail!(
            "assessment capability blocked: {}",
            serde_json::to_string(&preview.blockers)?
        );
    }
    let run_id = format!("assessment-{}", nonce());
    let evidence_root = create_evidence_root(evidence_parent, &run_id)?;
    let project_path = evidence_root.join("project.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&project_path)?;
    file.write_all(&serde_json::to_vec_pretty(project)?)?;
    file.sync_all()?;
    drop(file);
    let prepared = aiw_runner::prepare_windows_sandbox_application_assessment(
        &evidence_root,
        &run_id,
        project,
        agent_source,
        agent_sha256,
        &now_rfc3339(),
        aiw_runner::ApplicationAssessmentPreparationInput {
            source,
            settings,
            inputs,
        },
    )?;
    // Publish one representation for paths already constructed or observed by
    // trusted preparation. Retained locators still undergo all layout, plan and
    // workspace-binding checks below; spelling equivalence grants no authority.
    let workspace =
        disk_locator_path(Path::new(&prepared.receipt.workspace.root.final_path)).to_path_buf();
    let evidence_root = disk_locator_path(&evidence_root).to_path_buf();
    let project_path = disk_locator_path(&project_path).to_path_buf();
    aiw_runner::import_windows_sandbox_preparation(
        &workspace,
        project,
        agent_sha256,
        &now_rfc3339(),
    )?;
    let assessment = prepared
        .receipt
        .application_assessment
        .as_ref()
        .ok_or_else(|| anyhow!("generic prepared assessment is absent"))?;
    let run = ApplicationAssessmentRun {
        schema_version: APPLICATION_RUN_SCHEMA.into(),
        run_id: run_id.clone(),
        workspace: workspace.clone(),
        evidence_root: evidence_root.clone(),
        project_path,
        project_revision_sha256: prepared.receipt.project_revision_sha256.clone(),
        plan_sha256: prepared.receipt.run_plan_sha256.clone(),
        assessment_sha256: assessment.assessment_sha256()?,
        agent_sha256: agent_sha256.into(),
    };
    save_stage(&evidence_root, "application-assessment", &run)?;
    let review = ApprovalReview {
        run_id,
        workspace,
        evidence_root,
        recipe: serde_json::json!({"schemaVersion":"aiw.dev/application-assessment-review/v0alpha2", "application":project.metadata.display_name,"assessment":assessment.compiled,"executionContext":aiw_provider_wsb::assessment_request::AssessmentExecutionContext::SYSTEM0,"providerChecks":{"runtime":"requiredAtStartNotObserved","requiredProtocol":prepared.receipt.provider_protocol},"mappings":prepared.wsb_plan.mappings,"scope":aiw_provider_wsb::assessment::ASSESSMENT_SCOPE}),
        proposed_approval: ApprovalRecord::for_plan(&prepared.run_plan, identity, now_rfc3339())?,
        plan: prepared.run_plan,
    };
    run.validate()?;
    Ok(PreparedApplicationAssessment {
        run,
        review,
        receipt_retention: None,
    })
}

pub fn request_cancellation(run: &ApplicationAssessmentRun) -> Result<()> {
    let layout = run.validate()?;
    if matches!(
        layout.status()?,
        aiw_orchestrator::RecoveryStatus::Terminal { .. }
    ) {
        bail!("assessment is already terminal");
    }
    layout.request_cancellation("owned-application-assessment", now_rfc3339())?;
    Ok(())
}

#[cfg(windows)]
pub fn start(run: &ApplicationAssessmentRun) -> Result<aiw_runner::WsbApprovedExecution> {
    run.validate()?;
    let project = run.project()?;
    aiw_runner::start_approved_windows_sandbox(
        &run.workspace,
        &run.project_path,
        &project,
        &run.agent_sha256,
        3600,
    )
    .map_err(Into::into)
}

pub fn open_retained(workspace: &Path, run_id: &str) -> Result<ApplicationAssessmentRun> {
    let parent = workspace
        .parent()
        .ok_or_else(|| anyhow!("assessment parent is absent"))?;
    let run: ApplicationAssessmentRun = serde_json::from_slice(&read_file_bounded(
        &parent.join("application-assessment.json"),
        128 * 1024,
    )?)?;
    if run.run_id != run_id
        || normalized_path(&run.workspace.to_string_lossy())
            != normalized_path(&workspace.to_string_lossy())
    {
        bail!("retained locator does not identify this assessment");
    }
    run.validate()?;
    Ok(run)
}

#[cfg(windows)]
pub fn report(run: &ApplicationAssessmentRun) -> Result<aiw_runner::GenericApplicationRunReport> {
    run.validate()?;
    report_validated_run(run)
}

#[cfg(windows)]
fn report_validated_run(
    run: &ApplicationAssessmentRun,
) -> Result<aiw_runner::GenericApplicationRunReport> {
    aiw_runner::report_windows_sandbox_application_assessment(
        &run.workspace,
        &run.run_id,
        &run.project()?,
        &run.agent_sha256,
    )
    .map_err(Into::into)
}

#[cfg(windows)]
pub fn prepare_package_for_review(
    package: &Path,
    agent_source: &Path,
    agent_sha256: &str,
    evidence_parent: &Path,
    identity: &str,
) -> Result<PreparedApplicationAssessment> {
    prepare_package_for_review_with_manifest_sha256(
        package,
        None,
        agent_source,
        agent_sha256,
        evidence_parent,
        identity,
    )
}

#[cfg(windows)]
pub fn prepare_package_for_review_with_manifest_sha256(
    package: &Path,
    expected_manifest_sha256: Option<&str>,
    agent_source: &Path,
    agent_sha256: &str,
    evidence_parent: &Path,
    identity: &str,
) -> Result<PreparedApplicationAssessment> {
    let package = super::application_package::verify_package_with_manifest_sha256(
        package,
        expected_manifest_sha256,
    )?;
    let prepared = prepare_for_review(
        &package.package.project,
        &package.package.compiled.settings,
        &package.source,
        &package.inputs,
        agent_source,
        agent_sha256,
        evidence_parent,
        identity,
    )?;
    package.revalidate()?;
    Ok(prepared
        .finish_replay_preparation(expected_manifest_sha256.map(|_| package.manifest_sha256())))
}

#[cfg(windows)]
const REPLAY_PREPARATION_SCHEMA: &str = "aiw.dev/replay-package-preparation/v0alpha1";

#[cfg(windows)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplayPackagePreparationEvidence {
    schema_version: String,
    run_id: String,
    plan_sha256: String,
    package_manifest_sha256: String,
}

#[cfg(windows)]
#[derive(Debug, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ReplayPackageProvenance {
    Matched {
        plan_sha256: String,
        package_manifest_sha256: String,
    },
    Missing,
    Mismatched,
    Unavailable,
}

#[cfg(windows)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationAssessmentProvenanceReport {
    #[serde(flatten)]
    pub report: aiw_runner::GenericApplicationRunReport,
    pub replay_provenance: ReplayPackageProvenance,
}

#[cfg(windows)]
pub fn report_with_replay_provenance(
    run: &ApplicationAssessmentRun,
) -> Result<ApplicationAssessmentProvenanceReport> {
    let (_, plan) = run.validate_with_plan()?;
    let report = report_validated_run(run)?;
    let replay_provenance = read_replay_provenance(run, &plan);
    Ok(ApplicationAssessmentProvenanceReport {
        report,
        replay_provenance,
    })
}

#[cfg(windows)]
fn read_replay_provenance(
    run: &ApplicationAssessmentRun,
    plan: &aiw_orchestrator::RunPlan,
) -> ReplayPackageProvenance {
    use ReplayPackageProvenance as Provenance;
    let Some(aiw_orchestrator::PlannedAction::ExecuteWindowsSandboxApplicationAssessment {
        workspace,
        ..
    }) = plan.actions.get(2)
    else {
        return Provenance::Unavailable;
    };
    let bytes = match aiw_windows_platform::read_replay_preparation_receipt(&workspace.parent) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Provenance::Missing,
        Err(aiw_windows_platform::WorkspaceError::IdentityRejected) => {
            return Provenance::Mismatched;
        }
        Err(_) => return Provenance::Unavailable,
    };
    let Ok(receipt) = serde_json::from_slice::<ReplayPackagePreparationEvidence>(&bytes) else {
        return Provenance::Mismatched;
    };
    if receipt.schema_version != REPLAY_PREPARATION_SCHEMA
        || receipt.run_id != run.run_id
        || receipt.plan_sha256 != run.plan_sha256
        || !valid_sha256(&receipt.package_manifest_sha256)
    {
        return Provenance::Mismatched;
    }
    Provenance::Matched {
        plan_sha256: receipt.plan_sha256,
        package_manifest_sha256: receipt.package_manifest_sha256,
    }
}

#[cfg(windows)]
fn retain_replay_package_preparation(
    prepared: &PreparedApplicationAssessment,
    package_manifest_sha256: &str,
) -> Result<()> {
    let Some(aiw_orchestrator::PlannedAction::ExecuteWindowsSandboxApplicationAssessment {
        workspace,
        ..
    }) = prepared.review.plan.actions.get(2)
    else {
        bail!("prepared assessment action is absent");
    };
    let run = &prepared.run;
    let bytes = serde_json::to_vec_pretty(&ReplayPackagePreparationEvidence {
        schema_version: REPLAY_PREPARATION_SCHEMA.into(),
        run_id: run.run_id.clone(),
        plan_sha256: run.plan_sha256.clone(),
        package_manifest_sha256: package_manifest_sha256.into(),
    })?;
    aiw_windows_platform::publish_replay_preparation_receipt(&workspace.parent, &bytes)?;
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationWorkflowComparison {
    pub schema_version: &'static str,
    pub comparable: bool,
    pub baseline: aiw_runner::GenericApplicationRunReport,
    pub candidate: aiw_runner::GenericApplicationRunReport,
    pub gaps: Vec<String>,
}

#[cfg(windows)]
pub fn compare_retained(
    baseline: &ApplicationAssessmentRun,
    candidate: &ApplicationAssessmentRun,
) -> Result<ApplicationWorkflowComparison> {
    Ok(compare_reports(report(baseline)?, report(candidate)?))
}

#[cfg(any(windows, test))]
fn compare_reports(
    baseline: aiw_runner::GenericApplicationRunReport,
    candidate: aiw_runner::GenericApplicationRunReport,
) -> ApplicationWorkflowComparison {
    use aiw_provider_wsb::assessment::AssessmentMode;
    use aiw_provider_wsb::assessment_evidence::AssessmentFactStatus;
    let mut gaps = Vec::new();
    if baseline.mode != AssessmentMode::Ordinary
        || candidate.mode != AssessmentMode::ClassicAppContainer
    {
        gaps.push(
            "comparison requires an ordinary baseline and classic AppContainer candidate".into(),
        );
    }
    if baseline.semantic_sha256 != candidate.semantic_sha256
        || baseline.source_manifest_sha256 != candidate.source_manifest_sha256
        || baseline.guest_agent_sha256 != candidate.guest_agent_sha256
        || baseline.provider_sha256 != candidate.provider_sha256
    {
        gaps.push("source, inputs, workflow or executor identities differ".into());
    }
    if baseline.windows.is_none() || baseline.windows != candidate.windows {
        gaps.push("fresh worker Windows versions are absent or differ".into());
    }
    if baseline.execution_context != candidate.execution_context {
        gaps.push("collector role, application session or desktop policy differs".into());
    }
    if baseline.run_id == candidate.run_id {
        gaps.push("comparison requires independently prepared fresh workers".into());
    }
    if !baseline.has_authenticated_start_evidence() || !candidate.has_authenticated_start_evidence()
    {
        gaps.push(
            "both runs require evidence authenticated against their local approved Start".into(),
        );
    }
    for row in [&baseline, &candidate] {
        if row.recorded_outcome != Some(aiw_orchestrator::RunOutcome::InsufficientEvidence)
            || row.recorded_cleanup_verified != Some(true)
            || row.evidence.as_ref().is_none_or(|e| {
                !e.driver_complete
                    || e.coverage.process_records == 0
                    || e.coverage.process_records != e.coverage.measured_root_policies
                    || e.coverage.complete_captures != e.coverage.process_records * 2
            })
        {
            gaps.push("both runs require completed outer transactions, complete admitted driver evidence, root observations, captures and recorded cleanup".into());
        }
    }
    if baseline
        .evidence
        .as_ref()
        .is_none_or(|e| e.workflow_status != AssessmentFactStatus::Passed)
    {
        gaps.push(
            "baseline workflow did not pass; candidate behavior cannot establish a regression"
                .into(),
        );
    }
    let comparable = gaps.is_empty();
    gaps.push("Comparison covers declared CLI assertions and root-token policy only. Descendants, memory, registry, brokers and denial controls remain unmeasured; no general compatibility or isolation verdict follows.".into());
    ApplicationWorkflowComparison {
        schema_version: "aiw.dev/application-workflow-comparison/v0alpha1",
        comparable,
        baseline,
        candidate,
        gaps,
    }
}

#[cfg(test)]
mod comparison_tests {
    use super::*;
    use aiw_provider_wsb::assessment::AssessmentMode;
    use aiw_provider_wsb::assessment_evidence::{
        AssessmentFactStatus::Passed, VerifiedAssessmentCleanup, VerifiedAssessmentCoverage,
        VerifiedAssessmentEvidence,
    };

    fn completed_report(
        run_id: &str,
        mode: AssessmentMode,
    ) -> aiw_runner::GenericApplicationRunReport {
        aiw_runner::GenericApplicationRunReport {
            schema_version: "aiw.dev/generic-application-run-report/v0alpha3".into(),
            run_id: run_id.into(),
            project_revision_sha256: "0".repeat(64),
            semantic_sha256: "1".repeat(64),
            source_manifest_sha256: "2".repeat(64),
            guest_agent_sha256: "3".repeat(64),
            provider_sha256: "4".repeat(64),
            mode,
            execution_context: None,
            windows: Some(aiw_probe::WindowsVersionObservation {
                major: 10,
                minor: 0,
                build: 26100,
                revision: 1,
                observer_architecture: "x64".into(),
            }),
            recorded_cleanup_verified: Some(true),
            recorded_outcome: Some(aiw_orchestrator::RunOutcome::InsufficientEvidence),
            evidence_status: "authenticatedLocalStart".into(),
            receipt_sha256: Some("5".repeat(64)),
            evidence_root_hash: Some("6".repeat(64)),
            evidence: Some(VerifiedAssessmentEvidence {
                schema_version: "fixture".into(),
                scope: String::new(),
                semantic_sha256: "1".repeat(64),
                mode,
                status:
                    aiw_provider_wsb::assessment_evidence::AssessmentEvidenceStatus::WorkflowPassed,
                workflow_status: Passed,
                driver_complete: true,
                steps: vec![],
                assertions: vec![],
                coverage: VerifiedAssessmentCoverage {
                    planned_steps: 3,
                    retained_steps: 3,
                    process_records: 1,
                    complete_captures: 2,
                    measured_root_policies: 1,
                    collector_write_denied: Some(true),
                    collector_unimpersonated: Some(true),
                    collector_key_protected: Some(true),
                    collector_storage: None,
                    windows_observed: true,
                    gaps: vec![],
                },
                cleanup: VerifiedAssessmentCleanup {
                    status: Passed,
                    application_jobs_empty: Some(true),
                    environment_destroyed: Some(true),
                    profile_unloaded: Some(true),
                    account_deleted: Some(true),
                    appcontainer_profile_deleted: (mode == AssessmentMode::ClassicAppContainer)
                        .then_some(true),
                },
            }),
            diagnostic_progress: None,
            gaps: vec![],
        }
    }

    #[cfg(windows)]
    #[test]
    fn replay_provenance_extends_the_report_without_changing_its_fields() {
        let report = completed_report("fixture", AssessmentMode::Ordinary);
        let existing = serde_json::to_value(&report).unwrap();
        let mut extended = serde_json::to_value(ApplicationAssessmentProvenanceReport {
            report,
            replay_provenance: ReplayPackageProvenance::Missing,
        })
        .unwrap();
        assert_eq!(
            extended.as_object_mut().unwrap().remove("replayProvenance"),
            Some(serde_json::json!({"status":"missing"}))
        );
        assert_eq!(extended, existing);
    }

    #[test]
    fn comparison_requires_authenticated_start_for_both_retained_reports() {
        let ordinary = completed_report("ordinary", AssessmentMode::Ordinary);
        let classic = completed_report("classic", AssessmentMode::ClassicAppContainer);
        assert!(compare_reports(ordinary.clone(), classic.clone()).comparable);

        let mut historical_ordinary = ordinary.clone();
        historical_ordinary.evidence_status = "verified".into();
        let mut historical_classic = classic.clone();
        historical_classic.evidence_status = "verified".into();

        for comparison in [
            compare_reports(historical_ordinary.clone(), classic),
            compare_reports(ordinary, historical_classic.clone()),
            compare_reports(historical_ordinary, historical_classic),
        ] {
            assert!(!comparison.comparable);
            assert!(
                comparison
                    .gaps
                    .iter()
                    .any(|gap| gap.contains("local approved Start"))
            );
            assert!(comparison.baseline.evidence.is_some());
            assert!(comparison.candidate.evidence.is_some());
        }
    }
}

#[cfg(test)]
mod locator_tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn replay_receipt_conflicts_return_a_recoverable_pending_locator() {
        use aiw_orchestrator::{
            APPLICATION_ASSESSMENT_TRUST_DELTA, PlannedAction, RecoveryStatus, RunLifecycleKind,
            WSB_APPLICATION_ASSESSMENT_IMPORT_SCHEMA, WsbPlanningImportReceipt,
            WsbPlanningImportStatus,
        };
        use aiw_windows_platform::HeldRunWorkspace;
        use std::fs;

        struct FixtureRoot(PathBuf);
        impl Drop for FixtureRoot {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        let root = std::env::temp_dir().join(format!(
            "aiw-replay-evidence-{}-{}",
            std::process::id(),
            nonce()
        ));
        fs::create_dir(&root).unwrap();
        let owned_root = FixtureRoot(root);
        let evidence_root = owned_root.0.canonicalize().unwrap();
        let run_id = "fixture-run";
        let held = HeldRunWorkspace::create(&evidence_root, run_id).unwrap();
        let binding = held.evidence().clone();
        let workspace_path = PathBuf::from(&binding.root.final_path);
        let workspace = disk_locator_path(&workspace_path).to_path_buf();
        let workspace_sha256 = lowercase_sha256(
            &aiw_evidence::canonical_json_bytes(&serde_json::to_value(&binding).unwrap()).unwrap(),
        );
        let plan = aiw_orchestrator::RunPlan::new(
            run_id,
            "fixture-project",
            "a".repeat(64),
            RunLifecycleKind::Assessment,
            "now",
            vec![
                PlannedAction::AssessHost,
                PlannedAction::PrepareWorkspace,
                PlannedAction::ExecuteWindowsSandboxApplicationAssessment {
                    provider_protocol: Some(
                        aiw_probe::WindowsSandboxCliAdapter::V0_8_107_0.protocol(),
                    ),
                    evidence_channel: Some(
                        aiw_probe::APPLICATION_ASSESSMENT_CHANNEL_PROTOCOL.into(),
                    ),
                    sandbox_plan_sha256: "b".repeat(64),
                    provider_sha256: "c".repeat(64),
                    guest_agent_sha256: "d".repeat(64),
                    workspace_identity_sha256: workspace_sha256.clone(),
                    workspace: Box::new(binding.clone()),
                    intake_receipt_sha256: "e".repeat(64),
                    source_manifest_sha256: "f".repeat(64),
                    assessment_sha256: "1".repeat(64),
                },
                PlannedAction::CollectEvidence,
            ],
            vec![APPLICATION_ASSESSMENT_TRUST_DELTA.into()],
        )
        .unwrap();
        let plan_sha256 = plan.hash().unwrap();
        RunLayout::new(&workspace, run_id)
            .unwrap()
            .create_or_verify_pending_wsb_import_bound(
                &held,
                &plan,
                &WsbPlanningImportReceipt {
                    schema_version: WSB_APPLICATION_ASSESSMENT_IMPORT_SCHEMA.into(),
                    run_id: run_id.into(),
                    imported_at: "now".into(),
                    status: WsbPlanningImportStatus::PendingApproval,
                    project_revision_sha256: plan.project_revision_hash.clone(),
                    workspace_root: binding.root.final_path.clone(),
                    workspace_identity_sha256: workspace_sha256,
                    preparation_receipt_sha256: "2".repeat(64),
                    run_plan_sha256: plan_sha256.clone(),
                    windows_sandbox_plan_sha256: "b".repeat(64),
                    guest_agent_sha256: "d".repeat(64),
                    provider_sha256: "c".repeat(64),
                    run_root: binding.root.final_path.clone(),
                    journal_sequence: 1,
                    approval_present: false,
                    provider_acquired: false,
                    provider_mutated: false,
                },
            )
            .unwrap();
        drop(held);
        let run = ApplicationAssessmentRun {
            schema_version: APPLICATION_RUN_SCHEMA.into(),
            run_id: run_id.into(),
            workspace: workspace.clone(),
            project_path: disk_locator_path(&evidence_root).join("project.json"),
            evidence_root: disk_locator_path(&evidence_root).to_path_buf(),
            project_revision_sha256: plan.project_revision_hash.clone(),
            plan_sha256: plan_sha256.clone(),
            assessment_sha256: "1".repeat(64),
            agent_sha256: "d".repeat(64),
        };
        let locator = evidence_root.join("application-assessment.json");
        save_stage(&evidence_root, "application-assessment", &run).unwrap();
        let original_locator = fs::read(&locator).unwrap();
        let make_prepared = || PreparedApplicationAssessment {
            run: run.clone(),
            review: ApprovalReview {
                run_id: run_id.into(),
                workspace: workspace.clone(),
                evidence_root: run.evidence_root.clone(),
                recipe: serde_json::json!({}),
                proposed_approval: ApprovalRecord::for_plan(&plan, "operator", "now").unwrap(),
                plan: plan.clone(),
            },
            receipt_retention: None,
        };
        let output = |prepared: PreparedApplicationAssessment| {
            let bytes = serde_json::to_vec_pretty(&prepared.replay_package_output()).unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };
        let unpinned = output(make_prepared().finish_replay_preparation(None));
        assert!(unpinned.get("receiptRetention").is_none());

        let (_, retained_plan) = run.validate_with_plan().unwrap();
        let provenance =
            || serde_json::to_value(read_replay_provenance(&run, &retained_plan)).unwrap();
        assert_eq!(provenance(), serde_json::json!({"status":"missing"}));

        let digest = "3".repeat(64);
        let record = evidence_root.join("replay-package-preparation.json");
        let staged = evidence_root.join("replay-package-preparation.json.pending");
        assert!(!record.exists());
        assert!(!staged.exists());
        fs::write(&staged, b"foreign staging bytes").unwrap();
        let failed = output(make_prepared().finish_replay_preparation(Some(&digest)));
        assert_eq!(failed["receiptRetention"], "failed");
        assert_eq!(failed["run"], unpinned["run"]);
        assert_eq!(failed["approvalRecorded"], false);
        assert_eq!(failed["executionStarted"], false);
        assert!(!record.exists());
        assert_eq!(fs::read(&staged).unwrap(), b"foreign staging bytes");
        assert_eq!(provenance(), serde_json::json!({"status":"missing"}));
        fs::remove_file(&staged).unwrap();
        let recovered: ApplicationAssessmentRun =
            serde_json::from_value(failed["run"].clone()).unwrap();
        assert_eq!(recovered, run);
        assert!(matches!(
            recovered.validate().unwrap().status().unwrap(),
            RecoveryStatus::PendingApproval { plan_hash, .. } if plan_hash == plan_sha256
        ));
        assert_eq!(fs::read(&locator).unwrap(), original_locator);

        let retained = output(make_prepared().finish_replay_preparation(Some(&digest)));
        assert_eq!(retained["receiptRetention"], "retained");
        assert!(!staged.exists());
        let original_record = fs::read(&record).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&original_record).unwrap(),
            serde_json::json!({
                "schemaVersion": "aiw.dev/replay-package-preparation/v0alpha1",
                "runId": run_id,
                "planSha256": plan_sha256,
                "packageManifestSha256": digest,
            })
        );

        let collision = output(make_prepared().finish_replay_preparation(Some(&"4".repeat(64))));
        assert_eq!(collision["receiptRetention"], "failed");
        assert_eq!(collision["run"], unpinned["run"]);
        assert!(!staged.exists());
        assert_eq!(fs::read(&record).unwrap(), original_record);
        assert_eq!(
            provenance(),
            serde_json::json!({
                "status":"matched",
                "planSha256":plan_sha256,
                "packageManifestSha256":digest,
            })
        );

        let valid: serde_json::Value = serde_json::from_slice(&original_record).unwrap();
        for (field, changed) in [
            ("schemaVersion", serde_json::json!("unknown")),
            ("runId", serde_json::json!("another-run")),
            ("planSha256", serde_json::json!("4".repeat(64))),
            ("packageManifestSha256", serde_json::json!("invalid")),
            ("extra", serde_json::json!("private value")),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = changed;
            fs::write(&record, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert_eq!(provenance(), serde_json::json!({"status":"mismatched"}));
        }
        fs::write(&record, b"{").unwrap();
        assert_eq!(provenance(), serde_json::json!({"status":"mismatched"}));

        use std::os::windows::fs::OpenOptionsExt;
        let busy = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&record)
            .unwrap();
        assert_eq!(provenance(), serde_json::json!({"status":"unavailable"}));
        drop(busy);
    }

    #[test]
    fn disk_locator_conversion_only_removes_extended_drive_prefix() {
        assert_eq!(
            disk_locator_path(Path::new(r"\\?\C:\Evidence\run")),
            Path::new(r"C:\Evidence\run")
        );
        for path in [
            r"C:\Evidence\run",
            r"\\?\UNC\server\share\run",
            r"\\.\C:\Evidence\run",
            r"\\?\GLOBALROOT\Device\volume\run",
            r"\\?\C:relative",
            r"\\?\C:/Evidence/run",
            r"relative\run",
        ] {
            assert_eq!(disk_locator_path(Path::new(path)), Path::new(path));
        }
        // Other spelling changes deliberately remain unchanged, not resolved.
        assert_eq!(
            disk_locator_path(Path::new(r"\\?\C:\Evidence\..\other")),
            Path::new(r"C:\Evidence\..\other")
        );
    }

    #[cfg(windows)]
    #[test]
    fn locator_parent_equivalence_is_limited_to_extended_drive_spelling() {
        for workspace in [r"C:\Evidence\run", r"\\?\C:\Evidence\run"] {
            for evidence in [r"C:\Evidence", r"\\?\C:\Evidence"] {
                for project in [r"C:\Evidence\project.json", r"\\?\C:\Evidence\project.json"] {
                    assert!(locator_parents_match(
                        Path::new(workspace),
                        Path::new(evidence),
                        Path::new(project),
                    ));
                }
            }
        }
        // This is the construction-time mismatch present before the fix.
        assert_ne!(
            Path::new(r"C:\Evidence\run").parent(),
            Some(Path::new(r"\\?\C:\Evidence"))
        );
        for (workspace, project) in [
            (r"D:\Evidence\run", r"C:\Evidence\project.json"),
            (r"C:\Other\run", r"C:\Evidence\project.json"),
            (r"C:\Evidence\run", r"C:\Other\project.json"),
            (r"C:\evidence\run", r"C:\Evidence\project.json"),
            (r"\\?\UNC\server\Evidence\run", r"C:\Evidence\project.json"),
        ] {
            assert!(!locator_parents_match(
                Path::new(workspace),
                Path::new(r"\\?\C:\Evidence"),
                Path::new(project),
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn equivalent_locator_spelling_does_not_bypass_retained_plan_checks() {
        let root =
            std::env::temp_dir().join(format!("aiw-locator-{}-{}", std::process::id(), nonce()));
        std::fs::create_dir(&root).unwrap();
        let evidence_root = root.canonicalize().unwrap();
        let workspace = disk_locator_path(&evidence_root).join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let plan = aiw_orchestrator::RunPlan::new(
            "locator-test",
            "project",
            "a".repeat(64),
            aiw_orchestrator::RunLifecycleKind::Assessment,
            "now",
            vec![aiw_orchestrator::PlannedAction::AssessHost],
            vec![],
        )
        .unwrap();
        let layout = RunLayout::new(&workspace, &plan.run_id).unwrap();
        layout.create(&plan).unwrap();
        let mut run = ApplicationAssessmentRun {
            schema_version: APPLICATION_RUN_SCHEMA.into(),
            run_id: plan.run_id.clone(),
            workspace,
            project_path: evidence_root.join("project.json"),
            evidence_root,
            project_revision_sha256: "a".repeat(64),
            plan_sha256: plan.hash().unwrap(),
            assessment_sha256: "b".repeat(64),
            agent_sha256: "c".repeat(64),
        };
        // Equivalent paths pass shape checks, but a retained non-assessment
        // plan cannot borrow generic execution authority from the locator.
        assert_eq!(
            run.validate().err().unwrap().to_string(),
            "generic assessment action is absent"
        );
        run.plan_sha256 = "d".repeat(64);
        assert_eq!(
            run.validate().err().unwrap().to_string(),
            "generic assessment plan differs from retained locator"
        );
        drop(layout);
        std::fs::remove_dir_all(root).unwrap();
    }
}
