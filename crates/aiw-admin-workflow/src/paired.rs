//! Fixed paired-control product workflow. Native provider operations remain in
//! aiw-runner; this service owns preparation and the existing approval gates.
use super::*;
use aiw_orchestrator::{PlannedAction, RecoveryStatus};
pub use aiw_probe::paired_controls::parse_guest_windows;

pub const PRODUCT: &str = "aiw-fixed-paired-controls";
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedRun {
    pub schema_version: String,
    pub run_id: String,
    pub workspace: PathBuf,
    pub evidence_root: PathBuf,
    pub project_path: PathBuf,
    pub project_revision_sha256: String,
    pub plan_sha256: String,
    pub profile_sha256: String,
    pub agent_sha256: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedWorkflowResult {
    pub run: PairedRun,
    pub approval_recorded: bool,
    pub start_requested: bool,
    pub operation_failed: bool,
    pub operation_error: Option<String>,
    pub recovery_required: bool,
    pub report: Option<aiw_runner::PairedControlRunReport>,
}

fn fixed_project(agent_sha256: &str) -> Result<Project> {
    if !valid_sha256(agent_sha256) {
        bail!("Fixed guest-agent hash is invalid");
    }
    let mut project: Project = serde_yaml::from_str(include_str!("paired-project.yaml"))?;
    let ApplicationSource::Exe(source) = &mut project.application else {
        bail!("Fixed project contract changed");
    };
    source.sha256 = agent_sha256.into();
    if !validate_project_for_planning(&project).is_empty() || project.metadata.name != PRODUCT {
        bail!("Fixed paired project is invalid");
    }
    Ok(project)
}

fn same_bound_path(a: &Path, b: &Path) -> bool {
    fn normalize(path: &Path) -> String {
        let value = path.to_string_lossy();
        value
            .strip_prefix(r"\\?\")
            .unwrap_or(&value)
            .trim_end_matches(['\\', '/'])
            .to_owned()
    }
    normalize(a).eq_ignore_ascii_case(&normalize(b))
}

impl PairedRun {
    /// Read-only authority recheck. Never acquires a provider or changes a run.
    pub fn validate(&self) -> Result<RunLayout> {
        if self.schema_version != "aiw.dev/paired-workflow-run/v0alpha1"
            || !valid_sha256(&self.agent_sha256)
            || !self.workspace.is_absolute()
            || !self.project_path.is_absolute()
        {
            bail!("Owned paired run binding rejected");
        }
        let layout = RunLayout::new(&self.workspace, &self.run_id)?;
        let snapshot = layout.retained_snapshot()?;
        if snapshot.plan.hash()?.as_str() != self.plan_sha256
            || snapshot.plan.project_revision_hash != self.project_revision_sha256
        {
            bail!("Owned paired plan changed; preserve retained evidence");
        }
        let [
            PlannedAction::AssessHost,
            PlannedAction::PrepareWorkspace,
            PlannedAction::ExecuteWindowsSandboxPairedControls {
                profile,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
                ..
            },
            PlannedAction::CollectEvidence,
        ] = snapshot.plan.actions.as_slice()
        else {
            bail!("Owned run is not the fixed paired action");
        };
        if guest_agent_sha256 != &self.agent_sha256
            || profile.hash().map_err(anyhow::Error::msg)? != self.profile_sha256
        {
            bail!("Owned fixed control identity changed");
        }
        if !same_bound_path(&self.workspace, Path::new(&workspace.root.final_path))
            || self
                .workspace
                .parent()
                .is_none_or(|parent| !same_bound_path(parent, &self.evidence_root))
            || !same_bound_path(
                &self.project_path,
                &self.evidence_root.join("paired-project.yaml"),
            )
        {
            bail!("Owned paired paths differ from the original fixed workspace");
        }
        let expected = Path::new(&workspace.root.final_path).canonicalize()?;
        if self.workspace.canonicalize()? != expected {
            bail!("Selected paired workspace differs from its bound original");
        }
        let actual_hash = lowercase_sha256(&aiw_evidence::canonical_json_bytes(
            &serde_json::to_value(workspace)?,
        )?);
        if &actual_hash != workspace_identity_sha256 {
            bail!("Owned workspace commitment rejected");
        }
        #[cfg(windows)]
        {
            let held = aiw_windows_platform::HeldRunWorkspace::reopen_bound(workspace)
                .map_err(|e| anyhow!("Owned protected workspace rejected: {e}"))?;
            held.revalidate()
                .map_err(|e| anyhow!("Owned protected workspace changed: {e}"))?;
            if self.workspace.canonicalize()? != held.root_path().canonicalize()? {
                bail!("Owned workspace namespace changed");
            }
        }
        Ok(layout)
    }
    #[cfg(windows)]
    fn hold(&self) -> Result<(RunLayout, aiw_windows_platform::HeldRunWorkspace)> {
        let layout = self.validate()?;
        let plan = layout.retained_snapshot()?.plan;
        let PlannedAction::ExecuteWindowsSandboxPairedControls { workspace, .. } = &plan.actions[2]
        else {
            bail!("Paired action absent");
        };
        let held = aiw_windows_platform::HeldRunWorkspace::reopen_bound(workspace)
            .map_err(|e| anyhow!("Owned protected workspace rejected: {e}"))?;
        held.revalidate()
            .map_err(|e| anyhow!("Owned protected workspace changed: {e}"))?;
        if self.workspace.canonicalize()? != held.root_path().canonicalize()? {
            bail!("Owned workspace namespace changed");
        }
        Ok((layout, held))
    }
    fn project(&self, current: bool) -> Result<Project> {
        let project: Project =
            serde_yaml::from_slice(&read_file_bounded(&self.project_path, MAX_CONFIG_BYTES)?)?;
        if aiw_orchestrator::project_revision_hash(&project)?.as_str()
            != self.project_revision_sha256
            || (current && project != fixed_project(&self.agent_sha256)?)
        {
            bail!("Owned paired project changed; preserve retained evidence");
        }
        Ok(project)
    }
}

/// Opens only an explicit retained product marker; never executes or recovers.
pub fn open_retained(workspace: &Path, run_id: &str) -> Result<PairedRun> {
    let parent = workspace
        .parent()
        .ok_or_else(|| anyhow!("Retained paired parent missing"))?;
    let run: PairedRun = serde_json::from_slice(&read_file_bounded(
        &parent.join("paired-workflow.json"),
        128 * 1024,
    )?)?;
    if run.run_id != run_id
        || run.workspace.canonicalize()? != workspace.canonicalize()?
        || run.evidence_root.canonicalize()? != parent.canonicalize()?
    {
        bail!("Retained paired marker does not bind this workspace/run");
    }
    run.validate()?;
    Ok(run)
}
pub fn summary(report: &aiw_runner::PairedControlRunReport) -> String {
    use aiw_provider_wsb::{ControlAccess as Access, PairedComparisonReason as Reason};
    let recorded = |value: Option<bool>| match value {
        Some(true) => "verified in the historical receipt",
        Some(false) => "not verified in the historical receipt",
        None => "unmeasured or unresolved",
    };
    let access = |value: Access| match value {
        Access::Success => "completed",
        Access::AccessDenied => "access denied",
        Access::NotFound => "resource missing",
        Access::Timeout => "timed out",
        Access::Failure => "failed",
        Access::Unmeasured => "unmeasured",
    };
    let origin = match report.profile.origin {
        aiw_probe::ControlEvidenceOrigin::SyntheticRehearsal => {
            "SYNTHETIC offline rehearsal; not native acceptance"
        }
        aiw_probe::ControlEvidenceOrigin::NativeWorker if report.observations.is_some() => {
            "historical native fixed-case records"
        }
        _ => "native profile requested; no verified complete pair",
    };
    let evidence = match report.evidence_status {
        aiw_runner::PairedReportEvidenceStatus::Verified => "receipt-verified recorded evidence",
        aiw_runner::PairedReportEvidenceStatus::DriverIncomplete => {
            "verified incomplete driver progress"
        }
        aiw_runner::PairedReportEvidenceStatus::Absent => "no verified case evidence",
        aiw_runner::PairedReportEvidenceStatus::Rejected => "evidence rejected",
    };
    let mut text = format!(
        "Fixed ordinary-user / classic AppContainer controls. {origin}. Evidence: {evidence}.\n\nGeneral compatibility, effective host isolation and production acceptance remain unmeasured. Historical outer cleanup: {}.\n",
        recorded(report.recorded_cleanup_verified)
    );
    if let Some(comparison) = &report.comparison {
        let reason = match comparison.reason {
            Reason::FixedControlsObserved => "fixed cases observed",
            Reason::BaselineFailed => "baseline failed",
            Reason::CandidateFailed => "candidate failed",
            Reason::DriverIncomplete => "driver incomplete",
            Reason::CleanupUnknown => "outer cleanup unresolved",
        };
        text.push_str(&format!(
            "Fixed-case comparison: {}; {reason}.\n",
            if comparison.eligible {
                "eligible only for these recorded cases"
            } else {
                "inconclusive"
            }
        ));
    }
    if let Some(observed) = &report.observations {
        for (name, variant) in [
            ("Ordinary-user baseline", &observed.baseline),
            ("AppContainer candidate", &observed.candidate),
        ] {
            let code = |value: Option<u32>| {
                value
                    .map(|c| format!(" (native code {c})"))
                    .unwrap_or_default()
            };
            text.push_str(&format!(
                "{name}: file {}{}, registry {}{}, child {}.\n",
                access(variant.file.outcome),
                code(variant.file.native_code),
                access(variant.registry.outcome),
                code(variant.registry.native_code),
                access(variant.child_outcome)
            ));
        }
        text.push_str(&format!(
            "Inner profile deletion: {}. This is separate from outer cleanup.\n",
            recorded(observed.profile_deleted)
        ));
    }
    if let Some(failure) = &report.driver_failure {
        text.push_str(&format!("Driver incomplete; {} case progress records retained. No comparable pair established.\n",failure.progress.len()));
    }
    text.push_str("Open an explicit selection in Results for token facts, failures, evidence hashes and safe JSON/Markdown summary export.\n");
    text
}

/// Durable cancellation only; the existing leased runner owns exact cleanup.
pub fn request_cancellation(run: &PairedRun) -> Result<()> {
    #[cfg(windows)]
    let (layout, _held) = run.hold()?;
    #[cfg(not(windows))]
    let layout = run.validate()?;
    if matches!(layout.status()?, RecoveryStatus::Terminal { .. }) {
        bail!("The paired run is already terminal; no cancellation was requested");
    }
    if matches!(
        layout.status()?,
        RecoveryStatus::CancellationRequested { .. }
    ) {
        return Ok(());
    }
    layout.request_cancellation("desktop-owned-paired-workflow", now_rfc3339())?;
    Ok(())
}

pub fn native_recovery_required(run: &PairedRun) -> Result<bool> {
    let layout = run.validate()?;
    let plan = layout.retained_snapshot()?.plan;
    if plan.actions.iter().any(|action|matches!(action,PlannedAction::ExecuteWindowsSandboxPairedControls{profile,..} if profile.origin==aiw_probe::ControlEvidenceOrigin::SyntheticRehearsal)) {return Ok(false);}
    needs_recovery(run)
}

pub fn needs_recovery(run: &PairedRun) -> Result<bool> {
    let layout = run.validate()?;
    Ok(aiw_runner::observe_wsb_session_status(&layout)?.status
        == aiw_runner::WsbSessionDisposition::RecoveryRequired)
}

#[cfg(windows)]
pub fn recover_owned(run: &PairedRun) -> Result<aiw_runner::WsbRecoveryResult> {
    let (layout, _held) = run.hold()?;
    let plan = layout.retained_snapshot()?.plan;
    if plan.actions.iter().any(|action|matches!(action,PlannedAction::ExecuteWindowsSandboxPairedControls{profile,..} if profile.origin==aiw_probe::ControlEvidenceOrigin::SyntheticRehearsal)) {bail!("Synthetic records cannot acquire a native recovery provider");}
    let status = aiw_runner::observe_wsb_session_status(&layout)?;
    if status.status != aiw_runner::WsbSessionDisposition::RecoveryRequired {
        bail!("This owned paired run does not require recovery; no provider was acquired");
    }
    aiw_runner::recover_windows_sandbox(&layout).map_err(Into::into)
}

#[cfg(windows)]
pub fn report(run: &PairedRun) -> Result<aiw_runner::PairedControlRunReport> {
    run.validate()?;
    let project = run.project(false)?;
    aiw_runner::report_windows_sandbox_paired_controls(
        &run.workspace,
        &run.run_id,
        &project,
        &run.agent_sha256,
    )
    .map_err(Into::into)
}

#[cfg(windows)]
fn prepare_review_context(
    evidence_parent: &Path,
    identity: &str,
    expected_guest_windows: Option<&aiw_probe::WindowsVersionObservation>,
    progress: impl Fn(&str),
) -> Result<PreparedReviewContext> {
    if identity.trim().is_empty() {
        bail!("Operator identity is required");
    }
    if let Some(guest) = expected_guest_windows {
        guest.validate().map_err(anyhow::Error::msg)?;
        if guest.observer_architecture != "x86_64" {
            bail!("Fixed paired controls require an exact x64 guest version");
        }
    }
    // Reuse the already enrolled shared agent from the existing product package.
    // Its application recipe is not executed or used as the control project.
    let assets_root = packaged_asset_root("notepad-plus-plus")?;
    let manifest: ProductAssetManifest = serde_json::from_slice(&read_file_bounded(
        &assets_root.join("manifest.json"),
        1024 * 1024,
    )?)?;
    if manifest.guest_agent_control_source_sha256.as_deref()
        != Some(aiw_probe::paired_controls::paired_control_source_sha256().as_str())
    {
        return Err(anyhow!(AiwError {code:"AIW_PAIRED_AGENT_NOT_ENROLLED".into(),summary:"Bundled agent is not enrolled for the current fixed paired controls".into(),stage:"pairedAssets".into(),run_id:None,retryable:false,remediation:"Use a current-source package with independently enrolled agent and control-source hashes. No provider was acquired and no run was prepared.".into(),detail:"The agent control-source commitment is absent or stale.".into()}));
    }
    let assets = manifest.resolve(&assets_root)?;
    let agent = aiw_windows_platform::HeldApplicationFile::open(&assets.guest_agent)
        .map_err(|e| anyhow!("Bundled paired agent unavailable: {e}"))?;
    if agent.observation().sha256 != manifest.guest_agent_sha256 {
        bail!("Bundled guest-agent bytes differ from enrollment");
    }
    let project = fixed_project(&manifest.guest_agent_sha256)?;
    let run_id = format!("paired-{}", nonce());
    let evidence_root = create_evidence_root(evidence_parent, &run_id)?;
    let project_path = evidence_root.join("paired-project.yaml");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&project_path)?;
    file.write_all(serde_yaml::to_string(&project)?.as_bytes())?;
    file.sync_all()?;
    drop(file);
    progress("Preparing fixed controls and immutable plan; no provider is executed.");
    let prepared = aiw_runner::prepare_windows_sandbox_paired_controls(
        &evidence_root,
        &run_id,
        &project,
        &assets.guest_agent,
        &manifest.guest_agent_sha256,
        &now_rfc3339(),
        expected_guest_windows,
    )?;
    agent
        .revalidate()
        .map_err(|e| anyhow!("Bundled guest agent changed: {e}"))?;
    let workspace = PathBuf::from(&prepared.receipt.workspace.root.final_path);
    aiw_runner::import_windows_sandbox_paired_preparation(
        &workspace,
        &project,
        &manifest.guest_agent_sha256,
        &now_rfc3339(),
    )?;
    let profile = &prepared
        .receipt
        .paired_controls
        .as_ref()
        .ok_or_else(|| anyhow!("Fixed control profile missing"))?
        .profile;
    let run = PairedRun {
        schema_version: "aiw.dev/paired-workflow-run/v0alpha1".into(),
        run_id: run_id.clone(),
        workspace: workspace.clone(),
        evidence_root: evidence_root.clone(),
        project_path,
        project_revision_sha256: prepared.receipt.project_revision_sha256.clone(),
        plan_sha256: prepared.receipt.run_plan_sha256.clone(),
        profile_sha256: profile.hash().map_err(anyhow::Error::msg)?,
        agent_sha256: manifest.guest_agent_sha256,
    };
    save_stage(&evidence_root, "paired-workflow", &run)?;
    let review = paired_review(&run, &prepared, identity)?;
    Ok(PreparedReviewContext {
        run,
        review,
        project,
        _agent: agent,
    })
}

#[cfg(windows)]
struct PreparedReviewContext {
    run: PairedRun,
    review: ApprovalReview,
    project: Project,
    // Preserve the desktop's original package-agent custody through approval,
    // Start and completion. Headless preparation drops it only on return.
    _agent: aiw_windows_platform::HeldApplicationFile,
}

/// Prepare/import only. No gate callback, approval writer, lease or Start route.
/// Uses this package's enrolled fixed agent; accepts no executable/policy inputs.
pub fn prepare_for_review(
    evidence_parent: &Path,
    identity: &str,
    expected_guest_windows: Option<&aiw_probe::WindowsVersionObservation>,
) -> Result<serde_json::Value> {
    #[cfg(windows)]
    {
        let context =
            prepare_review_context(evidence_parent, identity, expected_guest_windows, |_| {})?;
        let value = preparation_review_value(&context.run, &context.review);
        save_stage(&context.run.evidence_root, "paired-review", &value)?;
        Ok(value)
    }
    #[cfg(not(windows))]
    {
        let _ = (evidence_parent, identity, expected_guest_windows);
        bail!("Fixed paired preparation requires Windows; no provider was invoked")
    }
}

#[cfg(windows)]
fn preparation_review_value(run: &PairedRun, review: &ApprovalReview) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion":"aiw.dev/admin-paired-preparation/v0alpha1",
        "status":"pendingApproval", "approvalRecorded":false,
        "startRequested":false, "providerInvoked":false,
        "measurements":"unmeasured; this is a plan review, not a result or approval",
        "run":run, "recipe":review.recipe, "plan":review.plan,
        "proposedApproval":review.proposed_approval,
    })
}

#[cfg(windows)]
pub fn assess_with_gate(
    evidence_parent: &Path,
    identity: &str,
    expected_guest_windows: Option<&aiw_probe::WindowsVersionObservation>,
    gate: &dyn ApprovalGate,
) -> Result<PairedWorkflowResult> {
    let context = prepare_review_context(
        evidence_parent,
        identity,
        expected_guest_windows,
        |message| gate.progress(message),
    )?;
    let PreparedReviewContext {
        run,
        review,
        project,
        _agent,
    } = context;
    let start_workspace = run.workspace.clone();
    let start_project = run.project_path.clone();
    let start_agent = run.agent_sha256.clone();
    run_prepared_with_gate(run, review, gate, || {
        gate.progress("Running fixed paired controls. Cancellation requests exact owned cleanup; it never starts another run.");
        aiw_runner::start_approved_windows_sandbox(
            &start_workspace,
            &start_project,
            &project,
            &start_agent,
            300,
        )
        .map(|_| ())
        .map_err(Into::into)
    })
}

fn paired_review(
    run: &PairedRun,
    prepared: &aiw_runner::PreparedWsbArtifacts,
    identity: &str,
) -> Result<ApprovalReview> {
    let profile = &prepared
        .receipt
        .paired_controls
        .as_ref()
        .ok_or_else(|| anyhow!("Fixed control profile missing"))?
        .profile;
    Ok(ApprovalReview {
        run_id: run.run_id.clone(),
        workspace: run.workspace.clone(),
        evidence_root: run.evidence_root.clone(),
        recipe: serde_json::json!({"schemaVersion":"aiw.dev/admin-paired-recipe/v0alpha1","executionIdentity":"Fixed ordinary-user versus classic AppContainer controls inside one offline Windows Sandbox. These are fixed primitives, not an application compatibility assessment.","dataLifetime":"Only the fixed canaries and child token output are used. Original evidence is retained locally. Results summary exports exclude raw tokens, account identifiers and private paths.","limits":"Runtime CLI protocol, Sandbox feature readiness and current session availability are UNMEASURED during preparation. They are required and rechecked only after this exact approval and separate Start. No general compatibility, effective host isolation, network or production acceptance claim. Outer worker cleanup and inner profile/job cleanup are separate.","providerChecks":{"runtime":"requiredAtStartNotObserved","requiredProtocol":prepared.receipt.provider_protocol},"profile":profile,"runPlan":prepared.run_plan}),
        plan: prepared.run_plan.clone(),
        proposed_approval: ApprovalRecord::for_plan(
            &run.validate()?.read_plan()?,
            identity.trim(),
            now_rfc3339(),
        )?,
    })
}

fn run_prepared_with_gate(
    run: PairedRun,
    review: ApprovalReview,
    gate: &dyn ApprovalGate,
    start: impl FnOnce() -> Result<()>,
) -> Result<PairedWorkflowResult> {
    let mut outcome = (|| {
        run.validate()?;
        run.project(true)?;
        if review.run_id != run.run_id
            || review.workspace != run.workspace
            || review.evidence_root != run.evidence_root
            || review.plan.hash()?.as_str() != run.plan_sha256
            || review.proposed_approval.plan_hash != run.plan_sha256
        {
            bail!("Review differs from the owned immutable paired plan");
        }
        gate.paired_prepared(&run)?;
        if !approve_review(gate, &review)? {
            save_stage(
                &run.evidence_root,
                "approval-cancelled",
                &serde_json::json!({"runId":run.run_id,"providerAcquired":false}),
            )?;
            return Ok(PairedWorkflowResult {
                run: run.clone(),
                approval_recorded: false,
                start_requested: false,
                operation_failed: false,
                operation_error: None,
                recovery_required: false,
                report: None,
            });
        }
        if !wait_for_start(gate, &review)? {
            save_stage(
                &run.evidence_root,
                "execution-not-started",
                &serde_json::json!({"runId":run.run_id,"providerAcquired":false}),
            )?;
            return Ok(PairedWorkflowResult {
                run: run.clone(),
                approval_recorded: true,
                start_requested: false,
                operation_failed: false,
                operation_error: None,
                recovery_required: false,
                report: None,
            });
        }
        run.validate()?;
        run.project(true)?;
        let operation = start();
        let layout = run.validate()?;
        let recovery_required = aiw_runner::observe_wsb_session_status(&layout).map_or(true, |s| {
            s.status == aiw_runner::WsbSessionDisposition::RecoveryRequired
        });
        #[cfg(windows)]
        let report = report(&run).ok();
        #[cfg(not(windows))]
        let report = None;
        let operation_failed = operation.is_err();
        let operation_error = operation
            .as_ref()
            .err()
            .map(|e| e.to_string().chars().take(2048).collect());
        if let Err(error) = operation
            && report.is_none()
        {
            return Err(anyhow!(
                "Paired Start request stopped: {error}. Preserve {}. Recovery required: {recovery_required}",
                run.workspace.display()
            ));
        }
        Ok(PairedWorkflowResult {
            run: run.clone(),
            approval_recorded: true,
            start_requested: true,
            operation_failed,
            operation_error,
            recovery_required,
            report,
        })
    })();
    let recovery_required = needs_recovery(&run).unwrap_or(true);
    if let Ok(value) = &mut outcome {
        value.recovery_required = recovery_required;
    }
    gate.paired_finished(&run, recovery_required);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn compiled_project_is_closed_and_agent_identity_is_the_only_input() {
        assert!(fixed_project("invalid").is_err());
        let a = fixed_project(&"a".repeat(64)).unwrap();
        let mut b = fixed_project(&"b".repeat(64)).unwrap();
        let ApplicationSource::Exe(source) = &mut b.application else {
            panic!("fixed exe");
        };
        source.sha256 = "a".repeat(64);
        assert_eq!(a, b);
        assert_eq!(a.metadata.name, PRODUCT);
    }

    #[test]
    fn invalid_owned_context_cannot_reach_either_gate_or_dispatch_and_always_settles() {
        struct Gate {
            finished: Cell<usize>,
        }
        impl ApprovalGate for Gate {
            fn review(&self, _: &ApprovalReview) -> Result<Option<String>> {
                panic!("invalid context reached review");
            }
            fn wait_for_start(&self, _: &ApprovalReview) -> Result<bool> {
                panic!("invalid context reached Start");
            }
            fn paired_finished(&self, _: &PairedRun, unresolved: bool) {
                assert!(unresolved);
                self.finished.set(self.finished.get() + 1);
            }
        }
        let plan = aiw_orchestrator::RunPlan::new(
            "invalid-paired",
            PRODUCT,
            "a".repeat(64),
            aiw_orchestrator::RunLifecycleKind::Assessment,
            "synthetic-time",
            vec![PlannedAction::AssessHost],
            vec![],
        )
        .unwrap();
        let run = PairedRun {
            schema_version: "invalid".into(),
            run_id: "invalid-paired".into(),
            workspace: PathBuf::from("relative"),
            evidence_root: PathBuf::from("relative"),
            project_path: PathBuf::from("relative"),
            project_revision_sha256: "a".repeat(64),
            plan_sha256: plan.hash().unwrap().to_string(),
            profile_sha256: "b".repeat(64),
            agent_sha256: "c".repeat(64),
        };
        let review = ApprovalReview {
            run_id: run.run_id.clone(),
            workspace: run.workspace.clone(),
            evidence_root: run.evidence_root.clone(),
            recipe: serde_json::json!({}),
            proposed_approval: ApprovalRecord::for_plan(
                &plan,
                "synthetic-operator",
                "synthetic-time",
            )
            .unwrap(),
            plan,
        };
        let gate = Gate {
            finished: Cell::new(0),
        };
        assert!(
            run_prepared_with_gate(run, review, &gate, || panic!("invalid context dispatched"))
                .is_err()
        );
        assert_eq!(gate.finished.get(), 1);
    }
}

#[cfg(all(test, windows))]
#[path = "paired_rehearsal_tests.rs"]
mod rehearsal_tests;
