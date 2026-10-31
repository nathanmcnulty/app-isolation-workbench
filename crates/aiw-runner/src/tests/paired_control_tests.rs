//! Runs the production lifecycle through the existing fake process/lease seams.
use super::*;
use aiw_probe::paired_controls::{PairedControlPolicy, paired_control_source_sha256};
use aiw_probe::{ControlEvidenceOrigin, PairedControlProfile};
use aiw_provider_wsb::{PairedComparisonReason, PairedControlResult, PairedControlsRequest};

fn setup_pair() -> (
    Root,
    RunLayout,
    WsbGoldenProbeStart,
    WindowsSandboxReadiness,
) {
    setup_pair_source(None)
}
fn setup_pair_source(
    source: Option<&str>,
) -> (
    Root,
    RunLayout,
    WsbGoldenProbeStart,
    WindowsSandboxReadiness,
) {
    setup_transformed(|start, plan| {
        let profile = PairedControlProfile {
            revision: aiw_probe::PAIRED_CONTROL_REVISION.into(),
            source_sha256: source
                .map(str::to_owned)
                .unwrap_or_else(paired_control_source_sha256),
            fixture_sha256: start.guest_agent.sha256.clone(),
            fixture_size_bytes: start.guest_agent.size_bytes,
            launcher_sha256: start.guest_agent.sha256.clone(),
            launcher_size_bytes: start.guest_agent.size_bytes,
            origin: ControlEvidenceOrigin::SyntheticRehearsal,
            expected_windows: aiw_probe::WindowsVersionObservation {
                major: 10,
                minor: 0,
                build: 26100,
                revision: 0,
                observer_architecture: "x86_64".into(),
            },
            policy: PairedControlPolicy::ClassicAppContainerNoCapabilitiesFixedChildOutputGrant,
        };
        let role = |name: &str| {
            let path = Path::new(&start.workspace.tools.final_path).join(name);
            fs::write(&path, b"guest-agent").unwrap();
            let payload = identity(&path);
            let mut staged_identity = start.workspace.tools.clone();
            staged_identity.final_path = payload.canonical_path.clone();
            WsbMsiDocument {
                staged_payload: payload,
                staged_identity,
            }
        };
        start.paired_controls = Some(WsbPairedControls {
            profile: profile.clone(),
            fixture: role("aiw-control-fixture.exe"),
            launcher: role("aiw-control-appcontainer.exe"),
        });
        start.schema_version = "aiw.dev/wsb-paired-controls-start/v0alpha1".into();
        start.wsb_plan.probe.output = r"C:\AIW\Output\scenario-result.json".into();
        *plan = RunPlan::new(
            &plan.run_id,
            &plan.project_id,
            &plan.project_revision_hash,
            plan.lifecycle,
            &plan.created_at,
            vec![
                PlannedAction::AssessHost,
                PlannedAction::PrepareWorkspace,
                PlannedAction::ExecuteWindowsSandboxPairedControls {
                    sandbox_plan_sha256: canonical_hash(&start.wsb_plan).unwrap(),
                    provider_sha256: start.provider.sha256.clone(),
                    guest_agent_sha256: start.guest_agent.sha256.clone(),
                    workspace: Box::new(start.workspace.clone()),
                    workspace_identity_sha256: start.workspace_identity_sha256.clone(),
                    profile: Box::new(profile),
                },
                PlannedAction::CollectEvidence,
            ],
            vec!["SYNTHETIC offline paired-control rehearsal; zero executable calls".into()],
        )
        .unwrap();
    })
}
fn write_pair_completion(start: &WsbGoldenProbeStart, mutation: usize) {
    crate::synthetic_receipt::write_pair_completion(start, mutation);
}
fn pair_process(start: &WsbGoldenProbeStart, mutation: usize) -> FakeProcess {
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
        let layout = RunLayout::new(&output_start.run_root, "w1-run").unwrap();
        let transaction = crate::session::observe_transaction(&layout)
            .unwrap()
            .transaction
            .unwrap();
        assert_eq!(
            transaction.current_state(),
            SessionTransactionState::StartIntent
        );
        assert_eq!(transaction.session_id, deterministic_sandbox_id("w1-run"));
        write_pair_completion(&output_start, mutation);
    }))
}
fn report_pair(
    start: &WsbGoldenProbeStart,
    cleanup: Option<bool>,
    outcome: Option<RunOutcome>,
) -> PairedControlRunReport {
    let expected = PairedControlsRequest::from_retained_binding(
        "w1-run",
        &deterministic_sandbox_id("w1-run"),
        &render_config(&start.wsb_plan).unwrap().sha256,
        &start.guest_agent.sha256,
        start.paired_controls.as_ref().unwrap().profile.clone(),
    )
    .unwrap();
    crate::paired_report::read_paired_output(
        Path::new(&start.workspace.output.final_path),
        &expected,
        cleanup,
        outcome,
        crate::paired_report::PairedExecutionProvenance::ApprovedDispatch,
        "synthetic-project-revision",
    )
    .unwrap()
}

#[cfg(windows)]
#[test]
fn paired_protected_fixture_runs_fake_kernel_and_actual_retained_report_set_without_execution() {
    protected_pair_rehearsal(false);
}
#[cfg(windows)]
#[test]
fn paired_protected_unknown_cleanup_remains_inconclusive_and_never_recovers_on_read() {
    protected_pair_rehearsal(true);
}
#[cfg(windows)]
fn protected_pair_rehearsal(unknown_cleanup: bool) {
    let mut root = Root::new();
    let (held, project, artifacts, ready) =
        crate::preparation::tests::protected_paired_fixture(&root.0, "w1-run");
    let workspace = held.root_path().to_path_buf();
    let project_path = root.0.join("project.yaml");
    fs::write(&project_path, serde_yaml::to_string(&project).unwrap()).unwrap();
    let receipt = aiw_orchestrator::WsbPlanningImportReceipt {
        schema_version: aiw_orchestrator::WSB_PAIRED_CONTROL_IMPORT_SCHEMA.into(),
        run_id: "w1-run".into(),
        imported_at: "synthetic-time".into(),
        status: aiw_orchestrator::WsbPlanningImportStatus::PendingApproval,
        project_revision_sha256: artifacts.receipt.project_revision_sha256.clone(),
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
    let layout = RunLayout::new(&workspace, "w1-run").unwrap();
    layout
        .create_or_verify_pending_wsb_import_bound(&held, &artifacts.run_plan, &receipt)
        .unwrap();
    assert!(matches!(
        crate::recover_windows_sandbox(&layout),
        Err(RunnerError::ApprovalBinding)
    ));
    let unstarted = crate::report_windows_sandbox_paired_controls(
        &workspace,
        "w1-run",
        &project,
        &artifacts.receipt.guest_agent.sha256,
    )
    .unwrap();
    assert_eq!(
        unstarted.evidence_status,
        PairedReportEvidenceStatus::Absent
    );
    assert!(unstarted.observations.is_none());
    assert!(
        unstarted
            .evidence_gaps
            .iter()
            .any(|gap| { gap == "Committed approval unavailable; no execution evidence accepted" })
    );
    layout
        .write_approval(
            &ApprovalRecord::for_plan(&artifacts.run_plan, "synthetic-operator", "synthetic-time")
                .unwrap(),
        )
        .unwrap();
    let approved_without_dispatch = crate::report_windows_sandbox_paired_controls(
        &workspace,
        "w1-run",
        &project,
        &artifacts.receipt.guest_agent.sha256,
    )
    .unwrap();
    assert!(approved_without_dispatch.evidence_gaps.iter().any(|gap| {
        gap == "Approval recorded; Sandbox dispatch not committed; fixed control cases remain unmeasured"
    }));
    assert_eq!(
        approved_without_dispatch.evidence_status,
        PairedReportEvidenceStatus::Absent
    );
    assert!(approved_without_dispatch.observations.is_none());
    assert!(approved_without_dispatch.comparison.is_none());
    assert_eq!(approved_without_dispatch.recorded_cleanup_verified, None);
    assert_eq!(approved_without_dispatch.recorded_outcome, None);
    assert!(!layout.run_dir().join("wsb-session-transaction").exists());
    let start = WsbGoldenProbeStart {
        schema_version: "aiw.dev/wsb-paired-controls-start/v0alpha1".into(),
        run_root: artifacts.wsb_plan.workspace_root.clone(),
        project_path: project_path.to_string_lossy().into_owned(),
        provider: artifacts.receipt.provider.clone(),
        guest_agent: artifacts.receipt.guest_agent.clone(),
        workspace: artifacts.receipt.workspace.clone(),
        workspace_identity_sha256: artifacts.receipt.workspace_identity_sha256.clone(),
        wsb_plan: artifacts.wsb_plan.clone(),
        timeout_seconds: 1,
        msi: None,
        bambu: None,
        paired_controls: artifacts.receipt.paired_controls.clone(),
    };
    assert_eq!(
        start.run_root, artifacts.receipt.workspace.root.final_path,
        "fixture must use the same root spelling as the native facade"
    );
    let fake = pair_process(&start, 0);
    if unknown_cleanup {
        let id = deterministic_sandbox_id("w1-run");
        *fake.results.lock().unwrap() = vec![
            empty_list(),
            started(&id),
            list_with(&id, "running"),
            list_with(&id, "running"),
            stopped(&id),
            list_with(&id, "still-present"),
        ]
        .into_iter()
        .collect();
    }
    let process = TraceFake {
        process: fake,
        arguments: Mutex::new(vec![]),
    };
    let execution = super::super::execute_wsb_golden_probe(
        &start,
        &ready,
        &layout,
        &process,
        &TestLease::default(),
        &held,
    );
    if unknown_cleanup {
        assert!(matches!(execution, Err(RunnerError::RecoveryRequired(_))));
    } else {
        execution.unwrap();
    }
    let before = fixture_file_snapshot(&workspace);
    let before_read_calls = process.arguments.lock().unwrap().len();
    let report = crate::report_windows_sandbox_paired_controls(
        &workspace,
        "w1-run",
        &project,
        &start.guest_agent.sha256,
    )
    .unwrap();
    assert_eq!(report.evidence_status, PairedReportEvidenceStatus::Verified);
    assert_eq!(
        report.recorded_cleanup_verified,
        if unknown_cleanup { None } else { Some(true) }
    );
    assert_eq!(
        report.comparison.as_ref().unwrap().eligible,
        !unknown_cleanup
    );
    assert!(!report.comparison.as_ref().unwrap().production_acceptance);
    let entry = crate::WsbReportSetEntry {
        profile: crate::ReportSetProfile::PairedControls,
        run: crate::WsbMsiReportSetEntry {
            id: "synthetic-safe-fixture".into(),
            workspace_root: workspace.clone(),
            run_id: "w1-run".into(),
            project_path,
            guest_agent_sha256: start.guest_agent.sha256.clone(),
        },
    };
    let mut duplicate = entry.clone();
    duplicate.run.id = "synthetic-duplicate".into();
    let set = crate::report_windows_sandbox_set(&crate::WsbReportSetInput {
        schema_version: crate::WSB_REPORT_SET_INPUT_SCHEMA.into(),
        entries: vec![entry.clone(), duplicate.clone()],
    })
    .unwrap();
    assert!(matches!(
        set.entries[1].result,
        crate::WsbReportSetResult::Unavailable(crate::ReportSetUnavailableReason::DuplicateRun)
    ));
    let functions = serde_json::to_value(&set.entries[0].functions).unwrap();
    assert!(
        functions
            .as_object()
            .unwrap()
            .values()
            .all(serde_json::Value::is_null)
    );
    assert_eq!(before, fixture_file_snapshot(&workspace));
    assert_eq!(
        process.arguments.lock().unwrap().len(),
        before_read_calls,
        "retained views must not invoke any provider boundary"
    );
    assert_eq!(
        process
            .arguments
            .lock()
            .unwrap()
            .iter()
            .filter(|args| args.first().is_some_and(|s| s == "start"))
            .count(),
        1
    );
    if std::env::var("AIW_PAIRED_FIXTURE_RETAIN").as_deref() == Ok("1") {
        let selection = root.0.join("paired-assessment-selection.json");
        let value = serde_json::json!({"schemaVersion":crate::APPLICATION_ASSESSMENT_INPUT_SCHEMA,"windowsSandbox":{"schemaVersion":crate::WSB_REPORT_SET_INPUT_SCHEMA,"entries":[entry,duplicate]}});
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&selection)
            .unwrap();
        file.write_all(&serde_json::to_vec_pretty(&value).unwrap())
            .unwrap();
        file.sync_all().unwrap();
        let marker = serde_json::json!({"schemaVersion":"aiw.dev/paired-synthetic-demo/v0alpha1","origin":"syntheticRehearsal","realProviderApplicationControlCalls":0,"fakeProviderCalls":before_read_calls,"unknownCleanup":unknown_cleanup,"scope":"Test-only inert bytes and fake provider; not production acceptance"});
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.0.join("synthetic-demo.json"))
            .unwrap();
        file.write_all(&serde_json::to_vec_pretty(&marker).unwrap())
            .unwrap();
        file.sync_all().unwrap();
        root.preserve_on_drop();
        println!("AIW_PAIRED_DEMO_SELECTION={}", selection.display());
    }
}
#[cfg(windows)]
fn fixture_file_snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    // Inventory only this freshly created test fixture, never retained discovery.
    fn collect(root: &Path, path: &Path, out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
        for item in fs::read_dir(path).unwrap() {
            let item = item.unwrap();
            let path = item.path();
            if item.file_type().unwrap().is_dir() {
                collect(root, &path, out)
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    collect(root, root, &mut out);
    out
}

#[test]
fn paired_driver_failure_is_verified_and_terminal_without_replaying_dispatch() {
    for mutation in [7, 8] {
        let (_root, layout, start, ready) = setup_pair();
        let process = pair_process(&start, mutation);
        let error =
            execute_wsb_golden_probe(&start, &ready, &layout, &process, &TestLease::default())
                .unwrap_err();
        if mutation == 7 {
            assert!(error.to_string().contains("guest reported failure"));
        } else {
            assert!(error.to_string().contains("failure binding rejected"));
        }
        let report = report_pair(&start, Some(true), Some(RunOutcome::Failed));
        assert_eq!(
            report.evidence_status,
            if mutation == 7 {
                PairedReportEvidenceStatus::DriverIncomplete
            } else {
                PairedReportEvidenceStatus::Rejected
            }
        );
        assert!(report.comparison.is_none());

        assert!(matches!(
            layout.status().unwrap(),
            aiw_orchestrator::RecoveryStatus::Terminal { .. }
        ));
        let files = ["scenario-result.json", "evidence.jsonl", "completion.json"].map(|leaf| {
            fs::read(Path::new(&start.workspace.output.final_path).join(leaf)).unwrap()
        });
        assert!(
            execute_wsb_golden_probe(&start, &ready, &layout, &process, &TestLease::default())
                .is_err()
        );
        for (leaf, bytes) in ["scenario-result.json", "evidence.jsonl", "completion.json"]
            .into_iter()
            .zip(files)
        {
            assert_eq!(
                fs::read(Path::new(&start.workspace.output.final_path).join(leaf)).unwrap(),
                bytes
            );
        }
    }
}

#[test]
fn paired_production_kernel_collects_comparable_and_inconclusive_synthetic_receipts() {
    for (mutation, reason) in [
        (0, PairedComparisonReason::FixedControlsObserved),
        (1, PairedComparisonReason::BaselineFailed),
        (2, PairedComparisonReason::CandidateFailed),
        (3, PairedComparisonReason::DriverIncomplete),
    ] {
        let (_root, layout, start, ready) = setup_pair();
        let process = pair_process(&start, mutation);
        let result =
            execute_wsb_golden_probe(&start, &ready, &layout, &process, &TestLease::default())
                .unwrap();
        let observation = result.paired_observation.unwrap();
        let expected = PairedControlsRequest::new(
            &result.run_id,
            &result.sandbox_id,
            &result.config_sha256,
            &start.guest_agent.sha256,
            start.paired_controls.as_ref().unwrap().profile.clone(),
        )
        .unwrap();
        let comparison = observation
            .compare(&expected, Some(result.cleanup_complete))
            .unwrap();
        assert_eq!(comparison.reason, reason);
        assert!(!comparison.production_acceptance);
        assert_eq!(comparison.origin, ControlEvidenceOrigin::SyntheticRehearsal);
        let output = Path::new(&start.workspace.output.final_path);
        let original = ["scenario-result.json", "evidence.jsonl", "completion.json"]
            .map(|leaf| fs::read(output.join(leaf)).unwrap());
        let report = report_pair(&start, Some(true), Some(RunOutcome::InsufficientEvidence));
        assert_eq!(report.evidence_status, PairedReportEvidenceStatus::Verified);
        assert_eq!(report.comparison.as_ref().unwrap().reason, reason);
        let unknown = report_pair(&start, None, Some(RunOutcome::InsufficientEvidence));
        assert!(!unknown.comparison.as_ref().unwrap().eligible);
        assert_eq!(unknown.recorded_cleanup_verified, None);
        let incomplete = report_pair(&start, Some(true), None);
        assert!(!incomplete.comparison.as_ref().unwrap().eligible);
        assert_eq!(incomplete.recorded_cleanup_verified, Some(true));
        for (leaf, bytes) in ["scenario-result.json", "evidence.jsonl", "completion.json"]
            .into_iter()
            .zip(original)
        {
            assert_eq!(fs::read(output.join(leaf)).unwrap(), bytes);
        }

        assert!(matches!(
            layout.status().unwrap(),
            aiw_orchestrator::RecoveryStatus::Terminal { .. }
        ));
        assert!(
            !Path::new(&start.workspace.tools.final_path)
                .join("request.json")
                .exists()
        );
        assert!(process.calls.load(Ordering::SeqCst) > 0); // all calls terminate at this fake; inert bytes are never launched.
    }
}
#[test]
fn paired_unapproved_drifted_and_stale_inputs_cannot_reach_fake_dispatch() {
    for mutant in 0..5 {
        let (_root, layout, mut start, mut ready) = setup_pair();
        let process = FakeProcess::new(vec![]);
        match mutant {
            0 => fs::remove_file(layout.approval_path()).unwrap(),
            1 => fs::write(
                &start
                    .paired_controls
                    .as_ref()
                    .unwrap()
                    .fixture
                    .staged_payload
                    .canonical_path,
                b"drift",
            )
            .unwrap(),
            2 => fs::write(&start.provider.canonical_path, b"provider drift").unwrap(),
            3 => {
                start.paired_controls.as_mut().unwrap().profile.origin =
                    ControlEvidenceOrigin::NativeWorker
            }
            _ => ready.os_version.as_mut().unwrap().revision = 1,
        }
        assert!(
            execute_wsb_golden_probe(&start, &ready, &layout, &process, &TestLease::default())
                .is_err()
        );
        assert_eq!(process.calls.load(Ordering::SeqCst), 0, "mutant {mutant}");
    }
}
#[test]
fn paired_tampered_denial_never_becomes_comparable() {
    let (_root, layout, start, ready) = setup_pair();
    let process = pair_process(&start, 4);
    assert!(
        execute_wsb_golden_probe(&start, &ready, &layout, &process, &TestLease::default()).is_err()
    );
    assert_eq!(layout.read_result().unwrap().outcome, RunOutcome::Failed);
}

struct TraceFake {
    process: FakeProcess,
    arguments: Mutex<Vec<Vec<String>>>,
}
impl TraceFake {
    fn new(results: Vec<Result<ProcessResult, RunnerError>>) -> Self {
        Self {
            process: FakeProcess::new(results),
            arguments: Mutex::new(vec![]),
        }
    }
}
impl ProcessBoundary for TraceFake {
    fn invoke(
        &self,
        executable: &Path,
        arguments: &[String],
        timeout: u32,
    ) -> Result<ProcessResult, RunnerError> {
        self.arguments.lock().unwrap().push(arguments.to_vec());
        self.process.invoke(executable, arguments, timeout)
    }
}
#[test]
fn paired_cancellation_does_not_dispatch() {
    let (_root, layout, start, ready) = setup_pair();
    layout
        .request_cancellation("synthetic-operator", "now")
        .unwrap();
    let process = FakeProcess::new(vec![]);
    assert!(matches!(
        execute_wsb_golden_probe(&start, &ready, &layout, &process, &TestLease::default()),
        Err(RunnerError::Cancelled)
    ));
    assert_eq!(process.calls.load(Ordering::SeqCst), 0);
    assert_eq!(layout.read_result().unwrap().outcome, RunOutcome::Cancelled);
}
#[test]
fn paired_interrupted_dispatch_preserves_identity_and_recovers_only_the_exact_session() {
    let (_root, layout, start, ready) = setup_pair();
    let id = deterministic_sandbox_id("w1-run");
    let lost = TraceFake::new(vec![
        empty_list(),
        Err(RunnerError::ProviderFailure),
        empty_list(),
        empty_list(),
    ]);
    assert!(matches!(
        execute_wsb_golden_probe(&start, &ready, &layout, &lost, &TestLease::default()),
        Err(RunnerError::RecoveryRequired(_))
    ));
    assert!(request_path(&start).exists());
    assert!(!layout.result_path().exists());
    assert_eq!(
        lost.arguments
            .lock()
            .unwrap()
            .iter()
            .filter(|a| a.first().is_some_and(|s| s == "start"))
            .count(),
        1
    );
    let retry = FakeProcess::new(vec![]);
    assert!(
        execute_wsb_golden_probe(&start, &ready, &layout, &retry, &TestLease::default()).is_err()
    );
    assert_eq!(retry.calls.load(Ordering::SeqCst), 0);
    let absent = TraceFake::new(vec![empty_list(), empty_list()]);
    assert!(matches!(
        crate::recover_wsb_session(&start, &ready, &layout, &absent, &TestLease::default()),
        Err(RunnerError::RecoveryRequired(_))
    ));
    assert!(request_path(&start).exists());
    let recovery = TraceFake::new(vec![list_with(&id, "running"), stopped(&id), empty_list()]);
    let result =
        crate::recover_wsb_session(&start, &ready, &layout, &recovery, &TestLease::default())
            .unwrap();
    assert_eq!(
        result.current_state(),
        SessionTransactionState::CleanupVerified
    );
    let arguments = recovery.arguments.lock().unwrap();
    assert!(
        !arguments
            .iter()
            .any(|a| a.first().is_some_and(|s| s == "start"))
    );
    assert!(
        arguments
            .iter()
            .filter(|a| a.first().is_some_and(|s| s == "stop"))
            .all(|a| a.iter().any(|s| s == &id))
    );
    assert!(!request_path(&start).exists());
    assert!(layout.read_result().unwrap().cleanup_complete);
}

#[test]
fn paired_duplicate_and_out_of_order_evidence_is_rejected() {
    for mutation in [5, 6] {
        let (_root, layout, start, ready) = setup_pair();
        let process = pair_process(&start, mutation);
        assert!(
            execute_wsb_golden_probe(&start, &ready, &layout, &process, &TestLease::default())
                .is_err()
        );
        assert_eq!(layout.read_result().unwrap().outcome, RunOutcome::Failed);
        let report = report_pair(&start, Some(true), Some(RunOutcome::Failed));
        assert_eq!(report.evidence_status, PairedReportEvidenceStatus::Rejected);
        assert!(report.observations.is_none());
    }
}

#[test]
fn paired_historical_source_can_recover_but_cannot_start_again() {
    let old_source = "9".repeat(64);
    let (_root, layout, start, ready) = setup_pair_source(Some(&old_source));
    let original_plan = layout.read_plan().unwrap();
    let original_hash = original_plan.hash().unwrap();
    let rejected = FakeProcess::new(vec![]);
    assert!(
        execute_wsb_golden_probe(&start, &ready, &layout, &rejected, &TestLease::default())
            .is_err()
    );
    assert_eq!(rejected.calls.load(Ordering::SeqCst), 0);
    let context = prepare_execution(&start, &ready, &layout, false).unwrap();
    prepare_request_artifact(&context.request_path, &context.guest_request).unwrap();
    let original_request = fs::read(&context.request_path).unwrap();
    let store = TransactionStore::new(&layout, context.binding);
    store.create("synthetic-dispatch-crash").unwrap();
    // Cleanup relies on the original persisted binding, not current role bytes.
    fs::write(
        &start
            .paired_controls
            .as_ref()
            .unwrap()
            .fixture
            .staged_payload
            .canonical_path,
        b"changed after crash",
    )
    .unwrap();
    let id = deterministic_sandbox_id("w1-run");
    let recovery = TraceFake::new(vec![list_with(&id, "running"), stopped(&id), empty_list()]);
    crate::recover_wsb_session(&start, &ready, &layout, &recovery, &TestLease::default()).unwrap();
    assert_eq!(layout.read_plan().unwrap().hash().unwrap(), original_hash);
    assert_eq!(
        serde_json::from_slice::<ExecutionGuestRequest>(&original_request)
            .unwrap()
            .digest(),
        context.guest_request.digest()
    );
    assert!(
        recovery
            .arguments
            .lock()
            .unwrap()
            .iter()
            .all(|args| args.first().is_none_or(|s| s != "start"))
    );
    assert!(!request_path(&start).exists());
}

#[test]
fn paired_recovery_binding_rejects_copied_layout_and_changed_provider_without_dispatch() {
    let (_root, layout, start, ready) = setup_pair();
    let context = prepare_execution(&start, &ready, &layout, false).unwrap();
    let store = TransactionStore::new(&layout, context.binding);
    store.create("synthetic-binding-test").unwrap();
    let transaction = store.load_current().unwrap().unwrap();
    assert_eq!(
        recovery_workspace(&layout, &transaction).unwrap(),
        start.workspace
    );
    let other = Root::new();
    let copied = RunLayout::new(&other.0, "w1-run").unwrap();
    fs::create_dir_all(copied.run_dir().join("journal-heads")).unwrap();
    for leaf in [
        "plan.json",
        "approval.json",
        "events.jsonl",
        "wsb-planning-import.json",
    ] {
        let source = layout.run_dir().join(leaf);
        if source.exists() {
            fs::copy(source, copied.run_dir().join(leaf)).unwrap();
        }
    }
    for entry in fs::read_dir(layout.run_dir().join("journal-heads")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(
            entry.path(),
            copied
                .run_dir()
                .join("journal-heads")
                .join(entry.file_name()),
        )
        .unwrap();
    }
    assert!(copied.retained_snapshot().is_ok());
    assert!(recovery_workspace(&copied, &transaction).is_err());
    let mut changed = transaction.clone();
    changed.provider_sha256 = "f".repeat(64);
    assert!(recovery_workspace(&layout, &changed).is_err());
    let mut changed = transaction;
    changed.workspace_identity_sha256 = "f".repeat(64);
    assert!(recovery_workspace(&layout, &changed).is_err());
}
