//! Coupled production admin coordinator + existing runner kernel, offline only.
use super::*;
use aiw_runner::offline_rehearsal::{Fixture, Scenario};
use std::cell::Cell;

struct Gate {
    review: bool,
    start: bool,
    wrong: bool,
    drift: bool,
    prepared: Cell<u32>,
    reviews: Cell<u32>,
    starts: Cell<u32>,
    finished: Cell<u32>,
    unresolved: Cell<bool>,
}
impl Gate {
    fn new(review: bool, start: bool) -> Self {
        Self {
            review,
            start,
            wrong: false,
            drift: false,
            prepared: Cell::new(0),
            reviews: Cell::new(0),
            starts: Cell::new(0),
            finished: Cell::new(0),
            unresolved: Cell::new(false),
        }
    }
}
impl ApprovalGate for Gate {
    fn paired_prepared(&self, run: &PairedRun) -> Result<()> {
        run.validate()?;
        self.prepared.set(self.prepared.get() + 1);
        Ok(())
    }
    fn review(&self, review: &ApprovalReview) -> Result<Option<String>> {
        self.reviews.set(self.reviews.get() + 1);
        assert!(
            RunLayout::new(&review.workspace, &review.run_id)?
                .retained_snapshot()?
                .approval
                .is_none()
        );
        if self.drift {
            std::fs::write(
                review.evidence_root.join("paired-project.yaml"),
                b"drift after review",
            )?;
        }
        Ok(if !self.review {
            None
        } else if self.wrong {
            Some("approve stale-plan".into())
        } else {
            Some(format!("approve {}", review.plan.hash()?))
        })
    }
    fn wait_for_start(&self, review: &ApprovalReview) -> Result<bool> {
        self.starts.set(self.starts.get() + 1);
        assert_eq!(
            RunLayout::new(&review.workspace, &review.run_id)?
                .retained_snapshot()?
                .approval
                .unwrap(),
            review.proposed_approval
        );
        Ok(self.start)
    }
    fn paired_finished(&self, _: &PairedRun, unresolved: bool) {
        self.finished.set(self.finished.get() + 1);
        self.unresolved.set(unresolved);
    }
}
fn prepare() -> (Fixture, PairedRun, ApprovalReview) {
    let fixture = Fixture::prepare(|hash| fixed_project(hash).unwrap());
    let receipt = &fixture.artifacts.receipt;
    let profile = &receipt.paired_controls.as_ref().unwrap().profile;
    let run = PairedRun {
        schema_version: "aiw.dev/paired-workflow-run/v0alpha1".into(),
        run_id: "w1-run".into(),
        workspace: fixture.workspace().to_owned(),
        evidence_root: fixture.evidence_root().to_owned(),
        project_path: fixture.project_path(),
        project_revision_sha256: receipt.project_revision_sha256.clone(),
        plan_sha256: receipt.run_plan_sha256.clone(),
        profile_sha256: profile.hash().unwrap(),
        agent_sha256: receipt.guest_agent.sha256.clone(),
    };
    save_stage(&run.evidence_root, "paired-workflow", &run).unwrap();
    run.validate().unwrap();
    let plan = fixture.artifacts.run_plan.clone();
    let review = ApprovalReview {
        run_id: run.run_id.clone(),
        workspace: run.workspace.clone(),
        evidence_root: run.evidence_root.clone(),
        recipe: serde_json::json!({"origin":"syntheticRehearsal"}),
        proposed_approval: ApprovalRecord::for_plan(&plan, "synthetic-operator", "synthetic-time")
            .unwrap(),
        plan,
    };
    (fixture, run, review)
}
fn run(
    f: &Fixture,
    run: PairedRun,
    review: ApprovalReview,
    gate: &Gate,
    scenario: Scenario,
) -> Result<PairedWorkflowResult> {
    assert!(f.calls().is_empty(), "prepare never acquired a provider");
    run_prepared_with_gate(run, review, gate, || {
        f.dispatch(scenario).map_err(|error| {
            eprintln!(
                "{scenario:?} stopped: {error:?}; fake command count: {}",
                f.calls().len()
            );
            error.into()
        })
    })
}
#[test]
fn coupled_declined_stale_and_not_started_gates_never_dispatch() {
    for variant in 0..3 {
        let (f, owned, review) = prepare();
        if variant == 0 {
            assert!(f.dispatch(Scenario::Valid).is_err());
            assert!(f.calls().is_empty());
        }
        let mut gate = Gate::new(variant != 0, variant != 2);
        gate.wrong = variant == 1;
        let result = run(&f, owned, review, &gate, Scenario::Valid).unwrap();
        assert!(!result.start_requested);
        assert!(!result.recovery_required);
        assert!(f.calls().is_empty());
        assert_eq!(gate.finished.get(), 1);
        assert_eq!(gate.starts.get(), u32::from(variant == 2));
        assert_eq!(result.approval_recorded, variant == 2);
    }
}
#[test]
fn coupled_approved_pair_uses_one_dispatch_and_actual_retained_reader() {
    let (f, owned, review) = prepare();
    let gate = Gate::new(true, true);
    let result = run(&f, owned.clone(), review, &gate, Scenario::Valid).unwrap();
    assert!(result.approval_recorded && result.start_requested);
    assert!(!result.recovery_required);
    assert!(!result.operation_failed);
    let report = result.report.unwrap();
    assert_eq!(
        report.evidence_status,
        aiw_runner::PairedReportEvidenceStatus::Verified
    );
    assert!(report.comparison.as_ref().unwrap().eligible);
    assert!(!report.comparison.as_ref().unwrap().production_acceptance);
    assert_eq!(report.recorded_cleanup_verified, Some(true));
    assert_eq!(gate.prepared.get(), 1);
    assert_eq!(gate.reviews.get(), 1);
    assert_eq!(gate.starts.get(), 1);
    assert_eq!(gate.finished.get(), 1);
    let calls = f.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|a| a.first().is_some_and(|s| s == "start"))
            .count(),
        1
    );
    let before = f.retained_bytes();
    let again = super::report(&owned).unwrap();
    assert_eq!(f.retained_bytes(), before);
    assert_eq!(
        serde_json::to_value(report).unwrap(),
        serde_json::to_value(again).unwrap()
    );
    assert_eq!(f.calls(), calls);
    assert!(f.dispatch(Scenario::Valid).is_err());
    assert_eq!(f.calls(), calls);
    assert!(recover_owned(&owned).is_err());
    assert_eq!(f.calls(), calls);
    assert_eq!(open_retained(f.workspace(), &owned.run_id).unwrap(), owned);
    let entry = aiw_runner::WsbReportSetEntry {
        profile: aiw_runner::ReportSetProfile::PairedControls,
        run: aiw_runner::WsbMsiReportSetEntry {
            id: "SYNTHETIC-admin-paired-complete".into(),
            workspace_root: owned.workspace.clone(),
            run_id: owned.run_id.clone(),
            project_path: owned.project_path.clone(),
            guest_agent_sha256: owned.agent_sha256.clone(),
        },
    };
    let mut duplicate = entry.clone();
    duplicate.run.id = "SYNTHETIC-admin-paired-duplicate".into();
    let selection = serde_json::json!({"schemaVersion":aiw_runner::APPLICATION_ASSESSMENT_INPUT_SCHEMA,"windowsSandbox":{"schemaVersion":aiw_runner::WSB_REPORT_SET_INPUT_SCHEMA,"entries":[entry,duplicate]}});
    save_stage(f.evidence_root(), "paired-assessment-selection", &selection).unwrap();
    let marker = serde_json::json!({"schemaVersion":"aiw.dev/paired-synthetic-demo/v0alpha1","origin":"syntheticRehearsal","realProviderApplicationControlCalls":0,"fakeProviderCalls":calls.len(),"unknownCleanup":false,"coordinator":"actual paired run_prepared_with_gate","approvalReviews":gate.reviews.get(),"separateStartGates":gate.starts.get(),"productionAcceptance":false});
    save_stage(f.evidence_root(), "synthetic-demo", &marker).unwrap();
    println!(
        "AIW_COUPLED_DEMO_SELECTION={}",
        f.evidence_root()
            .join("paired-assessment-selection.json")
            .display()
    );
}
#[test]
fn coupled_project_drift_after_review_cannot_dispatch() {
    let (f, owned, review) = prepare();
    let mut gate = Gate::new(true, true);
    gate.drift = true;
    assert!(run(&f, owned, review, &gate, Scenario::Valid).is_err());
    assert!(f.calls().is_empty());
    assert_eq!(gate.finished.get(), 1);
}
#[test]
fn coupled_unknown_cleanup_keeps_comparison_inconclusive_then_recovers_exactly() {
    let (f, owned, review) = prepare();
    let gate = Gate::new(true, true);
    let result = run(&f, owned.clone(), review, &gate, Scenario::UnknownCleanup).unwrap();
    assert!(result.recovery_required && result.operation_failed);
    assert!(gate.unresolved.get());
    assert!(!result.report.unwrap().comparison.unwrap().eligible);
    let before = f.calls();
    assert!(recover_owned(&owned).is_err());
    assert_eq!(
        f.calls(),
        before,
        "synthetic cannot acquire native recovery"
    );
    f.recover_exact().unwrap();
    assert!(!needs_recovery(&owned).unwrap());
    assert_eq!(
        f.calls()
            .iter()
            .filter(|a| a.first().is_some_and(|s| s == "start"))
            .count(),
        1
    );
}

#[test]
fn coupled_evidence_matrix_preserves_missing_denied_driver_and_tamper_distinctions() {
    use aiw_provider_wsb::PairedComparisonReason as Reason;
    use aiw_runner::PairedReportEvidenceStatus as Status;
    for (scenario, status, reason) in [
        (
            Scenario::BaselineMissing,
            Status::Verified,
            Some(Reason::BaselineFailed),
        ),
        (
            Scenario::CandidateMissing,
            Status::Verified,
            Some(Reason::CandidateFailed),
        ),
        (
            Scenario::DriverIncomplete,
            Status::Verified,
            Some(Reason::DriverIncomplete),
        ),
        (Scenario::InvalidDeniedCode, Status::Rejected, None),
        (Scenario::DuplicateEvidence, Status::Rejected, None),
        (Scenario::OutOfOrderEvidence, Status::Rejected, None),
        (Scenario::DriverFailed, Status::DriverIncomplete, None),
        (Scenario::TamperedDriver, Status::Rejected, None),
    ] {
        let (f, owned, review) = prepare();
        let gate = Gate::new(true, true);
        let outcome = run(&f, owned.clone(), review, &gate, scenario).unwrap();
        let report = outcome.report.unwrap();
        assert_eq!(report.evidence_status, status, "{scenario:?}");
        assert_eq!(
            report.comparison.as_ref().map(|c| c.reason),
            reason,
            "{scenario:?}"
        );
        assert!(!report.comparison.as_ref().is_some_and(|c| c.eligible));
        if scenario == Scenario::BaselineMissing {
            let observed = report.observations.as_ref().unwrap();
            assert_eq!(
                observed.baseline.file.outcome,
                aiw_provider_wsb::ControlAccess::NotFound
            );
            assert_eq!(observed.baseline.file.native_code, Some(2));
            assert_eq!(
                observed.candidate.file.outcome,
                aiw_provider_wsb::ControlAccess::AccessDenied
            );
            assert_eq!(observed.candidate.file.native_code, Some(5));
        }
        let calls = f.calls();
        println!(
            "COUPLED_CASE={scenario:?}; evidence={status:?}; comparison={reason:?}; fake calls={}",
            calls.len()
        );
        assert_eq!(
            calls
                .iter()
                .filter(|a| a.first().is_some_and(|s| s == "start"))
                .count(),
            1
        );
        assert_eq!(gate.finished.get(), 1);
    }
}
#[test]
fn coupled_input_and_provider_drift_are_rejected_before_fake_boundary() {
    for scenario in [Scenario::InputDrift, Scenario::ProviderDrift] {
        let (f, owned, review) = prepare();
        let gate = Gate::new(true, true);
        let outcome = run(&f, owned, review, &gate, scenario);
        assert!(outcome.is_err() || outcome.as_ref().is_ok_and(|r| r.operation_failed));
        if let Ok(result) = outcome {
            assert!(result.operation_error.is_some());
        }
        assert!(f.calls().is_empty(), "{scenario:?} reached fake boundary");
        assert_eq!(gate.finished.get(), 1);
    }
}
#[test]
fn coupled_running_cancellation_and_interrupted_dispatch_do_not_replay() {
    for scenario in [
        Scenario::CancelDuringDispatch,
        Scenario::InterruptedDispatch,
    ] {
        let (f, owned, review) = prepare();
        let gate = Gate::new(true, true);
        let outcome = run(&f, owned.clone(), review, &gate, scenario);
        if scenario == Scenario::CancelDuringDispatch {
            let result = outcome.unwrap();
            assert_eq!(
                result.report.unwrap().recorded_outcome,
                Some(aiw_orchestrator::RunOutcome::Cancelled)
            );
            assert!(!result.recovery_required);
        } else {
            assert!(outcome.is_err() || outcome.as_ref().is_ok_and(|r| r.operation_failed));
            if needs_recovery(&owned).unwrap() {
                f.recover_exact().unwrap();
            }
        }
        let calls = f.calls();
        assert!(f.dispatch(Scenario::Valid).is_err());
        assert_eq!(f.calls(), calls);
        assert_eq!(
            calls
                .iter()
                .filter(|a| a.first().is_some_and(|s| s == "start"))
                .count(),
            1
        );
    }
}

#[test]
fn coupled_start_failure_keeps_bounded_actionable_detail_without_fake_dispatch() {
    let (f, owned, review) = prepare();
    let gate = Gate::new(true, true);
    let result =
        run_prepared_with_gate(owned, review, &gate, || Err(anyhow!("x".repeat(8192)))).unwrap();
    assert!(result.operation_failed && result.start_requested);
    assert_eq!(result.operation_error.unwrap().len(), 2048);
    assert!(f.calls().is_empty());
    assert_eq!(gate.finished.get(), 1);
}

#[test]
fn coupled_owned_cancellation_service_interrupts_only_the_running_original() {
    let (f, owned, review) = prepare();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let gate = Gate::new(true, true);
            run(
                &f,
                owned.clone(),
                review,
                &gate,
                Scenario::WaitForOwnedCancellation,
            )
            .unwrap()
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !f
            .calls()
            .iter()
            .any(|args| args.first().is_some_and(|s| s == "start"))
        {
            assert!(
                std::time::Instant::now() < deadline,
                "fake never reached its durable StartIntent"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        request_cancellation(&owned).unwrap();
        let result = worker.join().unwrap();
        assert_eq!(
            result.report.unwrap().recorded_outcome,
            Some(aiw_orchestrator::RunOutcome::Cancelled)
        );
        assert!(!result.recovery_required);
        assert_eq!(
            f.calls()
                .iter()
                .filter(|a| a.first().is_some_and(|s| s == "start"))
                .count(),
            1
        );
        assert!(
            request_cancellation(&owned).is_err(),
            "terminal cancellation must not mutate the original again"
        );
    });
}
