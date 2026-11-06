//! Backend-owned, single-use approval and Start gates. No UI field is authority.
use serde::Serialize;
use std::sync::{Arc, Mutex, mpsc};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Idle,
    Preparing,
    Review,
    Approved,
    Running,
    Completed,
    Cancelled,
    Failed,
    Exporting,
    Analyzing,
    Packaging,
}

impl Phase {
    fn busy(self) -> bool {
        matches!(
            self,
            Self::Preparing
                | Self::Review
                | Self::Approved
                | Self::Running
                | Self::Exporting
                | Self::Analyzing
                | Self::Packaging
        )
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    pub workflow_name: String,
    pub challenge_id: String,
    pub plan_hash: String,
    pub exact_confirmation: String,
    pub operator_identity: String,
    pub recipe_json: String,
    pub plan_json: String,
    pub approval_json: String,
    pub evidence_root: String,
    pub workspace: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultView {
    pub outcome: ResultOutcome,
    pub run_id: String,
    pub workspace: String,
    pub evidence_root: String,
    pub summary: String,
    pub can_export_document: bool,
    pub report_markdown: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ResultOutcome {
    Verified,
    NotRun,
    Incomplete,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorView {
    pub code: String,
    pub summary: String,
    pub remediation: String,
    pub detail: String,
    pub run_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Defaults {
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub progress: Option<String>,
    pub phase: Phase,
    pub workflow_id: Option<String>,
    pub review: Option<Review>,
    pub start_challenge_id: Option<String>,
    pub result: Option<ResultView>,
    pub error: Option<ErrorView>,
    pub defaults: Defaults,
    pub close_refused: bool,
    pub paired_cancel_available: bool,
    pub paired_cancel_requested: bool,
    pub paired_recovery_required: bool,
}

enum Pending {
    Approval(mpsc::Sender<Option<String>>),
    Start(mpsc::Sender<bool>),
}
struct Inner {
    snapshot: Snapshot,
    package_snapshot: Option<Snapshot>,
    pending: Option<Pending>,
    cancelled: bool,
    closing: bool,
    worker_active: bool,
    paired_settled: bool,
    paired_recovering: bool,
    paired_run: Option<(String, String)>, // plan hash and backend-created typed run JSON; never IPC input.
}

#[derive(Clone)]
pub struct Controller(Arc<Mutex<Inner>>);

impl Controller {
    pub fn new(evidence: String) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            snapshot: Snapshot {
                progress: None,
                phase: Phase::Idle,
                workflow_id: None,
                review: None,
                start_challenge_id: None,
                result: None,
                error: None,
                defaults: Defaults { evidence },
                close_refused: false,
                paired_cancel_available: false,
                paired_cancel_requested: false,
                paired_recovery_required: false,
            },
            pending: None,
            package_snapshot: None,
            cancelled: false,
            closing: false,
            worker_active: false,
            paired_settled: false,
            paired_recovering: false,
            paired_run: None,
        })))
    }
    pub fn snapshot(&self) -> Snapshot {
        self.0
            .lock()
            .expect("controller lock poisoned")
            .snapshot
            .clone()
    }
    pub fn progress(&self, id: &str, message: &str) {
        if let Ok(mut inner) = self.0.lock()
            && inner.snapshot.workflow_id.as_deref() == Some(id)
            && matches!(inner.snapshot.phase, Phase::Preparing | Phase::Running)
        {
            inner.snapshot.progress = Some(message.chars().take(4096).collect());
        }
    }
    pub fn begin(&self) -> Result<String, String> {
        self.begin_phase(Phase::Preparing)
    }
    pub fn begin_recovery(&self) -> Result<String, String> {
        self.begin_phase(Phase::Running)
    }
    pub fn begin_analysis(&self) -> Result<String, String> {
        self.begin_phase(Phase::Analyzing)
    }
    pub fn begin_packaging(&self) -> Result<String, String> {
        self.begin_phase(Phase::Packaging)
    }
    fn begin_phase(&self, phase: Phase) -> Result<String, String> {
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        if i.worker_active
            || i.snapshot.phase.busy()
            || i.closing
            || i.snapshot.paired_recovery_required
        {
            return Err("Wait for the current workflow to finish.".into());
        }
        let id = Uuid::new_v4().to_string();
        i.snapshot.progress = None;
        i.package_snapshot =
            matches!(phase, Phase::Analyzing | Phase::Packaging).then(|| i.snapshot.clone());
        i.snapshot.phase = phase;
        i.snapshot.workflow_id = Some(id.clone());
        i.snapshot.review = None;
        i.snapshot.start_challenge_id = None;
        i.snapshot.result = None;
        i.snapshot.error = None;
        i.snapshot.close_refused = false;
        i.pending = None;
        i.paired_settled = false;
        i.paired_recovering = false;
        i.paired_run = None;
        i.snapshot.paired_cancel_available = false;
        i.snapshot.paired_cancel_requested = false;
        i.snapshot.paired_recovery_required = false;
        i.cancelled = false;
        i.worker_active = true;
        Ok(id)
    }
    pub fn offer_review(
        &self,
        id: &str,
        mut review: Review,
    ) -> Result<mpsc::Receiver<Option<String>>, String> {
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        if i.snapshot.workflow_id.as_deref() != Some(id) || i.snapshot.phase != Phase::Preparing {
            return Err("Workflow is no longer preparing.".into());
        }
        let (tx, rx) = mpsc::channel();
        if i.cancelled {
            let _ = tx.send(None);
            return Ok(rx);
        }
        if i.paired_run
            .as_ref()
            .is_some_and(|(hash, _)| hash != &review.plan_hash)
        {
            return Err("Review differs from the owned paired plan.".into());
        }
        review.challenge_id = Uuid::new_v4().to_string();
        i.snapshot.review = Some(review);
        i.snapshot.phase = Phase::Review;
        i.pending = Some(Pending::Approval(tx));
        Ok(rx)
    }
    pub fn approve(&self, id: &str, challenge: &str, confirmation: &str) -> Result<(), String> {
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        let r = i.snapshot.review.as_ref().ok_or("No pending approval.")?;
        if i.snapshot.workflow_id.as_deref() != Some(id)
            || i.snapshot.phase != Phase::Review
            || r.challenge_id != challenge
            || r.exact_confirmation != confirmation
        {
            return Err("Approval does not match the current displayed plan and challenge.".into());
        }
        let Some(Pending::Approval(tx)) = i.pending.take() else {
            return Err("Approval has already been consumed.".into());
        };
        if tx.send(Some(confirmation.to_owned())).is_err() {
            Self::gate_unavailable(&mut i);
            return Err(
                "Approval worker is no longer available. Inspect retained state before retrying."
                    .into(),
            );
        }
        i.snapshot.phase = Phase::Preparing;
        Ok(())
    }
    pub fn offer_start(&self, id: &str) -> Result<mpsc::Receiver<bool>, String> {
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        if i.snapshot.workflow_id.as_deref() != Some(id) || i.snapshot.phase != Phase::Preparing {
            return Err("Workflow cannot offer Start.".into());
        }
        let (tx, rx) = mpsc::channel();
        if i.cancelled {
            let _ = tx.send(false);
            return Ok(rx);
        }
        i.snapshot.phase = Phase::Approved;
        i.snapshot.start_challenge_id = Some(Uuid::new_v4().to_string());
        i.pending = Some(Pending::Start(tx));
        Ok(rx)
    }
    pub fn start(&self, id: &str, challenge: &str) -> Result<(), String> {
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        if i.snapshot.workflow_id.as_deref() != Some(id)
            || i.snapshot.phase != Phase::Approved
            || i.snapshot.start_challenge_id.as_deref() != Some(challenge)
        {
            return Err("Start does not match a current approved workflow.".into());
        }
        let Some(Pending::Start(tx)) = i.pending.take() else {
            return Err("Start has already been consumed.".into());
        };
        if tx.send(true).is_err() {
            Self::gate_unavailable(&mut i);
            return Err(
                "Start worker is no longer available. Inspect retained state before retrying."
                    .into(),
            );
        }
        i.snapshot.phase = Phase::Running;
        if i.paired_run.is_some() {
            i.snapshot.paired_cancel_available = true;
            // Cleared only by the backend's retained-state observation.
            i.snapshot.paired_recovery_required = true;
        }
        i.snapshot.start_challenge_id = None;
        Ok(())
    }
    fn gate_unavailable(i: &mut Inner) {
        let detail = i
            .snapshot
            .review
            .as_ref()
            .map(|r| format!("Retained workspace: {}", r.workspace))
            .unwrap_or_default();
        i.snapshot.phase = Phase::Failed;
        i.snapshot.review = None;
        i.snapshot.start_challenge_id = None;
        i.snapshot.error = Some(ErrorView { code: "AIW_DESKTOP_GATE_UNAVAILABLE".into(), summary: "The workflow worker is no longer available".into(), remediation: "Preserve the retained workspace. Inspect its exact status before retrying; no completed result is established.".into(), detail, run_id: None });
    }
    /// Called only by the backend service after immutable preparation/import.
    pub fn register_paired(
        &self,
        id: &str,
        plan_hash: &str,
        run_json: String,
    ) -> Result<(), String> {
        if run_json.len() > 128 * 1024 {
            return Err("Paired context exceeds its bound.".into());
        }
        let value: serde_json::Value =
            serde_json::from_str(&run_json).map_err(|_| "Invalid paired context")?;
        if run_json.len() > 128 * 1024
            || value["schemaVersion"] != "aiw.dev/paired-workflow-run/v0alpha1"
            || value["planSha256"].as_str() != Some(plan_hash)
            || plan_hash.len() != 64
            || !plan_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Paired context binding rejected.".into());
        }
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        if i.snapshot.workflow_id.as_deref() != Some(id)
            || i.snapshot.phase != Phase::Preparing
            || i.paired_run.is_some()
        {
            return Err("No matching preparing paired workflow.".into());
        }
        i.paired_run = Some((plan_hash.into(), run_json));
        Ok(())
    }
    pub fn settle_paired(&self, id: &str, plan_hash: &str, recovery_required: bool) {
        if let Ok(mut i) = self.0.lock()
            && i.snapshot.workflow_id.as_deref() == Some(id)
            && i.paired_run
                .as_ref()
                .is_some_and(|(hash, _)| hash == plan_hash)
        {
            i.paired_settled = true;
            i.snapshot.paired_recovery_required = recovery_required;
            i.snapshot.paired_cancel_available = false;
            i.snapshot.paired_cancel_requested = false;
        }
    }
    /// No path/session ID comes from the UI. Claiming is single-use per request.
    pub fn claim_paired_cancel(&self, id: &str) -> Result<String, String> {
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        if i.snapshot.workflow_id.as_deref() != Some(id)
            || i.snapshot.phase != Phase::Running
            || !i.worker_active
            || i.paired_settled
            || i.paired_recovering
            || !i.snapshot.paired_cancel_available
            || i.snapshot.paired_cancel_requested
        {
            return Err("No cancellable owned paired run.".into());
        }
        let run = i
            .paired_run
            .as_ref()
            .ok_or("Paired context unavailable")?
            .1
            .clone();
        i.snapshot.paired_cancel_requested = true;
        i.snapshot.paired_cancel_available = false;
        Ok(run)
    }
    pub fn paired_cancel_failed(&self, id: &str) {
        if let Ok(mut i) = self.0.lock()
            && i.snapshot.workflow_id.as_deref() == Some(id)
            && i.worker_active
            && i.snapshot.phase == Phase::Running
            && !i.paired_settled
            && !i.paired_recovering
        {
            i.snapshot.paired_cancel_requested = false;
            i.snapshot.paired_cancel_available = i.paired_run.is_some();
        }
    }
    pub fn claim_paired_recovery(&self, id: &str) -> Result<String, String> {
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        if i.snapshot.workflow_id.as_deref() != Some(id)
            || i.worker_active
            || !i.snapshot.paired_recovery_required
            || !matches!(
                i.snapshot.phase,
                Phase::Failed | Phase::Completed | Phase::Cancelled
            )
        {
            return Err("No unresolved owned paired run is ready for recovery.".into());
        }
        let run = i
            .paired_run
            .as_ref()
            .ok_or("Paired context unavailable")?
            .1
            .clone();
        i.worker_active = true;
        i.paired_recovering = true;
        i.snapshot.paired_cancel_requested = false;
        i.snapshot.phase = Phase::Running;
        i.snapshot.paired_cancel_available = false;
        i.snapshot.progress = Some(
            "Reconciling only the retained exact paired session; no assessment is replayed.".into(),
        );
        Ok(run)
    }
    pub fn cancel(&self, id: &str) -> Result<(), String> {
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        if i.snapshot.workflow_id.as_deref() != Some(id)
            || !matches!(
                i.snapshot.phase,
                Phase::Preparing | Phase::Review | Phase::Approved
            )
        {
            return Err(
                "Only a pending workflow can be cancelled. A running worker must finish cleanup."
                    .into(),
            );
        }
        i.cancelled = true;
        Self::cancel_gate(&mut i);
        Ok(())
    }
    fn cancel_gate(i: &mut Inner) {
        match i.pending.take() {
            Some(Pending::Approval(tx)) => {
                let _ = tx.send(None);
            }
            Some(Pending::Start(tx)) => {
                let _ = tx.send(false);
            }
            None => {}
        }
        i.snapshot.start_challenge_id = None;
    }
    /// Returns true only when closing cannot abandon a worker or pending stage publication.
    pub fn request_close(&self) -> bool {
        let mut i = self.0.lock().expect("controller lock poisoned");
        if !i.worker_active && !i.snapshot.phase.busy() && !i.snapshot.paired_recovery_required {
            return true;
        }
        i.snapshot.close_refused = true;
        if matches!(
            i.snapshot.phase,
            Phase::Preparing | Phase::Review | Phase::Approved | Phase::Failed
        ) {
            i.closing = true;
            i.cancelled = true;
            Self::cancel_gate(&mut i);
        }
        false
    }
    pub fn finish(
        &self,
        id: &str,
        phase: Phase,
        result: Option<ResultView>,
        error: Option<ErrorView>,
    ) -> bool {
        let mut i = self.0.lock().expect("controller lock poisoned");
        if i.snapshot.workflow_id.as_deref() != Some(id) {
            return false;
        }
        Self::cancel_gate(&mut i);
        // Packaging errors are returned by their IPC call. Keep retained trial
        // errors with the trial rather than replacing them with an auxiliary error.
        if let Some(previous) = i.package_snapshot.take() {
            i.snapshot = previous;
            i.worker_active = false;
            i.snapshot.close_refused = false;
            return i.closing && !i.snapshot.paired_recovery_required;
        }
        i.snapshot.phase = phase;
        i.snapshot.paired_cancel_available = false;
        i.worker_active = false;
        i.snapshot.close_refused = false;
        i.snapshot.result = result;
        i.snapshot.error = error;
        i.snapshot.review = None;
        i.closing && !i.snapshot.paired_recovery_required
    }
    pub fn begin_export(&self) -> Result<(String, ResultView), String> {
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        if i.snapshot.phase != Phase::Completed {
            return Err("A completed verified transfer is required before export.".into());
        }
        let result = i
            .snapshot
            .result
            .clone()
            .filter(|r| r.can_export_document)
            .ok_or("No verified export is available.")?;
        let id = i
            .snapshot
            .workflow_id
            .clone()
            .ok_or("No retained workflow.")?;
        i.snapshot.phase = Phase::Exporting;
        i.worker_active = true;
        i.snapshot.error = None;
        Ok((id, result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running_pair() -> (Controller, String) {
        let c = Controller::new("test".into());
        let id = c.begin().unwrap();
        let hash = "a".repeat(64);
        let context = serde_json::json!({"schemaVersion":"aiw.dev/paired-workflow-run/v0alpha1", "planSha256":hash}).to_string();
        assert!(
            c.register_paired("foreign", &hash, context.clone())
                .is_err()
        );
        assert!(
            c.register_paired(&id, &"b".repeat(64), context.clone())
                .is_err()
        );
        c.register_paired(&id, &hash, context.clone()).unwrap();
        assert!(c.register_paired(&id, &hash, context).is_err());
        let mut wrong = review();
        wrong.plan_hash = "b".repeat(64);
        assert!(c.offer_review(&id, wrong).is_err());
        let approval = c.offer_review(&id, review()).unwrap();
        let r = c.snapshot().review.unwrap();
        c.approve(&id, &r.challenge_id, &r.exact_confirmation)
            .unwrap();
        approval.recv().unwrap();
        let start = c.offer_start(&id).unwrap();
        c.start(&id, &c.snapshot().start_challenge_id.unwrap())
            .unwrap();
        assert!(start.recv().unwrap());
        (c, id)
    }

    #[test]
    fn paired_cancel_is_owned_single_use_and_stale_failures_cannot_reenable_it() {
        let (c, id) = running_pair();
        assert!(c.claim_paired_cancel("foreign").is_err());
        assert!(c.claim_paired_cancel(&id).is_ok());
        assert!(c.snapshot().paired_cancel_requested);
        assert!(c.claim_paired_cancel(&id).is_err());
        c.settle_paired("foreign", &"a".repeat(64), false);
        assert!(c.snapshot().paired_cancel_requested);
        c.settle_paired(&id, &"a".repeat(64), false);
        c.paired_cancel_failed(&id);
        assert!(!c.snapshot().paired_cancel_requested);
        assert!(!c.snapshot().paired_cancel_available);
        assert!(c.claim_paired_cancel(&id).is_err());
        c.finish(&id, Phase::Completed, None, None);
        assert!(c.claim_paired_recovery(&id).is_err());
        assert!(c.request_close());
    }

    #[test]
    fn paired_unresolved_cleanup_blocks_close_and_new_work_and_recovery_is_single_flight() {
        let (c, id) = running_pair();
        c.claim_paired_cancel(&id).unwrap();
        c.settle_paired(&id, &"a".repeat(64), true);
        c.finish(&id, Phase::Failed, None, None);
        assert!(!c.request_close());
        assert!(c.begin().is_err());
        assert!(c.begin_packaging().is_err());
        assert!(c.claim_paired_recovery("foreign").is_err());
        assert!(c.claim_paired_recovery(&id).is_ok());
        assert!(c.claim_paired_recovery(&id).is_err());
        c.paired_cancel_failed(&id);
        assert!(!c.snapshot().paired_cancel_available);
        c.settle_paired(&id, &"a".repeat(64), true);
        assert!(!c.finish(&id, Phase::Failed, None, None));
        assert!(!c.request_close());
        c.claim_paired_recovery(&id).unwrap();
        c.settle_paired(&id, &"a".repeat(64), false);
        assert!(c.finish(&id, Phase::Completed, None, None));
        assert!(c.request_close());
        assert!(c.begin().is_err()); // A previously requested close still owns completion.
    }

    #[test]
    fn paired_registration_bounds_input_before_decoding() {
        let c = Controller::new("test".into());
        let id = c.begin().unwrap();
        assert!(
            c.register_paired(&id, &"a".repeat(64), " ".repeat(128 * 1024 + 1))
                .is_err()
        );
        assert!(
            c.register_paired(&id, &"a".repeat(64), "{}".into())
                .is_err()
        );
        assert!(!c.snapshot().paired_recovery_required);
    }

    #[test]
    fn packaging_operations_exclude_execution_and_guard_close_until_publication() {
        let c = Controller::new("test".into());
        let id = c.begin_analysis().unwrap();
        assert_eq!(c.snapshot().phase, Phase::Analyzing);
        assert!(c.begin().is_err());
        assert!(c.begin_packaging().is_err());
        assert!(c.cancel(&id).is_err());
        assert!(!c.request_close());
        c.finish(&id, Phase::Idle, None, None);
        assert!(c.request_close());
        let id = c.begin_packaging().unwrap();
        assert_eq!(c.snapshot().phase, Phase::Packaging);
        assert!(c.offer_review(&id, review()).is_err());
        assert!(!c.request_close());
        c.finish(&id, Phase::Idle, None, None);
        assert!(c.request_close());
    }

    #[test]
    fn auxiliary_packaging_preserves_completed_transfer_export_authority() {
        let c = Controller::new("test".into());
        let id = c.begin().unwrap();
        let result = ResultView {
            outcome: ResultOutcome::Verified,
            run_id: "retained-run".into(),
            workspace: "retained-workspace".into(),
            evidence_root: "retained-evidence".into(),
            summary: "Verified transfer".into(),
            can_export_document: true,
            report_markdown: "retained report".into(),
        };
        let trial_error = ErrorView {
            code: "retained-export-error".into(),
            summary: "trial error".into(),
            remediation: "preserve trial evidence".into(),
            detail: "original error".into(),
            run_id: Some("retained-run".into()),
        };
        c.finish(&id, Phase::Completed, Some(result), Some(trial_error));
        let auxiliary = c.begin_analysis().unwrap();
        assert!(c.begin_export().is_err());
        c.finish(&auxiliary, Phase::Idle, None, None);
        assert_eq!(c.snapshot().phase, Phase::Completed);
        assert_eq!(c.snapshot().result.unwrap().run_id, "retained-run");
        let auxiliary = c.begin_packaging().unwrap();
        c.finish(
            &auxiliary,
            Phase::Failed,
            None,
            Some(ErrorView {
                code: "package-error".into(),
                summary: "package failed".into(),
                remediation: "preserve package evidence".into(),
                detail: "auxiliary error".into(),
                run_id: None,
            }),
        );
        assert_eq!(c.snapshot().error.unwrap().code, "retained-export-error");
        let auxiliary = c.begin_packaging().unwrap();
        c.finish(&auxiliary, Phase::Idle, None, None);
        assert_eq!(c.snapshot().error.unwrap().code, "retained-export-error");
        let (_, result) = c.begin_export().unwrap();
        assert!(result.can_export_document);
        assert_eq!(result.run_id, "retained-run");
    }
    fn review() -> Review {
        Review {
            workflow_name: "Test workflow".into(),
            challenge_id: String::new(),
            plan_hash: "a".repeat(64),
            exact_confirmation: format!("approve {}", "a".repeat(64)),
            operator_identity: "test".into(),
            recipe_json: "{}".into(),
            plan_json: "{}".into(),
            approval_json: "{}".into(),
            evidence_root: "test".into(),
            workspace: "test".into(),
        }
    }
    #[test]
    fn gates_are_distinct_exact_and_single_use() {
        let c = Controller::new("test".into());
        let id = c.begin().unwrap();
        let rx = c.offer_review(&id, review()).unwrap();
        let s = c.snapshot();
        let r = s.review.unwrap();
        assert!(c.begin().is_err());
        assert!(c.start(&id, &r.challenge_id).is_err());
        assert!(
            c.approve("other", &r.challenge_id, &r.exact_confirmation)
                .is_err()
        );
        assert!(c.approve(&id, "stale", &r.exact_confirmation).is_err());
        assert!(c.approve(&id, &r.challenge_id, "approve wrong").is_err());
        c.approve(&id, &r.challenge_id, &r.exact_confirmation)
            .unwrap();
        assert_eq!(rx.recv().unwrap(), Some(r.exact_confirmation.clone()));
        assert!(
            c.approve(&id, &r.challenge_id, &r.exact_confirmation)
                .is_err()
        );
        assert_eq!(c.snapshot().phase, Phase::Preparing);
        let start = c.offer_start(&id).unwrap();
        let challenge = c.snapshot().start_challenge_id.unwrap();
        assert_eq!(c.snapshot().phase, Phase::Approved);
        assert!(start.try_recv().is_err());
        assert!(c.start(&id, "stale").is_err());
        c.start(&id, &challenge).unwrap();
        assert!(start.recv().unwrap());
        assert!(c.start(&id, &challenge).is_err());
        assert!(c.cancel(&id).is_err());
        assert!(!c.request_close());
        assert!(!c.finish(&id, Phase::Completed, None, None));
        assert!(!c.snapshot().close_refused);
        assert!(c.request_close());
    }
    #[test]
    fn closure_cancels_pending_and_waits_for_durable_finish() {
        let c = Controller::new("test".into());
        let id = c.begin().unwrap();
        let rx = c.offer_review(&id, review()).unwrap();
        assert!(!c.request_close());
        assert_eq!(rx.recv().unwrap(), None);
        assert!(c.finish(&id, Phase::Cancelled, None, None));
    }
    #[test]
    fn cancellation_after_approval_does_not_start() {
        let c = Controller::new("test".into());
        let id = c.begin().unwrap();
        let rx = c.offer_review(&id, review()).unwrap();
        let r = c.snapshot().review.unwrap();
        c.approve(&id, &r.challenge_id, &r.exact_confirmation)
            .unwrap();
        rx.recv().unwrap();
        let rx = c.offer_start(&id).unwrap();
        c.cancel(&id).unwrap();
        assert!(!rx.recv().unwrap());
        assert!(c.begin_export().is_err());
    }
    #[test]
    fn cancel_during_preparation_survives_review_publication() {
        let c = Controller::new("test".into());
        let id = c.begin().unwrap();
        c.cancel(&id).unwrap();
        assert_eq!(c.offer_review(&id, review()).unwrap().recv().unwrap(), None);
    }
    #[test]
    fn lost_gate_receivers_cannot_leave_a_permanent_busy_state() {
        let c = Controller::new("test".into());
        let id = c.begin().unwrap();
        let rx = c.offer_review(&id, review()).unwrap();
        let r = c.snapshot().review.unwrap();
        drop(rx);
        assert!(
            c.approve(&id, &r.challenge_id, &r.exact_confirmation)
                .is_err()
        );
        assert_eq!(c.snapshot().phase, Phase::Failed);
        assert!(c.begin().is_err());
        c.finish(&id, Phase::Failed, None, None);
        assert!(c.request_close());
        let id = c.begin().unwrap();
        let rx = c.offer_review(&id, review()).unwrap();
        let r = c.snapshot().review.unwrap();
        c.approve(&id, &r.challenge_id, &r.exact_confirmation)
            .unwrap();
        rx.recv().unwrap();
        let rx = c.offer_start(&id).unwrap();
        let challenge = c.snapshot().start_challenge_id.unwrap();
        drop(rx);
        assert!(c.start(&id, &challenge).is_err());
        assert_eq!(c.snapshot().phase, Phase::Failed);
        assert!(c.begin().is_err());
        c.finish(&id, Phase::Failed, None, None);
        assert!(c.request_close());
    }
    #[test]
    fn recovery_is_busy_has_bound_progress_and_cannot_be_cancelled_as_pending_work() {
        let c = Controller::new("test".into());
        let id = c.begin_recovery().unwrap();
        assert_eq!(c.snapshot().phase, Phase::Running);
        c.progress("other-workflow", "wrong");
        assert!(c.snapshot().progress.is_none());
        c.progress(&id, "Verifying cold restore");
        assert_eq!(
            c.snapshot().progress.as_deref(),
            Some("Verifying cold restore")
        );
        assert!(c.begin().is_err());
        assert!(c.cancel(&id).is_err());
        assert!(!c.request_close());
        assert!(!c.finish(&id, Phase::Completed, None, None));
        assert!(c.request_close());
    }
}

#[cfg(windows)]
pub mod results;

#[cfg(all(test, windows))]
#[path = "workflow_demo.rs"]
mod workflow_demo;
