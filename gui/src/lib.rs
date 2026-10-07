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
    pub phase: Phase,
    pub workflow_id: Option<String>,
    pub review: Option<Review>,
    pub start_challenge_id: Option<String>,
    pub result: Option<ResultView>,
    pub error: Option<ErrorView>,
    pub defaults: Defaults,
    pub close_refused: bool,
}

enum Pending {
    Approval(mpsc::Sender<Option<String>>),
    Start(mpsc::Sender<bool>),
}
struct Inner {
    snapshot: Snapshot,
    pending: Option<Pending>,
    cancelled: bool,
    closing: bool,
    worker_active: bool,
}

#[derive(Clone)]
pub struct Controller(Arc<Mutex<Inner>>);

impl Controller {
    pub fn new(evidence: String) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            snapshot: Snapshot {
                phase: Phase::Idle,
                workflow_id: None,
                review: None,
                start_challenge_id: None,
                result: None,
                error: None,
                defaults: Defaults { evidence },
                close_refused: false,
            },
            pending: None,
            cancelled: false,
            closing: false,
            worker_active: false,
        })))
    }
    pub fn snapshot(&self) -> Snapshot {
        self.0
            .lock()
            .expect("controller lock poisoned")
            .snapshot
            .clone()
    }
    pub fn begin(&self) -> Result<String, String> {
        self.begin_phase(Phase::Preparing)
    }
    pub fn begin_analysis(&self) -> Result<String, String> {
        self.begin_phase(Phase::Analyzing)
    }
    pub fn begin_packaging(&self) -> Result<String, String> {
        self.begin_phase(Phase::Packaging)
    }
    fn begin_phase(&self, phase: Phase) -> Result<String, String> {
        let mut i = self.0.lock().map_err(|_| "controller unavailable")?;
        if i.worker_active || i.snapshot.phase.busy() || i.closing {
            return Err("Wait for the current workflow to finish.".into());
        }
        let id = Uuid::new_v4().to_string();
        i.snapshot.phase = phase;
        i.snapshot.workflow_id = Some(id.clone());
        i.snapshot.review = None;
        i.snapshot.start_challenge_id = None;
        i.snapshot.result = None;
        i.snapshot.error = None;
        i.snapshot.close_refused = false;
        i.pending = None;
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
        if !i.worker_active && !i.snapshot.phase.busy() {
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
        i.snapshot.phase = phase;
        i.worker_active = false;
        i.snapshot.close_refused = false;
        i.snapshot.result = result;
        i.snapshot.error = error;
        i.snapshot.review = None;
        i.closing
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
}
