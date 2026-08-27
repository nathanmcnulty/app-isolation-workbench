#![forbid(unsafe_code)]

mod analyst;
mod canary;

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use analyst::{
    ANALYST_REPORT_KIND, ANALYST_REPORT_SCHEMA_VERSION, ANALYST_VALIDATION_SCHEMA_VERSION,
    AnalystAction, AnalystCategory, AnalystConfidence, AnalystFinding, AnalystInputClass,
    AnalystNetworkAccess, AnalystPriority, AnalystProvenance, AnalystRecommendation, AnalystReport,
    AnalystReportError, AnalystReportValidation, AnalystSeverity, AnalystTextFormat,
    AnalystToolAccess, AnalystTransport, CitedStatement, EscalationTarget, EvidenceCitation,
    EvidenceKind, RelaxationControl, validate_analyst_report,
};
pub use canary::{
    CANARY_OBSERVATION_SET_SCHEMA_VERSION, CANARY_PLAN_SCHEMA_VERSION,
    CANARY_REPORT_SCHEMA_VERSION, CanaryAssertion, CanaryAssertionResult, CanaryBoundary,
    CanaryEvaluationError, CanaryObservation, CanaryObservationSet, CanaryOutcome, CanaryPhase,
    CanaryPlan, CanaryReason, CanaryReport, CanaryVerdict, evaluate_canaries,
};

/// Lifecycle for an evidence-producing baseline/candidate assessment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentRunState {
    Created,
    Planned,
    Approved,
    BaselineRunning,
    CandidateRunning,
    EvidenceCollecting,
    Compared,
    Finalized,
    Failed,
}

/// Lifecycle for replaying a validated launch profile; it is intentionally separate from assessment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LaunchRunState {
    Created,
    DriftChecking,
    Launching,
    EvidenceCollecting,
    Finalized,
    Failed,
}

/// Lifecycle for Studio authoring, from reviewed capture through final-package validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AuthoringRunState {
    Created,
    Planned,
    Approved,
    Capturing,
    Adapting,
    Packaging,
    Inspecting,
    TestSigning,
    Validating,
    FinalSigning,
    FinalValidating,
    Finalized,
    Failed,
}

macro_rules! lifecycle_machine {
    ($state:ident, $transition:ident, $machine:ident, $error:ident, $initial:ident, $can_transition:ident) => {
        #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $transition {
            pub sequence: u64,
            pub from: $state,
            pub to: $state,
            pub reason: String,
        }

        #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $machine {
            state: $state,
            transitions: Vec<$transition>,
        }

        impl $machine {
            #[must_use]
            pub fn new() -> Self {
                Self {
                    state: $state::$initial,
                    transitions: Vec::new(),
                }
            }

            #[must_use]
            pub const fn state(&self) -> $state {
                self.state
            }

            #[must_use]
            pub fn transitions(&self) -> &[$transition] {
                &self.transitions
            }

            pub fn transition(
                &mut self,
                to: $state,
                reason: impl Into<String>,
            ) -> Result<&$transition, $error> {
                if !$can_transition(self.state, to) {
                    return Err($error::IllegalTransition {
                        from: self.state,
                        to,
                    });
                }
                let reason = reason.into();
                if reason.trim().is_empty() {
                    return Err($error::EmptyReason);
                }
                let transition = $transition {
                    sequence: self.transitions.len() as u64,
                    from: self.state,
                    to,
                    reason,
                };
                self.state = to;
                self.transitions.push(transition);
                Ok(self
                    .transitions
                    .last()
                    .expect("transition was just appended"))
            }
        }

        impl Default for $machine {
            fn default() -> Self {
                Self::new()
            }
        }

        #[derive(Debug, Error, PartialEq, Eq)]
        pub enum $error {
            #[error("illegal lifecycle transition from {from:?} to {to:?}")]
            IllegalTransition { from: $state, to: $state },
            #[error("lifecycle transitions require a non-empty reason")]
            EmptyReason,
        }
    };
}

lifecycle_machine!(
    AssessmentRunState,
    AssessmentRunTransition,
    AssessmentRunStateMachine,
    AssessmentRunStateError,
    Created,
    can_transition_assessment
);
lifecycle_machine!(
    LaunchRunState,
    LaunchRunTransition,
    LaunchRunStateMachine,
    LaunchRunStateError,
    Created,
    can_transition_launch
);
lifecycle_machine!(
    AuthoringRunState,
    AuthoringRunTransition,
    AuthoringRunStateMachine,
    AuthoringRunStateError,
    Created,
    can_transition_authoring
);

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunSummary {
    pub schema_version: String,
    pub run_id: String,
    pub project_hash: String,
    pub candidate_id: String,
    pub os_build: String,
    pub effective_backend: String,
    pub scenarios: BTreeMap<String, ScenarioResult>,
    pub assertions: BTreeMap<String, bool>,
    pub evidence_root_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScenarioResult {
    pub status: ScenarioStatus,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ScenarioStatus {
    Passed,
    Failed,
    Skipped,
    Incomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComparisonReport {
    pub schema_version: String,
    pub left_run_id: String,
    pub right_run_id: String,
    pub project_hash_match: bool,
    pub os_build_match: bool,
    pub backend_match: bool,
    pub scenario_deltas: Vec<ScenarioDelta>,
    pub assertion_deltas: Vec<AssertionDelta>,
    pub regression_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScenarioDelta {
    pub scenario_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<ScenarioStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right: Option<ScenarioStatus>,
    pub classification: DeltaClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssertionDelta {
    pub assertion_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right: Option<bool>,
    pub classification: DeltaClassification,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DeltaClassification {
    Unchanged,
    Added,
    Removed,
    Improved,
    Regressed,
    Changed,
}

#[must_use]
pub fn compare_runs(left: &RunSummary, right: &RunSummary) -> ComparisonReport {
    let scenario_ids: BTreeSet<_> = left
        .scenarios
        .keys()
        .chain(right.scenarios.keys())
        .cloned()
        .collect();
    let scenario_deltas: Vec<_> = scenario_ids
        .into_iter()
        .map(|scenario_id| {
            let left_status = left.scenarios.get(&scenario_id).map(|result| result.status);
            let right_status = right
                .scenarios
                .get(&scenario_id)
                .map(|result| result.status);
            ScenarioDelta {
                scenario_id,
                left: left_status,
                right: right_status,
                classification: classify_scenario(left_status, right_status),
            }
        })
        .collect();

    let assertion_ids: BTreeSet<_> = left
        .assertions
        .keys()
        .chain(right.assertions.keys())
        .cloned()
        .collect();
    let assertion_deltas: Vec<_> = assertion_ids
        .into_iter()
        .map(|assertion_id| {
            let left_value = left.assertions.get(&assertion_id).copied();
            let right_value = right.assertions.get(&assertion_id).copied();
            AssertionDelta {
                assertion_id,
                left: left_value,
                right: right_value,
                classification: classify_assertion(left_value, right_value),
            }
        })
        .collect();

    let regression_count = scenario_deltas
        .iter()
        .filter(|delta| delta.classification == DeltaClassification::Regressed)
        .count()
        + assertion_deltas
            .iter()
            .filter(|delta| delta.classification == DeltaClassification::Regressed)
            .count();

    ComparisonReport {
        schema_version: "aiw.dev/comparison/v0alpha1".to_owned(),
        left_run_id: left.run_id.clone(),
        right_run_id: right.run_id.clone(),
        project_hash_match: left.project_hash == right.project_hash,
        os_build_match: left.os_build == right.os_build,
        backend_match: left.effective_backend == right.effective_backend,
        scenario_deltas,
        assertion_deltas,
        regression_count: regression_count as u64,
    }
}

const fn can_transition_assessment(from: AssessmentRunState, to: AssessmentRunState) -> bool {
    if matches!(to, AssessmentRunState::Failed) {
        return !matches!(
            from,
            AssessmentRunState::Finalized | AssessmentRunState::Failed
        );
    }
    matches!(
        (from, to),
        (AssessmentRunState::Created, AssessmentRunState::Planned)
            | (AssessmentRunState::Planned, AssessmentRunState::Approved)
            | (
                AssessmentRunState::Approved,
                AssessmentRunState::BaselineRunning
            )
            | (
                AssessmentRunState::BaselineRunning,
                AssessmentRunState::CandidateRunning
            )
            | (
                AssessmentRunState::CandidateRunning,
                AssessmentRunState::EvidenceCollecting
            )
            | (
                AssessmentRunState::EvidenceCollecting,
                AssessmentRunState::Compared
            )
            | (AssessmentRunState::Compared, AssessmentRunState::Finalized)
    )
}

const fn can_transition_launch(from: LaunchRunState, to: LaunchRunState) -> bool {
    if matches!(to, LaunchRunState::Failed) {
        return !matches!(from, LaunchRunState::Finalized | LaunchRunState::Failed);
    }
    matches!(
        (from, to),
        (LaunchRunState::Created, LaunchRunState::DriftChecking)
            | (LaunchRunState::DriftChecking, LaunchRunState::Launching)
            | (
                LaunchRunState::Launching,
                LaunchRunState::EvidenceCollecting
            )
            | (
                LaunchRunState::EvidenceCollecting,
                LaunchRunState::Finalized
            )
    )
}

const fn can_transition_authoring(from: AuthoringRunState, to: AuthoringRunState) -> bool {
    if matches!(to, AuthoringRunState::Failed) {
        return !matches!(
            from,
            AuthoringRunState::Finalized | AuthoringRunState::Failed
        );
    }
    matches!(
        (from, to),
        (AuthoringRunState::Created, AuthoringRunState::Planned)
            | (AuthoringRunState::Planned, AuthoringRunState::Approved)
            | (AuthoringRunState::Approved, AuthoringRunState::Capturing)
            | (AuthoringRunState::Capturing, AuthoringRunState::Adapting)
            | (AuthoringRunState::Adapting, AuthoringRunState::Packaging)
            | (AuthoringRunState::Packaging, AuthoringRunState::Inspecting)
            | (
                AuthoringRunState::Inspecting,
                AuthoringRunState::TestSigning
            )
            | (
                AuthoringRunState::TestSigning,
                AuthoringRunState::Validating
            )
            | (
                AuthoringRunState::Validating,
                AuthoringRunState::FinalSigning
            )
            | (
                AuthoringRunState::FinalSigning,
                AuthoringRunState::FinalValidating
            )
            | (
                AuthoringRunState::FinalValidating,
                AuthoringRunState::Finalized
            )
    )
}

fn classify_scenario(
    left: Option<ScenarioStatus>,
    right: Option<ScenarioStatus>,
) -> DeltaClassification {
    match (left, right) {
        (None, Some(_)) => DeltaClassification::Added,
        (Some(_), None) => DeltaClassification::Removed,
        (Some(left), Some(right)) if scenario_rank(left) < scenario_rank(right) => {
            DeltaClassification::Improved
        }
        (Some(left), Some(right)) if scenario_rank(left) > scenario_rank(right) => {
            DeltaClassification::Regressed
        }
        (Some(left), Some(right)) if left == right => DeltaClassification::Unchanged,
        _ => DeltaClassification::Changed,
    }
}

const fn classify_assertion(left: Option<bool>, right: Option<bool>) -> DeltaClassification {
    match (left, right) {
        (None, Some(_)) => DeltaClassification::Added,
        (Some(_), None) => DeltaClassification::Removed,
        (Some(false), Some(true)) => DeltaClassification::Improved,
        (Some(true), Some(false)) => DeltaClassification::Regressed,
        (Some(left), Some(right)) if left == right => DeltaClassification::Unchanged,
        _ => DeltaClassification::Changed,
    }
}

const fn scenario_rank(status: ScenarioStatus) -> u8 {
    match status {
        ScenarioStatus::Failed => 0,
        ScenarioStatus::Incomplete => 1,
        ScenarioStatus::Skipped => 2,
        ScenarioStatus::Passed => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assessment_lifecycle_rejects_skipped_approval() {
        let mut machine = AssessmentRunStateMachine::new();
        let error = machine
            .transition(AssessmentRunState::Approved, "skip plan")
            .unwrap_err();
        assert_eq!(
            error,
            AssessmentRunStateError::IllegalTransition {
                from: AssessmentRunState::Created,
                to: AssessmentRunState::Approved,
            }
        );
    }

    #[test]
    fn assessment_failure_is_terminal() {
        let mut machine = AssessmentRunStateMachine::new();
        machine
            .transition(AssessmentRunState::Failed, "worker unavailable")
            .unwrap();
        assert!(
            machine
                .transition(AssessmentRunState::Planned, "retry")
                .is_err()
        );
    }

    #[test]
    fn launch_lifecycle_requires_drift_check_before_launch() {
        let mut machine = LaunchRunStateMachine::new();
        assert!(matches!(
            machine.transition(LaunchRunState::Launching, "skip drift"),
            Err(LaunchRunStateError::IllegalTransition { .. })
        ));
        machine
            .transition(LaunchRunState::DriftChecking, "validate profile")
            .unwrap();
        machine
            .transition(LaunchRunState::Launching, "profile current")
            .unwrap();
    }

    #[test]
    fn authoring_lifecycle_requires_final_validation_after_final_signing() {
        let mut machine = AuthoringRunStateMachine::new();
        for state in [
            AuthoringRunState::Planned,
            AuthoringRunState::Approved,
            AuthoringRunState::Capturing,
            AuthoringRunState::Adapting,
            AuthoringRunState::Packaging,
            AuthoringRunState::Inspecting,
            AuthoringRunState::TestSigning,
            AuthoringRunState::Validating,
            AuthoringRunState::FinalSigning,
        ] {
            machine.transition(state, "advance authoring").unwrap();
        }
        assert!(matches!(
            machine.transition(AuthoringRunState::Finalized, "skip final validation"),
            Err(AuthoringRunStateError::IllegalTransition { .. })
        ));
        machine
            .transition(
                AuthoringRunState::FinalValidating,
                "validate signed artifact",
            )
            .unwrap();
        machine
            .transition(AuthoringRunState::Finalized, "complete")
            .unwrap();
    }

    #[test]
    fn comparison_identifies_regressions() {
        let mut left_scenarios = BTreeMap::new();
        left_scenarios.insert(
            "first-run".to_owned(),
            ScenarioResult {
                status: ScenarioStatus::Passed,
                evidence_ids: vec!["e1".to_owned()],
                detail: None,
            },
        );
        let mut right_scenarios = left_scenarios.clone();
        right_scenarios.get_mut("first-run").unwrap().status = ScenarioStatus::Failed;

        let base = RunSummary {
            schema_version: "aiw.dev/run-summary/v0alpha1".to_owned(),
            run_id: "baseline".to_owned(),
            project_hash: "a".repeat(64),
            candidate_id: "baseline".to_owned(),
            os_build: "26100".to_owned(),
            effective_backend: "win32".to_owned(),
            scenarios: left_scenarios,
            assertions: BTreeMap::from([("tokenVerified".to_owned(), true)]),
            evidence_root_hash: "b".repeat(64),
        };
        let mut candidate = base.clone();
        candidate.run_id = "candidate".to_owned();
        candidate.effective_backend = "processContainer".to_owned();
        candidate.scenarios = right_scenarios;
        candidate
            .assertions
            .insert("tokenVerified".to_owned(), false);

        let comparison = compare_runs(&base, &candidate);
        assert_eq!(comparison.regression_count, 2);
        assert!(!comparison.backend_match);
    }
}
