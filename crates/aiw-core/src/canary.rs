use std::collections::{BTreeMap, BTreeSet};

use aiw_evidence::{EvidenceError, EvidenceRecord, verify_records};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CANARY_PLAN_SCHEMA_VERSION: &str = "aiw.dev/canary-plan/v0alpha1";
pub const CANARY_OBSERVATION_SET_SCHEMA_VERSION: &str = "aiw.dev/canary-observation-set/v0alpha1";
pub const CANARY_REPORT_SCHEMA_VERSION: &str = "aiw.dev/canary-report/v0alpha1";
const MAX_ASSERTIONS: usize = 64;
const MAX_EVIDENCE_IDS: usize = 32;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CanaryBoundary {
    HostFileRead,
    HostFileWrite,
    HostRegistryRead,
    HostRegistryWrite,
    DnsResolve,
    TcpConnect,
    ClipboardRead,
    SiblingProcessOpen,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanaryAssertion {
    pub id: String,
    pub boundary: CanaryBoundary,
    pub resource_id: String,
    #[serde(default = "default_true")]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanaryPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub assertions: Vec<CanaryAssertion>,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "camelCase")]
pub enum CanaryPhase {
    BaselineControl,
    IsolatedCandidate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CanaryOutcome {
    Succeeded,
    AccessDenied,
    NotFound,
    TimedOut,
    NetworkUnreachable,
    Unavailable,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanaryObservation {
    pub assertion_id: String,
    pub phase: CanaryPhase,
    pub outcome: CanaryOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_error_code: Option<u32>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanaryObservationSet {
    pub schema_version: String,
    pub plan_id: String,
    pub candidate_id: String,
    pub observations: Vec<CanaryObservation>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CanaryVerdict {
    Passed,
    Failed,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CanaryReason {
    VerifiedDenial,
    IsolationGap,
    BaselineControlNotProven,
    CandidateObservationUnavailable,
    MissingObservation,
    MissingEvidence,
    MissingNativeErrorCode,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanaryAssertionResult {
    pub assertion_id: String,
    pub boundary: CanaryBoundary,
    pub resource_id: String,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_outcome: Option<CanaryOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_native_error_code: Option<u32>,
    #[serde(default)]
    pub baseline_evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_outcome: Option<CanaryOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_native_error_code: Option<u32>,
    #[serde(default)]
    pub candidate_evidence_ids: Vec<String>,
    pub verdict: CanaryVerdict,
    pub reason: CanaryReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanaryReport {
    pub schema_version: String,
    pub plan_id: String,
    pub candidate_id: String,
    pub evidence_root_hash: String,
    pub evidence_chain_verified: bool,
    pub verdict: CanaryVerdict,
    pub required_count: u64,
    pub passed_required_count: u64,
    pub failed_required_count: u64,
    pub indeterminate_required_count: u64,
    pub results: Vec<CanaryAssertionResult>,
}

#[derive(Debug, Error)]
pub enum CanaryEvaluationError {
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error("unsupported canary plan schema version '{0}'")]
    UnsupportedPlanSchema(String),
    #[error("unsupported canary observation-set schema version '{0}'")]
    UnsupportedObservationSchema(String),
    #[error("plan or candidate IDs must contain 1-64 lowercase ASCII letters, digits, or hyphens")]
    InvalidTopLevelId,
    #[error("canary plan must contain 1-{MAX_ASSERTIONS} assertions")]
    InvalidAssertionCount,
    #[error("canary plan must contain at least one required assertion")]
    NoRequiredAssertions,
    #[error("canary assertion ID is invalid: {0}")]
    InvalidAssertionId(String),
    #[error("canary resource ID is invalid: {0}")]
    InvalidResourceId(String),
    #[error("canary assertion ID is duplicated: {0}")]
    DuplicateAssertion(String),
    #[error("observation plan ID '{actual}' does not match '{expected}'")]
    PlanIdMismatch { expected: String, actual: String },
    #[error("observation references an unknown assertion: {0}")]
    UnknownAssertion(String),
    #[error("observation is duplicated for assertion '{assertion_id}' phase {phase:?}")]
    DuplicateObservation {
        assertion_id: String,
        phase: CanaryPhase,
    },
    #[error("observation has too many evidence IDs for assertion '{0}'")]
    TooManyEvidenceIds(String),
    #[error("observation contains an invalid evidence ID: {0}")]
    InvalidEvidenceId(String),
    #[error("observation contains a duplicate evidence ID: {0}")]
    DuplicateEvidenceId(String),
    #[error("observation references evidence that is not in the verified chain: {0}")]
    UnknownEvidenceId(String),
}

pub fn evaluate_canaries(
    plan: &CanaryPlan,
    observation_set: &CanaryObservationSet,
    evidence_records: &[EvidenceRecord],
) -> Result<CanaryReport, CanaryEvaluationError> {
    let evidence_manifest = verify_records(evidence_records)?;
    validate_plan(plan)?;
    validate_observation_set(plan, observation_set, evidence_records)?;

    let observations: BTreeMap<_, _> = observation_set
        .observations
        .iter()
        .map(|observation| {
            (
                (observation.assertion_id.as_str(), observation.phase),
                observation,
            )
        })
        .collect();
    let mut assertions: Vec<_> = plan.assertions.iter().collect();
    assertions.sort_by_key(|assertion| assertion.id.as_str());
    let results: Vec<_> = assertions
        .into_iter()
        .map(|assertion| {
            let baseline = observations
                .get(&(assertion.id.as_str(), CanaryPhase::BaselineControl))
                .copied();
            let candidate = observations
                .get(&(assertion.id.as_str(), CanaryPhase::IsolatedCandidate))
                .copied();
            evaluate_assertion(assertion, baseline, candidate)
        })
        .collect();

    let required_count = results.iter().filter(|result| result.required).count() as u64;
    let passed_required_count = count_required(&results, CanaryVerdict::Passed);
    let failed_required_count = count_required(&results, CanaryVerdict::Failed);
    let indeterminate_required_count = count_required(&results, CanaryVerdict::Indeterminate);
    let verdict = if failed_required_count > 0 {
        CanaryVerdict::Failed
    } else if indeterminate_required_count > 0 {
        CanaryVerdict::Indeterminate
    } else {
        CanaryVerdict::Passed
    };

    Ok(CanaryReport {
        schema_version: CANARY_REPORT_SCHEMA_VERSION.to_owned(),
        plan_id: plan.plan_id.clone(),
        candidate_id: observation_set.candidate_id.clone(),
        evidence_root_hash: evidence_manifest.root_hash,
        evidence_chain_verified: true,
        verdict,
        required_count,
        passed_required_count,
        failed_required_count,
        indeterminate_required_count,
        results,
    })
}

fn validate_plan(plan: &CanaryPlan) -> Result<(), CanaryEvaluationError> {
    if plan.schema_version != CANARY_PLAN_SCHEMA_VERSION {
        return Err(CanaryEvaluationError::UnsupportedPlanSchema(
            plan.schema_version.clone(),
        ));
    }
    if !is_valid_id(&plan.plan_id) {
        return Err(CanaryEvaluationError::InvalidTopLevelId);
    }
    if plan.assertions.is_empty() || plan.assertions.len() > MAX_ASSERTIONS {
        return Err(CanaryEvaluationError::InvalidAssertionCount);
    }
    if !plan.assertions.iter().any(|assertion| assertion.required) {
        return Err(CanaryEvaluationError::NoRequiredAssertions);
    }
    let mut assertion_ids = BTreeSet::new();
    for assertion in &plan.assertions {
        if !is_valid_id(&assertion.id) {
            return Err(CanaryEvaluationError::InvalidAssertionId(
                assertion.id.clone(),
            ));
        }
        if !is_valid_id(&assertion.resource_id) {
            return Err(CanaryEvaluationError::InvalidResourceId(
                assertion.resource_id.clone(),
            ));
        }
        if !assertion_ids.insert(assertion.id.as_str()) {
            return Err(CanaryEvaluationError::DuplicateAssertion(
                assertion.id.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_observation_set(
    plan: &CanaryPlan,
    observation_set: &CanaryObservationSet,
    evidence_records: &[EvidenceRecord],
) -> Result<(), CanaryEvaluationError> {
    if observation_set.schema_version != CANARY_OBSERVATION_SET_SCHEMA_VERSION {
        return Err(CanaryEvaluationError::UnsupportedObservationSchema(
            observation_set.schema_version.clone(),
        ));
    }
    if observation_set.plan_id != plan.plan_id {
        return Err(CanaryEvaluationError::PlanIdMismatch {
            expected: plan.plan_id.clone(),
            actual: observation_set.plan_id.clone(),
        });
    }
    if !is_valid_id(&observation_set.candidate_id) {
        return Err(CanaryEvaluationError::InvalidTopLevelId);
    }

    let assertion_ids: BTreeSet<_> = plan
        .assertions
        .iter()
        .map(|assertion| assertion.id.as_str())
        .collect();
    let mut observation_keys = BTreeSet::new();
    let evidence_hashes: BTreeSet<_> = evidence_records
        .iter()
        .map(|record| record.hash.as_str())
        .collect();
    for observation in &observation_set.observations {
        if !assertion_ids.contains(observation.assertion_id.as_str()) {
            return Err(CanaryEvaluationError::UnknownAssertion(
                observation.assertion_id.clone(),
            ));
        }
        if !observation_keys.insert((observation.assertion_id.as_str(), observation.phase)) {
            return Err(CanaryEvaluationError::DuplicateObservation {
                assertion_id: observation.assertion_id.clone(),
                phase: observation.phase,
            });
        }
        if observation.evidence_ids.len() > MAX_EVIDENCE_IDS {
            return Err(CanaryEvaluationError::TooManyEvidenceIds(
                observation.assertion_id.clone(),
            ));
        }
        let mut evidence_ids = BTreeSet::new();
        for evidence_id in &observation.evidence_ids {
            if !is_valid_evidence_id(evidence_id) {
                return Err(CanaryEvaluationError::InvalidEvidenceId(
                    evidence_id.clone(),
                ));
            }
            if !evidence_ids.insert(evidence_id.as_str()) {
                return Err(CanaryEvaluationError::DuplicateEvidenceId(
                    evidence_id.clone(),
                ));
            }
            if !evidence_hashes.contains(evidence_id.as_str()) {
                return Err(CanaryEvaluationError::UnknownEvidenceId(
                    evidence_id.clone(),
                ));
            }
        }
    }
    Ok(())
}

fn evaluate_assertion(
    assertion: &CanaryAssertion,
    baseline: Option<&CanaryObservation>,
    candidate: Option<&CanaryObservation>,
) -> CanaryAssertionResult {
    let (verdict, reason) = match (baseline, candidate) {
        (None, _) | (_, None) => (
            CanaryVerdict::Indeterminate,
            CanaryReason::MissingObservation,
        ),
        (Some(baseline), Some(candidate))
            if baseline.evidence_ids.is_empty() || candidate.evidence_ids.is_empty() =>
        {
            (CanaryVerdict::Indeterminate, CanaryReason::MissingEvidence)
        }
        (Some(baseline), _) if baseline.outcome != CanaryOutcome::Succeeded => (
            CanaryVerdict::Indeterminate,
            CanaryReason::BaselineControlNotProven,
        ),
        (_, Some(candidate))
            if candidate.outcome == CanaryOutcome::AccessDenied
                && candidate.native_error_code.is_none() =>
        {
            (
                CanaryVerdict::Indeterminate,
                CanaryReason::MissingNativeErrorCode,
            )
        }
        (_, Some(candidate)) if candidate.outcome == CanaryOutcome::AccessDenied => {
            (CanaryVerdict::Passed, CanaryReason::VerifiedDenial)
        }
        (_, Some(candidate)) if candidate.outcome == CanaryOutcome::Succeeded => {
            (CanaryVerdict::Failed, CanaryReason::IsolationGap)
        }
        _ => (
            CanaryVerdict::Indeterminate,
            CanaryReason::CandidateObservationUnavailable,
        ),
    };

    CanaryAssertionResult {
        assertion_id: assertion.id.clone(),
        boundary: assertion.boundary,
        resource_id: assertion.resource_id.clone(),
        required: assertion.required,
        baseline_outcome: baseline.map(|observation| observation.outcome),
        baseline_native_error_code: baseline.and_then(|observation| observation.native_error_code),
        baseline_evidence_ids: baseline.map_or_else(Vec::new, sorted_evidence_ids),
        candidate_outcome: candidate.map(|observation| observation.outcome),
        candidate_native_error_code: candidate
            .and_then(|observation| observation.native_error_code),
        candidate_evidence_ids: candidate.map_or_else(Vec::new, sorted_evidence_ids),
        verdict,
        reason,
    }
}

fn sorted_evidence_ids(observation: &CanaryObservation) -> Vec<String> {
    let mut evidence_ids = observation.evidence_ids.clone();
    evidence_ids.sort_unstable();
    evidence_ids
}

fn count_required(results: &[CanaryAssertionResult], verdict: CanaryVerdict) -> u64 {
    results
        .iter()
        .filter(|result| result.required && result.verdict == verdict)
        .count() as u64
}

fn is_valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_valid_evidence_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use aiw_evidence::{EvidenceEvent, EvidenceLog};

    use super::*;

    fn evidence_log() -> EvidenceLog {
        let mut log = EvidenceLog::new();
        for (index, phase) in ["baselineControl", "isolatedCandidate"].iter().enumerate() {
            log.append(EvidenceEvent {
                observed_utc: format!("2026-08-19T00:00:0{index}Z"),
                kind: "canaryObservation".to_owned(),
                source: "fixture".to_owned(),
                payload: serde_json::json!({"phase": phase}),
            })
            .unwrap();
        }
        log
    }

    fn assertion(id: &str, required: bool) -> CanaryAssertion {
        CanaryAssertion {
            id: id.to_owned(),
            boundary: CanaryBoundary::HostFileRead,
            resource_id: format!("{id}-resource"),
            required,
        }
    }

    fn plan(assertions: Vec<CanaryAssertion>) -> CanaryPlan {
        CanaryPlan {
            schema_version: CANARY_PLAN_SCHEMA_VERSION.to_owned(),
            plan_id: "boundary-controls".to_owned(),
            assertions,
        }
    }

    fn observation(
        assertion_id: &str,
        phase: CanaryPhase,
        outcome: CanaryOutcome,
    ) -> CanaryObservation {
        let log = evidence_log();
        let evidence_index = usize::from(phase == CanaryPhase::IsolatedCandidate);
        CanaryObservation {
            assertion_id: assertion_id.to_owned(),
            phase,
            outcome,
            native_error_code: (outcome == CanaryOutcome::AccessDenied).then_some(5),
            evidence_ids: vec![log.records()[evidence_index].hash.clone()],
        }
    }

    fn observation_set(observations: Vec<CanaryObservation>) -> CanaryObservationSet {
        CanaryObservationSet {
            schema_version: CANARY_OBSERVATION_SET_SCHEMA_VERSION.to_owned(),
            plan_id: "boundary-controls".to_owned(),
            candidate_id: "process-container".to_owned(),
            observations,
        }
    }

    fn evaluate_fixture_canaries(
        plan: &CanaryPlan,
        observation_set: &CanaryObservationSet,
    ) -> Result<CanaryReport, CanaryEvaluationError> {
        let log = evidence_log();
        evaluate_canaries(plan, observation_set, log.records())
    }

    #[test]
    fn explicit_denial_with_baseline_control_passes() {
        let report = evaluate_fixture_canaries(
            &plan(vec![assertion("file-read", true)]),
            &observation_set(vec![
                observation(
                    "file-read",
                    CanaryPhase::BaselineControl,
                    CanaryOutcome::Succeeded,
                ),
                observation(
                    "file-read",
                    CanaryPhase::IsolatedCandidate,
                    CanaryOutcome::AccessDenied,
                ),
            ]),
        )
        .unwrap();

        assert_eq!(report.verdict, CanaryVerdict::Passed);
        assert!(report.evidence_chain_verified);
        assert_eq!(
            report.evidence_root_hash,
            evidence_log().manifest().unwrap().root_hash
        );
        assert_eq!(report.passed_required_count, 1);
        assert_eq!(report.results[0].reason, CanaryReason::VerifiedDenial);
    }

    #[test]
    fn successful_candidate_access_is_a_failure() {
        let report = evaluate_fixture_canaries(
            &plan(vec![assertion("file-read", true)]),
            &observation_set(vec![
                observation(
                    "file-read",
                    CanaryPhase::BaselineControl,
                    CanaryOutcome::Succeeded,
                ),
                observation(
                    "file-read",
                    CanaryPhase::IsolatedCandidate,
                    CanaryOutcome::Succeeded,
                ),
            ]),
        )
        .unwrap();

        assert_eq!(report.verdict, CanaryVerdict::Failed);
        assert_eq!(report.results[0].reason, CanaryReason::IsolationGap);
    }

    #[test]
    fn generic_failure_is_not_misreported_as_denial() {
        let report = evaluate_fixture_canaries(
            &plan(vec![assertion("network", true)]),
            &observation_set(vec![
                observation(
                    "network",
                    CanaryPhase::BaselineControl,
                    CanaryOutcome::Succeeded,
                ),
                observation(
                    "network",
                    CanaryPhase::IsolatedCandidate,
                    CanaryOutcome::NetworkUnreachable,
                ),
            ]),
        )
        .unwrap();

        assert_eq!(report.verdict, CanaryVerdict::Indeterminate);
        assert_eq!(
            report.results[0].reason,
            CanaryReason::CandidateObservationUnavailable
        );
    }

    #[test]
    fn failed_baseline_control_is_indeterminate() {
        let report = evaluate_fixture_canaries(
            &plan(vec![assertion("file-read", true)]),
            &observation_set(vec![
                observation(
                    "file-read",
                    CanaryPhase::BaselineControl,
                    CanaryOutcome::NotFound,
                ),
                observation(
                    "file-read",
                    CanaryPhase::IsolatedCandidate,
                    CanaryOutcome::AccessDenied,
                ),
            ]),
        )
        .unwrap();

        assert_eq!(report.verdict, CanaryVerdict::Indeterminate);
        assert_eq!(
            report.results[0].reason,
            CanaryReason::BaselineControlNotProven
        );
    }

    #[test]
    fn missing_evidence_is_indeterminate() {
        let mut candidate = observation(
            "file-read",
            CanaryPhase::IsolatedCandidate,
            CanaryOutcome::AccessDenied,
        );
        candidate.evidence_ids.clear();
        let report = evaluate_fixture_canaries(
            &plan(vec![assertion("file-read", true)]),
            &observation_set(vec![
                observation(
                    "file-read",
                    CanaryPhase::BaselineControl,
                    CanaryOutcome::Succeeded,
                ),
                candidate,
            ]),
        )
        .unwrap();

        assert_eq!(report.verdict, CanaryVerdict::Indeterminate);
        assert_eq!(report.results[0].reason, CanaryReason::MissingEvidence);
    }

    #[test]
    fn denial_without_native_error_is_indeterminate() {
        let mut candidate = observation(
            "file-read",
            CanaryPhase::IsolatedCandidate,
            CanaryOutcome::AccessDenied,
        );
        candidate.native_error_code = None;
        let report = evaluate_fixture_canaries(
            &plan(vec![assertion("file-read", true)]),
            &observation_set(vec![
                observation(
                    "file-read",
                    CanaryPhase::BaselineControl,
                    CanaryOutcome::Succeeded,
                ),
                candidate,
            ]),
        )
        .unwrap();

        assert_eq!(report.verdict, CanaryVerdict::Indeterminate);
        assert_eq!(
            report.results[0].reason,
            CanaryReason::MissingNativeErrorCode
        );
    }

    #[test]
    fn optional_failure_does_not_fail_required_verdict() {
        let report = evaluate_fixture_canaries(
            &plan(vec![
                assertion("required-file", true),
                assertion("optional-file", false),
            ]),
            &observation_set(vec![
                observation(
                    "required-file",
                    CanaryPhase::BaselineControl,
                    CanaryOutcome::Succeeded,
                ),
                observation(
                    "required-file",
                    CanaryPhase::IsolatedCandidate,
                    CanaryOutcome::AccessDenied,
                ),
                observation(
                    "optional-file",
                    CanaryPhase::BaselineControl,
                    CanaryOutcome::Succeeded,
                ),
                observation(
                    "optional-file",
                    CanaryPhase::IsolatedCandidate,
                    CanaryOutcome::Succeeded,
                ),
            ]),
        )
        .unwrap();

        assert_eq!(report.verdict, CanaryVerdict::Passed);
        assert_eq!(report.failed_required_count, 0);
    }

    #[test]
    fn duplicate_observations_are_rejected() {
        let duplicate = observation(
            "file-read",
            CanaryPhase::BaselineControl,
            CanaryOutcome::Succeeded,
        );
        let error = evaluate_fixture_canaries(
            &plan(vec![assertion("file-read", true)]),
            &observation_set(vec![duplicate.clone(), duplicate]),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            CanaryEvaluationError::DuplicateObservation { .. }
        ));
    }

    #[test]
    fn invented_evidence_reference_is_rejected() {
        let mut candidate = observation(
            "file-read",
            CanaryPhase::IsolatedCandidate,
            CanaryOutcome::AccessDenied,
        );
        candidate.evidence_ids = vec!["0".repeat(64)];
        let error = evaluate_fixture_canaries(
            &plan(vec![assertion("file-read", true)]),
            &observation_set(vec![
                observation(
                    "file-read",
                    CanaryPhase::BaselineControl,
                    CanaryOutcome::Succeeded,
                ),
                candidate,
            ]),
        )
        .unwrap_err();

        assert!(matches!(error, CanaryEvaluationError::UnknownEvidenceId(_)));
    }

    #[test]
    fn results_are_sorted_independent_of_plan_order() {
        let report = evaluate_fixture_canaries(
            &plan(vec![assertion("z-file", true), assertion("a-file", true)]),
            &observation_set(vec![]),
        )
        .unwrap();
        assert_eq!(report.results[0].assertion_id, "a-file");
        assert_eq!(report.results[1].assertion_id, "z-file");
    }
}
