//! Pure admission and safe projection of bound native observations. This is not
//! host attestation: original evidence custody, approval and trustworthy native
//! collection remain prerequisites enforced outside this function.
use std::collections::BTreeMap;

use aiw_probe::WindowsFileIdentity;
use aiw_token::{ElevationType, IntegrityLevel, TokenEvidence, TokenType};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    StandardUserRuntimeContext,
    assessment::{
        ASSESSMENT_SCOPE, AssessmentAssertionTarget, AssessmentMode, CompiledAssessmentStep,
    },
    assessment_observation::{
        APPLICATION_ASSESSMENT_RESULT_SCHEMA, ApplicationAssessmentResult, AssessmentCapture,
        AssessmentCollectorTarget, AssessmentFileObservation, AssessmentImageObservation,
        AssessmentProcessObservation,
    },
    assessment_request::ApplicationAssessmentGuestRequest,
};

pub const ASSESSMENT_NATIVE_OBSERVATION_SCHEMA: &str =
    "aiw.dev/assessment-native-observation/v0alpha1";
pub const VERIFIED_ASSESSMENT_EVIDENCE_SCHEMA: &str =
    "aiw.dev/verified-assessment-evidence/v0alpha1";
pub const VERIFIED_ASSESSMENT_SCOPE: &str = "Only the declared portable CLI workflow and reported elevated-collector/standard-user root-process, capture, work-file and cleanup facts. No general compatibility, isolation, descendants, DLL/memory, brokers, network-denial, loaded-memory or host-coverage verdict; this is bound native evidence, not host attestation.";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentEvidenceStatus {
    NotRun,
    DriverIncomplete,
    WorkflowFailed,
    WorkflowPassed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentFactStatus {
    NotRun,
    Unmeasured,
    Failed,
    Passed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentStepKind {
    StagePortable,
    Launch,
    ExpectExitCode,
    ObserveFile,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentCoverageGap {
    IncompleteSteps,
    IncompleteAssertions,
    CaptureIncomplete,
    RootPolicyUnmeasured,
    WindowsUnmeasured,
    ApplicationJobCleanupUnmeasured,
    CollectorWriteDenialUnmeasured,
    CollectorUnimpersonatedUnmeasured,
    DescendantsUnmeasured,
    NetworkDenialUnmeasured,
    CleanupUnmeasured,
    IncompleteMeasurements,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedAssessmentStep {
    pub index: usize,
    pub kind: AssessmentStepKind,
    pub status: AssessmentFactStatus,
    pub exit_code: Option<u32>,
    pub timed_out: Option<bool>,
    pub root_policy: AssessmentFactStatus,
    pub stdout_complete: Option<bool>,
    pub stderr_complete: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedAssessmentAssertion {
    /// Index into the approved assertion list; caller IDs/free text are omitted.
    pub index: usize,
    pub status: AssessmentFactStatus,
    pub actual_sha256: Option<String>,
    pub actual_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedAssessmentCleanup {
    pub status: AssessmentFactStatus,
    pub application_jobs_empty: Option<bool>,
    pub environment_destroyed: Option<bool>,
    pub profile_unloaded: Option<bool>,
    pub account_deleted: Option<bool>,
    /// None for ordinary mode, which creates no AppContainer profile.
    pub appcontainer_profile_deleted: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedAssessmentCoverage {
    pub planned_steps: usize,
    pub retained_steps: usize,
    pub process_records: usize,
    pub complete_captures: usize,
    pub measured_root_policies: usize,
    pub collector_write_denied: Option<bool>,
    pub collector_unimpersonated: Option<bool>,
    pub windows_observed: bool,
    pub gaps: Vec<AssessmentCoverageGap>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedAssessmentEvidence {
    pub schema_version: String,
    pub scope: String,
    pub semantic_sha256: String,
    pub mode: AssessmentMode,
    pub status: AssessmentEvidenceStatus,
    pub workflow_status: AssessmentFactStatus,
    pub driver_complete: bool,
    pub steps: Vec<VerifiedAssessmentStep>,
    pub assertions: Vec<VerifiedAssessmentAssertion>,
    pub coverage: VerifiedAssessmentCoverage,
    pub cleanup: VerifiedAssessmentCleanup,
}

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn bounded(value: &str, chars: usize, bytes: usize) -> bool {
    value.len() <= bytes && value.chars().count() <= chars && !value.contains('\0')
}
fn error(value: &Option<String>) -> Result<(), String> {
    if let Some(v) = value {
        require(
            !v.is_empty() && bounded(v, 1024, 4096),
            "diagnostic string exceeds bounds or is empty",
        )?;
    }
    Ok(())
}
fn errors(values: &[String]) -> Result<(), String> {
    require(values.len() <= 64, "too many diagnostic strings")?;
    for v in values {
        error(&Some(v.clone()))?;
    }
    Ok(())
}
fn lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn nonzero_hex(value: &str, width: usize) -> bool {
    lower_hex(value, width) && value.bytes().any(|b| b != b'0')
}
fn canonical_birth(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n != 0 && n.to_string() == value)
}
fn sid(value: &str) -> bool {
    if !bounded(value, 184, 184) {
        return false;
    }
    let parts: Vec<_> = value.split('-').collect();
    parts.len() >= 4
        && parts.len() <= 18
        && parts[0] == "S"
        && parts[1] == "1"
        && parts[2]
            .parse::<u64>()
            .ok()
            .is_some_and(|n| n < (1_u64 << 48) && n.to_string() == parts[2])
        && parts[3..]
            .iter()
            .all(|s| s.parse::<u32>().ok().is_some_and(|n| n.to_string() == *s))
}
fn token_shape(token: &TokenEvidence) -> Result<(), String> {
    require(
        token.schema_version == aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
            && token.process_id != 0
            && sid(&token.user_sid)
            && token.integrity.sid == format!("S-1-16-{}", token.integrity.rid)
            && token.integrity.level == aiw_token::classify_integrity_rid(token.integrity.rid)
            && token.is_app_container == token.app_container_sid.is_some()
            && token.app_container_sid.as_deref().is_none_or(sid)
            && token.capabilities.len() <= 64
            && match token.token_type {
                TokenType::Primary => token.impersonation_level.is_none(),
                TokenType::Impersonation => token.impersonation_level.is_some(),
            },
        "malformed token observation",
    )?;
    for capability in &token.capabilities {
        require(sid(&capability.sid), "malformed capability SID")?;
    }
    Ok(())
}
fn identity(value: &WindowsFileIdentity, expected: &str) -> Result<(), String> {
    let path = value
        .final_path
        .strip_prefix(r"\\?\")
        .unwrap_or(&value.final_path);
    require(
        bounded(&value.final_path, 1024, 2048)
            && path.eq_ignore_ascii_case(expected)
            && nonzero_hex(&value.volume_serial_number, 16)
            && nonzero_hex(&value.file_id, 32),
        "held file identity/path is invalid",
    )
}
fn image_path(path: &str) -> String {
    format!(r"C:\AIW\Assessment\App\{}", path.replace('/', r"\"))
}
fn work_path(path: &str) -> String {
    format!(r"C:\AIW\Assessment\Work\{}", path.replace('/', r"\"))
}

fn capture(value: &AssessmentCapture, limit: u64) -> Result<bool, String> {
    error(&value.read_error)?;
    require(
        value.limit_bytes == limit
            && limit <= 16 * 1024 * 1024
            && value.size_bytes <= limit
            && value.bytes_hex.len() as u64 == value.size_bytes * 2
            && lower_hex(&value.sha256, 64)
            && value
                .bytes_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "capture shape, limit or hex domain is invalid",
    )?;
    let bytes = hex::decode(&value.bytes_hex).map_err(|_| "capture hex is invalid")?;
    require(
        hex::encode(Sha256::digest(&bytes)) == value.sha256,
        "capture digest differs from retained raw bytes",
    )?;
    require(
        !value.overflowed || value.size_bytes == limit,
        "overflowed capture is not a full retained prefix",
    )?;
    require(
        !value.complete || (!value.overflowed && value.read_error.is_none()),
        "capture completion contradicts error/overflow",
    )?;
    Ok(value.complete && !value.overflowed && value.read_error.is_none())
}

fn image(
    value: &AssessmentImageObservation,
    path: &str,
    hash: &str,
    size: u64,
) -> Result<bool, String> {
    identity(&value.identity, &image_path(path))?;
    require(
        value.sha256 == hash && value.size_bytes == size,
        "prelaunch image does not match the reviewed code",
    )?;
    error(&value.architecture_error)?;
    for item in [&value.machine, &value.optional_header_magic]
        .into_iter()
        .flatten()
    {
        require(
            item.len() == 6 && item.starts_with("0x") && lower_hex(&item[2..], 4),
            "PE observation has invalid numeric encoding",
        )?;
    }
    Ok(value.machine.as_deref() == Some("0x8664")
        && value.optional_header_magic.as_deref() == Some("0x020b")
        && value.architecture_error.is_none())
}

fn root_policy(
    value: &AssessmentProcessObservation,
    context: Option<&StandardUserRuntimeContext>,
    mode: AssessmentMode,
    profile_sid: Option<&str>,
) -> AssessmentFactStatus {
    let (Some(token), Some(context)) = (&value.held_token, context) else {
        return AssessmentFactStatus::Unmeasured;
    };
    let primary = token.process_id == value.process_id
        && token.user_sid == context.user_sid
        && token.token_type == TokenType::Primary
        && token.impersonation_level.is_none()
        && !token.is_elevated
        && token.elevation_type == ElevationType::Default;
    let correct = primary
        && match mode {
            AssessmentMode::Ordinary => context.validate_token(token).is_ok(),
            AssessmentMode::ClassicAppContainer => {
                token.is_app_container
                    && profile_sid.is_some()
                    && token.app_container_sid.as_deref() == profile_sid
                    && token.capabilities.is_empty()
                    && token.integrity.rid == 4096
                    && token.integrity.level == IntegrityLevel::Low
                    && token.integrity.sid == "S-1-16-4096"
            }
        };
    if correct {
        AssessmentFactStatus::Passed
    } else {
        AssessmentFactStatus::Failed
    }
}

fn file(value: &AssessmentFileObservation, path: &str, limit: u64) -> Result<(), String> {
    identity(&value.identity, &work_path(path))?;
    require(
        value.relative_path == path && value.size_bytes <= limit && lower_hex(&value.sha256, 64),
        "work file does not match the declared observation",
    )
}
fn kind(step: &CompiledAssessmentStep) -> (AssessmentStepKind, &'static str) {
    match step {
        CompiledAssessmentStep::StagePortable => {
            (AssessmentStepKind::StagePortable, "stagePortable")
        }
        CompiledAssessmentStep::Launch { .. } => (AssessmentStepKind::Launch, "launch"),
        CompiledAssessmentStep::ExpectExitCode { .. } => {
            (AssessmentStepKind::ExpectExitCode, "expectExitCode")
        }
        CompiledAssessmentStep::ObserveFile { .. } => {
            (AssessmentStepKind::ObserveFile, "observeFile")
        }
    }
}

/// Each right is independent: denying GENERIC_WRITE alone would not prove
/// FILE_WRITE_DATA denied. A wrong principal or another Win32 failure is unknown.
fn collector_denial(
    native: &crate::assessment_observation::AssessmentNativeOutcome,
) -> Result<Option<bool>, String> {
    use AssessmentCollectorTarget::{Directory, ProgressFile};
    let required = [
        (Directory, 2),
        (Directory, 4),
        (Directory, 0x40),
        (Directory, 0x10000),
        (Directory, 0x10),
        (Directory, 0x100),
        (Directory, 0x40000),
        (Directory, 0x80000),
        (ProgressFile, 2),
        (ProgressFile, 4),
        (ProgressFile, 0x10),
        (ProgressFile, 0x100),
        (ProgressFile, 0x10000),
        (ProgressFile, 0x40000),
        (ProgressFile, 0x80000),
    ];
    require(
        native.collector_access_denials.len() <= required.len(),
        "collector access probe count exceeds the closed table",
    )?;
    let mut all_denied = native.collector_access_denials.len() == required.len();
    let mut allowed = false;
    for (observed, (target, mask)) in native.collector_access_denials.iter().zip(required) {
        require(
            observed.target == target && observed.access_mask == mask,
            "collector access probe target/right/order differs",
        )?;
        error(&observed.error)?;
        require(
            (observed.effective_user_sid.is_empty() && observed.error.is_some())
                || sid(&observed.effective_user_sid),
            "collector probe effective SID is malformed",
        )?;
        if observed.error.is_some() {
            require(
                observed.denied.is_none(),
                "failed probe claims completed denial/access facts",
            )?;
        } else {
            require(
                matches!(
                    (observed.native_code, observed.denied),
                    (Some(5), Some(true)) | (Some(0), Some(false))
                ),
                "collector denial must be native code5, or observed successful access code0",
            )?;
        }
        let actor = native
            .standard_context
            .as_ref()
            .is_some_and(|c| c.user_sid == observed.effective_user_sid);
        all_denied &= actor
            && observed.error.is_none()
            && observed.native_code == Some(5)
            && observed.denied == Some(true);
        allowed |= actor
            && observed.error.is_none()
            && observed.native_code == Some(0)
            && observed.denied == Some(false);
    }
    let derived = if allowed {
        Some(false)
    } else if all_denied {
        Some(true)
    } else {
        None
    };
    if let Some(claimed) = native.collector_write_denied {
        require(
            derived == Some(claimed),
            "collector-write summary contradicts the effective-user per-right native probes",
        )?;
    }
    Ok(derived)
}

/// Verify typed facts after retained evidence/approved-request custody admission.
/// Optional failed measurements remain unmeasured; contradictions are refused.
pub fn verify_assessment_result(
    request: &ApplicationAssessmentGuestRequest,
    result: &ApplicationAssessmentResult,
) -> Result<VerifiedAssessmentEvidence, String> {
    use AssessmentFactStatus as F;
    request.validate()?;
    let serialized = serde_json::to_vec(result).map_err(|e| e.to_string())?;
    require(
        serialized.len() <= 16 * 1024 * 1024,
        "complete assessment evidence exceeds 16 MiB",
    )?;
    let plan = &request.assessment;
    let native = &result.native;
    require(
        result.schema_version == APPLICATION_ASSESSMENT_RESULT_SCHEMA
            && result.run_id == request.run_id
            && result.request_sha256 == request.request_sha256
            && result.assessment_sha256 == request.assessment_sha256
            && native.schema_version == ASSESSMENT_NATIVE_OBSERVATION_SCHEMA
            && native.semantic_sha256 == plan.semantic_sha256
            && native.mode == plan.mode
            && native.scope == ASSESSMENT_SCOPE,
        "result schema or reviewed execution binding differs",
    )?;
    require(
        native.steps.len() <= plan.steps.len()
            && native.steps.len() <= 64
            && native.assertions.len() <= plan.settings.assertions.len()
            && native.assertions.len() <= 128,
        "retained operation/assertion prefix exceeds plan",
    )?;
    errors(&native.driver_errors)?;
    errors(&native.account_cleanup.errors)?;
    error(&native.windows_error)?;
    if let Some(windows) = &native.windows {
        windows.validate()?;
        require(
            native.windows_error.is_none(),
            "Windows facts and failed observation conflict",
        )?;
    }
    if let Some(context) = &native.standard_context {
        context.validate()?;
    }
    let collector_write_denied = collector_denial(native)?;
    if let Some(token) = &native.setup_token {
        token_shape(token)?;
    }
    require(
        plan.mode != AssessmentMode::Ordinary
            || (native.profile_cleanup.is_none() && native.profile_sid.is_none()),
        "ordinary mode claims an AppContainer profile",
    )?;
    if let Some(profile) = &native.profile_sid {
        require(
            sid(profile) && profile.starts_with("S-1-15-2-") && profile.split('-').count() == 11,
            "created profile SID is malformed",
        )?;
    }
    // A fresh CreateAppContainerProfile can succeed and be deleted during error
    // cleanup before SID-to-text conversion succeeds. Retain that raw no-app
    // failure, but never project successful identity-bound profile cleanup.
    let unbound_profile_failure = plan.mode == AssessmentMode::ClassicAppContainer
        && !native.driver_completed
        && !native.driver_errors.is_empty()
        && native.steps.is_empty()
        && native.assertions.is_empty();
    require(
        native.profile_cleanup.is_none() || native.profile_sid.is_some() || unbound_profile_failure,
        "profile cleanup has no independently retained created-profile identity",
    )?;
    let setup_ok = native.setup_token.as_ref().is_some_and(|t| {
        t.user_sid.starts_with("S-1-5-21-")
            && t.user_sid.ends_with("-504")
            && t.token_type == TokenType::Primary
            && t.impersonation_level.is_none()
            && t.is_elevated
            && !t.is_app_container
            && t.app_container_sid.is_none()
            && t.capabilities.is_empty()
            && t.integrity.rid == 12288
            && t.integrity.level == IntegrityLevel::High
    });
    let context_ok = native.standard_context.as_ref().is_some_and(|context| {
        native.setup_token.as_ref().is_some_and(|setup| {
            setup.user_sid != context.user_sid
                && setup.user_sid.rsplit_once('-').map(|v| v.0)
                    == context.user_sid.rsplit_once('-').map(|v| v.0)
        })
    });
    let mut rows = Vec::new();
    let mut complete_captures = 0;
    let mut process_records = 0;
    let mut root_count = 0;
    let mut births: BTreeMap<u32, u64> = BTreeMap::new();
    let mut package: Option<&str> = None;
    let mut operations_complete = true;
    let mut capture_incomplete = false;
    for (index, row) in native.steps.iter().enumerate() {
        let expected = &plan.steps[index];
        let (step_kind, wire_kind) = kind(expected);
        require(
            row.index == index && row.kind == wire_kind,
            "step prefix index or kind differs from reviewed operation",
        )?;
        error(&row.error)?;
        require(
            row.error.is_none() || index + 1 == native.steps.len(),
            "a later step follows a failed operation",
        )?;
        let mut projected = VerifiedAssessmentStep {
            index,
            kind: step_kind,
            status: F::Unmeasured,
            exit_code: None,
            timed_out: None,
            root_policy: F::NotRun,
            stdout_complete: None,
            stderr_complete: None,
        };
        match expected {
            CompiledAssessmentStep::StagePortable => {
                require(
                    row.process.is_none()
                        && row.image.is_none()
                        && row.file.is_none()
                        && row.file_exists.is_none()
                        && row.assertion_passed.is_none(),
                    "stage row contains facts from another operation",
                )?;
                projected.status = if row.error.is_none() {
                    F::Passed
                } else {
                    F::Unmeasured
                };
            }
            CompiledAssessmentStep::Launch {
                path,
                sha256,
                size_bytes,
                ..
            } => {
                require(
                    row.file.is_none()
                        && row.file_exists.is_none()
                        && row.assertion_passed.is_none(),
                    "launch row contains unrelated file/assertion facts",
                )?;
                let image_ok = if let Some(observed) = &row.image {
                    image(observed, path, sha256, *size_bytes)?
                } else {
                    false
                };
                if let Some(process) = &row.process {
                    process_records += 1;
                    require(
                        collector_write_denied == Some(true)
                            && native.collector_unimpersonated == Some(true)
                            && setup_ok
                            && context_ok,
                        "application process exists without the mandatory collector-write-denial gate",
                    )?;
                    require(process.process_id != 0, "zero target PID")?;
                    errors(&process.errors)?;
                    let observed = row
                        .image
                        .as_ref()
                        .ok_or("process has no independently held prelaunch image fact")?;
                    require(
                        image_ok
                            && process.image_identity == observed.identity
                            && process.image_sha256 == *sha256
                            && process.image_size_bytes == *size_bytes
                            && process.image_machine == "amd64-pe32plus",
                        "process image/PE facts contradict prelaunch held code",
                    )?;
                    if let Some(token) = &process.held_token {
                        token_shape(token)?;
                        require(
                            token.process_id == process.process_id,
                            "held target token belongs to a different PID",
                        )?;
                    }
                    let birth = process
                        .creation_time_100ns
                        .as_deref()
                        .map(|s| {
                            canonical_birth(s)
                                .ok_or("root birth is not canonical nonzero u64 FILETIME")
                        })
                        .transpose()?;
                    let lifetime_ok = if let Some(birth) = birth {
                        let old = births.insert(process.process_id, birth);
                        old.is_none_or(|old| birth > old)
                    } else {
                        false
                    };
                    require(
                        lifetime_ok || birth.is_none(),
                        "numeric PID reuse has duplicate or decreasing creation time",
                    )?;
                    require(
                        native
                            .setup_token
                            .as_ref()
                            .is_none_or(|t| t.process_id != process.process_id),
                        "target aliases the live elevated collector PID",
                    )?;
                    let out = capture(&process.stdout, plan.settings.stdout_max_bytes)?;
                    let err = capture(&process.stderr, plan.settings.stderr_max_bytes)?;
                    complete_captures += usize::from(out) + usize::from(err);
                    capture_incomplete |= !out || !err;
                    let measured_policy = root_policy(
                        process,
                        native.standard_context.as_ref(),
                        plan.mode,
                        native.profile_sid.as_deref(),
                    );
                    let policy = if measured_policy == F::Passed
                        && !(lifetime_ok && setup_ok && context_ok)
                    {
                        F::Unmeasured
                    } else {
                        measured_policy
                    };
                    if policy == F::Passed {
                        root_count += 1;
                    }
                    if plan.mode == AssessmentMode::ClassicAppContainer
                        && let Some(sid) = process
                            .held_token
                            .as_ref()
                            .and_then(|t| t.app_container_sid.as_deref())
                    {
                        require(
                            package.is_none_or(|prior| prior == sid),
                            "classic roots report different package SIDs",
                        )?;
                        package = Some(sid);
                    }
                    projected.exit_code = process.exit_code;
                    projected.timed_out = Some(process.timed_out);
                    projected.root_policy = policy;
                    projected.stdout_complete = Some(out);
                    projected.stderr_complete = Some(err);
                    if image_ok
                        && lifetime_ok
                        && setup_ok
                        && context_ok
                        && policy == F::Passed
                        && process.exit_code.is_some()
                        && !process.timed_out
                        && process.job_empty == Some(true)
                        && out
                        && err
                        && process.errors.is_empty()
                        && row.error.is_none()
                    {
                        projected.status = F::Passed;
                    }
                }
            }
            CompiledAssessmentStep::ExpectExitCode { launch_step, value } => {
                require(
                    row.process.is_none()
                        && row.image.is_none()
                        && row.file.is_none()
                        && row.file_exists.is_none(),
                    "exit expectation contains unrelated process/file facts",
                )?;
                let process = native
                    .steps
                    .get(*launch_step)
                    .and_then(|s| s.process.as_ref());
                let actual = process.and_then(|p| p.exit_code.map(|exit| (exit, p.timed_out)));
                let measured = actual
                    .filter(|(_, timed)| !*timed)
                    .map(|(exit, _)| exit == *value as u32);
                if let Some(claimed) = row.assertion_passed {
                    require(
                        measured.is_none_or(|actual| actual == claimed),
                        "reported exit assertion contradicts the actual root exit",
                    )?;
                    require(
                        !claimed || measured == Some(true),
                        "exit assertion passes without measured exit",
                    )?;
                }
                projected.status = match measured {
                    Some(true) => F::Passed,
                    Some(false) => F::Failed,
                    None => F::Unmeasured,
                };
                if row.error.is_some() {
                    projected.status = F::Unmeasured;
                }
            }
            CompiledAssessmentStep::ObserveFile { path } => {
                require(
                    row.process.is_none() && row.image.is_none() && row.assertion_passed.is_none(),
                    "file observation contains unrelated launch/assertion facts",
                )?;
                if let Some(observed) = &row.file {
                    file(observed, path, plan.settings.file_max_bytes)?;
                    require(
                        row.file_exists == Some(true),
                        "held file fact contradicts existence flag",
                    )?;
                }
                require(
                    row.file_exists != Some(true) || row.file.is_some(),
                    "existing file has no held file fact",
                )?;
                if row.error.is_none() {
                    projected.status = match row.file_exists {
                        Some(true) => F::Passed,
                        Some(false) => F::Failed,
                        None => F::Unmeasured,
                    };
                }
            }
        }
        operations_complete &= matches!(projected.status, F::Passed | F::Failed);
        rows.push(projected);
    }
    require(
        native.assertions.is_empty()
            || (native.steps.len() == plan.steps.len()
                && native.steps.iter().all(|s| s.error.is_none())),
        "assertions precede a complete operation prefix",
    )?;
    let mut assertions = Vec::new();
    for (index, expected) in plan.settings.assertions.iter().enumerate() {
        let observed = native.assertions.get(index);
        if let Some(fact) = observed {
            require(
                fact.id == expected.id,
                "assertion prefix differs from approved order/identity",
            )?;
            error(&fact.error)?;
            require(
                fact.actual_sha256.is_some() == fact.actual_size_bytes.is_some(),
                "assertion hash/size presence differs",
            )?;
            if let Some(h) = &fact.actual_sha256 {
                require(lower_hex(h, 64), "assertion hash is malformed")?;
            }
        }
        let (actual, known_absent) = match &expected.target {
            AssessmentAssertionTarget::Stdout { launch_step }
            | AssessmentAssertionTarget::Stderr { launch_step } => {
                let p = native
                    .steps
                    .get(*launch_step)
                    .and_then(|s| s.process.as_ref());
                let c = p.map(|p| {
                    if matches!(expected.target, AssessmentAssertionTarget::Stdout { .. }) {
                        &p.stdout
                    } else {
                        &p.stderr
                    }
                });
                (
                    c.filter(|c| c.complete && !c.overflowed && c.read_error.is_none())
                        .map(|c| (c.sha256.clone(), c.size_bytes)),
                    false,
                )
            }
            AssessmentAssertionTarget::WorkFile { path } => {
                let row=native.steps.iter().find(|row|matches!(&plan.steps[row.index],CompiledAssessmentStep::ObserveFile{path:p}if p==path));
                (
                    row.filter(|r| r.error.is_none())
                        .and_then(|r| r.file.as_ref())
                        .map(|f| (f.sha256.clone(), f.size_bytes)),
                    row.is_some_and(|r| r.error.is_none() && r.file_exists == Some(false)),
                )
            }
        };
        let status = if let Some(fact) = observed {
            if fact.error.is_some() {
                require(
                    fact.passed.is_none() && fact.actual_sha256.is_none(),
                    "failed assertion measurement claims completed facts",
                )?;
                F::Unmeasured
            } else if let Some((hash, size)) = &actual {
                require(
                    fact.actual_sha256.as_ref() == Some(hash)
                        && fact.actual_size_bytes == Some(*size),
                    "assertion does not match actual captured/held bytes",
                )?;
                let passed = expected.expected_sha256.as_ref().is_none_or(|h| h == hash)
                    && expected.expected_size_bytes.is_none_or(|n| n == *size);
                require(
                    fact.passed == Some(passed),
                    "assertion result contradicts independently recomputed expectation",
                )?;
                if passed { F::Passed } else { F::Failed }
            } else if known_absent {
                require(
                    fact.passed == Some(false) && fact.actual_sha256.is_none(),
                    "missing file asserted as present/passed",
                )?;
                F::Failed
            } else {
                require(
                    fact.passed.is_none() && fact.actual_sha256.is_none(),
                    "assertion claims unmeasured bytes",
                )?;
                F::Unmeasured
            }
        } else {
            F::NotRun
        };
        assertions.push(VerifiedAssessmentAssertion {
            index,
            status,
            actual_sha256: actual.as_ref().map(|v| v.0.clone()),
            actual_size_bytes: actual.as_ref().map(|v| v.1),
        });
    }
    let full = native.steps.len() == plan.steps.len()
        && native.assertions.len() == plan.settings.assertions.len();
    let assertion_complete = assertions
        .iter()
        .all(|a| matches!(a.status, F::Passed | F::Failed));
    let functional = full
        && operations_complete
        && assertion_complete
        && setup_ok
        && context_ok
        && collector_write_denied == Some(true)
        && native.collector_unimpersonated == Some(true);
    let workflow_status = if process_records == 0 {
        F::NotRun
    } else if functional {
        if rows.iter().any(|r| r.status == F::Failed)
            || assertions.iter().any(|a| a.status == F::Failed)
        {
            F::Failed
        } else {
            F::Passed
        }
    } else {
        F::Unmeasured
    };
    let driver_facts = full
        && operations_complete
        && assertion_complete
        && setup_ok
        && context_ok
        && collector_write_denied == Some(true)
        && native.collector_unimpersonated == Some(true)
        && native.driver_errors.is_empty();
    require(
        !native.driver_completed || driver_facts,
        "driver completion contradicts required operation/collector facts",
    )?;
    let driver_complete = native.driver_completed && driver_facts;
    let application_jobs_empty = if process_records == 0 {
        None
    } else if native
        .steps
        .iter()
        .filter_map(|s| s.process.as_ref())
        .any(|p| p.job_empty == Some(false))
    {
        Some(false)
    } else if native
        .steps
        .iter()
        .filter_map(|s| s.process.as_ref())
        .all(|p| p.job_empty == Some(true))
    {
        Some(true)
    } else {
        None
    };
    let cleanup_values = [
        application_jobs_empty,
        native.account_cleanup.environment_destroyed,
        native.account_cleanup.profile_unloaded,
        native.account_cleanup.account_deleted,
    ];
    let cleanup_status = if cleanup_values.contains(&Some(false))
        || native.profile_cleanup == Some(false)
        || !native.account_cleanup.errors.is_empty()
    {
        F::Failed
    } else if cleanup_values.iter().all(|v| *v == Some(true))
        && context_ok
        && setup_ok
        && (plan.mode == AssessmentMode::Ordinary || native.profile_cleanup == Some(true))
    {
        F::Passed
    } else {
        F::Unmeasured
    };
    let mut gaps = vec![
        AssessmentCoverageGap::DescendantsUnmeasured,
        AssessmentCoverageGap::NetworkDenialUnmeasured,
    ];
    if native.steps.len() != plan.steps.len() {
        gaps.push(AssessmentCoverageGap::IncompleteSteps);
    }
    if native.assertions.len() != plan.settings.assertions.len() {
        gaps.push(AssessmentCoverageGap::IncompleteAssertions);
    }
    if !operations_complete || !assertion_complete {
        gaps.push(AssessmentCoverageGap::IncompleteMeasurements);
    }
    if capture_incomplete {
        gaps.push(AssessmentCoverageGap::CaptureIncomplete);
    }
    if root_count != process_records || !setup_ok || !context_ok {
        gaps.push(AssessmentCoverageGap::RootPolicyUnmeasured);
    }
    if native.windows.is_none() {
        gaps.push(AssessmentCoverageGap::WindowsUnmeasured);
    }
    if application_jobs_empty.is_none() {
        gaps.push(AssessmentCoverageGap::ApplicationJobCleanupUnmeasured);
    }
    if collector_write_denied != Some(true) {
        gaps.push(AssessmentCoverageGap::CollectorWriteDenialUnmeasured);
    }
    if native.collector_unimpersonated != Some(true) {
        gaps.push(AssessmentCoverageGap::CollectorUnimpersonatedUnmeasured);
    }
    if cleanup_status == F::Unmeasured {
        gaps.push(AssessmentCoverageGap::CleanupUnmeasured);
    }
    let status = if process_records == 0 {
        AssessmentEvidenceStatus::NotRun
    } else if !driver_complete {
        AssessmentEvidenceStatus::DriverIncomplete
    } else if workflow_status == F::Failed {
        AssessmentEvidenceStatus::WorkflowFailed
    } else {
        AssessmentEvidenceStatus::WorkflowPassed
    };
    Ok(VerifiedAssessmentEvidence {
        schema_version: VERIFIED_ASSESSMENT_EVIDENCE_SCHEMA.into(),
        scope: VERIFIED_ASSESSMENT_SCOPE.into(),
        semantic_sha256: plan.semantic_sha256.clone(),
        mode: plan.mode,
        status,
        workflow_status,
        driver_complete,
        steps: rows,
        assertions,
        coverage: VerifiedAssessmentCoverage {
            planned_steps: plan.steps.len(),
            retained_steps: native.steps.len(),
            process_records,
            complete_captures,
            measured_root_policies: root_count,
            collector_write_denied,
            collector_unimpersonated: native.collector_unimpersonated,
            windows_observed: native.windows.is_some(),
            gaps,
        },
        cleanup: VerifiedAssessmentCleanup {
            status: cleanup_status,
            application_jobs_empty,
            environment_destroyed: native.account_cleanup.environment_destroyed,
            profile_unloaded: native.account_cleanup.profile_unloaded,
            account_deleted: native.account_cleanup.account_deleted,
            appcontainer_profile_deleted: native.profile_sid.as_ref().and(native.profile_cleanup),
        },
    })
}

pub const APPLICATION_ASSESSMENT_EVIDENCE_EVENT: &str = "applicationAssessmentResult";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentResultReference {
    pub run_id: String,
    pub request_sha256: String,
    pub assessment_sha256: String,
    pub result_sha256: String,
}

/// A hash reference keeps captured application bytes out of the bounded log.
pub fn assessment_result_reference(
    request: &ApplicationAssessmentGuestRequest,
    result: &ApplicationAssessmentResult,
) -> Result<AssessmentResultReference, String> {
    request.validate()?;
    require(
        result.run_id == request.run_id
            && result.request_sha256 == request.request_sha256
            && result.assessment_sha256 == request.assessment_sha256,
        "result reference execution binding differs",
    )?;
    Ok(AssessmentResultReference {
        run_id: request.run_id.clone(),
        request_sha256: request.request_sha256.clone(),
        assessment_sha256: request.assessment_sha256.clone(),
        result_sha256: crate::assessment_request::assessment_value_sha256(result)?,
    })
}

pub fn verify_assessment_evidence(
    bytes: &[u8],
    expected_root: &str,
    request: &ApplicationAssessmentGuestRequest,
    result: &ApplicationAssessmentResult,
) -> Result<VerifiedAssessmentEvidence, String> {
    require(
        bytes.len() <= 1024 * 1024 && lower_hex(expected_root, 64),
        "evidence log/root exceeds contract",
    )?;
    let records = crate::application_token::verified_application_records(bytes, expected_root)?;
    require(
        records.len() == 1,
        "assessment evidence requires exactly one result-reference event",
    )?;
    let record = &records[0];
    require(
        record.kind == APPLICATION_ASSESSMENT_EVIDENCE_EVENT && record.source == "aiw-guest-agent",
        "assessment evidence event/source differs",
    )?;
    let reference: AssessmentResultReference =
        serde_json::from_value(record.payload.clone()).map_err(|e| e.to_string())?;
    require(
        reference == assessment_result_reference(request, result)?,
        "evidence reference differs from actual full result",
    )?;
    verify_assessment_result(request, result)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentStartedProcess {
    pub index: usize,
    pub process: AssessmentProcessObservation,
}

/// Diagnostic reconstruction only until a complete terminal is independently
/// matched to the final result. A pending start is NOT proof user code resumed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentProgressPrefix {
    pub result: ApplicationAssessmentResult,
    pub terminal_present: bool,
    pub trailing_incomplete: bool,
    pub records: usize,
    pub pending_launch: Option<AssessmentStartedProcess>,
}

fn same_process_origin(a: &AssessmentProcessObservation, b: &AssessmentProcessObservation) -> bool {
    a.process_id == b.process_id
        && a.creation_time_100ns == b.creation_time_100ns
        && a.held_token == b.held_token
        && a.image_identity == b.image_identity
        && a.image_sha256 == b.image_sha256
        && a.image_size_bytes == b.image_size_bytes
        && a.image_machine == b.image_machine
}

pub fn parse_assessment_progress(
    bytes: &[u8],
    request: &ApplicationAssessmentGuestRequest,
) -> Result<AssessmentProgressPrefix, String> {
    use crate::assessment_observation::{
        ASSESSMENT_PROGRESS_SCHEMA, AssessmentAccountCleanup, AssessmentNativeOutcome,
        AssessmentProgressEvent as E,
    };
    request.validate()?;
    require(
        !bytes.is_empty() && bytes.len() <= 16 * 1024 * 1024,
        "progress bytes exceed bound or are absent",
    )?;
    let plan = &request.assessment;
    let mut native = AssessmentNativeOutcome {
        schema_version: ASSESSMENT_NATIVE_OBSERVATION_SCHEMA.into(),
        semantic_sha256: plan.semantic_sha256.clone(),
        mode: plan.mode,
        windows: None,
        windows_error: None,
        setup_token: None,
        standard_context: None,
        steps: vec![],
        assertions: vec![],
        collector_write_denied: None,
        collector_access_denials: vec![],
        collector_unimpersonated: None,
        profile_sid: None,
        account_cleanup: AssessmentAccountCleanup::default(),
        profile_cleanup: None,
        driver_errors: vec![],
        driver_completed: false,
        scope: ASSESSMENT_SCOPE.into(),
    };
    let mut records = 0;
    let mut context_seen = 0;
    let mut terminal = false;
    let mut trailing = false;
    let mut pending: Option<AssessmentStartedProcess> = None;
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if !line.ends_with(b"\n") {
            require(
                line.len() <= 8 * 1024 * 1024,
                "incomplete progress line exceeds bound",
            )?;
            trailing = true;
            break;
        }
        require(!terminal, "progress record follows terminal")?;
        let line = &line[..line.len() - 1];
        require(
            !line.is_empty() && line.len() <= 8 * 1024 * 1024,
            "progress record length invalid",
        )?;
        records += 1;
        require(records <= 512, "too many progress records")?;
        let event: E = serde_json::from_slice(line)
            .map_err(|e| format!("strict progress record refused: {e}"))?;
        if records == 1 {
            require(
                matches!(&event, E::Header { .. }),
                "progress first record is not a bound header",
            )?;
        }
        match event {
            E::Header {
                schema_version,
                run_id,
                sandbox_id,
                request_sha256,
                assessment_sha256,
                agent_sha256,
                config_sha256,
                project_revision_sha256,
                collector_token,
            } => {
                require(
                    records == 1
                        && schema_version == ASSESSMENT_PROGRESS_SCHEMA
                        && run_id == request.run_id
                        && sandbox_id == request.sandbox_id
                        && request_sha256 == request.request_sha256
                        && assessment_sha256 == request.assessment_sha256
                        && agent_sha256 == request.agent_sha256
                        && config_sha256 == request.config_sha256
                        && project_revision_sha256 == request.project_revision_sha256,
                    "progress header execution binding differs",
                )?;
                token_shape(&collector_token)?;
                native.setup_token = Some(collector_token);
            }
            E::Context {
                windows,
                windows_error,
                standard_context,
            } => {
                require(
                    context_seen < 2
                        && native.collector_access_denials.is_empty()
                        && native.steps.is_empty()
                        && pending.is_none(),
                    "progress context duplicated or late",
                )?;
                if let Some(w) = &windows {
                    w.validate()?;
                }
                error(&windows_error)?;
                require(
                    windows.is_none() || windows_error.is_none(),
                    "progress Windows facts conflict",
                )?;
                if let Some(c) = &standard_context {
                    c.validate()?;
                }
                require(
                    (context_seen == 0 && standard_context.is_none())
                        || (context_seen == 1
                            && standard_context.is_some()
                            && native.standard_context.is_none()
                            && native.windows == windows
                            && native.windows_error == windows_error),
                    "context must transition only from environment-only to the same environment plus actual standard user",
                )?;
                context_seen += 1;
                native.windows = windows;
                native.windows_error = windows_error;
                native.standard_context = standard_context;
            }
            E::CollectorAccess { observation } => {
                require(
                    context_seen == 2 && native.steps.is_empty() && pending.is_none(),
                    "collector probe precedes standard context or follows application work",
                )?;
                native.collector_access_denials.push(observation);
                collector_denial(&native)?;
            }
            E::ProfileCreated { profile_sid } => {
                require(
                    context_seen == 2
                        && plan.mode == AssessmentMode::ClassicAppContainer
                        && native.profile_sid.is_none()
                        && pending.is_none()
                        && native.steps.iter().all(|s| s.process.is_none()),
                    "created profile identity duplicated, late or wrong mode",
                )?;
                require(
                    sid(&profile_sid)
                        && profile_sid.starts_with("S-1-15-2-")
                        && profile_sid.split('-').count() == 11,
                    "progress profile SID malformed",
                )?;
                native.profile_sid = Some(profile_sid);
            }
            E::LaunchStarted { index, process } => {
                require(
                    context_seen == 2
                        && pending.is_none()
                        && native.assertions.is_empty()
                        && index == native.steps.len(),
                    "launch creation record index/order differs",
                )?;
                let Some(CompiledAssessmentStep::Launch {
                    path,
                    sha256,
                    size_bytes,
                    ..
                }) = plan.steps.get(index)
                else {
                    return Err("creation record is not a reviewed launch".into());
                };
                identity(&process.image_identity, &image_path(path))?;
                require(
                    process.process_id != 0
                        && process.image_sha256 == *sha256
                        && process.image_size_bytes == *size_bytes
                        && process.image_machine == "amd64-pe32plus",
                    "creation record code binding differs",
                )?;
                require(
                    process.exit_code.is_none()
                        && process.job_empty.is_none()
                        && !process.timed_out,
                    "pre-Resume creation record claims completion",
                )?;
                require(
                    process.stdout.size_bytes == 0
                        && process.stderr.size_bytes == 0
                        && !process.stdout.complete
                        && !process.stderr.complete,
                    "pre-Resume creation record contains application output",
                )?;
                capture(&process.stdout, plan.settings.stdout_max_bytes)?;
                capture(&process.stderr, plan.settings.stderr_max_bytes)?;
                errors(&process.errors)?;
                if let Some(t) = &process.held_token {
                    token_shape(t)?;
                    require(
                        t.process_id == process.process_id,
                        "creation token PID differs",
                    )?;
                }
                if let Some(b) = &process.creation_time_100ns {
                    require(
                        canonical_birth(b).is_some(),
                        "creation record FILETIME malformed",
                    )?;
                }
                require(
                    collector_denial(&native)? == Some(true),
                    "creation record precedes mandatory complete access-denial gate",
                )?;
                pending = Some(AssessmentStartedProcess { index, process });
            }
            E::Step { observation } => {
                require(
                    context_seen == 2
                        && native.assertions.is_empty()
                        && observation.index == native.steps.len()
                        && native.steps.len() < 64,
                    "progress step prefix order invalid",
                )?;
                require(
                    plan.steps
                        .get(observation.index)
                        .is_some_and(|s| kind(s).1 == observation.kind),
                    "progress operation differs from approved plan",
                )?;
                if let Some(process) = &observation.process {
                    let created = pending
                        .take()
                        .ok_or("process completion lacks pre-Resume creation record")?;
                    require(
                        created.index == observation.index
                            && same_process_origin(&created.process, process)
                            && process.errors.starts_with(&created.process.errors),
                        "completed process differs from held creation lifetime/code/token",
                    )?;
                } else {
                    require(
                        pending.is_none(),
                        "operation discarded a known created process",
                    )?;
                }
                native.steps.push(*observation);
            }
            E::Assertion { observation } => {
                require(
                    pending.is_none()
                        && native.steps.len() == plan.steps.len()
                        && plan
                            .settings
                            .assertions
                            .get(native.assertions.len())
                            .is_some_and(|a| a.id == observation.id),
                    "progress assertion order or identity differs",
                )?;
                native.assertions.push(observation);
            }
            E::Terminal {
                collector_write_denied,
                collector_unimpersonated,
                profile_sid,
                profile_cleanup,
                account_cleanup,
                driver_completed,
                errors: driver_errors,
            } => {
                require(
                    pending.is_none() && profile_sid == native.profile_sid,
                    "terminal lost a pending root/profile identity",
                )?;
                native.collector_write_denied = collector_write_denied;
                native.collector_unimpersonated = collector_unimpersonated;
                native.profile_cleanup = profile_cleanup;
                native.account_cleanup = account_cleanup;
                native.driver_completed = driver_completed;
                native.driver_errors = driver_errors;
                errors(&native.driver_errors)?;
                errors(&native.account_cleanup.errors)?;
                collector_denial(&native)?;
                terminal = true;
            }
        }
    }
    require(
        records > 0 && native.setup_token.is_some(),
        "progress lacks a complete bound header",
    )?;
    if !terminal {
        native.driver_completed = false;
    }
    Ok(AssessmentProgressPrefix {
        result: ApplicationAssessmentResult {
            schema_version: APPLICATION_ASSESSMENT_RESULT_SCHEMA.into(),
            run_id: request.run_id.clone(),
            request_sha256: request.request_sha256.clone(),
            assessment_sha256: request.assessment_sha256.clone(),
            native,
        },
        terminal_present: terminal,
        trailing_incomplete: trailing,
        records,
        pending_launch: pending,
    })
}

pub fn verify_assessment_progress(
    bytes: &[u8],
    request: &ApplicationAssessmentGuestRequest,
    result: &ApplicationAssessmentResult,
) -> Result<AssessmentProgressPrefix, String> {
    let parsed = parse_assessment_progress(bytes, request)?;
    require(
        parsed.terminal_present && !parsed.trailing_incomplete && parsed.pending_launch.is_none(),
        "journal is only a diagnostic prefix; no final evidence credit",
    )?;
    require(
        parsed.result == *result,
        "complete journal facts differ from published typed result",
    )?;
    verify_assessment_result(request, result)?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::{AssessmentAssertion, AssessmentAssertionTarget, compile_assessment};
    use crate::assessment_observation::*;
    use aiw_token::IntegrityEvidence;

    fn token(pid: u32, high: bool, classic: bool) -> TokenEvidence {
        let rid = if high {
            12288
        } else if classic {
            4096
        } else {
            8192
        };
        TokenEvidence {
            schema_version: aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION.into(),
            process_id: pid,
            token_type: TokenType::Primary,
            impersonation_level: None,
            is_app_container: classic,
            app_container_sid: classic.then(|| "S-1-15-2-1-2-3-4-5-6-7".into()),
            user_sid: format!("S-1-5-21-100-200-300-{}", if high { 504 } else { 1001 }),
            integrity: IntegrityEvidence {
                sid: format!("S-1-16-{rid}"),
                rid,
                level: aiw_token::classify_integrity_rid(rid),
            },
            elevation_type: if high {
                ElevationType::Full
            } else {
                ElevationType::Default
            },
            is_elevated: high,
            capabilities: vec![],
            restricted_sid_count: 0,
        }
    }
    fn capture_bytes(bytes: &[u8], limit: u64) -> AssessmentCapture {
        AssessmentCapture {
            bytes_hex: hex::encode(bytes),
            sha256: hex::encode(Sha256::digest(bytes)),
            size_bytes: bytes.len() as u64,
            limit_bytes: limit,
            overflowed: false,
            complete: true,
            read_error: None,
        }
    }
    fn held(path: String) -> WindowsFileIdentity {
        WindowsFileIdentity {
            final_path: path,
            volume_serial_number: "0000000000000001".into(),
            file_id: "1".repeat(32),
        }
    }
    fn empty_step(index: usize, kind: &str) -> AssessmentStepObservation {
        AssessmentStepObservation {
            index,
            kind: kind.into(),
            process: None,
            image: None,
            file: None,
            file_exists: None,
            assertion_passed: None,
            error: None,
        }
    }
    fn denials() -> Vec<AssessmentCollectorAccessDenial> {
        use AssessmentCollectorTarget::{Directory, ProgressFile};
        [
            (Directory, 2),
            (Directory, 4),
            (Directory, 64),
            (Directory, 65536),
            (Directory, 16),
            (Directory, 256),
            (Directory, 262144),
            (Directory, 524288),
            (ProgressFile, 2),
            (ProgressFile, 4),
            (ProgressFile, 16),
            (ProgressFile, 256),
            (ProgressFile, 65536),
            (ProgressFile, 262144),
            (ProgressFile, 524288),
        ]
        .into_iter()
        .map(|(target, access_mask)| AssessmentCollectorAccessDenial {
            effective_user_sid: "S-1-5-21-100-200-300-1001".into(),
            target,
            access_mask,
            native_code: Some(5),
            denied: Some(true),
            error: None,
        })
        .collect()
    }
    fn request(classic: bool) -> ApplicationAssessmentGuestRequest {
        let (project, mut settings, manifest) = crate::assessment::tests::fixture();
        if classic {
            settings.candidate_id = "candidate".into();
        }
        ApplicationAssessmentGuestRequest::new(
            "synthetic-assessment".into(),
            "4a0f039f-4bb7-4d14-b1d8-4c9891bc44a3".into(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            compile_assessment(&project, &settings, &manifest).unwrap(),
        )
        .unwrap()
    }
    fn result(request: &ApplicationAssessmentGuestRequest) -> ApplicationAssessmentResult {
        let plan = &request.assessment;
        let classic = plan.mode == AssessmentMode::ClassicAppContainer;
        let CompiledAssessmentStep::Launch {
            path,
            sha256,
            size_bytes,
            ..
        } = &plan.steps[1]
        else {
            unreachable!()
        };
        let image = AssessmentImageObservation {
            identity: held(image_path(path)),
            sha256: sha256.clone(),
            size_bytes: *size_bytes,
            machine: Some("0x8664".into()),
            optional_header_magic: Some("0x020b".into()),
            architecture_error: None,
        };
        let mut launch = empty_step(1, "launch");
        launch.image = Some(image.clone());
        launch.process = Some(AssessmentProcessObservation {
            process_id: 77,
            creation_time_100ns: Some("133000000000000001".into()),
            held_token: Some(token(77, false, classic)),
            image_identity: image.identity.clone(),
            image_sha256: sha256.clone(),
            image_size_bytes: *size_bytes,
            image_machine: "amd64-pe32plus".into(),
            exit_code: Some(0),
            timed_out: false,
            job_empty: Some(true),
            stdout: capture_bytes(b"abc", plan.settings.stdout_max_bytes),
            stderr: capture_bytes(b"", plan.settings.stderr_max_bytes),
            errors: vec![],
        });
        let mut exit = empty_step(2, "expectExitCode");
        exit.assertion_passed = Some(true);
        ApplicationAssessmentResult {
            schema_version: APPLICATION_ASSESSMENT_RESULT_SCHEMA.into(),
            run_id: request.run_id.clone(),
            request_sha256: request.request_sha256.clone(),
            assessment_sha256: request.assessment_sha256.clone(),
            native: AssessmentNativeOutcome {
                schema_version: ASSESSMENT_NATIVE_OBSERVATION_SCHEMA.into(),
                semantic_sha256: plan.semantic_sha256.clone(),
                mode: plan.mode,
                windows: Some(aiw_probe::WindowsVersionObservation {
                    major: 10,
                    minor: 0,
                    build: 26100,
                    revision: 9974,
                    observer_architecture: "x86_64".into(),
                }),
                windows_error: None,
                setup_token: Some(token(50, true, false)),
                standard_context: Some(StandardUserRuntimeContext {
                    user_sid: "S-1-5-21-100-200-300-1001".into(),
                    profile_path: r"C:\Users\AiwStandardUser".into(),
                    roaming_app_data: r"C:\Users\AiwStandardUser\AppData\Roaming".into(),
                    local_app_data: r"C:\Users\AiwStandardUser\AppData\Local".into(),
                    administrators_enabled: false,
                }),
                profile_sid: classic.then(|| "S-1-15-2-1-2-3-4-5-6-7".into()),
                steps: vec![empty_step(0, "stagePortable"), launch, exit],
                assertions: vec![AssessmentAssertionObservation {
                    id: plan.settings.assertions[0].id.clone(),
                    passed: Some(true),
                    actual_sha256: Some(hex::encode(Sha256::digest(b"abc"))),
                    actual_size_bytes: Some(3),
                    error: None,
                }],
                collector_write_denied: Some(true),
                collector_access_denials: denials(),
                collector_unimpersonated: Some(true),
                account_cleanup: AssessmentAccountCleanup {
                    environment_destroyed: Some(true),
                    profile_unloaded: Some(true),
                    account_deleted: Some(true),
                    errors: vec![],
                },
                profile_cleanup: classic.then_some(true),
                driver_errors: vec![],
                driver_completed: true,
                scope: ASSESSMENT_SCOPE.into(),
            },
        }
    }
    fn partial(value: &mut ApplicationAssessmentResult) {
        value.native.steps.truncate(2);
        value.native.assertions.clear();
        value.native.steps[1].error = Some("measurement incomplete".into());
        value.native.driver_completed = false;
        value
            .native
            .driver_errors
            .push("retained failed prefix".into());
    }

    #[test]
    fn ordinary_and_classic_derive_scoped_safe_rows_with_exact_birth_and_code() {
        for classic in [false, true] {
            let request = request(classic);
            let result = result(&request);
            let evidence = verify_assessment_result(&request, &result).unwrap();
            assert_eq!(evidence.workflow_status, AssessmentFactStatus::Passed);
            assert_eq!(evidence.status, AssessmentEvidenceStatus::WorkflowPassed);
            assert_eq!(evidence.coverage.process_records, 1);
            assert_eq!(evidence.coverage.complete_captures, 2);
            assert_eq!(evidence.cleanup.status, AssessmentFactStatus::Passed);
            let json = serde_json::to_string(&evidence).unwrap();
            for private in [
                "S-1-5-21",
                "C:\\",
                "133000000000000001",
                "heldToken",
                "processId",
                "Unknown tool",
            ] {
                assert!(!json.contains(private), "{private}");
            }
            assert_eq!(
                serde_json::from_str::<VerifiedAssessmentEvidence>(&json).unwrap(),
                evidence
            );
        }
    }
    #[test]
    fn schemas_run_and_all_execution_hashes_are_bound() {
        let request = request(false);
        let baseline = result(&request);
        for field in [
            "schemaVersion",
            "runId",
            "requestSha256",
            "assessmentSha256",
        ] {
            let mut wire = serde_json::to_value(&baseline).unwrap();
            wire[field] = serde_json::json!("wrong");
            let changed: ApplicationAssessmentResult = serde_json::from_value(wire).unwrap();
            assert!(
                verify_assessment_result(&request, &changed).is_err(),
                "{field}"
            );
        }
        for field in ["schemaVersion", "semanticSha256", "scope"] {
            let mut wire = serde_json::to_value(&baseline).unwrap();
            wire["native"][field] = serde_json::json!("wrong");
            let changed: ApplicationAssessmentResult = serde_json::from_value(wire).unwrap();
            assert!(
                verify_assessment_result(&request, &changed).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn forged_capture_shape_hash_or_completion_is_refused_but_partial_is_retained() {
        let request = request(false);
        let original = result(&request);
        for mutate in 0..5 {
            let mut bad = original.clone();
            let c = &mut bad.native.steps[1].process.as_mut().unwrap().stdout;
            match mutate {
                0 => c.sha256 = "f".repeat(64),
                1 => c.bytes_hex.push_str("00"),
                2 => c.limit_bytes += 1,
                3 => c.overflowed = true,
                _ => c.read_error = Some("read failed".into()),
            };
            assert!(
                verify_assessment_result(&request, &bad).is_err(),
                "{mutate}"
            );
        }
        let mut retained = original;
        partial(&mut retained);
        let c = &mut retained.native.steps[1].process.as_mut().unwrap().stdout;
        c.complete = false;
        c.read_error = Some("EOF unmeasured".into());
        let verified = verify_assessment_result(&request, &retained).unwrap();
        assert_eq!(verified.status, AssessmentEvidenceStatus::DriverIncomplete);
        assert_eq!(verified.workflow_status, AssessmentFactStatus::Unmeasured);
        assert_eq!(verified.coverage.complete_captures, 1);
    }
    #[test]
    fn app_failure_is_recomputed_and_not_a_candidate_incompatibility_verdict() {
        let request = request(false);
        let mut value = result(&request);
        let bytes = b"abcd";
        value.native.steps[1].process.as_mut().unwrap().stdout =
            capture_bytes(bytes, request.assessment.settings.stdout_max_bytes);
        value.native.assertions[0].actual_sha256 = Some(hex::encode(Sha256::digest(bytes)));
        value.native.assertions[0].actual_size_bytes = Some(4);
        assert!(verify_assessment_result(&request, &value).is_err());
        value.native.assertions[0].passed = Some(false);
        let summary = verify_assessment_result(&request, &value).unwrap();
        assert_eq!(summary.status, AssessmentEvidenceStatus::WorkflowFailed);
        assert!(summary.driver_complete);
        assert_eq!(summary.assertions[0].status, AssessmentFactStatus::Failed);
    }
    #[test]
    fn missing_or_wrong_root_measurements_never_receive_function_credit() {
        let request = request(false);
        let original = result(&request);
        for mutate in 0..5 {
            let mut value = original.clone();
            partial(&mut value);
            let p = value.native.steps[1].process.as_mut().unwrap();
            match mutate {
                0 => p.held_token = None,
                1 => p.creation_time_100ns = None,
                2 => p.held_token.as_mut().unwrap().user_sid = "S-1-5-21-100-200-300-1002".into(),
                3 => p.held_token.as_mut().unwrap().is_elevated = true,
                _ => p.job_empty = None,
            };
            let summary = verify_assessment_result(&request, &value).unwrap();
            assert_eq!(
                summary.workflow_status,
                AssessmentFactStatus::Unmeasured,
                "{mutate}"
            );
            if mutate <= 1 {
                assert_eq!(
                    summary.steps[1].root_policy,
                    AssessmentFactStatus::Unmeasured
                );
                assert_eq!(summary.coverage.measured_root_policies, 0);
            }
        }
        for birth in [
            "0",
            "0133000000000000001",
            "133000000000000001.0",
            "18446744073709551616",
        ] {
            let mut value = original.clone();
            value.native.steps[1]
                .process
                .as_mut()
                .unwrap()
                .creation_time_100ns = Some(birth.into());
            assert!(verify_assessment_result(&request, &value).is_err());
        }
        let mut value = original;
        value.native.steps[1]
            .process
            .as_mut()
            .unwrap()
            .held_token
            .as_mut()
            .unwrap()
            .process_id = 78;
        assert!(verify_assessment_result(&request, &value).is_err());
    }
    #[test]
    fn image_identity_architecture_size_and_package_binding_cannot_be_forged() {
        let request = request(true);
        let original = result(&request);
        for mutate in 0..6 {
            let mut value = original.clone();
            match mutate {
                0 => value.native.steps[1].image.as_mut().unwrap().sha256 = "a".repeat(64),
                1 => value.native.steps[1].image.as_mut().unwrap().size_bytes += 1,
                2 => {
                    value.native.steps[1]
                        .image
                        .as_mut()
                        .unwrap()
                        .identity
                        .file_id = "0".repeat(32)
                }
                3 => {
                    value.native.steps[1]
                        .image
                        .as_mut()
                        .unwrap()
                        .optional_header_magic = Some("0x010b".into())
                }
                4 => {
                    value.native.steps[1]
                        .process
                        .as_mut()
                        .unwrap()
                        .image_identity
                        .file_id = "2".repeat(32)
                }
                _ => value.native.profile_sid = Some("S-1-15-2-2-2-3-4-5-6-7".into()),
            };
            assert!(
                verify_assessment_result(&request, &value).is_err(),
                "{mutate}"
            );
        }
    }
    #[test]
    fn cleanup_is_independent_and_unknown_is_not_success() {
        let request = request(false);
        let mut value = result(&request);
        value.native.account_cleanup.account_deleted = Some(false);
        value
            .native
            .account_cleanup
            .errors
            .push("account cleanup failed".into());
        value.native.driver_completed = false;
        let evidence = verify_assessment_result(&request, &value).unwrap();
        assert_eq!(evidence.workflow_status, AssessmentFactStatus::Passed);
        assert_eq!(evidence.status, AssessmentEvidenceStatus::DriverIncomplete);
        assert_eq!(evidence.cleanup.status, AssessmentFactStatus::Failed);
        value.native.account_cleanup.errors.clear();
        value.native.account_cleanup.account_deleted = None;
        let evidence = verify_assessment_result(&request, &value).unwrap();
        assert_eq!(evidence.cleanup.status, AssessmentFactStatus::Unmeasured);
    }

    #[test]
    fn pre_sid_profile_cleanup_is_retained_only_as_an_uncredited_no_app_failure() {
        let request = request(true);
        let original = result(&request);
        let mut failed = original.clone();
        failed.native.steps.clear();
        failed.native.assertions.clear();
        failed.native.profile_sid = None;
        failed.native.profile_cleanup = Some(true);
        failed.native.driver_completed = false;
        failed.native.driver_errors =
            vec!["fresh profile conversion failed; owned cleanup reported".into()];
        let safe = verify_assessment_result(&request, &failed).unwrap();
        assert_eq!(safe.status, AssessmentEvidenceStatus::NotRun);
        assert!(!safe.driver_complete);
        assert_eq!(safe.cleanup.appcontainer_profile_deleted, None);
        assert_eq!(safe.cleanup.status, AssessmentFactStatus::Unmeasured);
        assert_eq!(failed.native.profile_cleanup, Some(true));
        for mutate in 0..4 {
            let mut invalid = failed.clone();
            match mutate {
                0 => invalid.native.driver_completed = true,
                1 => invalid.native.steps = original.native.steps.clone(),
                2 => invalid.native.driver_errors.clear(),
                _ => invalid.native.steps.push(empty_step(0, "stagePortable")),
            }
            assert!(
                verify_assessment_result(&request, &invalid).is_err(),
                "{mutate}"
            );
        }
        let ordinary = self::request(false);
        let mut invalid = result(&ordinary);
        invalid.native.steps.clear();
        invalid.native.assertions.clear();
        invalid.native.profile_cleanup = Some(true);
        invalid.native.driver_completed = false;
        invalid.native.driver_errors = vec!["no application".into()];
        assert!(verify_assessment_result(&ordinary, &invalid).is_err());
    }
    #[test]
    fn denial_gate_blocks_dispatch_and_empty_failed_preflight_is_truthful_not_run() {
        let request = request(false);
        let mut value = result(&request);
        value.native.collector_write_denied = Some(false);
        assert!(verify_assessment_result(&request, &value).is_err());
        value.native.steps.clear();
        value.native.assertions.clear();
        value.native.setup_token = None;
        value.native.standard_context = None;
        value.native.collector_access_denials.clear();
        value.native.collector_unimpersonated = None;
        value.native.collector_write_denied = None;
        value.native.windows = None;
        value.native.windows_error = Some("preflight failed".into());
        value.native.account_cleanup = AssessmentAccountCleanup::default();
        value.native.driver_completed = false;
        value.native.driver_errors = vec!["no application started".into()];
        let summary = verify_assessment_result(&request, &value).unwrap();
        assert_eq!(summary.status, AssessmentEvidenceStatus::NotRun);
        assert_eq!(summary.workflow_status, AssessmentFactStatus::NotRun);
        assert_eq!(summary.cleanup.status, AssessmentFactStatus::Unmeasured);
    }
    #[test]
    fn full_width_exit_bits_and_work_file_facts_are_used_not_caller_flags() {
        let (mut project, mut settings, manifest) = crate::assessment::tests::fixture();
        project.scenarios[0].steps[2] = aiw_schema::ScenarioStep::ExpectExitCode { value: -1 };
        project.scenarios[0]
            .steps
            .push(aiw_schema::ScenarioStep::ObserveFile {
                path: "state.db".into(),
            });
        settings.assertions.push(AssessmentAssertion {
            id: "file".into(),
            target: AssessmentAssertionTarget::WorkFile {
                path: "state.db".into(),
            },
            expected_sha256: None,
            expected_size_bytes: Some(4),
        });
        let request = ApplicationAssessmentGuestRequest::new(
            "synthetic-assessment".into(),
            "4a0f039f-4bb7-4d14-b1d8-4c9891bc44a3".into(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            compile_assessment(&project, &settings, &manifest).unwrap(),
        )
        .unwrap();
        let mut value = result(&request);
        value.native.steps[1].process.as_mut().unwrap().exit_code = Some(u32::MAX);
        let mut observed = empty_step(3, "observeFile");
        observed.file_exists = Some(true);
        observed.file = Some(AssessmentFileObservation {
            relative_path: "state.db".into(),
            identity: held(work_path("state.db")),
            size_bytes: 4,
            sha256: hex::encode(Sha256::digest(b"data")),
        });
        value.native.steps.push(observed);
        value
            .native
            .assertions
            .push(AssessmentAssertionObservation {
                id: "file".into(),
                passed: Some(true),
                actual_sha256: Some(hex::encode(Sha256::digest(b"data"))),
                actual_size_bytes: Some(4),
                error: None,
            });
        let summary = verify_assessment_result(&request, &value).unwrap();
        assert_eq!(summary.steps[1].exit_code, Some(u32::MAX));
        assert_eq!(summary.workflow_status, AssessmentFactStatus::Passed);
        let mut forged = value.clone();
        forged.native.assertions[1].actual_sha256 = Some("e".repeat(64));
        assert!(verify_assessment_result(&request, &forged).is_err());
        value.native.steps[3].file = None;
        value.native.steps[3].file_exists = Some(false);
        value.native.assertions[1].actual_sha256 = None;
        value.native.assertions[1].actual_size_bytes = None;
        value.native.assertions[1].passed = Some(false);
        assert_eq!(
            verify_assessment_result(&request, &value)
                .unwrap()
                .workflow_status,
            AssessmentFactStatus::Failed
        );
        value.native.assertions[1].passed = Some(true);
        assert!(verify_assessment_result(&request, &value).is_err());
    }
    #[test]
    fn prefix_order_flags_and_bounds_cannot_supply_missing_measurements() {
        let request = request(false);
        let original = result(&request);
        for mutate in 0..5 {
            let mut value = original.clone();
            match mutate {
                0 => value.native.steps[1].index = 2,
                1 => value.native.steps[1].kind = "install".into(),
                2 => value.native.steps.pop().map(|_| ()).unwrap(),
                3 => value.native.driver_errors.push("diagnostic".into()),
                _ => value.native.steps[1].error = Some("failed before a later step".into()),
            };
            assert!(
                verify_assessment_result(&request, &value).is_err(),
                "{mutate}"
            );
        }
        let mut value = original;
        value.native.driver_completed = false;
        value.native.driver_errors = vec!["x".repeat(4097)];
        assert!(verify_assessment_result(&request, &value).is_err());
    }

    #[test]
    fn numeric_pid_reuse_requires_distinct_increasing_full_width_births() {
        let (mut project, settings, manifest) = crate::assessment::tests::fixture();
        project.scenarios[0].steps.extend([
            aiw_schema::ScenarioStep::Launch {
                entrypoint: "main".into(),
                arguments: vec![],
            },
            aiw_schema::ScenarioStep::ExpectExitCode { value: 0 },
        ]);
        let request = ApplicationAssessmentGuestRequest::new(
            "synthetic-assessment".into(),
            "4a0f039f-4bb7-4d14-b1d8-4c9891bc44a3".into(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            compile_assessment(&project, &settings, &manifest).unwrap(),
        )
        .unwrap();
        let mut value = result(&request);
        let mut launch = value.native.steps[1].clone();
        launch.index = 3;
        launch.process.as_mut().unwrap().creation_time_100ns = Some("133000000000000002".into());
        value.native.steps.push(launch);
        let mut exit = empty_step(4, "expectExitCode");
        exit.assertion_passed = Some(true);
        value.native.steps.push(exit);
        assert_eq!(
            verify_assessment_result(&request, &value)
                .unwrap()
                .coverage
                .process_records,
            2
        );
        for birth in ["133000000000000001", "133000000000000000"] {
            let mut bad = value.clone();
            bad.native.steps[3]
                .process
                .as_mut()
                .unwrap()
                .creation_time_100ns = Some(birth.into());
            assert!(verify_assessment_result(&request, &bad).is_err());
        }
    }

    #[test]
    fn collector_gate_requires_every_individual_right_actual_user_code5_and_unimpersonated_collector()
     {
        let request = request(false);
        let original = result(&request);
        let mut wrong_collector = original.clone();
        wrong_collector
            .native
            .setup_token
            .as_mut()
            .unwrap()
            .is_elevated = false;
        wrong_collector.native.driver_completed = false;
        assert!(verify_assessment_result(&request, &wrong_collector).is_err());
        assert_eq!(collector_denial(&original.native).unwrap(), Some(true));
        for mutate in 0..9 {
            let mut value = original.clone();
            match mutate {
                0 => {
                    value.native.collector_access_denials.pop();
                }
                1 => value.native.collector_access_denials[0].access_mask = 0x40000000,
                2 => value.native.collector_access_denials[0].native_code = Some(32),
                3 => {
                    value.native.collector_access_denials[0].effective_user_sid =
                        "S-1-5-21-100-200-300-1002".into()
                }
                4 => value.native.collector_access_denials.swap(0, 1),
                5 => value.native.collector_unimpersonated = Some(false),
                6 => value.native.collector_unimpersonated = None,
                7 => {
                    value.native.collector_access_denials[0].native_code = Some(0);
                    value.native.collector_access_denials[0].denied = Some(false);
                    value.native.collector_write_denied = Some(false);
                }
                _ => {
                    value.native.collector_access_denials[0].denied = None;
                    value.native.collector_access_denials[0].native_code = None;
                    value.native.collector_access_denials[0].error = Some("probe unknown".into());
                    value.native.collector_write_denied = None;
                }
            }
            assert!(
                verify_assessment_result(&request, &value).is_err(),
                "guard mutation {mutate}"
            );
        }
        let mut blocked = original;
        blocked.native.steps.clear();
        blocked.native.assertions.clear();
        blocked.native.driver_completed = false;
        blocked.native.driver_errors = vec!["guard incomplete; no application dispatched".into()];
        blocked.native.collector_access_denials.truncate(5);
        blocked.native.collector_write_denied = None;
        let summary = verify_assessment_result(&request, &blocked).unwrap();
        assert_eq!(summary.status, AssessmentEvidenceStatus::NotRun);
        assert_eq!(summary.coverage.collector_write_denied, None);
        blocked.native.collector_access_denials[0].native_code = Some(0);
        blocked.native.collector_access_denials[0].denied = Some(false);
        blocked.native.collector_write_denied = Some(false);
        let summary = verify_assessment_result(&request, &blocked).unwrap();
        assert_eq!(summary.status, AssessmentEvidenceStatus::NotRun);
        assert_eq!(summary.coverage.collector_write_denied, Some(false));
    }

    fn progress(
        request: &ApplicationAssessmentGuestRequest,
        result: &ApplicationAssessmentResult,
    ) -> Vec<crate::assessment_observation::AssessmentProgressEvent> {
        use crate::assessment_observation::{
            ASSESSMENT_PROGRESS_SCHEMA, AssessmentProgressEvent as E,
        };
        let n = &result.native;
        let mut events = vec![
            E::Header {
                schema_version: ASSESSMENT_PROGRESS_SCHEMA.into(),
                run_id: request.run_id.clone(),
                sandbox_id: request.sandbox_id.clone(),
                request_sha256: request.request_sha256.clone(),
                assessment_sha256: request.assessment_sha256.clone(),
                agent_sha256: request.agent_sha256.clone(),
                config_sha256: request.config_sha256.clone(),
                project_revision_sha256: request.project_revision_sha256.clone(),
                collector_token: n.setup_token.clone().unwrap(),
            },
            E::Context {
                windows: n.windows.clone(),
                windows_error: n.windows_error.clone(),
                standard_context: None,
            },
            E::Context {
                windows: n.windows.clone(),
                windows_error: n.windows_error.clone(),
                standard_context: n.standard_context.clone(),
            },
        ];
        events.extend(
            n.collector_access_denials
                .iter()
                .cloned()
                .map(|observation| E::CollectorAccess { observation }),
        );
        if let Some(profile_sid) = &n.profile_sid {
            events.push(E::ProfileCreated {
                profile_sid: profile_sid.clone(),
            });
        }
        for row in &n.steps {
            if let Some(observed) = &row.process {
                let mut process = observed.clone();
                process.exit_code = None;
                process.job_empty = None;
                process.timed_out = false;
                process.stdout = capture_bytes(b"", request.assessment.settings.stdout_max_bytes);
                process.stdout.complete = false;
                process.stderr = capture_bytes(b"", request.assessment.settings.stderr_max_bytes);
                process.stderr.complete = false;
                events.push(E::LaunchStarted {
                    index: row.index,
                    process,
                });
            }
            events.push(E::Step {
                observation: Box::new(row.clone()),
            });
        }
        events.extend(
            n.assertions
                .iter()
                .cloned()
                .map(|observation| E::Assertion { observation }),
        );
        events.push(E::Terminal {
            collector_write_denied: n.collector_write_denied,
            collector_unimpersonated: n.collector_unimpersonated,
            profile_sid: n.profile_sid.clone(),
            profile_cleanup: n.profile_cleanup,
            account_cleanup: n.account_cleanup.clone(),
            driver_completed: n.driver_completed,
            errors: n.driver_errors.clone(),
        });
        events
    }
    fn progress_bytes(
        events: &[crate::assessment_observation::AssessmentProgressEvent],
    ) -> Vec<u8> {
        let mut bytes = vec![];
        for e in events {
            serde_json::to_writer(&mut bytes, e).unwrap();
            bytes.push(b'\n');
        }
        bytes
    }

    #[test]
    fn progress_binds_full_request_monotonic_environment_created_roots_and_final_cleanup() {
        use crate::assessment_observation::AssessmentProgressEvent as E;
        for classic in [false, true] {
            let request = request(classic);
            let result = result(&request);
            let events = progress(&request, &result);
            verify_assessment_progress(&progress_bytes(&events), &request, &result).unwrap();
            for mutate in 0..5 {
                let mut changed = events.clone();
                match mutate {
                    0 => {
                        if let E::Header { config_sha256, .. } = &mut changed[0] {
                            *config_sha256 = "e".repeat(64);
                        }
                    }
                    1 => {
                        if let E::Context {
                            windows: Some(w), ..
                        } = &mut changed[2]
                        {
                            w.revision += 1;
                        }
                    }
                    2 => {
                        let at = changed
                            .iter()
                            .position(|e| matches!(e, E::LaunchStarted { .. }))
                            .unwrap();
                        if let E::LaunchStarted { process, .. } = &mut changed[at] {
                            process.creation_time_100ns = Some("133000000000000002".into());
                        }
                    }
                    3 => {
                        let at = changed
                            .iter()
                            .position(|e| matches!(e, E::LaunchStarted { .. }))
                            .unwrap();
                        changed.remove(at);
                    }
                    _ => {
                        let extra = changed[0].clone();
                        changed.push(extra);
                    }
                }
                assert!(
                    verify_assessment_progress(&progress_bytes(&changed), &request, &result)
                        .is_err(),
                    "{mutate}"
                );
            }
            let mut changed = result.clone();
            changed.native.account_cleanup.account_deleted = Some(false);
            assert!(
                verify_assessment_progress(&progress_bytes(&events), &request, &changed).is_err()
            );
        }
    }

    #[test]
    fn pending_pre_resume_creation_and_trailing_partial_line_are_diagnostic_only() {
        use crate::assessment_observation::AssessmentProgressEvent as E;
        let request = request(false);
        let result = result(&request);
        let events = progress(&request, &result);
        let at = events
            .iter()
            .position(|e| matches!(e, E::LaunchStarted { .. }))
            .unwrap();
        let bytes = progress_bytes(&events[..=at]);
        let partial = parse_assessment_progress(&bytes, &request).unwrap();
        assert!(!partial.terminal_present);
        assert!(!partial.result.native.driver_completed);
        assert!(partial.pending_launch.is_some());
        assert_eq!(partial.result.native.steps.len(), 1);
        assert!(verify_assessment_progress(&bytes, &request, &result).is_err());
        let mut trailing = progress_bytes(&events[..1]);
        trailing.extend_from_slice(b"{\"type\":\"context\"");
        let parsed = parse_assessment_progress(&trailing, &request).unwrap();
        assert!(parsed.trailing_incomplete);
        assert!(!parsed.terminal_present);
        assert!(parsed.pending_launch.is_none());
        let mut full = progress_bytes(&events);
        full.extend_from_slice(b"{");
        assert!(verify_assessment_progress(&full, &request, &result).is_err());
        let text = String::from_utf8(progress_bytes(&events[..1])).unwrap();
        let duplicate = text.replacen("{", "{\"runId\":\"shadow\",", 1);
        assert!(parse_assessment_progress(duplicate.as_bytes(), &request).is_err());
    }

    #[test]
    fn single_hash_reference_event_binds_actual_result_without_copying_captures() {
        let request = request(false);
        let result = result(&request);
        let mut log = aiw_evidence::EvidenceLog::new();
        log.append(aiw_evidence::EvidenceEvent {
            observed_utc: "untrusted-time".into(),
            kind: APPLICATION_ASSESSMENT_EVIDENCE_EVENT.into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::to_value(assessment_result_reference(&request, &result).unwrap())
                .unwrap(),
        })
        .unwrap();
        let mut bytes = vec![];
        for record in log.records() {
            serde_json::to_writer(&mut bytes, record).unwrap();
            bytes.push(b'\n');
        }
        let root = log.manifest().unwrap().root_hash;
        assert!(bytes.len() < 2048);
        assert!(!String::from_utf8_lossy(&bytes).contains("bytesHex"));
        verify_assessment_evidence(&bytes, &root, &request, &result).unwrap();
        let mut changed = result;
        changed.native.account_cleanup.account_deleted = Some(false);
        assert!(verify_assessment_evidence(&bytes, &root, &request, &changed).is_err());
        let mut repeated = bytes.clone();
        repeated.extend_from_slice(&bytes);
        assert!(verify_assessment_evidence(&repeated, &root, &request, &changed).is_err());
    }
}
