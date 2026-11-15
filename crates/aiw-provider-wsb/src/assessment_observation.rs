//! Native facts only. Assertions, driver completion and cleanup are separate.
use crate::{StandardUserRuntimeContext, assessment::AssessmentMode};
use aiw_probe::{WindowsFileIdentity, WindowsVersionObservation};
use aiw_token::TokenEvidence;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentCapture {
    pub bytes_hex: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub limit_bytes: u64,
    pub overflowed: bool,
    pub complete: bool,
    pub read_error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentProcessObservation {
    pub process_id: u32,
    /// Exact decimal FILETIME, never a JSON number vulnerable to JS rounding.
    pub creation_time_100ns: Option<String>,
    pub held_token: Option<TokenEvidence>,
    pub image_identity: WindowsFileIdentity,
    pub image_sha256: String,
    pub image_size_bytes: u64,
    pub image_machine: String,
    pub exit_code: Option<u32>,
    pub timed_out: bool,
    pub job_empty: Option<bool>,
    pub stdout: AssessmentCapture,
    pub stderr: AssessmentCapture,
    pub errors: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentFileObservation {
    pub relative_path: String,
    pub identity: WindowsFileIdentity,
    pub size_bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentImageObservation {
    pub identity: WindowsFileIdentity,
    pub sha256: String,
    pub size_bytes: u64,
    pub machine: Option<String>,
    pub optional_header_magic: Option<String>,
    pub architecture_error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentStepObservation {
    pub index: usize,
    pub kind: String,
    pub process: Option<AssessmentProcessObservation>,
    pub image: Option<AssessmentImageObservation>,
    pub file: Option<AssessmentFileObservation>,
    pub file_exists: Option<bool>,
    pub assertion_passed: Option<bool>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentAssertionObservation {
    pub id: String,
    pub passed: Option<bool>,
    pub actual_sha256: Option<String>,
    pub actual_size_bytes: Option<u64>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentAccountCleanup {
    pub environment_destroyed: Option<bool>,
    pub profile_unloaded: Option<bool>,
    pub account_deleted: Option<bool>,
    pub errors: Vec<String>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentCollectorTarget {
    Directory,
    ProgressFile,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentCollectorAccessDenial {
    pub effective_user_sid: String,
    pub target: AssessmentCollectorTarget,
    pub access_mask: u32,
    pub native_code: Option<u32>,
    pub denied: Option<bool>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentNativeOutcome {
    pub schema_version: String,
    pub semantic_sha256: String,
    pub mode: AssessmentMode,
    pub windows: Option<WindowsVersionObservation>,
    pub windows_error: Option<String>,
    pub setup_token: Option<TokenEvidence>,
    pub standard_context: Option<StandardUserRuntimeContext>,
    pub steps: Vec<AssessmentStepObservation>,
    pub assertions: Vec<AssessmentAssertionObservation>,
    pub collector_write_denied: Option<bool>,
    pub collector_access_denials: Vec<AssessmentCollectorAccessDenial>,
    pub collector_unimpersonated: Option<bool>,
    pub profile_sid: Option<String>,
    pub account_cleanup: AssessmentAccountCleanup,
    pub profile_cleanup: Option<bool>,
    pub driver_errors: Vec<String>,
    pub driver_completed: bool,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationAssessmentResult {
    pub schema_version: String,
    pub run_id: String,
    pub request_sha256: String,
    pub assessment_sha256: String,
    pub native: AssessmentNativeOutcome,
}
pub const APPLICATION_ASSESSMENT_RESULT_SCHEMA: &str =
    "aiw.dev/application-assessment-result/v0alpha1";

pub const ASSESSMENT_PROGRESS_SCHEMA: &str = "aiw.dev/assessment-progress/v0alpha1";
pub const ASSESSMENT_PROGRESS_PATH: &str = r"C:\AIW\Output\assessment-progress.jsonl";
/// Closed independent records. Earlier complete records remain diagnostic
/// observations after an absent/interrupted terminal, never compatibility credit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AssessmentProgressEvent {
    Header {
        schema_version: String,
        run_id: String,
        sandbox_id: String,
        request_sha256: String,
        assessment_sha256: String,
        agent_sha256: String,
        config_sha256: String,
        project_revision_sha256: String,
        collector_token: TokenEvidence,
    },
    Context {
        windows: Option<WindowsVersionObservation>,
        windows_error: Option<String>,
        standard_context: Option<StandardUserRuntimeContext>,
    },
    CollectorAccess {
        observation: AssessmentCollectorAccessDenial,
    },
    ProfileCreated {
        profile_sid: String,
    },
    LaunchStarted {
        index: usize,
        process: AssessmentProcessObservation,
    },
    Step {
        observation: Box<AssessmentStepObservation>,
    },
    Assertion {
        observation: AssessmentAssertionObservation,
    },
    Terminal {
        collector_write_denied: Option<bool>,
        collector_unimpersonated: Option<bool>,
        profile_sid: Option<String>,
        profile_cleanup: Option<bool>,
        account_cleanup: AssessmentAccountCleanup,
        driver_completed: bool,
        errors: Vec<String>,
    },
}
