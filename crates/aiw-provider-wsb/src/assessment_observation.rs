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
pub const ASSESSMENT_COLLECTOR_PROTECTION_SCHEMA: &str =
    "aiw.dev/assessment-collector-protection/v0alpha1";
pub const ASSESSMENT_COLLECTOR_PROTECTION_V2_SCHEMA: &str =
    "aiw.dev/assessment-collector-protection/v0alpha2";
pub const ASSESSMENT_COLLECTOR_PROCESS_RIGHTS: [u32; 7] =
    [0x2, 0x8, 0x10, 0x20, 0x40, 0x40000, 0x80000];
pub const ASSESSMENT_COLLECTOR_THREAD_RIGHTS: [u32; 7] =
    [0x8, 0x10, 0x80, 0x100, 0x200, 0x40000, 0x80000];
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentCollectorObject {
    CollectorProcess,
    SigningThread,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentCollectorObjectAccess {
    pub effective_user_sid: String,
    pub target: AssessmentCollectorObject,
    pub access_mask: u32,
    pub native_code: Option<u32>,
    pub denied: Option<bool>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentCollectorObjectSecurity {
    pub owner_sid: String,
    pub sddl: String,
    /// SHA256 of the exact observed SDDL UTF8 bytes, not a private key.
    pub sha256: String,
    pub trustee_sids: Vec<String>,
    pub parse_error: Option<String>,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentCollectorProtection {
    pub schema_version: String,
    pub storage: crate::assessment_channel::ChannelCollectorStorage,
    pub collector_process_id: u32,
    pub collector_creation_time_100ns: String,
    pub signing_thread_id: u32,
    pub process_security: AssessmentCollectorObjectSecurity,
    pub thread_security: AssessmentCollectorObjectSecurity,
    /// Actual primary TokenDefaultDacl; creator provenance for subsequently
    /// created unimpersonated reader threads, not an observation of all threads.
    pub primary_default_dacl: AssessmentCollectorDefaultDacl,
    /// Actual held primary-token observations, never inferred from ACL text.
    /// Historical protection v1 cannot use a logon-SID trustee exception.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_provenance: Option<AssessmentCollectorTokenProvenance>,
    pub access_checks: Vec<AssessmentCollectorObjectAccess>,
}

#[derive(Default)]
struct TokenProvenancePresence {
    present: bool,
    value: Option<AssessmentCollectorTokenProvenance>,
}
impl<'de> Deserialize<'de> for TokenProvenancePresence {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self {
            present: true,
            value: Option::<AssessmentCollectorTokenProvenance>::deserialize(d)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CollectorProtectionWire {
    schema_version: String,
    storage: crate::assessment_channel::ChannelCollectorStorage,
    collector_process_id: u32,
    collector_creation_time_100ns: String,
    signing_thread_id: u32,
    process_security: AssessmentCollectorObjectSecurity,
    thread_security: AssessmentCollectorObjectSecurity,
    primary_default_dacl: AssessmentCollectorDefaultDacl,
    #[serde(default)]
    token_provenance: TokenProvenancePresence,
    access_checks: Vec<AssessmentCollectorObjectAccess>,
}
impl<'de> Deserialize<'de> for AssessmentCollectorProtection {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = CollectorProtectionWire::deserialize(d)?;
        if w.schema_version == ASSESSMENT_COLLECTOR_PROTECTION_SCHEMA && w.token_provenance.present
        {
            return Err(serde::de::Error::custom(
                "historical collector protection cannot contain token provenance",
            ));
        }
        Ok(Self {
            schema_version: w.schema_version,
            storage: w.storage,
            collector_process_id: w.collector_process_id,
            collector_creation_time_100ns: w.collector_creation_time_100ns,
            signing_thread_id: w.signing_thread_id,
            process_security: w.process_security,
            thread_security: w.thread_security,
            primary_default_dacl: w.primary_default_dacl,
            token_provenance: w.token_provenance.value,
            access_checks: w.access_checks,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentTokenGroup {
    pub sid: String,
    pub attributes: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentCollectorTokenProvenance {
    pub collector_user_sid: String,
    pub collector_token_type: aiw_token::TokenType,
    pub collector_logon_sid: String,
    pub collector_logon_attributes: u32,
    pub standard_user_sid: String,
    /// Complete bounded TokenGroups observation from the held standard token.
    pub standard_groups: Vec<AssessmentTokenGroup>,
}

/// Validate reported provenance and return only its exact logon-SID trustee
/// exception. Native callers must independently measure/revalidate the held
/// tokens. This pure function grants no observation or execution authority.
pub fn validate_collector_token_provenance<'a>(
    protection: &'a AssessmentCollectorProtection,
    collector_sid: &str,
    standard_sid: &str,
) -> Result<Option<&'a str>, String> {
    match protection.schema_version.as_str() {
        ASSESSMENT_COLLECTOR_PROTECTION_SCHEMA if protection.token_provenance.is_none() => {
            return Ok(None);
        }
        ASSESSMENT_COLLECTOR_PROTECTION_V2_SCHEMA => {}
        _ => return Err("collector token provenance version refused".into()),
    }
    let p = protection
        .token_provenance
        .as_ref()
        .ok_or("collector token provenance absent")?;
    let canonical_sid = |value: &str| {
        if value.len() > 184 {
            return false;
        }
        let parts: Vec<_> = value.split('-').collect();
        (4..=18).contains(&parts.len())
            && parts[0] == "S"
            && parts[1] == "1"
            && parts[2]
                .parse::<u64>()
                .ok()
                .is_some_and(|n| n < (1_u64 << 48) && n.to_string() == parts[2])
            && parts[3..].iter().all(|part| {
                part.parse::<u32>()
                    .ok()
                    .is_some_and(|n| n.to_string() == *part)
            })
    };
    let canonical_logon = canonical_sid(&p.collector_logon_sid)
        && p.collector_logon_sid
            .strip_prefix("S-1-5-5-")
            .is_some_and(|tail| tail.split('-').count() == 2);
    if !canonical_sid(&p.collector_user_sid)
        || !canonical_sid(&p.standard_user_sid)
        || p.collector_user_sid != collector_sid
        || p.standard_user_sid != standard_sid
        || collector_sid == standard_sid
        || p.collector_token_type != aiw_token::TokenType::Primary
        || p.collector_logon_sid == p.standard_user_sid
        || !canonical_logon
        || p.collector_logon_attributes & 0xc000_0000 != 0xc000_0000
        || p.collector_logon_attributes & 0x4 == 0
        || p.collector_logon_attributes & 0x10 != 0
        || p.standard_groups.len() > 256
        || p.standard_groups
            .iter()
            .any(|group| !canonical_sid(&group.sid) || group.sid == p.collector_logon_sid)
        || !p
            .standard_groups
            .windows(2)
            .all(|pair| pair[0].sid < pair[1].sid)
    {
        return Err("collector token provenance binding/groups refused".into());
    }
    Ok(Some(&p.collector_logon_sid))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentCollectorDefaultDacl {
    pub acl_hex: String,
    pub sha256: String,
    pub trustee_sids: Vec<String>,
    pub parse_error: Option<String>,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq, schemars::JsonSchema)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_protection: Option<AssessmentCollectorProtection>,
    pub profile_sid: Option<String>,
    pub account_cleanup: AssessmentAccountCleanup,
    pub profile_cleanup: Option<bool>,
    pub driver_errors: Vec<String>,
    pub driver_completed: bool,
    pub scope: String,
}
#[derive(Default)]
struct ProtectionPresence {
    present: bool,
    value: Option<AssessmentCollectorProtection>,
}
impl<'de> Deserialize<'de> for ProtectionPresence {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self {
            present: true,
            value: Option::<AssessmentCollectorProtection>::deserialize(d)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeWire {
    schema_version: String,
    semantic_sha256: String,
    mode: AssessmentMode,
    windows: Option<WindowsVersionObservation>,
    windows_error: Option<String>,
    setup_token: Option<TokenEvidence>,
    standard_context: Option<StandardUserRuntimeContext>,
    steps: Vec<AssessmentStepObservation>,
    assertions: Vec<AssessmentAssertionObservation>,
    collector_write_denied: Option<bool>,
    collector_access_denials: Vec<AssessmentCollectorAccessDenial>,
    collector_unimpersonated: Option<bool>,
    #[serde(default)]
    collector_protection: ProtectionPresence,
    profile_sid: Option<String>,
    account_cleanup: AssessmentAccountCleanup,
    profile_cleanup: Option<bool>,
    driver_errors: Vec<String>,
    driver_completed: bool,
    scope: String,
}
impl<'de> Deserialize<'de> for AssessmentNativeOutcome {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = NativeWire::deserialize(d)?;
        if w.schema_version == "aiw.dev/assessment-native-observation/v0alpha1"
            && w.collector_protection.present
        {
            return Err(serde::de::Error::custom(
                "historical native outcome cannot contain collector protection",
            ));
        }
        Ok(Self {
            schema_version: w.schema_version,
            semantic_sha256: w.semantic_sha256,
            mode: w.mode,
            windows: w.windows,
            windows_error: w.windows_error,
            setup_token: w.setup_token,
            standard_context: w.standard_context,
            steps: w.steps,
            assertions: w.assertions,
            collector_write_denied: w.collector_write_denied,
            collector_access_denials: w.collector_access_denials,
            collector_unimpersonated: w.collector_unimpersonated,
            collector_protection: w.collector_protection.value,
            profile_sid: w.profile_sid,
            account_cleanup: w.account_cleanup,
            profile_cleanup: w.profile_cleanup,
            driver_errors: w.driver_errors,
            driver_completed: w.driver_completed,
            scope: w.scope,
        })
    }
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
pub const APPLICATION_ASSESSMENT_RESULT_V2_SCHEMA: &str =
    "aiw.dev/application-assessment-result/v0alpha2";
pub const ASSESSMENT_NATIVE_OBSERVATION_V2_SCHEMA: &str =
    "aiw.dev/assessment-native-observation/v0alpha2";

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
    /// New authenticated semantic version only. Historical raw v1 refuses it.
    CollectorProtection {
        observation: Box<AssessmentCollectorProtection>,
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
