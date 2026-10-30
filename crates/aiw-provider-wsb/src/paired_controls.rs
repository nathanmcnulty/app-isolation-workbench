//! Typed paired measurements and comparison. No provider calls, grants or execution.
use aiw_evidence::canonical_json_bytes;
use aiw_probe::{ControlEvidenceOrigin, PairedControlProfile};
use aiw_token::{IntegrityLevel, TokenEvidence, TokenType};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const PAIRED_CONTROL_REQUEST_SCHEMA: &str = "aiw.dev/paired-controls-request/v0alpha1";
pub const PAIRED_CONTROL_RESULT_SCHEMA: &str = "aiw.dev/paired-controls-result/v0alpha1";
pub const PAIRED_CONTROL_FILE_BYTES: &[u8] = b"AIW controlled readable bytes";
pub const PAIRED_CONTROL_REGISTRY_BYTES: &[u8] = b"AIW controlled registry bytes";
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedControlsRequest {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub config_sha256: String,
    pub agent_sha256: String,
    pub request_sha256: String,
    pub profile: PairedControlProfile,
}
impl PairedControlsRequest {
    pub fn new(
        run_id: &str,
        sandbox_id: &str,
        config: &str,
        agent: &str,
        profile: PairedControlProfile,
    ) -> Result<Self, String> {
        profile.validate()?;
        Self::from_retained_binding(run_id, sandbox_id, config, agent, profile)
    }
    /// Reconstruct the exact original commitment for reading/recovery only.
    pub fn from_retained_binding(
        run_id: &str,
        sandbox_id: &str,
        config: &str,
        agent: &str,
        profile: PairedControlProfile,
    ) -> Result<Self, String> {
        let mut value = Self {
            schema_version: PAIRED_CONTROL_REQUEST_SCHEMA.into(),
            run_id: run_id.into(),
            sandbox_id: sandbox_id.into(),
            config_sha256: config.into(),
            agent_sha256: agent.into(),
            request_sha256: String::new(),
            profile,
        };
        value.request_sha256 = value.hash()?;
        value.validate()?;
        Ok(value)
    }
    pub fn hash(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.request_sha256.clear();
        digest(&value)
    }
    pub fn validate(&self) -> Result<(), String> {
        self.profile.validate_historical()?;
        if self.profile.fixture_sha256 != self.agent_sha256
            || self.schema_version != PAIRED_CONTROL_REQUEST_SCHEMA
            || !safe_id(&self.run_id)
            || !crate::imported_bambu::canonical_sandbox_id(&self.sandbox_id)
            || !aiw_probe::paired_controls::control_hash(&self.config_sha256)
            || !aiw_probe::paired_controls::control_hash(&self.agent_sha256)
            || self.request_sha256 != self.hash()?
        {
            return Err("Paired control request binding rejected".into());
        }
        Ok(())
    }
}
fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
pub fn paired_controls_digest(value: &impl Serialize) -> Result<String, String> {
    digest(value)
}
fn digest(value: &impl Serialize) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(
        canonical_json_bytes(&serde_json::to_value(value).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
    )))
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ControlAccess {
    Success,
    AccessDenied,
    NotFound,
    Timeout,
    Failure,
    Unmeasured,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ControlResourceKind {
    FixedFile,
    FixedRegistry64,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ControlReadStage {
    FileRead,
    NotMeasured,
    OpenKey,
    QuerySize,
    QueryValue,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlReadObservation {
    pub resource: ControlResourceKind,
    pub stage: ControlReadStage,
    pub outcome: ControlAccess,
    pub native_code: Option<u32>,
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
}
impl ControlReadObservation {
    fn validate(&self, bytes: &[u8], resource: ControlResourceKind) -> Result<(), String> {
        let native_stage = match resource {
            ControlResourceKind::FixedFile => self.stage == ControlReadStage::FileRead,
            ControlResourceKind::FixedRegistry64 => matches!(
                self.stage,
                ControlReadStage::OpenKey
                    | ControlReadStage::QuerySize
                    | ControlReadStage::QueryValue
            ),
        };
        let unmeasured_stage = matches!(
            self.outcome,
            ControlAccess::Timeout | ControlAccess::Failure | ControlAccess::Unmeasured
        ) && self.stage == ControlReadStage::NotMeasured;
        if self.resource != resource
            || (!native_stage && !unmeasured_stage)
            || (resource == ControlResourceKind::FixedRegistry64
                && self.outcome == ControlAccess::Success
                && self.stage != ControlReadStage::QueryValue)
        {
            return Err("Control read resource/stage differs from the fixed case".into());
        }
        let valid = match self.outcome {
            ControlAccess::Success => {
                self.native_code.is_none()
                    && self.size_bytes == Some(bytes.len() as u64)
                    && self.sha256.as_deref() == Some(hex::encode(Sha256::digest(bytes)).as_str())
            }
            ControlAccess::AccessDenied => {
                self.native_code == Some(5) && self.size_bytes.is_none() && self.sha256.is_none()
            }
            ControlAccess::NotFound => {
                matches!(self.native_code, Some(2 | 3))
                    && self.size_bytes.is_none()
                    && self.sha256.is_none()
            }
            ControlAccess::Timeout | ControlAccess::Failure | ControlAccess::Unmeasured => {
                self.size_bytes.is_none() && self.sha256.is_none()
            }
        };
        if !valid {
            return Err("Control access evidence is malformed; denial requires native error 5, missing requires 2/3".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedInvocation {
    pub process_id: u32,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    /// Measured on a retained process handle by the launcher, before resume.
    pub held_token: Option<TokenEvidence>,
    pub self_token: Option<TokenEvidence>,
    pub job_empty: Option<bool>,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedVariant {
    pub file_process: PairedInvocation,
    pub file: ControlReadObservation,
    pub registry_process: PairedInvocation,
    pub registry: ControlReadObservation,
    pub child_process: PairedInvocation,
    pub child_id: Option<u32>,
    pub child_token: Option<TokenEvidence>,
    pub child_stdout_bytes: Option<u64>,
    pub child_outcome: ControlAccess,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedControlResult {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub profile_sha256: String,
    pub origin: ControlEvidenceOrigin,
    pub windows: aiw_probe::WindowsVersionObservation,
    pub resources: PairedControlResources,
    pub launcher_id: u32,
    pub launcher_token: TokenEvidence,
    pub user_sid: String,
    pub package_sid: String,
    pub baseline: PairedVariant,
    pub candidate: PairedVariant,
    pub fixture_unchanged: bool,
    pub launcher_unchanged: bool,
    pub file_unchanged: bool,
    pub file_acl_unchanged: bool,
    pub registry_value_unchanged: bool,
    pub registry_acl_unchanged: bool,
    pub profile_deleted: Option<bool>,
    pub driver_complete: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedControlResources {
    pub file_path: String,
    pub file_sha256: String,
    pub file_size_bytes: u64,
    pub file_dacl_before_sha256: String,
    pub file_dacl_after_sha256: String,
    pub registry_hive: String,
    pub registry_view: String,
    pub registry_key: String,
    pub registry_value: String,
    pub registry_type: String,
    pub registry_sha256: String,
    pub registry_size_bytes: u64,
    pub registry_dacl_before_sha256: String,
    pub registry_dacl_after_sha256: String,
}
impl PairedControlResources {
    pub fn validate(&self) -> Result<(), String> {
        if self.file_path != r"C:\AIW\Control\SharedCanary\canary.txt"
            || self.file_size_bytes != 29
            || self.file_sha256 != hex::encode(Sha256::digest(PAIRED_CONTROL_FILE_BYTES))
            || self.registry_hive != "HKLM"
            || self.registry_view != "registry64"
            || self.registry_key != r"SOFTWARE\AIWControlCanary"
            || self.registry_value != "Canary"
            || self.registry_type != "binary"
            || self.registry_size_bytes != 29
            || self.registry_sha256 != hex::encode(Sha256::digest(PAIRED_CONTROL_REGISTRY_BYTES))
            || [
                &self.file_dacl_before_sha256,
                &self.file_dacl_after_sha256,
                &self.registry_dacl_before_sha256,
                &self.registry_dacl_after_sha256,
            ]
            .iter()
            .any(|h| !aiw_probe::paired_controls::control_hash(h))
        {
            return Err("Paired file/registry resource scope or identity rejected".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PairedControlComparison {
    pub eligible: bool,
    pub baseline_verified: bool,
    pub candidate_verified: bool,
    pub origin: ControlEvidenceOrigin,
    pub production_acceptance: bool,
    pub outer_boundary: &'static str,
    pub inner_boundary: &'static str,
    pub reason: PairedComparisonReason,
    pub gaps: Vec<&'static str>,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum PairedComparisonReason {
    FixedControlsObserved,
    BaselineFailed,
    CandidateFailed,
    DriverIncomplete,
    CleanupUnknown,
}
impl PairedControlResult {
    pub fn compare(
        &self,
        request: &PairedControlsRequest,
        outer_cleanup: Option<bool>,
    ) -> Result<PairedControlComparison, String> {
        request.validate()?;
        if self.schema_version != PAIRED_CONTROL_RESULT_SCHEMA
            || self.run_id != request.run_id
            || self.sandbox_id != request.sandbox_id
            || self.request_sha256 != request.request_sha256
            || self.profile_sha256 != request.profile.hash()?
            || self.origin != request.profile.origin
        {
            return Err(
                "Paired result does not bind to this exact approved request/profile".into(),
            );
        }
        self.windows.validate()?;
        self.resources.validate()?;
        if self.windows != request.profile.expected_windows
            || !valid_user_sid(&self.user_sid)
            || !valid_package_sid(&self.package_sid)
        {
            return Err("Paired user/environment/package provenance rejected".into());
        }
        validate_token(&self.launcher_token, self.launcher_id, &self.user_sid, None)?;
        let mut ids = BTreeSet::from([self.launcher_id]);
        for (variant, package) in [
            (&self.baseline, None),
            (&self.candidate, Some(self.package_sid.as_str())),
        ] {
            variant
                .file
                .validate(PAIRED_CONTROL_FILE_BYTES, ControlResourceKind::FixedFile)?;
            variant.registry.validate(
                PAIRED_CONTROL_REGISTRY_BYTES,
                ControlResourceKind::FixedRegistry64,
            )?;
            for invocation in [
                &variant.file_process,
                &variant.registry_process,
                &variant.child_process,
            ] {
                if invocation.process_id == 0 {
                    if invocation.held_token.is_some() || invocation.self_token.is_some() {
                        return Err("Unstarted control carries a token".into());
                    }
                    continue;
                }
                if !ids.insert(invocation.process_id) {
                    return Err("Duplicate control process identity".into());
                }
                for token in [&invocation.held_token, &invocation.self_token]
                    .into_iter()
                    .flatten()
                {
                    validate_token(token, invocation.process_id, &self.user_sid, package)?;
                }
            }
            if let Some(child) = variant.child_id {
                if !ids.insert(child) {
                    return Err("Child identity aliases another process".into());
                }
                if let Some(token) = &variant.child_token {
                    validate_token(token, child, &self.user_sid, package)?;
                }
            } else if variant.child_token.is_some() {
                return Err("Child token has no observed process identity".into());
            }
        }
        let baseline = variant_verified(&self.baseline, false);
        let candidate = variant_verified(&self.candidate, true);
        let driver = self.resources.file_dacl_before_sha256
            == self.resources.file_dacl_after_sha256
            && self.resources.registry_dacl_before_sha256
                == self.resources.registry_dacl_after_sha256
            && self.driver_complete
            && self.fixture_unchanged
            && self.launcher_unchanged
            && self.file_unchanged
            && self.file_acl_unchanged
            && self.registry_value_unchanged
            && self.registry_acl_unchanged;
        let cleanup = outer_cleanup == Some(true)
            && self.profile_deleted == Some(true)
            && [&self.baseline, &self.candidate].iter().all(|v| {
                [&v.file_process, &v.registry_process, &v.child_process]
                    .iter()
                    .all(|p| p.job_empty == Some(true))
            });
        let reason = if !driver {
            PairedComparisonReason::DriverIncomplete
        } else if !baseline {
            PairedComparisonReason::BaselineFailed
        } else if !candidate {
            PairedComparisonReason::CandidateFailed
        } else if !cleanup {
            PairedComparisonReason::CleanupUnknown
        } else {
            PairedComparisonReason::FixedControlsObserved
        };
        let mut gaps = vec![
            "real application compatibility unmeasured",
            "network and broader isolation unmeasured",
            "no endpoint baseline: both variants share the outer worker",
        ];
        if !driver {
            gaps.push("measurement driver incomplete or resource identity changed");
        }
        if !cleanup {
            gaps.push("historical process/profile/outer cleanup incomplete or unknown");
        }
        if self.origin == ControlEvidenceOrigin::SyntheticRehearsal {
            gaps.push("synthetic rehearsal: cannot satisfy production acceptance");
        }
        Ok(PairedControlComparison {
            eligible: reason == PairedComparisonReason::FixedControlsObserved,
            baseline_verified: baseline,
            candidate_verified: candidate,
            origin: self.origin,
            production_acceptance: false,
            outer_boundary: "Windows Sandbox (disposable measurement worker)",
            inner_boundary: "ordinary user versus classic AppContainer, zero capabilities",
            reason,
            gaps,
        })
    }
}
fn valid_user_sid(s: &str) -> bool {
    s.starts_with("S-1-5-21-")
        && s.len() <= 184
        && s.split('-')
            .skip(1)
            .all(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
}
fn valid_package_sid(s: &str) -> bool {
    s.starts_with("S-1-15-2-")
        && s.len() <= 184
        && s.split('-').count() == 11
        && s.split('-')
            .skip(1)
            .all(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
}
fn validate_token(
    token: &TokenEvidence,
    id: u32,
    user: &str,
    package: Option<&str>,
) -> Result<(), String> {
    let (level, rid) = if package.is_some() {
        (IntegrityLevel::Low, 4096)
    } else {
        (IntegrityLevel::Medium, 8192)
    };
    if id == 0
        || token.schema_version != aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
        || token.process_id != id
        || token.token_type != TokenType::Primary
        || token.impersonation_level.is_some()
        || token.user_sid != user
        || token.is_elevated
        || token.is_app_container != package.is_some()
        || token.app_container_sid.as_deref() != package
        || token.integrity.level != level
        || token.integrity.rid != rid
        || token.integrity.sid != format!("S-1-16-{rid}")
        || !token.capabilities.is_empty()
    {
        return Err("Held/self/descendant token does not match paired user, PID, integrity or package policy".into());
    }
    Ok(())
}
fn invocation_verified(value: &PairedInvocation) -> bool {
    value.process_id != 0
        && value.exit_code == Some(0)
        && !value.timed_out
        && value.held_token.is_some()
        && value.self_token.is_some()
        && value.held_token == value.self_token
}
fn variant_verified(value: &PairedVariant, candidate: bool) -> bool {
    [
        &value.file_process,
        &value.registry_process,
        &value.child_process,
    ]
    .iter()
    .all(|p| invocation_verified(p))
        && value.file.outcome
            == if candidate {
                ControlAccess::AccessDenied
            } else {
                ControlAccess::Success
            }
        && value.registry.outcome
            == if candidate {
                ControlAccess::AccessDenied
            } else {
                ControlAccess::Success
            }
        && value.child_outcome == ControlAccess::Success
        && value.child_id.is_some()
        && value.child_token.is_some()
        && value.child_stdout_bytes == Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiw_probe::paired_controls::{PairedControlPolicy, paired_control_source_sha256};
    use aiw_token::{ElevationType, IntegrityEvidence};
    fn token(id: u32, candidate: bool) -> TokenEvidence {
        let rid = if candidate { 4096 } else { 8192 };
        TokenEvidence {
            schema_version: aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION.into(),
            process_id: id,
            token_type: TokenType::Primary,
            impersonation_level: None,
            is_app_container: candidate,
            app_container_sid: candidate.then(|| "S-1-15-2-1-2-3-4-5-6-7".into()),
            user_sid: "S-1-5-21-11-22-33-1001".into(),
            integrity: IntegrityEvidence {
                sid: format!("S-1-16-{rid}"),
                rid,
                level: if candidate {
                    IntegrityLevel::Low
                } else {
                    IntegrityLevel::Medium
                },
            },
            elevation_type: ElevationType::Default,
            is_elevated: false,
            capabilities: vec![],
            restricted_sid_count: 0,
        }
    }
    fn invocation(id: u32, candidate: bool) -> PairedInvocation {
        PairedInvocation {
            process_id: id,
            exit_code: Some(0),
            timed_out: false,
            held_token: Some(token(id, candidate)),
            self_token: Some(token(id, candidate)),
            job_empty: Some(true),
        }
    }
    fn read(bytes: &[u8], candidate: bool) -> ControlReadObservation {
        ControlReadObservation {
            resource: if bytes == PAIRED_CONTROL_FILE_BYTES {
                ControlResourceKind::FixedFile
            } else {
                ControlResourceKind::FixedRegistry64
            },
            stage: if bytes == PAIRED_CONTROL_FILE_BYTES {
                ControlReadStage::FileRead
            } else if candidate {
                ControlReadStage::OpenKey
            } else {
                ControlReadStage::QueryValue
            },
            outcome: if candidate {
                ControlAccess::AccessDenied
            } else {
                ControlAccess::Success
            },
            native_code: candidate.then_some(5),
            size_bytes: (!candidate).then_some(29),
            sha256: (!candidate).then(|| hex::encode(Sha256::digest(bytes))),
        }
    }
    fn variant(id: u32, candidate: bool) -> PairedVariant {
        PairedVariant {
            file_process: invocation(id, candidate),
            file: read(PAIRED_CONTROL_FILE_BYTES, candidate),
            registry_process: invocation(id + 1, candidate),
            registry: read(PAIRED_CONTROL_REGISTRY_BYTES, candidate),
            child_process: invocation(id + 2, candidate),
            child_id: Some(id + 3),
            child_token: Some(token(id + 3, candidate)),
            child_stdout_bytes: Some(0),
            child_outcome: ControlAccess::Success,
        }
    }
    fn fixture() -> (PairedControlsRequest, PairedControlResult) {
        let windows = aiw_probe::WindowsVersionObservation {
            major: 10,
            minor: 0,
            build: 28000,
            revision: 1,
            observer_architecture: "x86_64".into(),
        };
        let profile = PairedControlProfile {
            revision: aiw_probe::PAIRED_CONTROL_REVISION.into(),
            source_sha256: paired_control_source_sha256(),
            fixture_sha256: "d".repeat(64),
            fixture_size_bytes: 10,
            launcher_sha256: "d".repeat(64),
            launcher_size_bytes: 10,
            origin: ControlEvidenceOrigin::SyntheticRehearsal,
            expected_windows: windows.clone(),
            policy: PairedControlPolicy::ClassicAppContainerNoCapabilitiesFixedChildOutputGrant,
        };
        let request = PairedControlsRequest::new(
            "paired-one",
            "12345678-1234-4234-8234-123456789abc",
            &"c".repeat(64),
            &"d".repeat(64),
            profile,
        )
        .unwrap();
        let result = PairedControlResult {
            schema_version: PAIRED_CONTROL_RESULT_SCHEMA.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            profile_sha256: request.profile.hash().unwrap(),
            origin: request.profile.origin,
            windows,
            resources: PairedControlResources {
                file_path: r"C:\AIW\Control\SharedCanary\canary.txt".into(),
                file_sha256: hex::encode(Sha256::digest(PAIRED_CONTROL_FILE_BYTES)),
                file_size_bytes: 29,
                file_dacl_before_sha256: "e".repeat(64),
                file_dacl_after_sha256: "e".repeat(64),
                registry_hive: "HKLM".into(),
                registry_view: "registry64".into(),
                registry_key: r"SOFTWARE\AIWControlCanary".into(),
                registry_value: "Canary".into(),
                registry_type: "binary".into(),
                registry_sha256: hex::encode(Sha256::digest(PAIRED_CONTROL_REGISTRY_BYTES)),
                registry_size_bytes: 29,
                registry_dacl_before_sha256: "f".repeat(64),
                registry_dacl_after_sha256: "f".repeat(64),
            },
            launcher_id: 10,
            launcher_token: token(10, false),
            user_sid: "S-1-5-21-11-22-33-1001".into(),
            package_sid: "S-1-15-2-1-2-3-4-5-6-7".into(),
            baseline: variant(20, false),
            candidate: variant(30, true),
            fixture_unchanged: true,
            launcher_unchanged: true,
            file_unchanged: true,
            file_acl_unchanged: true,
            registry_value_unchanged: true,
            registry_acl_unchanged: true,
            profile_deleted: Some(true),
            driver_complete: true,
        };
        (request, result)
    }
    #[test]
    fn synthetic_valid_pair_is_deterministic_but_never_production_acceptance() {
        let (request, result) = fixture();
        let compared = result.compare(&request, Some(true)).unwrap();
        assert!(compared.eligible);
        assert!(compared.baseline_verified && compared.candidate_verified);
        assert!(!compared.production_acceptance);
        assert_eq!(
            request.profile.hash().unwrap(),
            paired_controls_digest(&request.profile).unwrap()
        );
        assert_eq!(compared.origin, ControlEvidenceOrigin::SyntheticRehearsal);
        assert_eq!(
            digest(&compared).unwrap(),
            digest(&result.compare(&request, Some(true)).unwrap()).unwrap()
        );
    }
    #[test]
    fn baseline_candidate_driver_and_cleanup_failures_are_inconclusive() {
        let (request, result) = fixture();
        let mut baseline = result.clone();
        baseline.baseline.file = ControlReadObservation {
            resource: ControlResourceKind::FixedFile,
            stage: ControlReadStage::FileRead,
            outcome: ControlAccess::NotFound,
            native_code: Some(2),
            sha256: None,
            size_bytes: None,
        };
        assert_eq!(
            baseline.compare(&request, Some(true)).unwrap().reason,
            PairedComparisonReason::BaselineFailed
        );
        for outcome in [
            ControlAccess::NotFound,
            ControlAccess::Timeout,
            ControlAccess::Failure,
        ] {
            let mut failed = result.clone();
            failed.candidate.file = ControlReadObservation {
                resource: ControlResourceKind::FixedFile,
                stage: ControlReadStage::FileRead,
                outcome,
                native_code: if outcome == ControlAccess::NotFound {
                    Some(2)
                } else {
                    None
                },
                sha256: None,
                size_bytes: None,
            };
            let report = failed.compare(&request, Some(true)).unwrap();
            assert!(!report.eligible);
            assert_eq!(report.reason, PairedComparisonReason::CandidateFailed);
        }
        let mut broken = result.clone();
        broken.driver_complete = false;
        assert_eq!(
            broken.compare(&request, Some(true)).unwrap().reason,
            PairedComparisonReason::DriverIncomplete
        );
        assert_eq!(
            result.compare(&request, None).unwrap().reason,
            PairedComparisonReason::CleanupUnknown
        );
        let mut changed = result.clone();
        changed.resources.registry_dacl_after_sha256 = "1".repeat(64);
        assert_eq!(
            changed.compare(&request, Some(true)).unwrap().reason,
            PairedComparisonReason::DriverIncomplete
        );
    }
    #[test]
    fn denies_tampering_wrong_native_codes_resource_scope_and_token_provenance() {
        let (request, result) = fixture();
        for index in 0..12 {
            let mut mutated = result.clone();
            match index {
                0 => mutated.candidate.file.native_code = Some(2),
                1 => {
                    mutated.candidate.child_token.as_mut().unwrap().user_sid =
                        "S-1-5-21-9-8-7-1002".into()
                }
                2 => {
                    mutated
                        .candidate
                        .file_process
                        .self_token
                        .as_mut()
                        .unwrap()
                        .process_id = 987
                }
                3 => {
                    mutated
                        .baseline
                        .file_process
                        .held_token
                        .as_mut()
                        .unwrap()
                        .is_elevated = true
                }
                4 => mutated.resources.registry_view = "registry32".into(),
                5 => mutated.resources.registry_key = "SOFTWARE\\Other".into(),
                6 => mutated.origin = ControlEvidenceOrigin::NativeWorker,
                7 => mutated.request_sha256 = "0".repeat(64),
                8 => mutated.windows.build = 26100,
                9 => mutated.candidate.child_id = Some(mutated.baseline.file_process.process_id),
                10 => mutated.candidate.registry.resource = ControlResourceKind::FixedFile,
                11 => mutated.candidate.registry.stage = ControlReadStage::FileRead,
                _ => unreachable!(),
            }
            assert!(
                mutated.compare(&request, Some(true)).is_err(),
                "mutant {index}"
            );
        }
    }
    #[test]
    fn historical_source_commitments_remain_readable_but_cannot_prepare_new_requests() {
        let (request, mut result) = fixture();
        let mut historical = request.profile.clone();
        historical.source_sha256 = "9".repeat(64);
        assert!(historical.validate().is_err());
        assert!(historical.validate_historical().is_ok());
        assert!(
            PairedControlsRequest::new(
                &request.run_id,
                &request.sandbox_id,
                &request.config_sha256,
                &request.agent_sha256,
                historical.clone()
            )
            .is_err()
        );
        let retained = PairedControlsRequest::from_retained_binding(
            &request.run_id,
            &request.sandbox_id,
            &request.config_sha256,
            &request.agent_sha256,
            historical,
        )
        .unwrap();
        result.request_sha256 = retained.request_sha256.clone();
        result.profile_sha256 = retained.profile.hash().unwrap();
        assert!(result.compare(&retained, Some(true)).is_ok());
        assert_eq!(retained.hash().unwrap(), retained.request_sha256);
    }
    #[test]
    fn raw_native_mapping_preserves_missing_denied_timeout_and_validates_scope() {
        let case = |id, mode: &str, result: serde_json::Value| CollectedControlCase {
            process: invocation(id, true),
            report: Some(
                serde_json::json!({"schemaVersion":"aiw.dev/control-fixture-report/v0alpha1","mode":mode,"ownProcessToken":token(id,true),"result":result}),
            ),
        };
        let file = case(
            30,
            "readCanary",
            serde_json::json!({"status":"readCanary","outcome":{"kind":"accessDenied","nativeCode":5}}),
        );
        let registry = case(
            31,
            "readRegistry",
            serde_json::json!({"status":"readRegistry","probe":{"scope":{"hive":"HKLM","view":"registry64","key":"SOFTWARE\\AIWControlCanary","value":"Canary"},"outcome":{"kind":"notFound","nativeCode":2,"stage":"openKey"}}}),
        );
        let child = case(
            32,
            "child",
            serde_json::json!({"status":"childTimeout","childProcessId":33,"cleanupVerified":true}),
        );
        let observed =
            normalize_control_variant(file.clone(), registry.clone(), child.clone()).unwrap();
        assert_eq!(observed.file.outcome, ControlAccess::AccessDenied);
        assert_eq!(observed.registry.outcome, ControlAccess::NotFound);
        assert_eq!(observed.child_outcome, ControlAccess::Timeout);
        assert!(observed.child_token.is_none());
        let mut wrong = registry.clone();
        wrong.report.as_mut().unwrap()["result"]["probe"]["scope"]["view"] =
            serde_json::json!("registry32");
        assert!(normalize_control_variant(file.clone(), wrong, child.clone()).is_err());
        let mut timed_out = file;
        timed_out.process.timed_out = true;
        assert_eq!(
            normalize_control_variant(timed_out, registry, child)
                .unwrap()
                .file
                .outcome,
            ControlAccess::Timeout
        );
    }
    #[test]
    fn incomplete_process_observations_never_gain_verified_functions() {
        let (request, mut result) = fixture();
        result.baseline.child_process.timed_out = true;
        result.baseline.child_token = None;
        let compared = result.compare(&request, Some(true)).unwrap();
        assert!(!compared.baseline_verified);
        assert!(!compared.eligible);
        let (request, mut result) = fixture();
        result.candidate.registry_process.self_token = None;
        assert!(
            !result
                .compare(&request, Some(true))
                .unwrap()
                .candidate_verified
        );
    }
}

/// One exact receipt-bound event; accepts failed/inconclusive measurements as
/// observations, never reconstructs success from a process exit code.
pub fn verify_paired_controls_evidence(
    bytes: &[u8],
    root: &str,
    request: &PairedControlsRequest,
    result: &PairedControlResult,
) -> Result<(), String> {
    result.compare(request, Some(true))?;
    let records = crate::application_token::verified_application_records(bytes, root)?;
    if records.len() != 1
        || records[0].kind != "pairedControls"
        || records[0].source != "aiw-guest-agent"
        || records[0].payload != serde_json::to_value(result).map_err(|e| e.to_string())?
    {
        return Err("Paired result differs from receipt-bound evidence".into());
    }
    Ok(())
}

/// A receipt-bound driver failure carries no invented process, token or access
/// observations. The host still verifies outer cleanup independently.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedControlDriverFailure {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub profile_sha256: String,
    pub origin: ControlEvidenceOrigin,
    pub reason: PairedDriverFailureReason,
    pub progress: Vec<PairedCaseProgress>,
    pub launcher_token: Option<TokenEvidence>,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum PairedDriverFailureReason {
    DriverIncomplete,
}
impl PairedControlDriverFailure {
    pub fn for_request(request: &PairedControlsRequest) -> Result<Self, String> {
        request.validate()?;
        Ok(Self {
            schema_version: "aiw.dev/paired-controls-driver-failure/v0alpha1".into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            profile_sha256: request.profile.hash()?,
            origin: request.profile.origin,
            reason: PairedDriverFailureReason::DriverIncomplete,
            progress: Vec::new(),
            launcher_token: None,
        })
    }
    pub fn validate(&self, request: &PairedControlsRequest) -> Result<(), String> {
        let mut binding = self.clone();
        binding.progress.clear();
        binding.launcher_token = None;
        if binding != Self::for_request(request)? {
            return Err("Paired driver failure binding rejected".into());
        }
        validate_paired_progress(&self.progress)?;
        if let Some(launcher) = &self.launcher_token {
            if !valid_user_sid(&launcher.user_sid) {
                return Err("Partial launcher user rejected".into());
            }
            validate_token(launcher, launcher.process_id, &launcher.user_sid, None)?;
            for case in &self.progress {
                if case
                    .process
                    .held_token
                    .as_ref()
                    .is_none_or(|t| t.user_sid != launcher.user_sid)
                    || case.process.process_id == launcher.process_id
                    || case.observation.child_id == Some(launcher.process_id)
                {
                    return Err("Partial case differs from held launcher provenance".into());
                }
            }
        } else if !self.progress.is_empty() {
            return Err("Partial progress lacks held launcher provenance".into());
        }
        Ok(())
    }
}
pub fn verify_paired_driver_failure_evidence(
    bytes: &[u8],
    root: &str,
    request: &PairedControlsRequest,
    result: &PairedControlDriverFailure,
) -> Result<(), String> {
    result.validate(request)?;
    let records = crate::application_token::verified_application_records(bytes, root)?;
    if records.len() != 1
        || records[0].kind != "pairedControlsDriverFailure"
        || records[0].source != "aiw-guest-agent"
        || records[0].payload != serde_json::to_value(result).map_err(|e| e.to_string())?
    {
        return Err("Paired driver failure differs from receipt-bound evidence".into());
    }
    Ok(())
}

/// Output from the fixed native collector. Failed cases retain actual process
/// observations; an absent raw record remains unmeasured, never access denied.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectedControlCase {
    pub process: PairedInvocation,
    pub report: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum FixedControlCase {
    File,
    Registry,
    Child,
}
pub fn normalize_control_variant(
    file: CollectedControlCase,
    registry: CollectedControlCase,
    child: CollectedControlCase,
) -> Result<PairedVariant, String> {
    let (file_process, file_result) = normalize_control_case(file, FixedControlCase::File)?;
    let (registry_process, registry_result) =
        normalize_control_case(registry, FixedControlCase::Registry)?;
    let (child_process, child_result) = normalize_control_case(child, FixedControlCase::Child)?;
    let mut variant = PairedVariant {
        file_process,
        file: file_result.read.ok_or("File result missing")?,
        registry_process,
        registry: registry_result.read.ok_or("Registry result missing")?,
        child_process,
        child_id: child_result.child_id,
        child_token: child_result.child_token,
        child_stdout_bytes: child_result.child_stdout_bytes,
        child_outcome: child_result.outcome,
    };
    if variant.child_process.timed_out {
        variant.child_outcome = ControlAccess::Timeout;
    }
    Ok(variant)
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedCase {
    pub read: Option<ControlReadObservation>,
    pub child_id: Option<u32>,
    pub child_token: Option<TokenEvidence>,
    pub child_stdout_bytes: Option<u64>,
    pub outcome: ControlAccess,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum PairedVariantKind {
    Baseline,
    Candidate,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedCaseProgress {
    pub variant: PairedVariantKind,
    pub case: FixedControlCase,
    pub process: PairedInvocation,
    pub observation: NormalizedCase,
}
pub fn validate_paired_progress(progress: &[PairedCaseProgress]) -> Result<(), String> {
    use FixedControlCase::{Child, File, Registry};
    use PairedVariantKind::{Baseline, Candidate};
    let order = [
        (Baseline, File),
        (Baseline, Registry),
        (Baseline, Child),
        (Candidate, File),
        (Candidate, Registry),
        (Candidate, Child),
    ];
    if progress.len() > order.len() {
        return Err("Paired progress exceeds fixed cases".into());
    }
    let mut ids = BTreeSet::new();
    let mut user: Option<&str> = None;
    let mut package: Option<&str> = None;
    for (value, expected) in progress.iter().zip(order) {
        if (value.variant, value.case) != expected
            || value.process.process_id == 0
            || !ids.insert(value.process.process_id)
        {
            return Err("Paired progress case order or PID rejected".into());
        }
        let held = value
            .process
            .held_token
            .as_ref()
            .ok_or("Paired progress lacks held token")?;
        if !valid_user_sid(&held.user_sid) {
            return Err("Paired progress user rejected".into());
        }
        if let Some(user) = user {
            if held.user_sid != user {
                return Err("Paired progress user changed".into());
            }
        } else {
            user = Some(&held.user_sid);
        }
        let candidate = value.variant == Candidate;
        if candidate {
            let sid = held
                .app_container_sid
                .as_deref()
                .ok_or("Paired progress package absent")?;
            if !valid_package_sid(sid) || package.is_some_and(|p| p != sid) {
                return Err("Paired progress package changed".into());
            }
            package = Some(sid);
        }
        validate_token(
            held,
            value.process.process_id,
            &held.user_sid,
            if candidate { package } else { None },
        )?;
        if value
            .process
            .self_token
            .as_ref()
            .is_some_and(|self_token| self_token != held)
        {
            return Err("Paired progress self/held token mismatch".into());
        }
        if matches!(
            value.observation.outcome,
            ControlAccess::Success | ControlAccess::AccessDenied | ControlAccess::NotFound
        ) && !invocation_verified(&value.process)
        {
            return Err("Measured progress lacks completed held/self process evidence".into());
        }
        if value.process.timed_out && value.observation.outcome != ControlAccess::Timeout {
            return Err("Timed-out progress has another outcome".into());
        }
        if value.case == Child {
            if value.observation.outcome == ControlAccess::Success
                && (value.observation.child_id.is_none()
                    || value.observation.child_token.is_none()
                    || value.observation.child_stdout_bytes != Some(0))
            {
                return Err("Successful child progress lacks descendant evidence".into());
            }
            if value.observation.read.is_some() {
                return Err("Child progress has a read result".into());
            }
            if let Some(id) = value.observation.child_id {
                if id == 0 || !ids.insert(id) {
                    return Err("Paired progress child PID rejected".into());
                }
                if let Some(token) = &value.observation.child_token {
                    validate_token(
                        token,
                        id,
                        &held.user_sid,
                        if candidate { package } else { None },
                    )?;
                }
            } else if value.observation.child_token.is_some() {
                return Err("Paired progress child token has no PID".into());
            }
        } else {
            let (bytes, resource) = if value.case == File {
                (PAIRED_CONTROL_FILE_BYTES, ControlResourceKind::FixedFile)
            } else {
                (
                    PAIRED_CONTROL_REGISTRY_BYTES,
                    ControlResourceKind::FixedRegistry64,
                )
            };
            let read = value
                .observation
                .read
                .as_ref()
                .ok_or("Paired progress read absent")?;
            read.validate(bytes, resource)?;
            if value.observation.outcome != read.outcome
                || value.observation.child_id.is_some()
                || value.observation.child_token.is_some()
                || value.observation.child_stdout_bytes.is_some()
            {
                return Err("Paired progress read shape rejected".into());
            }
        }
    }
    Ok(())
}
pub fn normalize_control_case(
    mut case: CollectedControlCase,
    mode: FixedControlCase,
) -> Result<(PairedInvocation, NormalizedCase), String> {
    use serde_json::Value;
    // The collector's self_token field is never authority. Only a parsed raw
    // report matched against its held process token may populate it.
    case.process.self_token = None;
    let resource = if mode == FixedControlCase::Registry {
        ControlResourceKind::FixedRegistry64
    } else {
        ControlResourceKind::FixedFile
    };
    let mut result = NormalizedCase {
        read: if mode == FixedControlCase::Child {
            None
        } else {
            Some(ControlReadObservation {
                resource,
                stage: ControlReadStage::NotMeasured,
                outcome: if case.process.timed_out {
                    ControlAccess::Timeout
                } else {
                    ControlAccess::Unmeasured
                },
                native_code: None,
                size_bytes: None,
                sha256: None,
            })
        },
        child_id: None,
        child_token: None,
        child_stdout_bytes: None,
        outcome: ControlAccess::Unmeasured,
    };
    if case.process.timed_out {
        case.process.self_token = None;
        result.outcome = ControlAccess::Timeout;
        return Ok((case.process, result));
    }
    let Some(report) = case.report else {
        return Ok((case.process, result));
    };
    let expected = match mode {
        FixedControlCase::File => "readCanary",
        FixedControlCase::Registry => "readRegistry",
        FixedControlCase::Child => "child",
    };
    if report.as_object().is_none_or(|m| m.len() != 4)
        || report["schemaVersion"] != "aiw.dev/control-fixture-report/v0alpha1"
        || report["mode"] != expected
    {
        return Err("Fixed fixture schema/case mismatch".into());
    }
    let self_token: TokenEvidence = serde_json::from_value(report["ownProcessToken"].clone())
        .map_err(|_| "Malformed fixture self token")?;
    if self_token.process_id != case.process.process_id
        || case.process.held_token.as_ref() != Some(&self_token)
    {
        return Err("Fixture self token differs from held process identity".into());
    }
    case.process.self_token = Some(self_token);
    let raw = &report["result"];
    if raw["status"] == "error" {
        result.outcome = ControlAccess::Failure;
        if let Some(read) = &mut result.read {
            read.outcome = ControlAccess::Failure;
        }
        return Ok((case.process, result));
    }
    if mode == FixedControlCase::Child {
        if raw["status"] == "childTimeout" {
            result.outcome = ControlAccess::Timeout;
            result.child_id = raw["childProcessId"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok());
            return Ok((case.process, result));
        }
        if raw["status"] != "child" {
            return Err("Unsupported child control result".into());
        }
        result.child_id = raw["childProcessId"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok());
        result.child_token = Some(
            serde_json::from_value(raw["childToken"].clone())
                .map_err(|_| "Malformed descendant token")?,
        );
        result.child_stdout_bytes = raw["childStdoutBytes"].as_u64();
        result.outcome = ControlAccess::Success;
        return Ok((case.process, result));
    }
    if raw["status"] != expected {
        return Err("Fixed fixture result kind differs from invoked case".into());
    }
    let (observed, stage) = if mode == FixedControlCase::Registry {
        let scope = &raw["probe"]["scope"];
        if scope.as_object().is_none_or(|m| m.len() != 4)
            || scope["hive"] != "HKLM"
            || scope["view"] != "registry64"
            || scope["key"] != r"SOFTWARE\AIWControlCanary"
            || scope["value"] != "Canary"
        {
            return Err("Registry probe scope differs from approved fixed resource".into());
        }
        let observed = &raw["probe"]["outcome"];
        let stage = match observed["stage"].as_str() {
            Some("openKey") => ControlReadStage::OpenKey,
            Some("querySize") => ControlReadStage::QuerySize,
            Some("queryValue") => ControlReadStage::QueryValue,
            None if observed["kind"] == "success" || observed["kind"] == "invalidValue" => {
                ControlReadStage::QueryValue
            }
            _ => return Err("Registry native stage missing or unsupported".into()),
        };
        (observed, stage)
    } else {
        (&raw["outcome"], ControlReadStage::FileRead)
    };
    let outcome = match observed["kind"].as_str() {
        Some("success") => ControlAccess::Success,
        Some("accessDenied") => ControlAccess::AccessDenied,
        Some("notFound") => ControlAccess::NotFound,
        Some("error" | "nativeFailure" | "invalidValue") => ControlAccess::Failure,
        _ => return Err("Unsupported native control outcome".into()),
    };
    let native_code = observed
        .get("nativeCode")
        .or_else(|| observed.get("rawOsError"))
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok());
    result.read = Some(ControlReadObservation {
        resource,
        stage,
        outcome,
        native_code,
        size_bytes: observed["sizeBytes"].as_u64(),
        sha256: observed["sha256"].as_str().map(str::to_owned),
    });
    result.outcome = outcome;
    Ok((case.process, result))
}
