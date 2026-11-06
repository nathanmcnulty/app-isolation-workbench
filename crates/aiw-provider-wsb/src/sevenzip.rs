//! Closed receipt-bound 7-Zip observations and fixed workflow normalization.
//! This module never executes, widens grants, or produces a general isolation verdict.
use aiw_probe::SevenZipProfile;
use aiw_probe::paired_controls::{ControlEvidenceOrigin, control_digest, control_hash};
use aiw_token::{IntegrityLevel, TokenEvidence, TokenType};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SEVENZIP_REQUEST_SCHEMA: &str = "aiw.dev/sevenzip-assessment-request/v0alpha1";
pub const SEVENZIP_RESULT_SCHEMA: &str = "aiw.dev/sevenzip-assessment-result/v0alpha1";
pub const SEVENZIP_EVENT: &str = "sevenZipAssessment";
pub const SEVENZIP_DRIVER_BYTES: &[u8] = b"AIW sevenzip driver control\r\n";
pub const SEVENZIP_CANARY_BYTES: &[u8] = b"AIW sevenzip ungranted canary";
pub const MAX_SEVENZIP_DRIVER_DIAGNOSTIC_CHARS: usize = 2048;
pub const MAX_SEVENZIP_DRIVER_DIAGNOSTIC_BYTES: usize = 8192;

/// Private failure text only; this never supplies function or boundary evidence.
/// Truncating Unicode scalar values also bounds UTF-8 bytes to 8192 (4 per scalar).
pub fn bound_driver_diagnostic(value: &str) -> String {
    value
        .chars()
        .take(MAX_SEVENZIP_DRIVER_DIAGNOSTIC_CHARS)
        .collect()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipRequest {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub config_sha256: String,
    pub agent_sha256: String,
    pub request_sha256: String,
    pub profile: SevenZipProfile,
}
impl SevenZipRequest {
    pub fn new(
        run_id: &str,
        sandbox_id: &str,
        config: &str,
        agent: &str,
        profile: SevenZipProfile,
    ) -> Result<Self, String> {
        profile.validate()?;
        Self::from_retained_binding(run_id, sandbox_id, config, agent, profile)
    }
    pub fn from_retained_binding(
        run_id: &str,
        sandbox_id: &str,
        config: &str,
        agent: &str,
        profile: SevenZipProfile,
    ) -> Result<Self, String> {
        let mut value = Self {
            schema_version: SEVENZIP_REQUEST_SCHEMA.into(),
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
        control_digest(&value)
    }
    pub fn validate(&self) -> Result<(), String> {
        self.profile.validate_historical()?;
        if self.schema_version != SEVENZIP_REQUEST_SCHEMA
            || self.run_id.is_empty()
            || self.run_id.len() > 128
            || !self
                .run_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || !crate::imported_bambu::canonical_sandbox_id(&self.sandbox_id)
            || !control_hash(&self.config_sha256)
            || self.agent_sha256 != self.profile.agent_sha256
            || self.request_sha256 != self.hash()?
        {
            return Err("7-Zip exact request binding rejected".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipFileDigest {
    pub sha256: String,
    pub size_bytes: u64,
}
pub type SevenZipInventory = BTreeMap<String, SevenZipFileDigest>;
impl SevenZipFileDigest {
    pub fn for_bytes(bytes: &[u8]) -> Self {
        Self {
            sha256: hex::encode(Sha256::digest(bytes)),
            size_bytes: bytes.len() as u64,
        }
    }
    fn validate(&self) -> Result<(), String> {
        if !control_hash(&self.sha256) || self.size_bytes > 32 * 1024 * 1024 {
            return Err("7-Zip bounded file identity rejected".into());
        }
        Ok(())
    }
}
pub fn sevenzip_fixture_bytes() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            "hello.txt".into(),
            b"App Isolation Workbench archive verification\r\n".to_vec(),
        ),
        (
            "sub folder/Unicode-\u{65e5}\u{672c}.txt".into(),
            "7-Zip UTF-8 text: \u{e9}\u{65e5}\u{672c}\r\n"
                .as_bytes()
                .to_vec(),
        ),
        ("binary.bin".into(), (0..=255).cycle().take(4096).collect()),
        ("empty.txt".into(), vec![]),
    ])
}
pub fn sevenzip_fixture_inventory() -> SevenZipInventory {
    sevenzip_fixture_bytes()
        .into_iter()
        .map(|(name, bytes)| (name, SevenZipFileDigest::for_bytes(&bytes)))
        .collect()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipInvocation {
    pub process_id: u32,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    /// Measured from the retained suspended process handle. Third-party 7-Zip
    /// does not self-report its token; absence is not replaced with a self token.
    pub held_token: Option<TokenEvidence>,
    pub job_empty: Option<bool>,
    pub stdout_sha256: Option<String>,
    pub stdout_size_bytes: Option<u64>,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipInstallation {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub job_empty: Option<bool>,
    pub files_after: Option<SevenZipInventory>,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipCodeBinding {
    pub image_before: SevenZipFileDigest,
    pub image_after: SevenZipFileDigest,
    pub dll_before: SevenZipFileDigest,
    pub dll_after: SevenZipFileDigest,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipDriverControls {
    pub capture: SevenZipInvocation,
    pub deadline: SevenZipInvocation,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipAccessObservation {
    /// Native Win32 result: 0 success, 5 access denied; missing and other codes
    /// remain missing/other errors and never count as a verified denial.
    pub native_code: u32,
    pub read: Option<SevenZipFileDigest>,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipCanaries {
    pub baseline_process: Option<SevenZipInvocation>,
    pub candidate_process: Option<SevenZipInvocation>,
    pub baseline_outside_read: Option<SevenZipAccessObservation>,
    pub candidate_outside_read: Option<SevenZipAccessObservation>,
    pub candidate_input_write: Option<SevenZipAccessObservation>,
    pub candidate_input_file_delete: Option<SevenZipAccessObservation>,
    pub candidate_input_directory_delete: Option<SevenZipAccessObservation>,
}
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipVariant {
    pub input_before: Option<SevenZipInventory>,
    pub create: Option<SevenZipInvocation>,
    pub test: Option<SevenZipInvocation>,
    pub extract: Option<SevenZipInvocation>,
    pub input_after: Option<SevenZipInventory>,
    pub extracted: Option<SevenZipInventory>,
    pub archive: Option<SevenZipFileDigest>,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SevenZipDriverError {
    DriverIncomplete,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipResult {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub profile_sha256: String,
    pub origin: ControlEvidenceOrigin,
    pub windows: Option<aiw_probe::WindowsVersionObservation>,
    pub launcher_token: Option<TokenEvidence>,
    pub package_sid: Option<String>,
    pub installation: Option<SevenZipInstallation>,
    pub code_binding: Option<SevenZipCodeBinding>,
    pub driver_controls: Option<SevenZipDriverControls>,
    pub canaries: Option<SevenZipCanaries>,
    pub baseline: Option<SevenZipVariant>,
    pub candidate: Option<SevenZipVariant>,
    pub profile_deleted: Option<bool>,
    pub driver_error: Option<SevenZipDriverError>,
    /// Private retained failure diagnostics. Never project this text into a safe
    /// summary or treat it as a native observation, denial, or function result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_diagnostic: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SevenZipFunction {
    Create,
    Test,
    Extract,
    Verify,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SevenZipFunctionStatus {
    Passed,
    Failed,
    NotReached,
    Unmeasured,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SevenZipFunctionRow {
    pub function: SevenZipFunction,
    pub baseline: SevenZipFunctionStatus,
    pub candidate: SevenZipFunctionStatus,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SevenZipComparisonReason {
    WorkflowCompared,
    CandidateFunctionFailed,
    BaselineFailed,
    DriverIncomplete,
    RequiredMeasurementsMissing,
    BoundaryControlsFailed,
    CleanupUnknown,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SevenZipComparison {
    pub eligible: bool,
    pub reason: SevenZipComparisonReason,
    pub functions: Vec<SevenZipFunctionRow>,
    pub baseline_verified: bool,
    pub candidate_verified: bool,
    pub selected_controls_verified: bool,
    pub origin: ControlEvidenceOrigin,
    pub production_acceptance: bool,
    pub outer_boundary: &'static str,
    pub inner_boundary: &'static str,
    pub baseline_archive: Option<SevenZipFileDigest>,
    pub candidate_archive: Option<SevenZipFileDigest>,
    pub archive_bytes_equal: Option<bool>,
    pub gaps: Vec<&'static str>,
}

impl SevenZipResult {
    pub fn for_request(request: &SevenZipRequest) -> Result<Self, String> {
        request.validate()?;
        Ok(Self {
            schema_version: SEVENZIP_RESULT_SCHEMA.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            profile_sha256: request.profile.hash()?,
            origin: request.profile.origin,
            windows: None,
            launcher_token: None,
            package_sid: None,
            installation: None,
            code_binding: None,
            driver_controls: None,
            canaries: None,
            baseline: None,
            candidate: None,
            profile_deleted: None,
            driver_error: None,
            driver_diagnostic: None,
        })
    }
    pub fn compare(
        &self,
        request: &SevenZipRequest,
        outer_cleanup: Option<bool>,
    ) -> Result<SevenZipComparison, String> {
        self.validate(request)?;
        let baseline = normalize_variant(self.baseline.as_ref());
        let candidate = normalize_variant(self.candidate.as_ref());
        let baseline_ok = baseline
            .iter()
            .all(|v| *v == SevenZipFunctionStatus::Passed);
        let candidate_ok = candidate
            .iter()
            .all(|v| *v == SevenZipFunctionStatus::Passed);
        let baseline_failed = baseline.contains(&SevenZipFunctionStatus::Failed);
        let candidate_failed = candidate.contains(&SevenZipFunctionStatus::Failed);
        let driver = self
            .driver_controls
            .as_ref()
            .is_some_and(driver_controls_pass)
            && self.installation.as_ref().is_some_and(installation_pass)
            && self.code_binding.as_ref().is_some_and(|code| {
                code.image_before == code.image_after && code.dll_before == code.dll_after
            })
            && self.windows.is_some()
            && self.launcher_token.is_some();
        let controls = self.canaries.as_ref().is_some_and(canaries_pass);
        let cleanup = outer_cleanup == Some(true)
            && self.profile_deleted == Some(true)
            && all_jobs_empty(self);
        let reason = if self.driver_error.is_some() {
            SevenZipComparisonReason::DriverIncomplete
        } else if !driver {
            SevenZipComparisonReason::RequiredMeasurementsMissing
        } else if baseline_failed {
            SevenZipComparisonReason::BaselineFailed
        } else if !baseline_ok {
            SevenZipComparisonReason::RequiredMeasurementsMissing
        } else if !controls {
            SevenZipComparisonReason::BoundaryControlsFailed
        } else if !cleanup {
            SevenZipComparisonReason::CleanupUnknown
        } else if candidate_failed {
            SevenZipComparisonReason::CandidateFunctionFailed
        } else if !candidate_ok {
            SevenZipComparisonReason::RequiredMeasurementsMissing
        } else {
            SevenZipComparisonReason::WorkflowCompared
        };
        let eligible = matches!(
            reason,
            SevenZipComparisonReason::WorkflowCompared
                | SevenZipComparisonReason::CandidateFunctionFailed
        );
        let baseline_archive = self.baseline.as_ref().and_then(|v| v.archive.clone());
        let candidate_archive = self.candidate.as_ref().and_then(|v| v.archive.clone());
        let archive_bytes_equal = baseline_archive
            .as_ref()
            .zip(candidate_archive.as_ref())
            .map(|(a, b)| a == b);
        let mut gaps = vec![
            "generalCompatibilityUnmeasured",
            "generalEffectiveIsolationUnmeasured",
            "allDescendantTokensUnmeasured",
            "networkRegistryIpcUiUnmeasured",
            "guiShellIntegrationUnmeasured",
            "systemWideInstallationChangesUnmeasured",
            "hostEndpointEquivalenceUnmeasured",
        ];
        if archive_bytes_equal == Some(false) {
            gaps.push("archiveByteDifferenceCauseUnmeasured");
        }
        if !eligible {
            gaps.push("comparisonNotEligible");
        }
        Ok(SevenZipComparison {
            eligible,
            reason,
            functions: [
                SevenZipFunction::Create,
                SevenZipFunction::Test,
                SevenZipFunction::Extract,
                SevenZipFunction::Verify,
            ]
            .into_iter()
            .enumerate()
            .map(|(i, function)| SevenZipFunctionRow {
                function,
                baseline: baseline[i],
                candidate: candidate[i],
            })
            .collect(),
            baseline_verified: driver && baseline_ok,
            candidate_verified: driver && baseline_ok && candidate_ok && controls && cleanup,
            selected_controls_verified: driver && controls && cleanup,
            origin: self.origin,
            production_acceptance: false,
            outer_boundary: "Windows Sandbox (disposable measurement worker)",
            inner_boundary: "ordinary user versus classic AppContainer, zero capabilities",
            baseline_archive,
            candidate_archive,
            archive_bytes_equal,
            gaps,
        })
    }
    pub fn validate(&self, request: &SevenZipRequest) -> Result<(), String> {
        request.validate()?;
        if self.driver_diagnostic.as_ref().is_some_and(|value| {
            self.driver_error.is_none()
                || value.chars().count() > MAX_SEVENZIP_DRIVER_DIAGNOSTIC_CHARS
                || value.len() > MAX_SEVENZIP_DRIVER_DIAGNOSTIC_BYTES
        }) {
            return Err(
                "7-Zip private driver diagnostic exceeds bounds or lacks a driver failure".into(),
            );
        }
        if self.schema_version != SEVENZIP_RESULT_SCHEMA
            || self.run_id != request.run_id
            || self.sandbox_id != request.sandbox_id
            || self.request_sha256 != request.request_sha256
            || self.profile_sha256 != request.profile.hash()?
            || self.origin != request.profile.origin
        {
            return Err("7-Zip result differs from exact approved request/profile".into());
        }
        if let Some(windows) = &self.windows {
            windows.validate()?;
            if windows != &request.profile.expected_windows {
                return Err("7-Zip guest version differs".into());
            }
        }
        if let Some(package) = &self.package_sid
            && !valid_package_sid(package)
        {
            return Err("7-Zip package SID malformed".into());
        }
        let mut ids = BTreeSet::new();
        let user = if let Some(token) = &self.launcher_token {
            if !valid_user_sid(&token.user_sid) {
                return Err("7-Zip ordinary user SID malformed".into());
            }
            validate_token(token, token.process_id, &token.user_sid, None)?;
            ids.insert(token.process_id);
            Some(token.user_sid.as_str())
        } else {
            None
        };
        for (invocation, candidate) in invocations(self) {
            let user = user.ok_or("7-Zip process without measured launcher identity")?;
            let package = if candidate {
                Some(
                    self.package_sid
                        .as_deref()
                        .ok_or("candidate process without profile SID")?,
                )
            } else {
                None
            };
            validate_invocation(invocation, user, package, &mut ids)?;
        }
        if let Some(installation) = &self.installation {
            if installation.timed_out && installation.exit_code.is_some() {
                return Err("timed out installer carries exit code".into());
            }
            if let Some(files) = &installation.files_after {
                validate_inventory(files)?;
            }
        }
        if let Some(code) = &self.code_binding {
            for file in [
                &code.image_before,
                &code.image_after,
                &code.dll_before,
                &code.dll_after,
            ] {
                file.validate()?;
                if file.size_bytes == 0 {
                    return Err("empty installed executable".into());
                }
            }
            if let Some(files) = self
                .installation
                .as_ref()
                .and_then(|v| v.files_after.as_ref())
                && (files.get("7z.exe") != Some(&code.image_before)
                    || files.get("7z.dll") != Some(&code.dll_before))
            {
                return Err("installed inventory and held code differ".into());
            }
        }
        for variant in [&self.baseline, &self.candidate].into_iter().flatten() {
            for files in [
                &variant.input_before,
                &variant.input_after,
                &variant.extracted,
            ]
            .into_iter()
            .flatten()
            {
                validate_inventory(files)?;
            }
            if let Some(archive) = &variant.archive {
                archive.validate()?;
                if archive.size_bytes == 0 {
                    return Err("empty archive identity".into());
                }
            }
            validate_stage_order(variant)?;
        }
        if let Some(canaries) = &self.canaries {
            for access in [
                &canaries.baseline_outside_read,
                &canaries.candidate_outside_read,
                &canaries.candidate_input_write,
                &canaries.candidate_input_file_delete,
                &canaries.candidate_input_directory_delete,
            ]
            .into_iter()
            .flatten()
            {
                if let Some(read) = &access.read {
                    read.validate()?;
                    if access.native_code != 0 {
                        return Err("failed access carries successful read bytes".into());
                    }
                }
            }
        }
        Ok(())
    }
}

fn validate_inventory(files: &SevenZipInventory) -> Result<(), String> {
    if files.len() > 512 {
        return Err("7-Zip inventory entry count exceeds bound".into());
    }
    let mut total = 0u64;
    for (path, file) in files {
        if path.is_empty()
            || path.len() > 1024
            || path.contains(['\\', ':', '\0'])
            || path
                .split('/')
                .any(|p| p.is_empty() || matches!(p, "." | "..") || p.ends_with([' ', '.']))
        {
            return Err("7-Zip inventory has unsafe relative path".into());
        }
        file.validate()?;
        total = total
            .checked_add(file.size_bytes)
            .ok_or("inventory byte overflow")?;
    }
    if total > 64 * 1024 * 1024 {
        return Err("7-Zip inventory byte budget exceeds bound".into());
    }
    Ok(())
}
fn valid_user_sid(value: &str) -> bool {
    value.starts_with("S-1-5-21-") && valid_sid_components(value, 8)
}
fn valid_package_sid(value: &str) -> bool {
    value.starts_with("S-1-15-2-") && valid_sid_components(value, 11)
}
fn valid_sid_components(value: &str, count: usize) -> bool {
    value.len() <= 184
        && value.split('-').count() == count
        && value.split('-').skip(1).all(|v| {
            !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) && v.parse::<u32>().is_ok()
        })
}
fn validate_token(
    token: &TokenEvidence,
    pid: u32,
    user: &str,
    package: Option<&str>,
) -> Result<(), String> {
    let (rid, level) = if package.is_some() {
        (4096, IntegrityLevel::Low)
    } else {
        (8192, IntegrityLevel::Medium)
    };
    if pid == 0
        || token.schema_version != aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
        || token.process_id != pid
        || token.token_type != TokenType::Primary
        || token.impersonation_level.is_some()
        || token.user_sid != user
        || token.is_elevated
        || token.is_app_container != package.is_some()
        || token.app_container_sid.as_deref() != package
        || token.integrity.rid != rid
        || token.integrity.level != level
        || token.integrity.sid != format!("S-1-16-{rid}")
        || !token.capabilities.is_empty()
    {
        return Err(
            "7-Zip held token differs from exact user/PID/primary/integrity/zero-capability policy"
                .into(),
        );
    }
    Ok(())
}
fn validate_invocation(
    value: &SevenZipInvocation,
    user: &str,
    package: Option<&str>,
    ids: &mut BTreeSet<u32>,
) -> Result<(), String> {
    if value.process_id == 0
        || !ids.insert(value.process_id)
        || value.timed_out && value.exit_code.is_some()
        || value.stdout_sha256.is_some() != value.stdout_size_bytes.is_some()
        || value
            .stdout_sha256
            .as_deref()
            .is_some_and(|v| !control_hash(v))
        || value.stdout_size_bytes.is_some_and(|v| v > 128 * 1024)
    {
        return Err("7-Zip process/capture observation malformed or duplicated".into());
    }
    if let Some(token) = &value.held_token {
        validate_token(token, value.process_id, user, package)?;
    }
    Ok(())
}
fn invocations(value: &SevenZipResult) -> Vec<(&SevenZipInvocation, bool)> {
    let mut values = vec![];
    if let Some(driver) = &value.driver_controls {
        values.extend([(&driver.capture, false), (&driver.deadline, false)]);
    }
    if let Some(canaries) = &value.canaries {
        if let Some(process) = &canaries.baseline_process {
            values.push((process, false));
        }
        if let Some(process) = &canaries.candidate_process {
            values.push((process, true));
        }
    }
    for (variant, candidate) in [(&value.baseline, false), (&value.candidate, true)] {
        if let Some(variant) = variant {
            for invocation in [&variant.create, &variant.test, &variant.extract]
                .into_iter()
                .flatten()
            {
                values.push((invocation, candidate));
            }
        }
    }
    values
}
fn process_measured(value: &SevenZipInvocation) -> bool {
    value.held_token.is_some()
        && value.job_empty == Some(true)
        && (value.exit_code.is_some() || value.timed_out)
}
fn process_pass(value: &SevenZipInvocation) -> bool {
    process_measured(value) && value.exit_code == Some(0) && !value.timed_out
}
fn normalize_variant(value: Option<&SevenZipVariant>) -> [SevenZipFunctionStatus; 4] {
    use SevenZipFunctionStatus::*;
    let Some(value) = value else {
        return [Unmeasured; 4];
    };
    let fixture = sevenzip_fixture_inventory();
    if value.input_before.as_ref() != Some(&fixture) {
        return [Unmeasured; 4];
    }
    let mut rows = [Unmeasured; 4];
    let mut failed = false;
    for (i, invocation) in [&value.create, &value.test, &value.extract]
        .into_iter()
        .enumerate()
    {
        if failed {
            rows[i] = NotReached;
            continue;
        }
        rows[i] = match invocation {
            Some(p) if process_pass(p) => Passed,
            Some(p) if process_measured(p) => {
                failed = true;
                Failed
            }
            _ => Unmeasured,
        };
    }
    rows[3] = if failed {
        NotReached
    } else if rows[..3].iter().any(|v| *v != Passed)
        || value.input_after.is_none()
        || value.extracted.is_none()
        || value.archive.is_none()
    {
        Unmeasured
    } else if value.input_after.as_ref() == Some(&fixture)
        && value.extracted.as_ref() == Some(&fixture)
    {
        Passed
    } else {
        Failed
    };
    rows
}
fn validate_stage_order(value: &SevenZipVariant) -> Result<(), String> {
    let stages = [&value.create, &value.test, &value.extract];
    for index in 1..3 {
        if stages[index].is_some()
            && !stages[index - 1]
                .as_ref()
                .is_some_and(|v| v.exit_code == Some(0) && !v.timed_out)
        {
            return Err("7-Zip stage continues after missing/failed prior function".into());
        }
    }
    if (value.input_after.is_some() || value.extracted.is_some() || value.archive.is_some())
        && !value
            .extract
            .as_ref()
            .is_some_and(|v| v.exit_code == Some(0) && !v.timed_out)
    {
        return Err("verification artifacts precede successful extraction".into());
    }
    Ok(())
}
fn driver_controls_pass(value: &SevenZipDriverControls) -> bool {
    process_measured(&value.capture)
        && value.capture.exit_code == Some(23)
        && !value.capture.timed_out
        && value.capture.stdout_sha256.as_deref()
            == Some(
                SevenZipFileDigest::for_bytes(SEVENZIP_DRIVER_BYTES)
                    .sha256
                    .as_str(),
            )
        && value.capture.stdout_size_bytes == Some(SEVENZIP_DRIVER_BYTES.len() as u64)
        && value.deadline.held_token.is_some()
        && value.deadline.timed_out
        && value.deadline.exit_code.is_none()
        && value.deadline.job_empty == Some(true)
}
fn installation_pass(value: &SevenZipInstallation) -> bool {
    value.exit_code == Some(0)
        && !value.timed_out
        && value.job_empty == Some(true)
        && value
            .files_after
            .as_ref()
            .is_some_and(|v| v.contains_key("7z.exe") && v.contains_key("7z.dll"))
}
fn canaries_pass(value: &SevenZipCanaries) -> bool {
    value.baseline_process.as_ref().is_some_and(process_pass)
        && value.candidate_process.as_ref().is_some_and(process_pass)
        && value.baseline_outside_read.as_ref().is_some_and(|v| {
            v.native_code == 0
                && v.read == Some(SevenZipFileDigest::for_bytes(SEVENZIP_CANARY_BYTES))
        })
        && [
            &value.candidate_outside_read,
            &value.candidate_input_write,
            &value.candidate_input_file_delete,
            &value.candidate_input_directory_delete,
        ]
        .into_iter()
        .all(|v| {
            v.as_ref()
                .is_some_and(|v| v.native_code == 5 && v.read.is_none())
        })
}
fn all_jobs_empty(value: &SevenZipResult) -> bool {
    invocations(value)
        .iter()
        .all(|(v, _)| v.job_empty == Some(true))
        && value
            .installation
            .as_ref()
            .is_some_and(|v| v.job_empty == Some(true))
}

/// Call only after the existing receipt/evidence-root verification. Exactly one
/// typed event must equal the supplied result; research ZIPs are not this format.
pub fn verify_sevenzip_evidence(
    bytes: &[u8],
    root: &str,
    request: &SevenZipRequest,
    result: &SevenZipResult,
) -> Result<(), String> {
    result.validate(request)?;
    let records = crate::application_token::verified_application_records(bytes, root)?;
    if records.len() != 1
        || records[0].kind != SEVENZIP_EVENT
        || records[0].source != "aiw-guest-agent"
        || records[0].payload != serde_json::to_value(result).map_err(|e| e.to_string())?
    {
        return Err("7-Zip result differs from receipt-bound evidence".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiw_probe::sevenzip::*;
    use aiw_token::{ElevationType, IntegrityEvidence, SidAndAttributes};
    const USER: &str = "S-1-5-21-11-22-33-1001";
    const PACKAGE: &str = "S-1-15-2-1-2-3-4-5-6-7";
    fn token(pid: u32, candidate: bool) -> TokenEvidence {
        let (rid, level) = if candidate {
            (4096, IntegrityLevel::Low)
        } else {
            (8192, IntegrityLevel::Medium)
        };
        TokenEvidence {
            schema_version: aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION.into(),
            process_id: pid,
            token_type: TokenType::Primary,
            impersonation_level: None,
            is_app_container: candidate,
            app_container_sid: candidate.then(|| PACKAGE.into()),
            user_sid: USER.into(),
            integrity: IntegrityEvidence {
                sid: format!("S-1-16-{rid}"),
                rid,
                level,
            },
            elevation_type: ElevationType::Default,
            is_elevated: false,
            capabilities: vec![],
            restricted_sid_count: 0,
        }
    }
    fn process(pid: u32, candidate: bool) -> SevenZipInvocation {
        SevenZipInvocation {
            process_id: pid,
            exit_code: Some(0),
            timed_out: false,
            held_token: Some(token(pid, candidate)),
            job_empty: Some(true),
            stdout_sha256: Some(SevenZipFileDigest::for_bytes(b"synthetic output").sha256),
            stdout_size_bytes: Some(16),
        }
    }
    fn variant(first: u32, candidate: bool) -> SevenZipVariant {
        SevenZipVariant {
            input_before: Some(sevenzip_fixture_inventory()),
            create: Some(process(first, candidate)),
            test: Some(process(first + 1, candidate)),
            extract: Some(process(first + 2, candidate)),
            input_after: Some(sevenzip_fixture_inventory()),
            extracted: Some(sevenzip_fixture_inventory()),
            archive: Some(SevenZipFileDigest {
                sha256: if candidate {
                    "c".repeat(64)
                } else {
                    "b".repeat(64)
                },
                size_bytes: if candidate { 579 } else { 578 },
            }),
        }
    }
    fn fixture() -> (SevenZipRequest, SevenZipResult) {
        let profile = SevenZipProfile {
            revision: SEVENZIP_PROFILE_REVISION.into(),
            source_sha256: seven_zip_source_sha256(),
            installer_sha256: SEVENZIP_INSTALLER_SHA256.into(),
            installer_size_bytes: SEVENZIP_INSTALLER_SIZE_BYTES,
            agent_sha256: "a".repeat(64),
            agent_size_bytes: 100,
            launcher_sha256: "a".repeat(64),
            launcher_size_bytes: 100,
            origin: ControlEvidenceOrigin::SyntheticRehearsal,
            expected_windows: aiw_probe::paired_controls::parse_guest_windows("10.0.26100.2")
                .unwrap(),
            expected_host_windows: aiw_probe::paired_controls::parse_guest_windows("10.0.26300.1")
                .unwrap(),
            policy: SevenZipPolicy::ClassicAppContainerNoCapabilitiesReadInputWriteOutput,
        };
        let request = SevenZipRequest::new(
            "synthetic-sevenzip",
            "11111111-2222-3333-4444-555555555555",
            &"f".repeat(64),
            &"a".repeat(64),
            profile,
        )
        .unwrap();
        let mut result = SevenZipResult::for_request(&request).unwrap();
        result.windows = Some(request.profile.expected_windows.clone());
        result.launcher_token = Some(token(1, false));
        result.package_sid = Some(PACKAGE.into());
        let image = SevenZipFileDigest::for_bytes(b"synthetic image");
        let dll = SevenZipFileDigest::for_bytes(b"synthetic dll");
        result.installation = Some(SevenZipInstallation {
            exit_code: Some(0),
            timed_out: false,
            job_empty: Some(true),
            files_after: Some(BTreeMap::from([
                ("7z.exe".into(), image.clone()),
                ("7z.dll".into(), dll.clone()),
            ])),
        });
        result.code_binding = Some(SevenZipCodeBinding {
            image_before: image.clone(),
            image_after: image,
            dll_before: dll.clone(),
            dll_after: dll,
        });
        let mut capture = process(2, false);
        capture.exit_code = Some(23);
        let bytes = SevenZipFileDigest::for_bytes(SEVENZIP_DRIVER_BYTES);
        capture.stdout_sha256 = Some(bytes.sha256);
        capture.stdout_size_bytes = Some(bytes.size_bytes);
        let mut deadline = process(3, false);
        deadline.exit_code = None;
        deadline.timed_out = true;
        result.driver_controls = Some(SevenZipDriverControls { capture, deadline });
        let denied = Some(SevenZipAccessObservation {
            native_code: 5,
            read: None,
        });
        result.canaries = Some(SevenZipCanaries {
            baseline_process: Some(process(4, false)),
            candidate_process: Some(process(5, true)),
            baseline_outside_read: Some(SevenZipAccessObservation {
                native_code: 0,
                read: Some(SevenZipFileDigest::for_bytes(SEVENZIP_CANARY_BYTES)),
            }),
            candidate_outside_read: denied.clone(),
            candidate_input_write: denied.clone(),
            candidate_input_file_delete: denied.clone(),
            candidate_input_directory_delete: denied,
        });
        result.baseline = Some(variant(10, false));
        result.candidate = Some(variant(20, true));
        result.profile_deleted = Some(true);
        (request, result)
    }
    #[test]
    fn sevenzip_success_matrix_uses_content_not_archive_byte_equality_and_never_claims_general_isolation()
     {
        let (request, result) = fixture();
        let comparison = result.compare(&request, Some(true)).unwrap();
        assert!(
            comparison.eligible
                && comparison.baseline_verified
                && comparison.candidate_verified
                && comparison.selected_controls_verified
        );
        assert_eq!(comparison.functions.len(), 4);
        assert!(
            comparison
                .functions
                .iter()
                .all(|v| v.baseline == SevenZipFunctionStatus::Passed
                    && v.candidate == SevenZipFunctionStatus::Passed)
        );
        assert_eq!(comparison.archive_bytes_equal, Some(false));
        assert_eq!(comparison.baseline_archive.unwrap().size_bytes, 578);
        assert_eq!(comparison.candidate_archive.unwrap().size_bytes, 579);
        assert!(
            comparison
                .gaps
                .contains(&"archiveByteDifferenceCauseUnmeasured")
        );
        assert!(!comparison.production_acceptance);
        let inventory = sevenzip_fixture_inventory();
        assert_eq!(inventory.len(), 4);
        assert_eq!(inventory.values().map(|v| v.size_bytes).sum::<u64>(), 4170);
    }
    #[test]
    fn sevenzip_wrong_tokens_request_origin_and_code_inventory_are_rejected() {
        let (request, result) = fixture();
        for case in 0..12 {
            let mut bad = result.clone();
            match case {
                0 => bad.request_sha256 = "0".repeat(64),
                1 => bad.origin = ControlEvidenceOrigin::NativeWorker,
                2 => bad.windows.as_mut().unwrap().build += 1,
                3 => {
                    bad.candidate
                        .as_mut()
                        .unwrap()
                        .create
                        .as_mut()
                        .unwrap()
                        .held_token
                        .as_mut()
                        .unwrap()
                        .is_elevated = true
                }
                4 => {
                    bad.candidate
                        .as_mut()
                        .unwrap()
                        .create
                        .as_mut()
                        .unwrap()
                        .held_token
                        .as_mut()
                        .unwrap()
                        .user_sid = "S-1-5-21-99-88-77-1001".into()
                }
                5 => {
                    bad.candidate
                        .as_mut()
                        .unwrap()
                        .create
                        .as_mut()
                        .unwrap()
                        .held_token
                        .as_mut()
                        .unwrap()
                        .app_container_sid = Some("S-1-15-2-7-6-5-4-3-2-1".into())
                }
                6 => bad
                    .candidate
                    .as_mut()
                    .unwrap()
                    .create
                    .as_mut()
                    .unwrap()
                    .held_token
                    .as_mut()
                    .unwrap()
                    .capabilities
                    .push(SidAndAttributes {
                        sid: "S-1-15-3-1".into(),
                        attributes: 4,
                    }),
                7 => {
                    bad.candidate
                        .as_mut()
                        .unwrap()
                        .create
                        .as_mut()
                        .unwrap()
                        .held_token
                        .as_mut()
                        .unwrap()
                        .process_id = 100
                }
                8 => {
                    bad.candidate
                        .as_mut()
                        .unwrap()
                        .create
                        .as_mut()
                        .unwrap()
                        .process_id = 10
                }
                9 => {
                    bad.code_binding.as_mut().unwrap().image_before =
                        SevenZipFileDigest::for_bytes(b"otherimage")
                }
                10 => {
                    bad.baseline
                        .as_mut()
                        .unwrap()
                        .input_before
                        .as_mut()
                        .unwrap()
                        .insert("../escape".into(), SevenZipFileDigest::for_bytes(b"x"));
                }
                _ => {
                    bad.candidate
                        .as_mut()
                        .unwrap()
                        .create
                        .as_mut()
                        .unwrap()
                        .timed_out = true;
                }
            };
            assert!(bad.compare(&request, Some(true)).is_err(), "case{case}");
        }
    }
    #[test]
    fn sevenzip_candidate_failure_is_useful_but_broken_baseline_never_is_incompatibility() {
        let (request, result) = fixture();
        let mut candidate = result.clone();
        let variant = candidate.candidate.as_mut().unwrap();
        variant.create.as_mut().unwrap().exit_code = Some(2);
        variant.test = None;
        variant.extract = None;
        variant.input_after = None;
        variant.extracted = None;
        variant.archive = None;
        let comparison = candidate.compare(&request, Some(true)).unwrap();
        assert!(comparison.eligible);
        assert_eq!(
            comparison.reason,
            SevenZipComparisonReason::CandidateFunctionFailed
        );
        assert_eq!(
            comparison.functions[0].candidate,
            SevenZipFunctionStatus::Failed
        );
        assert_eq!(
            comparison.functions[1].candidate,
            SevenZipFunctionStatus::NotReached
        );
        let mut baseline = result;
        let variant = baseline.baseline.as_mut().unwrap();
        variant.create.as_mut().unwrap().exit_code = Some(2);
        variant.test = None;
        variant.extract = None;
        variant.input_after = None;
        variant.extracted = None;
        variant.archive = None;
        baseline.candidate = None;
        let comparison = baseline.compare(&request, Some(true)).unwrap();
        assert!(!comparison.eligible);
        assert_eq!(comparison.reason, SevenZipComparisonReason::BaselineFailed);
    }
    #[test]
    fn sevenzip_missing_capture_denials_cleanup_and_driver_failures_cannot_pass() {
        let (request, result) = fixture();
        for case in 0..8 {
            let mut bad = result.clone();
            match case {
                0 => {
                    bad.driver_controls.as_mut().unwrap().capture.stdout_sha256 =
                        Some("0".repeat(64))
                }
                1 => {
                    bad.canaries
                        .as_mut()
                        .unwrap()
                        .candidate_outside_read
                        .as_mut()
                        .unwrap()
                        .native_code = 2
                }
                2 => bad.canaries.as_mut().unwrap().candidate_input_file_delete = None,
                3 => bad.profile_deleted = None,
                4 => bad.driver_error = Some(SevenZipDriverError::DriverIncomplete),
                5 => {
                    bad.candidate
                        .as_mut()
                        .unwrap()
                        .extract
                        .as_mut()
                        .unwrap()
                        .job_empty = None
                }
                6 => bad.candidate.as_mut().unwrap().extracted = None,
                _ => {
                    bad.code_binding.as_mut().unwrap().dll_after =
                        SevenZipFileDigest::for_bytes(b"changed")
                }
            };
            assert!(
                !bad.compare(&request, Some(true)).unwrap().eligible,
                "case{case}"
            );
        }
        assert!(!result.compare(&request, None).unwrap().eligible);
        let missing = SevenZipResult::for_request(&request)
            .unwrap()
            .compare(&request, Some(true))
            .unwrap();
        assert!(
            missing
                .functions
                .iter()
                .all(|v| v.baseline == SevenZipFunctionStatus::Unmeasured
                    && v.candidate == SevenZipFunctionStatus::Unmeasured)
        );
    }
    #[test]
    fn sevenzip_verification_detects_empty_missing_extra_and_changed_extracted_files() {
        let (request, result) = fixture();
        for case in 0..4 {
            let mut changed = result.clone();
            let files = changed
                .candidate
                .as_mut()
                .unwrap()
                .extracted
                .as_mut()
                .unwrap();
            match case {
                0 => files.clear(),
                1 => {
                    files.remove("empty.txt");
                }
                2 => {
                    files.insert("extra.txt".into(), SevenZipFileDigest::for_bytes(b"extra"));
                }
                _ => {
                    files.insert(
                        "hello.txt".into(),
                        SevenZipFileDigest::for_bytes(b"changed"),
                    );
                }
            }
            let comparison = changed.compare(&request, Some(true)).unwrap();
            assert!(comparison.eligible);
            assert_eq!(
                comparison.functions[3].candidate,
                SevenZipFunctionStatus::Failed
            );
        }
    }
    fn evidence(payload: serde_json::Value, kind: &str) -> (Vec<u8>, String) {
        let mut log = aiw_evidence::EvidenceLog::new();
        log.append(aiw_evidence::EvidenceEvent {
            observed_utc: "synthetic-not-clock-authority".into(),
            kind: kind.into(),
            source: "aiw-guest-agent".into(),
            payload,
        })
        .unwrap();
        let mut bytes = vec![];
        for record in log.records() {
            serde_json::to_writer(&mut bytes, record).unwrap();
            bytes.push(b'\n');
        }
        (bytes, log.manifest().unwrap().root_hash)
    }
    #[test]
    fn sevenzip_receipt_event_reverification_rejects_summary_substitution_research_and_drift() {
        let (request, result) = fixture();
        let (bytes, root) = evidence(serde_json::to_value(&result).unwrap(), SEVENZIP_EVENT);
        verify_sevenzip_evidence(&bytes, &root, &request, &result).unwrap();
        let mut changed = result.clone();
        changed.candidate.as_mut().unwrap().extracted = None;
        assert!(verify_sevenzip_evidence(&bytes, &root, &request, &changed).is_err());
        assert!(verify_sevenzip_evidence(&bytes, &"0".repeat(64), &request, &result).is_err());
        let (research, root) = evidence(
            serde_json::json!({"productionEvidence":false,"driverCompleted":true}),
            "researchSevenZip",
        );
        assert!(verify_sevenzip_evidence(&research, &root, &request, &result).is_err());
        let mut supplied = serde_json::to_value(&result).unwrap();
        supplied["candidateCompatible"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SevenZipResult>(supplied).is_err());
    }
    #[test]
    fn sevenzip_private_driver_diagnostic_is_unicode_bounded_and_failure_only() {
        let (request, result) = fixture();
        let bounded = bound_driver_diagnostic(&"\u{1f9ea}".repeat(3000));
        assert_eq!(bounded.chars().count(), 2048);
        assert_eq!(bounded.len(), 8192);
        assert_eq!(
            bound_driver_diagnostic("native stage failed"),
            "native stage failed"
        );
        let mut failed = result.clone();
        failed.driver_error = Some(SevenZipDriverError::DriverIncomplete);
        failed.driver_diagnostic = Some(bounded);
        failed.validate(&request).unwrap();
        failed.driver_diagnostic = Some("\u{1f9ea}".repeat(2049));
        assert!(failed.validate(&request).is_err());
        failed.driver_diagnostic = Some("x".repeat(2049));
        assert!(failed.validate(&request).is_err());
        let mut healthy = result;
        healthy.driver_diagnostic = Some(String::new());
        assert!(healthy.validate(&request).is_err());
    }
    #[test]
    fn sevenzip_absent_diagnostic_preserves_historical_payload_and_receipt_event_bytes() {
        let (request, result) = fixture();
        assert_eq!(
            result.schema_version,
            "aiw.dev/sevenzip-assessment-result/v0alpha1"
        );
        let historical = serde_json::to_value(&result).unwrap();
        assert!(historical.get("driverDiagnostic").is_none());
        let (before, root) = evidence(historical.clone(), SEVENZIP_EVENT);
        let parsed: SevenZipResult = serde_json::from_value(historical.clone()).unwrap();
        assert_eq!(parsed.driver_diagnostic, None);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), historical);
        let (after, after_root) = evidence(serde_json::to_value(&parsed).unwrap(), SEVENZIP_EVENT);
        assert_eq!(before, after);
        assert_eq!(root, after_root);
        verify_sevenzip_evidence(&before, &root, &request, &parsed).unwrap();
    }
    #[test]
    fn sevenzip_private_diagnostic_is_receipt_bound_and_never_supplies_function_measurements() {
        let (request, _) = fixture();
        let mut failed = SevenZipResult::for_request(&request).unwrap();
        failed.driver_error = Some(SevenZipDriverError::DriverIncomplete);
        let before = failed.compare(&request, Some(true)).unwrap();
        failed.driver_diagnostic=Some("PRIVATE C:\\synthetic\\input; all functions passed and every file denied (untrusted diagnostic text)".into());
        let after = failed.compare(&request, Some(true)).unwrap();
        assert_eq!(before, after);
        assert!(
            !after.eligible
                && !after.baseline_verified
                && !after.candidate_verified
                && !after.selected_controls_verified
        );
        assert!(
            after
                .functions
                .iter()
                .all(|row| row.baseline == SevenZipFunctionStatus::Unmeasured
                    && row.candidate == SevenZipFunctionStatus::Unmeasured)
        );
        let (bytes, root) = evidence(serde_json::to_value(&failed).unwrap(), SEVENZIP_EVENT);
        verify_sevenzip_evidence(&bytes, &root, &request, &failed).unwrap();
        failed.driver_diagnostic = Some("different private cause".into());
        assert!(verify_sevenzip_evidence(&bytes, &root, &request, &failed).is_err());
    }
}
