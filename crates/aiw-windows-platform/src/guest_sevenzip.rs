//! Approved native 7-Zip boundary. Raw records are fresh guest-local stages;
//! only the typed request-bound result crosses the completion-receipt boundary.
use crate::control_appcontainer::research_sevenzip as native;
use aiw_probe::ControlEvidenceOrigin;
use aiw_provider_wsb::sevenzip::*;
use aiw_token::TokenEvidence;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use std::path::Path;

pub fn run_fixed_sevenzip_role() -> Result<u8, String> {
    native::run_production_role().map_err(|e| e.to_string())
}

pub fn execute_fixed_sevenzip(request: &SevenZipRequest) -> Result<SevenZipResult, String> {
    request.validate()?;
    request.profile.validate()?;
    if request.profile.origin != ControlEvidenceOrigin::NativeWorker
        || std::env::current_exe().map_err(|e| e.to_string())?
            != Path::new(r"C:\AIW\Tools\aiw-guest-agent.exe")
    {
        return Err("fixed native 7-Zip agent and native-worker origin required".into());
    }
    let token = aiw_token::collect_current_process_token().map_err(|e| e.to_string())?;
    if !token.is_elevated
        || token.is_app_container
        || token.user_sid
            != crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")
                .map_err(|e| e.to_string())?
    {
        return Err("7-Zip setup requires fixed elevated Sandbox agent".into());
    }
    let windows = crate::observe_windows_version().map_err(|e| e.to_string())?;
    if windows != request.profile.expected_windows {
        return Err(
            "7-Zip guest Windows differs from approved exact version; nothing installed".into(),
        );
    }
    // All operational errors after the approved identity checks retain whatever
    // measured prefix exists. They never become application incompatibility.
    let (stages_owned, operation) = native::execute_production(request);
    let mut stages = Stages {
        issues: operation.is_err(),
    };
    let mut result = SevenZipResult::for_request(request)?;
    result.windows = Some(windows);
    if !stages_owned {
        // A refused preexisting stage root is never this request's observation.
        result.driver_error = Some(SevenZipDriverError::DriverIncomplete);
        return Ok(result);
    }
    result.launcher_token = stages.field("02-launcher", "heldToken");
    if let Some(installation) = stages.read::<InstallExit>("04-install-exit") {
        result.installation = Some(SevenZipInstallation {
            exit_code: Some(installation.exit_code),
            timed_out: false,
            job_empty: Some(installation.job_empty),
            files_after: stages.field("04-install-files", "appFilesAfter"),
        });
    }
    result.code_binding = stages.field("05-workflow-exit", "codeBinding");
    if let (Some(capture), Some(deadline)) = (
        stages.invocation("workflow-00-driver-control"),
        stages.invocation("workflow-01-deadline-control"),
    ) {
        result.driver_controls = Some(SevenZipDriverControls { capture, deadline });
    }
    result.baseline = stages.variant("baseline");
    result.candidate = stages.variant("candidate");
    if let Some(boundary) = stages.read::<Boundary>("workflow-03-boundary") {
        if !boundary.capabilities.is_empty()
            || boundary.grant_scope != "read app/input, write candidate data only"
        {
            stages.issues = true;
        }
        result.package_sid = Some(boundary.profile_sid);
        let baseline_access = if boundary.baseline.exit_code == Some(0)
            && !boundary.baseline.timed_out
            && boundary.baseline.output == b"canary-readable"
        {
            Some(SevenZipAccessObservation {
                native_code: 0,
                read: Some(SevenZipFileDigest::for_bytes(SEVENZIP_CANARY_BYTES)),
            })
        } else {
            None
        };
        let denied = boundary.candidate.exit_code == Some(0)
            && !boundary.candidate.timed_out
            && boundary.candidate.output == b"canary-denied-code5;input-write-delete-denied-code5";
        let denial = || {
            denied.then_some(SevenZipAccessObservation {
                native_code: 5,
                read: None,
            })
        };
        result.canaries = Some(SevenZipCanaries {
            baseline_process: Some(boundary.baseline.typed()),
            candidate_process: Some(boundary.candidate.typed()),
            baseline_outside_read: baseline_access,
            candidate_outside_read: denial(),
            candidate_input_write: denial(),
            candidate_input_file_delete: denial(),
            candidate_input_directory_delete: denial(),
        });
    }
    if result.package_sid.is_none() {
        result.package_sid = stages.field("workflow-app-ready", "profileSid");
    }
    result.profile_deleted = stages.field("workflow-04-profile-cleanup", "deleted");
    if stages.issues {
        result.driver_error = Some(SevenZipDriverError::DriverIncomplete);
    }
    result.validate(request)?;
    Ok(result)
}

struct Stages {
    issues: bool,
}
impl Stages {
    fn read<T: DeserializeOwned>(&mut self, name: &str) -> Option<T> {
        match native::production_stage(name) {
            Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
                Ok(value) => Some(value),
                Err(_) => {
                    self.issues = true;
                    None
                }
            },
            Ok(None) => None,
            Err(_) => {
                self.issues = true;
                None
            }
        }
    }
    fn field<T: DeserializeOwned>(&mut self, name: &str, key: &str) -> Option<T> {
        let value = self.read::<Value>(name)?;
        match value.get(key).cloned().map(serde_json::from_value) {
            Some(Ok(value)) => Some(value),
            _ => {
                self.issues = true;
                None
            }
        }
    }
    fn invocation(&mut self, name: &str) -> Option<SevenZipInvocation> {
        self.read::<RawInvocation>(name).map(|v| v.typed())
    }
    fn variant(&mut self, name: &str) -> Option<SevenZipVariant> {
        let input_before = self.read(&format!("workflow-{name}-input-before"));
        let create = self
            .field::<RawInvocation>(&format!("workflow-{name}-0"), "observation")
            .map(|v| v.typed());
        let test = self
            .field::<RawInvocation>(&format!("workflow-{name}-1"), "observation")
            .map(|v| v.typed());
        let extract = self
            .field::<RawInvocation>(&format!("workflow-{name}-2"), "observation")
            .map(|v| v.typed());
        let verification = self.read::<Verification>(&format!("workflow-{name}-3"));
        if input_before.is_none()
            && create.is_none()
            && test.is_none()
            && extract.is_none()
            && verification.is_none()
        {
            return None;
        }
        let (input_after, extracted, archive) = verification
            .map(|v| (Some(v.input_after), Some(v.actual), Some(v.archive)))
            .unwrap_or_default();
        Some(SevenZipVariant {
            input_before,
            create,
            test,
            extract,
            input_after,
            extracted,
            archive,
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawInvocation {
    token: TokenEvidence,
    exit_code: Option<i32>,
    timed_out: bool,
    job_empty: bool,
    output: Vec<u8>,
}
impl RawInvocation {
    fn typed(&self) -> SevenZipInvocation {
        let capture = SevenZipFileDigest::for_bytes(&self.output);
        SevenZipInvocation {
            process_id: self.token.process_id,
            exit_code: self.exit_code,
            timed_out: self.timed_out,
            held_token: Some(self.token.clone()),
            job_empty: Some(self.job_empty),
            stdout_sha256: Some(capture.sha256),
            stdout_size_bytes: Some(capture.size_bytes),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallExit {
    exit_code: i32,
    job_empty: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Boundary {
    baseline: RawInvocation,
    candidate: RawInvocation,
    profile_sid: String,
    capabilities: Vec<String>,
    grant_scope: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Verification {
    actual: SevenZipInventory,
    archive: SevenZipFileDigest,
    #[serde(rename = "expected")]
    _expected: SevenZipInventory,
    #[serde(rename = "function")]
    _function: String,
    #[serde(rename = "passed")]
    _passed: bool,
    input_after: SevenZipInventory,
}
