//! Approved native 7-Zip boundary. Raw records are fresh guest-local stages;
//! only the typed request-bound result crosses the completion-receipt boundary.
use crate::control_appcontainer::research_sevenzip as native;
use aiw_probe::ControlEvidenceOrigin;
use aiw_provider_wsb::sevenzip::*;
use aiw_token::TokenEvidence;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

pub fn run_fixed_sevenzip_role() -> Result<u8, String> {
    native::run_production_role().map_err(|e| e.to_string())
}

pub fn execute_fixed_sevenzip(request: &SevenZipRequest) -> Result<SevenZipResult, String> {
    request.validate()?;
    request.profile.validate().map_err(|error| {
        format!(
            "{error}; compiled source={}",
            aiw_probe::seven_zip_source_sha256()
        )
    })?;
    let current_image = std::env::current_exe().map_err(|e| e.to_string())?;
    if request.profile.origin != ControlEvidenceOrigin::NativeWorker
        || !native::fixed_role_image(&current_image, r"C:\AIW\Tools\aiw-guest-agent.exe")
    {
        return Err(format!(
            "fixed native 7-Zip agent and native-worker origin required; current image={}",
            current_image.display()
        ));
    }
    let token = aiw_token::collect_current_process_token().map_err(|e| e.to_string())?;
    if !token.is_elevated
        || token.is_app_container
        || token.user_sid
            != crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")
                .map_err(|e| e.to_string())?
    {
        return Err(format!(
            "7-Zip setup requires fixed elevated Sandbox agent; elevated={}, AppContainer={}, user={}",
            token.is_elevated, token.is_app_container, token.user_sid
        ));
    }
    let windows = crate::observe_windows_version().map_err(|e| e.to_string())?;
    if windows != request.profile.expected_windows {
        return Err(format!(
            "7-Zip guest Windows differs from approved exact version; nothing installed; observed={windows:?}; expected={:?}",
            request.profile.expected_windows
        ));
    }
    // All operational errors after the approved identity checks retain whatever
    // measured prefix exists. They never become application incompatibility.
    let (stages_owned, operation) = native::execute_production(request);
    let operation_error = operation.as_ref().err().map(ToString::to_string);
    let mut stages = Stages {
        issues: operation.is_err(),
        diagnostics: operation_error.into_iter().collect(),
        observed: vec![],
    };
    let mut result = SevenZipResult::for_request(request)?;
    result.windows = Some(windows);
    if !stages_owned {
        // A refused preexisting stage root is never this request's observation.
        result.driver_error = Some(SevenZipDriverError::DriverIncomplete);
        result.driver_diagnostic = Some(bound_driver_diagnostic(&format!(
            "Fresh raw-stage ownership refused: {}",
            stages.diagnostics.join("; ")
        )));
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
            stages.issue(
                "workflow-03-boundary",
                "unexpected capabilities or grant scope",
            );
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
    if let Some(error) = stages.field::<String>("99-driver-error", "driverError") {
        stages.issue("99-driver-error", error);
    }
    if let Some(error) = stages.field::<String>("workflow-99-driver-error", "driverError") {
        stages.issue("workflow-99-driver-error", error);
    }
    if let Some(collection) = stages.read::<Value>("07-stage-collection")
        && collection["collectionErrors"]
            .as_array()
            .is_some_and(|errors| !errors.is_empty())
    {
        stages.issue("07-stage-collection", &collection["collectionErrors"]);
    }
    if stages.issues {
        result.driver_error = Some(SevenZipDriverError::DriverIncomplete);
        result.driver_diagnostic = Some(bound_driver_diagnostic(&stages.diagnostics.join("; ")));
    }
    result.validate(request).map_err(|error| format!("Typed observation validation refused: {error}; positive local stage reads={:?}; private driver causes={}", stages.observed, stages.diagnostics.join("; ")))?;
    Ok(result)
}

struct Stages {
    issues: bool,
    diagnostics: Vec<String>,
    observed: Vec<String>,
}
impl Stages {
    fn issue(&mut self, name: &str, detail: impl std::fmt::Display) {
        self.issues = true;
        if self.diagnostics.len() < 16 {
            self.diagnostics.push(format!("{name}: {detail}"));
        }
    }
    fn read<T: DeserializeOwned>(&mut self, name: &str) -> Option<T> {
        match native::production_stage(name) {
            Ok(Some(bytes)) => self.decode(name, &bytes),
            Ok(None) => None,
            Err(error) => {
                self.issue(name, error);
                None
            }
        }
    }
    fn decode<T: DeserializeOwned>(&mut self, name: &str, bytes: &[u8]) -> Option<T> {
        if !self.observed.iter().any(|value| value == name) {
            self.observed.push(name.into());
        }
        match serde_json::from_slice(bytes) {
            Ok(value) => Some(value),
            Err(error) => {
                self.issue(name, error);
                None
            }
        }
    }
    fn field<T: DeserializeOwned>(&mut self, name: &str, key: &str) -> Option<T> {
        let value = self.read::<Value>(name)?;
        match value.get(key).cloned().map(serde_json::from_value) {
            Some(Ok(value)) => Some(value),
            Some(Err(error)) => {
                self.issue(&format!("{name}/{key}"), error);
                None
            }
            None => {
                self.issue(
                    &format!("{name}/{key}"),
                    "required field absent in retained stage",
                );
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

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn sevenzip_stage_decode_preserves_private_cause_without_inventing_a_measurement() {
        let mut stages = Stages {
            issues: false,
            diagnostics: vec![],
            observed: vec![],
        };
        let value = stages.decode::<RawInvocation>("workflow-baseline-0", br#"{"exitCode":"bad"}"#);
        assert!(value.is_none());
        assert!(stages.issues);
        assert_eq!(stages.observed, ["workflow-baseline-0"]);
        assert!(stages.diagnostics[0].contains("workflow-baseline-0"));
        assert!(
            stages.diagnostics[0].contains("missing field")
                || stages.diagnostics[0].contains("invalid type")
        );
    }
}
