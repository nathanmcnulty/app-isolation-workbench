//! Approved native 7-Zip boundary. Raw records are fresh guest-local stages;
//! only the typed request-bound result crosses the completion-receipt boundary.
use crate::control_appcontainer::research_sevenzip as native;
use aiw_probe::ControlEvidenceOrigin;
use aiw_provider_wsb::sevenzip::*;
use aiw_token::TokenEvidence;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
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
    let installation_trace = stages
        .read::<aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionTrace>(
        "04-install-trace",
    );
    if let Some(installation) = stages.read::<InstallExit>("04-install-exit") {
        let mut trace = installation.execution_trace;
        merge_trace(
            &mut stages,
            "04-install-trace",
            &mut trace,
            installation_trace,
        );
        result.installation = Some(SevenZipInstallation {
            exit_code: installation.exit_code,
            timed_out: installation.timed_out,
            job_empty: Some(installation.job_empty),
            files_after: stages.field("04-install-files", "appFilesAfter"),
            execution_trace: trace,
        });
    } else if let Some(trace) = installation_trace {
        stages.issue(
            "04-install-exit",
            "installer row missing; retained actual partial execution trace",
        );
        result.installation = Some(SevenZipInstallation {
            exit_code: trace_root_exit(&trace),
            timed_out: trace.chain.timed_out,
            job_empty: trace.chain.job_active_processes.map(|count| count == 0),
            files_after: stages.field("04-install-files", "appFilesAfter"),
            execution_trace: Some(trace),
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
    if let Some(error) = result.execution_trace_problem(request) {
        stages.issue("execution-traces", error);
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
                if let Some(metadata) = refused_trace_diagnostic(name, bytes) {
                    self.issues = true;
                    // This small source-defined refusal precedes generic errors
                    // so the final 2048-character private diagnostic retains it.
                    // Keep the original decode cause and prior actual errors as
                    // space permits; never manufacture a typed trace from this.
                    self.diagnostics.insert(0, format!(
                        "{name}: trace refusal metadata (not a complete trace): {metadata}; decode error: {}",
                        error.to_string().chars().take(128).collect::<String>(),
                    ));
                    self.diagnostics.truncate(16);
                } else {
                    self.issue(name, error);
                }
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
        let create = self.application_invocation(name, 0);
        let test = self.application_invocation(name, 1);
        let extract = self.application_invocation(name, 2);
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
            artifacts: self.read(&format!("workflow-{name}-artifacts")),
        })
    }
    fn application_invocation(&mut self, variant: &str, index: u8) -> Option<SevenZipInvocation> {
        // Callers above supply only this fixed pair and the three closed roles.
        if !matches!(variant, "baseline" | "candidate") || index > 2 {
            self.issue("execution-trace", "unknown fixed application trace role");
            return None;
        }
        let name = format!("workflow-{variant}-{index}");
        let invocation = self
            .field::<RawInvocation>(&name, "observation")
            .map(|v| v.typed());
        let trace = self
            .read::<aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionTrace>(&format!(
                "{name}-trace"
            ));
        retain_application_trace(self, &name, invocation, trace)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TraceRefusalMetadata {
    trace_refused: String,
    complete_serialized_size_bytes: u64,
    complete_serialized_sha256: String,
    complete_trace_retained: bool,
    phase: aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionPhase,
    root_process_id: u32,
    events_processed: u32,
    job_total_processes: Option<u32>,
    job_active_processes: Option<u32>,
    owned_job_termination_requested: bool,
    owned_job_termination_succeeded: bool,
    requires_debugger_process_exit: bool,
    application_incompatibility: bool,
}

fn fixed_trace_phase(
    name: &str,
) -> Option<aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionPhase> {
    use aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionPhase::*;
    match name {
        "04-install-trace" => Some(InstallationSetup),
        "workflow-baseline-0-trace" | "workflow-candidate-0-trace" => Some(Create),
        "workflow-baseline-1-trace" | "workflow-candidate-1-trace" => Some(Test),
        "workflow-baseline-2-trace" | "workflow-candidate-2-trace" => Some(Extract),
        _ => None,
    }
}

fn refused_trace_diagnostic(name: &str, bytes: &[u8]) -> Option<String> {
    let phase = fixed_trace_phase(name)?;
    if bytes.len() > 4096 {
        return None;
    }
    let value: Value = serde_json::from_slice(bytes).ok()?;
    // Require all thirteen keys, including explicitly null unknown counters.
    // deny_unknown_fields below prevents a replacement key hiding a missing one.
    if value.as_object()?.len() != 13 {
        return None;
    }
    let refusal: TraceRefusalMetadata = serde_json::from_slice(bytes).ok()?;
    if refusal.trace_refused != "execution trace exceeds fixed 128 KiB stage limit"
        || refusal.complete_trace_retained
        || refusal.application_incompatibility
        || refusal.phase != phase
        || refusal.complete_serialized_size_bytes <= 128 * 1024
        // Conservative upper bound for the bounded native 64-process report,
        // including escaped paths/tokens and duplicated lifetime observations.
        || refusal.complete_serialized_size_bytes > 64 * 1024 * 1024
        || refusal.complete_serialized_sha256.len() != 64
        || !refusal.complete_serialized_sha256.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || refusal.root_process_id == 0
        || refusal.events_processed > aiw_provider_wsb::sevenzip_process_tree::MAX_CHAIN_EVENTS
    {
        return None;
    }
    // Report these values as private refusal metadata, never cleanup proof.
    let compact = serde_json::to_string(&refusal).ok()?;
    (compact.len() <= 1024).then_some(compact)
}

fn trace_root_exit(
    trace: &aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionTrace,
) -> Option<i32> {
    trace
        .chain
        .processes
        .first()
        .filter(|process| {
            process.ordinal == 0 && process.process_id == trace.root_binding.process_id
        })
        .and_then(|process| process.exit_code)
        .map(|code| code as i32)
}

fn merge_trace(
    stages: &mut Stages,
    name: &str,
    existing: &mut Option<aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionTrace>,
    retained: Option<aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionTrace>,
) {
    if let Some(retained) = retained {
        if existing.as_ref().is_some_and(|trace| trace != &retained) {
            stages.issue(
                name,
                "dedicated trace differs from invocation trace; both raw stages remain local",
            );
        } else if existing.is_none() {
            *existing = Some(retained);
        }
    }
}

fn retain_application_trace(
    stages: &mut Stages,
    name: &str,
    invocation: Option<SevenZipInvocation>,
    trace: Option<aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionTrace>,
) -> Option<SevenZipInvocation> {
    if let Some(mut invocation) = invocation {
        merge_trace(stages, name, &mut invocation.execution_trace, trace);
        return Some(invocation);
    }
    trace.map(|trace| {
        stages.issue(
            name,
            "invocation row missing; retained actual partial execution trace",
        );
        SevenZipInvocation {
            process_id: trace.root_binding.process_id,
            exit_code: trace_root_exit(&trace),
            timed_out: trace.chain.timed_out,
            held_token: Some(trace.root_binding.held_token.clone()),
            job_empty: trace.chain.job_active_processes.map(|count| count == 0),
            stdout_sha256: None,
            stdout_size_bytes: None,
            execution_trace: Some(trace),
        }
    })
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawInvocation {
    token: TokenEvidence,
    #[serde(default, deserialize_with = "native_exit_code")]
    exit_code: Option<i32>,
    timed_out: bool,
    job_empty: bool,
    output: Vec<u8>,
    #[serde(default)]
    execution_trace: Option<aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionTrace>,
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
            execution_trace: self.execution_trace.clone(),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallExit {
    // Preserve both historical signed and native unsigned exit-code bit patterns.
    #[serde(default, deserialize_with = "native_exit_code")]
    exit_code: Option<i32>,
    #[serde(default)]
    timed_out: bool,
    job_empty: bool,
    #[serde(default)]
    execution_trace: Option<aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionTrace>,
}

fn native_exit_code<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i32>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NativeExit {
        Signed(i32),
        Unsigned(u32),
    }
    Option::<NativeExit>::deserialize(deserializer).map(|value| {
        value.map(|code| match code {
            NativeExit::Signed(code) => code,
            NativeExit::Unsigned(code) => code as i32,
        })
    })
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
                || stages.diagnostics[0]
                    .contains("did not match any variant of untagged enum NativeExit")
        );
    }

    #[test]
    fn installer_exit_parsing_preserves_old_rows_timeout_and_unsigned_bit_patterns() {
        let old: InstallExit =
            serde_json::from_slice(br#"{"exitCode":0,"jobEmpty":true}"#).unwrap();
        assert_eq!(old.exit_code, Some(0));
        assert!(!old.timed_out && old.execution_trace.is_none());
        let high: InstallExit =
            serde_json::from_slice(br#"{"exitCode":4294967295,"timedOut":false,"jobEmpty":true}"#)
                .unwrap();
        assert_eq!(high.exit_code, Some(-1));
        let timeout: InstallExit =
            serde_json::from_slice(br#"{"exitCode":null,"timedOut":true,"jobEmpty":false}"#)
                .unwrap();
        assert!(timeout.timed_out && timeout.exit_code.is_none());
        assert!(
            serde_json::from_slice::<InstallExit>(br#"{"exitCode":4294967296,"jobEmpty":true}"#)
                .is_err()
        );
    }

    fn overflow_refusal(phase: &str) -> Value {
        serde_json::json!({
            "traceRefused":"execution trace exceeds fixed 128 KiB stage limit",
            "completeSerializedSizeBytes":200000,"completeSerializedSha256":"a".repeat(64),
            "completeTraceRetained":false,"phase":phase,"rootProcessId":123,"eventsProcessed":4096,
            "jobTotalProcesses":7,"jobActiveProcesses":null,
            "ownedJobTerminationRequested":true,"ownedJobTerminationSucceeded":false,
            "requiresDebuggerProcessExit":true,"applicationIncompatibility":false
        })
    }

    #[test]
    fn overflow_refusal_retains_private_metadata_without_creating_a_trace() {
        use aiw_provider_wsb::sevenzip_execution_trace::SevenZipExecutionTrace;
        for (name, phase) in [
            ("04-install-trace", "installationSetup"),
            ("workflow-baseline-0-trace", "create"),
            ("workflow-candidate-0-trace", "create"),
            ("workflow-baseline-1-trace", "test"),
            ("workflow-candidate-1-trace", "test"),
            ("workflow-baseline-2-trace", "extract"),
            ("workflow-candidate-2-trace", "extract"),
        ] {
            let mut stages = Stages {
                issues: false,
                diagnostics: vec![format!("original operation cause: {}", "x".repeat(3000)); 16],
                observed: vec![],
            };
            let bytes = serde_json::to_vec(&overflow_refusal(phase)).unwrap();
            assert!(
                stages
                    .decode::<SevenZipExecutionTrace>(name, &bytes)
                    .is_none()
            );
            assert!(stages.issues);
            assert_eq!(stages.diagnostics.len(), 16);
            let diagnostic = bound_driver_diagnostic(&stages.diagnostics.join("; "));
            assert!(diagnostic.chars().count() <= 2048);
            for expected in [
                "trace refusal metadata (not a complete trace)",
                "execution trace exceeds fixed 128 KiB stage limit",
                "\"completeSerializedSizeBytes\":200000",
                "\"completeSerializedSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
                "\"completeTraceRetained\":false",
                "\"jobTotalProcesses\":7",
                "\"jobActiveProcesses\":null",
                "\"ownedJobTerminationSucceeded\":false",
                "decode error:",
                "original operation cause:",
            ] {
                assert!(diagnostic.contains(expected), "missing {expected}");
            }
            // No invocation, exit or successful cleanup is constructed; only
            // the failure diagnostic crosses the existing receipt boundary.
        }
    }

    #[test]
    fn malformed_or_foreign_refusals_never_acquire_known_metadata_status() {
        let original = overflow_refusal("create");
        let bytes = serde_json::to_vec(&original).unwrap();
        for name in [
            "workflow-baseline-3-trace",
            "workflow-baseline-0",
            "foreign",
            "04-install-exit",
        ] {
            assert!(refused_trace_diagnostic(name, &bytes).is_none());
        }
        for mutate in [
            |v: &mut Value| v["phase"] = serde_json::json!("test"),
            |v: &mut Value| v["completeTraceRetained"] = serde_json::json!(true),
            |v: &mut Value| v["applicationIncompatibility"] = serde_json::json!(true),
            |v: &mut Value| v["traceRefused"] = serde_json::json!("arbitrary error"),
            |v: &mut Value| v["completeSerializedSha256"] = serde_json::json!("BAD"),
            |v: &mut Value| v["completeSerializedSizeBytes"] = serde_json::json!(128 * 1024),
            |v: &mut Value| {
                v["completeSerializedSizeBytes"] = serde_json::json!(64 * 1024 * 1024 + 1)
            },
            |v: &mut Value| v["rootProcessId"] = serde_json::json!(0),
            |v: &mut Value| v["eventsProcessed"] = serde_json::json!(4097),
            |v: &mut Value| v["unknown"] = serde_json::json!(true),
            |v: &mut Value| {
                v.as_object_mut().unwrap().remove("jobActiveProcesses");
            },
        ] {
            let mut value = original.clone();
            mutate(&mut value);
            assert!(
                refused_trace_diagnostic(
                    "workflow-baseline-0-trace",
                    &serde_json::to_vec(&value).unwrap()
                )
                .is_none()
            );
        }
        assert!(refused_trace_diagnostic("workflow-baseline-0-trace", &[b' '; 4097]).is_none());
        let text = String::from_utf8(bytes).unwrap();
        let duplicate = text.replacen("{", "{\"jobTotalProcesses\":null,", 1);
        assert!(
            refused_trace_diagnostic("workflow-baseline-0-trace", duplicate.as_bytes()).is_none()
        );
    }

    #[test]
    fn partial_trace_fallback_retains_root_without_inventing_capture_or_function_success() {
        use aiw_provider_wsb::sevenzip_execution_trace::*;
        let token: TokenEvidence = serde_json::from_value(serde_json::json!({
            "schemaVersion":aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,"processId":123,
            "tokenType":"primary","isAppContainer":false,"isElevated":false,
            "userSid":"S-1-5-21-1-2-3-1000","integrity":{"sid":"S-1-16-8192","rid":8192,"level":"medium"},
            "elevationType":"default","capabilities":[],"restrictedSidCount":0
        })).unwrap();
        let trace: SevenZipExecutionTrace = serde_json::from_value(serde_json::json!({
            "schemaVersion":SEVENZIP_EXECUTION_TRACE_SCHEMA,"phase":"create",
            "rootBinding":{"processId":123,"creationTime100ns":36028797018964091u64,"heldToken":token},
            "chain":{"schemaVersion":aiw_provider_wsb::sevenzip_process_tree::SEVENZIP_PROCESS_CHAIN_SCHEMA,
                "scope":aiw_provider_wsb::sevenzip_process_tree::SEVENZIP_PROCESS_CHAIN_SCOPE,
                "rootProcessId":123,"eventsProcessed":0,"processes":[],"timedOut":false,
                "ownedJobTerminationRequested":false,"ownedJobTerminationSucceeded":false,
                "jobTotalProcesses":null,"jobActiveProcesses":null,"jobLimitTerminatedProcesses":null,
                "jobAccountingReconciled":false,"debuggerChainComplete":false,
                "requiresDebuggerProcessExit":true,"gaps":["inert partial fixture"]},"imageLifetimes":[]
        })).unwrap();
        let mut stages = Stages {
            issues: false,
            diagnostics: vec![],
            observed: vec![],
        };
        let decoded = stages
            .decode::<SevenZipExecutionTrace>(
                "workflow-baseline-0-trace",
                &serde_json::to_vec(&trace).unwrap(),
            )
            .unwrap();
        assert_eq!(decoded, trace);
        assert!(!stages.issues);
        let process = retain_application_trace(
            &mut stages,
            "workflow-baseline-0",
            None,
            Some(trace.clone()),
        )
        .unwrap();
        assert!(stages.issues);
        assert_eq!(process.process_id, 123);
        assert_eq!(
            process.held_token.as_ref(),
            Some(&trace.root_binding.held_token)
        );
        assert_eq!(process.exit_code, None);
        assert_eq!(process.job_empty, None);
        assert!(process.stdout_sha256.is_none() && process.stdout_size_bytes.is_none());
        assert_eq!(process.execution_trace, Some(trace));
    }
}
