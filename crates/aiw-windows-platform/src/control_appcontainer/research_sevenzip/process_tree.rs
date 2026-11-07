//! Default-off native driver proof. No production invocation uses these roles.
use super::*;
use std::os::windows::io::IntoRawHandle;

use aiw_provider_wsb::sevenzip_process_tree::{SevenZipExpectedRootBinding, SevenZipProcessChain};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Threading::{GetCurrentThreadId, GetProcessTimes};

const TRACE_STAGE_LIMIT: usize = 128 * 1024;
const EMBEDDED_STAGE_LIMIT: usize = 768 * 1024;
const MARKER_LIMIT: usize = 1024 * 1024;

pub(super) fn validate_preexecution_windows(
    windows: &aiw_probe::WindowsVersionObservation,
) -> Result<()> {
    windows.validate()?;
    if (
        windows.major,
        windows.minor,
        windows.build,
        windows.revision,
    ) != (10, 0, 26100, 9711)
        || windows.observer_architecture != "x86_64"
    {
        return Err("tree-control guest Windows differs from the exact approved version; no account or control created".into());
    }
    Ok(())
}

fn insert_stage(
    stages: &mut serde_json::Map<String, Value>,
    errors: &mut serde_json::Map<String, Value>,
    key: &str,
    value: std::result::Result<Value, String>,
) -> Result<()> {
    let value = value.and_then(|value| {
        let bytes = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
        if bytes.len() > TRACE_STAGE_LIMIT {
            return Err("stage exceeds fixed 128 KiB serialized limit".into());
        }
        Ok(value)
    });
    match value {
        Ok(value) => {
            stages.insert(key.into(), value);
            // Reserve space for all later missing/refused stage errors. Actual
            // pretty serialization includes JSON escaping and nested indentation.
            let bytes =
                serde_json::to_vec_pretty(&json!({"stages":stages,"stageReadErrors":errors}))?;
            if bytes.len() > EMBEDDED_STAGE_LIMIT - 64 * 1024 {
                stages.remove(key);
                errors.insert(
                    key.into(),
                    json!("aggregate stage budget refused this value; earlier facts retained"),
                );
            }
        }
        Err(error) => {
            errors.insert(
                key.into(),
                json!(error.chars().take(512).collect::<String>()),
            );
        }
    }
    Ok(())
}

pub(super) fn publish_terminal_tree(
    result: &Result<u8>,
    windows: &aiw_probe::WindowsVersionObservation,
    observer_token: &TokenEvidence,
) -> Result<()> {
    let mut stages = serde_json::Map::new();
    let mut errors = serde_json::Map::new();
    // Root bindings and complete/partial traces have priority. Every fixed key
    // appears exactly once as data or an explicit missing/refusal record.
    for name in [
        "tree-baseline-binding",
        "tree-candidate-binding",
        "tree-baseline",
        "tree-candidate",
        "tree-baseline-error",
        "tree-candidate-error",
        "tree-candidate-profile",
        "tree-profile-cleanup",
        "tree-complete",
        "99-driver-error",
    ] {
        let key = if name == "99-driver-error" {
            "workflow-99-driver-error"
        } else {
            name
        };
        let captured = (|| -> Result<Value> {
            let file = HeldApplicationFile::open_bounded(
                &Path::new(WORK).join(format!("{name}.json")),
                TRACE_STAGE_LIMIT as u64,
            )?;
            let value = serde_json::from_slice(&file.read_bounded(TRACE_STAGE_LIMIT as u64)?)?;
            file.revalidate()?;
            Ok(value)
        })();
        insert_stage(
            &mut stages,
            &mut errors,
            key,
            captured.map_err(|e| e.to_string()),
        )?;
    }
    for name in [
        "00-start",
        "01-context",
        "02-launcher",
        "05-workflow-exit",
        "05-launcher-cleanup",
        "06-final",
        "99-driver-error",
    ] {
        let captured = (|| -> Result<Value> {
            let file = HeldApplicationFile::open_bounded(
                &Path::new(OUTPUT).join(format!("{name}.json")),
                TRACE_STAGE_LIMIT as u64,
            )?;
            let value = serde_json::from_slice(&file.read_bounded(TRACE_STAGE_LIMIT as u64)?)?;
            file.revalidate()?;
            Ok(value)
        })();
        insert_stage(
            &mut stages,
            &mut errors,
            &format!("owner-{name}"),
            captured.map_err(|e| e.to_string()),
        )?;
    }
    if serde_json::to_vec_pretty(&json!({"stages":stages,"stageReadErrors":errors}))?.len()
        > EMBEDDED_STAGE_LIMIT
    {
        return Err("embedded stage envelope exceeds fixed budget".into());
    }
    let marker = json!({
        "schemaVersion":"aiw.dev/research/sevenzip-tree-result/v0alpha1",
        "windows":windows,"observerToken":observer_token,
        "driverCompleted":result.is_ok(),
        "error":result.as_ref().err().map(|e|e.to_string().chars().take(512).collect::<String>()),
        "firstPartyControlsOnly":true,"vendorInstallerExecuted":false,"applicationExecuted":false,
        "stages":stages,"stageReadErrors":errors
    });
    if serde_json::to_vec_pretty(&marker)?.len() > MARKER_LIMIT {
        return Err("tree result exceeds fixed publisher limit".into());
    }
    publish_new(
        &Path::new(OUTPUT).join("RESULT.TMP"),
        &Path::new(OUTPUT).join("RESULT.DAT"),
        &marker,
    )
}

fn bounded_trace_record(value: Value) -> Result<(Value, bool)> {
    let bytes = serde_json::to_vec_pretty(&value)?;
    if bytes.len() <= TRACE_STAGE_LIMIT {
        return Ok((value, false));
    }
    // A refusal is distinct from a trace. Preserve bounded exact summary facts
    // and the digest/length of the complete serialization, never a truncated
    // value that could be accepted as complete process evidence.
    let refused = json!({
        "traceRefused":"serialized trace exceeds fixed 128 KiB stage limit",
        "completeSerializedSizeBytes":bytes.len(),"completeSerializedSha256":hex::encode(Sha256::digest(&bytes)),
        "completeTraceRetained":false,
        "rootProcessId":value["rootProcessId"],"eventsProcessed":value["eventsProcessed"],
        "observedProcessCount":value["processes"].as_array().map(Vec::len),
        "gapCount":value["gaps"].as_array().map(Vec::len),
        "timedOut":value["timedOut"],
        "ownedJobTerminationRequested":value["ownedJobTerminationRequested"],
        "ownedJobTerminationSucceeded":value["ownedJobTerminationSucceeded"],
        "jobTotalProcesses":value["jobTotalProcesses"],"jobActiveProcesses":value["jobActiveProcesses"],
        "jobLimitTerminatedProcesses":value["jobLimitTerminatedProcesses"],
        "requiresDebuggerProcessExit":value["requiresDebuggerProcessExit"],
        "applicationIncompatibility":false
    });
    if serde_json::to_vec_pretty(&refused)?.len() > TRACE_STAGE_LIMIT {
        return Err("trace refusal exceeds stage budget".into());
    }
    Ok((refused, true))
}

fn stage(profile: Option<PSID>) -> &'static str {
    if profile.is_some() {
        "tree-candidate"
    } else {
        "tree-baseline"
    }
}

pub(super) fn workflow(token: &TokenEvidence) -> Result<u8> {
    verify_token(token, std::process::id(), None, &token.user_sid)?;
    let _root = hold_directory_chain(Path::new(ROOT))?;
    let _work = hold_directory_chain(Path::new(WORK))?;
    control(None, &token.user_sid)?;
    let mut profile = AppContainerProfile::create(SEVENZIP_PROFILE)?;
    let candidate = (|| -> Result<()> {
        let expected = DerivedProfileSid::new()?;
        if profile.string_sid()? != sid_string(expected.0)? {
            return Err("fresh tree-control profile differs".into());
        }
        record(
            Path::new(WORK),
            "tree-candidate-profile",
            &json!({
                "ownedFreshProfileSid":profile.string_sid()?,
                "cleanup":"not yet attempted; abrupt debugger exit leaves deletion unverified"
            }),
        )?;
        control(Some(profile.sid), &token.user_sid)
    })();
    let cleanup = profile.delete();
    record(
        Path::new(WORK),
        "tree-profile-cleanup",
        &json!({
            "deleted":cleanup.is_ok(),"cleanupError":cleanup.as_ref().err().map(ToString::to_string),
            "candidateError":candidate.as_ref().err().map(ToString::to_string)
        }),
    )?;
    candidate?;
    cleanup?;
    record(
        Path::new(WORK),
        "tree-complete",
        &json!({
            "firstPartyControlsOnly":true,"ordinaryAndClassicPassed":true,"profileDeleted":true,
            "applicationCompatibility":"not measured"
        }),
    )?;
    Ok(0)
}

/// Stop this dedicated debugger after persisting its measurement. Never start
/// another operation on a thread whose debug chain could still be associated.
pub(super) fn fail_stop(profile: Option<PSID>, error: &str) -> ! {
    let retained = record(
        Path::new(WORK),
        &format!("{}-error", stage(profile)),
        &json!({
            "driverError":error.chars().take(2048).collect::<String>(),
            "applicationIncompatibility":false,
            "debuggerProcessExitRequired":true,
            "profileDeletion":"unverified after abrupt debugger exit",
            "cleanup":"exact outer owner must verify its job; no profile-name cleanup authorized"
        }),
    );
    eprintln!("fixed tree driver fail-stop: {error}; error record={retained:?}");
    std::process::exit(1)
}

pub(super) fn control(profile: Option<PSID>, sid: &str) -> Result<()> {
    let invocation = launch(Operation::Tree, profile, Path::new(WORK), sid)?;
    if invocation.exit_code != Some(31)
        || invocation.timed_out
        || !invocation.job_empty
        || !invocation.output.is_empty()
    {
        return Err("fixed tree control function/capture failed; no application verdict".into());
    }
    Ok(())
}

/// The root exits without waiting for its child; the child likewise launches a
/// grandchild. The delays permit observing root-first exit without holding a
/// live parent handle. The external collector must prove actual event ordering.
pub(super) fn run_fixed_role(role: &str) -> Result<u8> {
    let (next, code) = match role {
        "--tree-root" => (Some("--tree-child"), 31),
        "--tree-child" => {
            thread::sleep(Duration::from_millis(200));
            (Some("--tree-grandchild"), 32)
        }
        "--tree-grandchild" => {
            thread::sleep(Duration::from_millis(200));
            (None, 33)
        }
        _ => return Err("unknown fixed tree role".into()),
    };
    if let Some(argument) = next {
        // No DEBUG_PROCESS flag: inherit the creator's debugger chain and job.
        // No inherited stdio/extra handles, breakaway or mutable command input.
        let image = wide(OsStr::new(HELPER))?;
        let mut command = wide(OsStr::new(&aiw_windows_command_line::join_arguments([
            HELPER, argument,
        ])))?;
        let cwd = wide(OsStr::new(WORK))?;
        let startup = windows::Win32::System::Threading::STARTUPINFOW {
            cb: std::mem::size_of::<windows::Win32::System::Threading::STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: fixed executable/arguments/cwd, valid local buffers, no
        // inherited handles. Returns unique process/thread references.
        unsafe {
            CreateProcessW(
                PCWSTR(image.as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_NO_WINDOW,
                None,
                PCWSTR(cwd.as_ptr()),
                &startup,
                &mut info,
            )
        }?;
        // SAFETY: fresh distinct owned references; dropping them does not wait
        // for or terminate the child. The enclosing no-breakaway job owns it.
        let _process = unsafe { OwnedHandle::from_raw_handle(info.hProcess.0) };
        let _thread = unsafe { OwnedHandle::from_raw_handle(info.hThread.0) };
    }
    Ok(code)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn collect(
    info: PROCESS_INFORMATION,
    process: OwnedHandle,
    thread: OwnedHandle,
    job: Job,
    output: fs::File,
    capture: &Path,
    profile: Option<PSID>,
    sid: &str,
) -> Result<Invocation> {
    let before = (|| -> Result<_> {
        let _ancestry = hold_directory_chain(Path::new(ROOT))?;
        let image = HeldApplicationFile::open_bounded(Path::new(HELPER), 32 * 1024 * 1024)?;
        let token = collect_process_token(process.as_handle())?;
        verify_token(&token, info.dwProcessId, profile, sid)?;
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: independently held suspended root, correctly sized outputs.
        unsafe {
            GetProcessTimes(
                info.hProcess,
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        }?;
        let creation_time =
            (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        if creation_time == 0 {
            return Err("zero root creation time".into());
        }
        record(
            Path::new(WORK),
            &format!("{}-binding", stage(profile)),
            &json!({
                "processId":info.dwProcessId,"creationTime100ns":creation_time,
                "heldToken":token,"heldImage":{
                    "canonicalPath":image.observation().canonical_path,
                    "sha256":image.observation().sha256,
                    "sizeBytes":image.observation().size_bytes,
                    "identity":image.observation().identity
                },
                "profileDeletion":"not yet attempted"
            }),
        )?;
        Ok((_ancestry, image, token, creation_time))
    })();
    let (_ancestry, image, token, creation_time) = match before {
        Ok(value) => value,
        Err(error) => {
            let cleanup = job.terminate_and_verify_empty();
            fail_stop(
                profile,
                &format!("suspended root binding: {error}; owned cleanup={cleanup:?}"),
            );
        }
    };
    // Disarm wrappers exactly once. The collector owns these original PI
    // references, owns the job and resumes once on this creator OS thread.
    let process_raw = process.into_raw_handle();
    let thread_raw = thread.into_raw_handle();
    debug_assert_eq!(process_raw, info.hProcess.0);
    debug_assert_eq!(thread_raw, info.hThread.0);
    // SAFETY: this function is called directly on the CreateProcessW thread,
    // after exact-job assignment and root-token policy checks, without resume.
    let report = unsafe {
        crate::debug_tree::native::collect_suspended_debug_tree(
            info,
            job.into_owned_handle(),
            crate::debug_tree::ExpectedBinding {
                creator_thread_id: GetCurrentThreadId(),
                role: crate::debug_tree::RootRole::Control,
                image_sha256: image.observation().sha256.clone(),
                image_size_bytes: image.observation().size_bytes,
                token: token.clone(),
            },
        )
    };
    let trace = bounded_trace_record(json!(report));
    let refused = trace.as_ref().is_ok_and(|(_, refused)| *refused);
    let retained = trace.and_then(|(value, _)| record(Path::new(WORK), stage(profile), &value));
    if report.requires_debugger_process_exit {
        fail_stop(
            profile,
            &format!("incomplete debugger measurement; trace retention={retained:?}"),
        );
    }
    retained?;
    if refused {
        return Err(
            "oversized trace explicitly refused; complete process evidence unmeasured".into(),
        );
    }
    let typed: SevenZipProcessChain = serde_json::from_value(json!(report))?;
    typed.verify_complete(&SevenZipExpectedRootBinding {
        process_id: info.dwProcessId,
        creation_time_100ns: creation_time,
        held_token: &token,
        fixed_image_path: HELPER,
        image_sha256: &image.observation().sha256,
        image_size_bytes: image.observation().size_bytes,
        expected_control_processes: Some(3),
    })?;
    if typed
        .processes
        .iter()
        .map(|p| p.exit_code)
        .collect::<Vec<_>>()
        != [Some(31), Some(32), Some(33)]
        || typed.processes[0].exit_event_sequence >= typed.processes[1].exit_event_sequence
    {
        return Err("control role exits/root-first event order differ; preserve trace".into());
    }
    image.revalidate()?;
    output.sync_all()?;
    drop(output);
    Ok(Invocation {
        token,
        exit_code: Some(31),
        timed_out: false,
        job_empty: true,
        output: read_bounded(capture, 128 * 1024)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_preexecution_environment_refuses_wrong_revision_build_or_architecture() {
        let expected: aiw_probe::WindowsVersionObservation = serde_json::from_value(json!({
            "major":10,"minor":0,"build":26100,"revision":9711,"observerArchitecture":"x86_64"
        }))
        .unwrap();
        validate_preexecution_windows(&expected).unwrap();
        let mut wrong = expected.clone();
        wrong.revision += 1;
        assert!(validate_preexecution_windows(&wrong).is_err());
        let mut wrong = expected.clone();
        wrong.build = 26300;
        assert!(validate_preexecution_windows(&wrong).is_err());
        let mut wrong = expected;
        wrong.observer_architecture = "aarch64".into();
        assert!(validate_preexecution_windows(&wrong).is_err());
    }

    #[test]
    fn embedded_stage_budget_preserves_prior_values_and_partitions_all_fixed_keys() {
        let mut stages = serde_json::Map::new();
        let mut errors = serde_json::Map::new();
        for index in 0..17 {
            insert_stage(
                &mut stages,
                &mut errors,
                &format!("fixed-{index}"),
                Ok(json!({"bytes":"x".repeat(120 * 1024)})),
            )
            .unwrap();
        }
        assert!(stages.contains_key("fixed-0"));
        assert!(stages.len() < 17);
        assert!(!errors.is_empty());
        assert_eq!(stages.len() + errors.len(), 17);
        for key in stages.keys() {
            assert!(!errors.contains_key(key));
        }
        assert!(
            serde_json::to_vec_pretty(&json!({"stages":stages,"stageReadErrors":errors}))
                .unwrap()
                .len()
                <= EMBEDDED_STAGE_LIMIT
        );
    }

    #[test]
    fn embedded_stage_refusals_bound_unicode_errors_and_actual_escaped_values() {
        let mut stages = serde_json::Map::new();
        let mut errors = serde_json::Map::new();
        insert_stage(
            &mut stages,
            &mut errors,
            "failed",
            Err("\u{1f600}".repeat(3000)),
        )
        .unwrap();
        insert_stage(
            &mut stages,
            &mut errors,
            "oversized",
            Ok(json!("\u{0001}".repeat(TRACE_STAGE_LIMIT / 2))),
        )
        .unwrap();
        assert!(stages.is_empty());
        assert!(errors["failed"].as_str().unwrap().len() <= 2048);
        assert_eq!(errors.len(), 2);
        assert!(errors["oversized"].as_str().unwrap().contains("128 KiB"));
    }

    #[test]
    fn near_limit_prefix_plus_all_escaped_errors_fits_the_marker_stage_budget() {
        let mut stages = serde_json::Map::new();
        let mut errors = serde_json::Map::new();
        for index in 0..6 {
            insert_stage(
                &mut stages,
                &mut errors,
                &format!("prior-{index}"),
                Ok(json!("x".repeat(115 * 1024))),
            )
            .unwrap();
        }
        for index in 0..17 {
            insert_stage(
                &mut stages,
                &mut errors,
                &format!("error-{index}"),
                Err("\u{0001}".repeat(600)),
            )
            .unwrap();
        }
        assert!(stages.contains_key("prior-0"));
        assert_eq!(errors.len(), 17);
        assert!(
            serde_json::to_vec_pretty(&json!({"stages":stages,"stageReadErrors":errors}))
                .unwrap()
                .len()
                <= EMBEDDED_STAGE_LIMIT
        );
    }

    #[test]
    fn oversized_trace_is_an_explicit_bounded_refusal_with_actual_cleanup_facts() {
        let original = json!({"rootProcessId":42,"eventsProcessed":4000,
            "processes":[{"imagePath":"\u{0001}".repeat(TRACE_STAGE_LIMIT)}],
            "gaps":["overflow"],"timedOut":true,
            "ownedJobTerminationRequested":true,"ownedJobTerminationSucceeded":false,
            "jobTotalProcesses":9,"jobActiveProcesses":1,"jobLimitTerminatedProcesses":0,
            "requiresDebuggerProcessExit":true});
        let bytes = serde_json::to_vec_pretty(&original).unwrap();
        let (record, refused) = bounded_trace_record(original).unwrap();
        assert!(refused);
        assert_eq!(record["completeSerializedSizeBytes"], bytes.len());
        assert_eq!(
            record["completeSerializedSha256"],
            hex::encode(Sha256::digest(bytes))
        );
        assert_eq!(record["completeTraceRetained"], false);
        assert_eq!(record["jobActiveProcesses"], 1);
        assert_eq!(record["ownedJobTerminationSucceeded"], false);
        assert_eq!(record["requiresDebuggerProcessExit"], true);
        assert!(record.get("processes").is_none());
        assert!(serde_json::to_vec_pretty(&record).unwrap().len() < TRACE_STAGE_LIMIT);
        assert!(serde_json::from_value::<SevenZipProcessChain>(record).is_err());
    }

    #[test]
    fn bounded_trace_keeps_complete_original_and_budget_includes_json_escaping() {
        let original = json!({"diagnostic":"\u{0001}".repeat(100)});
        let (record, refused) = bounded_trace_record(original.clone()).unwrap();
        assert!(!refused);
        assert_eq!(record, original);
        let original = json!({"diagnostic":"\u{0001}".repeat(TRACE_STAGE_LIMIT / 2)});
        assert!(bounded_trace_record(original).unwrap().1);
    }
}
