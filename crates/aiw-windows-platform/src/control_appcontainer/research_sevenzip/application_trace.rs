//! Fixed real installer/application process observations. No arbitrary commands.
use super::*;
use aiw_provider_wsb::sevenzip_execution_trace::{
    SEVENZIP_EXECUTION_TRACE_SCHEMA, SevenZipExecutionPhase, SevenZipExecutionRootBinding,
    SevenZipExecutionTrace, SevenZipImageLifetime, verify_execution_trace,
};
use std::os::windows::io::{AsHandle, IntoRawHandle};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Threading::{GetCurrentThreadId, GetProcessTimes};

const TRACE_BYTES: usize = 128 * 1024;

fn source_observation(file: &HeldApplicationFile) -> Value {
    let source = file.observation();
    json!({"canonicalPath":source.canonical_path,"sha256":source.sha256,
        "sizeBytes":source.size_bytes,"identity":source.identity})
}

pub(super) struct HeldCode {
    phase: SevenZipExecutionPhase,
    image: HeldApplicationFile,
    dll: Option<HeldApplicationFile>,
    _directories: Vec<fs::File>,
}
impl HeldCode {
    pub(super) fn open(phase: SevenZipExecutionPhase) -> Result<Self> {
        let directories = hold_directory_chain(Path::new(
            if phase == SevenZipExecutionPhase::InstallationSetup {
                ROOT
            } else {
                APP
            },
        ))?;
        let image = HeldApplicationFile::open_bounded(
            Path::new(phase.fixed_image_path()),
            32 * 1024 * 1024,
        )?;
        if phase == SevenZipExecutionPhase::InstallationSetup
            && (image.observation().sha256 != INSTALLER_HASH
                || image.observation().size_bytes != INSTALLER_SIZE)
        {
            return Err("fixed installer identity differs before creation".into());
        }
        let dll = if phase == SevenZipExecutionPhase::InstallationSetup {
            None
        } else {
            Some(HeldApplicationFile::open_bounded(
                Path::new(DLL),
                32 * 1024 * 1024,
            )?)
        };
        Ok(Self {
            phase,
            image,
            dll,
            _directories: directories,
        })
    }
    fn revalidate(&self) -> Result<()> {
        self.image.revalidate()?;
        if let Some(dll) = &self.dll {
            dll.revalidate()?;
        }
        Ok(())
    }
}

fn location(phase: SevenZipExecutionPhase, candidate: bool) -> (&'static Path, String) {
    let operation = match phase {
        SevenZipExecutionPhase::InstallationSetup => {
            return (Path::new(OUTPUT), "04-install".into());
        }
        SevenZipExecutionPhase::Create => 0,
        SevenZipExecutionPhase::Test => 1,
        SevenZipExecutionPhase::Extract => 2,
    };
    (
        Path::new(WORK),
        format!(
            "{}-{operation}",
            if candidate { "candidate" } else { "baseline" }
        ),
    )
}

pub(super) fn fail_stop(root: &Path, error: &str) -> ! {
    let retained = record(
        root,
        "99-driver-error",
        &json!({
            "driverError":error.chars().take(2048).collect::<String>(),
            "applicationIncompatibility":false,"debuggerProcessExitRequired":true,
            "profileDeletion":"unverified after debugger fail-stop; no implicit cleanup retry"
        }),
    );
    eprintln!("fixed application debugger fail-stop: {error}; retention={retained:?}");
    std::process::exit(1)
}

fn bounded_trace(value: &Value) -> Result<(Value, bool)> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() <= TRACE_BYTES {
        return Ok((value.clone(), false));
    }
    let chain = &value["chain"];
    Ok((
        json!({"traceRefused":"execution trace exceeds fixed 128 KiB stage limit",
        "completeSerializedSizeBytes":bytes.len(),"completeSerializedSha256":hex::encode(Sha256::digest(&bytes)),
        "completeTraceRetained":false,"phase":value["phase"],
        "rootProcessId":chain["rootProcessId"],"eventsProcessed":chain["eventsProcessed"],
        "jobTotalProcesses":chain["jobTotalProcesses"],"jobActiveProcesses":chain["jobActiveProcesses"],
        "ownedJobTerminationRequested":chain["ownedJobTerminationRequested"],
        "ownedJobTerminationSucceeded":chain["ownedJobTerminationSucceeded"],
        "requiresDebuggerProcessExit":chain["requiresDebuggerProcessExit"],"applicationIncompatibility":false}),
        true,
    ))
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
    code: HeldCode,
) -> Result<Invocation> {
    let (root, name) = location(code.phase, profile.is_some());
    let before = (|| -> Result<_> {
        code.revalidate()?;
        let token = collect_process_token(process.as_handle())?;
        let role = if code.phase == SevenZipExecutionPhase::InstallationSetup {
            if token.user_sid != sid
                || token.user_sid != fixed_account_sid("WDAGUtilityAccount")?
                || !crate::debug_tree::token_matches_for_role(
                    &token,
                    &token,
                    info.dwProcessId,
                    crate::debug_tree::RootRole::InstallationSetup,
                )
            {
                return Err(
                    "installer requires the fixed elevated high Sandbox setup identity".into(),
                );
            }
            crate::debug_tree::RootRole::InstallationSetup
        } else {
            verify_token(&token, info.dwProcessId, profile, sid)?;
            crate::debug_tree::RootRole::SevenZip
        };
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: independently held, still suspended root and sized outputs.
        unsafe {
            GetProcessTimes(
                info.hProcess,
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        }?;
        let time = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        if time == 0 {
            return Err("missing held root creation time".into());
        }
        let binding = SevenZipExecutionRootBinding {
            process_id: info.dwProcessId,
            creation_time_100ns: time,
            held_token: token,
        };
        record(
            root,
            &format!("{name}-binding"),
            &json!({"rootBinding":binding,
                "heldImage":source_observation(&code.image),"heldDll":code.dll.as_ref().map(source_observation),
            "scope":if code.phase == SevenZipExecutionPhase::InstallationSetup {"elevated common setup; not candidate-isolated installation"} else {"fixed application operation"}}),
        )?;
        Ok((binding, role))
    })();
    let (binding, role) = match before {
        Ok(value) => value,
        Err(error) => {
            let cleanup = job.terminate_and_verify_empty();
            fail_stop(
                root,
                &format!("suspended root binding:{error};cleanup={cleanup:?}"),
            );
        }
    };
    let process_raw = process.into_raw_handle();
    let thread_raw = thread.into_raw_handle();
    debug_assert_eq!(process_raw, info.hProcess.0);
    debug_assert_eq!(thread_raw, info.hThread.0);
    // SAFETY: direct creator thread, exactly one explicit suspend; the collector
    // owns these handles and the no-breakaway kill-on-close job exactly once.
    let report = unsafe {
        crate::debug_tree::native::collect_suspended_debug_tree(
            info,
            job.into_owned_handle(),
            crate::debug_tree::ExpectedBinding {
                creator_thread_id: GetCurrentThreadId(),
                role,
                image_sha256: code.image.observation().sha256.clone(),
                image_size_bytes: code.image.observation().size_bytes,
                token: binding.held_token.clone(),
                console_support: None,
            },
        )
    };
    let lifetimes: Vec<_> = report
        .code_evidence
        .iter()
        .map(|image| SevenZipImageLifetime {
            ordinal: image.ordinal,
            process_id: image.process_id,
            create_event_sequence: image.create_event_sequence,
            image_after_exit: image.image_after_exit.clone(),
        })
        .collect();
    let envelope = json!({"schemaVersion":SEVENZIP_EXECUTION_TRACE_SCHEMA,"phase":code.phase,
        "rootBinding":binding,"chain":report,"imageLifetimes":lifetimes});
    let retained = bounded_trace(&envelope).and_then(|(value, refused)| {
        record(root, &format!("{name}-trace"), &value)?;
        Ok(refused)
    });
    if report.requires_debugger_process_exit {
        fail_stop(
            root,
            &format!("incomplete application debugger;trace retention={retained:?}"),
        );
    }
    if retained? {
        return Err("execution trace explicitly refused; collection unmeasured".into());
    }
    let trace: SevenZipExecutionTrace = serde_json::from_value(envelope)?;
    code.revalidate()?;
    verify_execution_trace(
        &trace,
        code.phase,
        &code.image.observation().sha256,
        code.image.observation().size_bytes,
    )?;
    output.sync_all()?;
    drop(output);
    Ok(Invocation {
        token: binding.held_token,
        exit_code: trace.chain.processes.first().and_then(|p| p.exit_code),
        timed_out: trace.chain.timed_out,
        job_empty: trace.chain.job_active_processes == Some(0)
            && trace.chain.job_accounting_reconciled,
        output: read_bounded(capture, 128 * 1024)?,
        execution_trace: Some(trace),
    })
}

pub(super) fn installation_role() -> Result<u8> {
    let _directories = hold_directory_chain(Path::new(OUTPUT))?;
    record(
        Path::new(OUTPUT),
        "04-install-debugger-start",
        &json!({
        "role":"fixed elevated installer debugger","installerSha256":INSTALLER_HASH,
        "candidateIsolatedInstallation":false}),
    )?;
    let operation = (|| -> Result<u8> {
        let installation = install()?;
        record(
            Path::new(OUTPUT),
            "04-install-exit",
            &json!({
        "exitCode":installation.exit_code,"timedOut":installation.timed_out,
        "jobEmpty":installation.job_empty,"executionTrace":installation.execution_trace}),
        )?;
        if installation.exit_code != Some(0) || installation.timed_out || !installation.job_empty {
            return Err("installer failed; application comparison not reached".into());
        }
        Ok(0)
    })();
    match operation {
        Ok(code) => Ok(code),
        Err(error) => {
            let retention = record(
                Path::new(OUTPUT),
                "99-driver-error",
                &json!({
                    "phase":"installationSetup", "driverError":error.to_string().chars().take(2048).collect::<String>(),
                    "applicationIncompatibility":false, "candidateIsolatedInstallation":false
                }),
            );
            Err(
                format!("installer helper failed: {error}; diagnostic retention={retention:?}")
                    .into(),
            )
        }
    }
}

fn install() -> Result<Invocation> {
    let current = collect_current_process_token()?;
    if current.user_sid != fixed_account_sid("WDAGUtilityAccount")?
        || !crate::debug_tree::token_matches_for_role(
            &current,
            &current,
            std::process::id(),
            crate::debug_tree::RootRole::InstallationSetup,
        )
    {
        return Err("fixed elevated Sandbox setup required before installer creation".into());
    }
    let code = HeldCode::open(SevenZipExecutionPhase::InstallationSetup)?;
    let capture = Path::new(OUTPUT).join("installer-capture.txt");
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&capture)?;
    let image = wide(OsStr::new(INSTALLER))?;
    let mut command = wide(OsStr::new(&aiw_windows_command_line::join_arguments([
        INSTALLER,
        "/S",
        r"/D=C:\AIW\SevenZip\App",
    ])))?;
    let cwd = wide(OsStr::new(ROOT))?;
    let output_handle = HANDLE(output.as_raw_handle());
    // SAFETY: this owned capture is the only explicitly inherited handle.
    unsafe { SetHandleInformation(output_handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }?;
    // Attribute values must outlive the list, including its destruction.
    let inherited = [output_handle];
    let mut attributes = Attributes::new(1)?;
    attributes.handles(&inherited)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = windows::Win32::System::Threading::STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdOutput = output_handle;
    startup.StartupInfo.hStdError = output_handle;
    startup.lpAttributeList = attributes.list;
    let job = Job::create()?;
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: fixed held executable/argv/cwd, suspended debug creation; only
    // the reviewed capture is in the explicit inherited handle list.
    unsafe {
        CreateProcessW(
            PCWSTR(image.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT
                | windows::Win32::System::Threading::DEBUG_PROCESS,
            None,
            PCWSTR(cwd.as_ptr()),
            (&startup as *const STARTUPINFOEXW).cast(),
            &mut info,
        )
    }?;
    // SAFETY: unique process/thread references returned by this successful creation.
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess.0) };
    let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread.0) };
    if let Err(error) = unsafe { AssignProcessToJobObject(job.handle(), info.hProcess) } {
        let stopped = unsafe { TerminateProcess(info.hProcess, 1) };
        let waited = wait(info.hProcess, Duration::from_secs(2));
        fail_stop(
            Path::new(OUTPUT),
            &format!("installer job assignment:{error};stopped={stopped:?};waited={waited:?}"),
        );
    }
    collect(
        info,
        process,
        thread,
        job,
        output,
        &capture,
        None,
        &current.user_sid,
        code,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_trace_refuses_without_replacing_cleanup_facts_with_success() {
        let value = json!({"phase":"create","chain":{"rootProcessId":42,"eventsProcessed":9,
            "jobTotalProcesses":2,"jobActiveProcesses":1,"ownedJobTerminationRequested":true,
            "ownedJobTerminationSucceeded":false,"requiresDebuggerProcessExit":true},"payload":"x".repeat(TRACE_BYTES)});
        let (refused, is_refused) = bounded_trace(&value).unwrap();
        assert!(is_refused);
        assert_eq!(refused["jobActiveProcesses"], 1);
        assert_eq!(refused["ownedJobTerminationSucceeded"], false);
        assert_eq!(refused["completeTraceRetained"], false);
        assert!(serde_json::from_value::<SevenZipExecutionTrace>(refused).is_err());
    }
}
