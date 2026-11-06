//! Private foundation for creation-time debugger-chain observations.
//!
//! Not integrated or native-validated. This is neither an arbitrary launcher nor
//! an all-host descendant census. DEBUG_PROCESS chains can be reset by children;
//! broker/WMI creation is outside the supported CreateProcess-tree scope.
use std::collections::BTreeMap;

use aiw_token::{TokenEvidence, TokenType};
use serde::Serialize;

const MAX_PROCESSES: usize = 64;
const MAX_EVENTS: u32 = 4096;
// Reserve bounded event capacity to continue exit events after terminating a
// flooding tree. Exhausting the reserve requires debugger-process fail-stop.
const COLLECTION_EVENTS: u32 = 3072;

#[derive(Debug, Clone, Copy)]
pub(crate) enum RootRole {
    SevenZip,
    Control,
}

impl RootRole {
    fn image(self) -> &'static str {
        match self {
            Self::SevenZip => r"C:\AIW\SevenZip\App\7z.exe",
            Self::Control => r"C:\AIW\SevenZip\sevenzip_assessment.exe",
        }
    }
}

/// Construct only from the independently validated suspended root token.
/// PSEC identity is not inferred from TokenIsAppContainer: native PSEC policy
/// and boundary observations remain separately required.
#[derive(Debug, Clone)]
pub(crate) struct ExpectedBinding {
    pub creator_thread_id: u32,
    pub role: RootRole,
    pub image_sha256: String,
    pub image_size_bytes: u64,
    pub token: TokenEvidence,
}

fn token_matches(actual: &TokenEvidence, expected: &TokenEvidence) -> bool {
    actual.token_type == TokenType::Primary
        && expected.token_type == TokenType::Primary
        && !actual.is_elevated
        && !expected.is_elevated
        && actual.integrity.rid <= 0x2000
        && expected.integrity.rid <= 0x2000
        && actual.capabilities.is_empty()
        && expected.capabilities.is_empty()
        && actual.user_sid == expected.user_sid
        && actual.is_app_container == expected.is_app_container
        && actual.app_container_sid == expected.app_container_sid
        && actual.integrity == expected.integrity
        && actual.elevation_type == expected.elevation_type
        && actual.restricted_sid_count == expected.restricted_sid_count
}

#[derive(Debug, Default)]
struct TraceState {
    active: BTreeMap<u32, usize>,
    exits: Vec<Option<u32>>,
}

impl TraceState {
    fn create(&mut self, pid: u32) -> Result<usize, &'static str> {
        if pid == 0 || self.active.contains_key(&pid) {
            return Err("duplicate_or_zero_process_create");
        }
        if self.exits.len() >= MAX_PROCESSES {
            return Err("process_budget_exhausted");
        }
        let index = self.exits.len();
        self.exits.push(None);
        self.active.insert(pid, index);
        Ok(index)
    }

    fn exit(&mut self, pid: u32, code: u32) -> Result<usize, &'static str> {
        let index = self.active.remove(&pid).ok_or("unpaired_process_exit")?;
        self.exits[index] = Some(code);
        Ok(index)
    }

    fn reconciles(&self, total: u32, active: u32, terminated_by_limit: u32) -> bool {
        self.active.is_empty()
            && !self.exits.is_empty()
            && self.exits.iter().all(Option::is_some)
            && total as usize == self.exits.len()
            && active == 0
            && terminated_by_limit == 0
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImageObservation {
    pub process_image_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub volume_serial_number: u32,
    pub file_index: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessObservation {
    pub ordinal: usize,
    pub process_id: u32,
    pub create_event_sequence: u32,
    pub creation_time_100ns: Option<u64>,
    // DEBUG_EVENT does not expose PPID; chain membership is not a parent edge.
    pub token_before_continue: Option<TokenEvidence>,
    pub image_before_continue: Option<ImageObservation>,
    pub exit_code: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DebugTreeReport {
    pub schema_version: &'static str,
    pub scope: &'static str,
    pub root_process_id: u32,
    pub events_processed: u32,
    pub processes: Vec<ProcessObservation>,
    pub timed_out: bool,
    pub owned_job_termination_requested: bool,
    pub owned_job_termination_succeeded: bool,
    pub job_total_processes: Option<u32>,
    pub job_active_processes: Option<u32>,
    pub job_limit_terminated_processes: Option<u32>,
    pub job_accounting_reconciled: bool,
    pub debugger_chain_complete: bool,
    pub requires_debugger_process_exit: bool,
    pub gaps: Vec<String>,
}

impl DebugTreeReport {
    fn new(root_process_id: u32) -> Self {
        Self {
            schema_version: "aiw.dev/private-debug-tree/v0alpha1",
            scope: "instrumented DEBUG_PROCESS inherited CreateProcess chain; not broker/all-host coverage",
            root_process_id,
            events_processed: 0,
            processes: Vec::new(),
            timed_out: false,
            owned_job_termination_requested: false,
            owned_job_termination_succeeded: false,
            job_total_processes: None,
            job_active_processes: None,
            job_limit_terminated_processes: None,
            job_accounting_reconciled: false,
            debugger_chain_complete: false,
            requires_debugger_process_exit: true,
            gaps: Vec::new(),
        }
    }

    fn gap(&mut self, message: impl AsRef<str>) {
        if self.gaps.len() < 32 {
            self.gaps.push(message.as_ref().chars().take(512).collect());
        }
    }

    fn requires_exit(&self, state: &TraceState, root_create_seen: bool) -> bool {
        !self.gaps.is_empty()
            || !root_create_seen
            || !state.active.is_empty()
            || !self.job_accounting_reconciled
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use std::fs::File;
    use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
    use std::time::{Duration, Instant};

    use aiw_token::collect_process_token;
    use sha2::{Digest, Sha256};
    use windows::Win32::Foundation::{
        CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, DUPLICATE_SAME_ACCESS,
        DuplicateHandle, ERROR_SEM_TIMEOUT, ERROR_TIMEOUT, EXCEPTION_BREAKPOINT, FILETIME, HANDLE,
        WAIT_OBJECT_0,
    };
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
    };
    use windows::Win32::System::Diagnostics::Debug::{
        CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT,
        DebugSetProcessKillOnExit, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
        EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT,
        UNLOAD_DLL_DEBUG_EVENT, WaitForDebugEventEx,
    };
    use windows::Win32::System::JobObjects::{
        IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, TerminateJobObject,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThreadId, GetProcessId, GetProcessTimes, PROCESS_INFORMATION,
        PROCESS_NAME_WIN32, QueryFullProcessImageNameW, ResumeThread, WaitForSingleObject,
    };
    use windows::core::PWSTR;

    const MAX_IMAGE_BYTES: u64 = 32 * 1024 * 1024;
    const RUN_DEADLINE: Duration = Duration::from_secs(30);
    const DRAIN_DEADLINE: Duration = Duration::from_secs(3);

    fn handle(value: &OwnedHandle) -> HANDLE {
        HANDLE(value.as_raw_handle())
    }

    /// Transfers a fresh owned Win32 handle into Rust exactly once.
    unsafe fn own(value: HANDLE) -> Result<OwnedHandle, String> {
        if value.is_invalid() {
            return Err("missing_native_handle".into());
        }
        // SAFETY: the caller transfers ownership of a fresh valid handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(value.0) })
    }

    fn duplicate(value: HANDLE) -> Result<OwnedHandle, String> {
        let mut duplicate = HANDLE::default();
        // SAFETY: supplied source is a live debug-event or owned process handle;
        // output is fresh writable storage; inheritance is explicitly disabled.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                value,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(|e| format!("duplicate_process_handle:{e}"))?;
        // SAFETY: DuplicateHandle returned ownership of this fresh handle.
        unsafe { own(duplicate) }
    }

    struct OwnedJob(OwnedHandle);
    impl Drop for OwnedJob {
        fn drop(&mut self) {
            // SAFETY: caller guarantees exclusive ownership of this trial job.
            // Always kill only that job on all unwind/early-return paths.
            let _ = unsafe { TerminateJobObject(handle(&self.0), 1) };
        }
    }

    fn terminate(job: &OwnedJob, report: &mut DebugTreeReport) {
        if report.owned_job_termination_requested {
            return;
        }
        report.owned_job_termination_requested = true;
        // SAFETY: exclusively owned trial job, never an arbitrary PID/tree.
        match unsafe { TerminateJobObject(handle(&job.0), 1) } {
            Ok(()) => report.owned_job_termination_succeeded = true,
            Err(e) => report.gap(format!("terminate_owned_job:{e}")),
        }
    }

    fn in_job(process: HANDLE, job: &OwnedJob) -> Result<(), String> {
        let mut member = windows::core::BOOL::default();
        // SAFETY: live process/job and writable BOOL storage.
        unsafe { IsProcessInJob(process, Some(handle(&job.0)), &mut member) }
            .map_err(|e| format!("query_job_membership:{e}"))?;
        if !member.as_bool() {
            return Err("debug_process_outside_owned_job".into());
        }
        Ok(())
    }

    fn creation_time(process: HANDLE) -> Result<u64, String> {
        let (mut c, mut e, mut k, mut u) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: exact held process, all FILETIME outputs are writable.
        unsafe { GetProcessTimes(process, &mut c, &mut e, &mut k, &mut u) }
            .map_err(|e| format!("query_creation_time:{e}"))?;
        Ok((u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime))
    }

    fn image(process: HANDLE, file: &mut File) -> Result<ImageObservation, String> {
        let file_handle = HANDLE(file.as_raw_handle());
        // SAFETY: file owns the exact event image handle; no path is reopened.
        if unsafe { GetFileType(file_handle) } != FILE_TYPE_DISK {
            return Err("non_disk_event_image".into());
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: same held event file and writable output structure.
        unsafe { GetFileInformationByHandle(file_handle, &mut info) }
            .map_err(|e| format!("event_image_identity:{e}"))?;
        if info.dwFileAttributes & 0x450 != 0 || info.nNumberOfLinks != 1 {
            return Err("event_image_type_or_links_rejected".into());
        }
        let size_bytes = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
        if size_bytes == 0 || size_bytes > MAX_IMAGE_BYTES {
            return Err("event_image_size_rejected".into());
        }
        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("event_image_seek:{e}"))?;
        let mut hash = Sha256::new();
        let mut read = 0_u64;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|e| format!("event_image_read:{e}"))?;
            if count == 0 {
                break;
            }
            read += count as u64;
            if read > size_bytes {
                return Err("event_image_changed_during_read".into());
            }
            hash.update(&buffer[..count]);
        }
        if read != size_bytes {
            return Err("event_image_truncated".into());
        }
        let mut path = vec![0_u16; 32768];
        let mut length = path.len() as u32;
        // SAFETY: exact held process; output buffer and its length are valid.
        unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(path.as_mut_ptr()),
                &mut length,
            )
        }
        .map_err(|e| format!("event_process_image_name:{e}"))?;
        let process_image_path = String::from_utf16(&path[..length as usize])
            .map_err(|_| "event_process_image_name_not_unicode".to_string())?;
        Ok(ImageObservation {
            process_image_path,
            sha256: hex::encode(hash.finalize()),
            size_bytes,
            volume_serial_number: info.dwVolumeSerialNumber,
            file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }

    struct LiveProcess {
        process: OwnedHandle,
        _image: File,
    }

    /// Collect a process already created with DEBUG_PROCESS | CREATE_SUSPENDED.
    ///
    /// # Safety
    /// Caller transfers unique PROCESS_INFORMATION process/thread handles and an
    /// exclusively owned fresh job containing only this root. The job must have
    /// KILL_ON_JOB_CLOSE and no breakaway. This MUST be invoked on the same OS
    /// thread that created the process; no other debugger loop may share it.
    /// Root has exactly one explicit suspend count. Expected binding came from
    /// independently validated held inputs/token; no handles are inherited by
    /// debuggees except separately reviewed dedicated app stdio. On a report
    /// requiring debugger-process exit, fail-stop that dedicated helper rather
    /// than reuse its OS thread/session. No debugger detach is performed here.
    pub(crate) unsafe fn collect_suspended_debug_tree(
        info: PROCESS_INFORMATION,
        job: OwnedHandle,
        expected: ExpectedBinding,
    ) -> DebugTreeReport {
        let job = OwnedJob(job);
        let mut report = DebugTreeReport::new(info.dwProcessId);
        // SAFETY: ownership transfer is the caller's explicit API contract.
        let root = unsafe { own(info.hProcess) };
        // SAFETY: distinct fresh primary-thread handle, same ownership contract.
        let thread = unsafe { own(info.hThread) };
        let (root, thread) = match (root, thread) {
            (Ok(root), Ok(thread)) => (root, thread),
            _ => {
                report.gap("invalid_initial_process_information");
                terminate(&job, &mut report);
                return report;
            }
        };
        let preflight = (|| -> Result<(), String> {
            // SAFETY: read-only queries on this current thread and held process.
            if unsafe { GetCurrentThreadId() } != expected.creator_thread_id
                || unsafe { GetProcessId(handle(&root)) } != info.dwProcessId
                || expected.token.process_id != info.dwProcessId
            {
                return Err("creator_thread_or_root_binding_mismatch".into());
            }
            if expected.image_sha256.len() != 64
                || !expected
                    .image_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("invalid_expected_image_hash".into());
            }
            in_job(handle(&root), &job)?;
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            // SAFETY: exact owned job and correctly sized writable output.
            unsafe {
                QueryInformationJobObject(
                    Some(handle(&job.0)),
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                    None,
                )
            }
            .map_err(|e| format!("job_limits:{e}"))?;
            let flags = limits.BasicLimitInformation.LimitFlags;
            if !flags.contains(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
                || flags.contains(JOB_OBJECT_LIMIT_BREAKAWAY_OK)
                || flags.contains(JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
            {
                return Err("unsafe_job_limits".into());
            }
            let token =
                collect_process_token(root.as_handle()).map_err(|e| format!("root_token:{e}"))?;
            if !token_matches(&token, &expected.token) {
                return Err("root_token_binding_mismatch".into());
            }
            // SAFETY: same thread owns this debugging chain. Explicitly retain
            // Windows fail-stop behavior if the debugger dies during collection.
            unsafe { DebugSetProcessKillOnExit(true) }
                .map_err(|e| format!("debug_kill_on_exit:{e}"))?;
            Ok(())
        })();
        if let Err(error) = preflight {
            report.gap(error);
            terminate(&job, &mut report);
            return report;
        }
        // SAFETY: caller promises exactly one explicit CREATE_SUSPENDED count;
        // root is in the no-breakaway owned job before any user code can run.
        if unsafe { ResumeThread(handle(&thread)) } != 1 {
            report.gap("unexpected_primary_suspend_count");
            terminate(&job, &mut report);
            return report;
        }
        drop(thread);
        // The debugging API owns its event handles; our own duplicates will
        // retain custody once CREATE_PROCESS is delivered. Do not keep the
        // original PROCESS_INFORMATION reference through job accounting.
        drop(root);
        let started = Instant::now();
        let mut draining_since = None;
        let mut state = TraceState::default();
        let mut live = BTreeMap::<u32, LiveProcess>::new();
        let mut initial_breakpoints = std::collections::BTreeSet::new();
        let mut root_create_seen = false;
        loop {
            if draining_since.is_none() && started.elapsed() >= RUN_DEADLINE {
                report.timed_out = true;
                report.gap("debug_tree_deadline");
            }
            if draining_since.is_none()
                && (!report.gaps.is_empty() || report.events_processed >= COLLECTION_EVENTS)
            {
                if report.gaps.is_empty() {
                    report.gap("debug_event_collection_budget_exhausted");
                }
                terminate(&job, &mut report);
                draining_since = Some(Instant::now());
            }
            if report.events_processed >= MAX_EVENTS
                || draining_since.is_some_and(|t: Instant| t.elapsed() >= DRAIN_DEADLINE)
            {
                report.gap("debug_event_drain_incomplete");
                break;
            }
            if root_create_seen && state.active.is_empty() {
                // Cross-process debug-event order is not a parent-first exit
                // guarantee. A fast child's CREATE may still be queued when
                // root EXIT is continued; keep draining until job accounting
                // also says no process remains and every association is paired.
                let mut pending = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
                // SAFETY: exact owned job, bounded correctly sized output.
                if unsafe {
                    QueryInformationJobObject(
                        Some(handle(&job.0)),
                        JobObjectBasicAccountingInformation,
                        (&mut pending as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        std::mem::size_of_val(&pending) as u32,
                        None,
                    )
                }
                .is_ok()
                    && state.reconciles(
                        pending.TotalProcesses,
                        pending.ActiveProcesses,
                        pending.TotalTerminatedProcesses,
                    )
                {
                    break;
                }
            }
            let mut event = DEBUG_EVENT::default();
            // SAFETY: this is the creator OS thread and writable event storage.
            match unsafe { WaitForDebugEventEx(&mut event, 50) } {
                Ok(()) => {}
                Err(error)
                    if error.code() == ERROR_SEM_TIMEOUT.to_hresult()
                        || error.code() == ERROR_TIMEOUT.to_hresult() =>
                {
                    continue;
                }
                Err(error) => {
                    report.gap(format!("wait_debug_event:{error}"));
                    terminate(&job, &mut report);
                    break;
                }
            }
            report.events_processed += 1;
            let mut status = DBG_CONTINUE;
            match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    // SAFETY: discriminant selects the matching union member.
                    let created = unsafe { event.u.CreateProcessInfo };
                    // Own only hFile; event process/thread handles remain owned
                    // by the debugging API and must not be manually closed.
                    let event_file = if created.hFile.is_invalid() {
                        None
                    } else {
                        // SAFETY: the event transfers this file handle to us.
                        Some(unsafe { File::from_raw_handle(created.hFile.0) })
                    };
                    let registered = state.create(event.dwProcessId);
                    match registered {
                        Err(error) => report.gap(error),
                        Ok(index) => {
                            report.processes.push(ProcessObservation {
                                ordinal: index,
                                process_id: event.dwProcessId,
                                create_event_sequence: report.events_processed,
                                creation_time_100ns: None,
                                token_before_continue: None,
                                image_before_continue: None,
                                exit_code: None,
                            });
                            if event.dwProcessId == info.dwProcessId {
                                root_create_seen = true;
                            }
                            if !root_create_seen {
                                report.gap("descendant_before_root_create");
                            }
                            if draining_since.is_none() {
                                let observed = (|| -> Result<(), String> {
                                    let process = duplicate(created.hProcess)?;
                                    // SAFETY: duplicate refers to the exact process event.
                                    if unsafe { GetProcessId(handle(&process)) }
                                        != event.dwProcessId
                                    {
                                        return Err("event_pid_handle_mismatch".into());
                                    }
                                    in_job(handle(&process), &job)?;
                                    let token = collect_process_token(process.as_handle())
                                        .map_err(|e| format!("event_token:{e}"))?;
                                    report.processes[index].token_before_continue =
                                        Some(token.clone());
                                    if !token_matches(&token, &expected.token) {
                                        return Err("descendant_token_binding_mismatch".into());
                                    }
                                    report.processes[index].creation_time_100ns =
                                        Some(creation_time(handle(&process))?);
                                    let mut file = event_file.ok_or("missing_event_image_file")?;
                                    let observed_image = image(handle(&process), &mut file)?;
                                    let root_image_matches = event.dwProcessId != info.dwProcessId
                                        || (observed_image
                                            .process_image_path
                                            .strip_prefix(r"\\?\")
                                            .unwrap_or(&observed_image.process_image_path)
                                            .eq_ignore_ascii_case(expected.role.image())
                                            && observed_image.sha256 == expected.image_sha256
                                            && observed_image.size_bytes
                                                == expected.image_size_bytes);
                                    report.processes[index].image_before_continue =
                                        Some(observed_image);
                                    if !root_image_matches {
                                        return Err("root_event_image_binding_mismatch".into());
                                    }
                                    live.insert(
                                        event.dwProcessId,
                                        LiveProcess {
                                            process,
                                            _image: file,
                                        },
                                    );
                                    Ok(())
                                })();
                                if let Err(error) = observed {
                                    report.gap(error);
                                }
                            }
                        }
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    // SAFETY: discriminant selects exit-process data.
                    let exit = unsafe { event.u.ExitProcess };
                    match state.exit(event.dwProcessId, exit.dwExitCode) {
                        Ok(index) => report.processes[index].exit_code = Some(exit.dwExitCode),
                        Err(error) => report.gap(error),
                    }
                    initial_breakpoints.remove(&event.dwProcessId);
                }
                LOAD_DLL_DEBUG_EVENT => {
                    // SAFETY: discriminant selects load-DLL data. Only hFile is
                    // caller-owned; no arbitrary DLL path is opened or read.
                    let file = unsafe { event.u.LoadDll.hFile };
                    if !file.is_invalid() {
                        let _ = unsafe { CloseHandle(file) };
                    }
                }
                EXCEPTION_DEBUG_EVENT => {
                    // SAFETY: discriminant selects exception data.
                    let exception = unsafe { event.u.Exception };
                    let initialization_breakpoint = exception.dwFirstChance != 0
                        && exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
                        && state.active.contains_key(&event.dwProcessId)
                        && initial_breakpoints.insert(event.dwProcessId);
                    if !initialization_breakpoint {
                        status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                CREATE_THREAD_DEBUG_EVENT
                | EXIT_THREAD_DEBUG_EVENT
                | UNLOAD_DLL_DEBUG_EVENT
                | OUTPUT_DEBUG_STRING_EVENT => {}
                RIP_EVENT => report.gap("debug_rip_event"),
                _ => report.gap("unknown_debug_event"),
            }
            // Do not permit a mismatched target to run after observation fails.
            if draining_since.is_none() && !report.gaps.is_empty() {
                terminate(&job, &mut report);
                draining_since = Some(Instant::now());
            }
            // SAFETY: same creator/debugger thread; exact event PID/TID pair.
            if let Err(error) =
                unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) }
            {
                report.gap(format!("continue_debug_event:{error}"));
                terminate(&job, &mut report);
                break;
            }
            if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT
                && let Some(process) = live.remove(&event.dwProcessId)
            {
                // SAFETY: duplicate remains live after API-owned event handle
                // is closed by ContinueDebugEvent. No PID reopening.
                if unsafe { WaitForSingleObject(handle(&process.process), 100) } != WAIT_OBJECT_0 {
                    report.gap("continued_process_exit_not_signaled");
                }
            }
        }
        // Release retained process references before final job active-count
        // reconciliation; Windows can defer accounting while references remain.
        drop(live);
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: exact owned job, correct output structure and size.
        match unsafe {
            QueryInformationJobObject(
                Some(handle(&job.0)),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&accounting) as u32,
                None,
            )
        } {
            Ok(()) => {
                report.job_total_processes = Some(accounting.TotalProcesses);
                report.job_active_processes = Some(accounting.ActiveProcesses);
                report.job_limit_terminated_processes = Some(accounting.TotalTerminatedProcesses);
                report.job_accounting_reconciled = state.reconciles(
                    accounting.TotalProcesses,
                    accounting.ActiveProcesses,
                    accounting.TotalTerminatedProcesses,
                );
                if !report.job_accounting_reconciled {
                    report.gap("job_debug_accounting_mismatch");
                }
            }
            Err(error) => report.gap(format!("final_job_accounting:{error}")),
        }
        report.debugger_chain_complete = root_create_seen
            && report.gaps.is_empty()
            && report.job_accounting_reconciled
            && report.processes.iter().all(|p| {
                p.token_before_continue.is_some()
                    && p.image_before_continue.is_some()
                    && p.exit_code.is_some()
            });
        report.requires_debugger_process_exit = report.requires_exit(&state, root_create_seen);
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuation_failure_requires_fail_stop_even_after_all_job_processes_exit() {
        let mut state = TraceState::default();
        state.create(10).unwrap();
        state.exit(10, 0).unwrap();
        let mut report = DebugTreeReport::new(10);
        report.job_accounting_reconciled = true;
        assert!(!report.requires_exit(&state, true));
        report.gap("continue_debug_event_failed");
        assert!(report.requires_exit(&state, true));
    }

    fn standard_token() -> TokenEvidence {
        TokenEvidence {
            schema_version: aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION.into(),
            process_id: 100,
            token_type: TokenType::Primary,
            impersonation_level: None,
            is_app_container: false,
            app_container_sid: None,
            user_sid: "S-1-5-21-1-2-3-1001".into(),
            integrity: aiw_token::IntegrityEvidence {
                sid: "S-1-16-8192".into(),
                rid: 0x2000,
                level: aiw_token::IntegrityLevel::Medium,
            },
            elevation_type: aiw_token::ElevationType::Default,
            is_elevated: false,
            capabilities: Vec::new(),
            restricted_sid_count: 0,
        }
    }

    #[test]
    fn descendants_must_match_the_validated_token_without_added_authority() {
        let expected = standard_token();
        let mut child = expected.clone();
        child.process_id = 101;
        assert!(token_matches(&child, &expected));
        child.is_elevated = true;
        assert!(!token_matches(&child, &expected));
        child = expected.clone();
        child.user_sid = "S-1-5-18".into();
        assert!(!token_matches(&child, &expected));
        child = expected.clone();
        child.capabilities.push(aiw_token::SidAndAttributes {
            sid: "S-1-15-3-1".into(),
            attributes: 4,
        });
        assert!(!token_matches(&child, &expected));
        child = expected.clone();
        child.is_app_container = true;
        child.app_container_sid = Some("S-1-15-2-123".into());
        assert!(!token_matches(&child, &expected));
        child = expected.clone();
        child.token_type = TokenType::Impersonation;
        assert!(!token_matches(&child, &expected));
    }

    #[test]
    fn fast_child_grandchild_events_reconcile_even_with_root_exiting_first() {
        let mut s = TraceState::default();
        assert_eq!(s.create(10), Ok(0));
        assert_eq!(s.create(11), Ok(1));
        assert_eq!(s.create(12), Ok(2));
        assert_eq!(s.exit(10, 0), Ok(0));
        assert!(!s.reconciles(3, 2, 0));
        s.exit(12, 0).unwrap();
        s.exit(11, 0).unwrap();
        assert!(s.reconciles(3, 0, 0));
        assert!(!s.reconciles(4, 0, 0));
        assert!(!s.reconciles(3, 0, 1));
    }

    #[test]
    fn duplicate_missing_and_reused_pids_do_not_fabricate_pairs() {
        let mut s = TraceState::default();
        assert!(s.create(0).is_err());
        s.create(5).unwrap();
        assert!(s.create(5).is_err());
        assert!(s.exit(6, 0).is_err());
        s.exit(5, 0).unwrap();
        assert!(s.exit(5, 0).is_err());
        assert_eq!(s.create(5), Ok(1));
        assert!(!s.reconciles(2, 0, 0));
        s.exit(5, 1).unwrap();
        assert!(s.reconciles(2, 0, 0));
    }

    #[test]
    fn bounded_state_refuses_more_processes_and_empty_trace_is_not_complete() {
        let mut s = TraceState::default();
        assert!(!s.reconciles(0, 0, 0));
        for pid in 1..=MAX_PROCESSES as u32 {
            s.create(pid).unwrap();
            s.exit(pid, 0).unwrap();
        }
        assert!(s.create(1000).is_err());
        assert!(s.reconciles(MAX_PROCESSES as u32, 0, 0));
    }
}
