//! Private foundation for creation-time debugger-chain observations.
//!
//! Fixed controls and application observations use separate root policies.
//! This is neither an arbitrary launcher nor
//! an all-host descendant census. DEBUG_PROCESS chains can be reset by children;
//! broker/WMI creation is outside the supported CreateProcess-tree scope.
use std::collections::BTreeMap;

use aiw_provider_wsb::sevenzip_code_control::{
    SevenZipControlCodeEvidence, classify_control_image,
};
use aiw_provider_wsb::sevenzip_process_tree::SevenZipImageObservation;
use aiw_provider_wsb::sevenzip_tree_control::SevenZipConsoleSupportObservation;
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
    InstallationSetup,
    Control,
}

impl RootRole {
    fn image(self) -> &'static str {
        match self {
            Self::SevenZip => r"C:\AIW\SevenZip\App\7z.exe",
            Self::InstallationSetup => r"C:\AIW\SevenZip\7z2605-x64.exe",
            Self::Control => r"C:\AIW\SevenZip\sevenzip_assessment.exe",
        }
    }

    fn run_deadline(self) -> std::time::Duration {
        std::time::Duration::from_secs(match self {
            Self::Control => 5,
            Self::SevenZip => 25,
            Self::InstallationSetup => 90,
        })
    }
}

pub(crate) fn token_matches_for_role(
    actual: &TokenEvidence,
    expected: &TokenEvidence,
    process_id: u32,
    role: RootRole,
) -> bool {
    if !matches!(role, RootRole::InstallationSetup) {
        return token_matches(actual, expected, process_id);
    }
    let high_setup = |token: &TokenEvidence, pid| {
        token.schema_version == aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
            && token.process_id == pid
            && pid != 0
            && token.token_type == TokenType::Primary
            && token.impersonation_level.is_none()
            && token.is_elevated
            && !token.is_app_container
            && token.app_container_sid.is_none()
            && token.integrity.rid == 0x3000
            && token.integrity.sid == "S-1-16-12288"
            && token.integrity.level == aiw_token::IntegrityLevel::High
            && token.capabilities.is_empty()
    };
    let mut normalized = actual.clone();
    normalized.process_id = expected.process_id;
    high_setup(expected, expected.process_id)
        && high_setup(actual, process_id)
        && normalized == *expected
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
    pub console_support: Option<SevenZipConsoleSupportObservation>,
}

fn token_matches(actual: &TokenEvidence, expected: &TokenEvidence, process_id: u32) -> bool {
    actual.schema_version == aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
        && expected.schema_version == aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
        && process_id != 0
        && expected.process_id != 0
        && actual.process_id == process_id
        && actual.token_type == TokenType::Primary
        && expected.token_type == TokenType::Primary
        && actual.impersonation_level.is_none()
        && expected.impersonation_level.is_none()
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImageObservation {
    pub process_image_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub volume_serial_number: u32,
    pub file_index: u64,
}

impl ImageObservation {
    fn code_observation(&self) -> SevenZipImageObservation {
        SevenZipImageObservation {
            process_image_path: self.process_image_path.clone(),
            sha256: self.sha256.clone(),
            size_bytes: self.size_bytes,
            volume_serial_number: self.volume_serial_number,
            file_index: self.file_index,
        }
    }
}

fn root_event_image_matches(
    ordinal: usize,
    event_pid: u32,
    root_pid: u32,
    expected: &ExpectedBinding,
    image: &ImageObservation,
) -> bool {
    ordinal != 0
        || (event_pid == root_pid
            && image
                .process_image_path
                .strip_prefix(r"\\?\")
                .unwrap_or(&image.process_image_path)
                .eq_ignore_ascii_case(expected.role.image())
            && image.sha256 == expected.image_sha256
            && image.size_bytes == expected.image_size_bytes)
}

fn validate_control_binding(expected: &ExpectedBinding) -> Result<(), String> {
    if matches!(expected.role, RootRole::Control) {
        expected
            .console_support
            .as_ref()
            .ok_or("control_requires_independently_held_console_support")?
            .validate_pinned()?;
    }
    Ok(())
}

fn classify_before_continue(
    expected: &ExpectedBinding,
    image: &ImageObservation,
) -> Result<Option<aiw_provider_wsb::sevenzip_code_control::SevenZipControlCodeClass>, String> {
    if !matches!(expected.role, RootRole::Control) {
        return Ok(None);
    }
    let console = expected
        .console_support
        .as_ref()
        .ok_or("control_requires_independently_held_console_support")?;
    classify_control_image(
        &image.code_observation(),
        &expected.image_sha256,
        expected.image_size_bytes,
        console,
    )
    .map(Some)
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
    pub exit_event_sequence: Option<u32>,
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
    // New contract evidence is deliberately outside the historical chain JSON.
    #[serde(skip)]
    pub code_evidence: Vec<SevenZipControlCodeEvidence>,
}

impl DebugTreeReport {
    fn new(root_process_id: u32) -> Self {
        Self {
            schema_version: aiw_provider_wsb::sevenzip_process_tree::SEVENZIP_PROCESS_CHAIN_SCHEMA,
            scope: aiw_provider_wsb::sevenzip_process_tree::SEVENZIP_PROCESS_CHAIN_SCOPE,
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
            code_evidence: Vec::new(),
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

    fn may_continue_pending_event(&self) -> bool {
        !self.owned_job_termination_requested || self.owned_job_termination_succeeded
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
    // Closed role budgets preserve control5/app25/installer90 second bounds.
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

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ImageFileIdentity {
        attributes: u32,
        links: u32,
        volume: u32,
        index: u64,
        size: u64,
        creation: u64,
        last_write: u64,
    }

    fn file_identity(file: &File) -> Result<ImageFileIdentity, String> {
        let file_handle = HANDLE(file.as_raw_handle());
        // SAFETY: file owns this exact event image handle; no path is reopened.
        if unsafe { GetFileType(file_handle) } != FILE_TYPE_DISK {
            return Err("non_disk_event_image".into());
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: live held file and correctly sized writable output.
        unsafe { GetFileInformationByHandle(file_handle, &mut info) }
            .map_err(|e| format!("event_image_identity:{e}"))?;
        if info.dwFileAttributes & 0x450 != 0 || info.nNumberOfLinks != 1 {
            return Err("event_image_type_or_links_rejected".into());
        }
        let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
        if size == 0 || size > MAX_IMAGE_BYTES {
            return Err("event_image_size_rejected".into());
        }
        let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        if info.dwVolumeSerialNumber == 0 || index == 0 {
            return Err("zero_event_image_identity".into());
        }
        let time = |value: FILETIME| {
            (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
        };
        Ok(ImageFileIdentity {
            attributes: info.dwFileAttributes,
            links: info.nNumberOfLinks,
            volume: info.dwVolumeSerialNumber,
            index,
            size,
            creation: time(info.ftCreationTime),
            last_write: time(info.ftLastWriteTime),
        })
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ImageSnapshot {
        image: ImageObservation,
        identity: ImageFileIdentity,
    }

    // Private hook for deterministic same-stream mutation regression tests.
    // Production supplies a no-op; no callback is exposed to callers.
    fn image_snapshot_with(
        file: &mut File,
        process_image_path: &str,
        after_read: impl FnOnce() -> Result<(), String>,
    ) -> Result<ImageSnapshot, String> {
        let before = file_identity(file)?;
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
            if read > before.size {
                return Err("event_image_changed_during_read".into());
            }
            hash.update(&buffer[..count]);
        }
        if read != before.size {
            return Err("event_image_truncated".into());
        }
        after_read()?;
        let after = file_identity(file)?;
        if before != after {
            return Err("event_image_identity_changed_during_read".into());
        }
        Ok(ImageSnapshot {
            image: ImageObservation {
                process_image_path: process_image_path.into(),
                sha256: hex::encode(hash.finalize()),
                size_bytes: before.size,
                volume_serial_number: before.volume,
                file_index: before.index,
            },
            identity: before,
        })
    }

    fn image_snapshot(file: &mut File, path: &str) -> Result<ImageSnapshot, String> {
        image_snapshot_with(file, path, || Ok(()))
    }

    fn image_at_create(process: HANDLE, file: &mut File) -> Result<ImageSnapshot, String> {
        let mut path = vec![0_u16; 32768];
        let mut length = path.len() as u32;
        // SAFETY: exact live event process; this query is never used at EXIT.
        unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(path.as_mut_ptr()),
                &mut length,
            )
        }
        .map_err(|e| format!("event_process_image_name:{e}"))?;
        let path = String::from_utf16(&path[..length as usize])
            .map_err(|_| "event_process_image_name_not_unicode".to_string())?;
        image_snapshot(file, &path)
    }

    struct LiveProcess {
        process: OwnedHandle,
        image: File,
        initial: ImageSnapshot,
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
            validate_control_binding(&expected)?;
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
            if !token_matches_for_role(&token, &expected.token, info.dwProcessId, expected.role) {
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
            if draining_since.is_none() && started.elapsed() >= expected.role.run_deadline() {
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
            // A failed kill never permits another debuggee event to resume.
            if !report.may_continue_pending_event() {
                break;
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
                                exit_event_sequence: None,
                            });
                            report.code_evidence.push(SevenZipControlCodeEvidence {
                                ordinal: index,
                                process_id: event.dwProcessId,
                                create_event_sequence: report.events_processed,
                                code_class_before_continue: None,
                                image_after_exit: None,
                            });
                            if index == 0 && event.dwProcessId == info.dwProcessId {
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
                                    if !token_matches_for_role(
                                        &token,
                                        &expected.token,
                                        event.dwProcessId,
                                        expected.role,
                                    ) {
                                        return Err("descendant_token_binding_mismatch".into());
                                    }
                                    report.processes[index].creation_time_100ns =
                                        Some(creation_time(handle(&process))?);
                                    let mut file = event_file.ok_or("missing_event_image_file")?;
                                    let initial = image_at_create(handle(&process), &mut file)?;
                                    let observed_image = &initial.image;
                                    let root_image_matches = root_event_image_matches(
                                        index,
                                        event.dwProcessId,
                                        info.dwProcessId,
                                        &expected,
                                        observed_image,
                                    );
                                    report.processes[index].image_before_continue =
                                        Some(observed_image.clone());
                                    if !root_image_matches {
                                        return Err("root_event_image_binding_mismatch".into());
                                    }
                                    // EVERY Control image is classified before
                                    // its CREATE event may resume user execution.
                                    report.code_evidence[index].code_class_before_continue =
                                        classify_before_continue(&expected, observed_image)?;
                                    live.insert(
                                        event.dwProcessId,
                                        LiveProcess {
                                            process,
                                            image: file,
                                            initial,
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
                        Ok(index) => {
                            report.processes[index].exit_code = Some(exit.dwExitCode);
                            report.processes[index].exit_event_sequence =
                                Some(report.events_processed);
                            if let Some(process) = live.get_mut(&event.dwProcessId) {
                                // Rehash the SAME event file. The cached logical
                                // path came from CREATE, never a dead PID query.
                                match image_snapshot(
                                    &mut process.image,
                                    &process.initial.image.process_image_path,
                                ) {
                                    Ok(after) => {
                                        report.code_evidence[index].image_after_exit =
                                            Some(after.image.code_observation());
                                        if after != process.initial {
                                            report.gap("event_image_changed_before_exit");
                                        }
                                    }
                                    Err(error) => report.gap(format!("exit_image:{error}")),
                                }
                            } else if draining_since.is_none() {
                                report.gap("exit_without_held_event_image");
                            }
                        }
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
            // Leave the pending event suspended and require dedicated debugger
            // process fail-stop if the owned job could not be terminated.
            if !report.may_continue_pending_event() {
                break;
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
                    && p.exit_event_sequence.is_some()
            });
        report.requires_debugger_process_exit = report.requires_exit(&state, root_create_seen);
        report
    }

    #[cfg(test)]
    mod image_tests {
        use super::*;
        use std::io::{Seek, SeekFrom, Write};
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);

        struct Fixture {
            path: std::path::PathBuf,
            file: Option<File>,
        }
        impl Fixture {
            fn new(bytes: &[u8]) -> Self {
                let path = std::env::temp_dir().join(format!(
                    "aiw-debug-image-{}-{}-{}.dat",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos(),
                    NEXT.fetch_add(1, Ordering::Relaxed),
                ));
                let mut file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .unwrap();
                file.write_all(bytes).unwrap();
                file.sync_all().unwrap();
                Self {
                    path,
                    file: Some(file),
                }
            }
            fn file(&mut self) -> &mut File {
                self.file.as_mut().unwrap()
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                drop(self.file.take());
                let _ = std::fs::remove_file(&self.path);
            }
        }

        #[test]
        fn same_event_stream_is_stable_then_detects_lifetime_byte_change() {
            let mut fixture = Fixture::new(b"original bytes");
            // Inert arbitrary bytes are data; no image is loaded or executed.
            let initial = image_snapshot(fixture.file(), "fixed-logical-image").unwrap();
            assert_eq!(
                initial,
                image_snapshot(fixture.file(), "fixed-logical-image").unwrap()
            );
            fixture.file().seek(SeekFrom::Start(0)).unwrap();
            fixture.file().write_all(b"modified bytes").unwrap();
            fixture.file().sync_all().unwrap();
            let after = image_snapshot(fixture.file(), "fixed-logical-image").unwrap();
            assert_eq!(initial.image.file_index, after.image.file_index);
            assert_eq!(initial.image.size_bytes, after.image.size_bytes);
            assert_ne!(initial.image.sha256, after.image.sha256);
            assert_ne!(initial, after);
        }

        #[test]
        fn revalidation_detects_change_after_read_before_snapshot_acceptance() {
            let mut fixture = Fixture::new(b"original bytes");
            let writer = fixture.file().try_clone().unwrap();
            let result = image_snapshot_with(fixture.file(), "fixed-logical-image", || {
                writer.set_len(2).map_err(|e| e.to_string())?;
                writer.sync_all().map_err(|e| e.to_string())
            });
            assert_eq!(
                result.unwrap_err(),
                "event_image_identity_changed_during_read"
            );
        }

        #[test]
        fn empty_and_oversize_event_images_refuse_before_hashing() {
            let mut fixture = Fixture::new(b"");
            assert_eq!(
                image_snapshot(fixture.file(), "fixed").unwrap_err(),
                "event_image_size_rejected"
            );
            fixture.file().set_len(MAX_IMAGE_BYTES + 1).unwrap();
            assert_eq!(
                image_snapshot(fixture.file(), "fixed").unwrap_err(),
                "event_image_size_rejected"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn elevated_setup_policy_never_relaxes_application_or_control_tokens() {
        let mut setup = standard_token();
        setup.is_elevated = true;
        setup.elevation_type = aiw_token::ElevationType::Full;
        setup.integrity.rid = 0x3000;
        setup.integrity.sid = "S-1-16-12288".into();
        setup.integrity.level = aiw_token::IntegrityLevel::High;
        assert!(token_matches_for_role(
            &setup,
            &setup,
            setup.process_id,
            RootRole::InstallationSetup
        ));
        for role in [RootRole::Control, RootRole::SevenZip] {
            assert!(!token_matches_for_role(
                &setup,
                &setup,
                setup.process_id,
                role
            ));
        }
        let mut changed = setup.clone();
        changed.user_sid = "S-1-5-18".into();
        assert!(!token_matches_for_role(
            &changed,
            &setup,
            changed.process_id,
            RootRole::InstallationSetup
        ));
        changed = setup.clone();
        changed.is_app_container = true;
        assert!(!token_matches_for_role(
            &changed,
            &changed,
            changed.process_id,
            RootRole::InstallationSetup
        ));
        changed = setup.clone();
        changed.integrity.sid = "S-1-16-4096".into();
        assert!(!token_matches_for_role(
            &changed,
            &changed,
            changed.process_id,
            RootRole::InstallationSetup
        ));
        assert_eq!(RootRole::Control.run_deadline().as_secs(), 5);
        assert_eq!(RootRole::SevenZip.run_deadline().as_secs(), 25);
        assert_eq!(RootRole::InstallationSetup.run_deadline().as_secs(), 90);
    }
    #[test]
    fn failed_termination_never_authorizes_continuing_a_pending_event() {
        let mut report = DebugTreeReport::new(10);
        assert!(report.may_continue_pending_event());
        report.owned_job_termination_requested = true;
        report.gap("terminate_owned_job:inert injected failure");
        assert!(!report.may_continue_pending_event());
        assert!(report.requires_exit(&TraceState::default(), true));
        report.owned_job_termination_succeeded = true;
        assert!(report.may_continue_pending_event());
        // A successful kill allows exit-event draining, never a complete claim.
        assert!(report.requires_exit(&TraceState::default(), true));
    }

    fn control_binding() -> ExpectedBinding {
        use aiw_provider_wsb::sevenzip_tree_control::{
            SEVENZIP_CONSOLE_SUPPORT_PATH, SEVENZIP_CONSOLE_SUPPORT_SCHEMA,
            SEVENZIP_CONSOLE_SUPPORT_SHA256, SEVENZIP_CONSOLE_SUPPORT_SIZE,
        };
        ExpectedBinding {
            creator_thread_id: 1,
            role: RootRole::Control,
            image_sha256: "a".repeat(64),
            image_size_bytes: 100,
            token: standard_token(),
            console_support: Some(SevenZipConsoleSupportObservation {
                schema_version: SEVENZIP_CONSOLE_SUPPORT_SCHEMA.into(),
                windows: aiw_probe::WindowsVersionObservation {
                    major: 10,
                    minor: 0,
                    build: 26100,
                    revision: 9711,
                    observer_architecture: "x86_64".into(),
                },
                canonical_path: SEVENZIP_CONSOLE_SUPPORT_PATH.into(),
                identity: aiw_probe::WindowsFileIdentity {
                    final_path: SEVENZIP_CONSOLE_SUPPORT_PATH.into(),
                    volume_serial_number: "1111111111111111".into(),
                    file_id: "11111111111111111111111111111111".into(),
                },
                sha256: SEVENZIP_CONSOLE_SUPPORT_SHA256.into(),
                size_bytes: SEVENZIP_CONSOLE_SUPPORT_SIZE,
                volume_serial_number: 1,
                file_index: 2,
            }),
        }
    }

    #[test]
    fn root_image_gate_binds_first_lifetime_without_rejecting_later_pid_reuse() {
        let expected = control_binding();
        let mut image = ImageObservation {
            process_image_path: expected.role.image().into(),
            sha256: expected.image_sha256.clone(),
            size_bytes: expected.image_size_bytes,
            volume_serial_number: 77,
            file_index: 99,
        };
        assert!(root_event_image_matches(0, 10, 10, &expected, &image));
        assert!(!root_event_image_matches(0, 11, 10, &expected, &image));
        image.process_image_path = expected
            .console_support
            .as_ref()
            .unwrap()
            .canonical_path
            .clone();
        assert!(!root_event_image_matches(0, 10, 10, &expected, &image));
        let mut state = TraceState::default();
        assert_eq!(state.create(10), Ok(0));
        state.exit(10, 31).unwrap();
        let reused = state.create(10).unwrap();
        assert_eq!(reused, 1);
        // The independent per-CREATE classifier still checks this lifetime's code.
        assert!(root_event_image_matches(reused, 10, 10, &expected, &image));
        assert!(classify_before_continue(&expected, &image).is_err());
        let support = expected.console_support.as_ref().unwrap();
        image.sha256 = support.sha256.clone();
        image.size_bytes = support.size_bytes;
        assert!(classify_before_continue(&expected, &image).is_ok());
    }

    #[test]
    fn control_requires_pinned_support_before_resume_and_classifies_every_create() {
        use aiw_provider_wsb::sevenzip_code_control::SevenZipControlCodeClass;
        let mut expected = control_binding();
        validate_control_binding(&expected).unwrap();
        let mut image = ImageObservation {
            process_image_path: expected.role.image().into(),
            sha256: expected.image_sha256.clone(),
            size_bytes: expected.image_size_bytes,
            volume_serial_number: 77,
            file_index: 99,
        };
        assert_eq!(
            classify_before_continue(&expected, &image).unwrap(),
            Some(SevenZipControlCodeClass::RootCode)
        );
        let support = expected.console_support.as_ref().unwrap();
        image.process_image_path = support.canonical_path.clone();
        image.sha256 = support.sha256.clone();
        image.size_bytes = support.size_bytes;
        // Distinct independently observed object IDs do not imply equivalence.
        assert_eq!(
            classify_before_continue(&expected, &image).unwrap(),
            Some(SevenZipControlCodeClass::ConsoleSupport)
        );
        image.sha256 = "b".repeat(64);
        assert!(classify_before_continue(&expected, &image).is_err());
        image.sha256 = support.sha256.clone();
        image.process_image_path = r"C:\AIW\unexpected.exe".into();
        assert!(classify_before_continue(&expected, &image).is_err());
        expected.console_support.as_mut().unwrap().windows.build = 26300;
        assert!(validate_control_binding(&expected).is_err());
        expected.console_support = None;
        assert!(validate_control_binding(&expected).is_err());
        assert!(classify_before_continue(&expected, &image).is_err());
        expected.role = RootRole::SevenZip;
        assert_eq!(classify_before_continue(&expected, &image).unwrap(), None);
    }

    #[test]
    fn new_code_sidecar_never_changes_historical_chain_serialization() {
        let mut report = DebugTreeReport::new(10);
        let before = serde_json::to_value(&report).unwrap();
        report.code_evidence.push(SevenZipControlCodeEvidence {
            ordinal: 0,
            process_id: 10,
            create_event_sequence: 1,
            code_class_before_continue: None,
            image_after_exit: None,
        });
        assert_eq!(before, serde_json::to_value(&report).unwrap());
        assert!(before.get("codeEvidence").is_none());
    }
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
        assert!(token_matches(&child, &expected, child.process_id));
        assert!(!token_matches(&child, &expected, child.process_id + 1));
        let mut wrong_schema = child.clone();
        wrong_schema.schema_version = "wrong".into();
        assert!(!token_matches(
            &wrong_schema,
            &expected,
            wrong_schema.process_id
        ));
        child.is_elevated = true;
        assert!(!token_matches(&child, &expected, child.process_id));
        child = expected.clone();
        child.user_sid = "S-1-5-18".into();
        assert!(!token_matches(&child, &expected, child.process_id));
        child = expected.clone();
        child.capabilities.push(aiw_token::SidAndAttributes {
            sid: "S-1-15-3-1".into(),
            attributes: 4,
        });
        assert!(!token_matches(&child, &expected, child.process_id));
        child = expected.clone();
        child.is_app_container = true;
        child.app_container_sid = Some("S-1-15-2-123".into());
        assert!(!token_matches(&child, &expected, child.process_id));
        child = expected.clone();
        child.token_type = TokenType::Impersonation;
        assert!(!token_matches(&child, &expected, child.process_id));
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
