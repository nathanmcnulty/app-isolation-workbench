//! One native suspended launch, exact owned job, fair bounded pipe draining.
//! No shell, PATH lookup or detached readers; suspended handle checks precede Resume.
use super::{Result, bound_error};
use crate::{
    HeldApplicationFile,
    control_appcontainer::{Attributes, Job},
    guest_standard_user::StandardUserSession,
};
use aiw_provider_wsb::StandardUserRuntimeContext;
use aiw_provider_wsb::assessment_observation::*;
use aiw_token::{ElevationType, IntegrityLevel, TokenEvidence, TokenType};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::File,
    io::Read,
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{
            FILETIME, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0,
            WAIT_TIMEOUT,
        },
        Security::{PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES},
        System::{
            JobObjects::{AssignProcessToJobObject, IsProcessInJob},
            Pipes::{CreatePipe, PeekNamedPipe},
            Threading::{
                CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
                CreateProcessAsUserW, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
                GetProcessTimes, PROCESS_INFORMATION, PROCESS_NAME_WIN32,
                QueryFullProcessImageNameW, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
                TerminateProcess, WaitForSingleObject,
            },
        },
    },
    core::{BOOL, PCWSTR, PWSTR},
};

fn raw(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn ProcessIdToSessionId(process_id: u32, session_id: *mut u32) -> BOOL;
}
fn same_session(process: HANDLE, pid: u32) -> Result<()> {
    use windows::Win32::{
        Security::{GetTokenInformation, TOKEN_QUERY, TokenSessionId},
        System::Threading::{GetCurrentProcessId, OpenProcessToken},
    };
    let (mut actual, mut current) = (0, 0);
    unsafe { ProcessIdToSessionId(pid, &mut actual) }
        .ok()
        .map_err(|e| e.to_string())?;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut current) }
        .ok()
        .map_err(|e| e.to_string())?;
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.map_err(|e| e.to_string())?;
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    let mut token_session = 0u32;
    let mut returned = 0;
    unsafe {
        GetTokenInformation(
            raw(&token),
            TokenSessionId,
            Some((&mut token_session as *mut u32).cast()),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
    }
    .map_err(|e| e.to_string())?;
    if current != 0 || actual != current || token_session != current || returned != 4 {
        return Err(format!(
            "suspended application session differs: token={token_session}; physical={actual}; collector={current}; returnedBytes={returned}"
        ));
    }
    Ok(())
}
fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let value: Vec<_> = value.encode_wide().chain(Some(0)).collect();
    if value[..value.len() - 1].contains(&0) {
        return Err("NUL in native argument".into());
    }
    Ok(value)
}
fn validate_command(command: &[u16]) -> Result<()> {
    // Keep the existing conservative command bound, including terminating NUL.
    if command.len() > 1024 {
        return Err("assessment command exceeds 1024 UTF-16 units including NUL".into());
    }
    Ok(())
}
#[derive(Default)]
struct Prefix {
    bytes: Vec<u8>,
    limit: u64,
    overflow: bool,
    eof: bool,
    error: Option<String>,
}
impl Prefix {
    fn append(&mut self, bytes: &[u8]) {
        let available = self.limit.saturating_sub(self.bytes.len() as u64) as usize;
        self.bytes
            .extend_from_slice(&bytes[..bytes.len().min(available)]);
        self.overflow |= bytes.len() > available;
    }
    fn observation(&self) -> AssessmentCapture {
        AssessmentCapture {
            bytes_hex: hex::encode(&self.bytes),
            sha256: hex::encode(Sha256::digest(&self.bytes)),
            size_bytes: self.bytes.len() as u64,
            limit_bytes: self.limit,
            overflowed: self.overflow,
            complete: self.eof && self.error.is_none() && !self.overflow,
            read_error: self.error.clone(),
        }
    }
}
struct Pipe {
    read: File,
    write: Option<OwnedHandle>,
    prefix: Prefix,
}
impl Pipe {
    fn new(limit: u64) -> Result<Self> {
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: BOOL(1),
            ..Default::default()
        };
        // SAFETY: valid outputs and bounded pipe, both handles immediately owned.
        unsafe { CreatePipe(&mut read, &mut write, Some(&attributes), 65536) }
            .map_err(|e| e.to_string())?;
        let read = unsafe { File::from_raw_handle(read.0) };
        let write = unsafe { OwnedHandle::from_raw_handle(write.0) };
        unsafe {
            SetHandleInformation(
                HANDLE(read.as_raw_handle()),
                HANDLE_FLAG_INHERIT.0,
                Default::default(),
            )
        }
        .map_err(|e| e.to_string())?;
        Ok(Self {
            read,
            write: Some(write),
            prefix: Prefix {
                limit,
                ..Default::default()
            },
        })
    }
    fn writer(&self) -> HANDLE {
        raw(self.write.as_ref().expect("writer retained until creation"))
    }
    fn poll(&mut self) {
        if self.prefix.eof || self.prefix.error.is_some() {
            return;
        }
        let mut available = 0;
        // Only this collector owns the read end. Read at most the bytes already
        // available; no blocking ReadFile or unjoinable background reader.
        let peek = unsafe {
            PeekNamedPipe(
                HANDLE(self.read.as_raw_handle()),
                None,
                0,
                None,
                Some(&mut available),
                None,
            )
        };
        if let Err(error) = peek {
            if matches!(error.code().0 as u32, 0x8007006d | 0x800700e8) {
                self.prefix.eof = true;
            } else {
                self.prefix.error = Some(bound_error(&format!("PeekNamedPipe: {error}")));
            }
            return;
        }
        if available == 0 {
            return;
        }
        let mut buffer = [0u8; 16384];
        let amount = (available as usize).min(buffer.len());
        match self.read.read(&mut buffer[..amount]) {
            Ok(0) => self.prefix.eof = true,
            Ok(count) => self.prefix.append(&buffer[..count]),
            Err(error) => self.prefix.error = Some(bound_error(&format!("pipe read: {error}"))),
        }
    }
}

pub(super) fn validate_boundary(
    token: &TokenEvidence,
    pid: u32,
    context: &StandardUserRuntimeContext,
    profile_sid: Option<&str>,
) -> Result<()> {
    if token.schema_version != aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
        || token.process_id != pid
        || token.user_sid != context.user_sid
        || token.token_type != TokenType::Primary
        || token.impersonation_level.is_some()
        || token.is_elevated
        || token.elevation_type != ElevationType::Default
    {
        return Err("suspended child primary identity differs".into());
    }
    match profile_sid {
        None => context.validate_token(token),
        Some(sid) => {
            if !token.is_app_container
                || token.app_container_sid.as_deref() != Some(sid)
                || !token.capabilities.is_empty()
                || token.integrity.level != IntegrityLevel::Low
                || token.integrity.rid != 4096
                || token.integrity.sid != "S-1-16-4096"
            {
                return Err("suspended zero-capability AppContainer token differs".into());
            }
            Ok(())
        }
    }
}

pub(super) struct Launch<'a> {
    pub image: &'a HeldApplicationFile,
    pub arguments: &'a [String],
    pub cwd: &'a Path,
    pub context: &'a StandardUserRuntimeContext,
    pub profile: Option<(PSID, &'a str)>,
    pub user: &'a StandardUserSession,
    pub collector_unimpersonated: &'a mut Option<bool>,
    pub progress: &'a mut super::progress::Progress,
    pub step_index: usize,
    pub deadline: Instant,
    pub stdout_limit: u64,
    pub stderr_limit: u64,
}
fn pe_fields(header: &[u8], file_size: u64) -> Result<(u16, u16, u16)> {
    if header.len() < 64 || &header[..2] != b"MZ" {
        return Err("execution image lacks bounded DOS header".into());
    }
    let offset = u32::from_le_bytes(header[60..64].try_into().map_err(|_| "DOS offset")?) as usize;
    let fixed_end = offset.checked_add(24).ok_or("PE offset overflow")?;
    if offset < 64
        || fixed_end > header.len()
        || header.get(offset..offset + 4) != Some(b"PE\0\0".as_slice())
    {
        return Err("execution image PE header offset/signature refused".into());
    }
    let machine = u16::from_le_bytes([header[offset + 4], header[offset + 5]]);
    let optional_size = u16::from_le_bytes([header[offset + 20], header[offset + 21]]) as usize;
    let characteristics = u16::from_le_bytes([header[offset + 22], header[offset + 23]]);
    let end = fixed_end
        .checked_add(optional_size)
        .ok_or("optional header overflow")?;
    if optional_size < 112 || end > header.len() || end as u64 > file_size {
        return Err("execution image optional header exceeds bounded held extent".into());
    }
    let magic = u16::from_le_bytes([header[fixed_end], header[fixed_end + 1]]);
    Ok((machine, magic, characteristics))
}
fn pe_machine(header: &[u8], file_size: u64) -> Result<String> {
    let (machine, magic, characteristics) = pe_fields(header, file_size)?;
    if machine != 0x8664
        || magic != 0x20b
        || characteristics & 0x0002 == 0
        || characteristics & 0x2000 != 0
    {
        return Err(format!(
            "execution image unsupported machine/magic/kind: {machine:#06x}/{magic:#06x}/{characteristics:#06x}"
        ));
    }
    Ok("amd64-pe32plus".into())
}
pub(super) fn observe_image(image: &HeldApplicationFile) -> Result<AssessmentImageObservation> {
    let header = image.read_execution_header().map_err(|e| e.to_string())?;
    let fact = image.observation();
    let mut result = AssessmentImageObservation {
        identity: fact.identity.clone(),
        sha256: fact.sha256.clone(),
        size_bytes: fact.size_bytes,
        machine: None,
        optional_header_magic: None,
        architecture_error: None,
    };
    match pe_fields(&header, fact.size_bytes) {
        Ok((machine, magic, _)) => {
            result.machine = Some(format!("0x{machine:04x}"));
            result.optional_header_magic = Some(format!("0x{magic:04x}"));
        }
        Err(error) => result.architecture_error = Some(bound_error(&error)),
    }
    if let Err(error) = pe_machine(&header, fact.size_bytes) {
        result.architecture_error = Some(bound_error(&error));
    }
    Ok(result)
}
pub(super) fn launch(spec: Launch<'_>) -> Result<AssessmentProcessObservation> {
    // Key acknowledgement alone is never dispatch authority. Revalidate actual
    // local15/object-access/security/thread gates before ANY process creation.
    spec.progress.require_dispatch()?;
    if Instant::now() >= spec.deadline {
        return Err("launch deadline already expired".into());
    }
    super::check_collector(&mut *spec.collector_unimpersonated)?;
    let _cwd = super::files::Directories::hold(spec.cwd)?;
    spec.image.revalidate().map_err(|e| e.to_string())?;
    let header = spec
        .image
        .read_execution_header()
        .map_err(|e| e.to_string())?;
    let image_machine = pe_machine(&header, spec.image.observation().size_bytes)?;
    let identity = spec.image.observation().clone();
    let image = wide(OsStr::new(&identity.canonical_path))?;
    let cwd = wide(spec.cwd.as_os_str())?;
    let mut command = wide(OsStr::new(&aiw_windows_command_line::join_arguments(
        std::iter::once(identity.canonical_path.as_str())
            .chain(spec.arguments.iter().map(String::as_str)),
    )))?;
    validate_command(&command)?;
    // Versioned noninteractiveLogonDefault: explicit empty string selects the
    // documented AsUser OS connection rules. No interactive desktop ACL repair.
    let mut desktop = wide(OsStr::new(""))?;
    let mut stdout = Pipe::new(spec.stdout_limit)?;
    let mut stderr = Pipe::new(spec.stderr_limit)?;
    let mut stdin = Pipe::new(0)?;
    // Inherit an EOF-only stdin, not the setup console or any host input.
    drop(stdin.write.take());
    unsafe {
        SetHandleInformation(
            HANDLE(stdin.read.as_raw_handle()),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAG_INHERIT,
        )
    }
    .map_err(|e| e.to_string())?;
    let handles = [
        HANDLE(stdin.read.as_raw_handle()),
        stdout.writer(),
        stderr.writer(),
    ];
    // Attribute values must outlive DeleteProcThreadAttributeList. Declaration
    // order makes Attributes drop before both capabilities and the handle array.
    let mut capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: spec.profile.map(|v| v.0).unwrap_or_default(),
        ..Default::default()
    };
    let mut attributes =
        Attributes::new(if spec.profile.is_some() { 2 } else { 1 }).map_err(|e| e.to_string())?;
    attributes.handles(&handles).map_err(|e| e.to_string())?;
    if spec.profile.is_some() {
        attributes
            .security_capabilities(&mut capabilities)
            .map_err(|e| e.to_string())?;
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.lpDesktop = PWSTR(desktop.as_mut_ptr());
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes.list;
    let job = Job::create().map_err(|e| e.to_string())?;
    let mut info = PROCESS_INFORMATION::default();
    let flags = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | CREATE_NO_WINDOW
        | EXTENDED_STARTUPINFO_PRESENT;
    if Instant::now() >= spec.deadline {
        return Err("launch deadline expired during image/pipe preparation".into());
    }
    let mut canary = super::suspended_handles::Canary::new()?;
    // SAFETY: explicit held image, quoted argv, held cwd and exact handle list.
    // The elevated collector always supplies the fresh ordinary user token.
    // No application is launched with the collector identity or a fallback.
    let created = unsafe {
        CreateProcessAsUserW(
            Some(spec.user.token()),
            PCWSTR(image.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            true,
            flags,
            Some(spec.user.environment().cast_const()),
            PCWSTR(cwd.as_ptr()),
            &startup.StartupInfo,
            &mut info,
        )
    };
    if let Err(error) = created {
        let cleanup = canary.close().err().unwrap_or_default();
        return Err(format!("CreateProcessAsUserW failed: {error}; {cleanup}"));
    }
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess.0) };
    let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread.0) };
    let mut result = AssessmentProcessObservation {
        process_id: info.dwProcessId,
        creation_time_100ns: None,
        held_token: None,
        image_identity: identity.identity,
        image_sha256: identity.sha256,
        image_size_bytes: identity.size_bytes,
        image_machine,
        exit_code: None,
        timed_out: false,
        job_empty: None,
        stdout: stdout.prefix.observation(),
        stderr: stderr.prefix.observation(),
        errors: vec![],
    };
    let assigned = unsafe { AssignProcessToJobObject(job.handle(), raw(&process)) };
    let mut started_recorded = false;
    if let Err(error) = assigned {
        result
            .errors
            .push(bound_error(&format!("owned job assignment: {error}")));
        if let Err(error) = spec
            .progress
            .record(&AssessmentProgressEvent::LaunchStarted {
                index: spec.step_index,
                process: result.clone(),
            })
        {
            result.errors.push(bound_error(&error));
        }
        let stopped = unsafe { TerminateProcess(raw(&process), 1) };
        let waited = unsafe { WaitForSingleObject(raw(&process), 2000) };
        if stopped.is_err() || waited != WAIT_OBJECT_0 {
            std::process::abort();
        }
    } else {
        let checked = (|| -> Result<()> {
            let mut membership = BOOL(0);
            unsafe { IsProcessInJob(raw(&process), Some(job.handle()), &mut membership) }
                .map_err(|e| e.to_string())?;
            if !membership.as_bool() {
                return Err("suspended process absent from exact owned job".into());
            }
            let token =
                aiw_token::collect_process_token(process.as_handle()).map_err(|e| e.to_string())?;
            result.held_token = Some(token.clone());
            validate_boundary(
                &token,
                info.dwProcessId,
                spec.context,
                spec.profile.map(|v| v.1),
            )?;
            if spec.profile.is_none() {
                spec.user
                    .validate_suspended_child(process.as_handle())
                    .map_err(|e| e.to_string())?;
            }
            same_session(raw(&process), info.dwProcessId)?;
            let (mut birth, mut exit, mut kernel, mut user) = (
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
            );
            unsafe {
                GetProcessTimes(raw(&process), &mut birth, &mut exit, &mut kernel, &mut user)
            }
            .map_err(|e| e.to_string())?;
            let value = (u64::from(birth.dwHighDateTime) << 32) | u64::from(birth.dwLowDateTime);
            if value == 0 {
                return Err("zero process creation time".into());
            }
            result.creation_time_100ns = Some(value.to_string());
            let mut name = [0u16; 32768];
            let mut length = name.len() as u32;
            unsafe {
                QueryFullProcessImageNameW(
                    raw(&process),
                    PROCESS_NAME_WIN32,
                    PWSTR(name.as_mut_ptr()),
                    &mut length,
                )
            }
            .map_err(|e| e.to_string())?;
            let name = String::from_utf16(&name[..length as usize]).map_err(|e| e.to_string())?;
            if !super::fixed_image(Path::new(&name), &identity.canonical_path) {
                return Err("suspended process image path differs".into());
            }
            canary.verify(raw(&process), handles, spec.deadline)?;
            drop(stdout.write.take());
            drop(stderr.write.take());
            spec.image.revalidate().map_err(|e| e.to_string())?;
            // Native privilege/access failures remain API failures. No grant,
            // desktop permission change, dropped attribute or fallback occurs.
            super::check_collector(&mut *spec.collector_unimpersonated)?;
            if Instant::now() >= spec.deadline {
                return Err("launch deadline expired before Resume".into());
            }
            spec.progress
                .record(&AssessmentProgressEvent::LaunchStarted {
                    index: spec.step_index,
                    process: result.clone(),
                })?;
            started_recorded = true;
            // Signed publication may synchronously flush past the deadline.
            // A retained pre-resume row never authorizes a late Resume.
            if Instant::now() >= spec.deadline {
                return Err("launch deadline expired during pre-resume publication".into());
            }
            if unsafe { ResumeThread(raw(&thread)) } != 1 {
                return Err("suspended resume count differs".into());
            }
            loop {
                stdout.poll();
                stderr.poll();
                match unsafe { WaitForSingleObject(raw(&process), 0) } {
                    WAIT_OBJECT_0 => {
                        let mut code = 0;
                        unsafe { GetExitCodeProcess(raw(&process), &mut code) }
                            .map_err(|e| e.to_string())?;
                        result.exit_code = Some(code);
                        break;
                    }
                    WAIT_TIMEOUT => {}
                    _ => return Err("root wait failed".into()),
                }
                if Instant::now() >= spec.deadline {
                    result.timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Ok(())
        })();
        if let Err(error) = checked {
            result.errors.push(bound_error(&error));
        }
        if !started_recorded
            && let Err(error) = spec
                .progress
                .record(&AssessmentProgressEvent::LaunchStarted {
                    index: spec.step_index,
                    process: result.clone(),
                })
        {
            result.errors.push(bound_error(&error));
        }
        match job.terminate_and_verify_empty() {
            Ok(()) => result.job_empty = Some(true),
            Err(error) => {
                result.job_empty = Some(false);
                result
                    .errors
                    .push(bound_error(&format!("owned cleanup: {error}")));
            }
        }
    }
    if let Err(error) = canary.close() {
        result.errors.push(bound_error(&error));
    }
    drop(stdout.write.take());
    drop(stderr.write.take());
    let drain = Instant::now() + Duration::from_secs(2);
    while Instant::now() < drain
        && ((!stdout.prefix.eof && stdout.prefix.error.is_none())
            || (!stderr.prefix.eof && stderr.prefix.error.is_none()))
    {
        stdout.poll();
        stderr.poll();
        std::thread::sleep(Duration::from_millis(2));
    }
    if !stdout.prefix.eof && stdout.prefix.error.is_none() {
        stdout.prefix.error = Some("post-cleanup stdout EOF unconfirmed".into());
    }
    if !stderr.prefix.eof && stderr.prefix.error.is_none() {
        stderr.prefix.error = Some("post-cleanup stderr EOF unconfirmed".into());
    }
    if let Err(error) = spec.image.revalidate() {
        result
            .errors
            .push(bound_error(&format!("image revalidation: {error}")));
    }
    result.stdout = stdout.prefix.observation();
    result.stderr = stderr.prefix.observation();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn with_token_command_bound_counts_utf16_and_the_terminating_nul() {
        assert!(validate_command(&wide(OsStr::new(&"a".repeat(1023))).unwrap()).is_ok());
        assert!(validate_command(&wide(OsStr::new(&"a".repeat(1024))).unwrap()).is_err());
        assert!(validate_command(&wide(OsStr::new(&"🚀".repeat(511))).unwrap()).is_ok());
        assert!(validate_command(&wide(OsStr::new(&"🚀".repeat(512))).unwrap()).is_err());
    }
    fn pe() -> Vec<u8> {
        let mut bytes = vec![0; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&128u32.to_le_bytes());
        bytes[128..132].copy_from_slice(b"PE\0\0");
        bytes[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[148..150].copy_from_slice(&240u16.to_le_bytes());
        bytes[150..152].copy_from_slice(&2u16.to_le_bytes());
        bytes[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes
    }
    #[test]
    fn image_machine_is_measured_not_inferred_from_64bit_optional_magic() {
        let bytes = pe();
        assert_eq!(pe_machine(&bytes, 512).unwrap(), "amd64-pe32plus");
        for machine in [0xaa64u16, 0x14c] {
            let mut altered = bytes.clone();
            altered[132..134].copy_from_slice(&machine.to_le_bytes());
            assert!(pe_machine(&altered, 512).is_err());
        }
        let mut dll = bytes.clone();
        dll[150..152].copy_from_slice(&0x2002u16.to_le_bytes());
        assert!(pe_machine(&dll, 512).is_err());
    }
    #[test]
    fn malformed_and_out_of_extent_pe_headers_are_refused() {
        let bytes = pe();
        assert!(pe_machine(&bytes, 200).is_err());
        for offset in [0u32, 500, u32::MAX] {
            let mut altered = bytes.clone();
            altered[60..64].copy_from_slice(&offset.to_le_bytes());
            assert!(pe_machine(&altered, 512).is_err());
        }
        let mut altered = bytes;
        altered[152..154].copy_from_slice(&0x10bu16.to_le_bytes());
        assert!(pe_machine(&altered, 512).is_err());
    }
    #[test]
    fn execution_header_is_read_from_held_file_and_writers_cannot_mutate_it() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "aiw-assessment-image-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("IMAGE.EXE");
        struct InertFile {
            path: std::path::PathBuf,
            directory: std::path::PathBuf,
        }
        impl Drop for InertFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
                let _ = std::fs::remove_dir(&self.directory);
            }
        }
        let _fixture = InertFile {
            path: path.clone(),
            directory,
        };
        let bytes = pe();
        std::fs::write(&path, &bytes).unwrap();
        let held = HeldApplicationFile::open_bounded(&path, 512).unwrap();
        let header = held.read_execution_header().unwrap();
        assert_eq!(header, bytes);
        assert_eq!(pe_machine(&header, 512).unwrap(), "amd64-pe32plus");
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, path.with_extension("NEW")).is_err());
        held.revalidate().unwrap();
        drop(held);
        let mut altered = bytes;
        altered[132..134].copy_from_slice(&0xaa64u16.to_le_bytes());
        std::fs::write(&path, &altered).unwrap();
        let held = HeldApplicationFile::open_bounded(&path, 512).unwrap();
        assert!(pe_machine(&held.read_execution_header().unwrap(), 512).is_err());
    }
    #[test]
    fn capture_overflow_retains_exact_prefix_but_never_claims_complete() {
        let mut p = Prefix {
            limit: 3,
            ..Default::default()
        };
        p.append(b"ab");
        p.append(b"cdef");
        p.eof = true;
        let fact = p.observation();
        assert_eq!(fact.bytes_hex, "616263");
        assert_eq!(fact.size_bytes, 3);
        assert!(fact.overflowed);
        assert!(!fact.complete);
    }
    #[test]
    fn missing_eof_and_read_error_do_not_become_complete() {
        let mut p = Prefix {
            limit: 5,
            ..Default::default()
        };
        p.append(b"x");
        assert!(!p.observation().complete);
        p.eof = true;
        p.error = Some("refused".into());
        assert!(!p.observation().complete);
    }
    fn context() -> StandardUserRuntimeContext {
        StandardUserRuntimeContext {
            user_sid: "S-1-5-21-1-2-3-1000".into(),
            profile_path: r"C:\Users\AiwStandardUser".into(),
            roaming_app_data: r"C:\Users\AiwStandardUser\AppData\Roaming".into(),
            local_app_data: r"C:\Users\AiwStandardUser\AppData\Local".into(),
            administrators_enabled: false,
        }
    }
    fn token() -> TokenEvidence {
        TokenEvidence {
            schema_version: aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION.into(),
            process_id: 42,
            token_type: TokenType::Primary,
            impersonation_level: None,
            is_app_container: false,
            app_container_sid: None,
            user_sid: context().user_sid,
            integrity: aiw_token::IntegrityEvidence {
                sid: "S-1-16-8192".into(),
                rid: 8192,
                level: IntegrityLevel::Medium,
            },
            elevation_type: ElevationType::Default,
            is_elevated: false,
            capabilities: vec![],
            restricted_sid_count: 0,
        }
    }
    #[test]
    fn ordinary_boundary_rejects_elevation_wrong_user_and_wrong_pid() {
        let good = token();
        assert!(validate_boundary(&good, 42, &context(), None).is_ok());
        let mut altered = good.clone();
        altered.is_elevated = true;
        assert!(validate_boundary(&altered, 42, &context(), None).is_err());
        altered = good.clone();
        altered.user_sid = "S-1-5-18".into();
        assert!(validate_boundary(&altered, 42, &context(), None).is_err());
        assert!(validate_boundary(&good, 43, &context(), None).is_err());
    }
    #[test]
    fn classic_requires_exact_package_and_zero_capabilities() {
        let mut ac = token();
        ac.is_app_container = true;
        ac.app_container_sid = Some("S-1-15-2-1-2-3-4-5-6-7".into());
        ac.integrity = aiw_token::IntegrityEvidence {
            sid: "S-1-16-4096".into(),
            rid: 4096,
            level: IntegrityLevel::Low,
        };
        assert!(validate_boundary(&ac, 42, &context(), ac.app_container_sid.as_deref()).is_ok());
        assert!(validate_boundary(&ac, 42, &context(), Some("S-1-15-2-9")).is_err());
        ac.capabilities.push(aiw_token::SidAndAttributes {
            sid: "S-1-15-3-1".into(),
            attributes: 4,
        });
        assert!(validate_boundary(&ac, 42, &context(), ac.app_container_sid.as_deref()).is_err());
    }
}
