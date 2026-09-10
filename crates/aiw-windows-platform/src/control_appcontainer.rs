//! Fixed, disposable AppContainer control launcher. This is research-only and
//! intentionally has no caller-supplied executable, argument, or path.

use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use aiw_token::{
    IntegrityLevel, TokenEvidence, TokenType, collect_current_process_token, collect_process_token,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use windows::Win32::Foundation::{
    GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree,
    SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_CAPABILITIES,
};
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOEXW, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

const CONTROL_ROOT: &str = r"C:\AIW\Control";
const FIXTURE: &str = r"C:\AIW\Control\aiw-control-fixture.exe";
const CANARY: &str = r"C:\AIW\Control\SharedCanary\canary.txt";
const CHILD_DIR: &str = r"C:\AIW\Control\AppContainerChild";
const CHILD_TOKEN: &str = r"C:\AIW\Control\AppContainerChild\child-token.json";
const PROFILE_NAME: &str = "AIW.Control.Research.v0alpha1";
const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_JSON: u64 = 48 * 1024;

#[derive(Debug, Error)]
pub enum ControlAppContainerError {
    #[error("{0}")]
    Fixed(String),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlAppContainerObservation {
    pub schema_version: String,
    pub production_evidence: bool,
    pub profile: ProfileObservation,
    pub launcher_token: TokenEvidence,
    pub resource: ResourceObservation,
    pub baseline: ModeObservations,
    pub appcontainer: ModeObservations,
    pub cleanup: CleanupObservation,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileObservation {
    pub name: String,
    pub sid: String,
    pub deleted: bool,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceObservation {
    pub canary_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub unchanged_after: bool,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeObservations {
    pub read_canary: FixedFixtureObservation,
    pub child: FixedFixtureObservation,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupObservation {
    pub baseline_job_empty: bool,
    pub appcontainer_job_empty: bool,
    pub profile_deleted: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixedFixtureObservation {
    pub process_id: u32,
    pub exit_code: i32,
    pub fixture_token: TokenEvidence,
    pub report: serde_json::Value,
    pub job_empty: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureWire {
    own_process_token: TokenEvidence,
}

/// Runs only the reviewed control fixture modes from the fixed guest paths.
pub fn execute_fixed_control_appcontainer()
-> Result<ControlAppContainerObservation, ControlAppContainerError> {
    require_regular_file(Path::new(FIXTURE))?;
    require_empty_directory(Path::new(CHILD_DIR))?;
    let canary = CanaryBinding::open(Path::new(CANARY))?;
    let launcher_token = collect_current_process_token()
        .map_err(|error| fixed(format!("collect launcher token failed: {error}")))?;
    if launcher_token.is_app_container
        || launcher_token.is_elevated
        || launcher_token.integrity.level != IntegrityLevel::Medium
    {
        return Err(fixed(
            "launcher must be the standard non-AppContainer medium-integrity user",
        ));
    }
    let baseline_read_canary = launch_fixture(
        "read-canary",
        None,
        Path::new(CONTROL_ROOT),
        None,
        &launcher_token.user_sid,
    )?;
    remove_fixed_result(Path::new(CONTROL_ROOT), "read-canary")?;
    let baseline_child = launch_fixture(
        "child",
        None,
        Path::new(CHILD_DIR),
        None,
        &launcher_token.user_sid,
    )?;
    remove_fixed_result(Path::new(CHILD_DIR), "child")?;
    fs::remove_file(CHILD_TOKEN).map_err(|error| {
        fixed(format!(
            "remove verified baseline child token failed: {error}"
        ))
    })?;
    require_empty_directory(Path::new(CHILD_DIR))?;

    let profile = AppContainerProfile::create_fresh()?;
    let candidate = (|| {
        grant_package_access(
            Path::new(CONTROL_ROOT),
            profile.sid,
            (GENERIC_READ | GENERIC_EXECUTE).0,
        )?;
        grant_package_access(
            Path::new(FIXTURE),
            profile.sid,
            (GENERIC_READ | GENERIC_EXECUTE).0,
        )?;
        grant_package_access(
            Path::new(CHILD_DIR),
            profile.sid,
            (GENERIC_READ | GENERIC_WRITE).0,
        )?;
        let read = launch_fixture(
            "read-canary",
            Some(profile.sid),
            Path::new(CONTROL_ROOT),
            Some(profile.sid),
            &launcher_token.user_sid,
        )?;
        remove_fixed_result(Path::new(CONTROL_ROOT), "read-canary")?;
        let child = launch_fixture(
            "child",
            Some(profile.sid),
            Path::new(CHILD_DIR),
            Some(profile.sid),
            &launcher_token.user_sid,
        )?;
        Ok::<_, ControlAppContainerError>((read, child))
    })();
    let profile_sid = profile.string_sid()?;
    let deleted = profile.delete();
    let (appcontainer_read_canary, appcontainer_child) = candidate?;
    deleted?;
    canary.verify_unchanged()?;
    Ok(ControlAppContainerObservation {
        schema_version: "aiw.dev/research/control-appcontainer/v0alpha1".to_owned(),
        production_evidence: false,
        profile: ProfileObservation {
            name: PROFILE_NAME.to_owned(),
            sid: profile_sid,
            deleted: true,
        },
        launcher_token,
        resource: ResourceObservation {
            canary_path: CANARY.to_owned(),
            sha256: canary.sha256,
            size_bytes: canary.size_bytes,
            unchanged_after: true,
        },
        baseline: ModeObservations {
            read_canary: baseline_read_canary,
            child: baseline_child,
        },
        appcontainer: ModeObservations {
            read_canary: appcontainer_read_canary,
            child: appcontainer_child,
        },
        cleanup: CleanupObservation {
            baseline_job_empty: true,
            appcontainer_job_empty: true,
            profile_deleted: true,
        },
    })
}
fn launch_fixture(
    mode: &str,
    appcontainer: Option<PSID>,
    directory: &Path,
    expected_sid: Option<PSID>,
    expected_user_sid: &str,
) -> Result<FixedFixtureObservation, ControlAppContainerError> {
    let report_path = directory.join(format!("{mode}-result.json"));
    if report_path.exists() {
        return Err(fixed("fixed fixture result path already exists"));
    }
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&report_path)
        .map_err(|error| fixed(format!("create fixed fixture result failed: {error}")))?;
    let output_handle = HANDLE(output.as_raw_handle() as isize as *mut _);
    unsafe { SetHandleInformation(output_handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .map_err(|error| {
            fixed(format!(
                "make fixed fixture result inheritable failed: {error}"
            ))
        })?;
    let command = format!("\"{FIXTURE}\" --mode {mode}");
    let mut command_wide = wide(OsStr::new(&command))?;
    let fixture_wide = wide(OsStr::new(FIXTURE))?;
    let directory_wide = wide(directory.as_os_str())?;
    let job = Job::create()?;
    let mut attributes = Attributes::new(if appcontainer.is_some() { 2 } else { 1 })?;
    attributes.handles(&[output_handle])?;
    let mut capabilities = SECURITY_CAPABILITIES::default();
    if let Some(sid) = appcontainer {
        capabilities.AppContainerSid = sid;
        attributes.security_capabilities(&mut capabilities)?;
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = windows::Win32::System::Threading::STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = HANDLE::default();
    startup.StartupInfo.hStdOutput = output_handle;
    startup.StartupInfo.hStdError = output_handle;
    startup.lpAttributeList = attributes.list;
    let mut info = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(fixture_wide.as_ptr()),
            Some(PWSTR(command_wide.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            None,
            PCWSTR(directory_wide.as_ptr()),
            (&startup as *const STARTUPINFOEXW).cast(),
            &mut info,
        )
    }
    .map_err(|error| fixed(format!("create fixed fixture process failed: {error}")))?;
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess.0) };
    let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread.0) };
    let token = collect_process_token(process.as_handle())
        .map_err(|error| fixed(format!("collect suspended fixture token failed: {error}")))?;
    verify_token(&token, info.dwProcessId, expected_sid, expected_user_sid)?;
    if let Err(error) = unsafe {
        AssignProcessToJobObject(
            job.handle(),
            HANDLE(process.as_raw_handle() as isize as *mut _),
        )
    } {
        let cleanup = job.terminate();
        return Err(fixed(format!(
            "assign fixture job failed: {error}; cleanup={cleanup:?}"
        )));
    }
    if unsafe { ResumeThread(HANDLE(thread.as_raw_handle() as isize as *mut _)) } == u32::MAX {
        let cleanup = job.terminate();
        return Err(fixed(format!("resume fixture failed; cleanup={cleanup:?}")));
    }
    let exit = wait(HANDLE(process.as_raw_handle() as isize as *mut _), TIMEOUT);
    exit?;
    job.terminate_and_verify_empty()?;
    let mut code = 0u32;
    unsafe {
        GetExitCodeProcess(
            HANDLE(process.as_raw_handle() as isize as *mut _),
            &mut code,
        )
    }
    .map_err(|error| fixed(format!("read fixture exit code failed: {error}")))?;
    let bytes = read_bounded(&report_path, MAX_JSON)?;
    let report: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| fixed(format!("parse fixture JSON failed: {error}")))?;
    let wire: FixtureWire = serde_json::from_value(report.clone())
        .map_err(|error| fixed(format!("parse fixture token failed: {error}")))?;
    if wire.own_process_token != token {
        return Err(fixed("fixture JSON token differed from held process token"));
    }
    if code != 0 {
        return Err(fixed(format!("fixed fixture {mode} exited with {code}")));
    }
    verify_fixture_report(&report, mode, &token, appcontainer.is_some())?;
    Ok(FixedFixtureObservation {
        process_id: info.dwProcessId,
        exit_code: code as i32,
        fixture_token: token,
        report,
        job_empty: true,
    })
}

fn verify_fixture_report(
    report: &serde_json::Value,
    mode: &str,
    token: &TokenEvidence,
    candidate: bool,
) -> Result<(), ControlAppContainerError> {
    let expected_mode = match mode {
        "read-canary" => "readCanary",
        "child" => "child",
        _ => return Err(fixed("unreviewed fixture mode")),
    };
    if report.get("mode").and_then(serde_json::Value::as_str) != Some(expected_mode) {
        return Err(fixed(
            "fixture report mode differed from launched fixed mode",
        ));
    }
    let result = report
        .get("result")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| fixed("fixture report omitted result"))?;
    match mode {
        "read-canary" => {
            if result.get("status").and_then(serde_json::Value::as_str) != Some("readCanary") {
                return Err(fixed("read-canary fixture reported another result"));
            }
            let expected = if candidate { "accessDenied" } else { "success" };
            let outcome = result
                .get("outcome")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| fixed("fixture read-canary omitted outcome"))?;
            if outcome.get("kind").and_then(serde_json::Value::as_str) != Some(expected) {
                return Err(fixed(
                    "fixture read-canary outcome differed from control expectation",
                ));
            }
        }
        "child" => {
            if result.get("status").and_then(serde_json::Value::as_str) != Some("child")
                || result
                    .get("childStdoutBytes")
                    .and_then(serde_json::Value::as_u64)
                    != Some(0)
            {
                return Err(fixed(
                    "child fixture report was not the fixed silent child result",
                ));
            }
            let child: TokenEvidence = serde_json::from_value(
                result
                    .get("childToken")
                    .cloned()
                    .ok_or_else(|| fixed("child fixture omitted child token"))?,
            )
            .map_err(|error| fixed(format!("parse child fixture token failed: {error}")))?;
            if result
                .get("childProcessId")
                .and_then(serde_json::Value::as_u64)
                != Some(child.process_id as u64)
                || child.user_sid != token.user_sid
                || child.is_elevated
                || child.token_type != TokenType::Primary
                || !child.capabilities.is_empty()
                || child.is_app_container != token.is_app_container
                || child.app_container_sid != token.app_container_sid
                || child.integrity != token.integrity
            {
                return Err(fixed(
                    "child fixture token did not retain the held root token identity",
                ));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
fn verify_token(
    token: &TokenEvidence,
    pid: u32,
    profile: Option<PSID>,
    expected_user_sid: &str,
) -> Result<(), ControlAppContainerError> {
    if token.process_id != pid
        || token.is_elevated
        || token.token_type != TokenType::Primary
        || !token.capabilities.is_empty()
        || token.user_sid != expected_user_sid
    {
        return Err(fixed(
            "held fixture token did not have expected PID, user, primary/no-capability, or non-elevated state",
        ));
    }
    match profile {
        Some(sid) => {
            if !token.is_app_container
                || token.integrity.level != IntegrityLevel::Low
                || token.app_container_sid.as_deref() != Some(&sid_string(sid)?)
            {
                return Err(fixed(
                    "held candidate token did not bind to fresh low-integrity AppContainer profile",
                ));
            }
        }
        None => {
            if token.is_app_container || token.integrity.level != IntegrityLevel::Medium {
                return Err(fixed(
                    "baseline fixture token was not the ordinary medium-integrity user",
                ));
            }
        }
    }
    Ok(())
}

struct AppContainerProfile {
    sid: PSID,
}
impl AppContainerProfile {
    fn create_fresh() -> Result<Self, ControlAppContainerError> {
        let name = wide(OsStr::new(PROFILE_NAME))?;
        let sid = unsafe {
            CreateAppContainerProfile(
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                None,
            )
        }
        .map_err(|error| fixed(format!("create fresh AppContainer profile failed: {error}")))?;
        Ok(Self { sid })
    }
    fn string_sid(&self) -> Result<String, ControlAppContainerError> {
        sid_string(self.sid)
    }
    fn delete(self) -> Result<(), ControlAppContainerError> {
        let name = wide(OsStr::new(PROFILE_NAME))?;
        let result = unsafe { DeleteAppContainerProfile(PCWSTR(name.as_ptr())) };
        unsafe { windows::Win32::Security::FreeSid(self.sid) };
        result.map_err(|error| fixed(format!("delete fresh AppContainer profile failed: {error}")))
    }
}

fn grant_package_access(
    path: &Path,
    sid: PSID,
    rights: u32,
) -> Result<(), ControlAppContainerError> {
    let mut entry = EXPLICIT_ACCESS_W::default();
    entry.grfAccessPermissions = rights;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee = TRUSTEE_W {
        pMultipleTrustee: core::ptr::null_mut(),
        MultipleTrusteeOperation: Default::default(),
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: PWSTR(sid.0.cast()),
    };
    let path = wide(path.as_os_str())?;
    let mut existing: *mut ACL = core::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut descriptor,
        )
    };
    if status.0 != 0 {
        return Err(fixed(format!(
            "read existing package ACL failed: {}",
            status.0
        )));
    }
    let mut acl: *mut ACL = core::ptr::null_mut();
    let status = unsafe { SetEntriesInAclW(Some(&[entry]), Some(existing), &mut acl) };
    unsafe { LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    if status.0 != 0 {
        return Err(fixed(format!("build package ACL failed: {}", status.0)));
    }
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        )
    };
    unsafe { LocalFree(Some(HLOCAL(acl.cast()))) };
    if status.0 != 0 {
        return Err(fixed(format!("apply package ACL failed: {}", status.0)));
    }
    Ok(())
}

struct Job {
    handle: OwnedHandle,
}
impl Job {
    fn create() -> Result<Self, ControlAppContainerError> {
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|error| fixed(format!("create fixture job failed: {error}")))?;
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                HANDLE(handle.as_raw_handle() as isize as *mut _),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        }
        .map_err(|error| fixed(format!("configure fixture job failed: {error}")))?;
        Ok(Self { handle })
    }
    fn handle(&self) -> HANDLE {
        HANDLE(self.handle.as_raw_handle() as isize as *mut _)
    }
    fn terminate(&self) -> Result<(), ControlAppContainerError> {
        unsafe { TerminateJobObject(self.handle(), 1) }
            .map_err(|error| fixed(format!("terminate fixture job failed: {error}")))
    }
    fn active_processes(&self) -> Result<u32, ControlAppContainerError> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        unsafe {
            QueryInformationJobObject(
                Some(self.handle()),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                None,
            )
        }
        .map_err(|error| fixed(format!("query fixture job failed: {error}")))?;
        Ok(accounting.ActiveProcesses)
    }
    fn terminate_and_verify_empty(&self) -> Result<(), ControlAppContainerError> {
        if self.active_processes()? > 0 {
            self.terminate()?;
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or_else(|| fixed("fixture cleanup deadline overflowed"))?;
        while self.active_processes()? != 0 {
            if Instant::now() >= deadline {
                return Err(fixed("fixture job remained active after cleanup"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}
fn wait(handle: HANDLE, timeout: Duration) -> Result<(), ControlAppContainerError> {
    match unsafe { WaitForSingleObject(handle, timeout.as_millis() as u32) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(fixed("fixed fixture deadline expired")),
        _ => Err(fixed("wait fixed fixture failed")),
    }
}
struct Attributes {
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    _storage: Vec<u8>,
}
impl Attributes {
    fn new(count: usize) -> Result<Self, ControlAppContainerError> {
        let mut size = 0;
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, count as u32, None, &mut size);
        }
        let mut storage = vec![0; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(list), count as u32, None, &mut size) }
            .map_err(|error| fixed(format!("initialize fixture attributes failed: {error}")))?;
        Ok(Self {
            list,
            _storage: storage,
        })
    }
    fn handles(&mut self, handles: &[HANDLE]) -> Result<(), ControlAppContainerError> {
        unsafe {
            UpdateProcThreadAttribute(
                self.list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                std::mem::size_of_val(handles),
                None,
                None,
            )
        }
        .map_err(|error| fixed(format!("set fixed fixture handle list failed: {error}")))
    }
    fn security_capabilities(
        &mut self,
        capabilities: &mut SECURITY_CAPABILITIES,
    ) -> Result<(), ControlAppContainerError> {
        unsafe {
            UpdateProcThreadAttribute(
                self.list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some((capabilities as *mut SECURITY_CAPABILITIES).cast()),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                None,
                None,
            )
        }
        .map_err(|error| fixed(format!("set AppContainer capabilities failed: {error}")))
    }
}
fn wide(value: &OsStr) -> Result<Vec<u16>, ControlAppContainerError> {
    let value: Vec<u16> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(fixed("fixed path contained NUL"));
    }
    Ok(value.into_iter().chain(Some(0)).collect())
}
fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, ControlAppContainerError> {
    let file = fs::File::open(path).map_err(|e| fixed(format!("open fixed result failed: {e}")))?;
    let len = file
        .metadata()
        .map_err(|e| fixed(format!("stat fixed result failed: {e}")))?
        .len();
    if len > maximum {
        return Err(fixed("fixed result exceeded bound"));
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| fixed(format!("read fixed result failed: {e}")))?;
    if bytes.len() as u64 > maximum {
        return Err(fixed("fixed result grew beyond bound"));
    }
    Ok(bytes)
}
struct CanaryBinding {
    _file: fs::File,
    sha256: String,
    size_bytes: u64,
}
impl CanaryBinding {
    fn open(path: &Path) -> Result<Self, ControlAppContainerError> {
        require_regular_file(path)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(path)
            .map_err(|error| fixed(format!("open fixed canary binding failed: {error}")))?;
        let metadata = file
            .metadata()
            .map_err(|error| fixed(format!("stat fixed canary binding failed: {error}")))?;
        if metadata.len() > 1024 {
            return Err(fixed("fixed canary exceeded 1 KiB bound"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| fixed(format!("read fixed canary binding failed: {error}")))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(fixed(
                "fixed canary changed while its read-only binding was opened",
            ));
        }
        use sha2::{Digest, Sha256};
        Ok(Self {
            _file: file,
            sha256: hex::encode(Sha256::digest(&bytes)),
            size_bytes: bytes.len() as u64,
        })
    }
    fn verify_unchanged(&self) -> Result<(), ControlAppContainerError> {
        let (sha256, size_bytes) = hash_file(Path::new(CANARY))?;
        if sha256 != self.sha256 || size_bytes != self.size_bytes {
            return Err(fixed("fixed canary changed during AppContainer control"));
        }
        Ok(())
    }
}
fn remove_fixed_result(directory: &Path, mode: &str) -> Result<(), ControlAppContainerError> {
    let path = directory.join(format!("{mode}-result.json"));
    fs::remove_file(&path).map_err(|error| {
        fixed(format!(
            "remove verified fixed fixture result failed: {error}"
        ))
    })
}
fn hash_file(path: &Path) -> Result<(String, u64), ControlAppContainerError> {
    use sha2::{Digest, Sha256};
    let bytes = read_bounded(path, 1024)?;
    Ok((hex::encode(Sha256::digest(&bytes)), bytes.len() as u64))
}
fn require_regular_file(path: &Path) -> Result<(), ControlAppContainerError> {
    if fs::metadata(path).map(|m| m.is_file()).unwrap_or(false) {
        Ok(())
    } else {
        Err(fixed("required fixed resource was not an ordinary file"))
    }
}
fn require_empty_directory(path: &Path) -> Result<(), ControlAppContainerError> {
    let mut entries =
        fs::read_dir(path).map_err(|e| fixed(format!("open fixed child directory failed: {e}")))?;
    if entries.next().is_some() {
        Err(fixed("fixed child directory was not empty"))
    } else {
        Ok(())
    }
}
fn sid_string(sid: PSID) -> Result<String, ControlAppContainerError> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut text) }
        .map_err(|e| fixed(format!("format AppContainer SID failed: {e}")))?;
    let value = unsafe { text.to_string() }
        .map_err(|e| fixed(format!("decode AppContainer SID failed: {e}")))?;
    unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    Ok(value)
}
fn fixed(message: impl Into<String>) -> ControlAppContainerError {
    ControlAppContainerError::Fixed(message.into())
}
