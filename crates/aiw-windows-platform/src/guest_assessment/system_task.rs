//! Fixed one-assessment SYSTEM bootstrap. Task completion is never evidence
//! authority: only the independently verified authenticated channel grants it.
use super::{Result, files, guard_no_impersonation};
use aiw_provider_wsb::assessment_request::{
    APPLICATION_ASSESSMENT_REQUEST_MAX_BYTES, APPLICATION_ASSESSMENT_REQUEST_PATH,
    ApplicationAssessmentGuestRequest,
};
use aiw_token::{IntegrityLevel, TokenType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    rc::Rc,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree, VARIANT_BOOL},
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
            SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY, TokenSessionId,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize,
            },
            RemoteDesktop::ProcessIdToSessionId,
            SystemInformation::GetTickCount64,
            TaskScheduler::{
                IExecAction, IRegisteredTask, ITaskDefinition, ITaskFolder, ITaskService,
                TASK_ACTION_EXEC, TASK_CREATE, TASK_DONT_ADD_PRINCIPAL_ACE,
                TASK_INSTANCES_IGNORE_NEW, TASK_LOGON_SERVICE_ACCOUNT, TASK_RUNLEVEL_HIGHEST,
                TASK_STATE_READY, TaskScheduler,
            },
            Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcessToken},
            Variant::VARIANT,
        },
    },
    core::{BOOL, BSTR, HRESULT, Interface, PCWSTR, PWSTR},
};

const AGENT: &str = r"C:\AIW\Tools\aiw-guest-agent.exe";
const TOOLS: &str = r"C:\AIW\Tools";
const ARGUMENTS: &str = r"--request C:\AIW\Tools\assessment-request.json --system-assessment";
const BOOTSTRAP: &str = r"C:\AIW\AssessmentBootstrap";
const TASK_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
const SYSTEM: &str = "S-1-5-18";
const XML_CAP: usize = 64 * 1024;
const BOOTSTRAP_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BootstrapIntent {
    schema: String,
    task_name: String,
    request_sha256: String,
    agent_sha256: String,
    original_request_sha256: String,
    maximum_wait_seconds: u64,
    started_tick_millis: u64,
    deadline_tick_millis: u64,
}

fn ticks() -> u64 {
    // SAFETY: monotonic, system-wide boot-relative clock; no input or handles.
    unsafe { GetTickCount64() }
}
fn remaining(deadline: u64, now: u64) -> Result<Duration> {
    let millis = deadline
        .checked_sub(now)
        .filter(|n| *n > 0)
        .ok_or("SYSTEM assessment shared deadline expired")?;
    require(millis <= 420_000, "SYSTEM assessment shared deadline bound")?;
    Ok(Duration::from_millis(millis))
}

fn create_bootstrap_directory() -> Result<()> {
    let wide: Vec<u16> = BOOTSTRAP_SDDL.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    win(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    })?;
    let _descriptor = LocalDescriptor(HLOCAL(descriptor.0));
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: BOOL(0),
    };
    let path: Vec<u16> = BOOTSTRAP.encode_utf16().chain(Some(0)).collect();
    // Fresh owned local leaf only, restrictive security at creation. An existing
    // directory is refused; no existing object or parent ACL is changed.
    win(unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(&security)) })
}

fn verify_bootstrap_security(file: &File, protected: bool) -> Result<()> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut owner = PSID::default();
    // SAFETY: borrowed live file handle, returned descriptor owns the SID and
    // DACL memory until the LocalDescriptor guard is dropped.
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .map_err(|_| "SYSTEM bootstrap security query refused")?;
    let _descriptor = LocalDescriptor(HLOCAL(descriptor.0));
    require(
        !owner.0.is_null() && !descriptor.0.is_null(),
        "SYSTEM bootstrap owner/descriptor absent",
    )?;
    let mut owner_text = PWSTR::null();
    win(unsafe { ConvertSidToStringSidW(owner, &mut owner_text) })?;
    let _owner = LocalDescriptor(HLOCAL(owner_text.0.cast()));
    let owner_sid =
        unsafe { owner_text.to_string() }.map_err(|_| "SYSTEM bootstrap owner encoding")?;
    let wdag = crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")
        .map_err(|e| e.to_string())?;
    require(
        owner_sid == SYSTEM || owner_sid == "S-1-5-32-544" || owner_sid == wdag,
        "SYSTEM bootstrap owner untrusted",
    )?;
    let mut text = PWSTR::null();
    win(unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
    })?;
    let _text = LocalDescriptor(HLOCAL(text.0.cast()));
    let sddl = unsafe { text.to_string() }.map_err(|_| "SYSTEM bootstrap descriptor encoding")?;
    verify_trusted_dacl(&sddl, protected, 0x13)
}

/// Called only after the SYSTEM0 collector role guard. Read a fresh launcher's
/// protected local intent, never a mapped/public claimed deadline. The returned
/// Instant uses only the remaining portion of the original shared budget.
pub(super) fn collector_deadline(request: &ApplicationAssessmentGuestRequest) -> Result<Instant> {
    request.require_system0_execution()?;
    request.validate()?;
    guard_no_impersonation()?;
    let _parents = files::Directories::hold(Path::new(BOOTSTRAP))?;
    let directory = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(BOOTSTRAP)
        .map_err(|e| e.to_string())?;
    verify_bootstrap_security(&directory, true)?;
    let path = Path::new(BOOTSTRAP).join("intent.json");
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&path)
        .map_err(|e| e.to_string())?;
    verify_bootstrap_security(&file, false)?;
    let before = crate::guest_document::file_information(&file)?;
    let size = crate::guest_document::file_length(&before);
    require(
        crate::guest_document::ordinary_file(&before)
            && before.nNumberOfLinks == 1
            && before.dwVolumeSerialNumber != 0
            && (before.nFileIndexHigh != 0 || before.nFileIndexLow != 0)
            && (1..=16 * 1024).contains(&size),
        "SYSTEM bootstrap intent identity/link/byte bound",
    )?;
    let mut raw = vec![0; size as usize];
    file.read_exact(&mut raw).map_err(|e| e.to_string())?;
    let mut tail = [0];
    require(
        file.read(&mut tail).map_err(|e| e.to_string())? == 0,
        "SYSTEM intent EOF drift",
    )?;
    let intent: BootstrapIntent =
        serde_json::from_slice(&raw).map_err(|_| "strict SYSTEM bootstrap intent refused")?;
    let mut held = RequestHold::open(request)?;
    let expected_name = task_name(
        &request
            .channel
            .as_ref()
            .ok_or("SYSTEM channel absent")?
            .nonce_hex,
    )?;
    let budget = wait_budget(request.assessment.settings.total_timeout_seconds)?;
    require(
        intent.schema == "aiw.dev/assessment-system-bootstrap-intent/v0alpha1"
            && intent.task_name == expected_name
            && intent.request_sha256 == request.request_sha256
            && intent.agent_sha256 == request.agent_sha256
            && intent.original_request_sha256 == hex::encode(Sha256::digest(&held.original))
            && intent.maximum_wait_seconds == budget.as_secs()
            && intent
                .started_tick_millis
                .checked_add(budget.as_millis() as u64)
                == Some(intent.deadline_tick_millis)
            && intent.started_tick_millis <= ticks(),
        "SYSTEM bootstrap intent binding/deadline refused",
    )?;
    held.revalidate()?;
    let fresh = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|e| e.to_string())?;
    require(
        crate::guest_document::same_file_information(
            &before,
            &crate::guest_document::file_information(&file)?,
        ) && crate::guest_document::same_file_information(
            &before,
            &crate::guest_document::file_information(&fresh)?,
        ),
        "SYSTEM intent namespace/extent drift",
    )?;
    Instant::now()
        .checked_add(remaining(intent.deadline_tick_millis, ticks())?)
        .ok_or("SYSTEM shared Instant overflow".into())
}

fn win<T>(value: windows::core::Result<T>) -> Result<T> {
    value.map_err(|e| format!("assessment SYSTEM task HRESULT {:08x}", e.code().0 as u32))
}
fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(message.into()) }
}
fn task_name(nonce: &str) -> Result<String> {
    require(
        nonce.len() == 64
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && nonce.bytes().any(|b| b != b'0'),
        "SYSTEM task nonce refused",
    )?;
    Ok(format!("AIW-Assessment-System0-{nonce}"))
}
fn wait_budget(total: u32) -> Result<Duration> {
    require(
        (1..=300).contains(&total),
        "SYSTEM task assessment timeout refused",
    )?;
    Ok(Duration::from_secs(u64::from(
        total
            .checked_add(120)
            .ok_or("SYSTEM task deadline overflow")?,
    )))
}

// Every COM interface and VARIANT drops before the apartment. Do not transfer
// these operations to a new thread/apartment or accept an existing remote server.
struct Apartment(PhantomData<Rc<()>>);
impl Apartment {
    fn enter() -> Result<Self> {
        // SAFETY: balanced on this thread; S_OK and S_FALSE both require uninit.
        win(unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok() })?;
        Ok(Self(PhantomData))
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: one successful initialization owned by this same-thread guard.
        unsafe { CoUninitialize() };
    }
}

fn guard_launcher() -> Result<()> {
    guard_no_impersonation()?;
    let observed = aiw_token::collect_current_process_token().map_err(|e| e.to_string())?;
    let expected = crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")
        .map_err(|e| e.to_string())?;
    require(
        expected.ends_with("-504")
            && observed.user_sid == expected
            && observed.token_type == TokenType::Primary
            && observed.is_elevated
            && observed.impersonation_level.is_none()
            && !observed.is_app_container
            && observed.app_container_sid.is_none()
            && observed.capabilities.is_empty()
            && observed.integrity.level == IntegrityLevel::High
            && observed.integrity.rid == 12288,
        "SYSTEM bootstrap requires exact primary High WDAG collector",
    )?;
    let mut handle = HANDLE::default();
    // SAFETY: current process token opened query-only, then owned for all queries.
    win(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) })?;
    let _token = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle.0) };
    let mut session = 0_u32;
    let mut returned = 0;
    win(unsafe {
        GetTokenInformation(
            handle,
            TokenSessionId,
            Some((&mut session as *mut u32).cast()),
            4,
            &mut returned,
        )
    })?;
    let mut physical = 0;
    win(unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut physical) })?;
    require(
        returned == 4 && session == 1 && physical == 1,
        "SYSTEM bootstrap requires WDAG token and physical session1",
    )
}

struct RequestHold {
    _parents: files::Directories,
    file: File,
    identity: BY_HANDLE_FILE_INFORMATION,
    original: Vec<u8>,
}
impl RequestHold {
    fn open(expected: &ApplicationAssessmentGuestRequest) -> Result<Self> {
        let parents = files::Directories::hold(Path::new(TOOLS))?;
        let file = Self::open_fixed()?;
        let identity = crate::guest_document::file_information(&file)?;
        let mut held = Self {
            _parents: parents,
            file,
            identity,
            original: vec![],
        };
        held.original = held.bytes()?;
        let actual: ApplicationAssessmentGuestRequest = serde_json::from_slice(&held.original)
            .map_err(|_| "strict fixed SYSTEM assessment request refused")?;
        actual.validate()?;
        actual.require_system0_execution()?;
        require(
            &actual == expected,
            "SYSTEM bootstrap request differs from fixed held request",
        )?;
        held.revalidate()?;
        Ok(held)
    }
    fn open_fixed() -> Result<File> {
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(APPLICATION_ASSESSMENT_REQUEST_PATH)
            .map_err(|e| format!("fixed SYSTEM request open: {e}"))
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let info = crate::guest_document::file_information(&self.file)?;
        require(
            crate::guest_document::ordinary_file(&info)
                && info.nNumberOfLinks == 1
                && crate::guest_document::same_file_information(&self.identity, &info),
            "SYSTEM request object identity/type/link refused",
        )?;
        let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
        require(
            size > 0 && size <= APPLICATION_ASSESSMENT_REQUEST_MAX_BYTES,
            "SYSTEM request byte bound refused",
        )?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut bytes = vec![0; size as usize];
        self.file
            .read_exact(&mut bytes)
            .map_err(|e| e.to_string())?;
        let mut tail = [0];
        require(
            self.file.read(&mut tail).map_err(|e| e.to_string())? == 0,
            "SYSTEM request EOF drift",
        )?;
        Ok(bytes)
    }
    fn revalidate(&mut self) -> Result<()> {
        require(
            self.bytes()? == self.original,
            "SYSTEM request original byte drift",
        )?;
        let fresh = Self::open_fixed()?;
        require(
            crate::guest_document::same_file_information(
                &self.identity,
                &crate::guest_document::file_information(&fresh)?,
            ),
            "SYSTEM request namespace drift",
        )
    }
}

fn fixed_definition(service: &ITaskService) -> Result<ITaskDefinition> {
    // SAFETY: local, same-apartment COM objects with fixed strings and empty
    // trigger collection. No caller program, arguments, identity or credentials.
    unsafe {
        let definition = win(service.NewTask(0))?;
        let principal = win(definition.Principal())?;
        win(principal.SetUserId(&BSTR::from(SYSTEM)))?;
        win(principal.SetLogonType(TASK_LOGON_SERVICE_ACCOUNT))?;
        win(principal.SetRunLevel(TASK_RUNLEVEL_HIGHEST))?;
        let settings = win(definition.Settings())?;
        win(settings.SetEnabled(VARIANT_BOOL(-1)))?;
        win(settings.SetAllowDemandStart(VARIANT_BOOL(-1)))?;
        win(settings.SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW))?;
        win(settings.SetRestartCount(0))?;
        win(settings.SetExecutionTimeLimit(&BSTR::from("PT0S")))?;
        win(settings.SetAllowHardTerminate(VARIANT_BOOL(0)))?;
        win(settings.SetStartWhenAvailable(VARIANT_BOOL(0)))?;
        win(settings.SetWakeToRun(VARIANT_BOOL(0)))?;
        win(settings.SetDisallowStartIfOnBatteries(VARIANT_BOOL(0)))?;
        win(settings.SetStopIfGoingOnBatteries(VARIANT_BOOL(0)))?;
        win(settings.SetRunOnlyIfNetworkAvailable(VARIANT_BOOL(0)))?;
        win(settings.SetRunOnlyIfIdle(VARIANT_BOOL(0)))?;
        let action: IExecAction =
            win(win(win(definition.Actions())?.Create(TASK_ACTION_EXEC))?.cast())?;
        win(action.SetPath(&BSTR::from(AGENT)))?;
        win(action.SetArguments(&BSTR::from(ARGUMENTS)))?;
        win(action.SetWorkingDirectory(&BSTR::from(TOOLS)))?;
        Ok(definition)
    }
}

fn verify_definition(task: &IRegisteredTask) -> Result<String> {
    // SAFETY: all out parameters are initialized live values; interface casts
    // check the executable action IID rather than treating arbitrary actions as it.
    unsafe {
        let definition = win(task.Definition())?;
        let principal = win(definition.Principal())?;
        let mut user = BSTR::new();
        let mut logon = Default::default();
        let mut level = Default::default();
        win(principal.UserId(&mut user))?;
        win(principal.LogonType(&mut logon))?;
        win(principal.RunLevel(&mut level))?;
        let raw_user = user.to_string();
        require(
            !raw_user.is_empty() && raw_user.len() <= 256 && !raw_user.contains('\0'),
            "registered SYSTEM principal encoding refused",
        )?;
        let user_sid = if raw_user == SYSTEM {
            raw_user
        } else {
            crate::control_appcontainer::fixed_account_sid(&raw_user).map_err(|e| e.to_string())?
        };
        require(
            user_sid == SYSTEM
                && logon == TASK_LOGON_SERVICE_ACCOUNT
                && level == TASK_RUNLEVEL_HIGHEST,
            "registered SYSTEM principal differs",
        )?;
        let actions = win(definition.Actions())?;
        let mut count = 0;
        win(actions.Count(&mut count))?;
        let mut triggers = 0;
        win(win(definition.Triggers())?.Count(&mut triggers))?;
        require(
            count == 1 && triggers == 0,
            "registered SYSTEM action/trigger count differs",
        )?;
        let action: IExecAction = win(win(actions.get_Item(1))?.cast())?;
        let (mut path, mut args, mut cwd) = (BSTR::new(), BSTR::new(), BSTR::new());
        win(action.Path(&mut path))?;
        win(action.Arguments(&mut args))?;
        win(action.WorkingDirectory(&mut cwd))?;
        require(
            path == AGENT && args == ARGUMENTS && cwd == TOOLS,
            "registered SYSTEM fixed action differs",
        )?;
        let settings = win(definition.Settings())?;
        let mut policy = Default::default();
        let mut retries = 0;
        let mut duration = BSTR::new();
        win(settings.MultipleInstances(&mut policy))?;
        win(settings.RestartCount(&mut retries))?;
        win(settings.ExecutionTimeLimit(&mut duration))?;
        require(
            policy == TASK_INSTANCES_IGNORE_NEW && retries == 0 && duration == "PT0S",
            "registered SYSTEM lifetime policy differs",
        )?;
        macro_rules! flag {
            ($getter:ident, $expected:expr) => {{
                let mut value = VARIANT_BOOL(0);
                win(settings.$getter(&mut value))?;
                require(
                    (value.0 != 0) == $expected,
                    "registered SYSTEM settings differ",
                )?;
            }};
        }
        flag!(Enabled, true);
        flag!(AllowDemandStart, true);
        flag!(AllowHardTerminate, false);
        flag!(StartWhenAvailable, false);
        flag!(WakeToRun, false);
        flag!(DisallowStartIfOnBatteries, false);
        flag!(StopIfGoingOnBatteries, false);
        flag!(RunOnlyIfNetworkAvailable, false);
        flag!(RunOnlyIfIdle, false);
        verify_task_dacl(&win(task.GetSecurityDescriptor(4))?.to_string())?;
        let raw_xml = win(task.Xml())?;
        let xml =
            String::from_utf16(&raw_xml).map_err(|_| "registered SYSTEM XML encoding refused")?;
        require(
            !xml.is_empty() && xml.len() <= XML_CAP,
            "registered SYSTEM XML byte bound",
        )?;
        Ok(xml)
    }
}

struct LocalDescriptor(HLOCAL);
impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSecurityDescriptor allocated this owned buffer.
        let _ = unsafe { LocalFree(Some(self.0)) };
    }
}

fn verify_task_dacl(sddl: &str) -> Result<()> {
    verify_trusted_dacl(sddl, true, 0)
}

fn verify_trusted_dacl(sddl: &str, protected: bool, allowed_ace_flags: u8) -> Result<()> {
    require(
        !sddl.is_empty() && sddl.len() <= 4096 && !sddl.contains('\0'),
        "registered SYSTEM task descriptor bound",
    )?;
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut size = 0;
    // SAFETY: live terminated input; returned LocalAlloc descriptor remains owned
    // while all ACL/ACE/SID offsets below are checked against its exact extent.
    win(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            Some(&mut size),
        )
    })?;
    let _allocation = LocalDescriptor(HLOCAL(descriptor.0));
    require(
        !descriptor.0.is_null() && (20..=65536).contains(&size),
        "registered task descriptor extent",
    )?;
    let mut control = 0;
    let mut revision = 0;
    win(unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) })?;
    require(
        (!protected || control & SE_DACL_PROTECTED.0 != 0) && revision == 1,
        "trusted DACL protection refused",
    )?;
    let mut present = BOOL(0);
    let mut defaulted = BOOL(0);
    let mut acl = std::ptr::null_mut();
    win(unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) })?;
    let base = descriptor.0 as usize;
    let acl_start = acl as usize;
    let end = base
        .checked_add(size as usize)
        .ok_or("task descriptor extent overflow")?;
    require(
        present.as_bool()
            && !defaulted.as_bool()
            && acl_start >= base
            && acl_start.checked_add(8).is_some_and(|n| n <= end),
        "registered task NULL/default DACL refused",
    )?;
    // SAFETY: header extent checked above; subsequent ACE reads are constrained
    // to both the ACL header's length and the owned converted descriptor buffer.
    let acl_bytes = unsafe { std::ptr::read_unaligned((acl_start + 2) as *const u16) } as usize;
    let count = unsafe { std::ptr::read_unaligned((acl_start + 4) as *const u16) };
    let acl_end = acl_start
        .checked_add(acl_bytes)
        .ok_or("task ACL extent overflow")?;
    require(
        count == 2 && acl_bytes >= 8 && acl_end <= end,
        "registered task must contain only two trusted ACEs",
    )?;
    let mut at = acl_start + 8;
    let mut seen = [false; 2];
    for _ in 0..count {
        require(
            at.checked_add(8).is_some_and(|n| n <= acl_end),
            "task ACE header extent",
        )?;
        let kind = unsafe { *(at as *const u8) };
        let flags = unsafe { *((at + 1) as *const u8) };
        let length = unsafe { std::ptr::read_unaligned((at + 2) as *const u16) } as usize;
        let mask = unsafe { std::ptr::read_unaligned((at + 4) as *const u32) };
        let next = at.checked_add(length).ok_or("task ACE extent overflow")?;
        require(
            kind == 0
                && flags & !allowed_ace_flags == 0
                && mask != 0
                && length >= 20
                && next <= acl_end,
            "registered task ACE type/rights/extent refused",
        )?;
        let sid = unsafe { std::slice::from_raw_parts((at + 8) as *const u8, length - 8) };
        let which = trusted_task_sid(sid).ok_or("registered task contains untrusted trustee")?;
        require(!seen[which], "registered task duplicate trustee")?;
        seen[which] = true;
        at = next;
    }
    require(
        seen == [true, true] && at == acl_end,
        "registered task ACL trailing bytes/trustees refused",
    )
}

fn trusted_task_sid(sid: &[u8]) -> Option<usize> {
    match sid {
        [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0] => Some(0),
        [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0] => Some(1),
        _ => None,
    }
}

fn idle(task: &IRegisteredTask) -> Result<bool> {
    // SAFETY: local same-apartment task interface, no process launch or stop.
    unsafe {
        Ok(win(win(task.GetInstances(0))?.Count())? == 0 && win(task.State())? == TASK_STATE_READY)
    }
}

/// No alternate task/program/session/credentials parameters. An existing task,
/// consumed bootstrap directory, failed registration or unknown run never retries.
pub(super) fn bootstrap(request: &ApplicationAssessmentGuestRequest) -> Result<()> {
    request.require_system0_execution()?;
    request.validate()?;
    guard_launcher()?;
    let started_tick_millis = ticks();
    let budget = wait_budget(request.assessment.settings.total_timeout_seconds)?;
    let deadline_tick_millis = started_tick_millis
        .checked_add(budget.as_millis() as u64)
        .ok_or("SYSTEM shared tick deadline overflow")?;
    require(
        super::fixed_image(&std::env::current_exe().map_err(|e| e.to_string())?, AGENT),
        "SYSTEM bootstrap fixed Tools agent required",
    )?;
    let mut agent = files::hold_agent(&request.agent_sha256)?;
    let mut held = RequestHold::open(request)?;
    let channel = request
        .channel
        .as_ref()
        .ok_or("SYSTEM bootstrap channel absent")?;
    let name = BSTR::from(task_name(&channel.nonce_hex)?);
    let _parents = files::Directories::hold(Path::new(r"C:\AIW"))?;
    // No workload/account exists yet. Protected at creation, never adopted.
    create_bootstrap_directory()?;
    let _directory = files::Directories::hold(Path::new(BOOTSTRAP))?;
    let intent = serde_json::to_vec(&BootstrapIntent {
        schema: "aiw.dev/assessment-system-bootstrap-intent/v0alpha1".into(),
        task_name: name.to_string(),
        request_sha256: request.request_sha256.clone(),
        agent_sha256: request.agent_sha256.clone(),
        original_request_sha256: hex::encode(Sha256::digest(&held.original)),
        maximum_wait_seconds: budget.as_secs(),
        started_tick_millis,
        deadline_tick_millis,
    })
    .map_err(|_| "SYSTEM bootstrap intent serialization refused")?;
    require(
        intent.len() <= 16 * 1024,
        "SYSTEM bootstrap intent byte bound",
    )?;
    let mut intent_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(Path::new(BOOTSTRAP).join("intent.json"))
        .map_err(|e| e.to_string())?;
    intent_file
        .write_all(&intent)
        .and_then(|_| intent_file.sync_all())
        .map_err(|e| e.to_string())?;
    drop(intent_file);
    let _apartment = Apartment::enter()?;
    // SAFETY: fixed local class, no activation/server/credentials from run data.
    let service: ITaskService =
        win(unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) })?;
    let empty = VARIANT::default();
    win(unsafe { service.Connect(&empty, &empty, &empty, &empty) })?;
    let folder: ITaskFolder = win(unsafe { service.GetFolder(&BSTR::from("\\")) })?;
    match unsafe { folder.GetTask(&name) } {
        Ok(_) => return Err("SYSTEM task already exists; never replace/replay".into()),
        Err(e) if e.code() == HRESULT::from_win32(2) => {}
        Err(e) => {
            return Err(format!(
                "SYSTEM task absence unknown {:08x}",
                e.code().0 as u32
            ));
        }
    }
    let definition = fixed_definition(&service)?;
    agent.revalidate()?;
    held.revalidate()?;
    guard_launcher()?;
    // Create-only and no automatic principal ACE: only SY and BA can mutate/run
    // this new task; no existing task or parent security descriptor is changed.
    let task = win(unsafe {
        folder.RegisterTaskDefinition(
            &name,
            &definition,
            TASK_CREATE.0 | TASK_DONT_ADD_PRINCIPAL_ACE.0,
            &VARIANT::from(SYSTEM),
            &empty,
            TASK_LOGON_SERVICE_ACCOUNT,
            &VARIANT::from(TASK_SDDL),
        )
    })?;
    let mut owned_xml = None;
    let outcome: Result<()> = (|| {
        let xml = verify_definition(&task)?;
        owned_xml = Some(xml);
        agent.revalidate()?;
        held.revalidate()?;
        guard_launcher()?;
        remaining(deadline_tick_millis, ticks())?;
        let previous_run = win(unsafe { task.LastRunTime() })?;
        // Empty VARIANT / default task principal. Never RunEx/session override.
        let _running = win(unsafe { task.Run(&empty) })?;
        loop {
            remaining(deadline_tick_millis, ticks()).map_err(|_| "SYSTEM assessment task active/unknown at shared deadline; retain task, outer Sandbox cleanup required")?;
            agent.revalidate()?;
            held.revalidate()?;
            guard_no_impersonation()?;
            let last = win(unsafe { task.LastRunTime() })?;
            if idle(&task)? && last.is_finite() && last > previous_run {
                require(
                    win(unsafe { task.LastTaskResult() })? == 0,
                    "SYSTEM assessment task failed; authenticated output determines measured facts",
                )?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })();
    // Run may have dispatched even if COM returned an error. Only delete a
    // positively idle object with the exact captured XML. Never call Stop/kill.
    let cleanup = (|| {
        let xml = owned_xml
            .as_ref()
            .ok_or("SYSTEM task XML unobserved; retain task")?;
        require(
            idle(&task)?,
            "SYSTEM task not idle; retain task for outer Sandbox stop",
        )?;
        let current = win(unsafe { folder.GetTask(&name) })?;
        require(
            idle(&current)? && win(unsafe { current.Xml() })? == xml.as_str(),
            "SYSTEM task changed/active; cleanup refused",
        )?;
        win(unsafe { folder.DeleteTask(&name, 0) })
    })();
    let custody = agent.revalidate().and_then(|_| held.revalidate());
    // Public, bounded bootstrap diagnostics are independent of the signed
    // application result. CreateNew only; active/unknown tasks remain untouched.
    let diagnostic = serde_json::to_vec(&serde_json::json!({
        "schema":"aiw.dev/assessment-system-bootstrap-outcome/v0alpha1",
        "requestSha256":request.request_sha256,"taskName":name.to_string(),
        "outcomeError":outcome.as_ref().err(),"cleanupError":cleanup.as_ref().err(),
        "custodyError":custody.as_ref().err(),"assessmentAuthority":false
    }))
    .map_err(|_| "SYSTEM bootstrap diagnostic serialization refused")?;
    require(
        diagnostic.len() <= 16 * 1024,
        "SYSTEM bootstrap diagnostic bound",
    )?;
    let mut diagnostic_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(Path::new(BOOTSTRAP).join("outcome.json"))
        .map_err(|e| e.to_string())?;
    diagnostic_file
        .write_all(&diagnostic)
        .and_then(|_| diagnostic_file.sync_all())
        .map_err(|e| e.to_string())?;
    match (outcome, cleanup, custody) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (result, cleanup, custody) => Err(format!(
            "SYSTEM assessment bootstrap refused: outcome={}; cleanup={}; custody={}",
            result.err().unwrap_or_default(),
            cleanup.err().unwrap_or_default(),
            custody.err().unwrap_or_default()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn system_task_namespace_and_bound_are_closed() {
        let nonce = "a".repeat(64);
        assert_eq!(
            task_name(&nonce).unwrap(),
            format!("AIW-Assessment-System0-{nonce}")
        );
        for value in [
            "a".repeat(63),
            "A".repeat(64),
            "0".repeat(64),
            "../task".into(),
            format!("{}\\evil", "a".repeat(64)),
        ] {
            assert!(task_name(&value).is_err());
        }
        assert_eq!(wait_budget(300).unwrap().as_secs(), 420);
        assert!(wait_budget(0).is_err());
        assert!(wait_budget(301).is_err());
        assert!(wait_budget(u32::MAX).is_err());
    }
    #[test]
    fn task_trustees_cannot_include_standard_or_package_principals() {
        assert_eq!(
            trusted_task_sid(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]),
            Some(0)
        );
        assert_eq!(
            trusted_task_sid(&[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]),
            Some(1)
        );
        assert_eq!(
            trusted_task_sid(&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]),
            None
        );
        assert_eq!(
            trusted_task_sid(&[1, 2, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 1, 0, 0, 0]),
            None
        );
        assert_eq!(
            trusted_task_sid(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0]),
            None
        );
    }
    #[test]
    fn task_descriptor_rejects_null_world_inheritance_and_extra_aces() {
        assert!(verify_task_dacl(TASK_SDDL).is_ok());
        for refused in [
            "D:NO_ACCESS_CONTROL",
            "D:P(A;;GA;;;WD)(A;;GA;;;BA)",
            "D:P(A;OI;GA;;;SY)(A;;GA;;;BA)",
            "D:(A;;GA;;;SY)(A;;GA;;;BA)",
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)",
            "D:P(A;;GA;;;SY)(A;;GA;;;SY)",
        ] {
            assert!(verify_task_dacl(refused).is_err(), "{refused}");
        }
        assert!(verify_trusted_dacl(BOOTSTRAP_SDDL, true, 0x13).is_ok());
        assert!(verify_trusted_dacl("D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)", false, 0x13).is_ok());
    }
    #[test]
    fn shared_deadline_cannot_reset_or_wrap() {
        assert_eq!(remaining(420_100, 100).unwrap(), Duration::from_secs(420));
        assert_eq!(
            remaining(420_100, 420_000).unwrap(),
            Duration::from_millis(100)
        );
        assert!(remaining(420_100, 420_100).is_err());
        assert!(remaining(420_100, 420_101).is_err());
        assert!(remaining(u64::MAX, 0).is_err());
    }
}
