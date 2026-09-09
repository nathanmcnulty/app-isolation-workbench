//! Native-only standard-user context for the fixed v0alpha4 Notepad++ guest
//! profile.  This deliberately creates one exact, fresh local account inside
//! the disposable Sandbox and never derives a restricted token from the
//! elevated guest agent.

use std::ffi::{OsStr, c_void};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use windows::Win32::Foundation::{GetLastError, HANDLE, HLOCAL, LocalFree, SetLastError};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, PSID, TOKEN_ELEVATION,
    TOKEN_ELEVATION_TYPE, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_TYPE, TOKEN_USER,
    TokenElevation, TokenElevationType, TokenElevationTypeDefault, TokenGroups,
    TokenIntegrityLevel, TokenPrimary, TokenType as TokenTypeClass, TokenUser,
};
use windows::Win32::System::Threading::{GetCurrentProcessId, GetProcessId, OpenProcessToken};
use windows::core::PWSTR;

use crate::GuestMsiExecutionError;
use aiw_provider_wsb::{STANDARD_USER_ACCOUNT_NAME, StandardUserRuntimeContext};

pub const STANDARD_USER_DOCUMENT_ROOT: &str = r"C:\Users\AiwStandardUser\AppData\Local\AIW";

const USER_PRIV_USER: u32 = 1;
const UF_SCRIPT: u32 = 1;
const NERR_SUCCESS: u32 = 0;
const NERR_USER_EXISTS: u32 = 2_222;
const STATUS_SUCCESS: i32 = 0;
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x20;
const TOKEN_QUERY_ACCESS: u32 = 0x8;
const SE_PRIVILEGE_ENABLED: u32 = 0x2;
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

#[repr(C)]
#[derive(Clone, Copy)]
struct Luid {
    low: u32,
    high: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct LuidAndAttributes {
    luid: Luid,
    attributes: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct TokenPrivilegesOne {
    count: u32,
    privilege: LuidAndAttributes,
}

#[repr(C)]
struct UserInfo1 {
    name: PWSTR,
    password: PWSTR,
    password_age: u32,
    privilege: u32,
    home_dir: PWSTR,
    comment: PWSTR,
    flags: u32,
    script_path: PWSTR,
}

#[repr(C)]
struct ProfileInfoW {
    size: u32,
    flags: u32,
    user_name: PWSTR,
    profile_path: PWSTR,
    default_path: PWSTR,
    server_name: PWSTR,
    policy_path: PWSTR,
    profile: HANDLE,
}

#[link(name = "Netapi32")]
unsafe extern "system" {
    fn NetUserAdd(server: PWSTR, level: u32, buffer: *const u8, parameter_error: *mut u32) -> u32;
}
#[link(name = "Bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut c_void,
        buffer: *mut u8,
        buffer_length: u32,
        flags: u32,
    ) -> i32;
}
#[link(name = "Advapi32")]
unsafe extern "system" {
    fn LogonUserW(
        user_name: PWSTR,
        domain: PWSTR,
        password: PWSTR,
        logon_type: u32,
        logon_provider: u32,
        token: *mut HANDLE,
    ) -> i32;
    fn ImpersonateLoggedOnUser(token: HANDLE) -> i32;
    fn RevertToSelf() -> i32;
    fn LookupPrivilegeValueW(system: PWSTR, name: PWSTR, luid: *mut Luid) -> i32;
    fn AdjustTokenPrivileges(
        token: HANDLE,
        disable_all: i32,
        new_state: *const TokenPrivilegesOne,
        buffer_length: u32,
        previous_state: *mut TokenPrivilegesOne,
        return_length: *mut u32,
    ) -> i32;
}
#[link(name = "Userenv")]
unsafe extern "system" {
    fn LoadUserProfileW(token: HANDLE, profile_info: *mut ProfileInfoW) -> i32;
    fn UnloadUserProfile(token: HANDLE, profile: HANDLE) -> i32;
    fn CreateEnvironmentBlock(environment: *mut *mut c_void, token: HANDLE, inherit: i32) -> i32;
    fn DestroyEnvironmentBlock(environment: *mut c_void) -> i32;
    fn GetUserProfileDirectoryW(token: HANDLE, profile_dir: PWSTR, size: *mut u32) -> i32;
}
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn ProcessIdToSessionId(process_id: u32, session_id: *mut u32) -> i32;
}

pub(crate) struct StandardUserSession {
    token: OwnedHandle,
    profile: HANDLE,
    environment: *mut c_void,
    context: StandardUserRuntimeContext,
    _profile_privileges: ScopedPrivileges,
}

impl StandardUserSession {
    /// Creates the one reviewed Sandbox-local account.  An existing account is
    /// always rejected: accepting it would turn this into account adoption.
    pub(crate) fn establish() -> Result<Self, GuestMsiExecutionError> {
        let mut user_name = wide(STANDARD_USER_ACCOUNT_NAME)?;
        let mut password = random_password()?;
        let created = create_user(&mut user_name, &mut password);
        if let Err(error) = created {
            password.fill(0);
            return Err(error);
        }

        let mut token = HANDLE::default();
        let domain = wide(".")?;
        // SAFETY: the account and password buffers remain valid for the call;
        // LOGON32_LOGON_INTERACTIVE returns a primary token on success.
        let logged_on = unsafe {
            LogonUserW(
                PWSTR(user_name.as_mut_ptr()),
                PWSTR(domain.as_ptr() as *mut u16),
                PWSTR(password.as_mut_ptr()),
                2, // LOGON32_LOGON_INTERACTIVE
                0, // LOGON32_PROVIDER_DEFAULT
                &mut token,
            )
        };
        password.fill(0);
        if logged_on == 0 {
            return Err(last_error("LogonUserW"));
        }
        // SAFETY: LogonUserW returned a unique, real token handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        let user_sid = validate_standard_token(raw_handle(&token))?;

        let profile_privileges =
            ScopedPrivileges::enable(&["SeBackupPrivilege", "SeRestorePrivilege"])?;
        let mut profile_info = ProfileInfoW {
            size: size_of::<ProfileInfoW>() as u32,
            flags: 0,
            user_name: PWSTR(user_name.as_mut_ptr()),
            profile_path: PWSTR::null(),
            default_path: PWSTR::null(),
            server_name: PWSTR::null(),
            policy_path: PWSTR::null(),
            profile: HANDLE::default(),
        };
        // SAFETY: token and PROFILEINFO are valid; this elevated guest owns
        // the resulting profile handle and unloads it in Drop.
        if unsafe { LoadUserProfileW(raw_handle(&token), &mut profile_info) } == 0 {
            return Err(last_error("LoadUserProfileW"));
        }
        let mut environment = std::ptr::null_mut();
        // SAFETY: a loaded, validated user primary token is supplied and the
        // returned block is destroyed in Drop.
        if unsafe { CreateEnvironmentBlock(&mut environment, raw_handle(&token), 0) } == 0 {
            // SAFETY: successful LoadUserProfileW returned this exact handle.
            let _ = unsafe { UnloadUserProfile(raw_handle(&token), profile_info.profile) };
            return Err(last_error("CreateEnvironmentBlock"));
        }
        // Own both native allocations before any fallible decoding or path checks.
        let mut session = Self {
            token,
            profile: profile_info.profile,
            environment,
            context: StandardUserRuntimeContext {
                user_sid,
                profile_path: String::new(),
                roaming_app_data: String::new(),
                local_app_data: String::new(),
                administrators_enabled: false,
            },
            _profile_privileges: profile_privileges,
        };
        let profile_path = user_profile_directory(session.token())?;
        let (environment_profile, roaming_app_data, local_app_data) =
            environment_paths(session.environment)?;
        if !profile_path.eq_ignore_ascii_case(&environment_profile) {
            return Err(GuestMsiExecutionError::Process(
                "loaded profile differs from the target environment".to_owned(),
            ));
        }
        session.context.profile_path = profile_path;
        session.context.roaming_app_data = roaming_app_data;
        session.context.local_app_data = local_app_data;
        session
            .context
            .validate()
            .map_err(GuestMsiExecutionError::Process)?;
        Ok(session)
    }

    pub(crate) fn token(&self) -> HANDLE {
        raw_handle(&self.token)
    }

    pub(crate) fn environment(&self) -> *mut c_void {
        self.environment
    }

    pub(crate) fn context(&self) -> &StandardUserRuntimeContext {
        &self.context
    }

    pub(crate) fn document_root(&self) -> &Path {
        Path::new(STANDARD_USER_DOCUMENT_ROOT)
    }

    pub(crate) fn roaming_app_data(&self) -> &Path {
        Path::new(&self.context.roaming_app_data)
    }

    pub(crate) fn local_app_data(&self) -> &Path {
        Path::new(&self.context.local_app_data)
    }

    pub(crate) fn impersonate<T>(
        &self,
        operation: impl FnOnce() -> Result<T, GuestMsiExecutionError>,
    ) -> Result<T, GuestMsiExecutionError> {
        // SAFETY: this is the validated primary token owned by the session.
        if unsafe { ImpersonateLoggedOnUser(raw_handle(&self.token)) } == 0 {
            return Err(last_error("ImpersonateLoggedOnUser"));
        }
        let guard = ImpersonationGuard { active: true };
        let result = operation();
        if guard.revert().is_err() {
            // A normal error receipt would be unsafe while this thread may
            // still impersonate the target user.
            std::process::abort();
        }
        result
    }

    pub(crate) fn validate_suspended_child(
        &self,
        process: BorrowedHandle<'_>,
    ) -> Result<(), GuestMsiExecutionError> {
        let mut child_token = HANDLE::default();
        // SAFETY: process is the exact child handle retained by the launcher.
        unsafe {
            OpenProcessToken(
                HANDLE(process.as_raw_handle()),
                TOKEN_QUERY,
                &mut child_token,
            )
        }
        .map_err(|error| {
            GuestMsiExecutionError::Process(format!("OpenProcessToken child failed: {error}"))
        })?;
        let child_token = unsafe { OwnedHandle::from_raw_handle(child_token.0) };
        let child_sid = validate_standard_token(raw_handle(&child_token))?;
        if child_sid != self.context.user_sid {
            return Err(GuestMsiExecutionError::Process(
                "suspended child SID differed from the created standard user".to_owned(),
            ));
        }
        let evidence = aiw_token::collect_process_token(process).map_err(|error| {
            GuestMsiExecutionError::Process(format!(
                "collect suspended standard-user child token failed: {error}"
            ))
        })?;
        self.context.validate_token(&evidence).map_err(|error| {
            GuestMsiExecutionError::Process(format!(
                "suspended standard-user child token violated the published runtime contract: {error}"
            ))
        })?;
        let child_session: u32 = query_fixed(
            raw_handle(&child_token),
            windows::Win32::Security::TokenSessionId,
            "TokenSessionId",
        )?;
        let mut current_session = 0;
        let mut actual_child_session = 0;
        let child_pid = unsafe { GetProcessId(HANDLE(process.as_raw_handle())) };
        // Bind the physical process session as well as the token's session.
        if child_pid == 0
            || unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut current_session) } == 0
            || unsafe { ProcessIdToSessionId(child_pid, &mut actual_child_session) } == 0
            || child_session != current_session
            || actual_child_session != current_session
        {
            return Err(GuestMsiExecutionError::Process(format!(
                "suspended child session mismatch: agent={current_session}, process={actual_child_session}, token={child_session}"
            )));
        }
        Ok(())
    }
}

pub(crate) struct ScopedPrivileges {
    token: OwnedHandle,
    previous: Vec<TokenPrivilegesOne>,
}

impl ScopedPrivileges {
    pub(crate) fn enable(names: &[&str]) -> Result<Self, GuestMsiExecutionError> {
        let mut raw = HANDLE::default();
        // SAFETY: current-process pseudo handle is accepted and output is valid.
        unsafe {
            OpenProcessToken(
                windows::Win32::System::Threading::GetCurrentProcess(),
                windows::Win32::Security::TOKEN_ACCESS_MASK(
                    TOKEN_QUERY_ACCESS | TOKEN_ADJUST_PRIVILEGES,
                ),
                &mut raw,
            )
        }
        .map_err(|e| {
            GuestMsiExecutionError::Process(format!("OpenProcessToken privileges failed: {e}"))
        })?;
        let token = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        let mut guard = Self {
            token,
            previous: Vec::with_capacity(names.len()),
        };
        for name in names {
            let mut luid = Luid { low: 0, high: 0 };
            let mut name_w = wide(name)?;
            if unsafe {
                LookupPrivilegeValueW(PWSTR::null(), PWSTR(name_w.as_mut_ptr()), &mut luid)
            } == 0
            {
                return Err(last_error("LookupPrivilegeValueW"));
            }
            let requested = TokenPrivilegesOne {
                count: 1,
                privilege: LuidAndAttributes {
                    luid,
                    attributes: SE_PRIVILEGE_ENABLED,
                },
            };
            let mut prior = TokenPrivilegesOne {
                count: 0,
                privilege: LuidAndAttributes {
                    luid,
                    attributes: 0,
                },
            };
            let mut returned = 0;
            // AdjustTokenPrivileges may succeed while reporting partial assignment
            // through last-error, so clear stale state immediately before it.
            unsafe { SetLastError(windows::Win32::Foundation::WIN32_ERROR(0)) };
            if unsafe {
                AdjustTokenPrivileges(
                    raw_handle(&guard.token),
                    0,
                    &requested,
                    size_of::<TokenPrivilegesOne>() as u32,
                    &mut prior,
                    &mut returned,
                )
            } == 0
                || unsafe { GetLastError() }.0 == ERROR_NOT_ALL_ASSIGNED
            {
                return Err(last_error("AdjustTokenPrivileges enable"));
            }
            // Already-enabled privileges have no changed entry to restore.
            if prior.count == 0
                && returned >= 4
                && returned <= size_of::<TokenPrivilegesOne>() as u32
            {
                continue;
            }
            if returned != size_of::<TokenPrivilegesOne>() as u32
                || prior.count != 1
                || prior.privilege.luid.low != luid.low
                || prior.privilege.luid.high != luid.high
            {
                // A change may have occurred but its restoration authority is invalid.
                std::process::abort();
            }
            guard.previous.push(prior);
        }
        Ok(guard)
    }
}

impl Drop for ScopedPrivileges {
    fn drop(&mut self) {
        for prior in self.previous.iter().rev() {
            // SAFETY: each value is the exact prior state returned for this token.
            unsafe { SetLastError(windows::Win32::Foundation::WIN32_ERROR(0)) };
            let ok = unsafe {
                AdjustTokenPrivileges(
                    raw_handle(&self.token),
                    0,
                    prior,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } != 0;
            if !ok || unsafe { GetLastError() }.0 == ERROR_NOT_ALL_ASSIGNED {
                std::process::abort();
            }
        }
    }
}

struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    fn revert(mut self) -> Result<(), GuestMsiExecutionError> {
        // SAFETY: this guard is constructed only after ImpersonateLoggedOnUser succeeds.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            // Never publish or unwind into other guest operations with uncertain identity.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
}

impl Drop for StandardUserSession {
    fn drop(&mut self) {
        if !self.environment.is_null() {
            // SAFETY: this is the exact block returned by CreateEnvironmentBlock.
            let _ = unsafe { DestroyEnvironmentBlock(self.environment) };
        }
        if !self.profile.is_invalid() {
            // SAFETY: this is the exact profile handle returned for this token.
            let _ = unsafe { UnloadUserProfile(raw_handle(&self.token), self.profile) };
        }
    }
}

fn create_user(user_name: &mut [u16], password: &mut [u16]) -> Result<(), GuestMsiExecutionError> {
    let mut info = UserInfo1 {
        name: PWSTR(user_name.as_mut_ptr()),
        password: PWSTR(password.as_mut_ptr()),
        password_age: 0,
        privilege: USER_PRIV_USER,
        home_dir: PWSTR::null(),
        comment: PWSTR::null(),
        flags: UF_SCRIPT,
        script_path: PWSTR::null(),
    };
    let mut parameter_error = 0;
    // SAFETY: USER_INFO_1 and its NUL-terminated strings remain valid.
    let status = unsafe {
        NetUserAdd(
            PWSTR::null(),
            1,
            (&mut info as *mut UserInfo1).cast(),
            &mut parameter_error,
        )
    };
    match status {
        NERR_SUCCESS => Ok(()),
        NERR_USER_EXISTS => Err(GuestMsiExecutionError::Process(
            "AiwStandardUser already exists; refusing to adopt a pre-existing account".to_owned(),
        )),
        _ => Err(GuestMsiExecutionError::Process(format!(
            "NetUserAdd failed with status {status}, parameter {parameter_error}"
        ))),
    }
}

fn random_password() -> Result<Vec<u16>, GuestMsiExecutionError> {
    let mut bytes = [0_u8; 32];
    // SAFETY: BCryptGenRandom writes exactly the supplied fixed buffer.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(GuestMsiExecutionError::Process(format!(
            "BCryptGenRandom failed with NTSTATUS 0x{status:08x}"
        )));
    }
    let mut password = Vec::with_capacity(bytes.len() + 1);
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const DIGIT: &[u8] = b"23456789";
    const SYMBOL: &[u8] = b"!@#$%^&*";
    let classes = [UPPER, LOWER, DIGIT, SYMBOL];
    for (index, byte) in bytes.into_iter().enumerate() {
        let class = if index < classes.len() {
            classes[index]
        } else {
            b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"
        };
        password.push(u16::from(class[usize::from(byte) % class.len()]));
    }
    password.push(0);
    Ok(password)
}

fn user_profile_directory(token: HANDLE) -> Result<String, GuestMsiExecutionError> {
    let mut size = 0_u32;
    // SAFETY: documented size-query call.
    let _ = unsafe { GetUserProfileDirectoryW(token, PWSTR::null(), &mut size) };
    if size == 0 || size > 32_768 {
        return Err(last_error("GetUserProfileDirectoryW size"));
    }
    let mut buffer = vec![0_u16; size as usize];
    // SAFETY: buffer has the returned character capacity.
    if unsafe { GetUserProfileDirectoryW(token, PWSTR(buffer.as_mut_ptr()), &mut size) } == 0 {
        return Err(last_error("GetUserProfileDirectoryW"));
    }
    let nul = buffer.iter().position(|value| *value == 0).ok_or_else(|| {
        GuestMsiExecutionError::Process(
            "GetUserProfileDirectoryW returned unterminated data".to_owned(),
        )
    })?;
    String::from_utf16(&buffer[..nul]).map_err(|_| {
        GuestMsiExecutionError::Process(
            "GetUserProfileDirectoryW returned invalid UTF-16".to_owned(),
        )
    })
}

fn environment_paths(
    environment: *mut c_void,
) -> Result<(String, String, String), GuestMsiExecutionError> {
    if environment.is_null() {
        return Err(GuestMsiExecutionError::Process(
            "CreateEnvironmentBlock returned null".to_owned(),
        ));
    }
    let mut values = Vec::new();
    for index in 0..32_768 {
        // SAFETY: this private function receives only the live OS-created block.
        // Its allocation is guaranteed through the double NUL, where we stop;
        // never invent a slice extending beyond that allocation.
        let unit = unsafe { environment.cast::<u16>().add(index).read() };
        let ended = unit == 0 && values.last() == Some(&0);
        values.push(unit);
        if ended {
            return parse_environment_paths(&values);
        }
    }
    Err(GuestMsiExecutionError::Process(
        "target environment exceeded the fixed bound".to_owned(),
    ))
}

fn parse_environment_paths(
    values: &[u16],
) -> Result<(String, String, String), GuestMsiExecutionError> {
    if values.len() > 32_768 || !values.ends_with(&[0, 0]) {
        return Err(GuestMsiExecutionError::Process(
            "target environment is not bounded and terminated".to_owned(),
        ));
    }
    let mut profile = None;
    let mut roaming = None;
    let mut local = None;
    let mut start = 0;
    while start < values.len() {
        let end = values[start..]
            .iter()
            .position(|value| *value == 0)
            .map(|offset| start + offset)
            .ok_or_else(|| {
                GuestMsiExecutionError::Process("environment block exceeded bound".to_owned())
            })?;
        if end == start {
            break;
        }
        let entry = String::from_utf16(&values[start..end]).map_err(|_| {
            GuestMsiExecutionError::Process("environment block contained invalid UTF-16".to_owned())
        })?;
        if let Some((key, value)) = entry.split_once('=') {
            match key.to_ascii_uppercase().as_str() {
                "USERPROFILE" => set_environment_path(&mut profile, value)?,
                "APPDATA" => set_environment_path(&mut roaming, value)?,
                "LOCALAPPDATA" => set_environment_path(&mut local, value)?,
                _ => {}
            }
        }
        start = end + 1;
    }
    Ok((
        profile.ok_or_else(|| {
            GuestMsiExecutionError::Process("target environment lacked USERPROFILE".to_owned())
        })?,
        roaming.ok_or_else(|| {
            GuestMsiExecutionError::Process("target environment lacked APPDATA".to_owned())
        })?,
        local.ok_or_else(|| {
            GuestMsiExecutionError::Process("target environment lacked LOCALAPPDATA".to_owned())
        })?,
    ))
}

fn set_environment_path(
    slot: &mut Option<String>,
    value: &str,
) -> Result<(), GuestMsiExecutionError> {
    if slot.is_some() || value.is_empty() {
        return Err(GuestMsiExecutionError::Process(
            "target environment has duplicate or empty profile variables".to_owned(),
        ));
    }
    *slot = Some(value.to_owned());
    Ok(())
}

fn validate_standard_token(token: HANDLE) -> Result<String, GuestMsiExecutionError> {
    let token_type: TOKEN_TYPE = query_fixed(token, TokenTypeClass, "TokenType")?;
    if token_type != TokenPrimary {
        return Err(GuestMsiExecutionError::Process(
            "standard user logon did not return a primary token".to_owned(),
        ));
    }
    let elevation: TOKEN_ELEVATION = query_fixed(token, TokenElevation, "TokenElevation")?;
    if elevation.TokenIsElevated != 0 {
        return Err(GuestMsiExecutionError::Process(
            "standard user token was elevated".to_owned(),
        ));
    }
    let elevation_type: TOKEN_ELEVATION_TYPE =
        query_fixed(token, TokenElevationType, "TokenElevationType")?;
    if elevation_type != TokenElevationTypeDefault {
        return Err(GuestMsiExecutionError::Process(
            "standard user token did not use the default non-UAC elevation type".to_owned(),
        ));
    }
    let integrity = query_variable(token, TokenIntegrityLevel, "TokenIntegrityLevel")?;
    let mandatory = cast::<TOKEN_MANDATORY_LABEL>(&integrity, "TokenIntegrityLevel")?;
    if sid_rid(mandatory.Label.Sid)? != SECURITY_MANDATORY_MEDIUM_RID {
        return Err(GuestMsiExecutionError::Process(
            "standard user token integrity was not Medium".to_owned(),
        ));
    }
    let groups = query_variable(token, TokenGroups, "TokenGroups")?;
    let mut has_builtin_users = false;
    if group_count(&groups)? != 0 {
        // A fresh local user is allowed to have ordinary groups, but never the
        // built-in Administrators SID.  The account's default Users group is
        // intentionally not treated as an elevation signal.
        for group in groups_list(&groups)? {
            let sid = sid_string(group.Sid)?;
            if sid == "S-1-5-32-545" {
                has_builtin_users = true;
            }
            if sid == "S-1-5-32-544" {
                return Err(GuestMsiExecutionError::Process(
                    "standard user token included the built-in Administrators group".to_owned(),
                ));
            }
        }
    }
    if !has_builtin_users {
        return Err(GuestMsiExecutionError::Process(
            "fresh standard user was not a member of the built-in Users group".to_owned(),
        ));
    }
    let user = query_variable(token, TokenUser, "TokenUser")?;
    let user = cast::<TOKEN_USER>(&user, "TokenUser")?;
    sid_string(user.User.Sid)
}

fn query_fixed<T: Copy>(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    operation: &str,
) -> Result<T, GuestMsiExecutionError> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let mut returned = 0;
    // SAFETY: output is valid for T and the caller selects a fixed-size class.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            Some(value.as_mut_ptr().cast()),
            size_of::<T>() as u32,
            &mut returned,
        )
    }
    .is_err()
        || returned != size_of::<T>() as u32
    {
        return Err(last_error(operation));
    }
    // SAFETY: successful GetTokenInformation initialized T.
    Ok(unsafe { value.assume_init() })
}

fn query_variable(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    operation: &str,
) -> Result<Vec<usize>, GuestMsiExecutionError> {
    let mut required = 0;
    // SAFETY: documented buffer-size query.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut required) };
    if required == 0 {
        return Err(last_error(operation));
    }
    let words = usize::try_from(required)
        .map_err(|_| GuestMsiExecutionError::Process(format!("{operation} size overflow")))?
        .div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    let mut returned = required;
    // SAFETY: usize storage has sufficient alignment and is at least required bytes.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &mut returned,
        )
    }
    .is_err()
        || returned != required
    {
        return Err(last_error(operation));
    }
    Ok(buffer)
}

fn cast<'a, T>(buffer: &'a [usize], operation: &str) -> Result<&'a T, GuestMsiExecutionError> {
    if std::mem::size_of_val(buffer) < size_of::<T>() {
        return Err(GuestMsiExecutionError::Process(format!(
            "{operation} returned a short token buffer"
        )));
    }
    // SAFETY: Vec<usize> alignment suffices and length was checked.
    Ok(unsafe { &*buffer.as_ptr().cast() })
}

fn group_count(buffer: &[usize]) -> Result<usize, GuestMsiExecutionError> {
    if std::mem::size_of_val(buffer) < size_of::<u32>() {
        return Err(GuestMsiExecutionError::Process(
            "TokenGroups returned no count".to_owned(),
        ));
    }
    // SAFETY: the buffer has enough bytes for the count.
    Ok(unsafe { *buffer.as_ptr().cast::<u32>() } as usize)
}

fn groups_list(
    buffer: &[usize],
) -> Result<&[windows::Win32::Security::SID_AND_ATTRIBUTES], GuestMsiExecutionError> {
    let count = group_count(buffer)?;
    let groups = cast::<TOKEN_GROUPS>(buffer, "TokenGroups")?;
    let start =
        size_of::<TOKEN_GROUPS>() - size_of::<windows::Win32::Security::SID_AND_ATTRIBUTES>();
    let needed = start
        .checked_add(
            count
                .checked_mul(size_of::<windows::Win32::Security::SID_AND_ATTRIBUTES>())
                .ok_or_else(|| {
                    GuestMsiExecutionError::Process("TokenGroups count overflow".to_owned())
                })?,
        )
        .ok_or_else(|| GuestMsiExecutionError::Process("TokenGroups size overflow".to_owned()))?;
    if std::mem::size_of_val(buffer) < needed {
        return Err(GuestMsiExecutionError::Process(
            "TokenGroups count exceeded returned buffer".to_owned(),
        ));
    }
    // SAFETY: flexible-array length was bounded by the returned allocation.
    Ok(unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), count) })
}

fn sid_rid(sid: PSID) -> Result<u32, GuestMsiExecutionError> {
    // SAFETY: the SID originates in successful token information.
    let count = unsafe { GetSidSubAuthorityCount(sid) };
    if count.is_null() || unsafe { *count } == 0 {
        return Err(GuestMsiExecutionError::Process(
            "token mandatory-label SID was malformed".to_owned(),
        ));
    }
    // SAFETY: checked nonzero count means index count - 1 is valid.
    let rid = unsafe { GetSidSubAuthority(sid, u32::from(*count - 1)) };
    if rid.is_null() {
        return Err(GuestMsiExecutionError::Process(
            "token mandatory-label SID lacked a subauthority".to_owned(),
        ));
    }
    // SAFETY: pointer returned for a valid SID subauthority is readable.
    Ok(unsafe { *rid })
}

fn sid_string(sid: PSID) -> Result<String, GuestMsiExecutionError> {
    let mut output = PWSTR::null();
    // SAFETY: token-sourced SID and output storage follow the API contract.
    unsafe { ConvertSidToStringSidW(sid, &mut output) }.map_err(|error| {
        GuestMsiExecutionError::Process(format!("ConvertSidToStringSidW failed: {error}"))
    })?;
    // SAFETY: successful conversion returns a NUL-terminated LocalAlloc string.
    let text = unsafe { output.to_string() }.map_err(|error| {
        GuestMsiExecutionError::Process(format!("token SID was not Unicode: {error}"))
    });
    // SAFETY: ConvertSidToStringSidW allocations are released with LocalFree.
    let _ = unsafe { LocalFree(Some(HLOCAL(output.0.cast()))) };
    text
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    use std::os::windows::io::AsRawHandle;
    HANDLE(handle.as_raw_handle() as isize as *mut c_void)
}

fn wide(value: &str) -> Result<Vec<u16>, GuestMsiExecutionError> {
    if value.contains('\0') {
        return Err(GuestMsiExecutionError::Process(
            "standard-user value contained NUL".to_owned(),
        ));
    }
    Ok(OsStr::new(value).encode_wide().chain(Some(0)).collect())
}

fn last_error(operation: &str) -> GuestMsiExecutionError {
    GuestMsiExecutionError::Process(format!(
        "{operation} failed: {}",
        windows::core::Error::from_thread()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_token_queries_accept_successful_fixed_and_variable_results() {
        let mut handle = HANDLE::default();
        // Read-only observation of this test process; never creates an account.
        unsafe {
            OpenProcessToken(
                windows::Win32::System::Threading::GetCurrentProcess(),
                TOKEN_QUERY,
                &mut handle,
            )
        }
        .unwrap();
        let held = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        let kind: TOKEN_TYPE = query_fixed(raw_handle(&held), TokenTypeClass, "TokenType").unwrap();
        assert_eq!(kind, TokenPrimary);
        let groups = query_variable(raw_handle(&held), TokenGroups, "TokenGroups").unwrap();
        assert_eq!(
            groups_list(&groups).unwrap().len(),
            group_count(&groups).unwrap()
        );
        let user = query_variable(raw_handle(&held), TokenUser, "TokenUser").unwrap();
        assert!(
            sid_string(cast::<TOKEN_USER>(&user, "TokenUser").unwrap().User.Sid)
                .unwrap()
                .starts_with("S-1-")
        );
    }

    #[test]
    fn environment_capture_is_bounded_and_rejects_ambiguous_paths() {
        let text = "USERPROFILE=C:\\User\0APPDATA=C:\\Roaming\0LOCALAPPDATA=C:\\Local\0\0";
        let block: Vec<u16> = text.encode_utf16().collect();
        assert_eq!(
            parse_environment_paths(&block).unwrap(),
            ("C:\\User".into(), "C:\\Roaming".into(), "C:\\Local".into())
        );
        assert!(parse_environment_paths(&block[..block.len() - 1]).is_err());
        let duplicate: Vec<u16> = ("userprofile=C:\\Other\0".to_owned() + text)
            .encode_utf16()
            .collect();
        assert!(parse_environment_paths(&duplicate).is_err());
        let missing: Vec<u16> = "APPDATA=C:\\Roaming\0\0".encode_utf16().collect();
        assert!(parse_environment_paths(&missing).is_err());
    }
}
