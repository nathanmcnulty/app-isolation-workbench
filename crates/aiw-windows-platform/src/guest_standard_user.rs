//! Native-only standard-user context for the fixed v0alpha4 Notepad++ guest
//! profile.  This deliberately creates one exact, fresh local account inside
//! the disposable Sandbox and never derives a restricted token from the
//! elevated guest agent.

use std::ffi::{OsStr, c_void};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
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
use aiw_provider_wsb::{
    STANDARD_USER_ACCOUNT_NAME, STANDARD_USER_PROFILE_PATH, StandardUserRuntimeContext,
};

pub const STANDARD_USER_DOCUMENT_ROOT: &str = r"C:\Users\AiwStandardUser\AppData\Local\AIW";
const STANDARD_USER_ROAMING_APP_DATA: &str = r"C:\Users\AiwStandardUser\AppData\Roaming";
const STANDARD_USER_LOCAL_APP_DATA: &str = r"C:\Users\AiwStandardUser\AppData\Local";

const USER_PRIV_USER: u32 = 1;
const UF_SCRIPT: u32 = 1;
const NERR_SUCCESS: u32 = 0;
const NERR_USER_EXISTS: u32 = 2_222;
const STATUS_SUCCESS: i32 = 0;
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;

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
        let profile_path = user_profile_directory(raw_handle(&token))?;
        let (environment_profile, roaming_app_data, local_app_data) = environment_paths(environment)?;
        if profile_path != STANDARD_USER_PROFILE_PATH
            || environment_profile != STANDARD_USER_PROFILE_PATH
            || roaming_app_data != STANDARD_USER_ROAMING_APP_DATA
            || local_app_data != STANDARD_USER_LOCAL_APP_DATA
        {
            // SAFETY: both values came from the successful calls immediately above.
            let _ = unsafe { DestroyEnvironmentBlock(environment) };
            let _ = unsafe { UnloadUserProfile(raw_handle(&token), profile_info.profile) };
            return Err(GuestMsiExecutionError::Process(
                "standard-user profile or environment did not match the fixed runtime paths".to_owned(),
            ));
        }
        Ok(Self {
            token,
            profile: profile_info.profile,
            environment,
            context: StandardUserRuntimeContext {
                user_sid,
                profile_path,
                roaming_app_data,
                local_app_data,
                administrators_enabled: false,
            },
        })
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
        let child_session: u32 = query_fixed(raw_handle(&child_token), windows::Win32::Security::TokenSessionId, "TokenSessionId")?;
        let mut current_session = 0;
        // SAFETY: both process ids are queried by the documented API.
        if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut current_session) } == 0
            || unsafe { GetProcessId(HANDLE(process.as_raw_handle())) } == 0
            || child_session != current_session
        {
            return Err(GuestMsiExecutionError::Process(
                "suspended child was not bound to the guest interactive session".to_owned(),
            ));
        }
        Ok(())
    }
}

struct ImpersonationGuard { active: bool }

impl ImpersonationGuard {
    fn revert(mut self) -> Result<(), GuestMsiExecutionError> {
        // SAFETY: this guard is constructed only after ImpersonateLoggedOnUser succeeds.
        if unsafe { RevertToSelf() } == 0 { return Err(last_error("RevertToSelf")); }
        self.active = false;
        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: best-effort unwinding cleanup for this thread's exact impersonation.
            let _ = unsafe { RevertToSelf() };
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
        let class = if index < classes.len() { classes[index] } else { b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*" };
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
    let nul = buffer.iter().position(|value| *value == 0).ok_or_else(|| GuestMsiExecutionError::Process("GetUserProfileDirectoryW returned unterminated data".to_owned()))?;
    String::from_utf16(&buffer[..nul]).map_err(|_| GuestMsiExecutionError::Process("GetUserProfileDirectoryW returned invalid UTF-16".to_owned()))
}

fn environment_paths(environment: *mut c_void) -> Result<(String, String, String), GuestMsiExecutionError> {
    if environment.is_null() { return Err(GuestMsiExecutionError::Process("CreateEnvironmentBlock returned null".to_owned())); }
    // SAFETY: CreateEnvironmentBlock returns a double-NUL-terminated UTF-16 block.
    let values = unsafe { std::slice::from_raw_parts(environment.cast::<u16>(), 32_768) };
    let mut profile = None;
    let mut roaming = None;
    let mut local = None;
    let mut start = 0;
    while start < values.len() {
        let end = values[start..].iter().position(|value| *value == 0).map(|offset| start + offset).ok_or_else(|| GuestMsiExecutionError::Process("environment block exceeded bound".to_owned()))?;
        if end == start { break; }
        let entry = String::from_utf16(&values[start..end]).map_err(|_| GuestMsiExecutionError::Process("environment block contained invalid UTF-16".to_owned()))?;
        if let Some((key, value)) = entry.split_once('=') {
            match key.to_ascii_uppercase().as_str() {
                "USERPROFILE" => profile = Some(value.to_owned()),
                "APPDATA" => roaming = Some(value.to_owned()),
                "LOCALAPPDATA" => local = Some(value.to_owned()),
                _ => {}
            }
        }
        start = end + 1;
    }
    Ok((profile.ok_or_else(|| GuestMsiExecutionError::Process("target environment lacked USERPROFILE".to_owned()))?, roaming.ok_or_else(|| GuestMsiExecutionError::Process("target environment lacked APPDATA".to_owned()))?, local.ok_or_else(|| GuestMsiExecutionError::Process("target environment lacked LOCALAPPDATA".to_owned()))?))
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
            if sid == "S-1-5-32-545" { has_builtin_users = true; }
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
    if buffer.len() * size_of::<usize>() < size_of::<T>() {
        return Err(GuestMsiExecutionError::Process(format!(
            "{operation} returned a short token buffer"
        )));
    }
    // SAFETY: Vec<usize> alignment suffices and length was checked.
    Ok(unsafe { &*buffer.as_ptr().cast() })
}

fn group_count(buffer: &[usize]) -> Result<usize, GuestMsiExecutionError> {
    if buffer.len() * size_of::<usize>() < size_of::<u32>() {
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
    if buffer.len() * size_of::<usize>() < needed {
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
    use std::path::PathBuf;

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
    fn standard_user_paths_are_the_reviewed_fixed_profile() {
        assert_eq!(STANDARD_USER_PROFILE_PATH, r"C:\Users\AiwStandardUser");
        assert_eq!(
            STANDARD_USER_ROAMING_APP_DATA,
            format!(r"{STANDARD_USER_PROFILE_PATH}\AppData\Roaming")
        );
        assert_eq!(
            STANDARD_USER_LOCAL_APP_DATA,
            format!(r"{STANDARD_USER_PROFILE_PATH}\AppData\Local")
        );
        assert_eq!(
            PathBuf::from(STANDARD_USER_DOCUMENT_ROOT).join("Scenario\\document.txt"),
            PathBuf::from(r"C:\Users\AiwStandardUser\AppData\Local\AIW\Scenario\document.txt")
        );
    }
}
