//! Native access to an already signed-in, run-owned standard user. No account creation,
//! alternate credentials, profile loading, desktop ACL changes or token export.
use crate::GuestMsiExecutionError;
use crate::guest_standard_user::{
    ScopedPrivileges, environment_paths, user_profile_directory, validate_standard_token,
};
use aiw_provider_wsb::StandardUserRuntimeContext;
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetTokenInformation, TOKEN_STATISTICS, TokenIsAppContainer, TokenSessionId, TokenStatistics,
};

#[link(name = "Wtsapi32")]
unsafe extern "system" {
    fn WTSQueryUserToken(session: u32, token: *mut HANDLE) -> i32;
    fn WTSQuerySessionInformationW(
        server: HANDLE,
        session: u32,
        class: i32,
        buffer: *mut *mut c_void,
        bytes: *mut u32,
    ) -> i32;
    fn WTSFreeMemory(buffer: *mut c_void);
    fn WTSEnumerateSessionsW(
        server: HANDLE,
        reserved: u32,
        version: u32,
        sessions: *mut *mut WtsSession,
        count: *mut u32,
    ) -> i32;
}
#[repr(C)]
struct WtsSession {
    id: u32,
    station: *mut u16,
    state: i32,
}
#[link(name = "Userenv")]
unsafe extern "system" {
    fn CreateEnvironmentBlock(block: *mut *mut c_void, token: HANDLE, inherit: i32) -> i32;
    fn DestroyEnvironmentBlock(block: *mut c_void) -> i32;
}
fn error(stage: &str) -> GuestMsiExecutionError {
    GuestMsiExecutionError::Process(format!("{stage}: {}", windows::core::Error::from_thread()))
}
pub(crate) fn token_logon(token: HANDLE) -> Result<(u32, String), GuestMsiExecutionError> {
    let mut needed = 0;
    let mut session = 0u32;
    let mut stats = TOKEN_STATISTICS::default();
    let mut container = 0u32;
    // SAFETY: fixed native output structures and exact live token handle.
    unsafe {
        GetTokenInformation(
            token,
            TokenIsAppContainer,
            Some((&mut container as *mut u32).cast()),
            4,
            &mut needed,
        )
        .map_err(|e| GuestMsiExecutionError::Process(e.to_string()))?;
        if needed != 4 || container != 0 {
            return Err(error("Non-AppContainer primary token required"));
        }
        GetTokenInformation(
            token,
            TokenSessionId,
            Some((&mut session as *mut u32).cast()),
            4,
            &mut needed,
        )
        .map_err(|e| GuestMsiExecutionError::Process(e.to_string()))?;
        if needed != 4 {
            return Err(error("Token session length differs"));
        }
        GetTokenInformation(
            token,
            TokenStatistics,
            Some((&mut stats as *mut TOKEN_STATISTICS).cast()),
            std::mem::size_of::<TOKEN_STATISTICS>() as u32,
            &mut needed,
        )
        .map_err(|e| GuestMsiExecutionError::Process(e.to_string()))?;
    }
    if needed != std::mem::size_of::<TOKEN_STATISTICS>() as u32 {
        return Err(error("Token statistics length differs"));
    }
    Ok((
        session,
        format!(
            "{:08x}{:08x}",
            stats.AuthenticationId.HighPart as u32, stats.AuthenticationId.LowPart
        ),
    ))
}
fn active_session(session: u32) -> Result<(), GuestMsiExecutionError> {
    let mut pointer = std::ptr::null_mut();
    let mut bytes = 0;
    // SAFETY: documented current-server query; allocation is freed below.
    if unsafe {
        WTSQuerySessionInformationW(HANDLE::default(), session, 8, &mut pointer, &mut bytes)
    } == 0
    {
        return Err(error("WTS active-state query"));
    }
    let result = if pointer.is_null() || bytes != 4 {
        Err(error("WTS active-state buffer"))
    } else {
        // SAFETY: successful query returned the checked four-byte state.
        if unsafe { pointer.cast::<i32>().read() } == 0 && session != 0 {
            Ok(())
        } else {
            Err(error("Primary user session is not active"))
        }
    };
    // SAFETY: only the WTS-owned query allocation is released.
    if !pointer.is_null() {
        unsafe { WTSFreeMemory(pointer) };
    }
    result
}
fn unique_user_session(expected: u32) -> Result<(), GuestMsiExecutionError> {
    let mut sessions = std::ptr::null_mut();
    let mut count = 0;
    // SAFETY: documented local-server enumeration; allocation freed below.
    if unsafe { WTSEnumerateSessionsW(HANDLE::default(), 0, 1, &mut sessions, &mut count) } == 0 {
        return Err(error("WTS session enumeration"));
    }
    let result = (|| {
        if sessions.is_null() || count > 128 {
            return Err(error("WTS enumeration bound"));
        }
        let mut matched = 0;
        for index in 0..count {
            // SAFETY: successful enumeration owns exactly count entries.
            let row = unsafe { &*sessions.add(index as usize) };
            let mut buffer = std::ptr::null_mut();
            let mut bytes = 0;
            // SAFETY: native query allocation is owned until freed below.
            if unsafe {
                WTSQuerySessionInformationW(HANDLE::default(), row.id, 5, &mut buffer, &mut bytes)
            } == 0
            {
                return Err(error("WTS username query"));
            }
            let name = (|| {
                if buffer.is_null() || !(2..=1024).contains(&bytes) || bytes % 2 != 0 {
                    return Err(error("WTS username bound"));
                }
                // SAFETY: query returned bytes checked above; UTF-16 buffer ends in NUL.
                let units =
                    unsafe { std::slice::from_raw_parts(buffer.cast::<u16>(), bytes as usize / 2) };
                if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
                    return Err(error("WTS username terminator"));
                }
                String::from_utf16(&units[..units.len() - 1])
                    .map_err(|e| GuestMsiExecutionError::Process(e.to_string()))
            })();
            // SAFETY: only this WTS query allocation is released.
            if !buffer.is_null() {
                unsafe { WTSFreeMemory(buffer) };
            }
            if name?.eq_ignore_ascii_case("AiwStandardUser") {
                matched += 1;
                if row.id != expected || row.state != 0 {
                    return Err(error("Another standard-user session exists"));
                }
            }
        }
        if matched != 1 {
            return Err(error("Unique signed-in standard user required"));
        }
        Ok(())
    })();
    // SAFETY: enumeration allocation remains owned until the loop completes.
    if !sessions.is_null() {
        unsafe { WTSFreeMemory(sessions.cast()) };
    }
    result
}
pub(crate) struct PrimaryInteractiveUser {
    token: OwnedHandle,
    environment: *mut c_void,
    context: StandardUserRuntimeContext,
    pub(crate) session: u32,
    pub(crate) authentication_id: String,
}
impl PrimaryInteractiveUser {
    /// Caller must enforce dedicated-VM/SYSTEM and controller-owned preparation.
    pub(crate) fn establish(
        expected_sid: &str,
        session: u32,
    ) -> Result<Self, GuestMsiExecutionError> {
        active_session(session)?;
        unique_user_session(session)?;
        let privilege = ScopedPrivileges::enable(&["SeTcbPrivilege"])?;
        let mut raw = HANDLE::default();
        // SAFETY: SYSTEM-scoped TCB privilege; token is immediately owned.
        let queried = unsafe { WTSQueryUserToken(session, &mut raw) };
        let query_error = error("WTS primary user token");
        drop(privilege);
        if queried == 0 {
            return Err(query_error);
        }
        // SAFETY: successful WTS query transferred one real handle.
        let token = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        let sid = validate_standard_token(raw)?;
        let (actual_session, authentication_id) = token_logon(raw)?;
        if sid != expected_sid || actual_session != session {
            return Err(error("Run-owned primary SID/session differs"));
        }
        let profile = user_profile_directory(raw)?;
        if !profile.eq_ignore_ascii_case(r"C:\Users\AiwStandardUser") {
            return Err(error("Fixed interactive profile differs"));
        }
        let mut environment = std::ptr::null_mut();
        // SAFETY: already logged-on primary user; never load/unload its profile.
        if unsafe { CreateEnvironmentBlock(&mut environment, raw, 0) } == 0 {
            return Err(error("Primary environment"));
        }
        let mut result = Self {
            token,
            environment,
            context: StandardUserRuntimeContext {
                user_sid: sid,
                profile_path: profile,
                roaming_app_data: String::new(),
                local_app_data: String::new(),
                administrators_enabled: false,
            },
            session,
            authentication_id,
        };
        let (profile, roaming, local) = environment_paths(result.environment)?;
        if !profile.eq_ignore_ascii_case(&result.context.profile_path) {
            return Err(error("Primary environment profile differs"));
        }
        result.context.roaming_app_data = roaming;
        result.context.local_app_data = local;
        result
            .context
            .validate()
            .map_err(GuestMsiExecutionError::Process)?;
        active_session(session)?;
        Ok(result)
    }
    pub(crate) fn token(&self) -> HANDLE {
        HANDLE(self.token.as_raw_handle())
    }
    #[cfg(feature = "research-msix-lifecycle")]
    pub(crate) fn token_handle(&self) -> &OwnedHandle {
        &self.token
    }
    pub(crate) fn environment(&self) -> *mut c_void {
        self.environment
    }
    pub(crate) fn context(&self) -> &StandardUserRuntimeContext {
        &self.context
    }
    pub(crate) fn validate_child(
        &self,
        process: &OwnedHandle,
    ) -> Result<(), GuestMsiExecutionError> {
        use windows::Win32::Security::TOKEN_QUERY;
        use windows::Win32::System::Threading::OpenProcessToken;
        let mut raw = HANDLE::default();
        // SAFETY: exact held suspended child; returned token is immediately owned.
        unsafe { OpenProcessToken(HANDLE(process.as_raw_handle()), TOKEN_QUERY, &mut raw) }
            .map_err(|e| GuestMsiExecutionError::Process(e.to_string()))?;
        // SAFETY: successful native call transferred the token handle.
        let _token = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        if validate_standard_token(raw)? != self.context.user_sid
            || token_logon(raw)? != (self.session, self.authentication_id.clone())
        {
            return Err(error("Suspended primary child token/logon differs"));
        }
        active_session(self.session)
    }
}
impl Drop for PrimaryInteractiveUser {
    fn drop(&mut self) {
        // SAFETY: this type exclusively owns the OS-created environment block.
        if !self.environment.is_null() {
            unsafe { DestroyEnvironmentBlock(self.environment) };
        }
    }
}
