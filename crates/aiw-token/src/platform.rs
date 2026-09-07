use std::ffi::c_void;
use std::mem::{MaybeUninit, size_of};
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
use std::slice;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, PSID,
    SECURITY_IMPERSONATION_LEVEL, SID_AND_ATTRIBUTES, SecurityAnonymous, SecurityDelegation,
    SecurityIdentification, SecurityImpersonation, TOKEN_APPCONTAINER_INFORMATION, TOKEN_ELEVATION,
    TOKEN_ELEVATION_TYPE, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_TYPE, TOKEN_USER,
    TokenAppContainerSid, TokenCapabilities, TokenElevation, TokenElevationType,
    TokenElevationTypeDefault, TokenElevationTypeFull, TokenElevationTypeLimited,
    TokenImpersonation, TokenImpersonationLevel, TokenIntegrityLevel, TokenIsAppContainer,
    TokenPrimary, TokenRestrictedSids, TokenType as TokenTypeClass, TokenUser,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessId, OpenProcessToken,
};
use windows::core::PWSTR;

use super::{
    ElevationType, ImpersonationLevel, IntegrityEvidence, SidAndAttributes,
    TOKEN_EVIDENCE_SCHEMA_VERSION, TokenEvidence, TokenEvidenceError, TokenType,
    classify_integrity_rid,
};

pub(super) fn collect_current_process_token() -> Result<TokenEvidence, TokenEvidenceError> {
    // SAFETY: GetCurrentProcessId has no preconditions. GetCurrentProcess is
    // the documented current-process pseudo-handle accepted by OpenProcessToken.
    collect_token_for_process(unsafe { GetCurrentProcess() }, unsafe {
        GetCurrentProcessId()
    })
}

pub(super) fn collect_process_token(
    process: BorrowedHandle<'_>,
) -> Result<TokenEvidence, TokenEvidenceError> {
    let process = HANDLE(process.as_raw_handle());
    // SAFETY: A BorrowedHandle supplies a live Windows handle for this call.
    // GetProcessId only observes that same handle and returns zero for a
    // handle that does not identify a process.
    let process_id = unsafe { GetProcessId(process) };
    if process_id == 0 {
        return Err(api_error(
            "GetProcessId",
            windows::core::Error::from_thread(),
        ));
    }
    collect_token_for_process(process, process_id)
}

fn collect_token_for_process(
    process: HANDLE,
    process_id: u32,
) -> Result<TokenEvidence, TokenEvidenceError> {
    let token = OwnedHandle::process_token(process)?;
    let raw_token_type: TOKEN_TYPE = query_fixed(token.0, TokenTypeClass, "TokenType")?;
    let token_type = map_token_type(raw_token_type)?;
    let impersonation_level = if token_type == TokenType::Impersonation {
        let raw: SECURITY_IMPERSONATION_LEVEL =
            query_fixed(token.0, TokenImpersonationLevel, "TokenImpersonationLevel")?;
        Some(map_impersonation_level(raw)?)
    } else {
        None
    };

    let is_app_container =
        query_fixed::<u32>(token.0, TokenIsAppContainer, "TokenIsAppContainer")? != 0;

    let app_container = query_buffer(token.0, TokenAppContainerSid, "TokenAppContainerSid")?;
    let app_container_info =
        app_container.cast::<TOKEN_APPCONTAINER_INFORMATION>("TokenAppContainerSid")?;
    let app_container_sid = if app_container_info.TokenAppContainer.0.is_null() {
        None
    } else {
        Some(sid_to_string(app_container_info.TokenAppContainer)?)
    };

    if is_app_container != app_container_sid.is_some() {
        return Err(TokenEvidenceError::MalformedTokenData {
            operation: "TokenAppContainerSid",
            detail: "TokenIsAppContainer and TokenAppContainerSid disagree",
        });
    }

    let user = query_buffer(token.0, TokenUser, "TokenUser")?;
    let user = user.cast::<TOKEN_USER>("TokenUser")?;
    let user_sid = sid_to_string(user.User.Sid)?;

    let integrity = query_buffer(token.0, TokenIntegrityLevel, "TokenIntegrityLevel")?;
    let integrity = integrity.cast::<TOKEN_MANDATORY_LABEL>("TokenIntegrityLevel")?;
    let integrity_sid = integrity.Label.Sid;
    let integrity_rid = sid_last_sub_authority(integrity_sid)?;

    let raw_elevation_type: TOKEN_ELEVATION_TYPE =
        query_fixed(token.0, TokenElevationType, "TokenElevationType")?;
    let elevation_type = map_elevation_type(raw_elevation_type)?;
    let elevation: TOKEN_ELEVATION = query_fixed(token.0, TokenElevation, "TokenElevation")?;

    let capabilities = query_groups(token.0, TokenCapabilities, "TokenCapabilities")?;
    let restricted_sid_count =
        query_group_count(token.0, TokenRestrictedSids, "TokenRestrictedSids")?;

    // This evidence is bound to the exact process handle the caller retained.
    // It does not infer a token from a PID or from the launcher/config.
    Ok(TokenEvidence {
        schema_version: TOKEN_EVIDENCE_SCHEMA_VERSION.to_owned(),
        process_id,
        token_type,
        impersonation_level,
        is_app_container,
        app_container_sid,
        user_sid,
        integrity: IntegrityEvidence {
            sid: sid_to_string(integrity_sid)?,
            rid: integrity_rid,
            level: classify_integrity_rid(integrity_rid),
        },
        elevation_type,
        is_elevated: elevation.TokenIsElevated != 0,
        capabilities,
        restricted_sid_count,
    })
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn process_token(process: HANDLE) -> Result<Self, TokenEvidenceError> {
        let mut token = HANDLE::default();
        // SAFETY: `process` is either the documented current-process pseudo-
        // handle or a caller-owned borrowed process handle. The output pointer
        // is valid, and TOKEN_QUERY is the minimum required access.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
            .map_err(|error| api_error("OpenProcessToken", error))?;
        Ok(Self(token))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the real token handle returned above.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct AlignedBuffer {
    words: Vec<usize>,
    byte_len: usize,
}

impl AlignedBuffer {
    fn new(byte_len: u32) -> Result<Self, TokenEvidenceError> {
        let byte_len =
            usize::try_from(byte_len).map_err(|_| TokenEvidenceError::MalformedTokenData {
                operation: "GetTokenInformation",
                detail: "required buffer length does not fit usize",
            })?;
        let word_count = byte_len.div_ceil(size_of::<usize>());
        Ok(Self {
            words: vec![0; word_count],
            byte_len,
        })
    }

    fn as_mut_void(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }

    fn cast<T>(&self, operation: &'static str) -> Result<&T, TokenEvidenceError> {
        if self.byte_len < size_of::<T>() {
            return Err(TokenEvidenceError::MalformedTokenData {
                operation,
                detail: "buffer is smaller than the expected structure",
            });
        }
        // SAFETY: Vec<usize> provides sufficient alignment, the buffer length
        // was validated, and GetTokenInformation initialized the structure.
        Ok(unsafe { &*self.words.as_ptr().cast::<T>() })
    }
}

fn query_buffer(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    operation: &'static str,
) -> Result<AlignedBuffer, TokenEvidenceError> {
    let mut required = 0_u32;
    // SAFETY: A null first buffer is the documented size-query pattern.
    let first = unsafe { GetTokenInformation(token, class, None, 0, &mut required) };
    if required == 0 {
        return Err(first.map_or_else(
            |error| api_error(operation, error),
            |_| TokenEvidenceError::MalformedTokenData {
                operation,
                detail: "size query unexpectedly returned zero bytes",
            },
        ));
    }

    let mut buffer = AlignedBuffer::new(required)?;
    let mut written = required;
    // SAFETY: The allocated buffer is writable for `required` bytes.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buffer.as_mut_void()),
            required,
            &mut written,
        )
    }
    .map_err(|error| api_error(operation, error))?;
    if written > required {
        return Err(TokenEvidenceError::MalformedTokenData {
            operation,
            detail: "API reported more bytes than the supplied buffer",
        });
    }
    buffer.byte_len = usize::try_from(written).unwrap_or(buffer.byte_len);
    Ok(buffer)
}

trait FixedTokenInformation: Copy {}

impl FixedTokenInformation for u32 {}
impl FixedTokenInformation for TOKEN_TYPE {}
impl FixedTokenInformation for SECURITY_IMPERSONATION_LEVEL {}
impl FixedTokenInformation for TOKEN_ELEVATION_TYPE {}
impl FixedTokenInformation for TOKEN_ELEVATION {}

fn query_fixed<T: FixedTokenInformation>(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    operation: &'static str,
) -> Result<T, TokenEvidenceError> {
    let size =
        u32::try_from(size_of::<T>()).map_err(|_| TokenEvidenceError::MalformedTokenData {
            operation,
            detail: "fixed structure is too large",
        })?;
    let mut value = MaybeUninit::<T>::uninit();
    let mut written = 0_u32;
    // SAFETY: `value` is writable for exactly `size_of::<T>()` bytes. The value
    // is only assumed initialized after the API reports success and exact size.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(value.as_mut_ptr().cast()),
            size,
            &mut written,
        )
    }
    .map_err(|error| api_error(operation, error))?;
    if written != size {
        return Err(TokenEvidenceError::MalformedTokenData {
            operation,
            detail: "API returned an unexpected fixed-structure size",
        });
    }
    // SAFETY: Successful GetTokenInformation initialized exactly `size` bytes.
    Ok(unsafe { value.assume_init() })
}

fn query_group_count(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    operation: &'static str,
) -> Result<u32, TokenEvidenceError> {
    let groups = query_buffer(token, class, operation)?;
    group_count(&groups, operation)
}

fn query_groups(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    operation: &'static str,
) -> Result<Vec<SidAndAttributes>, TokenEvidenceError> {
    let buffer = query_buffer(token, class, operation)?;
    let count = usize::try_from(group_count(&buffer, operation)?).map_err(|_| {
        TokenEvidenceError::MalformedTokenData {
            operation,
            detail: "group count does not fit usize",
        }
    })?;
    if count == 0 {
        return Ok(Vec::new());
    }
    let groups = buffer.cast::<TOKEN_GROUPS>(operation)?;
    let group_array_offset = size_of::<TOKEN_GROUPS>() - size_of::<SID_AND_ATTRIBUTES>();
    let minimum = group_array_offset
        .checked_add(count.checked_mul(size_of::<SID_AND_ATTRIBUTES>()).ok_or(
            TokenEvidenceError::MalformedTokenData {
                operation,
                detail: "group count overflowed buffer calculation",
            },
        )?)
        .ok_or(TokenEvidenceError::MalformedTokenData {
            operation,
            detail: "group buffer length overflowed",
        })?;
    if buffer.byte_len < minimum {
        return Err(TokenEvidenceError::MalformedTokenData {
            operation,
            detail: "group count exceeds the returned buffer",
        });
    }

    // SAFETY: The count was checked against the returned allocation. `Groups`
    // is the documented flexible-array start in TOKEN_GROUPS.
    let raw_groups = unsafe { slice::from_raw_parts(groups.Groups.as_ptr(), count) };
    let mut result = raw_groups
        .iter()
        .map(|entry| {
            Ok(SidAndAttributes {
                sid: sid_to_string(entry.Sid)?,
                attributes: entry.Attributes,
            })
        })
        .collect::<Result<Vec<_>, TokenEvidenceError>>()?;
    result.sort();
    Ok(result)
}

fn group_count(buffer: &AlignedBuffer, operation: &'static str) -> Result<u32, TokenEvidenceError> {
    if buffer.byte_len < size_of::<u32>() {
        return Err(TokenEvidenceError::MalformedTokenData {
            operation,
            detail: "group buffer does not contain a count",
        });
    }
    // SAFETY: AlignedBuffer is usize-aligned and contains at least four bytes.
    Ok(unsafe { *buffer.words.as_ptr().cast::<u32>() })
}

fn sid_to_string(sid: PSID) -> Result<String, TokenEvidenceError> {
    if sid.0.is_null() {
        return Err(TokenEvidenceError::MalformedTokenData {
            operation: "ConvertSidToStringSidW",
            detail: "SID pointer was null",
        });
    }

    let mut output = PWSTR::null();
    // SAFETY: The SID originates in a successful token query and output points
    // to a writable PWSTR that LocalFree releases below.
    unsafe { ConvertSidToStringSidW(sid, &mut output) }
        .map_err(|error| api_error("ConvertSidToStringSidW", error))?;
    // SAFETY: ConvertSidToStringSidW returned a valid NUL-terminated string.
    let text = unsafe { output.to_string() }.map_err(|error| TokenEvidenceError::WindowsApi {
        operation: "PWSTR::to_string",
        message: error.to_string(),
    });
    // SAFETY: This allocation is documented as requiring LocalFree.
    let _ = unsafe { LocalFree(Some(HLOCAL(output.0.cast()))) };
    text
}

fn sid_last_sub_authority(sid: PSID) -> Result<u32, TokenEvidenceError> {
    // SAFETY: The SID originates in a successful token query.
    let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
    if count_ptr.is_null() {
        return Err(TokenEvidenceError::MalformedTokenData {
            operation: "GetSidSubAuthorityCount",
            detail: "API returned a null count pointer",
        });
    }
    // SAFETY: `count_ptr` points into the validated SID.
    let count = unsafe { *count_ptr };
    if count == 0 {
        return Err(TokenEvidenceError::MalformedTokenData {
            operation: "GetSidSubAuthority",
            detail: "SID has no sub-authorities",
        });
    }
    // SAFETY: `count - 1` is within the SID's sub-authority array.
    let rid_ptr = unsafe { GetSidSubAuthority(sid, u32::from(count - 1)) };
    if rid_ptr.is_null() {
        return Err(TokenEvidenceError::MalformedTokenData {
            operation: "GetSidSubAuthority",
            detail: "API returned a null RID pointer",
        });
    }
    // SAFETY: `rid_ptr` points into the validated SID.
    Ok(unsafe { *rid_ptr })
}

fn map_token_type(value: TOKEN_TYPE) -> Result<TokenType, TokenEvidenceError> {
    if value == TokenPrimary {
        Ok(TokenType::Primary)
    } else if value == TokenImpersonation {
        Ok(TokenType::Impersonation)
    } else {
        Err(TokenEvidenceError::MalformedTokenData {
            operation: "TokenType",
            detail: "unknown TOKEN_TYPE value",
        })
    }
}

fn map_impersonation_level(
    value: SECURITY_IMPERSONATION_LEVEL,
) -> Result<ImpersonationLevel, TokenEvidenceError> {
    if value == SecurityAnonymous {
        Ok(ImpersonationLevel::Anonymous)
    } else if value == SecurityIdentification {
        Ok(ImpersonationLevel::Identification)
    } else if value == SecurityImpersonation {
        Ok(ImpersonationLevel::Impersonation)
    } else if value == SecurityDelegation {
        Ok(ImpersonationLevel::Delegation)
    } else {
        Err(TokenEvidenceError::MalformedTokenData {
            operation: "TokenImpersonationLevel",
            detail: "unknown SECURITY_IMPERSONATION_LEVEL value",
        })
    }
}

fn map_elevation_type(value: TOKEN_ELEVATION_TYPE) -> Result<ElevationType, TokenEvidenceError> {
    if value == TokenElevationTypeDefault {
        Ok(ElevationType::Default)
    } else if value == TokenElevationTypeFull {
        Ok(ElevationType::Full)
    } else if value == TokenElevationTypeLimited {
        Ok(ElevationType::Limited)
    } else {
        Err(TokenEvidenceError::MalformedTokenData {
            operation: "TokenElevationType",
            detail: "unknown TOKEN_ELEVATION_TYPE value",
        })
    }
}

fn api_error(operation: &'static str, error: windows::core::Error) -> TokenEvidenceError {
    TokenEvidenceError::WindowsApi {
        operation,
        message: error.to_string(),
    }
}
