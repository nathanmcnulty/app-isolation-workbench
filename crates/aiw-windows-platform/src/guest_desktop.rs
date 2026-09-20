//! Exact-SID GUI access inside the disposable worker. Grants live only until
//! that worker is disposed, like the freshly created account and profile.

use std::ffi::c_void;
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::{GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR, PSID};
use windows::core::{BOOL, PWSTR};

use crate::GuestMsiExecutionError;

const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const GRANT_ACCESS: u32 = 1;
const NO_INHERITANCE: u32 = 0;
const WINSTA_ENUMDESKTOPS: u32 = 0x0001;
const WINSTA_ENUMERATE: u32 = 0x0100;
const WINSTA_READATTRIBUTES: u32 = 0x0002;
const WINSTA_ACCESSCLIPBOARD: u32 = 0x0004;
const WINSTA_ACCESSGLOBALATOMS: u32 = 0x0020;
const DESKTOP_CREATEMENU: u32 = 0x0004;
const DESKTOP_CREATEWINDOW: u32 = 0x0002;
const DESKTOP_ENUMERATE: u32 = 0x0040;
const DESKTOP_READOBJECTS: u32 = 0x0001;
const DESKTOP_WRITEOBJECTS: u32 = 0x0080;

#[repr(C)]
struct Trustee {
    multiple_trustee: *mut c_void,
    multiple_operation: u32,
    form: u32,
    trustee_type: u32,
    name: *mut c_void,
}
#[repr(C)]
struct ExplicitAccess {
    access_permissions: u32,
    access_mode: u32,
    inheritance: u32,
    trustee: Trustee,
}
#[repr(C)]
struct AbsoluteSecurityDescriptor {
    revision: u8,
    sbz1: u8,
    control: u16,
    owner: *mut c_void,
    group: *mut c_void,
    sacl: *mut c_void,
    dacl: *mut c_void,
}

unsafe extern "system" {
    fn GetProcessWindowStation() -> HANDLE;
    fn GetThreadDesktop(thread_id: u32) -> HANDLE;
    fn GetCurrentThreadId() -> u32;
    fn GetUserObjectInformationW(
        object: HANDLE,
        index: i32,
        buffer: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
    fn GetUserObjectSecurity(
        object: HANDLE,
        requested: *mut u32,
        descriptor: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
    fn SetUserObjectSecurity(object: HANDLE, requested: *mut u32, descriptor: *const c_void)
    -> i32;
    fn ConvertStringSidToSidW(text: PWSTR, sid: *mut PSID) -> i32;
    fn SetEntriesInAclW(
        count: u32,
        entries: *const ExplicitAccess,
        old_acl: *mut c_void,
        new_acl: *mut *mut c_void,
    ) -> u32;
    fn InitializeSecurityDescriptor(
        descriptor: *mut AbsoluteSecurityDescriptor,
        revision: u32,
    ) -> i32;
    fn SetSecurityDescriptorDacl(
        descriptor: *mut AbsoluteSecurityDescriptor,
        present: i32,
        dacl: *mut c_void,
        defaulted: i32,
    ) -> i32;
    fn MakeSelfRelativeSD(
        absolute: *const AbsoluteSecurityDescriptor,
        relative: *mut c_void,
        length: *mut u32,
    ) -> i32;
}

#[link(name = "User32")]
unsafe extern "system" {}
#[link(name = "Advapi32")]
unsafe extern "system" {}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
    }
}

fn require_name(object: HANDLE, expected: &str) -> Result<(), GuestMsiExecutionError> {
    let mut name = [0u16; 128];
    let mut needed = 0;
    if object.is_invalid()
        || unsafe {
            GetUserObjectInformationW(
                object,
                2,
                name.as_mut_ptr().cast(),
                std::mem::size_of_val(&name) as u32,
                &mut needed,
            )
        } == 0
    {
        return Err(error("read current GUI object name"));
    }
    let end = name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| error("unterminated GUI object name"))?;
    if !String::from_utf16_lossy(&name[..end]).eq_ignore_ascii_case(expected) {
        return Err(GuestMsiExecutionError::Process(
            "guest GUI objects are not WinSta0/Default".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn grant_standard_user_desktop_access(
    user_sid: &str,
) -> Result<(), GuestMsiExecutionError> {
    let parts: Vec<_> = user_sid.split('-').collect();
    if parts.len() != 8
        || parts[..4] != ["S", "1", "5", "21"]
        || parts[4..].iter().any(|part| {
            part.parse::<u32>()
                .ok()
                .is_none_or(|number| number.to_string() != *part)
        })
    {
        return Err(GuestMsiExecutionError::Process(
            "desktop grant requires the validated local account SID".to_owned(),
        ));
    }
    let station = unsafe { GetProcessWindowStation() };
    let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
    require_name(station, "WinSta0")?;
    require_name(desktop, "Default")?;
    let mut text: Vec<u16> = user_sid.encode_utf16().chain(Some(0)).collect();
    let mut sid = PSID::default();
    if unsafe { ConvertStringSidToSidW(PWSTR(text.as_mut_ptr()), &mut sid) } == 0 {
        return Err(error("ConvertStringSidToSidW"));
    }
    let _sid = LocalAllocation(sid.0);
    let station_rights = WINSTA_ENUMDESKTOPS
        | WINSTA_ENUMERATE
        | WINSTA_READATTRIBUTES
        | WINSTA_ACCESSCLIPBOARD
        | WINSTA_ACCESSGLOBALATOMS;
    let desktop_rights = DESKTOP_CREATEMENU
        | DESKTOP_CREATEWINDOW
        | DESKTOP_ENUMERATE
        | DESKTOP_READOBJECTS
        | DESKTOP_WRITEOBJECTS;
    grant(station, sid, station_rights)?;
    grant(desktop, sid, desktop_rights)
}

fn read_descriptor(object: HANDLE) -> Result<Vec<usize>, GuestMsiExecutionError> {
    let mut info = DACL_SECURITY_INFORMATION;
    let mut needed = 0;
    let _ =
        unsafe { GetUserObjectSecurity(object, &mut info, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 || needed > 64 * 1024 {
        return Err(error("GetUserObjectSecurity size"));
    }
    let mut descriptor = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetUserObjectSecurity(
            object,
            &mut info,
            descriptor.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(error("GetUserObjectSecurity"));
    }
    Ok(descriptor)
}

fn merge_descriptor(
    descriptor: &mut [usize],
    sid: PSID,
    rights: u32,
) -> Result<Vec<usize>, GuestMsiExecutionError> {
    let mut present = BOOL(0);
    let mut defaulted = BOOL(0);
    let mut old_acl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast()),
            &mut present,
            &mut old_acl,
            &mut defaulted,
        )
    }
    .is_err()
        || !present.as_bool()
        || old_acl.is_null()
    {
        return Err(GuestMsiExecutionError::Process(
            "current desktop object has no explicit DACL".to_owned(),
        ));
    }
    let entry = ExplicitAccess {
        access_permissions: rights,
        access_mode: GRANT_ACCESS,
        inheritance: NO_INHERITANCE,
        trustee: Trustee {
            multiple_trustee: std::ptr::null_mut(),
            multiple_operation: 0,
            form: 0,
            trustee_type: 0,
            name: sid.0,
        },
    };
    let mut new_acl = std::ptr::null_mut();
    let status = unsafe { SetEntriesInAclW(1, &entry, old_acl.cast(), &mut new_acl) };
    if status != 0 || new_acl.is_null() {
        return Err(GuestMsiExecutionError::Process(format!(
            "SetEntriesInAclW failed: {status}"
        )));
    }
    let _acl = LocalAllocation(new_acl);
    let mut absolute = AbsoluteSecurityDescriptor {
        revision: 0,
        sbz1: 0,
        control: 0,
        owner: std::ptr::null_mut(),
        group: std::ptr::null_mut(),
        sacl: std::ptr::null_mut(),
        dacl: std::ptr::null_mut(),
    };
    if unsafe { InitializeSecurityDescriptor(&mut absolute, 1) } == 0
        || unsafe { SetSecurityDescriptorDacl(&mut absolute, 1, new_acl, 0) } == 0
    {
        return Err(error("initialize merged desktop DACL"));
    }
    let mut relative_size = 0;
    let _ = unsafe { MakeSelfRelativeSD(&absolute, std::ptr::null_mut(), &mut relative_size) };
    if relative_size == 0 || relative_size > 64 * 1024 {
        return Err(error("MakeSelfRelativeSD size"));
    }
    let mut relative =
        vec![0usize; (relative_size as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe { MakeSelfRelativeSD(&absolute, relative.as_mut_ptr().cast(), &mut relative_size) }
        == 0
    {
        return Err(error("MakeSelfRelativeSD"));
    }
    Ok(relative)
}

fn grant(object: HANDLE, sid: PSID, rights: u32) -> Result<(), GuestMsiExecutionError> {
    let mut descriptor = read_descriptor(object)?;
    let relative = merge_descriptor(&mut descriptor, sid, rights)?;
    if descriptor != read_descriptor(object)? {
        return Err(GuestMsiExecutionError::Process(
            "guest GUI DACL changed before grant".to_owned(),
        ));
    }
    let mut applied = DACL_SECURITY_INFORMATION;
    let applied_ok =
        unsafe { SetUserObjectSecurity(object, &mut applied, relative.as_ptr().cast()) };
    if applied_ok == 0 {
        return Err(error("SetUserObjectSecurity"));
    }
    Ok(())
}

fn error(operation: &str) -> GuestMsiExecutionError {
    GuestMsiExecutionError::Process(format!(
        "{operation} failed: {}",
        windows::core::Error::from_thread()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows::Win32::Security::{ACCESS_ALLOWED_ACE, GetAce};
    use windows::core::PCWSTR;

    #[test]
    fn merged_descriptor_preserves_existing_ace_and_grants_only_exact_sid_mask() {
        let sddl: Vec<u16> = "D:(A;;0x1;;;SY)".encode_utf16().chain(Some(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut size = 0;
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                1,
                &mut descriptor,
                Some(&mut size),
            )
        }
        .unwrap();
        let _descriptor = LocalAllocation(descriptor.0);
        let mut aligned = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        unsafe {
            std::ptr::copy_nonoverlapping(
                descriptor.0.cast::<u8>(),
                aligned.as_mut_ptr().cast::<u8>(),
                size as usize,
            )
        };
        let before = aligned.clone();
        let mut name: Vec<u16> = "S-1-5-21-1-2-3-1001"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut sid = PSID::default();
        assert_ne!(
            unsafe { ConvertStringSidToSidW(PWSTR(name.as_mut_ptr()), &mut sid) },
            0
        );
        let _sid = LocalAllocation(sid.0);
        let mut merged = merge_descriptor(&mut aligned, sid, 0xc7).unwrap();
        assert_eq!(aligned, before);
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut acl = std::ptr::null_mut();
        unsafe {
            GetSecurityDescriptorDacl(
                PSECURITY_DESCRIPTOR(merged.as_mut_ptr().cast()),
                &mut present,
                &mut acl,
                &mut defaulted,
            )
        }
        .unwrap();
        assert!(present.as_bool());
        assert!(!acl.is_null());
        assert_eq!(unsafe { (*acl).AceCount }, 2);
        let mut entries = Vec::new();
        for index in 0..2 {
            let mut ace = std::ptr::null_mut();
            unsafe { GetAce(acl, index, &mut ace) }.unwrap();
            let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
            let mut text = PWSTR::null();
            unsafe {
                ConvertSidToStringSidW(
                    PSID(std::ptr::addr_of!((*ace).SidStart).cast_mut().cast()),
                    &mut text,
                )
            }
            .unwrap();
            let _text = LocalAllocation(text.0.cast());
            entries.push((unsafe { text.to_string() }.unwrap(), unsafe { (*ace).Mask }));
        }
        entries.sort();
        assert_eq!(
            entries,
            vec![
                ("S-1-5-18".to_owned(), 1),
                ("S-1-5-21-1-2-3-1001".to_owned(), 0xc7)
            ]
        );
    }
}
