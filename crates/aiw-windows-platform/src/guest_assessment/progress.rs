//! Exact local mutation-access observations; signing implementation is separate.
pub(super) use super::authenticated::Progress;
use super::{COLLECTOR, Result, bound_error};
use aiw_provider_wsb::assessment_observation::*;
use std::{
    fs::OpenOptions,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
};
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
        },
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
        System::Threading::{GetCurrentThread, OpenThreadToken},
    },
    core::PWSTR,
};
const DIRECTORY_MASKS: [u32; 8] = [2, 4, 0x40, 0x10000, 0x10, 0x100, 0x40000, 0x80000];
const FILE_MASKS: [u32; 7] = [2, 4, 0x10, 0x100, 0x10000, 0x40000, 0x80000];
pub(super) fn effective_sid() -> Result<String> {
    let mut token = HANDLE::default();
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) }
        .map_err(|e| e.to_string())?;
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    let mut size = 0;
    let _ = unsafe {
        GetTokenInformation(HANDLE(token.as_raw_handle()), TokenUser, None, 0, &mut size)
    };
    if size == 0 || size > 65536 {
        return Err("effective token user bound refused".into());
    }
    let mut storage = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    let mut returned = 0;
    unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            size,
            &mut returned,
        )
    }
    .map_err(|e| e.to_string())?;
    if returned > size || returned < std::mem::size_of::<TOKEN_USER>() as u32 {
        return Err("effective token user shape refused".into());
    }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }.map_err(|e| e.to_string())?;
    let result = unsafe { text.to_string() }.map_err(|e| e.to_string());
    unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    result
}
/// Called only inside the fresh standard-user scoped impersonation. Opens
/// request individual mutation rights but never perform those mutations.
pub(super) fn probe_access(expected_sid: &str) -> Result<Vec<AssessmentCollectorAccessDenial>> {
    let effective = effective_sid()?;
    if effective != expected_sid {
        return Err("collector access probe effective user differs".into());
    }
    let mut facts = vec![];
    let progress_path = super::local_progress();
    for (target, masks, path) in [
        (
            AssessmentCollectorTarget::Directory,
            DIRECTORY_MASKS.as_slice(),
            std::path::Path::new(COLLECTOR),
        ),
        (
            AssessmentCollectorTarget::ProgressFile,
            FILE_MASKS.as_slice(),
            progress_path.as_path(),
        ),
    ] {
        for &mask in masks {
            let opened = OpenOptions::new()
                .access_mode(mask)
                .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(path);
            let (code, denied, error) = match opened {
                Ok(_) => (Some(0), Some(false), None),
                Err(error) if error.raw_os_error() == Some(5) => (Some(5), Some(true), None),
                Err(error) => (
                    error.raw_os_error().and_then(|c| u32::try_from(c).ok()),
                    None,
                    Some(bound_error(&error.to_string())),
                ),
            };
            facts.push(AssessmentCollectorAccessDenial {
                effective_user_sid: effective.clone(),
                target,
                access_mask: mask,
                native_code: code,
                denied,
                error,
            });
        }
    }
    Ok(facts)
}
pub(super) fn derive_denial(facts: &[AssessmentCollectorAccessDenial], sid: &str) -> Option<bool> {
    if facts.iter().any(|f| {
        f.effective_user_sid == sid
            && f.denied == Some(false)
            && f.native_code == Some(0)
            && f.error.is_none()
    }) {
        return Some(false);
    }
    let expected = DIRECTORY_MASKS
        .iter()
        .map(|m| (AssessmentCollectorTarget::Directory, *m))
        .chain(
            FILE_MASKS
                .iter()
                .map(|m| (AssessmentCollectorTarget::ProgressFile, *m)),
        );
    if facts.len() != 15 {
        return None;
    }
    if facts.iter().zip(expected).all(|(f, (target, mask))| {
        f.effective_user_sid == sid
            && f.target == target
            && f.access_mask == mask
            && f.native_code == Some(5)
            && f.denied == Some(true)
            && f.error.is_none()
    }) {
        Some(true)
    } else {
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn facts() -> Vec<AssessmentCollectorAccessDenial> {
        DIRECTORY_MASKS
            .iter()
            .map(|m| (AssessmentCollectorTarget::Directory, *m))
            .chain(
                FILE_MASKS
                    .iter()
                    .map(|m| (AssessmentCollectorTarget::ProgressFile, *m)),
            )
            .map(|(target, mask)| AssessmentCollectorAccessDenial {
                effective_user_sid: "synthetic".into(),
                target,
                access_mask: mask,
                native_code: Some(5),
                denied: Some(true),
                error: None,
            })
            .collect()
    }
    #[test]
    fn all_individual_rights_and_exact_actor_are_required() {
        let mut f = facts();
        assert_eq!(derive_denial(&f, "synthetic"), Some(true));
        for index in 0..15 {
            let mut changed = f.clone();
            changed[index].access_mask = 0x40000000;
            assert_ne!(derive_denial(&changed, "synthetic"), Some(true));
            changed = f.clone();
            changed[index].effective_user_sid = "foreign".into();
            assert_ne!(derive_denial(&changed, "synthetic"), Some(true));
        }
        f.pop();
        assert_eq!(derive_denial(&f, "synthetic"), None);
    }
    #[test]
    fn sharing_or_unknown_is_not_access_denial_and_actual_allow_remains_false() {
        let mut f = facts();
        f[0].native_code = Some(32);
        f[0].denied = None;
        f[0].error = Some("sharing violation".into());
        assert_eq!(derive_denial(&f, "synthetic"), None);
        f[1].native_code = Some(0);
        f[1].denied = Some(false);
        assert_eq!(derive_denial(&f, "synthetic"), Some(false));
    }
}
