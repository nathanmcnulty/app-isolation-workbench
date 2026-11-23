//! Query-only Classic launch diagnostics. No repair and no alternate dispatch.
use super::Result;
use crate::{GuestMsiExecutionError, guest_standard_user::StandardUserSession};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::OpenOptions,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::Path,
};
use windows::{
    Win32::{
        Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT},
        Security::Isolation::GetAppContainerFolderPath,
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
        System::Com::CoTaskMemFree,
    },
    core::{PCWSTR, PWSTR},
};

struct FolderString(PWSTR);
impl Drop for FolderString {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(Some(self.0.0.cast())) };
    }
}

// Only the owned user's Packages subtree is opened. A lookup for another
// identity is still recorded by HRESULT/path hash, without traversing it.
fn owned_folder(path: &Path, local: &Path) -> bool {
    let Some(path) = path.to_str() else {
        return false;
    };
    let Some(local) = local.to_str() else {
        return false;
    };
    let prefix = format!("{}\\Packages\\", local.trim_end_matches('\\'));
    path.starts_with("C:\\")
        && !path[2..].contains(':')
        && !path.contains('/')
        && path.split('\\').all(|p| p != "." && p != "..")
        && path
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase())
}

fn access(path: &Path, mask: u32, directory: bool) -> Result<String> {
    let file = match OpenOptions::new()
        .access_mode(mask)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
    {
        Ok(file) => file,
        Err(e) => return Ok(format!("e{}", e.raw_os_error().unwrap_or(-1))),
    };
    let mut flags = 0;
    unsafe { GetHandleInformation(HANDLE(file.as_raw_handle()), &mut flags) }
        .map_err(|e| format!("launch diagnostic handle custody: {e}"))?;
    if flags & HANDLE_FLAG_INHERIT.0 != 0 {
        return Err("launch diagnostic handle unexpectedly inheritable".into());
    }
    let info = match file.metadata() {
        Ok(info) => info,
        Err(e) => return Ok(format!("m{}", e.raw_os_error().unwrap_or(-1))),
    };
    if info.file_attributes() & 0x400 != 0 || info.is_dir() != directory {
        return Ok("kind".into());
    }
    let info = crate::guest_document::file_information(&file)?;
    let v = info.dwVolumeSerialNumber;
    let i = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    if v == 0 || i == 0 {
        return Ok("id".into());
    }
    Ok(format!("ok{v:08x}:{i:016x}"))
}

fn facts(sid: &[u16], image: &Path, cwd: &Path, local: &Path) -> Result<String> {
    let folder = match unsafe { GetAppContainerFolderPath(PCWSTR(sid.as_ptr())) } {
        Err(e) => format!("h{:08x}", e.code().0 as u32),
        Ok(value) => {
            let value = FolderString(value);
            if value.0.is_null() {
                "null".into()
            } else {
                let mut units = Vec::new();
                // API-owned nul-terminated string; stop reading at its nul.
                for offset in 0..1024 {
                    let unit = unsafe { *value.0.0.add(offset) };
                    if unit == 0 {
                        break;
                    }
                    units.push(unit);
                }
                if units.len() == 1024 {
                    "bound".into()
                } else {
                    let hash = hex::encode(Sha256::digest(
                        units
                            .iter()
                            .flat_map(|u| u.to_le_bytes())
                            .collect::<Vec<_>>(),
                    ));
                    let path = OsString::from_wide(&units);
                    let path = Path::new(&path);
                    let opened = if owned_folder(path, local) {
                        // Ancestors are held without reparse traversal before opening leaf.
                        match super::files::Directories::hold(path) {
                            Ok(_held) => access(path, 0xa0, true)?,
                            Err(_) => "unheld".into(),
                        }
                    } else {
                        "outside".into()
                    };
                    format!("h00000000:{hash}:{opened}")
                }
            }
        }
    };
    Ok(format!(
        "f={folder},i={},d={}",
        access(image, 0xa1, false)?,
        access(cwd, 0xa0, true)?
    ))
}

pub(super) fn capture(
    user: &StandardUserSession,
    sid: &str,
    image: &Path,
    cwd: &Path,
) -> Result<String> {
    let sid: Vec<u16> = std::ffi::OsStr::new(sid)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let collector = facts(&sid, image, cwd, user.local_app_data())?;
    let standard = user
        .impersonate(|| {
            let actual =
                super::progress::effective_sid().map_err(GuestMsiExecutionError::Process)?;
            if actual != user.context().user_sid {
                return Err(GuestMsiExecutionError::Process(
                    "launch diagnostic standard identity differs".into(),
                ));
            }
            facts(&sid, image, cwd, user.local_app_data()).map_err(GuestMsiExecutionError::Process)
        })
        .map_err(|e| e.to_string())?;
    let result = format!("ctx1[C:{collector};U:{standard}]");
    if !result.is_ascii() || result.len() > 512 {
        return Err("launch diagnostic encoding/bound refused".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn folder_scope_rejects_aliases_and_siblings() {
        let local = Path::new(r"C:\Users\owned\AppData\Local");
        assert!(owned_folder(
            Path::new(r"C:\Users\owned\AppData\Local\Packages\app\LocalState"),
            local
        ));
        for path in [
            r"C:\Users\other\AppData\Local\Packages\app",
            r"C:\Users\owned\AppData\Local\Packages\..\secret",
            r"C:\Users\owned\AppData\Local\Packages\app:stream",
            r"\\?\C:\Users\owned\AppData\Local\Packages\app",
        ] {
            assert!(!owned_folder(Path::new(path), local));
        }
    }
    #[test]
    fn read_execute_query_uses_noninheritable_handles() {
        let image = std::env::current_exe().unwrap();
        assert!(access(&image, 0xa1, false).unwrap().starts_with("ok"));
        assert!(
            access(image.parent().unwrap(), 0xa0, true)
                .unwrap()
                .starts_with("ok")
        );
    }
}
