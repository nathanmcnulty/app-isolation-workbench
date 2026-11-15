//! One fixed receipt-bound progress stream. No app owns its writer or handle.
use super::{COLLECTOR, Result, bound_error, files::Directories};
use crate::guest_document as relative;
use aiw_provider_wsb::{
    assessment_observation::*, assessment_request::ApplicationAssessmentGuestRequest,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::windows::{
        fs::{FileExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
};
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileType,
        },
        System::Threading::{GetCurrentThread, OpenThreadToken},
    },
    core::PWSTR,
};
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORD: usize = 8 * 1024 * 1024;
const DIRECTORY_MASKS: [u32; 8] = [2, 4, 0x40, 0x10000, 0x10, 0x100, 0x40000, 0x80000];
const FILE_MASKS: [u32; 7] = [2, 4, 0x10, 0x100, 0x10000, 0x40000, 0x80000];
pub(super) struct Progress {
    _directories: Directories,
    file: Option<File>,
    identity: BY_HANDLE_FILE_INFORMATION,
    bytes: u64,
    digest: Sha256,
    refused: bool,
}
fn same_identity(a: &BY_HANDLE_FILE_INFORMATION, b: &BY_HANDLE_FILE_INFORMATION) -> bool {
    a.dwVolumeSerialNumber == b.dwVolumeSerialNumber
        && a.nFileIndexHigh == b.nFileIndexHigh
        && a.nFileIndexLow == b.nFileIndexLow
}
fn checked_file(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let info = relative::file_information(file)?;
    if !relative::ordinary_file(&info)
        || info.nNumberOfLinks != 1
        || info.dwVolumeSerialNumber == 0
        || (info.nFileIndexHigh == 0 && info.nFileIndexLow == 0)
        || unsafe { GetFileType(HANDLE(file.as_raw_handle())) } != FILE_TYPE_DISK
    {
        return Err("progress file type/link/identity refused".into());
    }
    Ok(info)
}
impl Progress {
    pub(super) fn create(
        request: &ApplicationAssessmentGuestRequest,
        token: aiw_token::TokenEvidence,
    ) -> Result<Self> {
        let directories = Directories::collector_probe()?;
        if std::fs::read_dir(COLLECTOR)
            .map_err(|e| e.to_string())?
            .next()
            .transpose()
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("collector Output is not initially empty; no progress adoption".into());
        }
        // Wide sharing exists ONLY before any untrusted app is launched, so
        // access probes measure DACL decisions, never our own sharing denial.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(ASSESSMENT_PROGRESS_PATH)
            .map_err(|e| e.to_string())?;
        let identity = checked_file(&file)?;
        let mut value = Self {
            _directories: directories,
            file: Some(file),
            identity,
            bytes: 0,
            digest: Sha256::new(),
            refused: false,
        };
        value.record(&AssessmentProgressEvent::Header {
            schema_version: ASSESSMENT_PROGRESS_SCHEMA.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            assessment_sha256: request.assessment_sha256.clone(),
            agent_sha256: request.agent_sha256.clone(),
            config_sha256: request.config_sha256.clone(),
            project_revision_sha256: request.project_revision_sha256.clone(),
            collector_token: token,
        })?;
        Ok(value)
    }
    pub(super) fn record(&mut self, event: &AssessmentProgressEvent) -> Result<()> {
        super::guard_no_impersonation()?;
        if self.refused {
            return Err("progress writer already refused; original prefix retained".into());
        }
        let encoded = serde_json::to_vec(event).map_err(|e| e.to_string())?;
        if encoded.len() > MAX_RECORD
            || self
                .bytes
                .checked_add(encoded.len() as u64 + 1)
                .is_none_or(|n| n > MAX_BYTES)
        {
            self.refused = true;
            return Err(
                "complete progress record/aggregate exceeds bound; original prefix retained".into(),
            );
        }
        let file = self.file.as_mut().ok_or("progress writer not held")?;
        let info = checked_file(file)?;
        if !same_identity(&info, &self.identity) || relative::file_length(&info) != self.bytes {
            self.refused = true;
            return Err("held progress identity/length changed".into());
        }
        let operation = file
            .write_all(&encoded)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all());
        if let Err(error) = operation {
            self.refused = true;
            return Err(format!(
                "progress publication failed; retained prefix may end mid-record: {error}"
            ));
        }
        self.digest.update(&encoded);
        self.digest.update(b"\n");
        self.bytes += encoded.len() as u64 + 1;
        Ok(())
    }
    fn verify(&self, file: &File) -> Result<()> {
        let info = checked_file(file)?;
        if !same_identity(&info, &self.identity) || relative::file_length(&info) != self.bytes {
            return Err("progress named/held identity or size differs".into());
        }
        let mut digest = Sha256::new();
        let mut position = 0;
        let mut buffer = [0u8; 65536];
        while position < self.bytes {
            let amount = (self.bytes - position).min(buffer.len() as u64) as usize;
            let count = file
                .seek_read(&mut buffer[..amount], position)
                .map_err(|e| e.to_string())?;
            if count == 0 {
                return Err("progress truncated".into());
            }
            digest.update(&buffer[..count]);
            position += count as u64;
        }
        if digest.finalize() != self.digest.clone().finalize() {
            return Err("progress byte prefix changed".into());
        }
        Ok(())
    }
    pub(super) fn seal_before_apps(&mut self) -> Result<()> {
        super::guard_no_impersonation()?;
        let previous = self.file.take().ok_or("progress writer missing")?;
        self.verify(&previous)?;
        drop(previous);
        // No untrusted account process exists yet. Close/reopen is necessary:
        // a read-sharing-only handle cannot coexist with our old wide writer.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(ASSESSMENT_PROGRESS_PATH)
            .map_err(|e| e.to_string())?;
        self.verify(&file)?;
        file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        self.file = Some(file);
        let narrow = Directories::hold(Path::new(COLLECTOR))?;
        if !self._directories.same_leaf(&narrow)? {
            return Err("collector directory identity changed during access checks".into());
        }
        self._directories = narrow;
        Ok(())
    }
    pub(super) fn revalidate(&self) -> Result<()> {
        self.verify(self.file.as_ref().ok_or("progress writer missing")?)
    }
}
fn effective_sid() -> Result<String> {
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
    for (target, masks, path) in [
        (
            AssessmentCollectorTarget::Directory,
            DIRECTORY_MASKS.as_slice(),
            COLLECTOR,
        ),
        (
            AssessmentCollectorTarget::ProgressFile,
            FILE_MASKS.as_slice(),
            ASSESSMENT_PROGRESS_PATH,
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
