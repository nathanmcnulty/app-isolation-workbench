//! Read-only, held-handle identity for untrusted application source files.
//!
//! This primitive does not execute, copy, trust, or authorize the source. It
//! holds the exact ordinary local file without write/delete sharing while its
//! identity, stream policy, size, and content hash are observed.

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use aiw_probe::WindowsFileIdentity;
use thiserror::Error;
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_READ, READ_CONTROL, SYNCHRONIZE,
};

use crate::exact_dispose::{
    basic_info, file_size, hash_file, stable_id, standard_info, verify_stream_policy,
};
use crate::workspace::{final_path, is_fixed_volume, same_path, verify_local_acl_volume};

const MAX_SOURCE_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const FORBIDDEN_SOURCE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_REPARSE_POINT.0
    | FILE_ATTRIBUTE_DIRECTORY.0
    | FILE_ATTRIBUTE_DEVICE.0
    | FILE_ATTRIBUTE_OFFLINE.0
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS.0
    | FILE_ATTRIBUTE_RECALL_ON_OPEN.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFileObservation {
    pub canonical_path: String,
    pub identity: WindowsFileIdentity,
    pub attributes: u32,
    pub size_bytes: u64,
    pub sha256: String,
    pub link_count: u32,
    pub only_unnamed_data_stream: bool,
}

#[derive(Debug)]
pub struct HeldApplicationFile {
    file: File,
    source_path: PathBuf,
    observation: SourceFileObservation,
}

#[derive(Debug, Error)]
pub enum SourceInspectionError {
    #[error("application source path is invalid: {0}")]
    InvalidPath(String),
    #[error("application source is not an ordinary single-link file")]
    InvalidShape,
    #[error("application source stream policy could not be verified: {0}")]
    StreamPolicy(String),
    #[error("application source exceeds the fixed size bound")]
    BoundsExceeded,
    #[error("application source identity or content changed during observation")]
    Drift,
    #[error("application source is currently open for modification")]
    Busy,
    #[error("native application source observation failed: {0}")]
    Native(String),
}

impl HeldApplicationFile {
    pub fn open(path: &Path) -> Result<Self, SourceInspectionError> {
        if !path.is_absolute() || path.as_os_str().is_empty() {
            return Err(SourceInspectionError::InvalidPath(
                "path must be absolute and nonempty".to_owned(),
            ));
        }
        let file = OpenOptions::new()
            .access_mode(
                FILE_READ_DATA.0
                    | FILE_READ_ATTRIBUTES.0
                    | FILE_READ_EA.0
                    | READ_CONTROL.0
                    | SYNCHRONIZE.0,
            )
            // New write/delete opens are incompatible while this evidence
            // handle is retained. Existing incompatible handles block entry.
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)
            .map_err(open_error)?;
        verify_local_acl_volume(&file).map_err(native)?;
        let held_path = final_path(&file).map_err(native)?;
        if !is_fixed_volume(&held_path).map_err(native)? {
            return Err(SourceInspectionError::InvalidPath(
                "opened source is not on a fixed volume".to_owned(),
            ));
        }
        let observation = observe(&file, &held_path)?;
        Ok(Self {
            file,
            source_path: held_path,
            observation,
        })
    }

    #[must_use]
    pub fn observation(&self) -> &SourceFileObservation {
        &self.observation
    }

    pub fn revalidate(&self) -> Result<(), SourceInspectionError> {
        let current_path = final_path(&self.file).map_err(native)?;
        if !same_path(&current_path, &self.source_path) {
            return Err(SourceInspectionError::Drift);
        }
        let current = observe(&self.file, &current_path)?;
        if current != self.observation {
            return Err(SourceInspectionError::Drift);
        }
        Ok(())
    }
}

fn observe(file: &File, path: &Path) -> Result<SourceFileObservation, SourceInspectionError> {
    let before = basic_info(file).map_err(native)?;
    let standard = standard_info(file).map_err(native)?;
    if before.dwFileAttributes & FORBIDDEN_SOURCE_ATTRIBUTES != 0 || standard.NumberOfLinks != 1 {
        return Err(SourceInspectionError::InvalidShape);
    }
    let size_bytes = file_size(file).map_err(native)?;
    if size_bytes > MAX_SOURCE_FILE_BYTES {
        return Err(SourceInspectionError::BoundsExceeded);
    }
    verify_stream_policy(file, false, size_bytes)
        .map_err(|error| SourceInspectionError::StreamPolicy(error.to_string()))?;
    let id = stable_id(file).map_err(native)?;
    let sha256 = hex::encode(hash_file(file, size_bytes).map_err(native)?);
    let after = basic_info(file).map_err(native)?;
    let after_standard = standard_info(file).map_err(native)?;
    if before.dwFileAttributes != after.dwFileAttributes
        || standard.EndOfFile != after_standard.EndOfFile
        || standard.NumberOfLinks != after_standard.NumberOfLinks
    {
        return Err(SourceInspectionError::Drift);
    }
    let canonical_path = path
        .to_str()
        .ok_or_else(|| SourceInspectionError::InvalidPath("final path is not Unicode".to_owned()))?
        .to_owned();
    Ok(SourceFileObservation {
        canonical_path: canonical_path.clone(),
        identity: WindowsFileIdentity {
            final_path: canonical_path,
            volume_serial_number: format!("{:016x}", id.volume_serial_number),
            file_id: hex::encode(id.file_id),
        },
        attributes: before.dwFileAttributes,
        size_bytes,
        sha256,
        link_count: standard.NumberOfLinks,
        only_unnamed_data_stream: true,
    })
}

fn native(error: impl std::fmt::Display) -> SourceInspectionError {
    SourceInspectionError::Native(error.to_string())
}

fn open_error(error: std::io::Error) -> SourceInspectionError {
    match error.raw_os_error() {
        // ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION are expected,
        // transient contention rather than malformed or unsupported sources.
        Some(32 | 33) => SourceInspectionError::Busy,
        _ => SourceInspectionError::Native(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Root(PathBuf);

    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aiw-held-application-file-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ordinary_file_is_hash_bound_and_blocks_write_and_rename() {
        let root = Root::new();
        let path = root.0.join("setup.exe");
        fs::write(&path, b"held-source").unwrap();
        let held = HeldApplicationFile::open(&path).unwrap();
        assert_eq!(held.observation().size_bytes, 11);
        assert_eq!(held.observation().link_count, 1);
        assert!(held.observation().only_unnamed_data_stream);
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::rename(&path, root.0.join("replacement.exe")).is_err());
        held.revalidate().unwrap();
    }

    #[test]
    fn existing_writer_is_reported_as_retryable_contention() {
        let root = Root::new();
        let path = root.0.join("busy.exe");
        fs::write(&path, b"busy-source").unwrap();
        let writer = OpenOptions::new().write(true).open(&path).unwrap();
        assert!(matches!(
            HeldApplicationFile::open(&path),
            Err(SourceInspectionError::Busy)
        ));
        drop(writer);
        HeldApplicationFile::open(&path).unwrap();
    }

    #[test]
    fn hardlinks_and_named_streams_are_rejected() {
        let root = Root::new();
        let linked = root.0.join("linked.exe");
        fs::write(&linked, b"linked").unwrap();
        fs::hard_link(&linked, root.0.join("second.exe")).unwrap();
        assert!(matches!(
            HeldApplicationFile::open(&linked),
            Err(SourceInspectionError::InvalidShape)
        ));

        let streamed = root.0.join("streamed.exe");
        fs::write(&streamed, b"streamed").unwrap();
        let mut stream = File::create(format!("{}:extra", streamed.display())).unwrap();
        stream.write_all(b"untrusted").unwrap();
        drop(stream);
        assert!(matches!(
            HeldApplicationFile::open(&streamed),
            Err(SourceInspectionError::StreamPolicy(_))
        ));
    }

    #[test]
    fn relative_and_reparse_sources_are_rejected() {
        assert!(matches!(
            HeldApplicationFile::open(Path::new("relative.exe")),
            Err(SourceInspectionError::InvalidPath(_))
        ));
        let root = Root::new();
        let target = root.0.join("target.exe");
        let link = root.0.join("link.exe");
        fs::write(&target, b"target").unwrap();
        if std::os::windows::fs::symlink_file(&target, &link).is_ok() {
            assert!(matches!(
                HeldApplicationFile::open(&link),
                Err(SourceInspectionError::InvalidShape)
                    | Err(SourceInspectionError::InvalidPath(_))
            ));
        }
    }
}
