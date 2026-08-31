//! Read-only, held-handle identity for untrusted application source files.
//!
//! This primitive does not execute, copy, trust, or authorize the source. It
//! holds the exact ordinary local file without write/delete sharing while its
//! identity, stream policy, size, and content hash are observed.

use std::ffi::{OsStr, c_void};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{FileExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};

use aiw_probe::{
    PORTABLE_DIRECTORY_AUTHORITY_SCHEMA, PORTABLE_MANIFEST_SCHEMA, PortableContentEntry,
    PortableContentEntryKind, PortableContentManifest, PortableDirectoryAuthority,
    PortableEntryAuthority, WindowsFileIdentity,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_READ,
    FILE_TRAVERSE, READ_CONTROL, SYNCHRONIZE,
};

use crate::exact_dispose::{
    DirectoryEntry, ExactDisposeError, StableFileId, basic_info, file_size, hash_file,
    reject_case_sensitive_directory, source_directory_entries, stable_id, standard_info,
    verify_stream_policy,
};
use crate::workspace::{final_path, is_fixed_volume, same_path, verify_local_acl_volume};

const MAX_SOURCE_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_PORTABLE_ENTRIES: usize = 10_000;
const MAX_PORTABLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PORTABLE_DEPTH: usize = 64;
const MAX_RELATIVE_PATH_BYTES: usize = 1024;
const FORBIDDEN_SOURCE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_REPARSE_POINT.0
    | FILE_ATTRIBUTE_DIRECTORY.0
    | FILE_ATTRIBUTE_DEVICE.0
    | FILE_ATTRIBUTE_OFFLINE.0
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS.0
    | FILE_ATTRIBUTE_RECALL_ON_OPEN.0;
const FORBIDDEN_PORTABLE_ATTRIBUTES: u32 =
    FORBIDDEN_SOURCE_ATTRIBUTES & !FILE_ATTRIBUTE_DIRECTORY.0;
const FILE_OPEN_DISPOSITION: u32 = 0x0000_0001;
const FILE_DIRECTORY_CREATE_OPTION: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_CREATE_OPTION: u32 = 0x0000_0040;
const FILE_SYNCHRONOUS_IO_NONALERT_OPTION: u32 = 0x0000_0020;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const STATUS_SHARING_VIOLATION: i32 = 0xC000_0043_u32 as i32;
const STATUS_FILE_LOCK_CONFLICT: i32 = 0xC000_0054_u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;
const STATUS_FILE_IS_A_DIRECTORY: i32 = 0xC000_00BA_u32 as i32;
const STATUS_NOT_A_DIRECTORY: i32 = 0xC000_0103_u32 as i32;
const STATUS_DELETE_PENDING: i32 = 0xC000_0056_u32 as i32;

#[repr(C)]
struct NtUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct NtObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut NtUnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct NtIoStatusBlock {
    status: i32,
    information: usize,
}

unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *mut NtObjectAttributes,
        io_status_block: *mut NtIoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut c_void,
        ea_length: u32,
    ) -> i32;
}

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

#[derive(Debug)]
pub struct HeldPortableDirectory {
    root_path: PathBuf,
    root_id: StableFileId,
    objects: Vec<HeldPortableObject>,
    manifest: PortableContentManifest,
    authority: PortableDirectoryAuthority,
}

#[derive(Debug)]
struct HeldPortableObject {
    relative_path: String,
    kind: PortableContentEntryKind,
    file: File,
    observation: PortableObjectObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PortableObjectObservation {
    id: StableFileId,
    attributes: u32,
    link_count: u32,
    size_bytes: u64,
    sha256: Option<[u8; 32]>,
    children: Vec<DirectoryEntry>,
}

#[derive(Debug, Error)]
pub enum SourceInspectionError {
    #[error("application source path is invalid: {0}")]
    InvalidPath(String),
    #[error("application source is not an ordinary single-link file")]
    InvalidShape,
    #[error("application source does not satisfy the fixed inspection policy: {0}")]
    PolicyRejected(String),
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

    pub(crate) fn copy_to(&self, destination: &mut File) -> Result<(), SourceInspectionError> {
        if destination.metadata().map_err(native)?.len() != 0 {
            return Err(SourceInspectionError::InvalidShape);
        }
        let mut offset = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        while offset < self.observation.size_bytes {
            let remaining = self.observation.size_bytes - offset;
            let request = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| SourceInspectionError::BoundsExceeded)?;
            let count = self
                .file
                .seek_read(&mut buffer[..request], offset)
                .map_err(native)?;
            if count == 0 {
                return Err(SourceInspectionError::Drift);
            }
            destination.write_all(&buffer[..count]).map_err(native)?;
            offset = offset
                .checked_add(count as u64)
                .ok_or(SourceInspectionError::BoundsExceeded)?;
        }
        destination.flush().map_err(native)?;
        destination.sync_all().map_err(native)?;
        self.revalidate()
    }
}

impl HeldPortableDirectory {
    pub fn open(path: &Path) -> Result<Self, SourceInspectionError> {
        if !path.is_absolute() || path.as_os_str().is_empty() {
            return Err(SourceInspectionError::InvalidPath(
                "path must be absolute and nonempty".to_owned(),
            ));
        }
        let root = OpenOptions::new()
            .access_mode(
                FILE_LIST_DIRECTORY.0
                    | FILE_TRAVERSE.0
                    | FILE_READ_ATTRIBUTES.0
                    | FILE_READ_EA.0
                    | READ_CONTROL.0
                    | SYNCHRONIZE.0,
            )
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(path)
            .map_err(open_error)?;
        verify_local_acl_volume(&root).map_err(native)?;
        let root_path = final_path(&root).map_err(native)?;
        if !is_fixed_volume(&root_path).map_err(native)? {
            return Err(SourceInspectionError::InvalidPath(
                "opened source is not on a fixed volume".to_owned(),
            ));
        }
        let root_observation = observe_portable_object(&root, true)?;
        let root_id = root_observation.id.clone();
        let mut objects = vec![HeldPortableObject {
            relative_path: String::new(),
            kind: PortableContentEntryKind::Directory,
            file: root,
            observation: root_observation,
        }];
        let mut pending = vec![(0_usize, 0_usize)];
        let mut total_size_bytes = 0_u64;

        while let Some((parent_index, depth)) = pending.pop() {
            if depth >= MAX_PORTABLE_DEPTH && !objects[parent_index].observation.children.is_empty()
            {
                return Err(SourceInspectionError::BoundsExceeded);
            }
            let children = objects[parent_index].observation.children.clone();
            let parent_relative = objects[parent_index].relative_path.clone();
            let mut opened = Vec::with_capacity(children.len());
            for child in children {
                if objects.len() + opened.len() > MAX_PORTABLE_ENTRIES {
                    return Err(SourceInspectionError::BoundsExceeded);
                }
                let relative_path = portable_relative_path(&parent_relative, &child.name)?;
                let directory = child.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
                if child.attributes & FORBIDDEN_PORTABLE_ATTRIBUTES != 0 {
                    return Err(SourceInspectionError::PolicyRejected(format!(
                        "{} has forbidden attributes {:#x}",
                        relative_path, child.attributes
                    )));
                }
                let file = open_relative(&objects[parent_index].file, &child.name, directory)?;
                let expected_path = final_path(&objects[parent_index].file)
                    .map_err(native)?
                    .join(&child.name);
                if !same_path(&final_path(&file).map_err(native)?, &expected_path) {
                    return Err(SourceInspectionError::Drift);
                }
                let observation = observe_portable_object(&file, directory)?;
                if observation.id.volume_serial_number != root_id.volume_serial_number
                    || observation.id.file_id != child.file_id
                {
                    return Err(SourceInspectionError::Drift);
                }
                let kind = if directory {
                    PortableContentEntryKind::Directory
                } else {
                    total_size_bytes = total_size_bytes
                        .checked_add(observation.size_bytes)
                        .filter(|size| *size <= MAX_PORTABLE_BYTES)
                        .ok_or(SourceInspectionError::BoundsExceeded)?;
                    PortableContentEntryKind::File
                };
                opened.push(HeldPortableObject {
                    relative_path,
                    kind,
                    file,
                    observation,
                });
            }
            for object in opened {
                let index = objects.len();
                if object.kind == PortableContentEntryKind::Directory {
                    pending.push((index, depth + 1));
                }
                objects.push(object);
            }
        }

        let (manifest, authority) = portable_evidence(&root_path, &root_id, &objects)?;
        let held = Self {
            root_path,
            root_id,
            objects,
            manifest,
            authority,
        };
        held.revalidate()?;
        Ok(held)
    }

    #[must_use]
    pub fn manifest(&self) -> &PortableContentManifest {
        &self.manifest
    }

    #[must_use]
    pub fn authority(&self) -> &PortableDirectoryAuthority {
        &self.authority
    }

    pub fn revalidate(&self) -> Result<(), SourceInspectionError> {
        if !same_path(
            &final_path(&self.objects[0].file).map_err(native)?,
            &self.root_path,
        ) || stable_id(&self.objects[0].file).map_err(exact)? != self.root_id
        {
            return Err(SourceInspectionError::Drift);
        }
        for object in &self.objects {
            let current = observe_portable_object(
                &object.file,
                object.kind == PortableContentEntryKind::Directory,
            )?;
            if current != object.observation {
                return Err(SourceInspectionError::Drift);
            }
        }
        Ok(())
    }
}

fn observe_portable_object(
    file: &File,
    directory: bool,
) -> Result<PortableObjectObservation, SourceInspectionError> {
    let before = basic_info(file).map_err(exact)?;
    let standard = standard_info(file).map_err(exact)?;
    if before.dwFileAttributes & FORBIDDEN_PORTABLE_ATTRIBUTES != 0 {
        return Err(SourceInspectionError::PolicyRejected(format!(
            "held object has forbidden attributes {:#x}",
            before.dwFileAttributes
        )));
    }
    if directory != (before.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0)
        || (!directory && standard.NumberOfLinks != 1)
    {
        return Err(SourceInspectionError::InvalidShape);
    }
    if directory {
        reject_case_sensitive_directory(file).map_err(exact)?;
        verify_stream_policy(file, true, 0).map_err(exact)?;
        let mut children = source_directory_entries(file).map_err(exact)?;
        children.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(PortableObjectObservation {
            id: stable_id(file).map_err(exact)?,
            attributes: before.dwFileAttributes,
            link_count: standard.NumberOfLinks,
            size_bytes: 0,
            sha256: None,
            children,
        })
    } else {
        let size_bytes = file_size(file).map_err(exact)?;
        if size_bytes > MAX_PORTABLE_BYTES {
            return Err(SourceInspectionError::BoundsExceeded);
        }
        verify_stream_policy(file, false, size_bytes).map_err(exact)?;
        let sha256 = hash_file(file, size_bytes).map_err(exact)?;
        let after = basic_info(file).map_err(exact)?;
        let after_standard = standard_info(file).map_err(exact)?;
        if before.dwFileAttributes != after.dwFileAttributes
            || standard.EndOfFile != after_standard.EndOfFile
            || standard.NumberOfLinks != after_standard.NumberOfLinks
        {
            return Err(SourceInspectionError::Drift);
        }
        Ok(PortableObjectObservation {
            id: stable_id(file).map_err(exact)?,
            attributes: before.dwFileAttributes,
            link_count: standard.NumberOfLinks,
            size_bytes,
            sha256: Some(sha256),
            children: Vec::new(),
        })
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

fn open_relative(
    parent: &File,
    leaf: &str,
    directory: bool,
) -> Result<File, SourceInspectionError> {
    let mut name: Vec<u16> = OsStr::new(leaf).encode_wide().collect();
    let byte_len = name
        .len()
        .checked_mul(2)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| SourceInspectionError::InvalidPath("child name is too long".to_owned()))?;
    let mut unicode = NtUnicodeString {
        length: byte_len,
        maximum_length: byte_len,
        buffer: name.as_mut_ptr(),
    };
    let mut attributes = NtObjectAttributes {
        length: size_of::<NtObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle(),
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let desired_access = FILE_READ_ATTRIBUTES.0
        | FILE_READ_EA.0
        | READ_CONTROL.0
        | SYNCHRONIZE.0
        | if directory {
            FILE_LIST_DIRECTORY.0 | FILE_TRAVERSE.0
        } else {
            FILE_READ_DATA.0
        };
    let create_options = FILE_SYNCHRONOUS_IO_NONALERT_OPTION
        | FILE_FLAG_OPEN_REPARSE_POINT.0
        | if directory {
            FILE_DIRECTORY_CREATE_OPTION
        } else {
            FILE_NON_DIRECTORY_CREATE_OPTION
        };
    let mut handle = std::ptr::null_mut();
    let mut io_status = NtIoStatusBlock {
        status: 0,
        information: 0,
    };
    // SAFETY: all pointers reference local buffers valid through the call;
    // successful NtCreateFile returns one uniquely owned handle.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &mut attributes,
            &mut io_status,
            std::ptr::null_mut(),
            0,
            FILE_SHARE_READ.0,
            FILE_OPEN_DISPOSITION,
            create_options,
            std::ptr::null_mut(),
            0,
        )
    };
    if matches!(status, STATUS_SHARING_VIOLATION | STATUS_FILE_LOCK_CONFLICT) {
        return Err(SourceInspectionError::Busy);
    }
    if matches!(
        status,
        STATUS_OBJECT_NAME_NOT_FOUND
            | STATUS_OBJECT_PATH_NOT_FOUND
            | STATUS_FILE_IS_A_DIRECTORY
            | STATUS_NOT_A_DIRECTORY
            | STATUS_DELETE_PENDING
    ) {
        return Err(SourceInspectionError::Drift);
    }
    if status < 0 || handle.is_null() {
        return Err(SourceInspectionError::Native(format!(
            "NtCreateFile(relative-source-open) failed: ntstatus=0x{:08x}",
            status as u32
        )));
    }
    // SAFETY: NtCreateFile returned a uniquely owned kernel handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn portable_relative_path(parent: &str, leaf: &str) -> Result<String, SourceInspectionError> {
    if leaf.is_empty()
        || !leaf.is_ascii()
        || leaf == "."
        || leaf == ".."
        || leaf.contains([':', '/', '\\'])
        || leaf.ends_with(['.', ' '])
        || leaf.bytes().any(|byte| byte < 32)
        || leaf.contains(['<', '>', '"', '|', '?', '*'])
        || is_reserved_windows_name(leaf)
    {
        return Err(SourceInspectionError::InvalidPath(
            "portable child name is unsupported".to_owned(),
        ));
    }
    let relative = if parent.is_empty() {
        leaf.to_owned()
    } else {
        format!("{parent}/{leaf}")
    };
    if relative.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(SourceInspectionError::BoundsExceeded);
    }
    Ok(relative)
}

fn is_reserved_windows_name(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
}

fn portable_evidence(
    root_path: &Path,
    root_id: &StableFileId,
    objects: &[HeldPortableObject],
) -> Result<(PortableContentManifest, PortableDirectoryAuthority), SourceInspectionError> {
    let mut entries = Vec::with_capacity(objects.len().saturating_sub(1));
    let mut authority_entries = Vec::with_capacity(objects.len().saturating_sub(1));
    for object in &objects[1..] {
        entries.push(PortableContentEntry {
            relative_path: object.relative_path.clone(),
            kind: object.kind,
            size_bytes: object.observation.size_bytes,
            sha256: object.observation.sha256.map(hex::encode),
        });
        authority_entries.push(PortableEntryAuthority {
            relative_path: object.relative_path.clone(),
            kind: object.kind,
            identity: file_identity(&object.file, &object.observation.id)?,
            link_count: object.observation.link_count,
            only_unnamed_data_stream: true,
        });
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    authority_entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let total_size_bytes = entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.size_bytes)
            .ok_or(SourceInspectionError::BoundsExceeded)
    })?;
    let mut digest = Sha256::new();
    for entry in &entries {
        let path = entry.relative_path.as_bytes();
        digest.update((path.len() as u64).to_le_bytes());
        digest.update(path);
        digest.update([match entry.kind {
            PortableContentEntryKind::Directory => 0,
            PortableContentEntryKind::File => 1,
        }]);
        digest.update(entry.size_bytes.to_le_bytes());
        if let Some(sha256) = &entry.sha256 {
            digest.update(hex::decode(sha256).map_err(native)?);
        }
    }
    let manifest_sha256 = hex::encode(digest.finalize());
    let root_path = root_path
        .to_str()
        .ok_or_else(|| SourceInspectionError::InvalidPath("final path is not Unicode".to_owned()))?
        .to_owned();
    Ok((
        PortableContentManifest {
            schema_version: PORTABLE_MANIFEST_SCHEMA.to_owned(),
            root_path: root_path.clone(),
            entries,
            total_size_bytes,
            manifest_sha256: manifest_sha256.clone(),
        },
        PortableDirectoryAuthority {
            schema_version: PORTABLE_DIRECTORY_AUTHORITY_SCHEMA.to_owned(),
            root_identity: WindowsFileIdentity {
                final_path: root_path,
                volume_serial_number: format!("{:016x}", root_id.volume_serial_number),
                file_id: hex::encode(root_id.file_id),
            },
            entries: authority_entries,
            manifest_sha256,
        },
    ))
}

fn file_identity(
    file: &File,
    id: &StableFileId,
) -> Result<WindowsFileIdentity, SourceInspectionError> {
    Ok(WindowsFileIdentity {
        final_path: final_path(file)
            .map_err(native)?
            .to_str()
            .ok_or_else(|| {
                SourceInspectionError::InvalidPath("final path is not Unicode".to_owned())
            })?
            .to_owned(),
        volume_serial_number: format!("{:016x}", id.volume_serial_number),
        file_id: hex::encode(id.file_id),
    })
}

fn native(error: impl std::fmt::Display) -> SourceInspectionError {
    SourceInspectionError::Native(error.to_string())
}

fn exact(error: ExactDisposeError) -> SourceInspectionError {
    match error {
        ExactDisposeError::Native { .. } => SourceInspectionError::Native(error.to_string()),
        ExactDisposeError::Contract(detail) | ExactDisposeError::Rejected(detail) => {
            SourceInspectionError::PolicyRejected(detail)
        }
        ExactDisposeError::TransientSmartLockerEa => {
            SourceInspectionError::PolicyRejected("extended attributes are unstable".to_owned())
        }
    }
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
    fn portable_tree_is_handle_bound_sorted_and_revalidated() {
        let root = Root::new();
        let nested = root.0.join("bin");
        fs::create_dir(&nested).unwrap();
        fs::write(root.0.join("readme.txt"), b"readme").unwrap();
        fs::write(nested.join("app.exe"), b"portable").unwrap();
        let held = HeldPortableDirectory::open(&root.0).unwrap();
        assert_eq!(held.manifest().entries.len(), 3);
        assert_eq!(held.manifest().entries[0].relative_path, "bin");
        assert_eq!(held.manifest().entries[1].relative_path, "bin/app.exe");
        assert_eq!(held.manifest().entries[2].relative_path, "readme.txt");
        assert_eq!(held.authority().entries.len(), 3);
        assert_eq!(
            held.authority().manifest_sha256,
            held.manifest().manifest_sha256
        );
        assert!(fs::write(nested.join("app.exe"), b"changed").is_err());
        assert!(fs::rename(&root.0, root.0.with_extension("moved")).is_err());
        held.revalidate().unwrap();
    }

    #[test]
    fn portable_manifest_is_independent_of_creation_order() {
        let first = Root::new();
        let second = Root::new();
        fs::create_dir(first.0.join("bin")).unwrap();
        fs::write(first.0.join("z.txt"), b"z").unwrap();
        fs::write(first.0.join("bin").join("a.txt"), b"a").unwrap();
        fs::write(second.0.join("z.txt"), b"z").unwrap();
        fs::create_dir(second.0.join("bin")).unwrap();
        fs::write(second.0.join("bin").join("a.txt"), b"a").unwrap();

        let first = HeldPortableDirectory::open(&first.0).unwrap();
        let second = HeldPortableDirectory::open(&second.0).unwrap();
        assert_eq!(first.manifest().entries, second.manifest().entries);
        assert_eq!(
            first.manifest().manifest_sha256,
            second.manifest().manifest_sha256
        );
    }

    #[test]
    fn portable_tree_rejects_hardlinks_streams_and_detects_new_children() {
        let linked_root = Root::new();
        let linked = linked_root.0.join("linked.exe");
        fs::write(&linked, b"linked").unwrap();
        fs::hard_link(&linked, linked_root.0.join("second.exe")).unwrap();
        assert!(matches!(
            HeldPortableDirectory::open(&linked_root.0),
            Err(SourceInspectionError::InvalidShape | SourceInspectionError::PolicyRejected(_))
        ));

        let streamed_root = Root::new();
        let streamed = streamed_root.0.join("streamed.exe");
        fs::write(&streamed, b"streamed").unwrap();
        let mut stream = File::create(format!("{}:extra", streamed.display())).unwrap();
        stream.write_all(b"untrusted").unwrap();
        drop(stream);
        assert!(matches!(
            HeldPortableDirectory::open(&streamed_root.0),
            Err(SourceInspectionError::InvalidShape | SourceInspectionError::PolicyRejected(_))
        ));

        let changing_root = Root::new();
        fs::write(changing_root.0.join("initial.txt"), b"initial").unwrap();
        let held = HeldPortableDirectory::open(&changing_root.0).unwrap();
        if fs::write(changing_root.0.join("later.txt"), b"later").is_ok() {
            assert!(matches!(
                held.revalidate(),
                Err(SourceInspectionError::Drift)
            ));
        }

        let busy_root = Root::new();
        let busy_path = busy_root.0.join("busy.txt");
        fs::write(&busy_path, b"busy").unwrap();
        let writer = OpenOptions::new().write(true).open(&busy_path).unwrap();
        assert!(matches!(
            HeldPortableDirectory::open(&busy_root.0),
            Err(SourceInspectionError::Busy)
        ));
        drop(writer);
        HeldPortableDirectory::open(&busy_root.0).unwrap();
    }

    #[test]
    fn relative_and_reparse_sources_are_rejected() {
        assert!(matches!(
            HeldApplicationFile::open(Path::new("relative.exe")),
            Err(SourceInspectionError::InvalidPath(_))
        ));
        assert!(matches!(
            HeldPortableDirectory::open(Path::new("relative-directory")),
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
        let real_directory = root.0.join("real-directory");
        let linked_directory = root.0.join("linked-directory");
        fs::create_dir(&real_directory).unwrap();
        if std::os::windows::fs::symlink_dir(&real_directory, &linked_directory).is_ok() {
            assert!(matches!(
                HeldPortableDirectory::open(&linked_directory),
                Err(SourceInspectionError::PolicyRejected(_))
                    | Err(SourceInspectionError::InvalidShape)
                    | Err(SourceInspectionError::InvalidPath(_))
            ));
        }
    }
}
