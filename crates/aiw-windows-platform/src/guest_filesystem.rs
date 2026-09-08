//! Read-only filesystem evidence for the fixed Notepad++ guest profile.
//!
//! The public entry point has no caller-controlled path.  Every directory and
//! file is opened relative to a retained parent handle with write and delete
//! sharing excluded, and reparse points are recorded as incomplete evidence
//! rather than traversed.

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aiw_provider_wsb::{
    ApplicationFileEntry, ApplicationFileRoot, ApplicationFilesystemSnapshot,
    FilesystemCaptureIssue, FilesystemCaptureIssueReason,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_READ, READ_CONTROL, SYNCHRONIZE,
};

use crate::exact_dispose::{
    basic_info, file_size, filesystem_capture_directory_entries, hash_file, stable_id,
    standard_info,
};
use crate::workspace::raw_handle;

const INSTALLATION_ROOT: &str = r"C:\Program Files\Notepad++";
const APPLICATION_DIRECTORY: &str = "Notepad++";
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(30);
const MAXIMUM_FILES: usize = 4096;
const MAXIMUM_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAXIMUM_RELATIVE_PATH_BYTES: usize = 1024;
const MAXIMUM_DIRECTORY_DEPTH: u8 = 64;
const FILE_DIRECTORY_OPEN_OPTION: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_OPEN_OPTION: u32 = 0x0000_0040;
const FILE_SYNCHRONOUS_IO_NONALERT_OPTION: u32 = 0x0000_0020;
const FILE_OPEN_DISPOSITION: u32 = 0x0000_0001;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;

const FIXED_ROOTS: [ApplicationFileRoot; 3] = [
    ApplicationFileRoot::Installation,
    ApplicationFileRoot::RoamingAppData,
    ApplicationFileRoot::LocalAppData,
];

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

enum OpenChildError {
    NotFound,
    Other,
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

#[derive(Clone, Copy)]
struct CaptureLimits {
    maximum_files: usize,
    maximum_total_bytes: u64,
    maximum_file_bytes: u64,
    timeout: Duration,
}

const FIXED_LIMITS: CaptureLimits = CaptureLimits {
    maximum_files: MAXIMUM_FILES,
    maximum_total_bytes: MAXIMUM_TOTAL_BYTES,
    maximum_file_bytes: MAXIMUM_FILE_BYTES,
    timeout: SNAPSHOT_TIMEOUT,
};

struct CaptureState {
    started: Instant,
    limits: CaptureLimits,
    entries: Vec<ApplicationFileEntry>,
    issues: BTreeSet<(ApplicationFileRoot, FilesystemCaptureIssueReason)>,
    total_bytes: u64,
}

impl CaptureState {
    fn new(limits: CaptureLimits) -> Self {
        Self {
            started: Instant::now(),
            limits,
            entries: Vec::new(),
            issues: BTreeSet::new(),
            total_bytes: 0,
        }
    }

    fn incomplete(&mut self, root: ApplicationFileRoot, reason: FilesystemCaptureIssueReason) {
        self.issues.insert((root, reason));
    }

    fn expired(&self) -> bool {
        self.started.elapsed() > self.limits.timeout
    }

    fn finish(mut self) -> ApplicationFilesystemSnapshot {
        self.entries.sort_by(|left, right| {
            (left.root, left.path.to_ascii_lowercase())
                .cmp(&(right.root, right.path.to_ascii_lowercase()))
        });
        let issues = self
            .issues
            .into_iter()
            .map(|(root, reason)| FilesystemCaptureIssue { root, reason })
            .collect();
        let snapshot = ApplicationFilesystemSnapshot {
            entries: self.entries,
            issues,
        };
        if snapshot.validate().is_ok() {
            snapshot
        } else {
            // The collector must never turn a validation discrepancy into a
            // guest-agent panic or silently emit invalid authority.  A bounded
            // all-incomplete snapshot preserves the fail-closed meaning.
            ApplicationFilesystemSnapshot {
                entries: Vec::new(),
                issues: FIXED_ROOTS
                    .into_iter()
                    .map(|root| FilesystemCaptureIssue {
                        root,
                        reason: FilesystemCaptureIssueReason::Unreadable,
                    })
                    .collect(),
            }
        }
    }
}

/// Captures the three fixed Notepad++ roots in the guest.  An unavailable,
/// malformed, reparse-backed, changing, or over-limit root is represented in
/// `issues`; missing Notepad++ roots are ordinary empty observations.
#[must_use]
pub fn snapshot_fixed_notepad_files() -> ApplicationFilesystemSnapshot {
    let roots = [
        (
            ApplicationFileRoot::Installation,
            Ok(PathBuf::from(INSTALLATION_ROOT)),
        ),
        (
            ApplicationFileRoot::RoamingAppData,
            application_data_root("APPDATA"),
        ),
        (
            ApplicationFileRoot::LocalAppData,
            application_data_root("LOCALAPPDATA"),
        ),
    ];
    snapshot_roots(&roots, FIXED_LIMITS)
}

fn application_data_root(variable: &str) -> Result<PathBuf, ()> {
    let value = std::env::var_os(variable).ok_or(())?;
    let path = PathBuf::from(value);
    if !safe_guest_absolute_path(&path) {
        return Err(());
    }
    Ok(path.join(APPLICATION_DIRECTORY))
}

fn safe_guest_absolute_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() >= 4
        && matches!(bytes[0], b'C' | b'c')
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && value.len() <= 32_000
        && !value.contains(['/', '\0'])
        && value.split('\\').skip(1).all(safe_leaf)
}

fn snapshot_roots(
    roots: &[(ApplicationFileRoot, Result<PathBuf, ()>)],
    limits: CaptureLimits,
) -> ApplicationFilesystemSnapshot {
    let mut state = CaptureState::new(limits);
    for (root, path) in roots {
        if state.expired() {
            state.incomplete(*root, FilesystemCaptureIssueReason::LimitExceeded);
            continue;
        }
        let Ok(path) = path else {
            state.incomplete(*root, FilesystemCaptureIssueReason::Unreadable);
            continue;
        };
        let directory = match open_root(path) {
            Ok(Some(directory)) => directory,
            Ok(None) => continue,
            Err(reason) => {
                state.incomplete(*root, reason);
                continue;
            }
        };
        capture_directory(*root, &directory, "", 0, &mut state);
    }
    if state.expired() {
        for (root, _) in roots {
            state.incomplete(*root, FilesystemCaptureIssueReason::LimitExceeded);
        }
    }
    state.finish()
}

fn open_root(path: &Path) -> Result<Option<File>, FilesystemCaptureIssueReason> {
    if !safe_guest_absolute_path(path) {
        return Err(FilesystemCaptureIssueReason::Unreadable);
    }
    let mut directory = match OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(r"C:\")
    {
        Ok(file) => file,
        Err(_) => return Err(FilesystemCaptureIssueReason::Unreadable),
    };
    let root_info = basic_info(&directory).map_err(|_| FilesystemCaptureIssueReason::Unreadable)?;
    if is_reparse_attributes(root_info.dwFileAttributes) {
        return Err(FilesystemCaptureIssueReason::ReparsePoint);
    }
    if root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
        return Err(FilesystemCaptureIssueReason::Unreadable);
    }
    let value = path
        .to_str()
        .ok_or(FilesystemCaptureIssueReason::Unreadable)?;
    for component in value.split('\\').skip(1) {
        directory = match open_child(&directory, component, true) {
            Ok(child) => child,
            Err(OpenChildError::NotFound) => return Ok(None),
            Err(OpenChildError::Other) => return Err(FilesystemCaptureIssueReason::Unreadable),
        };
        let info = basic_info(&directory).map_err(|_| FilesystemCaptureIssueReason::Unreadable)?;
        if is_reparse_attributes(info.dwFileAttributes) {
            return Err(FilesystemCaptureIssueReason::ReparsePoint);
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
            return Err(FilesystemCaptureIssueReason::Unreadable);
        }
    }
    Ok(Some(directory))
}

fn capture_directory(
    root: ApplicationFileRoot,
    directory: &File,
    relative: &str,
    depth: u8,
    state: &mut CaptureState,
) {
    if state.expired() {
        state.incomplete(root, FilesystemCaptureIssueReason::LimitExceeded);
        return;
    }
    let entries = match filesystem_capture_directory_entries(directory) {
        Ok(entries) => entries,
        Err(_) => {
            state.incomplete(root, FilesystemCaptureIssueReason::Unreadable);
            return;
        }
    };
    let mut entries = entries;
    entries.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
    });
    let mut names = BTreeSet::new();
    for entry in entries {
        if state.expired() {
            state.incomplete(root, FilesystemCaptureIssueReason::LimitExceeded);
            return;
        }
        if !safe_leaf(&entry.name) || !names.insert(entry.name.to_ascii_lowercase()) {
            state.incomplete(root, FilesystemCaptureIssueReason::Unreadable);
            continue;
        }
        if entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            state.incomplete(root, FilesystemCaptureIssueReason::ReparsePoint);
            continue;
        }
        let path = if relative.is_empty() {
            entry.name.clone()
        } else {
            format!("{relative}/{}", entry.name)
        };
        if path.len() > MAXIMUM_RELATIVE_PATH_BYTES {
            state.incomplete(root, FilesystemCaptureIssueReason::LimitExceeded);
            continue;
        }
        let directory_entry = entry.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
        let child = match open_child(directory, &entry.name, directory_entry) {
            Ok(file) => file,
            Err(_) => {
                state.incomplete(root, FilesystemCaptureIssueReason::ChangedDuringRead);
                continue;
            }
        };
        let child_info = match basic_info(&child) {
            Ok(info) => info,
            Err(_) => {
                state.incomplete(root, FilesystemCaptureIssueReason::Unreadable);
                continue;
            }
        };
        let child_id = match stable_id(&child) {
            Ok(id) => id,
            Err(_) => {
                state.incomplete(root, FilesystemCaptureIssueReason::Unreadable);
                continue;
            }
        };
        if is_reparse_attributes(child_info.dwFileAttributes) {
            state.incomplete(root, FilesystemCaptureIssueReason::ReparsePoint);
            continue;
        }
        if child_id.file_id != entry.file_id
            || directory_entry != (child_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0)
        {
            state.incomplete(root, FilesystemCaptureIssueReason::ChangedDuringRead);
            continue;
        }
        if directory_entry {
            if depth >= MAXIMUM_DIRECTORY_DEPTH {
                state.incomplete(root, FilesystemCaptureIssueReason::LimitExceeded);
            } else {
                capture_directory(root, &child, &path, depth + 1, state);
            }
        } else {
            capture_file(
                root,
                &path,
                &child,
                child_info.dwFileAttributes,
                &child_id.file_id,
                state,
            );
        }
    }
}

fn capture_file(
    root: ApplicationFileRoot,
    path: &str,
    file: &File,
    expected_attributes: u32,
    expected_id: &[u8; 16],
    state: &mut CaptureState,
) {
    if state.expired() || state.entries.len() >= state.limits.maximum_files {
        state.incomplete(root, FilesystemCaptureIssueReason::LimitExceeded);
        return;
    }
    let before_standard = match standard_info(file) {
        Ok(info) => info,
        Err(_) => {
            state.incomplete(root, FilesystemCaptureIssueReason::Unreadable);
            return;
        }
    };
    let size_bytes = match file_size(file) {
        Ok(size) => size,
        Err(_) => {
            state.incomplete(root, FilesystemCaptureIssueReason::Unreadable);
            return;
        }
    };
    if size_bytes > state.limits.maximum_file_bytes
        || state
            .total_bytes
            .checked_add(size_bytes)
            .is_none_or(|total| total > state.limits.maximum_total_bytes)
    {
        state.incomplete(root, FilesystemCaptureIssueReason::LimitExceeded);
        return;
    }
    let sha256 = match hash_file(file, size_bytes) {
        Ok(hash) => hex::encode(hash),
        Err(_) => {
            state.incomplete(root, FilesystemCaptureIssueReason::ChangedDuringRead);
            return;
        }
    };
    if state.expired() {
        state.incomplete(root, FilesystemCaptureIssueReason::LimitExceeded);
        return;
    }
    let after_info = match basic_info(file) {
        Ok(info) => info,
        Err(_) => {
            state.incomplete(root, FilesystemCaptureIssueReason::Unreadable);
            return;
        }
    };
    let after_standard = match standard_info(file) {
        Ok(info) => info,
        Err(_) => {
            state.incomplete(root, FilesystemCaptureIssueReason::Unreadable);
            return;
        }
    };
    let after_id = match stable_id(file) {
        Ok(id) => id,
        Err(_) => {
            state.incomplete(root, FilesystemCaptureIssueReason::Unreadable);
            return;
        }
    };
    if after_info.dwFileAttributes != expected_attributes
        || after_standard.EndOfFile != before_standard.EndOfFile
        || after_standard.NumberOfLinks != before_standard.NumberOfLinks
        || after_id.file_id != *expected_id
    {
        state.incomplete(root, FilesystemCaptureIssueReason::ChangedDuringRead);
        return;
    }
    if state.expired() {
        state.incomplete(root, FilesystemCaptureIssueReason::LimitExceeded);
        return;
    }
    state.total_bytes += size_bytes;
    state.entries.push(ApplicationFileEntry {
        root,
        path: path.to_owned(),
        size_bytes,
        sha256,
    });
}

fn open_child(parent: &File, leaf: &str, directory: bool) -> Result<File, OpenChildError> {
    if !safe_leaf(leaf) {
        return Err(OpenChildError::Other);
    }
    let mut name: Vec<u16> = leaf.encode_utf16().collect();
    let bytes = u16::try_from(name.len().checked_mul(2).ok_or(OpenChildError::Other)?)
        .map_err(|_| OpenChildError::Other)?;
    let mut unicode = NtUnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: name.as_mut_ptr(),
    };
    let mut attributes = NtObjectAttributes {
        length: size_of::<NtObjectAttributes>() as u32,
        root_directory: raw_handle(parent).0,
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
            FILE_LIST_DIRECTORY.0
        } else {
            FILE_READ_DATA.0
        };
    let options = if directory {
        FILE_DIRECTORY_OPEN_OPTION
    } else {
        FILE_NON_DIRECTORY_OPEN_OPTION
    } | FILE_SYNCHRONOUS_IO_NONALERT_OPTION
        | FILE_FLAG_OPEN_REPARSE_POINT.0;
    let mut handle = std::ptr::null_mut();
    let mut status = NtIoStatusBlock {
        status: 0,
        information: 0,
    };
    // SAFETY: the leaf buffer and object attributes remain valid for this call;
    // a successful call returns one uniquely owned kernel handle.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &mut attributes,
            &mut status,
            std::ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL.0,
            FILE_SHARE_READ.0,
            FILE_OPEN_DISPOSITION,
            options,
            std::ptr::null_mut(),
            0,
        )
    };
    if result < 0 || handle.is_null() {
        return Err(
            if matches!(
                result,
                STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND
            ) {
                OpenChildError::NotFound
            } else {
                OpenChildError::Other
            },
        );
    }
    // SAFETY: NtCreateFile returned a uniquely owned handle on success.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn safe_leaf(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && value.len() <= 255
        && !value.ends_with([' ', '.'])
        && !value.contains(['\\', '/', ':', '\0'])
        && !value.chars().any(char::is_control)
        && !matches!(value, "." | "..")
        && !is_reserved_device_name(value)
}

fn is_reserved_device_name(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                suffix.len() == 1 && suffix.as_bytes()[0].is_ascii_digit() && suffix != "0"
            })
}

fn is_reparse_attributes(attributes: u32) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aiw-guest-filesystem-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should follow epoch")
                .as_nanos()
        ))
    }

    #[test]
    fn captures_only_canonical_relative_files_and_normalizes_missing_roots() {
        let root = fixture_root("ordinary");
        std::fs::create_dir_all(root.join("plugins")).expect("fixture directories should exist");
        std::fs::write(root.join("plugins").join("NppExport.dll"), b"fixture")
            .expect("fixture file should exist");
        let missing = root.join("missing");
        let roots = [
            (ApplicationFileRoot::Installation, Ok(root.clone())),
            (ApplicationFileRoot::LocalAppData, Ok(missing)),
        ];
        let snapshot = snapshot_roots(&roots, FIXED_LIMITS);
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].path, "plugins/NppExport.dll");
        assert!(snapshot.issues.is_empty());
        snapshot.validate().expect("captured snapshot is canonical");
        std::fs::remove_dir_all(root).expect("fixture should be removed");
    }

    #[test]
    fn treats_unrepresentable_names_as_incomplete_evidence() {
        let root = fixture_root("non-ascii");
        std::fs::create_dir_all(&root).expect("fixture directory should exist");
        std::fs::write(root.join("é.txt"), b"fixture").expect("fixture file should exist");
        let roots = [(ApplicationFileRoot::Installation, Ok(root.clone()))];
        let snapshot = snapshot_roots(&roots, FIXED_LIMITS);
        assert!(snapshot.entries.is_empty());
        assert!(snapshot.issues.iter().any(|issue| {
            issue.root == ApplicationFileRoot::Installation
                && issue.reason == FilesystemCaptureIssueReason::Unreadable
        }));
        std::fs::remove_dir_all(root).expect("fixture should be removed");
    }

    #[test]
    fn records_ascii_file_limit_as_incomplete_evidence() {
        let root = fixture_root("file-limit");
        std::fs::create_dir_all(&root).expect("fixture directory should exist");
        std::fs::write(root.join("oversized.txt"), b"two bytes")
            .expect("fixture file should exist");
        let roots = [(ApplicationFileRoot::Installation, Ok(root.clone()))];
        let snapshot = snapshot_roots(
            &roots,
            CaptureLimits {
                maximum_files: 1,
                maximum_total_bytes: 1024,
                maximum_file_bytes: 1,
                timeout: SNAPSHOT_TIMEOUT,
            },
        );
        assert!(snapshot.entries.is_empty());
        assert!(snapshot.issues.iter().any(|issue| {
            issue.root == ApplicationFileRoot::Installation
                && issue.reason == FilesystemCaptureIssueReason::LimitExceeded
        }));
        std::fs::remove_dir_all(root).expect("fixture should be removed");
    }

    #[test]
    fn bounds_recursion_and_rejects_provider_invalid_leaf_spellings() {
        for unsafe_leaf in ["CON.txt", "Lpt1.log", "name.", "name ", "bad\u{0001}"] {
            assert!(!safe_leaf(unsafe_leaf), "{unsafe_leaf:?} must be rejected");
        }

        let root = fixture_root("depth");
        let mut leaf = root.clone();
        for index in 0..=MAXIMUM_DIRECTORY_DEPTH {
            leaf.push(format!("d{index:02}"));
        }
        std::fs::create_dir_all(&leaf).expect("deep fixture directories should exist");
        std::fs::write(leaf.join("inside.txt"), b"fixture")
            .expect("deep fixture file should exist");
        let roots = [(ApplicationFileRoot::Installation, Ok(root.clone()))];
        let snapshot = snapshot_roots(&roots, FIXED_LIMITS);
        assert!(snapshot.entries.is_empty());
        assert!(snapshot.issues.iter().any(|issue| {
            issue.root == ApplicationFileRoot::Installation
                && issue.reason == FilesystemCaptureIssueReason::LimitExceeded
        }));
        std::fs::remove_dir_all(root).expect("fixture should be removed");
    }
}
