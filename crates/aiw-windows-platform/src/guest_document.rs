//! Fixed-document authority for the Notepad++ exercise.
//!
//! This module has no caller-provided paths.  It retains every directory
//! handle from `C:\` through `C:\AIW\Scenario`, opens children relative to
//! those handles, and refuses reparse objects before the UI process starts.
//! `C:\` and `C:\AIW` deny write/delete sharing. The retained `Scenario`
//! handle permits write sharing because a normal atomic document save
//! replaces a child entry, but denies delete sharing to protect its own name.
//! It is revalidated by stable identity against the
//! share-read-held `AIW` parent before and after application use.

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::mem::size_of;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle};
use std::path::Path;

use aiw_provider_wsb::{DOCUMENT_EXPECTED_TEXT, DOCUMENT_INITIAL_TEXT};
use sha2::{Digest, Sha256};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DEVICE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_DATA, GetFileInformationByHandle, READ_CONTROL, SYNCHRONIZE,
};

const FIXED_ROOT: &str = r"C:\AIW";
const SCENARIO_LEAF: &str = "Scenario";
const DOCUMENT_LEAF: &str = "document.txt";
const FILE_DIRECTORY_OPEN_OPTION: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_OPEN_OPTION: u32 = 0x0000_0040;
const FILE_SYNCHRONOUS_IO_NONALERT_OPTION: u32 = 0x0000_0020;
const FILE_OPEN_DISPOSITION: u32 = 0x0000_0001;
const FILE_CREATE_DISPOSITION: u32 = 0x0000_0002;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;

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

enum RelativeOpenError {
    NotFound,
    Collision,
    Other(String),
}

/// Holds the fixed directory ancestry while Notepad++ edits the document.
/// The initial document handle is deliberately dropped after `prepare`, so the
/// application may save through a replace-style implementation.
pub(crate) struct FixedGuestDocument {
    _ancestors: Vec<File>,
    scenario: File,
    expected_sha256: String,
}

impl FixedGuestDocument {
    pub(crate) fn prepare() -> Result<Self, String> {
        Self::prepare_with_ancestors(held_directory_chain(Path::new(FIXED_ROOT))?)
    }

    /// Prepares the same fixed document contract below a native-selected
    /// profile root.  This remains crate-private so callers cannot turn the
    /// document primitive into a general path writer.
    pub(crate) fn prepare_at(root: &Path) -> Result<Self, String> {
        if root != Path::new(crate::guest_standard_user::STANDARD_USER_DOCUMENT_ROOT) {
            return Err("standard-user document root is not the fixed profile path".to_owned());
        }
        let parent = root
            .parent()
            .ok_or_else(|| "fixed AIW parent is absent".to_owned())?;
        Self::prepare_with_fresh_aiw(held_directory_chain_with_sharing(
            parent,
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
        )?)
    }

    fn prepare_with_fresh_aiw(mut ancestors: Vec<File>) -> Result<Self, String> {
        let parent = ancestors
            .last()
            .ok_or_else(|| "fixed AIW parent was not retained".to_owned())?;
        // A fresh profile has no AIW directory. Create only this exact child,
        // relative to its held ordinary Local directory while impersonating the user.
        // Existing entries are rejected, including an installer-created entry.
        let aiw = create_relative_directory(parent, "AIW", FILE_SHARE_READ.0)
            .map_err(|error| relative_error("create fresh standard-user AIW directory", error))?;
        ancestors.push(aiw);
        Self::prepare_with_ancestors(ancestors)
    }

    pub(crate) fn observe_expected(&self) -> Result<Option<String>, String> {
        self.revalidate()?;
        let document = match open_relative_file(&self.scenario, DOCUMENT_LEAF, FILE_READ_DATA.0)? {
            Some(file) => file,
            None => return Ok(None),
        };
        let before = file_information(&document)?;
        if !ordinary_file(&before) {
            return Err("fixed document is not an ordinary file".to_owned());
        }
        let expected = DOCUMENT_EXPECTED_TEXT.as_bytes();
        let expected_length = u64::try_from(expected.len())
            .map_err(|_| "fixed document expected size did not fit u64".to_owned())?;
        if file_length(&before) != expected_length {
            return Ok(None);
        }
        let maximum = expected_length
            .checked_add(1)
            .ok_or_else(|| "fixed document read bound overflowed".to_owned())?;
        let capacity = usize::try_from(maximum)
            .map_err(|_| "fixed document read bound did not fit memory".to_owned())?;
        let mut bytes = Vec::with_capacity(capacity);
        let reader = &document;
        reader
            .take(maximum)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read held fixed document failed: {error}"))?;
        let after = file_information(&document)?;
        if !ordinary_file(&after) || !same_file_information(&before, &after) {
            return Err("fixed document changed while it was observed".to_owned());
        }
        if bytes.len() != expected.len() || bytes != expected {
            return Ok(None);
        }
        let observed = sha256(&bytes);
        if observed != self.expected_sha256 {
            return Err("fixed document hash disagreed with its fixed bytes".to_owned());
        }
        Ok(Some(observed))
    }

    /// Bounded, content-free diagnostics for a failed fixed-text save.
    pub(crate) fn describe_observed(&self) -> Result<String, String> {
        self.revalidate()?;
        let Some(file) = open_relative_file(&self.scenario, DOCUMENT_LEAF, FILE_READ_DATA.0)?
        else {
            return Ok("file absent".to_owned());
        };
        let before = file_information(&file)?;
        if !ordinary_file(&before) {
            return Err("file is not ordinary".to_owned());
        }
        let length = file_length(&before);
        if length > 256 {
            return Ok(format!("bytes={length}, exceeds diagnostic bound"));
        }
        let mut bytes = Vec::new();
        (&file)
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 != length
            || !same_file_information(&before, &file_information(&file)?)
        {
            return Err("file changed during diagnostic".to_owned());
        }
        Ok(format!(
            "bytes={length}, sha256={}, CR={}, LF={}, UTF8BOM={}",
            sha256(&bytes),
            bytes.iter().filter(|b| **b == b'\r').count(),
            bytes.iter().filter(|b| **b == b'\n').count(),
            bytes.starts_with(&[0xef, 0xbb, 0xbf])
        ))
    }

    /// Verifies that the fixed `C:\AIW\Scenario` pathname still names the
    /// retained ordinary directory.  The caller invokes this after the UI
    /// process exits, and `observe_expected` invokes it before opening the
    /// saved document.
    pub(crate) fn revalidate(&self) -> Result<(), String> {
        let aiw = self
            ._ancestors
            .last()
            .ok_or_else(|| "fixed document AIW ancestor was not retained".to_owned())?;
        let reopened = open_relative_directory(aiw, SCENARIO_LEAF, 0, FILE_SHARE_READ.0)?
            .ok_or_else(|| "fixed document Scenario path is absent".to_owned())?;
        let retained = file_information(&self.scenario)?;
        let current = file_information(&reopened)?;
        if !ordinary_directory(&retained)
            || !ordinary_directory(&current)
            || !same_file_information(&retained, &current)
        {
            return Err(
                "fixed document Scenario path no longer binds the retained directory".to_owned(),
            );
        }
        Ok(())
    }

    #[cfg(test)]
    fn prepare_under(root: &Path) -> Result<Self, String> {
        Self::prepare_with_ancestors(vec![open_fixture_root(root)?])
    }

    fn prepare_with_ancestors(mut ancestors: Vec<File>) -> Result<Self, String> {
        let root = ancestors
            .last()
            .ok_or_else(|| "fixed document root chain was empty".to_owned())?;
        let scenario = open_or_create_directory(root, SCENARIO_LEAF)?;
        let mut document = create_new_file(&scenario, DOCUMENT_LEAF)?;
        document
            .write_all(DOCUMENT_INITIAL_TEXT.as_bytes())
            .map_err(|error| format!("write fixed initial document failed: {error}"))?;
        document
            .sync_all()
            .map_err(|error| format!("sync fixed initial document failed: {error}"))?;
        drop(document);
        let scenario = rehold_scenario_for_replace(root, scenario)?;
        Ok(Self {
            _ancestors: std::mem::take(&mut ancestors),
            scenario,
            expected_sha256: sha256(DOCUMENT_EXPECTED_TEXT.as_bytes()),
        })
    }
}

#[cfg(test)]
fn open_fixture_root(path: &Path) -> Result<File, String> {
    let root = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| format!("open owned document fixture root failed: {error}"))?;
    if !ordinary_directory(&file_information(&root)?) {
        return Err("owned document fixture root is not an ordinary directory".to_owned());
    }
    Ok(root)
}

fn rehold_scenario_for_replace(aiw: &File, scenario: File) -> Result<File, String> {
    let original = file_information(&scenario)?;
    // The initial Scenario handle needs FILE_ADD_FILE to create document.txt.
    // A one-call relay permits that original desired access while converting to
    // the long-lived read/write-share handle below. The held AIW directory
    // keeps the Scenario namespace from being renamed during this conversion.
    let relay = open_relative_directory(
        aiw,
        SCENARIO_LEAF,
        0,
        FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
    )?
    .ok_or_else(|| "fixed document Scenario disappeared while reducing authority".to_owned())?;
    let relay_info = file_information(&relay)?;
    if !ordinary_directory(&relay_info) || !same_file_information(&original, &relay_info) {
        return Err("fixed document Scenario changed while reducing authority".to_owned());
    }
    drop(scenario);
    let retained = open_relative_directory(
        aiw,
        SCENARIO_LEAF,
        0,
        FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
    )?
    .ok_or_else(|| "fixed document Scenario disappeared after reducing authority".to_owned())?;
    let retained_info = file_information(&retained)?;
    if !ordinary_directory(&retained_info) || !same_file_information(&relay_info, &retained_info) {
        return Err("fixed document Scenario changed after reducing authority".to_owned());
    }
    drop(relay);
    Ok(retained)
}

fn held_directory_chain(path: &Path) -> Result<Vec<File>, String> {
    held_directory_chain_with_sharing(path, FILE_SHARE_READ.0)
}

// Profile ancestors are shared application state. Permit write opens while
// retaining every directory with delete sharing denied, so their names cannot
// be replaced. The owned AIW directory retains the stricter read-only sharing.
fn held_directory_chain_with_sharing(path: &Path, share_access: u32) -> Result<Vec<File>, String> {
    let value = path
        .to_str()
        .ok_or_else(|| "fixed document root path was not Unicode".to_owned())?;
    let bytes = value.as_bytes();
    if bytes.len() < 4
        || !matches!(bytes[0], b'C' | b'c')
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || value.contains(['/', '\0'])
        || !value.split('\\').skip(1).all(safe_leaf)
    {
        return Err("fixed document root path was not a safe C drive path".to_owned());
    }
    let components: Vec<_> = value.split('\\').skip(1).collect();
    let mut current = open_absolute_c_root(share_access)?;
    let mut ancestors = Vec::new();
    ancestors.push(current);
    for component in &components {
        // Retained ancestors need no write access for relative child creation.
        // A write-capable handle would reject readers that do not share writes.
        let extra_access = 0;
        current = open_relative_directory(
            ancestors.last().expect("C root was retained"),
            component,
            extra_access,
            share_access,
        )?
        .ok_or_else(|| format!("fixed document ancestor is absent: {component}"))?;
        ancestors.push(current);
    }
    Ok(ancestors)
}

fn open_absolute_c_root(share_access: u32) -> Result<File, String> {
    let root = OpenOptions::new()
        .read(true)
        .share_mode(share_access)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(r"C:\")
        .map_err(|error| format!("open fixed document C root failed: {error}"))?;
    let info = file_information(&root)?;
    if !ordinary_directory(&info) {
        return Err("fixed document C root is not an ordinary directory".to_owned());
    }
    Ok(root)
}

fn open_or_create_directory(parent: &File, leaf: &str) -> Result<File, String> {
    match open_relative_directory(
        parent,
        leaf,
        FILE_LIST_DIRECTORY.0 | FILE_ADD_SUBDIRECTORY.0 | FILE_ADD_FILE.0,
        FILE_SHARE_READ.0 | FILE_SHARE_DELETE.0,
    )? {
        Some(directory) => Ok(directory),
        None => {
            match create_relative_directory(parent, leaf, FILE_SHARE_READ.0 | FILE_SHARE_DELETE.0) {
                Ok(directory) => Ok(directory),
                Err(RelativeOpenError::Collision) => open_relative_directory(
                    parent,
                    leaf,
                    FILE_LIST_DIRECTORY.0 | FILE_ADD_SUBDIRECTORY.0 | FILE_ADD_FILE.0,
                    FILE_SHARE_READ.0 | FILE_SHARE_DELETE.0,
                )?
                .ok_or_else(|| "fixed document Scenario disappeared after create race".to_owned()),
                Err(error) => Err(relative_error("create fixed document Scenario", error)),
            }
        }
    }
}

fn open_relative_directory(
    parent: &File,
    leaf: &str,
    extra_access: u32,
    share_access: u32,
) -> Result<Option<File>, String> {
    match nt_open_relative(
        parent,
        leaf,
        true,
        FILE_OPEN_DISPOSITION,
        FILE_LIST_DIRECTORY.0
            | FILE_READ_ATTRIBUTES.0
            | FILE_READ_EA.0
            | READ_CONTROL.0
            | SYNCHRONIZE.0
            | extra_access,
        share_access,
    ) {
        Ok(directory) => {
            let info = file_information(&directory)?;
            if !ordinary_directory(&info) {
                return Err(format!("fixed document directory is unsafe: {leaf}"));
            }
            Ok(Some(directory))
        }
        Err(RelativeOpenError::NotFound) => Ok(None),
        Err(error) => Err(relative_error("open fixed document directory", error)),
    }
}

fn create_relative_directory(
    parent: &File,
    leaf: &str,
    share_access: u32,
) -> Result<File, RelativeOpenError> {
    let directory = nt_open_relative(
        parent,
        leaf,
        true,
        FILE_CREATE_DISPOSITION,
        FILE_LIST_DIRECTORY.0
            | FILE_READ_ATTRIBUTES.0
            | FILE_READ_EA.0
            | READ_CONTROL.0
            | SYNCHRONIZE.0
            | FILE_ADD_SUBDIRECTORY.0
            | FILE_ADD_FILE.0,
        share_access,
    )?;
    let info = file_information(&directory).map_err(RelativeOpenError::Other)?;
    if !ordinary_directory(&info) {
        return Err(RelativeOpenError::Other(
            "new fixed document Scenario is unsafe".to_owned(),
        ));
    }
    Ok(directory)
}

fn create_new_file(parent: &File, leaf: &str) -> Result<File, String> {
    let file = nt_open_relative(
        parent,
        leaf,
        false,
        FILE_CREATE_DISPOSITION,
        FILE_WRITE_DATA.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0,
        FILE_SHARE_READ.0,
    )
    .map_err(|error| relative_error("create fixed document", error))?;
    let info = file_information(&file)?;
    if !ordinary_file(&info) {
        return Err("new fixed document is not an ordinary file".to_owned());
    }
    Ok(file)
}

fn open_relative_file(parent: &File, leaf: &str, access: u32) -> Result<Option<File>, String> {
    match nt_open_relative(
        parent,
        leaf,
        false,
        FILE_OPEN_DISPOSITION,
        access | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0,
        FILE_SHARE_READ.0,
    ) {
        Ok(file) => Ok(Some(file)),
        Err(RelativeOpenError::NotFound) => Ok(None),
        Err(error) => Err(relative_error("open held fixed document", error)),
    }
}

fn nt_open_relative(
    parent: &File,
    leaf: &str,
    directory: bool,
    disposition: u32,
    desired_access: u32,
    share_access: u32,
) -> Result<File, RelativeOpenError> {
    if !safe_leaf(leaf) {
        return Err(RelativeOpenError::Other(
            "fixed document leaf is unsafe".to_owned(),
        ));
    }
    let mut name: Vec<u16> = leaf.encode_utf16().collect();
    let length =
        u16::try_from(name.len().checked_mul(2).ok_or_else(|| {
            RelativeOpenError::Other("fixed document leaf is too long".to_owned())
        })?)
        .map_err(|_| RelativeOpenError::Other("fixed document leaf is too long".to_owned()))?;
    let mut unicode = NtUnicodeString {
        length,
        maximum_length: length,
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
    let options = if directory {
        FILE_DIRECTORY_OPEN_OPTION
    } else {
        FILE_NON_DIRECTORY_OPEN_OPTION
    } | FILE_SYNCHRONOUS_IO_NONALERT_OPTION
        | FILE_FLAG_OPEN_REPARSE_POINT.0;
    let mut handle = std::ptr::null_mut();
    let mut io_status = NtIoStatusBlock {
        status: 0,
        information: 0,
    };
    // SAFETY: all pointers refer to local values that remain live through the
    // call; a successful NtCreateFile result transfers one owned handle.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &mut attributes,
            &mut io_status,
            std::ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL.0,
            share_access,
            disposition,
            options,
            std::ptr::null_mut(),
            0,
        )
    };
    if status < 0 || handle.is_null() {
        return Err(match status {
            STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => {
                RelativeOpenError::NotFound
            }
            STATUS_OBJECT_NAME_COLLISION => RelativeOpenError::Collision,
            _ => RelativeOpenError::Other(format!("NtCreateFile status=0x{:08x}", status as u32)),
        });
    }
    // SAFETY: NtCreateFile returned a uniquely owned handle on success.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn raw_handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle() as isize as *mut c_void)
}

fn file_information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the borrowed handle and output pointer remain valid for this call.
    unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) }
        .map_err(|error| format!("GetFileInformationByHandle failed: {error}"))?;
    Ok(info)
}

fn ordinary_directory(info: &BY_HANDLE_FILE_INFORMATION) -> bool {
    info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0
        && info.dwFileAttributes & FILE_ATTRIBUTE_DEVICE.0 == 0
}

fn ordinary_file(info: &BY_HANDLE_FILE_INFORMATION) -> bool {
    info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0
        && info.dwFileAttributes & FILE_ATTRIBUTE_DEVICE.0 == 0
}

fn file_length(info: &BY_HANDLE_FILE_INFORMATION) -> u64 {
    (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow)
}

fn same_file_information(
    left: &BY_HANDLE_FILE_INFORMATION,
    right: &BY_HANDLE_FILE_INFORMATION,
) -> bool {
    left.dwFileAttributes == right.dwFileAttributes
        && left.nNumberOfLinks == right.nNumberOfLinks
        && left.nFileSizeHigh == right.nFileSizeHigh
        && left.nFileSizeLow == right.nFileSizeLow
        && left.dwVolumeSerialNumber == right.dwVolumeSerialNumber
        && left.nFileIndexHigh == right.nFileIndexHigh
        && left.nFileIndexLow == right.nFileIndexLow
}

fn relative_error(operation: &str, error: RelativeOpenError) -> String {
    match error {
        RelativeOpenError::NotFound => format!("{operation} failed: object is absent"),
        RelativeOpenError::Collision => format!("{operation} failed: object already exists"),
        RelativeOpenError::Other(detail) => format!("{operation} failed: {detail}"),
    }
}

fn safe_leaf(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && value.len() <= 255
        && !value.ends_with([' ', '.'])
        && !value.contains(['\\', '/', ':', '\0'])
        && !value.chars().any(char::is_control)
        && !matches!(value, "." | "..")
        && !reserved_device_name(value)
}

fn reserved_device_name(value: &str) -> bool {
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

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "aiw-fixed-document-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should follow epoch")
                .as_nanos()
        ))
    }

    #[test]
    fn prepares_bounded_fixed_document_and_observes_only_expected_bytes() {
        let root = fixture_root();
        std::fs::create_dir_all(&root).expect("fixture root should exist");
        let document = FixedGuestDocument::prepare_under(&root).expect("document should prepare");
        assert_eq!(
            document.observe_expected().expect("initial observation"),
            None
        );

        let path = root.join(SCENARIO_LEAF).join(DOCUMENT_LEAF);
        let diagnostic = document
            .describe_observed()
            .expect("bounded initial diagnostic");
        assert!(diagnostic.contains(&sha256(DOCUMENT_INITIAL_TEXT.as_bytes())));
        assert!(diagnostic.contains("CR=1, LF=1"));
        assert!(!diagnostic.contains(DOCUMENT_INITIAL_TEXT));
        std::fs::write(&path, vec![b'x'; 257]).expect("oversize diagnostic fixture");
        assert_eq!(
            document.describe_observed().unwrap(),
            "bytes=257, exceeds diagnostic bound"
        );
        let replacement = path.with_extension("replacement");
        std::fs::write(&replacement, DOCUMENT_EXPECTED_TEXT)
            .expect("fixture application replacement should write");
        std::fs::rename(&replacement, &path)
            .expect("held directory ancestry should allow document replacement");
        assert_eq!(
            document.observe_expected().expect("expected observation"),
            Some(sha256(DOCUMENT_EXPECTED_TEXT.as_bytes()))
        );
        let moved_scenario = root.join("Scenario-moved");
        assert!(
            std::fs::rename(root.join(SCENARIO_LEAF), moved_scenario).is_err(),
            "share-read-held AIW must reject a Scenario rename"
        );
        document
            .revalidate()
            .expect("Scenario should remain bound after document replacement");
        drop(document);
        std::fs::remove_dir_all(root).expect("fixture root should be removed");
    }

    #[test]
    fn fresh_profile_root_is_created_once_and_retained_during_save() {
        let root = fixture_root();
        std::fs::create_dir(&root).unwrap();
        let document =
            FixedGuestDocument::prepare_with_fresh_aiw(vec![open_fixture_root(&root).unwrap()])
                .unwrap();
        let path = root.join("AIW").join(SCENARIO_LEAF).join(DOCUMENT_LEAF);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            DOCUMENT_INITIAL_TEXT.as_bytes()
        );
        let replacement = path.with_extension("replacement");
        std::fs::write(&replacement, DOCUMENT_EXPECTED_TEXT).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert_eq!(
            document.observe_expected().unwrap(),
            Some(sha256(DOCUMENT_EXPECTED_TEXT.as_bytes()))
        );
        assert!(std::fs::rename(root.join("AIW"), root.join("moved")).is_err());
        drop(document);
        let error =
            FixedGuestDocument::prepare_with_fresh_aiw(vec![open_fixture_root(&root).unwrap()])
                .err()
                .unwrap();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            DOCUMENT_EXPECTED_TEXT.as_bytes()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profile_ancestors_allow_application_writes_but_reject_rename() {
        let root = fixture_root();
        std::fs::create_dir(&root).unwrap();
        let open_application_parent = || {
            OpenOptions::new()
                .access_mode(FILE_ADD_SUBDIRECTORY.0 | FILE_ADD_FILE.0)
                .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(&root)
        };
        let strict = open_fixture_root(&root).unwrap();
        assert!(open_application_parent().is_err());
        drop(strict);
        let shared =
            held_directory_chain_with_sharing(&root, FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
                .unwrap();
        let document = FixedGuestDocument::prepare_with_fresh_aiw(shared).unwrap();
        let read_only_consumer = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(&root)
            .unwrap();
        drop(read_only_consumer);
        let application_parent = open_application_parent().unwrap();
        std::fs::create_dir(root.join("Notepad++")).unwrap();
        assert!(std::fs::rename(&root, root.with_extension("moved")).is_err());
        assert!(std::fs::rename(root.join("AIW"), root.join("moved-AIW")).is_err());
        assert!(
            std::fs::rename(
                root.join("AIW").join("Scenario"),
                root.join("moved-Scenario")
            )
            .is_err()
        );
        drop(application_parent);
        drop(document);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unsafe_fixed_path_components() {
        for value in ["CON.txt", "name.", "name ", "bad\u{0001}", "nested/path"] {
            assert!(!safe_leaf(value), "{value:?} must be rejected");
        }
    }
}
