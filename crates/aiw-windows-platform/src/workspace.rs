use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, IsValidAcl,
    IsValidSecurityDescriptor, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
    FILE_REMOTE_PROTOCOL_INFO, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
    FileRemoteProtocolInfo, GetDriveTypeW, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
    GetVolumePathNameW, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows::core::{PCWSTR, PWSTR};

const WORKSPACE_SCHEMA: &str = "aiw.dev/workspace-binding-evidence/v0alpha1";
const WORKSPACE_POLICY: &str = "owner-system-full-control-protected-v1";
const SYSTEM_SID: &str = "S-1-5-18";
const MAX_FINAL_PATH: usize = 32_768;

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("workspace parent is not an absolute existing local fixed-volume directory")]
    InvalidParent,
    #[error("workspace leaf is not a bounded unambiguous identifier")]
    InvalidLeaf,
    #[error("workspace leaf already exists and will not be adopted or repaired")]
    AlreadyExists,
    #[error("workspace path is a link, reparse point, or changed identity")]
    IdentityRejected,
    #[error("workspace ACL is not protected owner-and-SYSTEM-only full control")]
    AclRejected,
    #[error("workspace native operation failed at {operation}: {detail}")]
    Native {
        operation: &'static str,
        detail: String,
    },
    #[error("new workspace requires explicit recovery at {path}: {detail}")]
    PartialWorkspace { path: String, detail: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceDirectoryIdentity {
    pub final_path: String,
    pub volume_serial_number: String,
    pub file_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceBindingEvidence {
    pub schema_version: String,
    pub policy: String,
    pub security_policy_sha256: String,
    pub owner_sid: String,
    pub dacl_protected: bool,
    pub allowed_sids: Vec<String>,
    pub parent: WorkspaceDirectoryIdentity,
    pub root: WorkspaceDirectoryIdentity,
    pub tools: WorkspaceDirectoryIdentity,
    pub output: WorkspaceDirectoryIdentity,
}

/// A newly-created workspace whose parent, root, tools, and output directory
/// identities remain held without delete sharing until this value is dropped.
/// Existing leaves are never adopted or repaired.
#[derive(Debug)]
pub struct HeldRunWorkspace {
    parent: File,
    root: File,
    tools: File,
    output: File,
    root_path: PathBuf,
    evidence: WorkspaceBindingEvidence,
}

impl HeldRunWorkspace {
    pub fn create(parent: &Path, leaf: &str) -> Result<Self, WorkspaceError> {
        validate_leaf(leaf)?;
        if !parent.is_absolute() {
            return Err(WorkspaceError::InvalidParent);
        }
        let parent_path = parent
            .canonicalize()
            .map_err(|_| WorkspaceError::InvalidParent)?;
        if !same_path(parent, &parent_path) {
            return Err(WorkspaceError::Native {
                operation: "supplied-parent-path",
                detail: format!(
                    "supplied {}; resolved {}",
                    parent.display(),
                    parent_path.display()
                ),
            });
        }
        let parent_handle = open_held_parent(&parent_path)?;
        let parent_identity = directory_identity(&parent_handle)?;
        if !same_path(&parent_identity.final_path, &parent_path) {
            return Err(WorkspaceError::Native {
                operation: "parent-handle-path",
                detail: format!(
                    "expected {}; observed {}",
                    parent_path.display(),
                    parent_identity.final_path
                ),
            });
        }
        if !is_fixed_volume(&parent_path)? {
            return Err(WorkspaceError::InvalidParent);
        }
        verify_local_acl_volume(&parent_handle)?;

        let owner = CurrentUser::query()?;
        let descriptor = SecurityDescriptor::owner_system_only(&owner.sid_string)?;
        let root_path = parent_path.join(leaf);
        create_directory(&root_path, &descriptor)?;

        let creation = (|| {
            let root_handle = open_held_directory(&root_path)?;
            let root_identity = verify_owner_system_directory(&root_handle, &owner.sid)?;
            if !same_path(&root_identity.final_path, &root_path) {
                return Err(WorkspaceError::IdentityRejected);
            }

            let tools_path = root_path.join("tools");
            create_directory(&tools_path, &descriptor)?;
            let tools_handle = open_held_directory(&tools_path)?;
            let tools_identity = verify_owner_system_directory(&tools_handle, &owner.sid)?;

            let output_path = root_path.join("output");
            create_directory(&output_path, &descriptor)?;
            let output_handle = open_held_directory(&output_path)?;
            let output_identity = verify_owner_system_directory(&output_handle, &owner.sid)?;

            if root_identity.volume_serial_number != tools_identity.volume_serial_number
                || root_identity.volume_serial_number != output_identity.volume_serial_number
            {
                return Err(WorkspaceError::IdentityRejected);
            }

            Ok(Self {
                parent: parent_handle,
                root: root_handle,
                tools: tools_handle,
                output: output_handle,
                root_path: root_path.clone(),
                evidence: WorkspaceBindingEvidence {
                    schema_version: WORKSPACE_SCHEMA.to_owned(),
                    policy: WORKSPACE_POLICY.to_owned(),
                    security_policy_sha256: policy_hash(&owner.sid_string),
                    owner_sid: owner.sid_string.clone(),
                    dacl_protected: true,
                    allowed_sids: vec![SYSTEM_SID.to_owned(), owner.sid_string.clone()],
                    parent: parent_identity,
                    root: root_identity,
                    tools: tools_identity,
                    output: output_identity,
                },
            })
        })();

        // On any post-creation validation failure, preserve the new path for
        // explicit recovery. Blind path deletion could remove an attacker-
        // substituted object from the same-user CreateDirectory/Open gap.
        creation.map_err(|error| WorkspaceError::PartialWorkspace {
            path: root_path.to_string_lossy().into_owned(),
            detail: error.to_string(),
        })
    }

    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    pub fn tools_path(&self) -> PathBuf {
        self.root_path.join("tools")
    }

    pub fn output_path(&self) -> PathBuf {
        self.root_path.join("output")
    }

    pub fn evidence(&self) -> &WorkspaceBindingEvidence {
        &self.evidence
    }

    /// Revalidates every held handle immediately before a privileged or
    /// provider mutation. The comparison is handle-based, not path-only.
    pub fn revalidate(&self) -> Result<(), WorkspaceError> {
        let owner = CurrentUser::query()?;
        let root = verify_owner_system_directory(&self.root, &owner.sid)?;
        let tools = verify_owner_system_directory(&self.tools, &owner.sid)?;
        let output = verify_owner_system_directory(&self.output, &owner.sid)?;
        if root != self.evidence.root
            || tools != self.evidence.tools
            || output != self.evidence.output
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        let parent = directory_identity(&self.parent)?;
        if parent != self.evidence.parent {
            return Err(WorkspaceError::IdentityRejected);
        }
        if Path::new(&root.final_path)
            .parent()
            .is_none_or(|value| !same_path(&parent.final_path, value))
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        let current_root = open_held_directory(&self.root_path)
            .and_then(|file| verify_owner_system_directory(&file, &owner.sid))?;
        let current_parent_path = self
            .root_path
            .parent()
            .ok_or(WorkspaceError::IdentityRejected)?;
        let current_parent =
            open_held_parent(current_parent_path).and_then(|file| directory_identity(&file))?;
        let current_tools = open_held_directory(&self.tools_path())
            .and_then(|file| verify_owner_system_directory(&file, &owner.sid))?;
        let current_output = open_held_directory(&self.output_path())
            .and_then(|file| verify_owner_system_directory(&file, &owner.sid))?;
        if current_parent != self.evidence.parent
            || current_root != self.evidence.root
            || current_tools != self.evidence.tools
            || current_output != self.evidence.output
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        Ok(())
    }
}

fn validate_leaf(leaf: &str) -> Result<(), WorkspaceError> {
    if leaf.is_empty()
        || leaf.len() > 80
        || !leaf
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !leaf.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err(WorkspaceError::InvalidLeaf);
    }
    let upper = leaf.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(upper.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(WorkspaceError::InvalidLeaf);
    }
    Ok(())
}

fn create_directory(path: &Path, descriptor: &SecurityDescriptor) -> Result<(), WorkspaceError> {
    let wide = wide_path(path)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: `wide` is NUL-terminated and lives through the call. The security
    // descriptor is a LocalAlloc-owned self-relative descriptor held by
    // `descriptor`; SECURITY_ATTRIBUTES is initialized and non-inheritable.
    match unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&attributes)) } {
        Ok(()) => Ok(()),
        Err(error) if matches!(error.code().0 as u32, 0x8007_00b7 | 0x8007_0050) => {
            Err(WorkspaceError::AlreadyExists)
        }
        Err(error) => Err(native("CreateDirectoryW", error)),
    }
}

fn open_held_directory(path: &Path) -> Result<File, WorkspaceError> {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| WorkspaceError::Native {
            operation: "CreateFileW(directory)",
            detail: error.to_string(),
        })?;
    ensure_directory_handle(&file)?;
    Ok(file)
}

fn open_held_parent(path: &Path) -> Result<File, WorkspaceError> {
    let file = OpenOptions::new()
        .access_mode(
            FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0 | FILE_ADD_SUBDIRECTORY.0,
        )
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| WorkspaceError::Native {
            operation: "CreateFileW(parent-directory)",
            detail: error.to_string(),
        })?;
    ensure_directory_handle(&file)?;
    Ok(file)
}

fn ensure_directory_handle(file: &File) -> Result<(), WorkspaceError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file owns a valid directory handle and `info` is writable.
    unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) }
        .map_err(|error| native("GetFileInformationByHandle", error))?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(WorkspaceError::IdentityRejected);
    }
    Ok(())
}

fn verify_local_acl_volume(file: &File) -> Result<(), WorkspaceError> {
    let mut flags = 0_u32;
    // SAFETY: the held handle is valid and the requested flags output is writable.
    unsafe {
        GetVolumeInformationByHandleW(raw_handle(file), None, None, None, Some(&mut flags), None)
    }
    .map_err(|error| native("GetVolumeInformationByHandleW", error))?;
    if flags & FILE_PERSISTENT_ACLS == 0 {
        return Err(WorkspaceError::InvalidParent);
    }
    let mut remote = FILE_REMOTE_PROTOCOL_INFO::default();
    // A successful FileRemoteProtocolInfo query identifies a remote handle.
    // Local handles normally reject the information class.
    if unsafe {
        GetFileInformationByHandleEx(
            raw_handle(file),
            FileRemoteProtocolInfo,
            (&mut remote as *mut FILE_REMOTE_PROTOCOL_INFO).cast(),
            size_of::<FILE_REMOTE_PROTOCOL_INFO>() as u32,
        )
    }
    .is_ok()
    {
        return Err(WorkspaceError::InvalidParent);
    }
    Ok(())
}

fn directory_identity(file: &File) -> Result<WorkspaceDirectoryIdentity, WorkspaceError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file owns a valid held handle and `info` is writable.
    unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) }
        .map_err(|error| native("GetFileInformationByHandle", error))?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(WorkspaceError::IdentityRejected);
    }
    let mut file_id = FILE_ID_INFO::default();
    // SAFETY: the held handle is valid and `file_id` is a correctly sized,
    // writable FILE_ID_INFO buffer.
    unsafe {
        GetFileInformationByHandleEx(
            raw_handle(file),
            FileIdInfo,
            (&mut file_id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(|error| native("GetFileInformationByHandleEx(FileIdInfo)", error))?;
    Ok(WorkspaceDirectoryIdentity {
        final_path: final_path(file)?.to_string_lossy().into_owned(),
        volume_serial_number: format!("{:016x}", file_id.VolumeSerialNumber),
        file_id: hex::encode(file_id.FileId.Identifier),
    })
}

fn verify_owner_system_directory(
    file: &File,
    expected_owner: &OwnedSid,
) -> Result<WorkspaceDirectoryIdentity, WorkspaceError> {
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: output pointers are valid and GetSecurityInfo returns one
    // LocalAlloc-owned descriptor which backs `owner` and `dacl`.
    let result = unsafe {
        GetSecurityInfo(
            raw_handle(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    };
    if result.0 != 0 {
        return Err(WorkspaceError::Native {
            operation: "GetSecurityInfo",
            detail: format!("win32={}", result.0),
        });
    }
    let descriptor = SecurityDescriptor(descriptor);
    // SAFETY: descriptor was returned by GetSecurityInfo and remains owned.
    if !unsafe { IsValidSecurityDescriptor(descriptor.0) }.as_bool()
        || !unsafe { IsValidSid(owner) }.as_bool()
        || !unsafe { IsValidSid(expected_owner.0) }.as_bool()
    {
        return Err(WorkspaceError::AclRejected);
    }
    // SAFETY: both SIDs are valid for the lifetime of their owning buffers.
    if unsafe { EqualSid(owner, expected_owner.0) }.is_err() {
        return Err(WorkspaceError::AclRejected);
    }
    verify_acl(descriptor.0, dacl, expected_owner)?;
    directory_identity(file)
}

fn verify_acl(
    descriptor: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
    expected_owner: &OwnedSid,
) -> Result<(), WorkspaceError> {
    if dacl.is_null() {
        return Err(WorkspaceError::AclRejected);
    }
    // SAFETY: dacl points into the still-owned security descriptor.
    if !unsafe { IsValidAcl(dacl) }.as_bool() {
        return Err(WorkspaceError::AclRejected);
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor is valid and both outputs are writable.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .map_err(|error| native("GetSecurityDescriptorControl", error))?;
    if control & SE_DACL_PROTECTED.0 == 0
        || control & SE_DACL_PRESENT.0 == 0
        || control & SE_DACL_DEFAULTED.0 != 0
    {
        return Err(WorkspaceError::AclRejected);
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl and output buffer are valid for the call.
    unsafe {
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(|error| native("GetAclInformation", error))?;
    if info.AceCount != 2 {
        return Err(WorkspaceError::AclRejected);
    }
    let system = OwnedSid::from_string(SYSTEM_SID)?;
    let mut owner_seen = false;
    let mut system_seen = false;
    for index in 0..info.AceCount {
        let mut raw_ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: index is bounded by the queried AceCount and output is valid.
        unsafe { GetAce(dacl, index, &mut raw_ace) }.map_err(|error| native("GetAce", error))?;
        if raw_ace.is_null() {
            return Err(WorkspaceError::AclRejected);
        }
        // SAFETY: IsValidAcl established that every ACE includes a valid common
        // header within the DACL allocation.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || usize::from(header.AceSize) < sid_offset + 8
        {
            return Err(WorkspaceError::AclRejected);
        }
        // SAFETY: the type and IsValidAcl-backed size checks above establish
        // that the fixed ACCESS_ALLOWED_ACE fields are present.
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        if u32::from(ace.Header.AceFlags) != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).0
            || ace.Mask != FILE_ALL_ACCESS.0
        {
            return Err(WorkspaceError::AclRejected);
        }
        let sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
        let sid_bytes = unsafe {
            std::slice::from_raw_parts(
                (&ace.SidStart as *const u32).cast::<u8>(),
                usize::from(header.AceSize) - sid_offset,
            )
        };
        let expected_sid_size = 8_usize + 4_usize * usize::from(sid_bytes[1]);
        // SAFETY: the SID pointer is within the IsValidAcl-validated ACE, and
        // the byte-derived length has been bounded by AceSize first.
        if expected_sid_size > sid_bytes.len()
            || !unsafe { IsValidSid(sid) }.as_bool()
            || unsafe { GetLengthSid(sid) } as usize != expected_sid_size
        {
            return Err(WorkspaceError::AclRejected);
        }
        // SAFETY: the SID lies inside the ACE returned by GetAce.
        if unsafe { EqualSid(sid, expected_owner.0) }.is_ok() {
            owner_seen = true;
        } else if unsafe { EqualSid(sid, system.0) }.is_ok() {
            system_seen = true;
        } else {
            return Err(WorkspaceError::AclRejected);
        }
    }
    if !owner_seen || !system_seen {
        return Err(WorkspaceError::AclRejected);
    }
    Ok(())
}

fn is_fixed_volume(path: &Path) -> Result<bool, WorkspaceError> {
    let wide = wide_path(path)?;
    let mut volume = vec![0_u16; MAX_FINAL_PATH];
    // SAFETY: both strings are valid and the output slice is writable.
    unsafe { GetVolumePathNameW(PCWSTR(wide.as_ptr()), &mut volume) }
        .map_err(|error| native("GetVolumePathNameW", error))?;
    let length = volume
        .iter()
        .position(|value| *value == 0)
        .ok_or(WorkspaceError::InvalidParent)?;
    volume.truncate(length + 1);
    // SAFETY: volume is a NUL-terminated root path returned by Windows.
    Ok(unsafe { GetDriveTypeW(PCWSTR(volume.as_ptr())) } == DRIVE_FIXED)
}

fn final_path(file: &File) -> Result<PathBuf, WorkspaceError> {
    let mut buffer = vec![0_u16; MAX_FINAL_PATH];
    // SAFETY: the handle is valid and buffer is writable for its full length.
    let count =
        unsafe { GetFinalPathNameByHandleW(raw_handle(file), &mut buffer, FILE_NAME_NORMALIZED) };
    if count == 0 || count as usize >= buffer.len() {
        return Err(WorkspaceError::IdentityRejected);
    }
    let value = String::from_utf16(&buffer[..count as usize])
        .map_err(|_| WorkspaceError::IdentityRejected)?;
    Ok(PathBuf::from(
        value.strip_prefix("\\\\?\\").unwrap_or(&value),
    ))
}

fn same_path(left: impl AsRef<Path>, right: impl AsRef<Path>) -> bool {
    normalized_path(left.as_ref()).eq_ignore_ascii_case(&normalized_path(right.as_ref()))
}

fn normalized_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    value
        .strip_prefix("\\\\?\\")
        .unwrap_or(&value)
        .trim_end_matches(['\\', '/'])
        .to_owned()
}

fn wide_path(path: &Path) -> Result<Vec<u16>, WorkspaceError> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.is_empty() || value.contains(&0) || value.len() >= MAX_FINAL_PATH {
        return Err(WorkspaceError::IdentityRejected);
    }
    value.push(0);
    Ok(value)
}

fn wide_string(value: &str) -> Result<Vec<u16>, WorkspaceError> {
    if value.is_empty() || value.encode_utf16().any(|unit| unit == 0) {
        return Err(WorkspaceError::AclRejected);
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

fn raw_handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}

fn native(operation: &'static str, error: windows::core::Error) -> WorkspaceError {
    WorkspaceError::Native {
        operation,
        detail: error.to_string(),
    }
}

fn policy_hash(owner_sid: &str) -> String {
    let semantic = format!(
        "policy={WORKSPACE_POLICY}\nowner={owner_sid}\nallow={owner_sid}:full:object-container-inherit\nallow={SYSTEM_SID}:full:object-container-inherit\n"
    );
    hex::encode(Sha256::digest(semantic.as_bytes()))
}

struct CurrentUser {
    _token: OwnedHandle,
    _buffer: Vec<usize>,
    sid: OwnedSid,
    sid_string: String,
}

impl CurrentUser {
    fn query() -> Result<Self, WorkspaceError> {
        let token = OwnedHandle::current_process_token()?;
        let mut required = 0_u32;
        // SAFETY: the first call intentionally supplies no buffer to obtain its size.
        let first = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
        if first.is_ok() || required < size_of::<TOKEN_USER>() as u32 {
            return Err(WorkspaceError::AclRejected);
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        // SAFETY: the aligned buffer is at least `required` bytes and writable.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                required,
                &mut required,
            )
        }
        .map_err(|error| native("GetTokenInformation(TokenUser)", error))?;
        // SAFETY: GetTokenInformation initialized a TOKEN_USER at the aligned buffer start.
        let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let sid_string = sid_to_string(token_user.User.Sid)?;
        let sid = OwnedSid::from_string(&sid_string)?;
        Ok(Self {
            _token: token,
            _buffer: buffer,
            sid,
            sid_string,
        })
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn current_process_token() -> Result<Self, WorkspaceError> {
        let mut handle = HANDLE::default();
        // SAFETY: output pointer is valid and GetCurrentProcess is always valid.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) }
            .map_err(|error| native("OpenProcessToken", error))?;
        Ok(Self(handle))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this value exclusively owns the token handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct OwnedSid(PSID);

impl OwnedSid {
    fn from_string(value: &str) -> Result<Self, WorkspaceError> {
        let wide = wide_string(value)?;
        let mut sid = PSID::default();
        // SAFETY: input is NUL-terminated and output pointer is valid.
        unsafe { ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut sid) }
            .map_err(|error| native("ConvertStringSidToSidW", error))?;
        Ok(Self(sid))
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSidToSidW allocated this SID with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
    }
}

fn sid_to_string(sid: PSID) -> Result<String, WorkspaceError> {
    let mut output = PWSTR::null();
    // SAFETY: sid comes from a validated TOKEN_USER and output pointer is valid.
    unsafe { ConvertSidToStringSidW(sid, &mut output) }
        .map_err(|error| native("ConvertSidToStringSidW", error))?;
    // SAFETY: successful conversion returns a NUL-terminated LocalAlloc string.
    let value = unsafe { output.to_string() }.map_err(|_| WorkspaceError::AclRejected)?;
    // SAFETY: output was allocated by ConvertSidToStringSidW.
    let _ = unsafe { LocalFree(Some(HLOCAL(output.0.cast()))) };
    Ok(value)
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn owner_system_only(owner_sid: &str) -> Result<Self, WorkspaceError> {
        let sddl = format!("O:{owner_sid}D:P(A;OICI;FA;;;{owner_sid})(A;OICI;FA;;;SY)");
        let wide = wide_string(&sddl)?;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: input is NUL-terminated and output pointer is valid.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| {
            native(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                error,
            )
        })?;
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: conversion allocated this descriptor with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent() -> PathBuf {
        std::env::temp_dir().canonicalize().unwrap()
    }

    fn leaf(suffix: &str) -> String {
        format!("aiw-workspace-test-{}-{suffix}", std::process::id())
    }

    fn remove_test_workspace(workspace: HeldRunWorkspace) {
        workspace.revalidate().unwrap();
        let path = workspace.root_path().to_owned();
        drop(workspace);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn creates_revalidates_and_removes_owner_bound_workspace() {
        let name = leaf("create");
        let path = parent().join(&name);
        let _ = std::fs::remove_dir_all(&path);
        let workspace = HeldRunWorkspace::create(&parent(), &name).unwrap();
        assert_eq!(workspace.evidence().schema_version, WORKSPACE_SCHEMA);
        assert_eq!(workspace.evidence().policy, WORKSPACE_POLICY);
        assert_eq!(workspace.evidence().security_policy_sha256.len(), 64);
        assert!(workspace.evidence().dacl_protected);
        assert_eq!(workspace.evidence().allowed_sids.len(), 2);
        for identity in [
            &workspace.evidence().parent,
            &workspace.evidence().root,
            &workspace.evidence().tools,
            &workspace.evidence().output,
        ] {
            assert_eq!(identity.volume_serial_number.len(), 16);
            assert_eq!(identity.file_id.len(), 32);
        }
        let mut tampered = serde_json::to_value(workspace.evidence()).unwrap();
        tampered
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<WorkspaceBindingEvidence>(tampered).is_err());
        assert!(workspace.tools_path().is_dir());
        assert!(workspace.output_path().is_dir());
        workspace.revalidate().unwrap();
        remove_test_workspace(workspace);
        assert!(!path.exists());
    }

    #[test]
    fn refuses_to_adopt_or_repair_an_existing_leaf() {
        let name = leaf("existing");
        let path = parent().join(&name);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        let error = HeldRunWorkspace::create(&parent(), &name).unwrap_err();
        assert!(matches!(error, WorkspaceError::AlreadyExists));
        assert!(path.is_dir());
        std::fs::remove_dir(&path).unwrap();
    }

    #[test]
    fn deletion_or_replacement_is_blocked_or_detected_before_reuse() {
        let name = leaf("held");
        let path = parent().join(&name);
        let _ = std::fs::remove_dir_all(&path);
        let workspace = HeldRunWorkspace::create(&parent(), &name).unwrap();
        let moved = parent().join(format!("{name}-moved"));
        let _ = std::fs::remove_dir_all(&moved);
        assert!(std::fs::rename(&path, &moved).is_err());
        if std::fs::remove_dir_all(&path).is_ok() {
            assert!(workspace.revalidate().is_err());
            drop(workspace);
        } else {
            remove_test_workspace(workspace);
        }
    }

    #[test]
    fn missing_parent_is_refused_without_partial_creation() {
        let missing = parent().join(leaf("missing-parent"));
        let child = missing.join("child");
        let _ = std::fs::remove_dir_all(&missing);
        assert!(matches!(
            HeldRunWorkspace::create(&missing, "child"),
            Err(WorkspaceError::InvalidParent)
        ));
        assert!(!child.exists());
    }

    #[test]
    fn rejects_ambiguous_leaf_names() {
        for leaf in [
            "", ".", "..", "a/b", "a\\b", "a:b", " name", "name.", "CON", "nul", "COM1", "lpt9",
        ] {
            assert!(matches!(
                HeldRunWorkspace::create(&parent(), leaf),
                Err(WorkspaceError::InvalidLeaf)
            ));
        }
    }
}
