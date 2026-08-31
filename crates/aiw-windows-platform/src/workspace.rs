use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};

use aiw_probe::{
    WINDOWS_SYSTEM_SID, WINDOWS_WORKSPACE_SCHEMA_VERSION, WINDOWS_WORKSPACE_SECURITY_POLICY,
    WindowsFileIdentity, WorkspaceBindingEvidence, workspace_policy_hash,
};
use thiserror::Error;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE, IsValidAcl,
    IsValidSecurityDescriptor, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    SE_OWNER_DEFAULTED, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, DELETE, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_WRITE_THROUGH, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_REMOTE_PROTOCOL_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FILE_WRITE_EA, FileIdInfo, FileRemoteProtocolInfo, GetDriveTypeW, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
    GetVolumePathNameW, READ_CONTROL, SYNCHRONIZE, SetFileShortNameW,
};
use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows::core::{PCWSTR, PWSTR};

use crate::exact_dispose::{ExactDisposeError, exact_directory_entry, rename_relative};

const MAX_FINAL_PATH: usize = 32_768;

// NtCreateFile is the only Windows creation primitive that returns a newly
// created directory handle.  Keep the ABI local and the wrapper below tiny;
// callers never receive an existing-object handle from this API.
const FILE_CREATE_DISPOSITION: u32 = 0x0000_0002;
const FILE_OPEN_DISPOSITION: u32 = 0x0000_0001;
const FILE_DIRECTORY_CREATE_OPTION: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_CREATE_OPTION: u32 = 0x0000_0040;
const FILE_SYNCHRONOUS_IO_NONALERT_OPTION: u32 = 0x0000_0020;
const FILE_WRITE_THROUGH_OPTION: u32 = 0x0000_0002;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
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

/// A newly-created owner-and-SYSTEM-protected workspace directory.  The
/// handle and identity come directly from the create operation; the type has
/// no path-reopen or create-or-open constructor.
#[derive(Debug)]
pub struct CreatedWorkspaceDirectory {
    file: File,
    identity: WindowsFileIdentity,
    owner_sid: String,
    acl_policy: WorkspaceAclPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceAclPolicy {
    Protected,
    Inherited,
}

impl WorkspaceAclPolicy {
    fn is_protected(self) -> bool {
        matches!(self, Self::Protected)
    }
}

impl CreatedWorkspaceDirectory {
    /// Creates one new owner-and-SYSTEM-protected directory below an existing
    /// absolute local fixed-volume parent. Existing leaves are never adopted.
    pub fn create_protected(parent: &Path, leaf: &str) -> Result<Self, WorkspaceError> {
        validate_leaf(leaf)?;
        if !parent.is_absolute() {
            return Err(WorkspaceError::InvalidParent);
        }
        let parent_path = parent
            .canonicalize()
            .map_err(|_| WorkspaceError::InvalidParent)?;
        if !is_fixed_volume(&parent_path)? {
            return Err(WorkspaceError::InvalidParent);
        }
        let parent_handle = open_held_parent(&parent_path)?;
        verify_local_acl_volume(&parent_handle)?;
        if !same_path(
            &directory_identity(&parent_handle)?.final_path,
            &parent_path,
        ) {
            return Err(WorkspaceError::IdentityRejected);
        }
        let owner = CurrentUser::query()?;
        create_directory_handle_with_policy(&parent_handle, leaf, &owner.sid_string, true)
    }

    pub fn identity(&self) -> &WindowsFileIdentity {
        &self.identity
    }

    pub fn final_path(&self) -> &Path {
        Path::new(&self.identity.final_path)
    }

    pub fn as_file(&self) -> &File {
        &self.file
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn revalidate(&self) -> Result<(), WorkspaceError> {
        let owner = OwnedSid::from_string(&self.owner_sid)?;
        verify_owner_system_acl(&self.file, &owner, self.acl_policy.is_protected(), true)?;
        if directory_identity(&self.file)? != self.identity {
            return Err(WorkspaceError::IdentityRejected);
        }
        Ok(())
    }

    /// Publish this newly-created directory under a held, protected parent.
    /// The rename is relative to the destination handle and never replaces an
    /// occupied name. The same creation handle is returned after the move.
    pub fn publish_into(
        self,
        destination_parent: &File,
        destination_leaf: &str,
    ) -> Result<Self, WorkspaceError> {
        validate_leaf(destination_leaf)?;
        let owner = OwnedSid::from_string(&self.owner_sid)?;
        let parent_identity = verify_owner_system_directory(destination_parent, &owner)?;
        if verify_owner_system_acl(&self.file, &owner, self.acl_policy.is_protected(), true)
            .is_err()
            || directory_identity(&self.file)? != self.identity
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        self.publish_into_parent(destination_parent, destination_leaf, parent_identity)
    }

    /// Publish this directory under another strict bound directory, honoring
    /// either its protected or inherited ACL policy.
    pub fn publish_into_bound(
        self,
        destination_parent: &BoundWorkspaceDirectory,
        destination_leaf: &str,
    ) -> Result<Self, WorkspaceError> {
        destination_parent.revalidate()?;
        if self.owner_sid != destination_parent.owner_sid {
            return Err(WorkspaceError::AclRejected);
        }
        let owner = OwnedSid::from_string(&self.owner_sid)?;
        if verify_owner_system_acl(&self.file, &owner, self.acl_policy.is_protected(), true)
            .is_err()
            || directory_identity(&self.file)? != self.identity
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        self.publish_into_parent(
            destination_parent.as_file(),
            destination_leaf,
            destination_parent.identity.clone(),
        )
    }

    fn publish_into_parent(
        mut self,
        destination_parent: &File,
        destination_leaf: &str,
        parent_identity: WindowsFileIdentity,
    ) -> Result<Self, WorkspaceError> {
        validate_leaf(destination_leaf)?;
        let owner = OwnedSid::from_string(&self.owner_sid)?;
        if verify_owner_system_acl(&self.file, &owner, self.acl_policy.is_protected(), true)
            .is_err()
            || directory_identity(&self.file)? != self.identity
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        rename_relative(
            &self.file,
            destination_parent,
            std::ffi::OsStr::new(destination_leaf),
        )
        .map_err(rename_error)?;
        clear_short_name(&self.file)?;
        let identity = file_identity(&self.file)?;
        if identity.volume_serial_number != self.identity.volume_serial_number
            || identity.file_id != self.identity.file_id
            || directory_identity(destination_parent)? != parent_identity
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        verify_owner_system_acl(&self.file, &owner, self.acl_policy.is_protected(), true)?;
        verify_created_child(destination_parent, destination_leaf, &self.file, true)?;
        verify_exact_child_entry(destination_parent, destination_leaf, &identity)?;
        self.identity = identity;
        Ok(self)
    }

    pub fn create_directory_new(
        &self,
        leaf: &str,
    ) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
        self.create_directory_new_with_policy(leaf, self.acl_policy)
    }

    pub fn create_directory_new_with_policy(
        &self,
        leaf: &str,
        policy: WorkspaceAclPolicy,
    ) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
        let owner = OwnedSid::from_string(&self.owner_sid)?;
        if verify_owner_system_acl(&self.file, &owner, self.acl_policy.is_protected(), true)
            .is_err()
            || directory_identity(&self.file)? != self.identity
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        create_directory_handle_with_policy(
            &self.file,
            leaf,
            &self.owner_sid,
            policy.is_protected(),
        )
    }

    pub fn create_file_new(&self, leaf: &str) -> Result<CreatedWorkspaceFile, WorkspaceError> {
        let owner = OwnedSid::from_string(&self.owner_sid)?;
        if verify_owner_system_directory(&self.file, &owner)? != self.identity {
            return Err(WorkspaceError::IdentityRejected);
        }
        create_owner_system_file_handle(&self.file, leaf, &self.owner_sid)
    }

    pub fn reopen_file_readonly(&self, leaf: &str) -> Result<BoundWorkspaceFile, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_file_readonly(&self.file, leaf, &self.owner_sid)
    }
}

/// A strict read-only binding to an existing ordinary workspace directory.
/// The handle is opened relative to an already-held directory and the
/// original identity is retained for every subsequent operation.
#[derive(Debug)]
pub struct BoundWorkspaceDirectory {
    parent: File,
    file: File,
    identity: WindowsFileIdentity,
    parent_identity: WindowsFileIdentity,
    leaf: String,
    owner_sid: String,
    acl_policy: WorkspaceAclPolicy,
}

#[derive(Debug)]
pub struct BoundWorkspaceFile {
    parent: File,
    file: File,
    identity: WindowsFileIdentity,
    parent_identity: WindowsFileIdentity,
    leaf: String,
    owner_sid: String,
}

impl BoundWorkspaceFile {
    pub fn identity(&self) -> &WindowsFileIdentity {
        &self.identity
    }

    pub fn final_path(&self) -> &Path {
        Path::new(&self.identity.final_path)
    }

    pub fn as_file(&self) -> &File {
        &self.file
    }

    pub fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn revalidate(&self) -> Result<(), WorkspaceError> {
        let owner = OwnedSid::from_string(&self.owner_sid)?;
        if directory_identity(&self.parent)? != self.parent_identity
            || file_identity(&self.file)? != self.identity
            || !same_exact_path(
                self.final_path(),
                parent_final_path(&self.parent)?.join(&self.leaf),
            )
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        verify_owner_system_acl(&self.file, &owner, false, false)?;
        verify_created_child(&self.parent, &self.leaf, &self.file, false)?;
        verify_exact_child_entry(&self.parent, &self.leaf, &self.identity)
    }
}

impl BoundWorkspaceDirectory {
    /// Reopens an exact persisted protected directory binding for the current
    /// owner. This is observational and never creates, repairs, or adopts it.
    pub fn reopen_protected(expected: &WindowsFileIdentity) -> Result<Self, WorkspaceError> {
        let path = PathBuf::from(&expected.final_path);
        let parent_path = path.parent().ok_or(WorkspaceError::IdentityRejected)?;
        let leaf = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(WorkspaceError::IdentityRejected)?;
        validate_leaf(leaf)?;
        let parent = open_held_parent(parent_path)?;
        verify_local_acl_volume(&parent)?;
        if !is_fixed_volume(parent_path)? {
            return Err(WorkspaceError::InvalidParent);
        }
        let owner = CurrentUser::query()?;
        let bound = reopen_bound_directory_readonly(
            &parent,
            leaf,
            &owner.sid_string,
            WorkspaceAclPolicy::Protected,
        )?;
        if bound.identity != *expected {
            return Err(WorkspaceError::IdentityRejected);
        }
        bound.revalidate()?;
        Ok(bound)
    }

    pub fn identity(&self) -> &WindowsFileIdentity {
        &self.identity
    }

    pub fn final_path(&self) -> &Path {
        Path::new(&self.identity.final_path)
    }

    pub fn as_file(&self) -> &File {
        &self.file
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn revalidate(&self) -> Result<(), WorkspaceError> {
        let owner = OwnedSid::from_string(&self.owner_sid)?;
        if directory_identity(&self.parent)? != self.parent_identity {
            return Err(WorkspaceError::IdentityRejected);
        }
        verify_owner_system_acl(&self.file, &owner, self.acl_policy.is_protected(), true)?;
        if directory_identity(&self.file)? != self.identity
            || !same_exact_path(
                self.final_path(),
                parent_final_path(&self.parent)?.join(&self.leaf),
            )
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        Ok(())
    }

    pub fn reopen_directory(
        &self,
        leaf: &str,
        acl_policy: WorkspaceAclPolicy,
    ) -> Result<Self, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_directory(&self.file, leaf, &self.owner_sid, acl_policy)
    }

    pub fn reopen_directory_readonly(
        &self,
        leaf: &str,
        acl_policy: WorkspaceAclPolicy,
    ) -> Result<Self, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_directory_readonly(&self.file, leaf, &self.owner_sid, acl_policy)
    }

    /// Publish a recovered directory under another strict bound directory.
    /// The recovered no-delete handle is closed only after its identity and
    /// ACL have been revalidated; a transient delete-capable handle is then
    /// opened relative to the retained parent solely for the one rename, and
    /// the result is strictly rebound to a no-delete handle.
    pub fn publish_into_bound(
        self,
        destination_parent: &BoundWorkspaceDirectory,
        destination_leaf: &str,
    ) -> Result<Self, WorkspaceError> {
        self.revalidate()?;
        destination_parent.revalidate()?;
        if self.owner_sid != destination_parent.owner_sid {
            return Err(WorkspaceError::AclRejected);
        }
        validate_leaf(destination_leaf)?;
        let BoundWorkspaceDirectory {
            parent,
            file,
            identity,
            leaf,
            owner_sid,
            acl_policy,
            ..
        } = self;
        drop(file);
        let source = create_child_handle(
            &parent,
            &leaf,
            None,
            true,
            FILE_OPEN_DISPOSITION,
            true,
            true,
        )?;
        let source_identity = directory_identity(&source)?;
        if source_identity != identity {
            return Err(WorkspaceError::IdentityRejected);
        }
        let owner = OwnedSid::from_string(&owner_sid)?;
        verify_owner_system_acl(&source, &owner, acl_policy.is_protected(), true)?;
        verify_created_child(&parent, &leaf, &source, true)?;
        verify_exact_child_entry(&parent, &leaf, &identity)?;
        let created = CreatedWorkspaceDirectory {
            file: source,
            identity,
            owner_sid: owner_sid.clone(),
            acl_policy,
        };
        let published = created.publish_into_bound(destination_parent, destination_leaf)?;
        let expected_identity = published.identity.clone();
        drop(published);
        let rebound = reopen_bound_directory(
            destination_parent.as_file(),
            destination_leaf,
            &owner_sid,
            acl_policy,
        )?;
        if rebound.identity != expected_identity {
            return Err(WorkspaceError::IdentityRejected);
        }
        Ok(rebound)
    }

    pub fn create_directory_new(
        &self,
        leaf: &str,
    ) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
        self.create_directory_new_with_policy(leaf, self.acl_policy)
    }

    pub fn create_directory_new_with_policy(
        &self,
        leaf: &str,
        policy: WorkspaceAclPolicy,
    ) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
        self.revalidate()?;
        create_directory_handle_with_policy(
            &self.file,
            leaf,
            &self.owner_sid,
            policy.is_protected(),
        )
    }

    pub fn create_file_new(&self, leaf: &str) -> Result<CreatedWorkspaceFile, WorkspaceError> {
        self.revalidate()?;
        create_owner_system_file_handle(&self.file, leaf, &self.owner_sid)
    }

    pub fn reopen_file(&self, leaf: &str) -> Result<BoundWorkspaceFile, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_file(&self.file, leaf, &self.owner_sid)
    }

    pub fn reopen_file_readonly(&self, leaf: &str) -> Result<BoundWorkspaceFile, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_file_readonly(&self.file, leaf, &self.owner_sid)
    }
}

/// A newly-created owner-and-SYSTEM-protected workspace file.  The returned
/// handle is retained for the caller to write and verify without reopening by
/// path.
#[derive(Debug)]
pub struct CreatedWorkspaceFile {
    file: File,
    identity: WindowsFileIdentity,
    owner_sid: String,
}

impl CreatedWorkspaceFile {
    pub fn identity(&self) -> &WindowsFileIdentity {
        &self.identity
    }

    pub fn final_path(&self) -> &Path {
        Path::new(&self.identity.final_path)
    }

    pub fn as_file(&self) -> &File {
        &self.file
    }

    pub fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn revalidate(&self) -> Result<(), WorkspaceError> {
        let owner = OwnedSid::from_string(&self.owner_sid)?;
        verify_owner_system_acl(&self.file, &owner, false, false)?;
        if file_identity(&self.file)? != self.identity {
            return Err(WorkspaceError::IdentityRejected);
        }
        Ok(())
    }

    pub fn publish_into_bound(
        mut self,
        destination_parent: &BoundWorkspaceDirectory,
        destination_leaf: &str,
    ) -> Result<Self, WorkspaceError> {
        destination_parent.revalidate()?;
        if self.owner_sid != destination_parent.owner_sid {
            return Err(WorkspaceError::AclRejected);
        }
        let owner = OwnedSid::from_string(&self.owner_sid)?;
        if file_identity(&self.file)? != self.identity {
            return Err(WorkspaceError::IdentityRejected);
        }
        verify_owner_system_acl(&self.file, &owner, false, false)?;
        let parent_identity = destination_parent.identity.clone();
        rename_relative(
            &self.file,
            destination_parent.as_file(),
            std::ffi::OsStr::new(destination_leaf),
        )
        .map_err(rename_error)?;
        clear_short_name(&self.file)?;
        let identity = file_identity(&self.file)?;
        if identity.volume_serial_number != self.identity.volume_serial_number
            || identity.file_id != self.identity.file_id
            || directory_identity(destination_parent.as_file())? != parent_identity
        {
            return Err(WorkspaceError::IdentityRejected);
        }
        verify_owner_system_acl(&self.file, &owner, false, false)?;
        verify_created_child(
            destination_parent.as_file(),
            destination_leaf,
            &self.file,
            false,
        )?;
        verify_exact_child_entry(destination_parent.as_file(), destination_leaf, &identity)?;
        self.identity = identity;
        Ok(self)
    }
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
        let root_path = parent_path.join(leaf);
        let root =
            match create_owner_system_directory_handle(&parent_handle, leaf, &owner.sid_string) {
                Ok(value) => value,
                Err(WorkspaceError::AlreadyExists) => return Err(WorkspaceError::AlreadyExists),
                Err(error) => {
                    return Err(WorkspaceError::PartialWorkspace {
                        path: root_path.to_string_lossy().into_owned(),
                        detail: error.to_string(),
                    });
                }
            };
        let creation = (|| {
            let tools =
                create_owner_system_directory_handle(root.as_file(), "tools", &owner.sid_string)?;
            let output =
                create_owner_system_directory_handle(root.as_file(), "output", &owner.sid_string)?;

            let root_identity = root.identity.clone();
            let tools_identity = tools.identity.clone();
            let output_identity = output.identity.clone();
            let root_policy = root.acl_policy;
            let tools_policy = tools.acl_policy;
            let output_policy = output.acl_policy;
            drop(root);
            drop(tools);
            drop(output);
            let root_bound =
                reopen_bound_directory(&parent_handle, leaf, &owner.sid_string, root_policy)?;
            if root_bound.identity != root_identity {
                return Err(WorkspaceError::IdentityRejected);
            }
            let root_handle = root_bound.into_file();
            let tools_bound =
                reopen_bound_directory(&root_handle, "tools", &owner.sid_string, tools_policy)?;
            if tools_bound.identity != tools_identity {
                return Err(WorkspaceError::IdentityRejected);
            }
            let tools_handle = tools_bound.into_file();
            let output_bound =
                reopen_bound_directory(&root_handle, "output", &owner.sid_string, output_policy)?;
            if output_bound.identity != output_identity {
                return Err(WorkspaceError::IdentityRejected);
            }
            let output_handle = output_bound.into_file();

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
                    schema_version: WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
                    policy: WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
                    security_policy_sha256: workspace_policy_hash(&owner.sid_string),
                    owner_sid: owner.sid_string.clone(),
                    dacl_protected: true,
                    allowed_sids: vec![WINDOWS_SYSTEM_SID.to_owned(), owner.sid_string.clone()],
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

    /// Reopens an already-created workspace only when every persisted binding
    /// still names the current owner and the exact same protected directories.
    /// This recovery path is read-only: it never creates, deletes, adopts, or
    /// repairs a directory and never changes ownership or an ACL.
    pub fn reopen_bound(expected: &WorkspaceBindingEvidence) -> Result<Self, WorkspaceError> {
        expected
            .validate()
            .map_err(|_| WorkspaceError::IdentityRejected)?;

        let owner = CurrentUser::query()?;
        if expected.owner_sid != owner.sid_string
            || expected.security_policy_sha256 != workspace_policy_hash(&owner.sid_string)
            || expected.allowed_sids.len() != 2
            || !expected
                .allowed_sids
                .iter()
                .any(|sid| sid == &owner.sid_string)
            || !expected
                .allowed_sids
                .iter()
                .any(|sid| sid == WINDOWS_SYSTEM_SID)
        {
            return Err(WorkspaceError::AclRejected);
        }

        let parent_path = PathBuf::from(&expected.parent.final_path);
        let root_path = PathBuf::from(&expected.root.final_path);
        let tools_path = PathBuf::from(&expected.tools.final_path);
        let output_path = PathBuf::from(&expected.output.final_path);
        if !parent_path.is_absolute()
            || !root_path.is_absolute()
            || !tools_path.is_absolute()
            || !output_path.is_absolute()
            || root_path
                .parent()
                .is_none_or(|path| !same_path(path, &parent_path))
            || !same_path(&tools_path, root_path.join("tools"))
            || !same_path(&output_path, root_path.join("output"))
        {
            return Err(WorkspaceError::IdentityRejected);
        }

        let parent = open_held_directory(&parent_path)?;
        verify_local_acl_volume(&parent)?;
        if !is_fixed_volume(&parent_path)? || directory_identity(&parent)? != expected.parent {
            return Err(WorkspaceError::IdentityRejected);
        }

        let root = open_held_directory(&root_path)?;
        let tools = open_held_directory(&tools_path)?;
        let output = open_held_directory(&output_path)?;
        if verify_owner_system_directory(&root, &owner.sid)? != expected.root
            || verify_owner_system_directory(&tools, &owner.sid)? != expected.tools
            || verify_owner_system_directory(&output, &owner.sid)? != expected.output
            || expected.root.volume_serial_number != expected.parent.volume_serial_number
            || expected.tools.volume_serial_number != expected.parent.volume_serial_number
            || expected.output.volume_serial_number != expected.parent.volume_serial_number
        {
            return Err(WorkspaceError::IdentityRejected);
        }

        let workspace = Self {
            parent,
            root,
            tools,
            output,
            root_path,
            evidence: expected.clone(),
        };
        workspace.revalidate()?;
        Ok(workspace)
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

    /// Create a new protected file directly below the held workspace root.
    pub fn create_root_file_new(&self, leaf: &str) -> Result<CreatedWorkspaceFile, WorkspaceError> {
        self.revalidate()?;
        create_owner_system_file_handle(&self.root, leaf, &self.evidence.owner_sid)
    }

    pub fn create_root_directory_new(
        &self,
        leaf: &str,
    ) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
        self.create_root_directory_new_with_policy(leaf, WorkspaceAclPolicy::Protected)
    }

    pub fn create_root_directory_new_with_policy(
        &self,
        leaf: &str,
        policy: WorkspaceAclPolicy,
    ) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
        self.revalidate()?;
        create_directory_handle_with_policy(
            &self.root,
            leaf,
            &self.evidence.owner_sid,
            policy.is_protected(),
        )
    }

    /// Create a new protected file directly below the held tools directory.
    pub fn create_tools_file_new(
        &self,
        leaf: &str,
    ) -> Result<CreatedWorkspaceFile, WorkspaceError> {
        self.revalidate()?;
        create_owner_system_file_handle(&self.tools, leaf, &self.evidence.owner_sid)
    }

    pub fn create_tools_directory_new(
        &self,
        leaf: &str,
    ) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
        self.create_tools_directory_new_with_policy(leaf, WorkspaceAclPolicy::Protected)
    }

    pub fn create_tools_directory_new_with_policy(
        &self,
        leaf: &str,
        policy: WorkspaceAclPolicy,
    ) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
        self.revalidate()?;
        create_directory_handle_with_policy(
            &self.tools,
            leaf,
            &self.evidence.owner_sid,
            policy.is_protected(),
        )
    }

    /// Create a new protected file directly below the held output directory.
    pub fn create_output_file_new(
        &self,
        leaf: &str,
    ) -> Result<CreatedWorkspaceFile, WorkspaceError> {
        self.revalidate()?;
        create_owner_system_file_handle(&self.output, leaf, &self.evidence.owner_sid)
    }

    pub fn create_output_directory_new(
        &self,
        leaf: &str,
    ) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
        self.create_output_directory_new_with_policy(leaf, WorkspaceAclPolicy::Protected)
    }

    pub fn create_output_directory_new_with_policy(
        &self,
        leaf: &str,
        policy: WorkspaceAclPolicy,
    ) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
        self.revalidate()?;
        create_directory_handle_with_policy(
            &self.output,
            leaf,
            &self.evidence.owner_sid,
            policy.is_protected(),
        )
    }

    /// Strictly reopen an existing immediate child below the workspace root.
    /// `protected_acl` selects the fixed ACL form expected for that child.
    pub fn reopen_root_directory(
        &self,
        leaf: &str,
        acl_policy: WorkspaceAclPolicy,
    ) -> Result<BoundWorkspaceDirectory, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_directory(&self.root, leaf, &self.evidence.owner_sid, acl_policy)
    }

    pub fn reopen_root_file(&self, leaf: &str) -> Result<BoundWorkspaceFile, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_file(&self.root, leaf, &self.evidence.owner_sid)
    }

    pub fn reopen_tools_directory(
        &self,
        leaf: &str,
        acl_policy: WorkspaceAclPolicy,
    ) -> Result<BoundWorkspaceDirectory, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_directory(&self.tools, leaf, &self.evidence.owner_sid, acl_policy)
    }

    pub fn reopen_tools_file(&self, leaf: &str) -> Result<BoundWorkspaceFile, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_file(&self.tools, leaf, &self.evidence.owner_sid)
    }

    pub fn reopen_output_directory(
        &self,
        leaf: &str,
        acl_policy: WorkspaceAclPolicy,
    ) -> Result<BoundWorkspaceDirectory, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_directory(&self.output, leaf, &self.evidence.owner_sid, acl_policy)
    }

    pub fn reopen_output_file(&self, leaf: &str) -> Result<BoundWorkspaceFile, WorkspaceError> {
        self.revalidate()?;
        reopen_bound_file(&self.output, leaf, &self.evidence.owner_sid)
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
            open_held_directory(current_parent_path).and_then(|file| directory_identity(&file))?;
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

fn validate_new_child_leaf(leaf: &str) -> Result<(), WorkspaceError> {
    if leaf.is_empty()
        || leaf.len() > 255
        || leaf.ends_with(['.', ' '])
        || !leaf
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !(leaf.as_bytes()[0].is_ascii_alphanumeric() || leaf.as_bytes()[0] == b'.')
    {
        return Err(WorkspaceError::InvalidLeaf);
    }
    let stem = leaf.split('.').next().unwrap_or_default();
    let upper = stem.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(upper.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(WorkspaceError::InvalidLeaf);
    }
    Ok(())
}

#[cfg(test)]
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
    match unsafe {
        windows::Win32::Storage::FileSystem::CreateDirectoryW(
            PCWSTR(wide.as_ptr()),
            Some(&attributes),
        )
    } {
        Ok(()) => Ok(()),
        Err(error) if matches!(error.code().0 as u32, 0x8007_00b7 | 0x8007_0050) => {
            Err(WorkspaceError::AlreadyExists)
        }
        Err(error) => Err(native("CreateDirectoryW", error)),
    }
}

/// Create one new owner/SYSTEM-protected directory relative to a held parent
/// and return the creation handle.  This is intentionally not an
/// create-or-open helper: an existing name is always a conflict.
fn create_owner_system_directory_handle(
    parent: &File,
    leaf: &str,
    owner_sid: &str,
) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
    create_directory_handle_with_policy(parent, leaf, owner_sid, true)
}

fn create_directory_handle_with_policy(
    parent: &File,
    leaf: &str,
    owner_sid: &str,
    protected_acl: bool,
) -> Result<CreatedWorkspaceDirectory, WorkspaceError> {
    let descriptor = protected_acl
        .then(|| SecurityDescriptor::owner_system_only(owner_sid, true))
        .transpose()?;
    let file = create_child_handle(
        parent,
        leaf,
        descriptor.as_ref(),
        true,
        FILE_CREATE_DISPOSITION,
        true,
        true,
    )?;
    clear_short_name(&file)?;
    let owner = OwnedSid::from_string(owner_sid)?;
    verify_owner_system_acl(&file, &owner, protected_acl, true)?;
    let identity = directory_identity(&file)?;
    verify_created_child(parent, leaf, &file, true)?;
    Ok(CreatedWorkspaceDirectory {
        file,
        identity,
        owner_sid: owner_sid.to_owned(),
        acl_policy: if protected_acl {
            WorkspaceAclPolicy::Protected
        } else {
            WorkspaceAclPolicy::Inherited
        },
    })
}

/// Create one new owner/SYSTEM-protected file relative to a held parent and
/// return the creation handle.  The handle is opened without delete sharing;
/// callers can write and flush it without a path reopen or adoption race.
fn create_owner_system_file_handle(
    parent: &File,
    leaf: &str,
    owner_sid: &str,
) -> Result<CreatedWorkspaceFile, WorkspaceError> {
    // Files inherit the protected owner/SYSTEM DACL from their held parent.
    // An explicit file descriptor would produce an unprotected DACL that does
    // not match the fixed WSB inventory contract.
    let file = create_child_handle(
        parent,
        leaf,
        None,
        false,
        FILE_CREATE_DISPOSITION,
        true,
        true,
    )?;
    clear_short_name(&file)?;
    let owner = OwnedSid::from_string(owner_sid)?;
    verify_owner_system_acl(&file, &owner, false, false)?;
    let identity = file_identity(&file)?;
    verify_created_child(parent, leaf, &file, false)?;
    Ok(CreatedWorkspaceFile {
        file,
        identity,
        owner_sid: owner_sid.to_owned(),
    })
}

fn reopen_bound_directory(
    parent: &File,
    leaf: &str,
    owner_sid: &str,
    acl_policy: WorkspaceAclPolicy,
) -> Result<BoundWorkspaceDirectory, WorkspaceError> {
    validate_new_child_leaf(leaf)?;
    let owner = OwnedSid::from_string(owner_sid)?;
    let parent_identity = directory_identity(parent)?;
    let file = create_child_handle(
        parent,
        leaf,
        None,
        true,
        FILE_OPEN_DISPOSITION,
        false,
        false,
    )?;
    verify_owner_system_acl(&file, &owner, acl_policy.is_protected(), true)?;
    let identity = directory_identity(&file)?;
    verify_created_child(parent, leaf, &file, true)?;
    verify_exact_child_entry(parent, leaf, &identity)?;
    if directory_identity(parent)? != parent_identity {
        return Err(WorkspaceError::IdentityRejected);
    }
    let parent_handle = parent.try_clone().map_err(|error| WorkspaceError::Native {
        operation: "DuplicateHandle(bound-directory-parent)",
        detail: error.to_string(),
    })?;
    Ok(BoundWorkspaceDirectory {
        parent: parent_handle,
        file,
        identity,
        parent_identity,
        leaf: leaf.to_owned(),
        owner_sid: owner_sid.to_owned(),
        acl_policy,
    })
}

fn reopen_bound_file(
    parent: &File,
    leaf: &str,
    owner_sid: &str,
) -> Result<BoundWorkspaceFile, WorkspaceError> {
    validate_new_child_leaf(leaf)?;
    let owner = OwnedSid::from_string(owner_sid)?;
    let parent_identity = directory_identity(parent)?;
    let file = create_child_handle(
        parent,
        leaf,
        None,
        false,
        FILE_OPEN_DISPOSITION,
        false,
        true,
    )?;
    verify_owner_system_acl(&file, &owner, false, false)?;
    let identity = file_identity(&file)?;
    verify_created_child(parent, leaf, &file, false)?;
    verify_exact_child_entry(parent, leaf, &identity)?;
    if directory_identity(parent)? != parent_identity {
        return Err(WorkspaceError::IdentityRejected);
    }
    let parent_handle = parent.try_clone().map_err(|error| WorkspaceError::Native {
        operation: "DuplicateHandle(bound-file-parent)",
        detail: error.to_string(),
    })?;
    Ok(BoundWorkspaceFile {
        parent: parent_handle,
        file,
        identity,
        parent_identity,
        leaf: leaf.to_owned(),
        owner_sid: owner_sid.to_owned(),
    })
}

fn reopen_bound_directory_readonly(
    parent: &File,
    leaf: &str,
    owner_sid: &str,
    acl_policy: WorkspaceAclPolicy,
) -> Result<BoundWorkspaceDirectory, WorkspaceError> {
    validate_new_child_leaf(leaf)?;
    let owner = OwnedSid::from_string(owner_sid)?;
    let parent_identity = directory_identity(parent)?;
    let file = open_child_read_authority(parent, leaf, true)?;
    verify_owner_system_acl(&file, &owner, acl_policy.is_protected(), true)?;
    let identity = directory_identity(&file)?;
    verify_created_child(parent, leaf, &file, true)?;
    verify_exact_child_entry(parent, leaf, &identity)?;
    if directory_identity(parent)? != parent_identity {
        return Err(WorkspaceError::IdentityRejected);
    }
    let parent_handle = parent.try_clone().map_err(|error| WorkspaceError::Native {
        operation: "DuplicateHandle(readonly-bound-directory-parent)",
        detail: error.to_string(),
    })?;
    Ok(BoundWorkspaceDirectory {
        parent: parent_handle,
        file,
        identity,
        parent_identity,
        leaf: leaf.to_owned(),
        owner_sid: owner_sid.to_owned(),
        acl_policy,
    })
}

fn reopen_bound_file_readonly(
    parent: &File,
    leaf: &str,
    owner_sid: &str,
) -> Result<BoundWorkspaceFile, WorkspaceError> {
    validate_new_child_leaf(leaf)?;
    let owner = OwnedSid::from_string(owner_sid)?;
    let parent_identity = directory_identity(parent)?;
    let file = open_child_read_authority(parent, leaf, false)?;
    verify_owner_system_acl(&file, &owner, false, false)?;
    let identity = file_identity(&file)?;
    verify_created_child(parent, leaf, &file, false)?;
    verify_exact_child_entry(parent, leaf, &identity)?;
    if directory_identity(parent)? != parent_identity {
        return Err(WorkspaceError::IdentityRejected);
    }
    let parent_handle = parent.try_clone().map_err(|error| WorkspaceError::Native {
        operation: "DuplicateHandle(readonly-bound-file-parent)",
        detail: error.to_string(),
    })?;
    Ok(BoundWorkspaceFile {
        parent: parent_handle,
        file,
        identity,
        parent_identity,
        leaf: leaf.to_owned(),
        owner_sid: owner_sid.to_owned(),
    })
}

fn verify_exact_child_entry(
    parent: &File,
    leaf: &str,
    identity: &WindowsFileIdentity,
) -> Result<(), WorkspaceError> {
    let mut last_error = None;
    let entry = (0..4)
        .find_map(|_| match exact_directory_entry(parent, leaf) {
            Ok(entry) => Some(entry),
            Err(error) => {
                last_error = Some(error);
                std::thread::yield_now();
                None
            }
        })
        .ok_or_else(|| WorkspaceError::Native {
            operation: "GetFileInformationByHandleEx(exact-child-entry)",
            detail: last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "exact child entry was not observed".to_owned()),
        })?;
    let expected_file_id =
        hex::decode(&identity.file_id).map_err(|_| WorkspaceError::IdentityRejected)?;
    if expected_file_id.as_slice() != entry.file_id
        || entry.name != leaf
        || entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(WorkspaceError::IdentityRejected);
    }
    Ok(())
}

fn open_child_read_authority(
    parent: &File,
    leaf: &str,
    directory: bool,
) -> Result<File, WorkspaceError> {
    validate_new_child_leaf(leaf)?;
    let mut name: Vec<u16> = leaf.encode_utf16().collect();
    let mut unicode = NtUnicodeString {
        length: u16::try_from(name.len() * 2).map_err(|_| WorkspaceError::InvalidLeaf)?,
        maximum_length: u16::try_from(name.len() * 2).map_err(|_| WorkspaceError::InvalidLeaf)?,
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
    let create_options = if directory {
        FILE_DIRECTORY_CREATE_OPTION
    } else {
        FILE_NON_DIRECTORY_CREATE_OPTION
    } | FILE_SYNCHRONOUS_IO_NONALERT_OPTION
        | FILE_FLAG_OPEN_REPARSE_POINT.0;
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
            FILE_ATTRIBUTE_NORMAL.0,
            FILE_SHARE_READ.0,
            FILE_OPEN_DISPOSITION,
            create_options,
            std::ptr::null_mut(),
            0,
        )
    };
    if status < 0 || handle.is_null() {
        return Err(WorkspaceError::Native {
            operation: "NtCreateFile(relative-read-authority)",
            detail: format!("ntstatus=0x{:08x}", status as u32),
        });
    }
    // SAFETY: NtCreateFile returned a uniquely owned kernel handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn create_child_handle(
    parent: &File,
    leaf: &str,
    descriptor: Option<&SecurityDescriptor>,
    directory: bool,
    disposition: u32,
    mutating: bool,
    writable: bool,
) -> Result<File, WorkspaceError> {
    validate_new_child_leaf(leaf)?;
    let mut name: Vec<u16> = leaf.encode_utf16().collect();
    let mut unicode = NtUnicodeString {
        length: u16::try_from(name.len() * 2).map_err(|_| WorkspaceError::InvalidLeaf)?,
        maximum_length: u16::try_from(name.len() * 2).map_err(|_| WorkspaceError::InvalidLeaf)?,
        buffer: name.as_mut_ptr(),
    };
    let mut attributes = NtObjectAttributes {
        length: size_of::<NtObjectAttributes>() as u32,
        root_directory: raw_handle(parent).0,
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: descriptor.map_or(std::ptr::null_mut(), |value| value.0.0),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let desired_access = if !mutating && directory {
        FILE_LIST_DIRECTORY.0
            | FILE_READ_ATTRIBUTES.0
            | FILE_READ_EA.0
            | READ_CONTROL.0
            | SYNCHRONIZE.0
    } else if !mutating && writable {
        FILE_READ_DATA.0
            | FILE_WRITE_DATA.0
            | FILE_READ_ATTRIBUTES.0
            | READ_CONTROL.0
            | SYNCHRONIZE.0
    } else if !mutating {
        FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0
    } else if directory {
        FILE_LIST_DIRECTORY.0
            | FILE_ADD_SUBDIRECTORY.0
            | FILE_READ_ATTRIBUTES.0
            | FILE_READ_EA.0
            | FILE_WRITE_ATTRIBUTES.0
            | DELETE.0
            | READ_CONTROL.0
            | SYNCHRONIZE.0
    } else {
        FILE_READ_DATA.0
            | FILE_WRITE_DATA.0
            | FILE_READ_EA.0
            | FILE_WRITE_EA.0
            | FILE_READ_ATTRIBUTES.0
            | FILE_WRITE_ATTRIBUTES.0
            | DELETE.0
            | READ_CONTROL.0
            | SYNCHRONIZE.0
    };
    let share_access = if !mutating {
        FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0
    } else if directory {
        FILE_SHARE_DELETE.0 | FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0
    } else {
        FILE_SHARE_READ.0
    };
    let create_options = if directory {
        FILE_DIRECTORY_CREATE_OPTION
    } else {
        FILE_NON_DIRECTORY_CREATE_OPTION
    } | FILE_SYNCHRONOUS_IO_NONALERT_OPTION
        | FILE_WRITE_THROUGH_OPTION
        | FILE_FLAG_OPEN_REPARSE_POINT.0;
    let mut handle = std::ptr::null_mut();
    let mut io_status = NtIoStatusBlock {
        status: 0,
        information: 0,
    };
    // SAFETY: all pointers reference stack/local buffers valid through the
    // call; NtCreateFile returns ownership of a new handle only on success.
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
            create_options,
            std::ptr::null_mut(),
            0,
        )
    };
    if status == STATUS_OBJECT_NAME_COLLISION {
        return Err(WorkspaceError::AlreadyExists);
    }
    if status < 0 || handle.is_null() {
        return Err(WorkspaceError::Native {
            operation: "NtCreateFile(relative-create-new)",
            detail: format!("ntstatus=0x{:08x}", status as u32),
        });
    }
    // SAFETY: NtCreateFile returned a uniquely owned kernel handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn clear_short_name(file: &File) -> Result<(), WorkspaceError> {
    let empty = [0_u16];
    unsafe { SetFileShortNameW(raw_handle(file), PCWSTR(empty.as_ptr())) }
        .map_err(|error| native("SetFileShortNameW(clear)", error))
}

fn verify_created_child(
    parent: &File,
    leaf: &str,
    file: &File,
    directory: bool,
) -> Result<(), WorkspaceError> {
    let attributes = basic_attributes(file)?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || (directory && attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0)
        || (!directory && attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0)
    {
        return Err(WorkspaceError::IdentityRejected);
    }
    if !same_exact_path(final_path(file)?, parent_final_path(parent)?.join(leaf)) {
        return Err(WorkspaceError::IdentityRejected);
    }
    if basic_link_count(file)? != 1 {
        return Err(WorkspaceError::IdentityRejected);
    }
    Ok(())
}

fn parent_final_path(parent: &File) -> Result<PathBuf, WorkspaceError> {
    final_path(parent)
}

fn basic_attributes(file: &File) -> Result<u32, WorkspaceError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file owns a valid handle and `info` is writable.
    unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) }
        .map_err(|error| native("GetFileInformationByHandle(child)", error))?;
    Ok(info.dwFileAttributes)
}

fn basic_link_count(file: &File) -> Result<u32, WorkspaceError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file owns a valid handle and `info` is writable.
    unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) }
        .map_err(|error| native("GetFileInformationByHandle(link-count)", error))?;
    Ok(info.nNumberOfLinks)
}

#[cfg(test)]
pub(crate) fn create_owner_system_directory(
    path: &Path,
    owner_sid: &str,
) -> Result<(), WorkspaceError> {
    let descriptor = SecurityDescriptor::owner_system_only(owner_sid, true)?;
    create_directory(path, &descriptor)
}

pub(crate) fn create_owner_system_file(
    path: &Path,
    owner_sid: &str,
) -> Result<File, WorkspaceError> {
    let descriptor = SecurityDescriptor::owner_system_only(owner_sid, false)?;
    let wide = wide_path(path)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: path and descriptor remain valid through this non-inheritable
    // CREATE_NEW call. A successful handle owns the newly created exact file.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_DATA.0
                | FILE_WRITE_DATA.0
                | FILE_READ_EA.0
                | FILE_WRITE_EA.0
                | FILE_READ_ATTRIBUTES.0
                | READ_CONTROL.0
                | DELETE.0
                | SYNCHRONIZE.0,
            FILE_SHARE_READ,
            Some(&attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            None,
        )
    };
    match handle {
        Ok(handle) => {
            // SAFETY: CreateFileW returned a uniquely owned kernel handle.
            Ok(unsafe { File::from_raw_handle(handle.0) })
        }
        Err(error) if matches!(error.code().0 as u32, 0x8007_00b7 | 0x8007_0050) => {
            Err(WorkspaceError::AlreadyExists)
        }
        Err(error) => Err(native("CreateFileW(owner-system-file)", error)),
    }
}

fn open_held_directory(path: &Path) -> Result<File, WorkspaceError> {
    let file = OpenOptions::new()
        .access_mode(
            FILE_READ_ATTRIBUTES.0
                | FILE_LIST_DIRECTORY.0
                | FILE_ADD_FILE.0
                | FILE_ADD_SUBDIRECTORY.0
                | READ_CONTROL.0
                | SYNCHRONIZE.0,
        )
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
            FILE_READ_ATTRIBUTES.0
                | FILE_LIST_DIRECTORY.0
                | FILE_ADD_FILE.0
                | FILE_ADD_SUBDIRECTORY.0
                | READ_CONTROL.0
                | SYNCHRONIZE.0,
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

pub(crate) fn verify_local_acl_volume(file: &File) -> Result<(), WorkspaceError> {
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

fn directory_identity(file: &File) -> Result<WindowsFileIdentity, WorkspaceError> {
    let identity = file_identity(file)?;
    let attributes = basic_attributes(file)?;
    if attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(WorkspaceError::IdentityRejected);
    }
    Ok(identity)
}

fn file_identity(file: &File) -> Result<WindowsFileIdentity, WorkspaceError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file owns a valid held handle and `info` is writable.
    unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) }
        .map_err(|error| native("GetFileInformationByHandle", error))?;
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
    Ok(WindowsFileIdentity {
        final_path: final_path(file)?.to_string_lossy().into_owned(),
        volume_serial_number: format!("{:016x}", file_id.VolumeSerialNumber),
        file_id: hex::encode(file_id.FileId.Identifier),
    })
}

pub(crate) fn verify_owner_system_directory(
    file: &File,
    expected_owner: &OwnedSid,
) -> Result<WindowsFileIdentity, WorkspaceError> {
    verify_owner_system_acl(file, expected_owner, true, true)?;
    directory_identity(file)
}

pub(crate) fn verify_owner_system_acl(
    file: &File,
    expected_owner: &OwnedSid,
    require_protected: bool,
    directory: bool,
) -> Result<(), WorkspaceError> {
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
    verify_acl(
        descriptor.0,
        dacl,
        expected_owner,
        require_protected,
        directory,
    )
}

fn verify_acl(
    descriptor: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
    expected_owner: &OwnedSid,
    require_protected: bool,
    directory: bool,
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
    if (require_protected != (control & SE_DACL_PROTECTED.0 != 0))
        || control & SE_DACL_PRESENT.0 == 0
        || control & SE_DACL_DEFAULTED.0 != 0
        || control & SE_OWNER_DEFAULTED.0 != 0
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
    let system = OwnedSid::from_string(WINDOWS_SYSTEM_SID)?;
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
        let flags = u32::from(ace.Header.AceFlags);
        let inheritance = if directory {
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).0
        } else {
            0
        };
        let flags_valid = flags
            == if require_protected {
                inheritance
            } else {
                inheritance | INHERITED_ACE.0
            };
        if !flags_valid || ace.Mask != FILE_ALL_ACCESS.0 {
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

pub(crate) fn is_fixed_volume(path: &Path) -> Result<bool, WorkspaceError> {
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

pub(crate) fn final_path(file: &File) -> Result<PathBuf, WorkspaceError> {
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

pub(crate) fn same_path(left: impl AsRef<Path>, right: impl AsRef<Path>) -> bool {
    normalized_path(left.as_ref()).eq_ignore_ascii_case(&normalized_path(right.as_ref()))
}

fn same_exact_path(left: impl AsRef<Path>, right: impl AsRef<Path>) -> bool {
    normalized_path(left.as_ref()) == normalized_path(right.as_ref())
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

pub(crate) fn raw_handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}

fn native(operation: &'static str, error: windows::core::Error) -> WorkspaceError {
    WorkspaceError::Native {
        operation,
        detail: error.to_string(),
    }
}

fn rename_error(error: ExactDisposeError) -> WorkspaceError {
    WorkspaceError::Native {
        operation: "NtSetInformationFile(FileRenameInformation)",
        detail: error.to_string(),
    }
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

pub(crate) struct OwnedSid(PSID);

impl OwnedSid {
    pub(crate) fn from_string(value: &str) -> Result<Self, WorkspaceError> {
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
    fn owner_system_only(owner_sid: &str, directory: bool) -> Result<Self, WorkspaceError> {
        let inheritance = if directory { "OICI" } else { "" };
        let sddl =
            format!("O:{owner_sid}D:P(A;{inheritance};FA;;;{owner_sid})(A;{inheritance};FA;;;SY)");
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
    use std::io::{Read, Seek, SeekFrom, Write};

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
        assert_eq!(
            workspace.evidence().schema_version,
            WINDOWS_WORKSPACE_SCHEMA_VERSION
        );
        assert_eq!(
            workspace.evidence().policy,
            WINDOWS_WORKSPACE_SECURITY_POLICY
        );
        workspace.evidence().validate().unwrap();
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
    fn reopens_only_the_exact_persisted_workspace_binding() {
        let name = leaf("reopen");
        let path = parent().join(&name);
        let _ = std::fs::remove_dir_all(&path);
        let workspace = HeldRunWorkspace::create(&parent(), &name).unwrap();
        let evidence = workspace.evidence().clone();
        drop(workspace);

        let reopened = HeldRunWorkspace::reopen_bound(&evidence).unwrap();
        assert_eq!(reopened.evidence(), &evidence);
        reopened.revalidate().unwrap();
        remove_test_workspace(reopened);
    }

    #[test]
    fn recovery_rejects_persisted_identity_or_owner_drift() {
        let name = leaf("binding-drift");
        let path = parent().join(&name);
        let _ = std::fs::remove_dir_all(&path);
        let workspace = HeldRunWorkspace::create(&parent(), &name).unwrap();
        let evidence = workspace.evidence().clone();
        drop(workspace);

        let mut identity_drift = evidence.clone();
        identity_drift.root.file_id = "0".repeat(32);
        assert!(matches!(
            HeldRunWorkspace::reopen_bound(&identity_drift),
            Err(WorkspaceError::IdentityRejected)
        ));

        let mut owner_drift = evidence.clone();
        owner_drift.owner_sid = "S-1-5-19".to_owned();
        owner_drift.allowed_sids = vec![WINDOWS_SYSTEM_SID.to_owned(), "S-1-5-19".to_owned()];
        owner_drift.security_policy_sha256 = workspace_policy_hash("S-1-5-19");
        assert!(matches!(
            HeldRunWorkspace::reopen_bound(&owner_drift),
            Err(WorkspaceError::AclRejected)
        ));

        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn recovery_rejects_acl_drift_without_repairing_it() {
        let name = leaf("acl-drift");
        let path = parent().join(&name);
        let _ = std::fs::remove_dir_all(&path);
        let workspace = HeldRunWorkspace::create(&parent(), &name).unwrap();
        let evidence = workspace.evidence().clone();
        drop(workspace);

        let handle = OpenOptions::new()
            .access_mode(READ_CONTROL.0 | windows::Win32::Storage::FileSystem::WRITE_DAC.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(&path)
            .unwrap();
        let result = unsafe {
            windows::Win32::Security::Authorization::SetSecurityInfo(
                raw_handle(&handle),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION
                    | windows::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(std::ptr::null()),
                None,
            )
        };
        assert_eq!(result.0, 0);
        drop(handle);

        assert!(matches!(
            HeldRunWorkspace::reopen_bound(&evidence),
            Err(WorkspaceError::AclRejected)
        ));
        // Recovery is deliberately non-repairing; the drift remains observable.
        let reopened = open_held_directory(&path).unwrap();
        assert!(matches!(
            verify_owner_system_directory(&reopened, &CurrentUser::query().unwrap().sid),
            Err(WorkspaceError::AclRejected)
        ));
        drop(reopened);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn recovery_rejects_path_replacement() {
        let name = leaf("replacement");
        let path = parent().join(&name);
        let moved = parent().join(format!("{name}-original"));
        let _ = std::fs::remove_dir_all(&path);
        let _ = std::fs::remove_dir_all(&moved);
        let workspace = HeldRunWorkspace::create(&parent(), &name).unwrap();
        let evidence = workspace.evidence().clone();
        drop(workspace);

        std::fs::rename(&path, &moved).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(HeldRunWorkspace::reopen_bound(&evidence).is_err());

        std::fs::remove_dir(&path).unwrap();
        std::fs::remove_dir_all(&moved).unwrap();
    }

    #[test]
    fn refuses_to_adopt_or_repair_an_existing_leaf() {
        let name = leaf("existing");
        let path = parent().join(&name);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        let error = HeldRunWorkspace::create(&parent(), &name).unwrap_err();
        assert!(matches!(error, WorkspaceError::AlreadyExists), "{error:?}");
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

    #[test]
    fn native_file_creation_returns_exact_handle_and_rejects_reuse() {
        let name = leaf("file-handle");
        let path = parent().join(&name);
        let _ = std::fs::remove_dir_all(&path);
        let workspace = HeldRunWorkspace::create(&parent(), &name).unwrap();

        let nested = workspace.create_root_directory_new("nested").unwrap();
        assert!(same_path(nested.final_path(), path.join("nested")));
        assert_eq!(
            nested.identity(),
            &directory_identity(nested.as_file()).unwrap()
        );
        let nested_file = nested.create_file_new("nested.txt").unwrap();
        assert!(same_path(
            nested_file.final_path(),
            path.join("nested").join("nested.txt")
        ));
        drop(nested_file);

        let destination = workspace.create_root_directory_new("destination").unwrap();
        drop(destination);
        let destination_bound = workspace
            .reopen_root_directory("destination", WorkspaceAclPolicy::Protected)
            .unwrap();
        let published = nested
            .publish_into_bound(&destination_bound, "published")
            .unwrap();
        assert!(same_path(
            published.final_path(),
            path.join("destination").join("published")
        ));
        assert_eq!(
            published.identity().file_id,
            directory_identity(published.as_file()).unwrap().file_id
        );
        let occupied = destination_bound.create_directory_new("occupied").unwrap();
        let source = workspace.create_root_directory_new("source").unwrap();
        assert!(
            source
                .publish_into_bound(&destination_bound, "occupied")
                .is_err()
        );
        assert!(path.join("source").is_dir());
        let mut published_file = workspace.create_tools_file_new("published.txt").unwrap();
        published_file
            .as_file_mut()
            .write_all(b"published-file")
            .unwrap();
        published_file.as_file_mut().sync_all().unwrap();
        let published_file = published_file
            .publish_into_bound(&destination_bound, "published.txt")
            .unwrap();
        assert!(same_path(
            published_file.final_path(),
            path.join("destination").join("published.txt")
        ));
        drop(published_file);
        drop(occupied);
        drop(published);
        drop(destination_bound);

        let mut created = workspace.create_tools_file_new("created.txt").unwrap();
        assert!(same_path(
            created.final_path(),
            path.join("tools").join("created.txt")
        ));
        assert_eq!(
            created.identity(),
            &file_identity(created.as_file()).unwrap()
        );
        created.as_file_mut().write_all(b"native-created").unwrap();
        created.as_file_mut().sync_all().unwrap();
        created.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        created.as_file_mut().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"native-created");

        assert!(matches!(
            workspace.create_tools_file_new("created.txt"),
            Err(WorkspaceError::AlreadyExists)
        ));
        assert!(matches!(
            workspace.create_tools_file_new("created.txt:ads"),
            Err(WorkspaceError::InvalidLeaf)
        ));
        drop(created);
        remove_test_workspace(workspace);
        assert!(!path.exists());
    }

    #[test]
    fn bound_directory_reopens_strictly_and_creates_inherited_children() {
        let name = leaf("bound-directory");
        let path = parent().join(&name);
        let _ = std::fs::remove_dir_all(&path);
        let workspace = HeldRunWorkspace::create(&parent(), &name).unwrap();

        let runs = workspace
            .create_root_directory_new_with_policy("runs", WorkspaceAclPolicy::Inherited)
            .unwrap();
        let runs_identity = runs.identity().clone();
        drop(runs);
        let bound = workspace
            .reopen_root_directory("runs", WorkspaceAclPolicy::Inherited)
            .unwrap();
        assert_eq!(bound.identity(), &runs_identity);
        bound.revalidate().unwrap();

        let run = bound
            .create_directory_new_with_policy("run-one", WorkspaceAclPolicy::Inherited)
            .unwrap();
        let run_identity = run.identity().clone();
        drop(run);
        let reopened_run = bound
            .reopen_directory("run-one", WorkspaceAclPolicy::Inherited)
            .unwrap();
        assert_eq!(reopened_run.identity(), &run_identity);
        let mut events = reopened_run.create_file_new("events.json").unwrap();
        events.as_file_mut().write_all(b"bound-child").unwrap();
        events.as_file_mut().sync_all().unwrap();
        drop(events);

        let movable = bound
            .create_directory_new_with_policy("movable", WorkspaceAclPolicy::Inherited)
            .unwrap();
        drop(movable);
        let movable = bound
            .reopen_directory("movable", WorkspaceAclPolicy::Inherited)
            .unwrap();
        let published = movable
            .publish_into_bound(&bound, "movable-published")
            .unwrap();
        assert!(same_path(
            published.final_path(),
            path.join("runs").join("movable-published")
        ));
        published.revalidate().unwrap();
        assert!(!path.join("runs").join("movable").is_dir());

        drop(reopened_run);
        drop(published);
        drop(bound);
        remove_test_workspace(workspace);
    }
}
