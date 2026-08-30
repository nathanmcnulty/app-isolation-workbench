//! Owner-and-SYSTEM-only kernel coordination primitives.
//!
//! A run coordination lease serializes cooperating host processes only. It is
//! not filesystem authority, cleanup authority, or durable recovery evidence.

use std::ffi::OsStr;
use std::marker::PhantomData;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::rc::Rc;

use aiw_probe::{WINDOWS_SYSTEM_SID, WorkspaceBindingEvidence};
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HLOCAL, LPARAM, LocalFree, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Globalization::{LCMAP_UPPERCASE, LCMapStringEx, LOCALE_NAME_INVARIANT};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, IsValidAcl, IsValidSecurityDescriptor,
    IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_DEFAULTED,
    SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_OWNER_DEFAULTED, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, MUTEX_ALL_ACCESS, OpenProcessToken, ReleaseMutex,
    WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

const RUN_MUTEX_PREFIX: &str = "Global\\AIW.RunCoordination.v1";
const RUN_BINDING_DOMAIN: &[u8] = b"aiw.dev/run-coordination-key/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunCoordinationMode {
    /// Acquire only when the mutex is immediately available and no abandonment
    /// is observed by this wait. Windows reports abandonment to one waiter;
    /// its absence is not durable proof that no earlier owner was abandoned.
    Normal,
    /// Permit acquisition after abandonment so an independently authorized
    /// durable recovery flow can continue. Abandonment is only a diagnostic;
    /// this mode does not itself grant recovery or cleanup authority.
    Recovery,
}

#[derive(Debug, Error)]
pub enum RunCoordinationError {
    #[error("run coordination binding is invalid: {0}")]
    InvalidBinding(&'static str),
    #[error("run coordination mutex is held by another operation")]
    LeaseUnavailable,
    #[error("run coordination mutex abandonment requires durable recovery")]
    RecoveryRequired,
    #[error("run coordination authority could not be established: {0}")]
    Authority(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCoordinationKey {
    name: String,
    expected_owner_sid: String,
    binding_sha256: String,
}

impl RunCoordinationKey {
    /// Resolve an existing local root to its canonical namespace and derive a
    /// normal-execution key using the current token owner. Persisted or
    /// elevated recovery must use [`Self::from_workspace`] so it neither opens
    /// the old path nor replaces the original owner expectation.
    pub fn from_existing_root(root: &Path, run_id: &str) -> Result<Self, RunCoordinationError> {
        validate_run_id(run_id)?;
        let canonical_root = resolve_existing_local_root(root)?;
        let owner_sid = current_user_sid().map_err(|error| match error {
            OwnerSystemMutexError::Authority(detail) => RunCoordinationError::Authority(detail),
            OwnerSystemMutexError::Busy | OwnerSystemMutexError::Abandoned => {
                RunCoordinationError::Authority(
                    "current token owner SID could not be established".to_owned(),
                )
            }
        })?;
        Self::from_root_and_owner(&canonical_root, run_id, owner_sid)
    }

    /// Derive the versioned kernel-object namespace from the canonical root
    /// namespace and run ID. The persisted owner SID is retained solely to
    /// verify the mutex DACL and does not affect the namespace digest.
    pub fn from_workspace(
        workspace: &WorkspaceBindingEvidence,
        run_id: &str,
    ) -> Result<Self, RunCoordinationError> {
        workspace
            .validate()
            .map_err(RunCoordinationError::InvalidBinding)?;
        Self::from_root_and_owner(
            Path::new(&workspace.root.final_path),
            run_id,
            workspace.owner_sid.clone(),
        )
    }

    fn from_root_and_owner(
        canonical_root: &Path,
        run_id: &str,
        expected_owner_sid: String,
    ) -> Result<Self, RunCoordinationError> {
        validate_run_id(run_id)?;
        let root_namespace = normalized_root_namespace(canonical_root)?;
        let mut binding = Sha256::new();
        update_length_prefixed(&mut binding, RUN_BINDING_DOMAIN)?;
        let mut root_bytes = Vec::with_capacity(root_namespace.len() * size_of::<u16>());
        for unit in root_namespace {
            root_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        update_length_prefixed(&mut binding, &root_bytes)?;
        update_length_prefixed(&mut binding, run_id.as_bytes())?;
        let binding_sha256 = hex::encode(binding.finalize());
        Ok(Self {
            name: format!("{RUN_MUTEX_PREFIX}.{binding_sha256}"),
            expected_owner_sid,
            binding_sha256,
        })
    }

    #[must_use]
    pub fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }
}

#[must_use]
pub struct RunCoordinationLease {
    _mutex: OwnerSystemMutexLease,
    binding_sha256: String,
    was_abandoned: bool,
}

impl RunCoordinationLease {
    /// Return the opaque digest that binds this lease to its run namespace.
    #[must_use]
    pub fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }

    /// Report whether Windows observed an abandoned prior owner.
    ///
    /// This signal is not durable recovery evidence or cleanup authority.
    #[must_use]
    pub fn was_abandoned(&self) -> bool {
        self.was_abandoned
    }
}

/// Attempt a non-blocking acquisition of the owner-and-SYSTEM run mutex.
///
/// Callers selecting [`RunCoordinationMode::Recovery`] must already hold the
/// durable recovery authority required by the higher-level transaction.
pub fn try_acquire_run_coordination(
    key: &RunCoordinationKey,
    mode: RunCoordinationMode,
) -> Result<RunCoordinationLease, RunCoordinationError> {
    let acquisition = OwnerSystemMutexLease::try_acquire(
        &key.name,
        &key.expected_owner_sid,
        matches!(mode, RunCoordinationMode::Recovery),
    )
    .map_err(|error| match error {
        OwnerSystemMutexError::Busy => RunCoordinationError::LeaseUnavailable,
        OwnerSystemMutexError::Abandoned => RunCoordinationError::RecoveryRequired,
        OwnerSystemMutexError::Authority(detail) => RunCoordinationError::Authority(detail),
    })?;
    Ok(RunCoordinationLease {
        was_abandoned: acquisition.was_abandoned(),
        _mutex: acquisition,
        binding_sha256: key.binding_sha256.clone(),
    })
}

#[derive(Debug)]
pub(crate) enum OwnerSystemMutexError {
    Busy,
    Abandoned,
    Authority(String),
}

pub(crate) struct OwnerSystemMutexLease {
    handle: HANDLE,
    was_abandoned: bool,
    // Windows mutex ownership belongs to the acquiring thread. This marker
    // prevents ReleaseMutex from ever running on a different thread.
    _thread_affinity: PhantomData<Rc<()>>,
}

impl OwnerSystemMutexLease {
    pub(crate) fn try_acquire(
        name: &str,
        expected_owner_sid: &str,
        accept_abandoned: bool,
    ) -> Result<Self, OwnerSystemMutexError> {
        let name = wide_string(name).map_err(OwnerSystemMutexError::Authority)?;
        let descriptor = MutexSecurityDescriptor::owner_system_only(expected_owner_sid)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: false.into(),
        };
        let handle = unsafe { CreateMutexW(Some(&attributes), false, PCWSTR(name.as_ptr())) }
            .map_err(|error| OwnerSystemMutexError::Authority(error.to_string()))?;
        if let Err(error) = verify_owner_system_mutex(handle, expected_owner_sid) {
            let _ = unsafe { CloseHandle(handle) };
            return Err(error);
        }
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        if wait == WAIT_OBJECT_0 {
            return Ok(Self {
                handle,
                was_abandoned: false,
                _thread_affinity: PhantomData,
            });
        }
        if wait == WAIT_ABANDONED {
            if accept_abandoned {
                return Ok(Self {
                    handle,
                    was_abandoned: true,
                    _thread_affinity: PhantomData,
                });
            }
            // WAIT_ABANDONED grants ownership. Release before returning the
            // diagnostic so this one-shot signal never becomes authority.
            let _ = unsafe { ReleaseMutex(handle) };
            let _ = unsafe { CloseHandle(handle) };
            return Err(OwnerSystemMutexError::Abandoned);
        }
        let _ = unsafe { CloseHandle(handle) };
        if wait == WAIT_TIMEOUT {
            Err(OwnerSystemMutexError::Busy)
        } else {
            Err(OwnerSystemMutexError::Authority(format!(
                "mutex wait failed with status 0x{:08x}",
                wait.0
            )))
        }
    }

    pub(crate) fn was_abandoned(&self) -> bool {
        self.was_abandoned
    }

    #[cfg(test)]
    pub(crate) fn raw_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for OwnerSystemMutexLease {
    fn drop(&mut self) {
        let _ = unsafe { ReleaseMutex(self.handle) };
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

pub(crate) fn current_user_sid() -> Result<String, OwnerSystemMutexError> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|error| OwnerSystemMutexError::Authority(error.to_string()))?;
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    let mut required = 0_u32;
    let first =
        unsafe { GetTokenInformation(token_handle(&token), TokenUser, None, 0, &mut required) };
    if first.is_ok() || required < size_of::<TOKEN_USER>() as u32 {
        return Err(OwnerSystemMutexError::Authority(
            "current user token SID size could not be established".to_owned(),
        ));
    }
    let mut buffer = vec![0_usize; (required as usize).div_ceil(size_of::<usize>())];
    unsafe {
        GetTokenInformation(
            token_handle(&token),
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .map_err(|error| OwnerSystemMutexError::Authority(error.to_string()))?;
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = PWSTR::null();
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid) }
        .map_err(|error| OwnerSystemMutexError::Authority(error.to_string()))?;
    let value = unsafe { sid.to_string() };
    let _ = unsafe { LocalFree(Some(HLOCAL(sid.0.cast()))) };
    value.map_err(|error| OwnerSystemMutexError::Authority(error.to_string()))
}

fn verify_owner_system_mutex(
    handle: HANDLE,
    expected_owner_sid: &str,
) -> Result<(), OwnerSystemMutexError> {
    let expected_owner = MutexSid::from_string(expected_owner_sid)?;
    let system = MutexSid::from_string(WINDOWS_SYSTEM_SID)?;
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    };
    if result.0 != 0 {
        return Err(OwnerSystemMutexError::Authority(format!(
            "mutex security query failed with win32={}",
            result.0
        )));
    }
    let descriptor = MutexSecurityDescriptor(descriptor);
    if !unsafe { IsValidSecurityDescriptor(descriptor.0) }.as_bool()
        || !unsafe { IsValidSid(owner) }.as_bool()
        || unsafe { EqualSid(owner, expected_owner.0) }.is_err()
        || dacl.is_null()
        || !unsafe { IsValidAcl(dacl) }.as_bool()
    {
        return Err(rejected_mutex_security());
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) }
        .map_err(|error| OwnerSystemMutexError::Authority(error.to_string()))?;
    if control & SE_DACL_PROTECTED.0 == 0
        || control & SE_DACL_PRESENT.0 == 0
        || control & SE_DACL_DEFAULTED.0 != 0
        || control & SE_OWNER_DEFAULTED.0 != 0
    {
        return Err(rejected_mutex_security());
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(|error| OwnerSystemMutexError::Authority(error.to_string()))?;
    if information.AceCount != 2 {
        return Err(rejected_mutex_security());
    }

    let mut owner_seen = false;
    let mut system_seen = false;
    for index in 0..information.AceCount {
        let mut raw_ace: *mut std::ffi::c_void = std::ptr::null_mut();
        unsafe { GetAce(dacl, index, &mut raw_ace) }
            .map_err(|error| OwnerSystemMutexError::Authority(error.to_string()))?;
        if raw_ace.is_null() {
            return Err(rejected_mutex_security());
        }
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || header.AceFlags != 0
            || usize::from(header.AceSize) < sid_offset + 8
        {
            return Err(rejected_mutex_security());
        }
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Mask != MUTEX_ALL_ACCESS.0 {
            return Err(rejected_mutex_security());
        }
        let sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
        let sid_bytes = unsafe {
            std::slice::from_raw_parts(
                (&ace.SidStart as *const u32).cast::<u8>(),
                usize::from(header.AceSize) - sid_offset,
            )
        };
        let sid_size = 8_usize + 4_usize * usize::from(sid_bytes[1]);
        if sid_size > sid_bytes.len()
            || !unsafe { IsValidSid(sid) }.as_bool()
            || unsafe { GetLengthSid(sid) } as usize != sid_size
        {
            return Err(rejected_mutex_security());
        }
        if unsafe { EqualSid(sid, expected_owner.0) }.is_ok() {
            owner_seen = true;
        } else if unsafe { EqualSid(sid, system.0) }.is_ok() {
            system_seen = true;
        } else {
            return Err(rejected_mutex_security());
        }
    }
    if !owner_seen || !system_seen {
        return Err(rejected_mutex_security());
    }
    Ok(())
}

fn rejected_mutex_security() -> OwnerSystemMutexError {
    OwnerSystemMutexError::Authority(
        "mutex security is not protected exact owner-and-SYSTEM-only full control".to_owned(),
    )
}

pub(crate) struct MutexSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl MutexSecurityDescriptor {
    pub(crate) fn owner_system_only(owner_sid: &str) -> Result<Self, OwnerSystemMutexError> {
        let sddl = wide_string(&format!(
            "O:{owner_sid}D:P(A;;0x001f0001;;;{owner_sid})(A;;0x001f0001;;;SY)"
        ))
        .map_err(OwnerSystemMutexError::Authority)?;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| OwnerSystemMutexError::Authority(error.to_string()))?;
        Ok(Self(descriptor))
    }
}

struct MutexSid(PSID);

impl MutexSid {
    fn from_string(value: &str) -> Result<Self, OwnerSystemMutexError> {
        let value = wide_string(value).map_err(OwnerSystemMutexError::Authority)?;
        let mut sid = PSID::default();
        unsafe { ConvertStringSidToSidW(PCWSTR(value.as_ptr()), &mut sid) }
            .map_err(|error| OwnerSystemMutexError::Authority(error.to_string()))?;
        Ok(Self(sid))
    }
}

impl Drop for MutexSid {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
    }
}

impl Drop for MutexSecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
    }
}

fn validate_run_id(value: &str) -> Result<(), RunCoordinationError> {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
    if value.is_empty()
        || value.len() > 128
        || matches!(value, "." | "..")
        || value.ends_with('.')
        || reserved
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(RunCoordinationError::InvalidBinding("run ID is unsafe"));
    }
    Ok(())
}

fn resolve_existing_local_root(path: &Path) -> Result<PathBuf, RunCoordinationError> {
    validate_local_root_prefix(path)?;
    let canonical = std::fs::canonicalize(path).map_err(|_| {
        RunCoordinationError::InvalidBinding(
            "root must resolve to an existing canonical local directory",
        )
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|_| {
        RunCoordinationError::InvalidBinding(
            "root must resolve to an existing canonical local directory",
        )
    })?;
    if !metadata.is_dir() {
        return Err(RunCoordinationError::InvalidBinding(
            "root must resolve to an existing canonical local directory",
        ));
    }
    // Revalidate the resolved namespace so a local junction targeting a remote
    // namespace cannot select a Global mutex name.
    normalized_root_namespace(&canonical)?;
    Ok(canonical)
}

fn validate_local_root_prefix(path: &Path) -> Result<(), RunCoordinationError> {
    let mut components = path.components();
    match components.next() {
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {}
        _ => {
            return Err(RunCoordinationError::InvalidBinding(
                "root namespace is not a local disk path",
            ));
        }
    }
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(RunCoordinationError::InvalidBinding(
            "root namespace is not absolute",
        ));
    }
    Ok(())
}

fn normalized_root_namespace(path: &Path) -> Result<Vec<u16>, RunCoordinationError> {
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive.to_ascii_uppercase(),
            _ => {
                return Err(RunCoordinationError::InvalidBinding(
                    "root namespace is not a local disk path",
                ));
            }
        },
        _ => {
            return Err(RunCoordinationError::InvalidBinding(
                "root namespace lacks a disk prefix",
            ));
        }
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(RunCoordinationError::InvalidBinding(
            "root namespace is not absolute",
        ));
    }
    let mut normalized = format!("\\\\?\\{}:\\", char::from(drive))
        .encode_utf16()
        .collect::<Vec<_>>();
    let mut first = true;
    for component in components {
        let Component::Normal(component) = component else {
            return Err(RunCoordinationError::InvalidBinding(
                "root namespace contains a relative component",
            ));
        };
        let units: Vec<_> = component.encode_wide().collect();
        if units.is_empty() || units.contains(&0) || units.contains(&(b':' as u16)) {
            return Err(RunCoordinationError::InvalidBinding(
                "root namespace contains an unsafe component",
            ));
        }
        if !first {
            normalized.push(b'\\' as u16);
        }
        first = false;
        normalized.extend(units);
    }
    uppercase_invariant(&normalized)
}

fn uppercase_invariant(value: &[u16]) -> Result<Vec<u16>, RunCoordinationError> {
    let required = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            value,
            None,
            None,
            None,
            LPARAM(0),
        )
    };
    if required <= 0 {
        return Err(RunCoordinationError::InvalidBinding(
            "root namespace case normalization failed",
        ));
    }
    let mut result = vec![0_u16; required as usize];
    let written = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            value,
            Some(&mut result),
            None,
            None,
            LPARAM(0),
        )
    };
    if written != required {
        return Err(RunCoordinationError::InvalidBinding(
            "root namespace case normalization was inconsistent",
        ));
    }
    Ok(result)
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) -> Result<(), RunCoordinationError> {
    let length = u32::try_from(value.len())
        .map_err(|_| RunCoordinationError::InvalidBinding("coordination key input is too large"))?;
    hasher.update(length.to_le_bytes());
    hasher.update(value);
    Ok(())
}

fn wide_string(value: &str) -> Result<Vec<u16>, String> {
    if value.contains('\0') {
        return Err("native string contains a NUL".to_owned());
    }
    Ok(OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

fn token_handle(handle: &OwnedHandle) -> HANDLE {
    use std::os::windows::io::AsRawHandle;
    HANDLE(handle.as_raw_handle())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{BufRead, Read, Write};
    use std::os::windows::io::FromRawHandle;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use aiw_probe::{
        WINDOWS_WORKSPACE_SCHEMA_VERSION, WINDOWS_WORKSPACE_SECURITY_POLICY, WindowsFileIdentity,
        workspace_policy_hash,
    };
    use windows::Win32::System::Threading::CreateEventW;

    use super::*;

    // Stable compile-time negative assertion: if the type ever implements the
    // named trait, selecting `AmbiguousIfImpl<_>` becomes ambiguous and the
    // test target stops compiling.
    macro_rules! assert_not_impl {
        ($type:ty, $trait:path) => {
            const _: fn() = || {
                trait AmbiguousIfImpl<A> {
                    fn marker() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                impl<T: ?Sized + $trait> AmbiguousIfImpl<u8> for T {}
                let _ = <$type as AmbiguousIfImpl<_>>::marker;
            };
        };
    }

    assert_not_impl!(OwnerSystemMutexLease, Send);
    assert_not_impl!(OwnerSystemMutexLease, Sync);
    assert_not_impl!(RunCoordinationLease, Send);
    assert_not_impl!(RunCoordinationLease, Sync);

    fn nonce() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn workspace(root: &str, owner_sid: &str) -> WorkspaceBindingEvidence {
        let identity = |path: String, id: u8| WindowsFileIdentity {
            final_path: path,
            volume_serial_number: "0000000000000001".to_owned(),
            file_id: format!("{id:032x}"),
        };
        WorkspaceBindingEvidence {
            schema_version: WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
            policy: WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
            security_policy_sha256: workspace_policy_hash(owner_sid),
            owner_sid: owner_sid.to_owned(),
            dacl_protected: true,
            allowed_sids: vec![WINDOWS_SYSTEM_SID.to_owned(), owner_sid.to_owned()],
            parent: identity("\\\\?\\C:\\AIW".to_owned(), 1),
            root: identity(root.to_owned(), 2),
            tools: identity(format!("{root}\\tools"), 3),
            output: identity(format!("{root}\\output"), 4),
        }
    }

    fn key(label: &str) -> RunCoordinationKey {
        let owner = current_user_sid().unwrap();
        RunCoordinationKey::from_workspace(
            &workspace(&format!("\\\\?\\C:\\AIW\\{label}-{}", nonce()), &owner),
            "run-one",
        )
        .unwrap()
    }

    fn create_named_mutex(key: &RunCoordinationKey, sddl: &str) -> OwnedHandle {
        let sddl = wide_string(sddl).unwrap();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .unwrap();
        let descriptor = MutexSecurityDescriptor(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: false.into(),
        };
        let name = wide_string(&key.name).unwrap();
        unsafe { CreateMutexW(Some(&attributes), false, PCWSTR(name.as_ptr())) }
            .map(|handle| unsafe { OwnedHandle::from_raw_handle(handle.0) })
            .unwrap()
    }

    fn create_exact_named_mutex(key: &RunCoordinationKey) -> OwnedHandle {
        create_named_mutex(
            key,
            &format!(
                "O:{0}D:P(A;;0x001f0001;;;{0})(A;;0x001f0001;;;SY)",
                key.expected_owner_sid
            ),
        )
    }

    fn helper_arguments() -> Vec<String> {
        vec![
            "--ignored".to_owned(),
            "--exact".to_owned(),
            "coordination::tests::process_coordination_helper".to_owned(),
            "--nocapture".to_owned(),
        ]
    }

    fn spawn_helper(key: &RunCoordinationKey, action: &str) -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .args(helper_arguments())
            .env("AIW_COORDINATION_HELPER", action)
            .env("AIW_COORDINATION_ROOT", key_root_for_helper(key))
            .env("AIW_COORDINATION_OWNER", &key.expected_owner_sid)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn wait_for_helper_acquired(
        child: &mut std::process::Child,
    ) -> std::io::BufReader<std::process::ChildStdout> {
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(
                stdout.read_line(&mut line).unwrap(),
                0,
                "helper exited early"
            );
            if line.contains("AIW_COORDINATION_ACQUIRED") {
                return stdout;
            }
        }
    }

    fn key_root_for_helper(key: &RunCoordinationKey) -> String {
        // The helper must reconstruct the public key rather than receive the
        // raw kernel-object name. Its synthetic root is carried separately in
        // binding_sha256 only in production, so tests retain it in this map.
        TEST_KEYS
            .lock()
            .unwrap()
            .iter()
            .find(|(_, candidate)| candidate.name == key.name)
            .map(|(root, _)| root.clone())
            .expect("test key root is registered")
    }

    static TEST_KEYS: std::sync::Mutex<Vec<(String, RunCoordinationKey)>> =
        std::sync::Mutex::new(Vec::new());

    fn registered_key(label: &str) -> RunCoordinationKey {
        let owner = current_user_sid().unwrap();
        let root = format!("\\\\?\\C:\\AIW\\{label}-{}", nonce());
        let key = RunCoordinationKey::from_workspace(&workspace(&root, &owner), "run-one").unwrap();
        TEST_KEYS.lock().unwrap().push((root, key.clone()));
        key
    }

    #[test]
    #[ignore = "internal subprocess fixture"]
    fn process_coordination_helper() {
        let Ok(action) = std::env::var("AIW_COORDINATION_HELPER") else {
            return;
        };
        let root = std::env::var("AIW_COORDINATION_ROOT").unwrap();
        let owner = std::env::var("AIW_COORDINATION_OWNER").unwrap();
        let key = RunCoordinationKey::from_workspace(&workspace(&root, &owner), "run-one").unwrap();
        let lease = try_acquire_run_coordination(&key, RunCoordinationMode::Normal).unwrap();
        println!("AIW_COORDINATION_ACQUIRED");
        std::io::stdout().flush().unwrap();
        if action == "hold" {
            let mut byte = [0_u8; 1];
            std::io::stdin().read_exact(&mut byte).unwrap();
            drop(lease);
        } else {
            std::mem::forget(lease);
            std::process::exit(0);
        }
    }

    #[test]
    fn normalized_key_ignores_case_owner_and_path_replacement_identity() {
        let owner = current_user_sid().unwrap();
        let root = format!("\\\\?\\C:\\AIW\\Case-{}", nonce());
        let first = workspace(&root, &owner);
        let mut second = workspace(&root.to_ascii_lowercase(), "S-1-5-19");
        second.root.file_id = "ffffffffffffffffffffffffffffffff".to_owned();
        let first = RunCoordinationKey::from_workspace(&first, "run-one").unwrap();
        let second = RunCoordinationKey::from_workspace(&second, "run-one").unwrap();
        assert_eq!(first.binding_sha256(), second.binding_sha256());
        assert_eq!(first.name, second.name);
    }

    #[test]
    fn current_user_constructor_resolves_alias_and_matches_persisted_namespace() {
        let root = std::env::temp_dir().join(format!("aiw-coordination-key-{}", nonce()));
        fs::create_dir(&root).unwrap();
        let canonical = root.canonicalize().unwrap();
        let canonical_text = canonical.to_string_lossy();
        let dos_alias = PathBuf::from(
            canonical_text
                .strip_prefix(r"\\?\")
                .expect("Windows canonical path has a verbatim prefix"),
        );
        let owner = current_user_sid().unwrap();
        let ordinary = RunCoordinationKey::from_existing_root(&canonical, "run-one").unwrap();
        let aliased = RunCoordinationKey::from_existing_root(&dos_alias, "run-one").unwrap();
        let persisted = RunCoordinationKey::from_workspace(
            &workspace(&canonical.to_string_lossy(), &owner),
            "run-one",
        )
        .unwrap();

        assert_ne!(canonical, dos_alias);
        assert_eq!(ordinary, aliased);
        assert_eq!(ordinary, persisted);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn current_user_constructor_rejects_unsafe_roots_and_run_ids() {
        for root in [
            Path::new(r"relative\root"),
            Path::new(r"\\server\share\root"),
        ] {
            assert!(matches!(
                RunCoordinationKey::from_existing_root(root, "run-one"),
                Err(RunCoordinationError::InvalidBinding(_))
            ));
        }

        let missing = std::env::temp_dir().join(format!("aiw-coordination-missing-{}", nonce()));
        assert!(matches!(
            RunCoordinationKey::from_existing_root(&missing, "run-one"),
            Err(RunCoordinationError::InvalidBinding(_))
        ));

        let file = std::env::temp_dir().join(format!("aiw-coordination-file-{}", nonce()));
        fs::write(&file, b"not a root").unwrap();
        assert!(matches!(
            RunCoordinationKey::from_existing_root(&file, "run-one"),
            Err(RunCoordinationError::InvalidBinding(_))
        ));
        fs::remove_file(file).unwrap();

        let root = std::env::temp_dir();
        for run_id in ["", "Run-One", "run/one", "run-one.", "con"] {
            assert!(matches!(
                RunCoordinationKey::from_existing_root(&root, run_id),
                Err(RunCoordinationError::InvalidBinding(_))
            ));
        }
    }

    #[test]
    fn unelevated_process_creates_and_acquires_global_mutex() {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.unwrap();
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        let mut elevation = windows::Win32::Security::TOKEN_ELEVATION::default();
        let mut returned = 0_u32;
        unsafe {
            GetTokenInformation(
                token_handle(&token),
                windows::Win32::Security::TokenElevation,
                Some((&mut elevation as *mut windows::Win32::Security::TOKEN_ELEVATION).cast()),
                size_of::<windows::Win32::Security::TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        }
        .unwrap();
        assert_eq!(elevation.TokenIsElevated, 0, "test must run unelevated");
        let key = key("global-unelevated");
        assert!(key.name.starts_with("Global\\"));
        let lease = try_acquire_run_coordination(&key, RunCoordinationMode::Normal).unwrap();
        assert!(!lease.was_abandoned());
    }

    #[test]
    fn same_key_is_busy_and_different_key_is_independent() {
        let first = key("busy-first");
        let different = key("busy-different");
        let (acquired_sender, acquired_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let held_key = first.clone();
        let holder = std::thread::spawn(move || {
            let lease =
                try_acquire_run_coordination(&held_key, RunCoordinationMode::Normal).unwrap();
            acquired_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
            drop(lease);
        });
        acquired_receiver.recv().unwrap();
        assert!(matches!(
            try_acquire_run_coordination(&first, RunCoordinationMode::Normal),
            Err(RunCoordinationError::LeaseUnavailable)
        ));
        let independent =
            try_acquire_run_coordination(&different, RunCoordinationMode::Normal).unwrap();
        drop(independent);
        release_sender.send(()).unwrap();
        holder.join().unwrap();
    }

    #[test]
    fn permissive_and_cross_type_precreation_fail_closed() {
        let owner = current_user_sid().unwrap();
        let permissive = key("permissive");
        let _mutex = create_named_mutex(
            &permissive,
            &format!(
                "O:{owner}D:P(A;;0x001f0001;;;{owner})(A;;0x001f0001;;;SY)(A;;0x001f0001;;;WD)"
            ),
        );
        assert!(matches!(
            try_acquire_run_coordination(&permissive, RunCoordinationMode::Normal),
            Err(RunCoordinationError::Authority(_))
        ));

        let collision = key("type-collision");
        let name = wide_string(&collision.name).unwrap();
        let event = unsafe { CreateEventW(None, true, false, PCWSTR(name.as_ptr())) }
            .map(|handle| unsafe { OwnedHandle::from_raw_handle(handle.0) })
            .unwrap();
        assert!(matches!(
            try_acquire_run_coordination(&collision, RunCoordinationMode::Normal),
            Err(RunCoordinationError::Authority(_))
        ));
        drop(event);
    }

    #[test]
    fn thread_abandonment_is_diagnostic_only() {
        let normal = key("thread-abandon-normal");
        let _anchor = create_exact_named_mutex(&normal);
        let (sender, receiver) = mpsc::channel();
        let child_key = normal.clone();
        std::thread::spawn(move || {
            let lease =
                try_acquire_run_coordination(&child_key, RunCoordinationMode::Normal).unwrap();
            sender.send(lease._mutex.raw_handle().0 as usize).unwrap();
            std::mem::forget(lease);
        })
        .join()
        .unwrap();
        let leaked = receiver.recv().unwrap();
        assert!(matches!(
            try_acquire_run_coordination(&normal, RunCoordinationMode::Normal),
            Err(RunCoordinationError::RecoveryRequired)
        ));
        let _ = unsafe { CloseHandle(HANDLE(leaked as *mut std::ffi::c_void)) };

        let recovery = key("thread-abandon-recovery");
        let _anchor = create_exact_named_mutex(&recovery);
        let child_key = recovery.clone();
        let leaked = std::thread::spawn(move || {
            let lease =
                try_acquire_run_coordination(&child_key, RunCoordinationMode::Normal).unwrap();
            let raw = lease._mutex.raw_handle().0 as usize;
            std::mem::forget(lease);
            raw
        })
        .join()
        .unwrap();
        let lease = try_acquire_run_coordination(&recovery, RunCoordinationMode::Recovery).unwrap();
        assert!(lease.was_abandoned());
        drop(lease);
        let _ = unsafe { CloseHandle(HANDLE(leaked as *mut std::ffi::c_void)) };
    }

    #[test]
    fn cross_process_busy_independence_and_abandonment_are_proven() {
        let busy = registered_key("process-busy");
        let mut child = spawn_helper(&busy, "hold");
        let mut stdout = wait_for_helper_acquired(&mut child);
        assert!(matches!(
            try_acquire_run_coordination(&busy, RunCoordinationMode::Normal),
            Err(RunCoordinationError::LeaseUnavailable)
        ));
        let different = key("process-independent");
        drop(try_acquire_run_coordination(&different, RunCoordinationMode::Normal).unwrap());
        child.stdin.take().unwrap().write_all(b"x").unwrap();
        let mut remaining = String::new();
        stdout.read_to_string(&mut remaining).unwrap();
        assert!(child.wait().unwrap().success());

        let abandoned = registered_key("process-abandoned");
        let _anchor = create_exact_named_mutex(&abandoned);
        let mut child = spawn_helper(&abandoned, "abandon");
        let mut output = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        assert!(child.wait().unwrap().success());
        assert!(output.contains("AIW_COORDINATION_ACQUIRED"));
        let lease =
            try_acquire_run_coordination(&abandoned, RunCoordinationMode::Recovery).unwrap();
        assert!(lease.was_abandoned());
    }

    #[test]
    fn held_named_lease_does_not_block_exact_root_rename() {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let root = parent.join(format!("aiw-coordination-root-{}", nonce()));
        let renamed = parent.join(format!("aiw-coordination-renamed-{}", nonce()));
        fs::create_dir(&root).unwrap();
        let canonical = root.canonicalize().unwrap();
        let owner = current_user_sid().unwrap();
        let key = RunCoordinationKey::from_workspace(
            &workspace(&canonical.to_string_lossy(), &owner),
            "run-one",
        )
        .unwrap();
        let lease = try_acquire_run_coordination(&key, RunCoordinationMode::Normal).unwrap();
        fs::rename(&root, &renamed).unwrap();
        assert!(renamed.is_dir());
        drop(lease);
        fs::remove_dir(renamed).unwrap();
    }
}
