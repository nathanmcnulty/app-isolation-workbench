use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use aiw_probe::{
    BinaryIdentity, CatalogTrustIdentity, ReadinessState, WindowsFileIdentity,
    WindowsPackageIdentity, WindowsSandboxCliProtocol, WindowsSandboxReadiness,
};
use aiw_provider_wsb::{WindowsSandboxPlan, render_config, validate_host_mappings};
use aiw_windows_command_line::join_arguments;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::ApplicationModel::{Package, PackageSignatureKind};
use windows::Management::Deployment::PackageManager;
use windows::System::ProcessorArchitecture;
use windows::System::Profile::AnalyticsInfo;
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, HLOCAL, HWND, LocalFree,
    SetHandleInformation, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminReleaseContext,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_DATA_PROVIDER_FLAGS, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE, WinVerifyTrust,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, IsValidAcl, IsValidSecurityDescriptor,
    IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_DEFAULTED,
    SE_DACL_PRESENT, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_NAME_NORMALIZED, FILE_SHARE_READ, GetFileInformationByHandle,
    GetFinalPathNameByHandleW,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateMutexW, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, InitializeProcThreadAttributeList, IsProcessorFeaturePresent,
    LPPROC_THREAD_ATTRIBUTE_LIST, MUTEX_ALL_ACCESS, OpenProcessToken, PF_VIRT_FIRMWARE_ENABLED,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ReleaseMutex, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
#[cfg(test)]
use windows::Win32::System::Threading::{CreateEventW, SetEvent};
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::{HSTRING, PCWSTR, PWSTR, w};

const PACKAGE_NAME: &str = "MicrosoftWindows.WindowsSandbox";
const PACKAGE_FAMILY: &str = "MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy";
const PUBLISHER: &str =
    "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
const PUBLISHER_ID: &str = "cw5n1h2txyewy";
const PROVIDER_FILE: &str = "wsb.exe";
const CATALOG_FILE: &str = "AppxMetadata\\CodeIntegrity.cat";
const SUPPORTED_CLI_VERSION: &str = "0.8.107.0";
const STREAM_LIMIT: u64 = 64 * 1024;
const READ_ONLY_TIMEOUT: Duration = Duration::from_secs(15);
const MUTATING_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_INVOCATION_TIMEOUT: Duration = Duration::from_secs(3_600);
const PROCESS_TREE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER_MUTEX_PREFIX: &str = "Local\\AIW.WindowsSandbox.Provider.v1";

#[derive(Debug, Error)]
pub enum WindowsSandboxInvocationError {
    #[error("Windows Sandbox provider authority could not be established: {0}")]
    Authority(String),
    #[error("Windows Sandbox provider lease is held by another operation")]
    LeaseUnavailable,
    #[error(
        "Windows Sandbox provider lease abandonment was observed; authoritative transaction recovery is required before another normal start"
    )]
    RecoveryRequired,
    #[error("Windows Sandbox CLI invocation failed: {0}")]
    Process(String),
    #[error("Windows Sandbox CLI protocol response was rejected: {0}")]
    Protocol(String),
    #[error("Windows Sandbox configuration was rejected: {0}")]
    Configuration(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalSandboxId(String);

impl CanonicalSandboxId {
    pub fn parse(value: &str) -> Result<Self, WindowsSandboxInvocationError> {
        if !is_uuid(value) || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(WindowsSandboxInvocationError::Protocol(
                "sandbox ID must be a lowercase canonical UUID".to_owned(),
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsbListObservation {
    pub session_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsbStartObservation {
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsbConnectObservation {
    pub session_id: String,
    pub output_was_discarded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsbStopObservation {
    pub session_id: String,
    pub output_was_empty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsbRecoveryDisposition {
    AlreadyAbsent,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsbRecoveryObservation {
    pub session_id: String,
    pub disposition: WsbRecoveryDisposition,
    pub mutex_was_abandoned: bool,
    pub start_provider_sha256: String,
    pub recovery_provider_sha256: String,
    pub provider_drifted: bool,
    pub session_ids_before: Vec<String>,
    pub session_ids_after: Vec<String>,
}

pub struct WindowsSandboxExecutionLease {
    readiness: WindowsSandboxReadiness,
    provider_path: PathBuf,
    _provider: File,
    _catalog: File,
    _mutex: ProviderMutex,
    owned_session: Option<CanonicalSandboxId>,
    connection_attempted: bool,
}

/// Recovery-only authority for one exact persisted Sandbox UUID. This type has
/// no start or connect surface and never accepts a provider path or command.
pub struct WindowsSandboxRecoveryLease {
    readiness: WindowsSandboxReadiness,
    provider_path: PathBuf,
    _provider: File,
    _catalog: File,
    _mutex: ProviderMutex,
    bound_session: CanonicalSandboxId,
    mutex_was_abandoned: bool,
    start_provider_sha256: String,
    recovery_provider_sha256: String,
    provider_drifted: bool,
    completed: bool,
}

impl WindowsSandboxRecoveryLease {
    pub fn readiness(&self) -> &WindowsSandboxReadiness {
        &self.readiness
    }

    pub fn bound_session(&self) -> &CanonicalSandboxId {
        &self.bound_session
    }

    pub fn mutex_was_abandoned(&self) -> bool {
        self.mutex_was_abandoned
    }

    pub fn start_provider_sha256(&self) -> &str {
        &self.start_provider_sha256
    }

    pub fn recovery_provider_sha256(&self) -> &str {
        &self.recovery_provider_sha256
    }

    pub fn provider_drifted(&self) -> bool {
        self.provider_drifted
    }

    pub fn reconcile(&mut self) -> Result<WsbRecoveryObservation, WindowsSandboxInvocationError> {
        self.reconcile_with_timeout(MUTATING_TIMEOUT)
    }

    /// Proves that the already-cleaned transaction UUID is still absent without
    /// issuing a stop. A later session reusing the same UUID is a conflict, not
    /// recovery authority for a second mutation.
    pub fn verify_bound_absent(
        &mut self,
    ) -> Result<WsbListObservation, WindowsSandboxInvocationError> {
        let deadline = invocation_deadline(READ_ONLY_TIMEOUT)?;
        let mut provider = NativeRecoveryProvider {
            provider_path: &self.provider_path,
        };
        let session_ids = provider.list(deadline)?;
        if session_ids
            .iter()
            .any(|session| session == self.bound_session.as_str())
        {
            return Err(WindowsSandboxInvocationError::Protocol(
                "a cleaned transaction UUID is present again; refusing recovery mutation"
                    .to_owned(),
            ));
        }
        self.completed = true;
        Ok(WsbListObservation { session_ids })
    }

    pub fn reconcile_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<WsbRecoveryObservation, WindowsSandboxInvocationError> {
        if self.completed {
            return Err(WindowsSandboxInvocationError::Protocol(
                "this recovery lease has already reconciled its bound session".to_owned(),
            ));
        }
        let deadline = invocation_deadline(timeout)?;
        let mut provider = NativeRecoveryProvider {
            provider_path: &self.provider_path,
        };
        let observation = reconcile_bound_session(
            &self.bound_session,
            self.mutex_was_abandoned,
            &self.start_provider_sha256,
            &self.recovery_provider_sha256,
            &mut provider,
            deadline,
        )?;
        self.completed = true;
        Ok(observation)
    }
}

impl WindowsSandboxExecutionLease {
    pub fn readiness(&self) -> &WindowsSandboxReadiness {
        &self.readiness
    }

    pub fn list(&self) -> Result<WsbListObservation, WindowsSandboxInvocationError> {
        self.list_with_timeout(READ_ONLY_TIMEOUT)
    }

    pub fn list_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<WsbListObservation, WindowsSandboxInvocationError> {
        self.list_until(invocation_deadline(timeout)?)
    }

    fn list_until(
        &self,
        deadline: Instant,
    ) -> Result<WsbListObservation, WindowsSandboxInvocationError> {
        let output = invoke_read_only(
            &self.provider_path,
            &["list", "--raw"],
            deadline,
            DescendantPolicy::ProviderManaged,
        )
        .map_err(WindowsSandboxInvocationError::Process)?;
        let session_ids = parse_list_ids_v0_8_107_0(&output.stdout)
            .map_err(WindowsSandboxInvocationError::Protocol)?;
        Ok(WsbListObservation { session_ids })
    }

    pub fn start(
        &mut self,
        sandbox_id: &CanonicalSandboxId,
        plan: &WindowsSandboxPlan,
    ) -> Result<WsbStartObservation, WindowsSandboxInvocationError> {
        self.start_with_timeout(sandbox_id, plan, MUTATING_TIMEOUT)
    }

    pub fn start_with_timeout(
        &mut self,
        sandbox_id: &CanonicalSandboxId,
        plan: &WindowsSandboxPlan,
        timeout: Duration,
    ) -> Result<WsbStartObservation, WindowsSandboxInvocationError> {
        let deadline = invocation_deadline(timeout)?;
        if self.owned_session.is_some() {
            return Err(WindowsSandboxInvocationError::Protocol(
                "this lease already owns or may own a sandbox session".to_owned(),
            ));
        }
        if self.connection_attempted {
            return Err(WindowsSandboxInvocationError::Protocol(
                "this lease has an unresolved prior connection attempt".to_owned(),
            ));
        }
        if !self.list_until(deadline)?.session_ids.is_empty() {
            return Err(WindowsSandboxInvocationError::Protocol(
                "start requires an empty provider under the held lease".to_owned(),
            ));
        }
        validate_host_mappings(plan)
            .map_err(|error| WindowsSandboxInvocationError::Configuration(error.to_string()))?;
        let rendered = render_config(plan)
            .map_err(|error| WindowsSandboxInvocationError::Configuration(error.to_string()))?;
        if rendered.xml.encode_utf16().count() > 24_000 {
            return Err(WindowsSandboxInvocationError::Configuration(
                "rendered configuration exceeds the fixed command-line budget".to_owned(),
            ));
        }
        // Persist the exact preselected identity in memory before invoking the
        // mutating provider. A production caller must additionally persist its
        // durable transaction before calling this method.
        self.owned_session = Some(sandbox_id.clone());
        let output = invoke_read_only(
            &self.provider_path,
            &[
                "start",
                "--raw",
                "--id",
                sandbox_id.as_str(),
                "--config",
                &rendered.xml,
            ],
            deadline,
            DescendantPolicy::ProviderManaged,
        )
        .map_err(WindowsSandboxInvocationError::Process)?;
        let observed = parse_start_v0_8_107_0(&output.stdout)
            .map_err(WindowsSandboxInvocationError::Protocol)?;
        if observed != sandbox_id.as_str() {
            return Err(WindowsSandboxInvocationError::Protocol(
                "start response did not match the preselected sandbox ID".to_owned(),
            ));
        }
        Ok(WsbStartObservation {
            session_id: observed,
        })
    }

    pub fn connect_owned(
        &mut self,
    ) -> Result<WsbConnectObservation, WindowsSandboxInvocationError> {
        self.connect_owned_with_timeout(MUTATING_TIMEOUT)
    }

    pub fn connect_owned_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<WsbConnectObservation, WindowsSandboxInvocationError> {
        let deadline = invocation_deadline(timeout)?;
        if self.connection_attempted {
            return Err(WindowsSandboxInvocationError::Protocol(
                "the owned sandbox connection is one-shot".to_owned(),
            ));
        }
        let sandbox_id = self.owned_session.clone().ok_or_else(|| {
            WindowsSandboxInvocationError::Protocol(
                "this lease has no bound sandbox session".to_owned(),
            )
        })?;
        let current = self.list_until(deadline)?;
        if current.session_ids != [sandbox_id.as_str()] {
            return Err(WindowsSandboxInvocationError::Protocol(
                "connect requires the exact owned sandbox session and no other session".to_owned(),
            ));
        }
        // Record the one-shot transition before mutation. A failed direct
        // response can still have established the remote-session descendant;
        // cleanup must stop the owned sandbox rather than retrying connect.
        self.connection_attempted = true;
        invoke_without_output(
            &self.provider_path,
            &["connect", "--raw", "--id", sandbox_id.as_str()],
            deadline,
        )
        .map_err(WindowsSandboxInvocationError::Process)?;
        let current = self.list_until(deadline)?;
        if current.session_ids != [sandbox_id.as_str()] {
            return Err(WindowsSandboxInvocationError::Protocol(
                "owned sandbox session drifted while establishing the user connection".to_owned(),
            ));
        }
        Ok(WsbConnectObservation {
            session_id: sandbox_id.as_str().to_owned(),
            // WindowsSandboxRemoteSession inherits captured pipe handles from
            // `wsb connect`, preventing EOF until the UI closes. The fixed
            // connect verb therefore uses null standard handles and relies on
            // its exit status plus exact-session reconciliation.
            output_was_discarded: true,
        })
    }

    pub fn stop_owned(&mut self) -> Result<WsbStopObservation, WindowsSandboxInvocationError> {
        self.stop_owned_with_timeout(MUTATING_TIMEOUT)
    }

    pub fn stop_owned_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<WsbStopObservation, WindowsSandboxInvocationError> {
        let deadline = invocation_deadline(timeout)?;
        let sandbox_id = self.owned_session.clone().ok_or_else(|| {
            WindowsSandboxInvocationError::Protocol(
                "this lease has no bound sandbox session".to_owned(),
            )
        })?;
        let output = invoke_read_only(
            &self.provider_path,
            &["stop", "--raw", "--id", sandbox_id.as_str()],
            deadline,
            DescendantPolicy::ProviderManaged,
        )
        .map_err(WindowsSandboxInvocationError::Process)?;
        if !output.stdout.is_empty() {
            return Err(WindowsSandboxInvocationError::Protocol(
                "stop response must be empty for CLI protocol 0.8.107.0".to_owned(),
            ));
        }
        let remaining = self.list_until(deadline)?;
        if !remaining.session_ids.is_empty() {
            return Err(WindowsSandboxInvocationError::Protocol(
                "exact stop did not establish an empty provider".to_owned(),
            ));
        }
        self.owned_session = None;
        self.connection_attempted = false;
        Ok(WsbStopObservation {
            session_id: sandbox_id.as_str().to_owned(),
            output_was_empty: true,
        })
    }
}

pub fn acquire_windows_sandbox(
    expected_provider_sha256: &str,
) -> Result<WindowsSandboxExecutionLease, WindowsSandboxInvocationError> {
    let authority = acquire_verified_provider(
        expected_provider_sha256,
        MutexAcquisitionMode::NormalExecution,
    )?;
    Ok(WindowsSandboxExecutionLease {
        readiness: authority.readiness,
        provider_path: authority.provider_path,
        _provider: authority.provider,
        _catalog: authority.catalog,
        _mutex: authority.mutex,
        owned_session: None,
        connection_attempted: false,
    })
}

pub fn acquire_windows_sandbox_recovery(
    start_provider_sha256: &str,
    persisted_session: CanonicalSandboxId,
) -> Result<WindowsSandboxRecoveryLease, WindowsSandboxInvocationError> {
    let authority =
        acquire_verified_provider(start_provider_sha256, MutexAcquisitionMode::Recovery)?;
    Ok(WindowsSandboxRecoveryLease {
        readiness: authority.readiness,
        provider_path: authority.provider_path,
        _provider: authority.provider,
        _catalog: authority.catalog,
        _mutex: authority.mutex,
        bound_session: persisted_session,
        mutex_was_abandoned: authority.mutex_was_abandoned,
        start_provider_sha256: authority.provider_hash_binding.start_sha256,
        recovery_provider_sha256: authority.provider_hash_binding.current_sha256,
        provider_drifted: authority.provider_hash_binding.drifted,
        completed: false,
    })
}

struct VerifiedProviderAuthority {
    readiness: WindowsSandboxReadiness,
    provider_path: PathBuf,
    provider: File,
    catalog: File,
    mutex: ProviderMutex,
    mutex_was_abandoned: bool,
    provider_hash_binding: ProviderHashBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderHashBinding {
    start_sha256: String,
    current_sha256: String,
    drifted: bool,
}

fn acquire_verified_provider(
    expected_provider_sha256: &str,
    mode: MutexAcquisitionMode,
) -> Result<VerifiedProviderAuthority, WindowsSandboxInvocationError> {
    if !is_lowercase_sha256(expected_provider_sha256) {
        return Err(WindowsSandboxInvocationError::Authority(
            "expected provider SHA-256 must be lowercase hexadecimal".to_owned(),
        ));
    }
    let mutex_acquisition = ProviderMutex::try_acquire(mode)?;
    let readiness = assess_windows_sandbox();
    if !readiness.supported {
        return Err(WindowsSandboxInvocationError::Authority(
            readiness.blockers.join(" "),
        ));
    }
    let provider_identity = readiness.provider_binary.as_ref().ok_or_else(|| {
        WindowsSandboxInvocationError::Authority("provider identity is absent".to_owned())
    })?;
    // Readiness has independently established the current Store package,
    // catalog member, held file identity, and pinned CLI protocol before
    // recovery may treat a changed hash as trusted servicing drift.
    let provider_hash_binding =
        bind_verified_provider_hash(mode, expected_provider_sha256, &provider_identity.sha256)?;
    let provider_path = PathBuf::from(&provider_identity.canonical_path);
    let mut provider =
        open_held_file(&provider_path).map_err(WindowsSandboxInvocationError::Authority)?;
    let observed_path = final_path(&provider).map_err(WindowsSandboxInvocationError::Authority)?;
    let observed_file_identity = file_identity(&provider, &observed_path)
        .map_err(WindowsSandboxInvocationError::Authority)?;
    let (observed_hash, observed_size) =
        hash_held_file(&mut provider).map_err(WindowsSandboxInvocationError::Authority)?;
    if !observed_path
        .to_string_lossy()
        .eq_ignore_ascii_case(&provider_identity.canonical_path)
        || observed_hash != provider_identity.sha256
        || observed_size != provider_identity.size_bytes
        || readiness.provider_file_identity.as_ref() != Some(&observed_file_identity)
    {
        return Err(WindowsSandboxInvocationError::Authority(
            "held provider identity drifted after readiness".to_owned(),
        ));
    }
    let trust = readiness.catalog_trust.as_ref().ok_or_else(|| {
        WindowsSandboxInvocationError::Authority("catalog trust identity is absent".to_owned())
    })?;
    let catalog_path = PathBuf::from(&trust.catalog_path);
    let catalog =
        open_held_file(&catalog_path).map_err(WindowsSandboxInvocationError::Authority)?;
    let package = readiness.provider_package.as_ref().ok_or_else(|| {
        WindowsSandboxInvocationError::Authority("package identity is absent".to_owned())
    })?;
    let verified = verify_catalog_member(
        &provider,
        &observed_path,
        &PathBuf::from(&package.install_location).join(CATALOG_FILE),
    )
    .map_err(WindowsSandboxInvocationError::Authority)?;
    if verified != *trust {
        return Err(WindowsSandboxInvocationError::Authority(
            "catalog trust identity drifted after readiness".to_owned(),
        ));
    }
    Ok(VerifiedProviderAuthority {
        readiness,
        provider_path: observed_path,
        provider,
        catalog,
        mutex: mutex_acquisition.mutex,
        mutex_was_abandoned: mutex_acquisition.was_abandoned,
        provider_hash_binding,
    })
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn bind_verified_provider_hash(
    mode: MutexAcquisitionMode,
    start_sha256: &str,
    current_sha256: &str,
) -> Result<ProviderHashBinding, WindowsSandboxInvocationError> {
    if !is_lowercase_sha256(start_sha256) || !is_lowercase_sha256(current_sha256) {
        return Err(WindowsSandboxInvocationError::Authority(
            "provider SHA-256 identity must be lowercase hexadecimal".to_owned(),
        ));
    }
    let drifted = start_sha256 != current_sha256;
    if drifted && matches!(mode, MutexAcquisitionMode::NormalExecution) {
        return Err(WindowsSandboxInvocationError::Authority(
            "provider hash differs from the approved identity".to_owned(),
        ));
    }
    Ok(ProviderHashBinding {
        start_sha256: start_sha256.to_owned(),
        current_sha256: current_sha256.to_owned(),
        drifted,
    })
}

trait RecoveryProvider {
    fn list(&mut self, deadline: Instant) -> Result<Vec<String>, WindowsSandboxInvocationError>;

    fn stop(
        &mut self,
        session: &CanonicalSandboxId,
        deadline: Instant,
    ) -> Result<(), WindowsSandboxInvocationError>;
}

struct NativeRecoveryProvider<'a> {
    provider_path: &'a Path,
}

impl RecoveryProvider for NativeRecoveryProvider<'_> {
    fn list(&mut self, deadline: Instant) -> Result<Vec<String>, WindowsSandboxInvocationError> {
        let output = invoke_read_only(
            self.provider_path,
            &["list", "--raw"],
            deadline,
            DescendantPolicy::ProviderManaged,
        )
        .map_err(WindowsSandboxInvocationError::Process)?;
        parse_list_ids_v0_8_107_0(&output.stdout).map_err(WindowsSandboxInvocationError::Protocol)
    }

    fn stop(
        &mut self,
        session: &CanonicalSandboxId,
        deadline: Instant,
    ) -> Result<(), WindowsSandboxInvocationError> {
        let output = invoke_read_only(
            self.provider_path,
            &["stop", "--raw", "--id", session.as_str()],
            deadline,
            DescendantPolicy::ProviderManaged,
        )
        .map_err(WindowsSandboxInvocationError::Process)?;
        if !output.stdout.is_empty() {
            return Err(WindowsSandboxInvocationError::Protocol(
                "recovery stop response must be empty for CLI protocol 0.8.107.0".to_owned(),
            ));
        }
        Ok(())
    }
}

fn reconcile_bound_session(
    bound_session: &CanonicalSandboxId,
    mutex_was_abandoned: bool,
    start_provider_sha256: &str,
    recovery_provider_sha256: &str,
    provider: &mut impl RecoveryProvider,
    deadline: Instant,
) -> Result<WsbRecoveryObservation, WindowsSandboxInvocationError> {
    let session_ids_before = provider.list(deadline)?;
    let was_present = session_ids_before
        .iter()
        .any(|session| session == bound_session.as_str());
    if was_present {
        provider.stop(bound_session, deadline)?;
    }
    let session_ids_after = provider.list(deadline)?;
    if session_ids_after
        .iter()
        .any(|session| session == bound_session.as_str())
    {
        return Err(WindowsSandboxInvocationError::Protocol(
            "recovery did not establish absence of the exact bound sandbox session".to_owned(),
        ));
    }

    let unrelated_before = session_ids_before
        .iter()
        .filter(|session| session.as_str() != bound_session.as_str())
        .cloned()
        .collect::<BTreeSet<_>>();
    let unrelated_after = session_ids_after.iter().cloned().collect::<BTreeSet<_>>();
    if unrelated_before != unrelated_after {
        return Err(WindowsSandboxInvocationError::Protocol(
            "unrelated sandbox sessions drifted during exact-session recovery".to_owned(),
        ));
    }

    Ok(WsbRecoveryObservation {
        session_id: bound_session.as_str().to_owned(),
        disposition: if was_present {
            WsbRecoveryDisposition::Stopped
        } else {
            WsbRecoveryDisposition::AlreadyAbsent
        },
        mutex_was_abandoned,
        start_provider_sha256: start_provider_sha256.to_owned(),
        recovery_provider_sha256: recovery_provider_sha256.to_owned(),
        provider_drifted: start_provider_sha256 != recovery_provider_sha256,
        session_ids_before,
        session_ids_after,
    })
}

pub(super) fn assess_windows_sandbox() -> WindowsSandboxReadiness {
    let mut result = empty_readiness();
    result.os_build = os_build();
    result.virtualization = if virtualization_firmware_enabled() {
        ReadinessState::Available
    } else {
        ReadinessState::Unknown
    };
    result.app_execution_alias = observed_alias();

    if result.os_build.is_none_or(|build| build < 26_100) {
        result.blockers.push(
            "AIW_WSB_OS_BUILD_UNSUPPORTED: Workbench v1 requires Windows build 26100 or later."
                .to_owned(),
        );
    }
    if result.process_architecture != "x86_64" {
        result.blockers.push(
            "AIW_WSB_ARCHITECTURE_UNSUPPORTED: Workbench v1 requires an x64 process and host."
                .to_owned(),
        );
    }
    if result.virtualization != ReadinessState::Available {
        result.blockers.push(
            "AIW_WSB_VIRTUALIZATION_UNVERIFIED: firmware virtualization is not reported as enabled."
                .to_owned(),
        );
    }

    match assess_provider(&mut result) {
        Ok(()) => {
            result.supported = result.blockers.is_empty();
        }
        Err(error) => result.blockers.push(error),
    }
    result
}

fn empty_readiness() -> WindowsSandboxReadiness {
    WindowsSandboxReadiness {
        schema_version: "aiw.dev/windows-sandbox-readiness/v0alpha2".to_owned(),
        supported: false,
        os_build: None,
        process_architecture: std::env::consts::ARCH.to_owned(),
        virtualization: ReadinessState::Unknown,
        sandbox_feature: ReadinessState::Unknown,
        provider_binary: None,
        provider_package: None,
        catalog_trust: None,
        provider_file_identity: None,
        cli_protocol: None,
        app_execution_alias: None,
        current_sessions: ReadinessState::Unknown,
        current_session_ids: Vec::new(),
        blockers: Vec::new(),
        warnings: vec![
            "Assessment is read-only and never enables Windows features, installs providers, or uses PATH/App Execution Aliases as execution authority.".to_owned(),
            "Provider readiness is not application containment evidence.".to_owned(),
        ],
    }
}

fn assess_provider(result: &mut WindowsSandboxReadiness) -> Result<(), String> {
    let _winrt = WinRtApartment::initialize()?;
    let package = resolve_package()?;
    let (package_identity, install_root) = validate_package(&package)?;
    let provider_path = install_root.join(PROVIDER_FILE);
    let catalog_path = install_root.join(CATALOG_FILE);
    let mut provider = open_held_file(&provider_path)?;
    let final_path = final_path(&provider)?;
    require_exact_child(&install_root, &final_path, PROVIDER_FILE)?;
    let file_identity = file_identity(&provider, &final_path)?;
    let (sha256, size_bytes) = hash_held_file(&mut provider)?;
    let catalog_trust = verify_catalog_member(&provider, &final_path, &catalog_path)?;

    let version_output = invoke_read_only(
        &final_path,
        &["--version"],
        invocation_deadline(READ_ONLY_TIMEOUT).map_err(|error| error.to_string())?,
        DescendantPolicy::ProviderManaged,
    )?;
    let cli_version = parse_version(&version_output.stdout)?;
    if cli_version != SUPPORTED_CLI_VERSION {
        return Err(format!(
            "AIW_WSB_CLI_VERSION_UNSUPPORTED: observed {cli_version}; supported protocol is {SUPPORTED_CLI_VERSION}."
        ));
    }
    let list_output = invoke_read_only(
        &final_path,
        &["list", "--raw"],
        invocation_deadline(READ_ONLY_TIMEOUT).map_err(|error| error.to_string())?,
        DescendantPolicy::ProviderManaged,
    )?;
    let session_count = parse_list_v0_8_107_0(&list_output.stdout)?;

    result.sandbox_feature = ReadinessState::Available;
    result.current_sessions = ReadinessState::Available;
    result.current_session_ids = parse_list_ids_v0_8_107_0(&list_output.stdout)?;
    if session_count > 0 {
        result.warnings.push(format!(
            "AIW_WSB_EXISTING_SESSIONS: observed {session_count} current Windows Sandbox session(s); execution preflight must require an empty provider."
        ));
    }
    result.provider_binary = Some(BinaryIdentity {
        canonical_path: final_path.to_string_lossy().into_owned(),
        sha256,
        size_bytes,
        version: Some(cli_version.clone()),
        signature_status: ReadinessState::Available,
    });
    result.provider_package = Some(package_identity);
    result.catalog_trust = Some(catalog_trust);
    result.provider_file_identity = Some(file_identity);
    result.cli_protocol = Some(WindowsSandboxCliProtocol {
        cli_version,
        protocol: "windowsSandboxCli/v0.8.107.0".to_owned(),
        list_schema: "WindowsSandboxEnvironments/Id".to_owned(),
    });
    Ok(())
}

fn resolve_package() -> Result<Package, String> {
    let manager = PackageManager::new()
        .map_err(|error| format!("AIW_WSB_PACKAGE_MANAGER_FAILED: {error}"))?;
    let packages = manager
        .FindPackagesByUserSecurityIdNamePublisher(
            &HSTRING::new(),
            &HSTRING::from(PACKAGE_NAME),
            &HSTRING::from(PUBLISHER),
        )
        .map_err(|error| format!("AIW_WSB_PACKAGE_QUERY_FAILED: {error}"))?;
    let mut matches = Vec::new();
    for package in packages {
        matches.push(package);
    }
    match matches.len() {
        0 => Err("AIW_WSB_CLI_PACKAGE_MISSING: launch Windows Sandbox once to install/update the Store CLI package.".to_owned()),
        1 => Ok(matches.remove(0)),
        count => Err(format!("AIW_WSB_PACKAGE_AMBIGUOUS: found {count} matching packages.")),
    }
}

fn validate_package(package: &Package) -> Result<(WindowsPackageIdentity, PathBuf), String> {
    let id = package.Id().map_err(package_error)?;
    let name = id.Name().map_err(package_error)?.to_string();
    let full_name = id.FullName().map_err(package_error)?.to_string();
    let family_name = id.FamilyName().map_err(package_error)?.to_string();
    let publisher = id.Publisher().map_err(package_error)?.to_string();
    let publisher_id = id.PublisherId().map_err(package_error)?.to_string();
    let architecture = id.Architecture().map_err(package_error)?;
    let version = id.Version().map_err(package_error)?;
    let signature_kind = package.SignatureKind().map_err(package_error)?;
    let status_ok = package
        .Status()
        .and_then(|status| status.VerifyIsOK())
        .map_err(package_error)?;
    let install_location = package
        .InstalledLocation()
        .and_then(|folder| folder.Path())
        .map_err(package_error)?
        .to_string();

    if name != PACKAGE_NAME
        || family_name != PACKAGE_FAMILY
        || publisher != PUBLISHER
        || publisher_id != PUBLISHER_ID
        || architecture != ProcessorArchitecture::X64
        || signature_kind != PackageSignatureKind::Store
        || !status_ok
    {
        return Err("AIW_WSB_PACKAGE_IDENTITY_REJECTED: package identity, architecture, Store signature kind, or status did not match the pinned Microsoft contract.".to_owned());
    }
    let version = format!(
        "{}.{}.{}.{}",
        version.Major, version.Minor, version.Build, version.Revision
    );
    let identity = WindowsPackageIdentity {
        name,
        full_name,
        family_name,
        publisher,
        publisher_id,
        version,
        architecture: "x64".to_owned(),
        signature_kind: "store".to_owned(),
        status_ok,
        install_location: install_location.clone(),
    };
    Ok((identity, PathBuf::from(install_location)))
}

fn package_error(error: windows::core::Error) -> String {
    format!("AIW_WSB_PACKAGE_IDENTITY_FAILED: {error}")
}

fn open_held_file(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
        .map_err(|error| format!("AIW_WSB_PROVIDER_OPEN_FAILED: {error}"))
}

fn raw_handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}

fn final_path(file: &File) -> Result<PathBuf, String> {
    let mut buffer = vec![0_u16; 32_768];
    let count =
        unsafe { GetFinalPathNameByHandleW(raw_handle(file), &mut buffer, FILE_NAME_NORMALIZED) };
    if count == 0 || count as usize >= buffer.len() {
        return Err("AIW_WSB_PROVIDER_FINAL_PATH_FAILED: final path exceeded the bounded buffer or could not be resolved.".to_owned());
    }
    let value = String::from_utf16(&buffer[..count as usize]).map_err(|_| {
        "AIW_WSB_PROVIDER_FINAL_PATH_INVALID: final path was not valid UTF-16.".to_owned()
    })?;
    Ok(PathBuf::from(
        value.strip_prefix("\\\\?\\").unwrap_or(&value),
    ))
}

fn require_exact_child(root: &Path, observed: &Path, leaf: &str) -> Result<(), String> {
    let expected = root.join(leaf);
    if !observed
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        return Err(
            "AIW_WSB_PROVIDER_PATH_REJECTED: opened provider is not the exact package child."
                .to_owned(),
        );
    }
    Ok(())
}

fn file_identity(file: &File, final_path: &Path) -> Result<WindowsFileIdentity, String> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) }
        .map_err(|error| format!("AIW_WSB_PROVIDER_FILE_ID_FAILED: {error}"))?;
    Ok(WindowsFileIdentity {
        final_path: final_path.to_string_lossy().into_owned(),
        volume_serial_number: format!("{:08x}", info.dwVolumeSerialNumber),
        file_id: format!(
            "{:016x}",
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)
        ),
    })
}

fn hash_held_file(file: &mut File) -> Result<(String, u64), String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("AIW_WSB_PROVIDER_HASH_FAILED: {error}"))?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("AIW_WSB_PROVIDER_HASH_FAILED: {error}"))?;
        if count == 0 {
            break;
        }
        size = size.saturating_add(count as u64);
        digest.update(&buffer[..count]);
    }
    Ok((hex::encode(digest.finalize()), size))
}

fn verify_catalog_member(
    member: &File,
    member_path: &Path,
    catalog_path: &Path,
) -> Result<CatalogTrustIdentity, String> {
    let mut catalog = open_held_file(catalog_path)?;
    let catalog_final_path = final_path(&catalog)?;
    if !catalog_final_path
        .to_string_lossy()
        .eq_ignore_ascii_case(&catalog_path.to_string_lossy())
    {
        return Err(
            "AIW_WSB_CATALOG_PATH_REJECTED: opened catalog is not the exact package catalog child."
                .to_owned(),
        );
    }
    let catalog_file_identity = file_identity(&catalog, &catalog_final_path)?;
    let (catalog_sha256, _) = hash_held_file(&mut catalog)?;
    let mut context = 0_isize;
    unsafe { CryptCATAdminAcquireContext2(&mut context, None, w!("SHA256"), None, None) }
        .map_err(|error| format!("AIW_WSB_CATALOG_CONTEXT_FAILED: {error}"))?;
    let context_guard = CatalogAdmin(context);

    let mut hash_size = 0_u32;
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            context_guard.0,
            raw_handle(member),
            &mut hash_size,
            None,
            None,
        )
    }
    .map_err(|error| format!("AIW_WSB_CATALOG_HASH_FAILED: {error}"))?;
    if hash_size == 0 || hash_size > 128 {
        return Err(
            "AIW_WSB_CATALOG_HASH_REJECTED: catalog member hash length was invalid.".to_owned(),
        );
    }
    let mut member_hash = vec![0_u8; hash_size as usize];
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            context_guard.0,
            raw_handle(member),
            &mut hash_size,
            Some(member_hash.as_mut_ptr()),
            None,
        )
    }
    .map_err(|error| format!("AIW_WSB_CATALOG_HASH_FAILED: {error}"))?;
    member_hash.truncate(hash_size as usize);
    let member_tag = hex::encode_upper(&member_hash);
    let member_tag_wide = wide(&member_tag);
    let member_path_wide = wide(&member_path.to_string_lossy());
    let catalog_path_wide = wide(&catalog_final_path.to_string_lossy());
    let mut catalog_info = WINTRUST_CATALOG_INFO {
        cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
        pcwszCatalogFilePath: PCWSTR(catalog_path_wide.as_ptr()),
        pcwszMemberTag: PCWSTR(member_tag_wide.as_ptr()),
        pcwszMemberFilePath: PCWSTR(member_path_wide.as_ptr()),
        hMemberFile: raw_handle(member),
        pbCalculatedFileHash: member_hash.as_mut_ptr(),
        cbCalculatedFileHash: member_hash.len() as u32,
        hCatAdmin: context_guard.0,
        ..Default::default()
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: WINTRUST_DATA_0 {
            pCatalog: &mut catalog_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(
            WTD_CACHE_ONLY_URL_RETRIEVAL.0 | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT.0,
        ),
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast(),
        )
    };
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast(),
        )
    };
    if status != 0 {
        return Err(format!(
            "AIW_WSB_CATALOG_TRUST_FAILED: WinVerifyTrust returned 0x{:08x}.",
            status as u32
        ));
    }
    Ok(CatalogTrustIdentity {
        trust_kind: "catalogMember".to_owned(),
        catalog_path: catalog_final_path.to_string_lossy().into_owned(),
        catalog_sha256,
        catalog_file_identity,
        member_tag,
        trust_policy: "cacheOnlyWholeChainExcludeRoot".to_owned(),
        verification_status: ReadinessState::Available,
    })
}

struct CatalogAdmin(isize);

impl Drop for CatalogAdmin {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = unsafe { CryptCATAdminReleaseContext(self.0, 0) };
        }
    }
}

#[derive(Debug)]
struct ProcessOutput {
    exit_code: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Copy)]
enum OutputMode {
    Capture,
    Discard,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DescendantPolicy {
    #[cfg(test)]
    Contained,
    ProviderManaged,
}

type BoundedReader = thread::JoinHandle<Result<Vec<u8>, String>>;

struct InvocationStdio {
    null: Option<File>,
    stdout_read: Option<OwnedHandle>,
    stdout_write: Option<OwnedHandle>,
    stderr_read: Option<OwnedHandle>,
    stderr_write: Option<OwnedHandle>,
}

impl InvocationStdio {
    fn new(mode: OutputMode) -> Result<Self, String> {
        let null = OpenOptions::new()
            .read(true)
            .write(true)
            .open("NUL")
            .map_err(|error| format!("AIW_WSB_CLI_NULL_FAILED: {error}"))?;
        set_inheritable(file_handle(&null), true)?;
        let (stdout_read, stdout_write, stderr_read, stderr_write) = match mode {
            OutputMode::Capture => {
                let (stdout_read, stdout_write) = inheritable_pipe()?;
                let (stderr_read, stderr_write) = inheritable_pipe()?;
                (
                    Some(stdout_read),
                    Some(stdout_write),
                    Some(stderr_read),
                    Some(stderr_write),
                )
            }
            OutputMode::Discard => (None, None, None, None),
        };
        Ok(Self {
            null: Some(null),
            stdout_read,
            stdout_write,
            stderr_read,
            stderr_write,
        })
    }

    fn inherited_handles(&self) -> Vec<HANDLE> {
        let mut handles = vec![file_handle(
            self.null.as_ref().expect("standard handles are present"),
        )];
        if let Some(stdout) = self.stdout_write.as_ref() {
            handles.push(owned_handle(stdout));
        }
        if let Some(stderr) = self.stderr_write.as_ref() {
            handles.push(owned_handle(stderr));
        }
        handles
    }

    fn startup_handles(&self) -> (HANDLE, HANDLE, HANDLE) {
        let null = file_handle(self.null.as_ref().expect("standard handles are present"));
        (
            null,
            self.stdout_write.as_ref().map_or(null, owned_handle),
            self.stderr_write.as_ref().map_or(null, owned_handle),
        )
    }

    fn close_child_ends(&mut self) {
        self.stdout_write.take();
        self.stderr_write.take();
        self.null.take();
    }

    fn take_readers(&mut self) -> (Option<BoundedReader>, Option<BoundedReader>) {
        let stdout = self.stdout_read.take().map(|handle| {
            thread::spawn(move || {
                let file = unsafe { File::from_raw_handle(handle.into_raw_handle()) };
                read_bounded(file)
            })
        });
        let stderr = self.stderr_read.take().map(|handle| {
            thread::spawn(move || {
                let file = unsafe { File::from_raw_handle(handle.into_raw_handle()) };
                read_bounded(file)
            })
        });
        (stdout, stderr)
    }
}

struct ProcessAttributeList {
    _storage: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl ProcessAttributeList {
    fn new(attribute_count: u32) -> Result<Self, String> {
        let mut bytes = 0usize;
        let initial =
            unsafe { InitializeProcThreadAttributeList(None, attribute_count, None, &mut bytes) };
        if initial.is_ok() || bytes == 0 {
            return Err(
                "AIW_WSB_CLI_ATTRIBUTE_LIST_FAILED: size query returned an invalid result."
                    .to_owned(),
            );
        }
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0usize; words];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(list), attribute_count, None, &mut bytes) }
            .map_err(|error| format!("AIW_WSB_CLI_ATTRIBUTE_LIST_FAILED: {error}"))?;
        Ok(Self {
            _storage: storage,
            list,
        })
    }

    fn update_handles(&mut self, attribute: u32, handles: &[HANDLE]) -> Result<(), String> {
        unsafe {
            UpdateProcThreadAttribute(
                self.list,
                0,
                attribute as usize,
                Some(handles.as_ptr().cast()),
                std::mem::size_of_val(handles),
                None,
                None,
            )
        }
        .map_err(|error| format!("AIW_WSB_CLI_ATTRIBUTE_LIST_FAILED: {error}"))
    }
}

impl Drop for ProcessAttributeList {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.list) };
    }
}

struct InvocationJob {
    handle: OwnedHandle,
}

impl InvocationJob {
    fn create(_descendants: DescendantPolicy) -> Result<Self, String> {
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|error| format!("AIW_WSB_CLI_JOB_CREATE_FAILED: {error}"))?;
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                owned_handle(&handle),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(|error| format!("AIW_WSB_CLI_JOB_LIMIT_FAILED: {error}"))?;
        Ok(Self { handle })
    }

    fn raw(&self) -> HANDLE {
        owned_handle(&self.handle)
    }

    fn active_processes(&self) -> Result<u32, String> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        unsafe {
            QueryInformationJobObject(
                Some(self.raw()),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                None,
            )
        }
        .map_err(|error| format!("AIW_WSB_CLI_JOB_QUERY_FAILED: {error}"))?;
        Ok(accounting.ActiveProcesses)
    }

    fn terminate_and_verify_empty(&self) -> Result<(), String> {
        let active = match self.active_processes() {
            Ok(active) => active,
            Err(error) => {
                let _ = unsafe { TerminateJobObject(self.raw(), 1) };
                return Err(error);
            }
        };
        if active > 0 {
            unsafe { TerminateJobObject(self.raw(), 1) }
                .map_err(|error| format!("AIW_WSB_CLI_JOB_TERMINATE_FAILED: {error}"))?;
        }
        let deadline = Instant::now()
            .checked_add(PROCESS_TREE_CLEANUP_TIMEOUT)
            .ok_or_else(|| {
                "AIW_WSB_CLI_JOB_CLEANUP_FAILED: cleanup deadline overflowed.".to_owned()
            })?;
        loop {
            if self.active_processes()? == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(
                    "AIW_WSB_CLI_JOB_CLEANUP_FAILED: assigned provider job remained active."
                        .to_owned(),
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn release_provider_managed_descendants(&self) -> Result<(), String> {
        let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        unsafe {
            SetInformationJobObject(
                owned_handle(&self.handle),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(|error| format!("AIW_WSB_CLI_JOB_RELEASE_FAILED: {error}"))
    }
}

fn invocation_deadline(timeout: Duration) -> Result<Instant, WindowsSandboxInvocationError> {
    if timeout.is_zero() || timeout > MAX_INVOCATION_TIMEOUT {
        return Err(WindowsSandboxInvocationError::Process(
            "AIW_WSB_CLI_DEADLINE_INVALID: timeout must be between 1 ns and 3600 seconds."
                .to_owned(),
        ));
    }
    Instant::now().checked_add(timeout).ok_or_else(|| {
        WindowsSandboxInvocationError::Process(
            "AIW_WSB_CLI_DEADLINE_INVALID: timeout overflowed the monotonic clock.".to_owned(),
        )
    })
}

fn provider_environment() -> Result<Vec<u16>, String> {
    let mut environment: Vec<(String, OsString)> = Vec::new();
    for name in [
        "APPDATA",
        "LOCALAPPDATA",
        "ProgramData",
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            environment.push((name.to_owned(), value));
        }
    }
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        environment.push((
            "PATH".to_owned(),
            PathBuf::from(system_root).join("System32").into_os_string(),
        ));
    }
    environment.sort_by_key(|entry| entry.0.to_ascii_uppercase());
    let mut block = Vec::new();
    for (name, value) in environment {
        let mut entry = OsString::from(name);
        entry.push("=");
        entry.push(value);
        let encoded: Vec<u16> = entry.encode_wide().collect();
        if encoded.contains(&0) {
            return Err(
                "AIW_WSB_CLI_ENVIRONMENT_REJECTED: environment contained a NUL.".to_owned(),
            );
        }
        block.extend(encoded);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn invoke_without_output(path: &Path, arguments: &[&str], deadline: Instant) -> Result<(), String> {
    let output = invoke_job_bound(
        path,
        arguments,
        deadline,
        OutputMode::Discard,
        DescendantPolicy::ProviderManaged,
    )?;
    if output.exit_code != 0 {
        return Err(format!(
            "AIW_WSB_CLI_FAILED: provider exited with {}.",
            output.exit_code
        ));
    }
    Ok(())
}

fn invoke_read_only(
    path: &Path,
    arguments: &[&str],
    deadline: Instant,
    descendants: DescendantPolicy,
) -> Result<ProcessOutput, String> {
    let output = invoke_job_bound(path, arguments, deadline, OutputMode::Capture, descendants)?;
    if output.exit_code != 0 {
        return Err(format!(
            "AIW_WSB_CLI_FAILED: provider exited with {}; stderr={}",
            output.exit_code,
            bounded_text(&output.stderr)
        ));
    }
    if !output.stderr.is_empty() {
        return Err(format!(
            "AIW_WSB_CLI_STDERR_REJECTED: {}",
            bounded_text(&output.stderr)
        ));
    }
    Ok(output)
}

fn invoke_job_bound(
    path: &Path,
    arguments: &[&str],
    deadline: Instant,
    output_mode: OutputMode,
    descendants: DescendantPolicy,
) -> Result<ProcessOutput, String> {
    if Instant::now() >= deadline {
        return Err("AIW_WSB_CLI_TIMEOUT: provider deadline expired before creation.".to_owned());
    }
    let provider_root = path.parent().ok_or_else(|| {
        "AIW_WSB_CLI_PATH_REJECTED: provider has no protected package parent.".to_owned()
    })?;
    let provider = path
        .to_str()
        .ok_or_else(|| "AIW_WSB_CLI_PATH_REJECTED: provider path was not Unicode.".to_owned())?;
    let provider_wide = null_terminated(provider)?;
    let provider_root_wide = null_terminated_os(provider_root.as_os_str())?;
    let command_line = join_arguments(std::iter::once(provider).chain(arguments.iter().copied()));
    let mut command_line_wide = null_terminated(&command_line)?;
    let environment = provider_environment()?;

    let job = InvocationJob::create(descendants)?;
    let mut stdio = InvocationStdio::new(output_mode)?;
    let inherited_handles = stdio.inherited_handles();
    let mut attributes = ProcessAttributeList::new(1)?;
    attributes.update_handles(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited_handles)?;

    let (stdin, stdout, stderr) = stdio.startup_handles();
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin;
    startup.StartupInfo.hStdOutput = stdout;
    startup.StartupInfo.hStdError = stderr;
    startup.lpAttributeList = attributes.list;
    let mut process_information = PROCESS_INFORMATION::default();
    if Instant::now() >= deadline {
        return Err("AIW_WSB_CLI_TIMEOUT: provider deadline expired before creation.".to_owned());
    }
    unsafe {
        CreateProcessW(
            PCWSTR(provider_wide.as_ptr()),
            Some(PWSTR(command_line_wide.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            Some(environment.as_ptr().cast()),
            PCWSTR(provider_root_wide.as_ptr()),
            (&startup as *const STARTUPINFOEXW).cast(),
            &mut process_information,
        )
    }
    .map_err(|error| format!("AIW_WSB_CLI_START_FAILED: {error}"))?;

    let process = unsafe { OwnedHandle::from_raw_handle(process_information.hProcess.0) };
    let thread_handle = unsafe { OwnedHandle::from_raw_handle(process_information.hThread.0) };
    if let Err(error) = unsafe { AssignProcessToJobObject(job.raw(), owned_handle(&process)) } {
        let cleanup = terminate_suspended_process(owned_handle(&process));
        return match cleanup {
            Ok(()) => Err(format!("AIW_WSB_CLI_JOB_ASSIGN_FAILED: {error}")),
            Err(cleanup) => Err(format!(
                "AIW_WSB_CLI_JOB_ASSIGN_FAILED: {error}; cleanup={cleanup}"
            )),
        };
    }
    if unsafe { ResumeThread(owned_handle(&thread_handle)) } == u32::MAX {
        let cleanup = job.terminate_and_verify_empty();
        return match cleanup {
            Ok(()) => Err("AIW_WSB_CLI_RESUME_FAILED: ResumeThread failed.".to_owned()),
            Err(cleanup) => Err(format!(
                "AIW_WSB_CLI_RESUME_FAILED: ResumeThread failed; cleanup={cleanup}"
            )),
        };
    }
    drop(thread_handle);
    drop(attributes);
    stdio.close_child_ends();
    let (stdout_reader, stderr_reader) = stdio.take_readers();

    let wait_result = wait_for_process(owned_handle(&process), deadline);
    let exit_code: Result<Option<u32>, String> = if wait_result.is_ok() {
        (|| {
            let mut code = 0u32;
            unsafe { GetExitCodeProcess(owned_handle(&process), &mut code) }
                .map_err(|error| format!("AIW_WSB_CLI_EXIT_CODE_FAILED: {error}"))?;
            Ok(Some(code))
        })()
    } else {
        Ok(None)
    };
    drop(process);

    let root_succeeded = matches!(&exit_code, Ok(Some(0)));
    let early_cleanup = if root_succeeded {
        Ok(())
    } else {
        job.terminate_and_verify_empty()
    };
    let streams_completed =
        !root_succeeded || wait_for_readers_until(&stdout_reader, &stderr_reader, deadline);
    let deadline_cleanup = if root_succeeded && !streams_completed {
        job.terminate_and_verify_empty()
    } else {
        Ok(())
    };
    let reader_cleanup_deadline = Instant::now()
        .checked_add(PROCESS_TREE_CLEANUP_TIMEOUT)
        .ok_or_else(|| "AIW_WSB_CLI_PIPE_CLEANUP_FAILED: deadline overflowed.".to_owned())?;
    let stdout = join_reader_bounded(stdout_reader, "stdout", reader_cleanup_deadline);
    let stderr = join_reader_bounded(stderr_reader, "stderr", reader_cleanup_deadline);
    let streams_succeeded = stdout.is_ok() && stderr.is_ok();
    let final_cleanup = if root_succeeded && streams_completed && streams_succeeded {
        match descendants {
            // A successful packaged CLI invocation can leave provider-owned
            // descendants. Remove kill-on-close only after the exact CLI root
            // and both bounded output streams complete cleanly. For mutating
            // calls, the persisted session UUID and list/stop/list transaction
            // then become their cleanup authority.
            DescendantPolicy::ProviderManaged => job.release_provider_managed_descendants(),
            #[cfg(test)]
            DescendantPolicy::Contained => job.terminate_and_verify_empty(),
        }
    } else if root_succeeded && streams_completed {
        job.terminate_and_verify_empty()
    } else {
        Ok(())
    };
    drop(job);
    early_cleanup?;
    deadline_cleanup?;
    final_cleanup?;
    if root_succeeded && !streams_completed {
        return Err(
            "AIW_WSB_CLI_PIPE_TIMEOUT: output remained open past the provider deadline.".to_owned(),
        );
    }
    wait_result?;
    let exit_code = exit_code?.expect("a successful wait has an exit code");
    let stdout = stdout?;
    let stderr = stderr?;
    Ok(ProcessOutput {
        exit_code,
        stdout,
        stderr,
    })
}

fn wait_for_process(process: HANDLE, deadline: Instant) -> Result<(), String> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(
                "AIW_WSB_CLI_TIMEOUT: provider operation exceeded its deadline.".to_owned(),
            );
        }
        let remaining = deadline.saturating_duration_since(now);
        let slice = remaining.min(Duration::from_millis(20));
        let milliseconds = slice.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
        let wait = unsafe { WaitForSingleObject(process, milliseconds) };
        if wait == WAIT_OBJECT_0 {
            return Ok(());
        }
        if wait == WAIT_TIMEOUT {
            continue;
        }
        if wait == WAIT_FAILED {
            return Err("AIW_WSB_CLI_WAIT_FAILED: WaitForSingleObject failed.".to_owned());
        }
        return Err(format!(
            "AIW_WSB_CLI_WAIT_FAILED: unexpected wait status 0x{:08x}.",
            wait.0
        ));
    }
}

fn wait_for_readers_until(
    stdout: &Option<BoundedReader>,
    stderr: &Option<BoundedReader>,
    deadline: Instant,
) -> bool {
    while !readers_finished(stdout, stderr) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    readers_finished(stdout, stderr)
}

fn readers_finished(stdout: &Option<BoundedReader>, stderr: &Option<BoundedReader>) -> bool {
    stdout.as_ref().is_none_or(thread::JoinHandle::is_finished)
        && stderr.as_ref().is_none_or(thread::JoinHandle::is_finished)
}

fn join_reader_bounded(
    reader: Option<BoundedReader>,
    name: &str,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    match reader {
        Some(reader) => {
            if !reader.is_finished() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let wait = unsafe {
                    WaitForSingleObject(
                        HANDLE(reader.as_raw_handle()),
                        remaining.as_millis().min(u128::from(u32::MAX)) as u32,
                    )
                };
                if wait != WAIT_OBJECT_0 {
                    return Err(format!(
                        "AIW_WSB_CLI_PIPE_CLEANUP_FAILED: {name} reader remained active."
                    ));
                }
            }
            reader
                .join()
                .map_err(|_| format!("AIW_WSB_CLI_PIPE_FAILED: {name} reader panicked."))?
        }
        None => Ok(Vec::new()),
    }
}

fn terminate_suspended_process(process: HANDLE) -> Result<(), String> {
    unsafe { TerminateProcess(process, 1) }
        .map_err(|error| format!("AIW_WSB_CLI_DIRECT_TERMINATE_FAILED: {error}"))?;
    let wait =
        unsafe { WaitForSingleObject(process, PROCESS_TREE_CLEANUP_TIMEOUT.as_millis() as u32) };
    if wait != WAIT_OBJECT_0 {
        return Err(
            "AIW_WSB_CLI_DIRECT_CLEANUP_FAILED: suspended provider remained active.".to_owned(),
        );
    }
    Ok(())
}

fn inheritable_pipe() -> Result<(OwnedHandle, OwnedHandle), String> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    unsafe { CreatePipe(&mut read, &mut write, Some(&attributes), 0) }
        .map_err(|error| format!("AIW_WSB_CLI_PIPE_FAILED: {error}"))?;
    let read = unsafe { OwnedHandle::from_raw_handle(read.0) };
    let write = unsafe { OwnedHandle::from_raw_handle(write.0) };
    set_inheritable(owned_handle(&read), false)?;
    Ok((read, write))
}

fn set_inheritable(handle: HANDLE, inheritable: bool) -> Result<(), String> {
    unsafe {
        SetHandleInformation(
            handle,
            HANDLE_FLAG_INHERIT.0,
            if inheritable {
                HANDLE_FLAG_INHERIT
            } else {
                HANDLE_FLAGS(0)
            },
        )
    }
    .map_err(|error| format!("AIW_WSB_CLI_HANDLE_INHERITANCE_FAILED: {error}"))
}

fn file_handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}

fn owned_handle(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

fn null_terminated(value: &str) -> Result<Vec<u16>, String> {
    null_terminated_os(std::ffi::OsStr::new(value))
}

fn null_terminated_os(value: &std::ffi::OsStr) -> Result<Vec<u16>, String> {
    let mut encoded: Vec<u16> = value.encode_wide().collect();
    if encoded.contains(&0) {
        return Err("AIW_WSB_CLI_STRING_REJECTED: value contained a NUL.".to_owned());
    }
    encoded.push(0);
    Ok(encoded)
}

fn read_bounded(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(STREAM_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("AIW_WSB_CLI_PIPE_FAILED: {error}"))?;
    if bytes.len() as u64 > STREAM_LIMIT {
        return Err("AIW_WSB_CLI_OUTPUT_OVERSIZED: provider output exceeded 64 KiB.".to_owned());
    }
    Ok(bytes)
}

fn parse_version(bytes: &[u8]) -> Result<String, String> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| "AIW_WSB_CLI_VERSION_INVALID: version output was not UTF-8.".to_owned())?
        .trim();
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 4
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(
            "AIW_WSB_CLI_VERSION_INVALID: version output did not match four numeric components."
                .to_owned(),
        );
    }
    Ok(value.to_owned())
}

fn parse_list_v0_8_107_0(bytes: &[u8]) -> Result<usize, String> {
    parse_list_ids_v0_8_107_0(bytes).map(|sessions| sessions.len())
}

fn parse_list_ids_v0_8_107_0(bytes: &[u8]) -> Result<Vec<String>, String> {
    let value: CliListResponse = serde_json::from_slice(bytes)
        .map_err(|error| format!("AIW_WSB_CLI_LIST_INVALID: {error}"))?;
    if value.environments.len() > 16 {
        return Err("AIW_WSB_CLI_LIST_INVALID: session count exceeded 16.".to_owned());
    }
    let mut ids = Vec::with_capacity(value.environments.len());
    for session in value.environments {
        let id = session.id;
        if !is_uuid(&id) {
            return Err("AIW_WSB_CLI_LIST_INVALID: Id was not a canonical UUID.".to_owned());
        }
        let id = id.to_ascii_lowercase();
        if ids.contains(&id) {
            return Err("AIW_WSB_CLI_LIST_INVALID: duplicate Id was observed.".to_owned());
        }
        ids.push(id);
    }
    Ok(ids)
}

fn parse_start_v0_8_107_0(bytes: &[u8]) -> Result<String, String> {
    let value: CliStartResponse = serde_json::from_slice(bytes)
        .map_err(|error| format!("AIW_WSB_CLI_START_INVALID: {error}"))?;
    if !is_uuid(&value.id) {
        return Err("AIW_WSB_CLI_START_INVALID: Id was not a canonical UUID.".to_owned());
    }
    Ok(value.id.to_ascii_lowercase())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CliStartResponse {
    #[serde(rename = "Id")]
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CliListResponse {
    #[serde(rename = "WindowsSandboxEnvironments")]
    environments: Vec<CliSessionResponse>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CliSessionResponse {
    #[serde(rename = "Id")]
    id: String,
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn bounded_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(1024).collect()
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn observed_alias() -> Option<String> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    let alias = PathBuf::from(base).join("Microsoft\\WindowsApps\\wsb.exe");
    alias.exists().then(|| alias.to_string_lossy().into_owned())
}

fn os_build() -> Option<u32> {
    let value = AnalyticsInfo::VersionInfo()
        .ok()?
        .DeviceFamilyVersion()
        .ok()?;
    let packed = value.to_string().parse::<u64>().ok()?;
    Some(((packed >> 16) & 0xffff) as u32)
}

fn virtualization_firmware_enabled() -> bool {
    unsafe { IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED).as_bool() }
}

struct WinRtApartment;

impl WinRtApartment {
    fn initialize() -> Result<Self, String> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }
            .map_err(|error| format!("AIW_COM_INITIALIZATION_FAILED: {error}"))?;
        Ok(Self)
    }
}

impl Drop for WinRtApartment {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

struct ProviderMutex(HANDLE);

#[derive(Clone, Copy)]
enum MutexAcquisitionMode {
    NormalExecution,
    Recovery,
}

struct ProviderMutexAcquisition {
    mutex: ProviderMutex,
    was_abandoned: bool,
}

impl ProviderMutex {
    fn try_acquire(
        mode: MutexAcquisitionMode,
    ) -> Result<ProviderMutexAcquisition, WindowsSandboxInvocationError> {
        let owner_sid = current_user_sid()?;
        let owner_scope = hex::encode(Sha256::digest(owner_sid.as_bytes()));
        let name = format!("{PROVIDER_MUTEX_PREFIX}.{}", &owner_scope[..32]);
        Self::try_acquire_owner_scoped(mode, &name, &owner_sid)
    }

    #[cfg(test)]
    fn try_acquire_named(
        mode: MutexAcquisitionMode,
        name: &str,
        owner_sid: &str,
    ) -> Result<ProviderMutexAcquisition, WindowsSandboxInvocationError> {
        Self::try_acquire_owner_scoped(mode, name, owner_sid)
    }

    fn try_acquire_owner_scoped(
        mode: MutexAcquisitionMode,
        name: &str,
        owner_sid: &str,
    ) -> Result<ProviderMutexAcquisition, WindowsSandboxInvocationError> {
        let name = wide(name);
        let descriptor = MutexSecurityDescriptor::owner_system_only(owner_sid)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: false.into(),
        };
        let handle = unsafe { CreateMutexW(Some(&attributes), false, PCWSTR(name.as_ptr())) }
            .map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))?;
        if let Err(error) = verify_owner_system_mutex(handle, owner_sid) {
            let _ = unsafe { CloseHandle(handle) };
            return Err(error);
        }
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        match interpret_mutex_wait(wait, mode) {
            Ok(was_abandoned) => Ok(ProviderMutexAcquisition {
                mutex: Self(handle),
                was_abandoned,
            }),
            Err(error) => {
                // WAIT_ABANDONED is a one-shot observation which grants
                // ownership. Normal execution records only that signal and
                // rejects; durable recovery authority lives in the persisted
                // transaction layer, not in the kernel bit.
                if wait == WAIT_ABANDONED {
                    let _ = unsafe { ReleaseMutex(handle) };
                }
                let _ = unsafe { CloseHandle(handle) };
                Err(error)
            }
        }
    }
}

fn verify_owner_system_mutex(
    handle: HANDLE,
    expected_owner_sid: &str,
) -> Result<(), WindowsSandboxInvocationError> {
    let expected_owner = MutexSid::from_string(expected_owner_sid)?;
    let system = MutexSid::from_string("S-1-5-18")?;
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
        return Err(WindowsSandboxInvocationError::Authority(format!(
            "provider mutex security query failed with win32={}",
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
        .map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))?;
    if control & SE_DACL_PROTECTED.0 == 0
        || control & SE_DACL_PRESENT.0 == 0
        || control & SE_DACL_DEFAULTED.0 != 0
    {
        return Err(rejected_mutex_security());
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))?;
    if information.AceCount != 2 {
        return Err(rejected_mutex_security());
    }

    let mut owner_seen = false;
    let mut system_seen = false;
    for index in 0..information.AceCount {
        let mut raw_ace: *mut std::ffi::c_void = std::ptr::null_mut();
        unsafe { GetAce(dacl, index, &mut raw_ace) }
            .map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))?;
        if raw_ace.is_null() {
            return Err(rejected_mutex_security());
        }
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
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

fn rejected_mutex_security() -> WindowsSandboxInvocationError {
    WindowsSandboxInvocationError::Authority(
        "provider mutex security is not protected current-owner-and-SYSTEM-only full control"
            .to_owned(),
    )
}

struct MutexSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl MutexSecurityDescriptor {
    fn owner_system_only(owner_sid: &str) -> Result<Self, WindowsSandboxInvocationError> {
        let sddl = wide(&format!(
            "O:{owner_sid}D:P(A;;0x001f0001;;;{owner_sid})(A;;0x001f0001;;;SY)"
        ));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))?;
        Ok(Self(descriptor))
    }
}

struct MutexSid(PSID);

impl MutexSid {
    fn from_string(value: &str) -> Result<Self, WindowsSandboxInvocationError> {
        let value = wide(value);
        let mut sid = PSID::default();
        unsafe { ConvertStringSidToSidW(PCWSTR(value.as_ptr()), &mut sid) }
            .map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))?;
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

fn current_user_sid() -> Result<String, WindowsSandboxInvocationError> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))?;
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    let mut required = 0_u32;
    let first =
        unsafe { GetTokenInformation(owned_handle(&token), TokenUser, None, 0, &mut required) };
    if first.is_ok() || required < std::mem::size_of::<TOKEN_USER>() as u32 {
        return Err(WindowsSandboxInvocationError::Authority(
            "current user token SID size could not be established".to_owned(),
        ));
    }
    let mut buffer = vec![0_usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    unsafe {
        GetTokenInformation(
            owned_handle(&token),
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))?;
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = PWSTR::null();
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid) }
        .map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))?;
    let value = unsafe { sid.to_string() };
    let _ = unsafe { LocalFree(Some(HLOCAL(sid.0.cast()))) };
    value.map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))
}

fn interpret_mutex_wait(
    wait: windows::Win32::Foundation::WAIT_EVENT,
    mode: MutexAcquisitionMode,
) -> Result<bool, WindowsSandboxInvocationError> {
    if wait == WAIT_OBJECT_0 {
        Ok(false)
    } else if wait == WAIT_ABANDONED {
        match mode {
            MutexAcquisitionMode::NormalExecution => {
                Err(WindowsSandboxInvocationError::RecoveryRequired)
            }
            MutexAcquisitionMode::Recovery => Ok(true),
        }
    } else if wait == WAIT_TIMEOUT {
        Err(WindowsSandboxInvocationError::LeaseUnavailable)
    } else {
        Err(WindowsSandboxInvocationError::Authority(format!(
            "provider mutex wait failed with status 0x{:08x}",
            wait.0
        )))
    }
}

impl Drop for ProviderMutex {
    fn drop(&mut self) {
        let _ = unsafe { ReleaseMutex(self.0) };
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const START_PROVIDER_HASH: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RECOVERY_PROVIDER_HASH: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn unique_mutex_name(label: &str) -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            "Local\\AIW.WindowsSandbox.Provider.test.{}.{label}.{nonce}",
            std::process::id()
        )
    }

    fn create_named_mutex(name: &str, sddl: &str) -> OwnedHandle {
        let sddl = wide(sddl);
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
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: false.into(),
        };
        let name = wide(name);
        unsafe { CreateMutexW(Some(&attributes), false, PCWSTR(name.as_ptr())) }
            .map(|handle| unsafe { OwnedHandle::from_raw_handle(handle.0) })
            .unwrap()
    }

    fn abandon_named_mutex(name: String, owner_sid: String) -> usize {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let acquisition = ProviderMutex::try_acquire_named(
                MutexAcquisitionMode::NormalExecution,
                &name,
                &owner_sid,
            )
            .expect("test thread acquires uniquely named mutex");
            sender.send(acquisition.mutex.0.0 as usize).unwrap();
            std::mem::forget(acquisition);
        })
        .join()
        .unwrap();
        receiver.recv().unwrap()
    }

    struct FakeRecoveryProvider {
        lists: VecDeque<Vec<String>>,
        stopped: Vec<String>,
    }

    impl FakeRecoveryProvider {
        fn new(lists: impl IntoIterator<Item = Vec<String>>) -> Self {
            Self {
                lists: lists.into_iter().collect(),
                stopped: Vec::new(),
            }
        }
    }

    impl RecoveryProvider for FakeRecoveryProvider {
        fn list(
            &mut self,
            _deadline: Instant,
        ) -> Result<Vec<String>, WindowsSandboxInvocationError> {
            self.lists.pop_front().ok_or_else(|| {
                WindowsSandboxInvocationError::Protocol(
                    "fake recovery list observation exhausted".to_owned(),
                )
            })
        }

        fn stop(
            &mut self,
            session: &CanonicalSandboxId,
            _deadline: Instant,
        ) -> Result<(), WindowsSandboxInvocationError> {
            self.stopped.push(session.as_str().to_owned());
            Ok(())
        }
    }

    fn helper_arguments(name: &str) -> Vec<String> {
        vec![
            "--ignored".to_owned(),
            "--exact".to_owned(),
            format!("windows_platform::tests::{name}"),
            "--nocapture".to_owned(),
        ]
    }

    fn invoked_as_helper(name: &str) -> bool {
        let expected = format!("windows_platform::tests::{name}");
        let arguments: Vec<String> = std::env::args().collect();
        arguments
            .windows(2)
            .any(|pair| pair[0] == "--exact" && pair[1] == expected)
    }

    fn invoke_test_helper(
        name: &str,
        timeout: Duration,
        output_mode: OutputMode,
    ) -> Result<ProcessOutput, String> {
        invoke_test_helper_with_arguments(name, timeout, output_mode, &[])
    }

    fn invoke_test_helper_with_policy(
        name: &str,
        timeout: Duration,
        output_mode: OutputMode,
        descendants: DescendantPolicy,
    ) -> Result<ProcessOutput, String> {
        let executable = std::env::current_exe().unwrap();
        let arguments = helper_arguments(name);
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let deadline = Instant::now().checked_add(timeout).unwrap();
        invoke_job_bound(&executable, &arguments, deadline, output_mode, descendants)
    }

    fn invoke_test_helper_with_arguments(
        name: &str,
        timeout: Duration,
        output_mode: OutputMode,
        additional_arguments: &[String],
    ) -> Result<ProcessOutput, String> {
        let executable = std::env::current_exe().unwrap();
        let mut arguments = helper_arguments(name);
        arguments.extend_from_slice(additional_arguments);
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let deadline = Instant::now().checked_add(timeout).unwrap();
        invoke_job_bound(
            &executable,
            &arguments,
            deadline,
            output_mode,
            DescendantPolicy::Contained,
        )
    }

    #[test]
    #[ignore = "internal subprocess fixture"]
    fn job_helper_prints_and_exits() {
        if invoked_as_helper("job_helper_prints_and_exits") {
            println!("AIW_JOB_HELPER_OK");
        }
    }

    #[test]
    #[ignore = "internal subprocess fixture"]
    fn job_helper_writes_oversized_output() {
        if invoked_as_helper("job_helper_writes_oversized_output") {
            use std::io::Write as _;
            let bytes = vec![b'x'; STREAM_LIMIT as usize + 1024];
            let _ = std::io::stdout().write_all(&bytes);
        }
    }

    #[test]
    #[ignore = "internal subprocess fixture"]
    fn job_helper_checks_unlisted_handle() {
        if !invoked_as_helper("job_helper_checks_unlisted_handle") {
            return;
        }
        let marker = std::env::args()
            .find_map(|argument| {
                argument
                    .strip_prefix("AIW_SENTINEL_HANDLE_")
                    .map(str::to_owned)
            })
            .expect("sentinel handle marker is present");
        let raw = usize::from_str_radix(&marker, 16).expect("sentinel handle is hexadecimal");
        let _ = unsafe { SetEvent(HANDLE(raw as *mut std::ffi::c_void)) };
        println!("AIW_UNLISTED_HANDLE_PROBED");
    }

    #[test]
    #[ignore = "internal subprocess fixture"]
    fn job_helper_descendant_hangs() {
        if invoked_as_helper("job_helper_descendant_hangs") {
            thread::sleep(Duration::from_secs(60));
        }
    }

    #[test]
    #[ignore = "internal subprocess fixture"]
    fn job_helper_parent_hangs_with_descendant() {
        if !invoked_as_helper("job_helper_parent_hangs_with_descendant") {
            return;
        }
        let _ = invoke_test_helper(
            "job_helper_descendant_hangs",
            Duration::from_secs(60),
            OutputMode::Discard,
        );
        thread::sleep(Duration::from_secs(60));
    }

    #[test]
    #[ignore = "internal subprocess fixture"]
    fn job_helper_exits_with_inheriting_descendant() {
        if !invoked_as_helper("job_helper_exits_with_inheriting_descendant") {
            return;
        }
        let executable = std::env::current_exe().unwrap();
        let child = std::process::Command::new(executable)
            .args(helper_arguments("job_helper_descendant_hangs"))
            .spawn()
            .unwrap();
        drop(child);
    }

    #[test]
    fn job_bound_launcher_captures_bounded_output_and_reaps_the_job() {
        let output = invoke_test_helper(
            "job_helper_prints_and_exits",
            Duration::from_secs(10),
            OutputMode::Capture,
        )
        .unwrap();
        assert_eq!(output.exit_code, 0);
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("AIW_JOB_HELPER_OK"),
            "captured output was {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn job_bound_launcher_terminates_a_hanging_process_tree_at_deadline() {
        let started = Instant::now();
        let error = invoke_test_helper(
            "job_helper_parent_hangs_with_descendant",
            Duration::from_millis(250),
            OutputMode::Capture,
        )
        .unwrap_err();
        assert!(error.contains("AIW_WSB_CLI_TIMEOUT"), "{error}");
        assert!(
            started.elapsed()
                < Duration::from_millis(250)
                    + PROCESS_TREE_CLEANUP_TIMEOUT
                    + Duration::from_secs(1)
        );
    }

    #[test]
    fn provider_managed_output_cannot_outlive_the_deadline() {
        let started = Instant::now();
        let error = invoke_test_helper_with_policy(
            "job_helper_exits_with_inheriting_descendant",
            Duration::from_secs(3),
            OutputMode::Capture,
            DescendantPolicy::ProviderManaged,
        )
        .unwrap_err();
        assert!(error.contains("AIW_WSB_CLI_PIPE_TIMEOUT"), "{error}");
        assert!(
            started.elapsed()
                < Duration::from_secs(3) + PROCESS_TREE_CLEANUP_TIMEOUT + Duration::from_secs(1)
        );
    }

    #[test]
    fn job_bound_launcher_rejects_oversized_output_after_tree_cleanup() {
        let error = invoke_test_helper(
            "job_helper_writes_oversized_output",
            Duration::from_secs(10),
            OutputMode::Capture,
        )
        .unwrap_err();
        assert!(error.contains("AIW_WSB_CLI_OUTPUT_OVERSIZED"), "{error}");
    }

    #[test]
    fn job_bound_launcher_inherits_only_the_explicit_handle_list() {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into(),
        };
        let sentinel = unsafe { CreateEventW(Some(&attributes), true, false, PCWSTR::null()) }
            .map(|handle| unsafe { OwnedHandle::from_raw_handle(handle.0) })
            .unwrap();
        let additional_arguments = vec![
            "--skip".to_owned(),
            format!(
                "AIW_SENTINEL_HANDLE_{:x}",
                sentinel.as_raw_handle() as usize
            ),
        ];
        let output = invoke_test_helper_with_arguments(
            "job_helper_checks_unlisted_handle",
            Duration::from_secs(10),
            OutputMode::Capture,
            &additional_arguments,
        )
        .unwrap();
        assert_eq!(output.exit_code, 0);
        assert!(String::from_utf8_lossy(&output.stdout).contains("AIW_UNLISTED_HANDLE_PROBED"));
        assert_eq!(
            unsafe { WaitForSingleObject(owned_handle(&sentinel), 0) },
            WAIT_TIMEOUT,
            "the child inherited and signalled a handle absent from HANDLE_LIST"
        );
    }

    #[test]
    fn invocation_deadlines_are_bounded_before_process_creation() {
        assert!(invocation_deadline(Duration::ZERO).is_err());
        assert!(invocation_deadline(MAX_INVOCATION_TIMEOUT + Duration::from_nanos(1)).is_err());
        assert!(invocation_deadline(Duration::from_nanos(1)).is_ok());
    }

    #[test]
    fn abandoned_mutex_signal_is_rejected_normally_and_recorded_for_recovery() {
        assert!(matches!(
            interpret_mutex_wait(WAIT_ABANDONED, MutexAcquisitionMode::NormalExecution),
            Err(WindowsSandboxInvocationError::RecoveryRequired)
        ));
        assert!(interpret_mutex_wait(WAIT_ABANDONED, MutexAcquisitionMode::Recovery).unwrap());
        assert!(!interpret_mutex_wait(WAIT_OBJECT_0, MutexAcquisitionMode::Recovery).unwrap());
        assert!(matches!(
            interpret_mutex_wait(WAIT_TIMEOUT, MutexAcquisitionMode::Recovery),
            Err(WindowsSandboxInvocationError::LeaseUnavailable)
        ));
    }

    #[test]
    fn provider_hash_policy_rejects_normal_drift_and_records_trusted_recovery_drift() {
        assert!(matches!(
            bind_verified_provider_hash(
                MutexAcquisitionMode::NormalExecution,
                START_PROVIDER_HASH,
                RECOVERY_PROVIDER_HASH,
            ),
            Err(WindowsSandboxInvocationError::Authority(_))
        ));
        let recovery = bind_verified_provider_hash(
            MutexAcquisitionMode::Recovery,
            START_PROVIDER_HASH,
            RECOVERY_PROVIDER_HASH,
        )
        .unwrap();
        assert_eq!(recovery.start_sha256, START_PROVIDER_HASH);
        assert_eq!(recovery.current_sha256, RECOVERY_PROVIDER_HASH);
        assert!(recovery.drifted);
    }

    #[test]
    fn mutex_rejects_a_permissive_preexisting_security_descriptor_before_waiting() {
        let owner_sid = current_user_sid().unwrap();
        let name = unique_mutex_name("permissive");
        let _precreated = create_named_mutex(
            &name,
            &format!(
                "O:{owner_sid}D:P(A;;0x001f0001;;;{owner_sid})(A;;0x001f0001;;;SY)(A;;0x001f0001;;;WD)"
            ),
        );
        assert!(matches!(
            ProviderMutex::try_acquire_named(MutexAcquisitionMode::Recovery, &name, &owner_sid,),
            Err(WindowsSandboxInvocationError::Authority(_))
        ));
    }

    #[test]
    fn mutex_accepts_a_correct_preexisting_security_descriptor() {
        let owner_sid = current_user_sid().unwrap();
        let name = unique_mutex_name("correct");
        let _precreated = create_named_mutex(
            &name,
            &format!("O:{owner_sid}D:P(A;;0x001f0001;;;{owner_sid})(A;;0x001f0001;;;SY)"),
        );
        let acquisition = ProviderMutex::try_acquire_named(
            MutexAcquisitionMode::NormalExecution,
            &name,
            &owner_sid,
        )
        .unwrap();
        assert!(!acquisition.was_abandoned);
    }

    #[test]
    fn unique_native_mutexes_record_the_one_shot_abandonment_signal() {
        let owner_sid = current_user_sid().unwrap();
        let normal_name = unique_mutex_name("normal-abandoned");
        let leaked_handle = abandon_named_mutex(normal_name.clone(), owner_sid.clone());

        assert!(matches!(
            ProviderMutex::try_acquire_named(
                MutexAcquisitionMode::NormalExecution,
                &normal_name,
                &owner_sid,
            ),
            Err(WindowsSandboxInvocationError::RecoveryRequired)
        ));

        let recovery_name = unique_mutex_name("recovery-abandoned");
        let second_leaked_handle = abandon_named_mutex(recovery_name.clone(), owner_sid.clone());
        let recovery = ProviderMutex::try_acquire_named(
            MutexAcquisitionMode::Recovery,
            &recovery_name,
            &owner_sid,
        )
        .unwrap();
        assert!(recovery.was_abandoned);
        drop(recovery);

        let _ = unsafe { CloseHandle(HANDLE(leaked_handle as *mut std::ffi::c_void)) };
        let _ = unsafe { CloseHandle(HANDLE(second_leaked_handle as *mut std::ffi::c_void)) };
    }

    #[test]
    fn recovery_stops_only_the_exact_bound_session_and_preserves_unrelated_sessions() {
        let bound = CanonicalSandboxId::parse("1782a9f3-4e9a-45ac-abe1-afc8ecf78666").unwrap();
        let unrelated = "7be1e7db-8340-45ac-97ce-3b1a7fd58e10".to_owned();
        let mut provider = FakeRecoveryProvider::new([
            vec![unrelated.clone(), bound.as_str().to_owned()],
            vec![unrelated.clone()],
        ]);

        let observation = reconcile_bound_session(
            &bound,
            true,
            START_PROVIDER_HASH,
            RECOVERY_PROVIDER_HASH,
            &mut provider,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(provider.stopped, vec![bound.as_str()]);
        assert_eq!(observation.disposition, WsbRecoveryDisposition::Stopped);
        assert!(observation.mutex_was_abandoned);
        assert!(observation.provider_drifted);
        assert_eq!(observation.start_provider_sha256, START_PROVIDER_HASH);
        assert_eq!(observation.recovery_provider_sha256, RECOVERY_PROVIDER_HASH);
        assert_eq!(observation.session_ids_after, vec![unrelated]);
    }

    #[test]
    fn recovery_proves_already_absent_without_issuing_stop() {
        let bound = CanonicalSandboxId::parse("1782a9f3-4e9a-45ac-abe1-afc8ecf78666").unwrap();
        let unrelated = "7be1e7db-8340-45ac-97ce-3b1a7fd58e10".to_owned();
        let mut provider =
            FakeRecoveryProvider::new([vec![unrelated.clone()], vec![unrelated.clone()]]);

        let observation = reconcile_bound_session(
            &bound,
            false,
            START_PROVIDER_HASH,
            START_PROVIDER_HASH,
            &mut provider,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();

        assert!(provider.stopped.is_empty());
        assert_eq!(
            observation.disposition,
            WsbRecoveryDisposition::AlreadyAbsent
        );
        assert_eq!(observation.session_ids_before, vec![unrelated]);
    }

    #[test]
    fn recovery_fails_closed_on_bound_or_unrelated_session_drift() {
        let bound = CanonicalSandboxId::parse("1782a9f3-4e9a-45ac-abe1-afc8ecf78666").unwrap();
        let unrelated = "7be1e7db-8340-45ac-97ce-3b1a7fd58e10".to_owned();
        let deadline = Instant::now() + Duration::from_secs(1);

        let mut still_present = FakeRecoveryProvider::new([
            vec![bound.as_str().to_owned()],
            vec![bound.as_str().to_owned()],
        ]);
        assert!(matches!(
            reconcile_bound_session(
                &bound,
                false,
                START_PROVIDER_HASH,
                START_PROVIDER_HASH,
                &mut still_present,
                deadline,
            ),
            Err(WindowsSandboxInvocationError::Protocol(_))
        ));

        let mut unrelated_drift =
            FakeRecoveryProvider::new([vec![unrelated, bound.as_str().to_owned()], Vec::new()]);
        assert!(matches!(
            reconcile_bound_session(
                &bound,
                false,
                START_PROVIDER_HASH,
                START_PROVIDER_HASH,
                &mut unrelated_drift,
                deadline,
            ),
            Err(WindowsSandboxInvocationError::Protocol(_))
        ));
        assert_eq!(unrelated_drift.stopped, vec![bound.as_str()]);
    }

    fn live_id(label: &str) -> CanonicalSandboxId {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let digest = hex::encode(Sha256::digest(
            format!("{label}:{}:{nonce}", std::process::id()).as_bytes(),
        ));
        CanonicalSandboxId::parse(&format!(
            "{}-{}-{}-{}-{}",
            &digest[0..8],
            &digest[8..12],
            &digest[12..16],
            &digest[16..20],
            &digest[20..32]
        ))
        .unwrap()
    }

    #[test]
    fn version_parser_is_exact() {
        assert_eq!(parse_version(b"0.8.107.0\r\n").unwrap(), "0.8.107.0");
        assert!(parse_version(b"0.8.107\n").is_err());
        assert!(parse_version(b"v0.8.107.0\n").is_err());
    }

    #[test]
    fn list_parser_matches_captured_protocol_and_rejects_drift() {
        assert_eq!(
            parse_list_v0_8_107_0(br#"{"WindowsSandboxEnvironments":[]}"#).unwrap(),
            0
        );
        assert_eq!(parse_list_v0_8_107_0(br#"{"WindowsSandboxEnvironments":[{"Id":"1782a9f3-4e9a-45ac-abe1-afc8ecf78666"}]}"#).unwrap(), 1);
        assert!(parse_list_v0_8_107_0(br#"{"sessions":[]}"#).is_err());
        assert!(
            parse_list_v0_8_107_0(br#"{"WindowsSandboxEnvironments":[],"extra":true}"#).is_err()
        );
        assert!(
            parse_list_v0_8_107_0(
                br#"{"WindowsSandboxEnvironments":[],"WindowsSandboxEnvironments":[]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn start_parser_matches_captured_protocol_and_rejects_drift() {
        let id = "1782a9f3-4e9a-45ac-abe1-afc8ecf78666";
        assert_eq!(
            parse_start_v0_8_107_0(format!(r#"{{"Id":"{id}"}}"#).as_bytes()).unwrap(),
            id
        );
        assert!(parse_start_v0_8_107_0(format!(r#"{{"id":"{id}"}}"#).as_bytes()).is_err());
        assert!(
            parse_start_v0_8_107_0(format!(r#"{{"Id":"{id}","extra":true}}"#).as_bytes()).is_err()
        );
        assert!(
            parse_start_v0_8_107_0(format!(r#"{{"Id":"{id}","Id":"{id}"}}"#).as_bytes()).is_err()
        );
    }

    #[test]
    #[ignore = "starts a real Windows Sandbox session; set AIW_RUN_LIVE_WSB_TEST=1 and run explicitly"]
    fn live_exact_session_lifecycle() {
        if std::env::var("AIW_RUN_LIVE_WSB_TEST").as_deref() != Ok("1") {
            return;
        }
        let readiness = assess_windows_sandbox();
        assert!(readiness.supported, "{:?}", readiness.blockers);
        let provider_hash = readiness.provider_binary.unwrap().sha256;
        let mut lease = acquire_windows_sandbox(&provider_hash).unwrap();
        assert!(lease.list().unwrap().session_ids.is_empty());

        let id = live_id("aiw-live-wsb");
        let workspace = std::env::temp_dir().join(format!("aiw-live-{}", id.as_str()));
        let tools = workspace.join("tools");
        let output = workspace.join("output");
        std::fs::create_dir_all(&tools).unwrap();
        std::fs::create_dir(&output).unwrap();
        std::fs::write(
            tools.join("agent.exe"),
            b"not-executed-by-this-lifecycle-test",
        )
        .unwrap();
        let plan = WindowsSandboxPlan {
            schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.to_owned(),
            workspace_root: workspace.to_string_lossy().into_owned(),
            mappings: vec![
                aiw_provider_wsb::MappedFolder {
                    purpose: aiw_provider_wsb::MappingPurpose::Tools,
                    host_folder: tools.to_string_lossy().into_owned(),
                    sandbox_folder: "C:\\AIW\\Tools".to_owned(),
                },
                aiw_provider_wsb::MappedFolder {
                    purpose: aiw_provider_wsb::MappingPurpose::Output,
                    host_folder: output.to_string_lossy().into_owned(),
                    sandbox_folder: "C:\\AIW\\Output".to_owned(),
                },
            ],
            probe: aiw_provider_wsb::GoldenProbe {
                executable: "C:\\AIW\\Tools\\agent.exe".to_owned(),
                request: None,
                output: "C:\\AIW\\Output\\token.json".to_owned(),
            },
            memory_mb: Some(2048),
        };
        eprintln!(
            "AIW live recovery state: workspace={} sandboxId={}",
            workspace.display(),
            id.as_str()
        );
        let started = lease.start(&id, &plan);
        let observed_after_start = lease.list();
        let stop = lease.stop_owned();
        let observed_after_stop = lease.list();
        assert_eq!(started.unwrap().session_id, id.as_str());
        assert_eq!(
            observed_after_start.unwrap().session_ids,
            vec![id.as_str().to_owned()]
        );
        assert!(stop.unwrap().output_was_empty);
        assert!(observed_after_stop.unwrap().session_ids.is_empty());
        drop(lease);

        let recovery_id = live_id("aiw-live-wsb-recovery");
        let mut interrupted = acquire_windows_sandbox(&provider_hash).unwrap();
        interrupted.start(&recovery_id, &plan).unwrap();
        assert_eq!(
            interrupted.list().unwrap().session_ids,
            vec![recovery_id.as_str().to_owned()]
        );
        drop(interrupted);
        let mut recovery =
            acquire_windows_sandbox_recovery(&provider_hash, recovery_id.clone()).unwrap();
        let recovered = recovery.reconcile().unwrap();
        assert_eq!(recovered.session_id, recovery_id.as_str());
        assert_eq!(recovered.disposition, WsbRecoveryDisposition::Stopped);
        assert!(recovered.session_ids_after.is_empty());
        std::fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    #[ignore = "executes the fixed golden probe in a real Windows Sandbox; set AIW_RUN_LIVE_WSB_PROBE=1 and AIW_LIVE_GOLDEN_PROBE"]
    fn live_mapped_golden_probe() {
        if std::env::var("AIW_RUN_LIVE_WSB_PROBE").as_deref() != Ok("1") {
            return;
        }
        let probe_source = std::path::PathBuf::from(
            std::env::var_os("AIW_LIVE_GOLDEN_PROBE")
                .expect("AIW_LIVE_GOLDEN_PROBE must name the statically linked probe"),
        );
        let readiness = assess_windows_sandbox();
        assert!(readiness.supported, "{:?}", readiness.blockers);
        let provider_hash = readiness.provider_binary.unwrap().sha256;
        let mut lease = acquire_windows_sandbox(&provider_hash).unwrap();
        assert!(lease.list().unwrap().session_ids.is_empty());

        let id = live_id("aiw-live-wsb-probe");
        let workspace = std::env::temp_dir().join(format!("aiw-live-probe-{}", id.as_str()));
        let tools = workspace.join("tools");
        let output = workspace.join("output");
        std::fs::create_dir_all(&tools).unwrap();
        std::fs::create_dir(&output).unwrap();
        std::fs::copy(&probe_source, tools.join("aiw-golden-probe.exe")).unwrap();
        let plan = WindowsSandboxPlan {
            schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.to_owned(),
            workspace_root: workspace.to_string_lossy().into_owned(),
            mappings: vec![
                aiw_provider_wsb::MappedFolder {
                    purpose: aiw_provider_wsb::MappingPurpose::Tools,
                    host_folder: tools.to_string_lossy().into_owned(),
                    sandbox_folder: "C:\\AIW\\Tools".to_owned(),
                },
                aiw_provider_wsb::MappedFolder {
                    purpose: aiw_provider_wsb::MappingPurpose::Output,
                    host_folder: output.to_string_lossy().into_owned(),
                    sandbox_folder: "C:\\AIW\\Output".to_owned(),
                },
            ],
            probe: aiw_provider_wsb::GoldenProbe {
                executable: "C:\\AIW\\Tools\\aiw-golden-probe.exe".to_owned(),
                request: None,
                output: "C:\\AIW\\Output\\token.json".to_owned(),
            },
            memory_mb: Some(2048),
        };

        eprintln!(
            "AIW live recovery state: workspace={} sandboxId={}",
            workspace.display(),
            id.as_str()
        );
        let started = lease.start(&id, &plan);
        let connected = if started.is_ok() {
            lease.connect_owned()
        } else {
            Err(WindowsSandboxInvocationError::Protocol(
                "start failed before connect".to_owned(),
            ))
        };
        let deadline = Instant::now() + Duration::from_secs(120);
        let token = output.join("token.json");
        while started.is_ok() && !token.is_file() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
        let stop = lease.stop_owned();
        let final_sessions = lease.list();
        let token_bytes = std::fs::read(&token);

        assert_eq!(started.unwrap().session_id, id.as_str());
        assert_eq!(connected.unwrap().session_id, id.as_str());
        assert!(stop.unwrap().output_was_empty);
        assert!(final_sessions.unwrap().session_ids.is_empty());
        let token: serde_json::Value = serde_json::from_slice(&token_bytes.unwrap()).unwrap();
        assert_eq!(token["schemaVersion"], "aiw.dev/token-evidence/v0alpha1");
        std::fs::remove_dir_all(workspace).unwrap();
    }
}
