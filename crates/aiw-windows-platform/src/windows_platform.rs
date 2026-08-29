use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aiw_probe::{
    BinaryIdentity, CatalogTrustIdentity, ReadinessState, WindowsFileIdentity,
    WindowsPackageIdentity, WindowsSandboxCliProtocol, WindowsSandboxReadiness,
};
use aiw_provider_wsb::RenderedWindowsSandboxConfig;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::ApplicationModel::{Package, PackageSignatureKind};
use windows::Management::Deployment::PackageManager;
use windows::System::ProcessorArchitecture;
use windows::System::Profile::AnalyticsInfo;
use windows::Win32::Foundation::{CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminReleaseContext,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_DATA_PROVIDER_FLAGS, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_NAME_NORMALIZED, FILE_SHARE_READ, GetFileInformationByHandle,
    GetFinalPathNameByHandleW,
};
use windows::Win32::System::Threading::{
    CreateMutexW, IsProcessorFeaturePresent, PF_VIRT_FIRMWARE_ENABLED, ReleaseMutex,
    WaitForSingleObject,
};
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::{HSTRING, PCWSTR, w};

const PACKAGE_NAME: &str = "MicrosoftWindows.WindowsSandbox";
const PACKAGE_FAMILY: &str = "MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy";
const PUBLISHER: &str =
    "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
const PUBLISHER_ID: &str = "cw5n1h2txyewy";
const PROVIDER_FILE: &str = "wsb.exe";
const CATALOG_FILE: &str = "AppxMetadata\\CodeIntegrity.cat";
const SUPPORTED_CLI_VERSION: &str = "0.8.107.0";
const STREAM_LIMIT: u64 = 64 * 1024;
const PROVIDER_MUTEX_NAME: PCWSTR = w!("Local\\AIW.WindowsSandbox.Provider.v1");

#[derive(Debug, Error)]
pub enum WindowsSandboxInvocationError {
    #[error("Windows Sandbox provider authority could not be established: {0}")]
    Authority(String),
    #[error("Windows Sandbox provider lease is held by another operation")]
    LeaseUnavailable,
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

pub struct BoundedWsbConfig {
    xml: String,
    sha256: String,
}

impl BoundedWsbConfig {
    pub fn from_rendered(
        rendered: &RenderedWindowsSandboxConfig,
    ) -> Result<Self, WindowsSandboxInvocationError> {
        if rendered.xml.is_empty() || rendered.xml.encode_utf16().count() > 24_000 {
            return Err(WindowsSandboxInvocationError::Configuration(
                "rendered configuration exceeds the fixed command-line budget".to_owned(),
            ));
        }
        let sha256 = hex::encode(Sha256::digest(rendered.xml.as_bytes()));
        if sha256 != rendered.sha256 {
            return Err(WindowsSandboxInvocationError::Configuration(
                "rendered configuration hash is inconsistent".to_owned(),
            ));
        }
        Ok(Self {
            xml: rendered.xml.clone(),
            sha256,
        })
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
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
pub struct WsbStopObservation {
    pub session_id: String,
    pub output_was_empty: bool,
}

pub struct WindowsSandboxExecutionLease {
    readiness: WindowsSandboxReadiness,
    provider_path: PathBuf,
    _provider: File,
    _catalog: File,
    _mutex: ProviderMutex,
}

impl WindowsSandboxExecutionLease {
    pub fn readiness(&self) -> &WindowsSandboxReadiness {
        &self.readiness
    }

    pub fn list(&self) -> Result<WsbListObservation, WindowsSandboxInvocationError> {
        let output = invoke_read_only(
            &self.provider_path,
            &["list", "--raw"],
            Duration::from_secs(15),
        )
        .map_err(WindowsSandboxInvocationError::Process)?;
        let session_ids = parse_list_ids_v0_8_107_0(&output.stdout)
            .map_err(WindowsSandboxInvocationError::Protocol)?;
        Ok(WsbListObservation { session_ids })
    }

    pub fn start(
        &self,
        sandbox_id: &CanonicalSandboxId,
        config: BoundedWsbConfig,
    ) -> Result<WsbStartObservation, WindowsSandboxInvocationError> {
        let output = invoke_read_only(
            &self.provider_path,
            &[
                "start",
                "--raw",
                "--id",
                sandbox_id.as_str(),
                "--config",
                &config.xml,
            ],
            Duration::from_secs(120),
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

    pub fn stop(
        &self,
        sandbox_id: &CanonicalSandboxId,
    ) -> Result<WsbStopObservation, WindowsSandboxInvocationError> {
        let output = invoke_read_only(
            &self.provider_path,
            &["stop", "--raw", "--id", sandbox_id.as_str()],
            Duration::from_secs(120),
        )
        .map_err(WindowsSandboxInvocationError::Process)?;
        if !output.stdout.is_empty() {
            return Err(WindowsSandboxInvocationError::Protocol(
                "stop response must be empty for CLI protocol 0.8.107.0".to_owned(),
            ));
        }
        Ok(WsbStopObservation {
            session_id: sandbox_id.as_str().to_owned(),
            output_was_empty: true,
        })
    }
}

pub fn acquire_windows_sandbox(
    expected_provider_sha256: &str,
) -> Result<WindowsSandboxExecutionLease, WindowsSandboxInvocationError> {
    if expected_provider_sha256.len() != 64
        || !expected_provider_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(WindowsSandboxInvocationError::Authority(
            "expected provider SHA-256 must be lowercase hexadecimal".to_owned(),
        ));
    }
    let mutex = ProviderMutex::try_acquire()?;
    let readiness = assess_windows_sandbox();
    if !readiness.supported {
        return Err(WindowsSandboxInvocationError::Authority(
            readiness.blockers.join(" "),
        ));
    }
    let provider_identity = readiness.provider_binary.as_ref().ok_or_else(|| {
        WindowsSandboxInvocationError::Authority("provider identity is absent".to_owned())
    })?;
    if provider_identity.sha256 != expected_provider_sha256 {
        return Err(WindowsSandboxInvocationError::Authority(
            "provider hash differs from the approved identity".to_owned(),
        ));
    }
    let provider_path = PathBuf::from(&provider_identity.canonical_path);
    let mut provider =
        open_held_file(&provider_path).map_err(WindowsSandboxInvocationError::Authority)?;
    let observed_path = final_path(&provider).map_err(WindowsSandboxInvocationError::Authority)?;
    let (observed_hash, observed_size) =
        hash_held_file(&mut provider).map_err(WindowsSandboxInvocationError::Authority)?;
    if !observed_path
        .to_string_lossy()
        .eq_ignore_ascii_case(&provider_identity.canonical_path)
        || observed_hash != provider_identity.sha256
        || observed_size != provider_identity.size_bytes
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
    Ok(WindowsSandboxExecutionLease {
        readiness,
        provider_path: observed_path,
        _provider: provider,
        _catalog: catalog,
        _mutex: mutex,
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

    let version_output = invoke_read_only(&final_path, &["--version"], Duration::from_secs(15))?;
    let cli_version = parse_version(&version_output.stdout)?;
    if cli_version != SUPPORTED_CLI_VERSION {
        return Err(format!(
            "AIW_WSB_CLI_VERSION_UNSUPPORTED: observed {cli_version}; supported protocol is {SUPPORTED_CLI_VERSION}."
        ));
    }
    let list_output = invoke_read_only(&final_path, &["list", "--raw"], Duration::from_secs(15))?;
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

struct ProcessOutput {
    stdout: Vec<u8>,
}

fn invoke_read_only(
    path: &Path,
    arguments: &[&str],
    timeout: Duration,
) -> Result<ProcessOutput, String> {
    let provider_root = path.parent().ok_or_else(|| {
        "AIW_WSB_CLI_PATH_REJECTED: provider has no protected package parent.".to_owned()
    })?;
    let mut command = Command::new(path);
    command
        .args(arguments)
        .current_dir(provider_root)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
            command.env(name, value);
        }
    }
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("PATH", PathBuf::from(system_root).join("System32"));
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("AIW_WSB_CLI_START_FAILED: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "AIW_WSB_CLI_PIPE_FAILED: stdout was unavailable.".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "AIW_WSB_CLI_PIPE_FAILED: stderr was unavailable.".to_owned())?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("AIW_WSB_CLI_WAIT_FAILED: {error}"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(
                "AIW_WSB_CLI_TIMEOUT: read-only provider observation exceeded its deadline."
                    .to_owned(),
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "AIW_WSB_CLI_PIPE_FAILED: stdout reader panicked.".to_owned())??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "AIW_WSB_CLI_PIPE_FAILED: stderr reader panicked.".to_owned())??;
    if !status.success() {
        return Err(format!(
            "AIW_WSB_CLI_FAILED: provider exited with {:?}; stderr={}",
            status.code(),
            bounded_text(&stderr)
        ));
    }
    if !stderr.is_empty() {
        return Err(format!(
            "AIW_WSB_CLI_STDERR_REJECTED: {}",
            bounded_text(&stderr)
        ));
    }
    Ok(ProcessOutput { stdout })
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

impl ProviderMutex {
    fn try_acquire() -> Result<Self, WindowsSandboxInvocationError> {
        let handle = unsafe { CreateMutexW(None, false, PROVIDER_MUTEX_NAME) }
            .map_err(|error| WindowsSandboxInvocationError::Authority(error.to_string()))?;
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            Ok(Self(handle))
        } else {
            let _ = unsafe { CloseHandle(handle) };
            if wait == WAIT_TIMEOUT {
                Err(WindowsSandboxInvocationError::LeaseUnavailable)
            } else {
                Err(WindowsSandboxInvocationError::Authority(format!(
                    "provider mutex wait failed with status 0x{:08x}",
                    wait.0
                )))
            }
        }
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
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let lease = acquire_windows_sandbox(&provider_hash).unwrap();
        assert!(lease.list().unwrap().session_ids.is_empty());

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let digest = hex::encode(Sha256::digest(
            format!("aiw-live-wsb:{}:{nonce}", std::process::id()).as_bytes(),
        ));
        let id = CanonicalSandboxId::parse(&format!(
            "{}-{}-{}-{}-{}",
            &digest[0..8],
            &digest[8..12],
            &digest[12..16],
            &digest[16..20],
            &digest[20..32]
        ))
        .unwrap();
        let xml = "<Configuration></Configuration>".to_owned();
        let config = BoundedWsbConfig {
            sha256: hex::encode(Sha256::digest(xml.as_bytes())),
            xml,
        };
        let started = lease.start(&id, config);
        let observed_after_start = lease.list();
        let stop = lease.stop(&id);
        let observed_after_stop = lease.list();
        assert_eq!(started.unwrap().session_id, id.as_str());
        assert_eq!(
            observed_after_start.unwrap().session_ids,
            vec![id.as_str().to_owned()]
        );
        assert!(stop.unwrap().output_was_empty);
        assert!(observed_after_stop.unwrap().session_ids.is_empty());
    }
}
