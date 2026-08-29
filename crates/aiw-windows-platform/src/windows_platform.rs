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
use serde_json::Value;
use sha2::{Digest, Sha256};
use windows::ApplicationModel::{Package, PackageSignatureKind};
use windows::Management::Deployment::PackageManager;
use windows::System::ProcessorArchitecture;
use windows::System::Profile::AnalyticsInfo;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminReleaseContext,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_NAME_NORMALIZED, FILE_SHARE_READ, GetFileInformationByHandle,
    GetFinalPathNameByHandleW,
};
use windows::Win32::System::Threading::{IsProcessorFeaturePresent, PF_VIRT_FIRMWARE_ENABLED};
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
        volume_serial_number: info.dwVolumeSerialNumber,
        file_id: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
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
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: WINTRUST_DATA_0 {
            pCatalog: &mut catalog_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
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
        member_tag,
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
    let mut child = Command::new(path)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("AIW_WSB_CLI_LIST_INVALID: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "AIW_WSB_CLI_LIST_INVALID: root must be an object.".to_owned())?;
    if object.len() != 1 || !object.contains_key("WindowsSandboxEnvironments") {
        return Err(
            "AIW_WSB_CLI_LIST_SCHEMA_DRIFT: expected only WindowsSandboxEnvironments.".to_owned(),
        );
    }
    let sessions = object["WindowsSandboxEnvironments"]
        .as_array()
        .ok_or_else(|| {
            "AIW_WSB_CLI_LIST_INVALID: WindowsSandboxEnvironments must be an array.".to_owned()
        })?;
    for session in sessions {
        let session = session
            .as_object()
            .ok_or_else(|| "AIW_WSB_CLI_LIST_INVALID: session must be an object.".to_owned())?;
        if session.len() != 1 || !session.contains_key("Id") {
            return Err(
                "AIW_WSB_CLI_LIST_SCHEMA_DRIFT: expected only Id in each session.".to_owned(),
            );
        }
        let id = session["Id"]
            .as_str()
            .ok_or_else(|| "AIW_WSB_CLI_LIST_INVALID: Id must be a string.".to_owned())?;
        if !is_uuid(id) {
            return Err("AIW_WSB_CLI_LIST_INVALID: Id was not a canonical UUID.".to_owned());
        }
    }
    Ok(sessions.len())
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

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
