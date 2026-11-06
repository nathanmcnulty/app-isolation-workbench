//! Exact v1.0.1 C-ABI request probe. No CLI startup, spawn or recovery exports.
//! Loading vendor code is execution and requires the reviewed disposable-worker
//! package/authorization. Merely compiling this module does not load the DLL.
use aiw_provider_mxc::process_container::{self as contract, FixedOperation, FixedRequest};
use std::ffi::{CString, OsStr, c_char};
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use windows::Win32::Foundation::{FreeLibrary, HMODULE};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows::core::{PCSTR, PCWSTR};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
// Strict holds apply to approved guest-local copies, never relaxed to accept
// mapped transport. The separate package setup must establish these identities.
const ROOT: &str = r"C:\AIW\MxcProbe";
const DLL: &str = r"C:\AIW\MxcProbe\mxc_ffi.dll";
const PROBE: &str = r"C:\AIW\MxcProbe\mxc_process_probe.exe";
const TRANSPORT_PROBE: &str = r"C:\AIW\Tools\mxc_process_probe.exe";
const DATA: &str = r"C:\AIW\MxcProbe\Data";
const RESULT: &str = r"C:\AIW\MxcProbe\Data\probe.json";
const OUTPUT: &str = r"C:\AIW\MxcProbeOutput";

// Copied/reviewed only for fda29ac's error_detail.rs and lib.rs. This ABI is not
// stable across arbitrary DLL versions. Every owned output uses its matching DLL
// deallocator while the exact held module is still loaded.
#[repr(C)]
#[derive(Default)]
struct ErrorDetail {
    message: *mut c_char,
    operation: *mut c_char,
    native_code: *mut c_char,
    remediation: *mut c_char,
}
type Version = unsafe extern "C" fn() -> *const c_char;
type Probe = unsafe extern "C" fn(*const c_char, *mut *mut c_char, *mut ErrorDetail) -> i32;
type StringFree = unsafe extern "C" fn(*mut c_char);
type ErrorFree = unsafe extern "C" fn(*mut ErrorDetail);

struct Runtime {
    module: HMODULE,
    _directories: Vec<fs::File>,
    file: crate::HeldApplicationFile,
    probe: Probe,
    string_free: StringFree,
    error_free: ErrorFree,
}
impl Drop for Runtime {
    fn drop(&mut self) {
        // No returned vendor allocation or live handle survives a probe call.
        let _ = unsafe { FreeLibrary(self.module) };
    }
}

impl Runtime {
    fn open() -> Result<Self> {
        let directories = hold_fixed_ancestry()?;
        let file =
            crate::HeldApplicationFile::open_bounded(Path::new(DLL), contract::RUNTIME_DLL_SIZE)?;
        if file.observation().size_bytes != contract::RUNTIME_DLL_SIZE
            || file.observation().sha256 != contract::RUNTIME_DLL_SHA256
        {
            return Err("MXC DLL differs from reviewed official bytes; not loaded".into());
        }
        // Absolute, held, non-reparse DLL and ancestry. Dependency search excludes
        // cwd, PATH, user directories and unheld siblings; reviewed imports are
        // system DLLs. Optional backend sidecars are intentionally unavailable.
        let path: Vec<u16> = OsStr::new(DLL).encode_wide().chain(Some(0)).collect();
        let module =
            unsafe { LoadLibraryExW(PCWSTR(path.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }?;
        let loaded = (|| -> Result<Self> {
            let mut module_path = [0_u16; 1024];
            let length = unsafe { GetModuleFileNameW(Some(module), &mut module_path) } as usize;
            if length == 0 || length >= module_path.len() {
                return Err("loaded MXC module path unavailable or truncated".into());
            }
            let actual_path = std::path::PathBuf::from(String::from_utf16(&module_path[..length])?);
            if !crate::control_appcontainer::research_sevenzip::fixed_role_image(&actual_path, DLL)
            {
                return Err("loaded MXC module differs from exact held local DLL path".into());
            }
            let loaded_file =
                crate::HeldApplicationFile::open_bounded(&actual_path, contract::RUNTIME_DLL_SIZE)?;
            if loaded_file.observation() != file.observation() {
                return Err("loaded MXC module differs from held runtime identity".into());
            }
            // Exact symbol signatures above are source-pinned; no caller name.
            let version: Version = unsafe { std::mem::transmute(export(module, c"mxc_version")?) };
            let probe: Probe = unsafe {
                std::mem::transmute(export(module, c"mxc_probe_request_json_with_error")?)
            };
            let string_free: StringFree =
                unsafe { std::mem::transmute(export(module, c"mxc_string_free")?) };
            let error_free: ErrorFree =
                unsafe { std::mem::transmute(export(module, c"mxc_error_detail_free")?) };
            let version_text = unsafe { read_string(version(), 128) }?;
            if version_text != contract::RELEASE {
                return Err(format!("MXC runtime version differs: {version_text}").into());
            }
            file.revalidate()?;
            Ok(Self {
                module,
                _directories: directories,
                file,
                probe,
                string_free,
                error_free,
            })
        })();
        if loaded.is_err() {
            let _ = unsafe { FreeLibrary(module) };
        }
        loaded
    }

    fn probe(&self, operation: FixedOperation) -> Result<serde_json::Value> {
        let request = FixedRequest::new(operation)?;
        let input = CString::new(request.json())?;
        let mut output = std::ptr::null_mut();
        let mut error = ErrorDetail::default();
        self.file.revalidate()?;
        let status = unsafe { (self.probe)(input.as_ptr(), &mut output, &mut error) };
        // Always release all returned allocations, including on invalid output.
        let observed = (|| -> Result<serde_json::Value> {
            if status != 0 {
                let details = [
                    &error.message,
                    &error.operation,
                    &error.native_code,
                    &error.remediation,
                ]
                .into_iter()
                .map(|p| {
                    if p.is_null() {
                        Ok(None)
                    } else {
                        unsafe { read_string(*p, 8192) }.map(Some)
                    }
                })
                .collect::<Result<Vec<_>>>()?;
                return Ok(
                    serde_json::json!({"operation":operation,"requestSha256":request.sha256(),
                    "request":serde_json::from_str::<serde_json::Value>(request.json())?,
                    "ffiStatus":status,"errorDetail":details,"enforcement":"unmeasured"}),
                );
            }
            let raw = unsafe { read_string(output, 65_536) }?;
            let bound = contract::parse_probe(&request, request.sha256(), raw.as_bytes())?;
            Ok(
                serde_json::json!({"operation":operation,"requestSha256":request.sha256(),
                "request":serde_json::from_str::<serde_json::Value>(request.json())?,
                "ffiStatus":status,"probe":bound.output,"disposition":bound.disposition,
                "enforcement":"unmeasured"}),
            )
        })();
        unsafe {
            if !output.is_null() {
                (self.string_free)(output);
            }
            (self.error_free)(&mut error);
        }
        self.file.revalidate()?;
        observed
    }
}

fn export(module: HMODULE, name: &std::ffi::CStr) -> Result<unsafe extern "system" fn() -> isize> {
    unsafe { GetProcAddress(module, PCSTR(name.as_ptr().cast())) }
        .ok_or_else(|| format!("missing fixed MXC export {name:?}").into())
}

/// Safety: pointer is an allocation/static string supplied by the exact trusted
/// DLL under the pinned C-string ABI, live until its matching free call.
unsafe fn read_string(pointer: *const c_char, maximum: usize) -> Result<String> {
    if pointer.is_null() {
        return Err("MXC returned a missing string".into());
    }
    for length in 0..=maximum {
        if unsafe { *pointer.add(length) } == 0 {
            let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
            return Ok(std::str::from_utf8(bytes)?.to_owned());
        }
    }
    Err("MXC returned an oversized string".into())
}

fn hold_fixed_ancestry() -> Result<Vec<fs::File>> {
    [r"C:\", r"C:\AIW", ROOT]
        .into_iter()
        .map(|name| {
            let file = fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(name)?;
            let metadata = file.metadata()?;
            if !metadata.is_dir()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            {
                return Err("MXC fixed ancestry is not an ordinary directory".into());
            }
            Ok(file)
        })
        .collect()
}

pub fn run_fixed_probe() -> Result<()> {
    let exe = std::env::current_exe()?;
    let token = aiw_token::collect_current_process_token()?;
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if setup_arguments(&arguments)
        && crate::control_appcontainer::research_sevenzip::fixed_role_image(&exe, TRANSPORT_PROBE)
        && token.is_elevated
        && !token.is_app_container
        && token.user_sid == crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")?
    {
        return setup_probe();
    }
    if arguments != ["--probe"]
        || !crate::control_appcontainer::research_sevenzip::fixed_role_image(&exe, PROBE)
        || token.is_elevated
        || token.is_app_container
        || token.user_sid
            != crate::control_appcontainer::fixed_account_sid(
                aiw_provider_wsb::STANDARD_USER_ACCOUNT_NAME,
            )?
    {
        return Err(
            "fixed disposable standard-user MXC probe role required; DLL not loaded".into(),
        );
    }
    let observed = collect_probe(&token);
    let report = match &observed {
        Ok(report) => report.clone(),
        Err(error) => {
            serde_json::json!({"schemaVersion":"aiw.dev/mxc-request-probe-failure/v0alpha1",
            "driverError":error.to_string().chars().take(2048).collect::<String>(),
            "requestedApplicationExecution":false,"enforcement":"unmeasured"})
        }
    };
    let _root = hold_fixed_ancestry()?;
    let _data = hold_directory(DATA)?;
    write_new_json(RESULT, &report)?;
    observed.map(|_| ())
}

fn setup_arguments(arguments: &[std::ffi::OsString]) -> bool {
    arguments == ["--output", crate::research_publication::CAPABILITY_RESULT]
}

fn collect_probe(token: &aiw_token::TokenEvidence) -> Result<serde_json::Value> {
    let windows = crate::observe_windows_version()?;
    require_guest_windows(&windows)?;
    let runtime = Runtime::open()?;
    let mut observations = Vec::new();
    let mut collection_error = None;
    let mut failed_operation = None;
    for operation in [
        FixedOperation::Driver,
        FixedOperation::Boundary,
        FixedOperation::Create,
        FixedOperation::Test,
        FixedOperation::Extract,
    ] {
        match runtime.probe(operation) {
            Ok(observation) => observations.push(observation),
            Err(error) => {
                collection_error = Some(error.to_string().chars().take(2048).collect::<String>());
                failed_operation = Some(operation);
                break;
            }
        }
    }
    Ok(serde_json::json!({
        "schemaVersion":"aiw.dev/mxc-request-probe-observations/v0alpha1",
        "dllSha256":contract::RUNTIME_DLL_SHA256,"dllSizeBytes":contract::RUNTIME_DLL_SIZE,
        "runtimeSource":contract::SOURCE_REVISION,"runtimeRelease":contract::RELEASE,
            "windows":windows,"observerToken":token,
            "collectionComplete":collection_error.is_none(),"collectionError":collection_error,"failedOperation":failed_operation,
        "requests":observations,"requestedApplicationExecution":false,"enforcement":"unmeasured"
    }))
}

fn setup_probe() -> Result<()> {
    use crate::guest_document::paired_inputs::mxc_probe::FixedMxcProbeInputs;
    use crate::guest_msi::GuestProcess;
    use crate::guest_standard_user::StandardUserSession;
    // Acquire the common C:/AIW mapped ancestry before following either fixed
    // output or local root name; never join distinct renamed AIW ancestors.
    let mut inputs = FixedMxcProbeInputs::open()?;
    let _output = hold_directory(OUTPUT)?;
    if fs::read_dir(OUTPUT)?.next().is_some() || Path::new(ROOT).try_exists()? {
        return Err("fresh empty mapped output and absent local MXC probe root required".into());
    }
    fs::create_dir(ROOT)?;
    let _root = hold_fixed_ancestry()?;
    set_owned_acl(ROOT, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    let operation = (|| -> Result<serde_json::Value> {
        let windows = crate::observe_windows_version()?;
        require_guest_windows(&windows)?;
        let standard = StandardUserSession::establish()?;
        let sid = &standard.context().user_sid;
        set_owned_acl(
            ROOT,
            &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{sid})"),
        )?;
        let mut helper = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(PROBE)?;
        inputs.copy_helper(&mut helper)?;
        drop(helper);
        let mut runtime = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(DLL)?;
        inputs.copy_runtime(&mut runtime)?;
        drop(runtime);
        let held_helper =
            crate::HeldApplicationFile::open_bounded(Path::new(PROBE), inputs.helper_size())?;
        let held_runtime =
            crate::HeldApplicationFile::open_bounded(Path::new(DLL), contract::RUNTIME_DLL_SIZE)?;
        if held_helper.observation().sha256 != inputs.helper_hash()
            || held_helper.observation().size_bytes != inputs.helper_size()
            || held_runtime.observation().sha256 != contract::RUNTIME_DLL_SHA256
            || held_runtime.observation().size_bytes != contract::RUNTIME_DLL_SIZE
        {
            return Err("guest-local runtime/helper differs from held mapped bytes".into());
        }
        fs::create_dir(DATA)?;
        set_owned_acl(
            DATA,
            &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"),
        )?;
        let _data = hold_directory(DATA)?;
        let (child, held_token) =
            GuestProcess::start_standard_user_measured(PROBE, &["--probe".into()], &standard)?;
        let exit = child.wait_for_exit(std::time::Duration::from_secs(60));
        let cleanup = child.cleanup();
        // Retain explicit failure/cleanup facts even when the child published no
        // output. No retry, recovery export, or application dispatch is present.
        let raw = (|| -> Result<serde_json::Value> {
            let held = crate::HeldApplicationFile::open_bounded(Path::new(RESULT), 1024 * 1024)?;
            Ok(serde_json::from_slice(&held.read_bounded(1024 * 1024)?)?)
        })();
        let mut validation_errors = Vec::new();
        for validation in [
            held_helper.revalidate().map_err(|error| error.to_string()),
            held_runtime.revalidate().map_err(|error| error.to_string()),
            inputs.revalidate(),
        ] {
            if let Err(error) = validation {
                validation_errors.push(error.chars().take(2048).collect::<String>());
            }
        }
        Ok(
            serde_json::json!({"schemaVersion":"aiw.dev/mxc-probe-trial/v0alpha1",
            "researchOnly":true,"helperSha256":inputs.helper_hash(),"helperSizeBytes":inputs.helper_size(),
            "dllSha256":contract::RUNTIME_DLL_SHA256,"dllSizeBytes":contract::RUNTIME_DLL_SIZE,
            "windows":windows,"standardContext":standard.context(),
            "heldObserverToken":held_token,"childExitCode":exit.as_ref().ok(),
            "childError":exit.as_ref().err().map(ToString::to_string),
            "ownedJobEmpty":cleanup.is_ok(),"cleanupError":cleanup.err().map(|error| error.to_string()),
            "probe":raw.as_ref().ok(),"probeReadError":raw.err().map(|error| error.to_string()),
            "payloadBindingsVerified":validation_errors.is_empty(),"validationErrors":validation_errors,
            "requestedApplicationExecution":false,"enforcement":"unmeasured"}),
        )
    })();
    let report = operation.unwrap_or_else(|error| {
        serde_json::json!({
        "schemaVersion":"aiw.dev/mxc-probe-trial-failure/v0alpha1","researchOnly":true,
        "driverError":error.to_string().chars().take(2048).collect::<String>(),
        "requestedApplicationExecution":false,"enforcement":"unmeasured"})
    });
    crate::research_publication::publish_mapped_json(
        crate::research_publication::MappedPublication::Capability,
        &report,
    )
}

fn require_guest_windows(windows: &aiw_probe::WindowsVersionObservation) -> Result<()> {
    windows.validate()?;
    if (
        windows.major,
        windows.minor,
        windows.build,
        windows.revision,
        windows.observer_architecture.as_str(),
    ) != (10, 0, 26100, 9711, "x86_64")
    {
        return Err(
            "guest Windows differs from the reviewed capability trial; DLL not loaded".into(),
        );
    }
    Ok(())
}

fn write_new_json(path: &str, report: &serde_json::Value) -> Result<()> {
    use std::io::Write;
    use windows::Win32::Storage::FileSystem::{MOVE_FILE_FLAGS, MoveFileExW};
    let pending = format!("{path}.pending");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(&serde_json::to_vec(report)?)?;
    file.sync_all()?;
    drop(file);
    let pending: Vec<u16> = pending.encode_utf16().chain(Some(0)).collect();
    let destination: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    // No REPLACE_EXISTING, COPY_ALLOWED or delayed move: one-volume publication
    // cannot overwrite an old result. A failed pending file remains inspectable.
    unsafe {
        MoveFileExW(
            PCWSTR(pending.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVE_FILE_FLAGS(0),
        )
    }?;
    Ok(())
}

fn hold_directory(path: &str) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err("fixed probe directory is not ordinary".into());
    }
    Ok(file)
}

fn set_owned_acl(path: &str, sddl: &str) -> Result<()> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SetFileSecurityW,
    };
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }?;
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let result = unsafe {
        SetFileSecurityW(
            PCWSTR(path.as_ptr()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    result.ok()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_probe_rejects_host_before_loading_runtime() {
        assert!(
            run_fixed_probe()
                .unwrap_err()
                .to_string()
                .contains("fixed disposable standard-user")
        );
    }
    #[test]
    fn vendor_string_reader_rejects_invalid_utf8_missing_and_overbound_data() {
        let text = CString::new("valid").unwrap();
        assert_eq!(unsafe { read_string(text.as_ptr(), 5) }.unwrap(), "valid");
        assert!(unsafe { read_string(text.as_ptr(), 4) }.is_err());
        assert!(unsafe { read_string(std::ptr::null(), 4) }.is_err());
        let bytes = [0xff_u8, 0];
        assert!(unsafe { read_string(bytes.as_ptr().cast(), 2) }.is_err());
    }
    #[test]
    fn setup_role_accepts_only_the_uppercase_fixed_publication_output() {
        let args = |items: &[&str]| {
            items
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        };
        assert!(setup_arguments(&args(&[
            "--output",
            r"C:\AIW\MxcProbeOutput\RESULT.DAT"
        ])));
        for items in [
            &["--setup"][..],
            &["--output", r"C:\private\result.json"],
            &["--output", r"C:\AIW\MxcProbeOutput\result.json"],
            &["--output", r"C:\AIW\MxcProbeOutput\result.json", "--probe"],
        ] {
            assert!(!setup_arguments(&args(items)));
        }
    }
    #[test]
    fn probe_publication_is_receipt_last_and_never_overwrites_an_old_result() {
        let root =
            std::env::temp_dir().join(format!("aiw-mxc-probe-publish-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let path = root.join("result.json");
        write_new_json(path.to_str().unwrap(), &serde_json::json!({"first":true})).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(!root.join("result.json.pending").exists());
        assert!(
            write_new_json(path.to_str().unwrap(), &serde_json::json!({"second":true})).is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(root.join("result.json.pending").exists());
        fs::remove_file(root.join("result.json.pending")).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
