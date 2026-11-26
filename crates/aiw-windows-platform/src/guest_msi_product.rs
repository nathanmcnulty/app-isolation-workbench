//! Fixed, read-only MSI identity and machine-registration queries in the guest.
//! No installer session, product enumeration, repair, or caller-supplied SQL.
use aiw_provider_wsb::{MsiMachineProductState, validate_msi_product_code};
use windows::core::{PCWSTR, PWSTR, w};

use crate::guest_msi::{GuestMsiExecutionError, GuestMsiProductRegistrationObservation};

#[link(name = "Msi")]
unsafe extern "system" {
    fn MsiOpenDatabaseW(path: PCWSTR, persist: PCWSTR, database: *mut u32) -> u32;
    fn MsiDatabaseOpenViewW(database: u32, query: PCWSTR, view: *mut u32) -> u32;
    fn MsiViewExecute(view: u32, record: u32) -> u32;
    fn MsiViewFetch(view: u32, record: *mut u32) -> u32;
    fn MsiRecordGetStringW(record: u32, field: u32, value: PWSTR, length: *mut u32) -> u32;
    fn MsiCloseHandle(handle: u32) -> u32;
    fn MsiGetComponentPathExW(
        product: PCWSTR,
        component: PCWSTR,
        user_sid: PCWSTR,
        context: u32,
        path: PWSTR,
        length: *mut u32,
    ) -> i32;
    fn MsiGetProductInfoExW(
        product: PCWSTR,
        user_sid: PCWSTR,
        context: u32,
        property: PCWSTR,
        value: PWSTR,
        length: *mut u32,
    ) -> u32;
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_DATA: u32 = 13;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_UNKNOWN_PRODUCT: u32 = 1605;
const MSIINSTALLCONTEXT_MACHINE: u32 = 4;

struct MsiHandle(u32);
impl Drop for MsiHandle {
    fn drop(&mut self) {
        // SAFETY: each successful MSI handle acquisition has one owner and is
        // dropped on the acquiring thread, after dependent handles are dropped.
        unsafe {
            MsiCloseHandle(self.0);
        }
    }
}

fn handle_result(
    code: u32,
    handle: u32,
    operation: &str,
) -> Result<MsiHandle, GuestMsiExecutionError> {
    if code == ERROR_SUCCESS && handle != 0 {
        Ok(MsiHandle(handle))
    } else {
        Err(failure(operation, code))
    }
}

fn failure(operation: &str, code: u32) -> GuestMsiExecutionError {
    GuestMsiExecutionError::Process(format!(
        "fixed MSI product {operation} failed with code {code}"
    ))
}

fn canonical_product_code(buffer: &[u16], length: u32) -> Result<String, GuestMsiExecutionError> {
    if length != 38 || buffer.len() <= 38 || buffer[38] != 0 {
        return Err(failure("identity shape", ERROR_INVALID_DATA));
    }
    let code = String::from_utf16(&buffer[..38])
        .map_err(|_| failure("identity encoding", ERROR_INVALID_DATA))?
        .to_ascii_uppercase();
    validate_msi_product_code(&code).map_err(|_| failure("identity format", ERROR_INVALID_DATA))?;
    Ok(code)
}

fn read_fixed_product_code() -> Result<String, GuestMsiExecutionError> {
    let mut database = 0;
    // SAFETY: fixed terminated path; null persist means MSIDBOPEN_READONLY,
    // never MsiOpenPackage or a running installation. Output pointer is valid.
    let result = unsafe {
        MsiOpenDatabaseW(
            w!(r"C:\AIW\Tools\application.msi"),
            PCWSTR::null(),
            &mut database,
        )
    };
    let database = handle_result(result, database, "database open")?;
    let mut view = 0;
    // SAFETY: live database, fixed one-column query, writable handle output.
    let result = unsafe {
        MsiDatabaseOpenViewW(
            database.0,
            w!("SELECT `Value` FROM `Property` WHERE `Property` = 'ProductCode'"),
            &mut view,
        )
    };
    let view = handle_result(result, view, "view open")?;
    // SAFETY: live view and no parameter record; query has no parameters.
    let result = unsafe { MsiViewExecute(view.0, 0) };
    if result != ERROR_SUCCESS {
        return Err(failure("view execute", result));
    }
    let mut record = 0;
    // SAFETY: live executed view and valid record output.
    let result = unsafe { MsiViewFetch(view.0, &mut record) };
    let record = handle_result(result, record, "identity fetch")?;
    let mut buffer = [0u16; 39];
    let mut length = buffer.len() as u32;
    // SAFETY: live record, fixed queried field, buffer length includes its terminator.
    let result =
        unsafe { MsiRecordGetStringW(record.0, 1, PWSTR(buffer.as_mut_ptr()), &mut length) };
    if result != ERROR_SUCCESS {
        return Err(failure("identity read", result));
    }
    let code = canonical_product_code(&buffer, length)?;
    let mut extra = 0;
    // SAFETY: same live view, valid output. Reject more than one row rather than
    // choosing an identity; a second successful handle is still closed.
    let result = unsafe { MsiViewFetch(view.0, &mut extra) };
    if result == ERROR_SUCCESS {
        let _extra = handle_result(result, extra, "extra identity")?;
        return Err(failure("duplicate identity", ERROR_INVALID_DATA));
    }
    if result != ERROR_NO_MORE_ITEMS {
        return Err(failure("identity completion", result));
    }
    Ok(code)
}

fn decode_machine_state(code: u32, buffer: &[u16], length: u32) -> MsiMachineProductState {
    match code {
        ERROR_UNKNOWN_PRODUCT => MsiMachineProductState::NotRegistered,
        ERROR_SUCCESS if length == 1 && buffer.len() >= 2 && buffer[1] == 0 => match buffer[0] {
            49 => MsiMachineProductState::Advertised,
            53 => MsiMachineProductState::Installed,
            _ => MsiMachineProductState::Unavailable {
                error_code: ERROR_INVALID_DATA,
            },
        },
        ERROR_SUCCESS => MsiMachineProductState::Unavailable {
            error_code: ERROR_INVALID_DATA,
        },
        error_code => MsiMachineProductState::Unavailable { error_code },
    }
}

fn machine_state(product_code: &str) -> MsiMachineProductState {
    let product: Vec<u16> = product_code.encode_utf16().chain(Some(0)).collect();
    let mut value = [0u16; 8];
    let mut length = value.len() as u32;
    // SAFETY: canonical terminated GUID, explicit machine context with null
    // SID, fixed INSTALLPROPERTY_PRODUCTSTATE, bounded writable output. This
    // query neither installs nor repairs the product and is called outside MSI execution.
    let code = unsafe {
        MsiGetProductInfoExW(
            PCWSTR(product.as_ptr()),
            PCWSTR::null(),
            MSIINSTALLCONTEXT_MACHINE,
            w!("State"),
            PWSTR(value.as_mut_ptr()),
            &mut length,
        )
    };
    decode_machine_state(code, &value, length)
}

pub(crate) struct ProductCapture {
    product_code: String,
    before_install: MsiMachineProductState,
}

impl ProductCapture {
    pub(crate) fn before_install() -> Result<Self, GuestMsiExecutionError> {
        let product_code = read_fixed_product_code()?;
        let before_install = machine_state(&product_code);
        Ok(Self {
            product_code,
            before_install,
        })
    }

    pub(crate) fn after_install(self) -> GuestMsiProductRegistrationObservation {
        let after_install = machine_state(&self.product_code);
        GuestMsiProductRegistrationObservation {
            product_code: self.product_code,
            before_install: self.before_install,
            after_install,
        }
    }
}

/// Install a fixed, verified MSI in the disposable worker, then inventory the
/// registered executable key paths. Installation and selection are separate.
pub fn execute_generic_msi_install(
    operation: &aiw_provider_wsb::CompiledMsiScenario,
    expected_bytes: u64,
) -> Result<aiw_provider_wsb::MsiInstallDiscovery, GuestMsiExecutionError> {
    use crate::guest_msi::{GuestProcess, complete_process_operation};
    use aiw_provider_wsb::{GENERIC_MSI_LOCAL_PACKAGE, GENERIC_MSI_LOCAL_ROOT};
    use std::{
        fs,
        io::{self, Read},
        path::Path,
        time::Duration,
    };

    if !(operation.is_generic_install_only() || operation.is_reviewed_launch())
        || operation.validate().is_err()
        || !(1..=128 * 1024 * 1024).contains(&expected_bytes)
    {
        return Err(failure("install contract", ERROR_INVALID_DATA));
    }
    let native = |error: io::Error| GuestMsiExecutionError::Process(error.to_string());
    fs::create_dir(GENERIC_MSI_LOCAL_ROOT).map_err(native)?;
    let mut source = fs::File::open(&operation.installer_path).map_err(native)?;
    let mut output = fs::File::create_new(GENERIC_MSI_LOCAL_PACKAGE).map_err(native)?;
    if io::copy(
        &mut io::Read::by_ref(&mut source).take(expected_bytes + 1),
        &mut output,
    )
    .map_err(native)?
        != expected_bytes
    {
        return Err(failure("staged extent", ERROR_INVALID_DATA));
    }
    output.sync_all().map_err(native)?;
    drop(output);
    let local = crate::HeldApplicationFile::open_bounded(
        Path::new(GENERIC_MSI_LOCAL_PACKAGE),
        expected_bytes,
    )
    .map_err(|error| GuestMsiExecutionError::Process(error.to_string()))?;
    if local.observation().sha256 != operation.application_sha256 {
        return Err(failure("staged digest", ERROR_INVALID_DATA));
    }
    let capture = ProductCapture::before_install()?;
    if capture.before_install != MsiMachineProductState::NotRegistered {
        return Err(failure(
            "expected fresh machine registration",
            ERROR_INVALID_DATA,
        ));
    }
    let process = GuestProcess::start(
        r"C:\Windows\System32\msiexec.exe",
        &operation.install_arguments,
    )?;
    let exit = process.wait_for_exit(Duration::from_secs(
        operation.install_timeout_seconds.into(),
    ));
    let cleanup = if exit.is_ok() {
        process.verify_empty_after_success()
    } else {
        process.cleanup()
    };
    let code = complete_process_operation(exit, cleanup)?;
    if code != 0 {
        return Err(GuestMsiExecutionError::Process(format!(
            "generic MSI exited with {code}"
        )));
    }
    local
        .revalidate()
        .map_err(|error| GuestMsiExecutionError::Process(error.to_string()))?;
    let registration = capture.after_install();
    if registration.after_install != MsiMachineProductState::Installed {
        return Err(failure(
            "completed machine registration",
            ERROR_INVALID_DATA,
        ));
    }
    let (candidates, candidate_scan_complete) = component_candidates(&registration.product_code);
    Ok(aiw_provider_wsb::MsiInstallDiscovery {
        product_code: registration.product_code,
        before_install: registration.before_install,
        after_install: registration.after_install,
        candidates,
        candidate_scan_complete,
    })
}

/// Retain the ordinary directory chain as well as the executable. In
/// particular the fixed path cannot be rebound by renaming a directory after
/// the file is hashed. Inventory holds are read-only and never dispatch.
struct HeldInstalledMsiCandidate {
    image: crate::HeldApplicationFile,
    parents: crate::guest_assessment::Directories,
}

impl HeldInstalledMsiCandidate {
    fn open(path: &std::path::Path) -> Result<Self, GuestMsiExecutionError> {
        use std::path::{Component, Path};

        let root = Path::new(r"C:\Program Files");
        let relative = path
            .strip_prefix(root)
            .map_err(|_| failure("candidate outside Program Files", ERROR_INVALID_DATA))?;
        let parent = path
            .parent()
            .filter(|_| {
                !relative.as_os_str().is_empty()
                    && relative
                        .components()
                        .all(|part| matches!(part, Component::Normal(_)))
            })
            .ok_or_else(|| failure("candidate path", ERROR_INVALID_DATA))?;
        let parents = crate::guest_assessment::Directories::hold(parent)
            .map_err(GuestMsiExecutionError::Process)?;
        let image = crate::HeldApplicationFile::open_bounded(
            path,
            aiw_provider_wsb::MAX_MSI_CANDIDATE_BYTES,
        )
        .map_err(|error| GuestMsiExecutionError::Process(error.to_string()))?;
        let observation = image.observation();
        let actual = observation
            .canonical_path
            .strip_prefix(r"\\?\")
            .unwrap_or(&observation.canonical_path);
        if !path
            .to_str()
            .is_some_and(|path| actual.eq_ignore_ascii_case(path))
            || observation.link_count != 1
            || !image.has_msi_candidate_pe_signature()
        {
            return Err(failure("candidate file identity", ERROR_INVALID_DATA));
        }
        parents
            .revalidate()
            .map_err(GuestMsiExecutionError::Process)?;
        Ok(Self { parents, image })
    }
}

/// Evidence returned only after the observed process accepts a graceful close
/// and its job is confirmed empty. Provider teardown remains a separate gate.
pub struct ReviewedMsiNativeOutcome {
    pub discovery: aiw_provider_wsb::MsiInstallDiscovery,
    pub application_token: aiw_token::TokenEvidence,
    pub process_id: u32,
    pub exit_code: i32,
}

/// Runs only inside the already approved disposable worker. The selected
/// image stays held from fresh measurement through suspended verification,
/// window observation and job cleanup.
pub fn execute_reviewed_msi_launch(
    operation: &aiw_provider_wsb::CompiledMsiScenario,
    expected_bytes: u64,
) -> Result<ReviewedMsiNativeOutcome, GuestMsiExecutionError> {
    use crate::{
        guest_msi::{GuestProcess, complete_process_operation},
        guest_standard_user::StandardUserSession,
    };
    use std::{
        os::windows::io::AsRawHandle,
        path::Path,
        time::{Duration, Instant},
    };
    use windows::Win32::{
        Foundation::HANDLE,
        System::Threading::{PROCESS_NAME_WIN32, QueryFullProcessImageNameW},
    };

    if !operation.is_reviewed_launch() || operation.validate().is_err() {
        return Err(failure("reviewed launch contract", ERROR_INVALID_DATA));
    }
    let reviewed = operation
        .reviewed_entry_point
        .as_ref()
        .ok_or_else(|| failure("missing reviewed launch selection", ERROR_INVALID_DATA))?;
    let discovery = execute_generic_msi_install(operation, expected_bytes)?;
    let matched = discovery
        .match_reviewed_candidate(&reviewed.product_code, &reviewed.candidate)
        .ok_or_else(|| {
            failure(
                "fresh registration differs from reviewed candidate",
                ERROR_INVALID_DATA,
            )
        })?;
    let held = HeldInstalledMsiCandidate::open(Path::new(&operation.launch_path))?;
    let image = held.image.observation();
    if image.size_bytes != matched.size_bytes || image.sha256 != matched.sha256 {
        return Err(failure(
            "held executable differs from reviewed candidate",
            ERROR_INVALID_DATA,
        ));
    }
    let ordinary = StandardUserSession::establish()?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(
            operation.process_wait_timeout_seconds.into(),
        ))
        .ok_or_else(|| failure("launch deadline", ERROR_INVALID_DATA))?;
    let (application, application_token) = GuestProcess::start_standard_user_checked(
        &operation.launch_path,
        &[],
        &ordinary,
        |process| {
            let mut path = [0u16; 1024];
            let mut len = path.len() as u32;
            // SAFETY: process is the still-suspended owned handle; path is
            // writable for the specified length.
            unsafe {
                QueryFullProcessImageNameW(
                    HANDLE(process.as_raw_handle()),
                    PROCESS_NAME_WIN32,
                    PWSTR(path.as_mut_ptr()),
                    &mut len,
                )
            }
            .map_err(|error| GuestMsiExecutionError::Process(error.to_string()))?;
            let observed = path
                .get(..len as usize)
                .and_then(|chars| String::from_utf16(chars).ok())
                .ok_or_else(|| failure("suspended image path", ERROR_INVALID_DATA))?;
            if !observed
                .strip_prefix(r"\\?\")
                .unwrap_or(&observed)
                .eq_ignore_ascii_case(&operation.launch_path)
            {
                return Err(failure("suspended image path differs", ERROR_INVALID_DATA));
            }
            held.parents
                .revalidate()
                .map_err(GuestMsiExecutionError::Process)?;
            held.image
                .revalidate()
                .map_err(|error| GuestMsiExecutionError::Process(error.to_string()))?;
            if Instant::now() >= deadline {
                return Err(failure(
                    "launch deadline exceeded before resume",
                    ERROR_INVALID_DATA,
                ));
            }
            Ok(())
        },
    )?;
    let result = (|| {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(failure("window deadline exceeded", ERROR_INVALID_DATA));
        }
        let window = application.wait_for_window(remaining)?;
        if Instant::now() >= deadline {
            return Err(failure(
                "window observed after deadline",
                ERROR_INVALID_DATA,
            ));
        }
        if application.collect_token()? != application_token {
            return Err(failure(
                "application token changed after launch",
                ERROR_INVALID_DATA,
            ));
        }
        application.request_visible_window_close(window)?;
        let exit_code = application.wait_for_exit(Duration::from_secs(
            operation.graceful_close_timeout_seconds.into(),
        ))?;
        if exit_code != operation.expected_exit_code {
            return Err(GuestMsiExecutionError::Process(format!(
                "reviewed application exited with {exit_code}"
            )));
        }
        Ok(exit_code)
    })();
    let cleanup = if result.is_ok() {
        application.verify_empty_after_success()
    } else {
        application.cleanup()
    };
    let exit_code = complete_process_operation(result, cleanup)?;
    Ok(ReviewedMsiNativeOutcome {
        discovery,
        application_token,
        process_id: application.process_id(),
        exit_code,
    })
}

fn component_candidates(product_code: &str) -> (Vec<aiw_provider_wsb::MsiLaunchCandidate>, bool) {
    use aiw_provider_wsb::{MAX_MSI_LAUNCH_CANDIDATES, MsiLaunchCandidate};
    use std::path::Path;

    fn text(record: &MsiHandle, field: u32) -> Option<String> {
        let mut buffer = [0u16; 260];
        let mut length = buffer.len() as u32;
        // SAFETY: a live fetched record, fixed column, and a writable bounded buffer.
        let result = unsafe {
            MsiRecordGetStringW(record.0, field, PWSTR(buffer.as_mut_ptr()), &mut length)
        };
        let text = buffer.get(..length as usize)?;
        (result == ERROR_SUCCESS)
            .then(|| String::from_utf16(text).ok())
            .flatten()
    }
    let mut database = 0;
    // SAFETY: fixed, read-only file and live output.
    let code = unsafe {
        MsiOpenDatabaseW(
            w!(r"C:\AIW\Tools\application.msi"),
            PCWSTR::null(),
            &mut database,
        )
    };
    let Ok(database) = handle_result(code, database, "component database open") else {
        return (Vec::new(), false);
    };
    let mut view = 0;
    // SAFETY: a live database and a fixed read-only join over component key files.
    let code = unsafe {
        MsiDatabaseOpenViewW(
            database.0,
            w!(
                "SELECT `Component`.`ComponentId`, `File`.`FileName` FROM `Component`, `File` WHERE `Component`.`Component` = `File`.`Component_` AND `Component`.`KeyPath` = `File`.`File`"
            ),
            &mut view,
        )
    };
    let Ok(view) = handle_result(code, view, "component view open") else {
        return (Vec::new(), false);
    };
    // SAFETY: valid view with no parameter record.
    if unsafe { MsiViewExecute(view.0, 0) } != ERROR_SUCCESS {
        return (Vec::new(), false);
    }
    let product: Vec<u16> = product_code.encode_utf16().chain(Some(0)).collect();
    let mut candidates: Vec<MsiLaunchCandidate> = Vec::new();
    let mut hits = 0;
    let mut complete = true;
    for _ in 0..4096 {
        let mut record = 0;
        // SAFETY: live executed view and writable record handle.
        let code = unsafe { MsiViewFetch(view.0, &mut record) };
        if code == ERROR_NO_MORE_ITEMS {
            return (candidates, complete);
        }
        let Ok(record) = handle_result(code, record, "component fetch") else {
            break;
        };
        let (Some(component), Some(file_name)) = (text(&record, 1), text(&record, 2)) else {
            complete = false;
            continue;
        };
        if component.is_empty() || !file_name.to_ascii_lowercase().ends_with(".exe") {
            continue;
        }
        hits += 1;
        if hits > MAX_MSI_LAUNCH_CANDIDATES {
            break;
        }
        let component = component.to_ascii_uppercase();
        if validate_msi_product_code(&component).is_err() {
            complete = false;
            continue;
        }
        let identifier: Vec<u16> = component.encode_utf16().chain(Some(0)).collect();
        let mut buffer = [0u16; 260];
        let mut length = buffer.len() as u32;
        // SAFETY: terminated canonical identities, explicit machine context with
        // null SID, and a fixed writable path buffer.
        let state = unsafe {
            MsiGetComponentPathExW(
                PCWSTR(product.as_ptr()),
                PCWSTR(identifier.as_ptr()),
                PCWSTR::null(),
                MSIINSTALLCONTEXT_MACHINE,
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
        };
        if state != 3 {
            continue;
        } // INSTALLSTATE_LOCAL
        let Some(text) = buffer
            .get(..length as usize)
            .and_then(|slice| String::from_utf16(slice).ok())
        else {
            complete = false;
            continue;
        };
        let path = Path::new(&text);
        let Ok(relative) = path.strip_prefix(r"C:\Program Files") else {
            continue;
        };
        let Some(relative) = relative.to_str() else {
            continue;
        };
        if relative.is_empty()
            || relative.len() > 240
            || !relative.to_ascii_lowercase().ends_with(".exe")
        {
            continue;
        }
        let Ok(held) = HeldInstalledMsiCandidate::open(path) else {
            complete = false;
            continue;
        };
        let observation = held.image.observation();
        if !candidates
            .iter()
            .any(|item| item.relative_path.eq_ignore_ascii_case(relative))
        {
            candidates.push(MsiLaunchCandidate {
                relative_path: relative.into(),
                component_code: component,
                sha256: observation.sha256.clone(),
                size_bytes: observation.size_bytes,
            });
        }
    }
    (candidates, false)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_candidate_rejects_outside_and_parent_traversal_paths() {
        use std::path::Path;
        for path in [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Program Files\..\Windows\System32\notepad.exe",
            r"C:\Program Files",
            r"relative.exe",
        ] {
            assert!(HeldInstalledMsiCandidate::open(Path::new(path)).is_err());
        }
    }

    #[test]
    fn product_identity_requires_one_complete_guid() {
        let text = "{a1234567-89ab-cdef-0123-456789abcdef}";
        let value: Vec<_> = text.encode_utf16().chain(Some(0)).collect();
        assert_eq!(
            canonical_product_code(&value, 38).unwrap(),
            text.to_ascii_uppercase()
        );
        assert!(canonical_product_code(&value, 37).is_err());
        assert!(canonical_product_code(&value[..38], 38).is_err());
        let mut invalid = value.clone();
        invalid[4] = 0;
        assert!(canonical_product_code(&invalid, 38).is_err());
        invalid[4] = 0xd800;
        assert!(canonical_product_code(&invalid, 38).is_err());
    }

    #[test]
    fn registration_errors_are_never_installed_or_not_registered() {
        assert_eq!(
            decode_machine_state(1605, &[], 0),
            MsiMachineProductState::NotRegistered
        );
        assert_eq!(
            decode_machine_state(0, &[49, 0], 1),
            MsiMachineProductState::Advertised
        );
        assert_eq!(
            decode_machine_state(0, &[53, 0], 1),
            MsiMachineProductState::Installed
        );
        for (code, value, length) in [
            (5, vec![53, 0], 1),
            (234, vec![53, 0], 9),
            (0, vec![53, 53], 1),
            (0, vec![50, 0], 1),
            (0, vec![], 0),
        ] {
            assert!(matches!(
                decode_machine_state(code, &value, length),
                MsiMachineProductState::Unavailable { .. }
            ));
        }
    }
}
