//! Fixed, disposable AppContainer control launcher. The historical research
//! entry point remains strict; the paired collector retains inconclusive native
//! observations. Neither accepts a caller-supplied executable, argument or path.

pub(crate) mod research_sevenzip;

use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use aiw_token::{
    IntegrityLevel, TokenEvidence, TokenType, collect_current_process_token, collect_process_token,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use windows::Win32::Foundation::{
    GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree,
    SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_CAPABILITIES, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

const CONTROL_ROOT: &str = r"C:\AIW\Control";
const FIXTURE: &str = r"C:\AIW\Control\aiw-control-fixture.exe";
const CANARY: &str = r"C:\AIW\Control\SharedCanary\canary.txt";
const CANARY_DIR: &str = r"C:\AIW\Control\SharedCanary";
const CHILD_DIR: &str = r"C:\AIW\Control\AppContainerChild";
const CHILD_TOKEN: &str = r"C:\AIW\Control\AppContainerChild\child-token.json";
const PROFILE_NAME: &str = "AIW.Control.Research.v0alpha1";
const PAIRED_PROFILE_NAME: &str = "AIW.Control.Paired.v0alpha1";
const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_JSON: u64 = 48 * 1024;

#[derive(Debug, Error)]
pub enum ControlAppContainerError {
    #[error("{0}")]
    Fixed(String),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlAppContainerObservation {
    pub schema_version: String,
    pub production_evidence: bool,
    pub profile: ProfileObservation,
    pub launcher_token: TokenEvidence,
    pub resource: ResourceObservation,
    pub baseline: ModeObservations,
    #[serde(rename = "appContainer")]
    pub appcontainer: ModeObservations,
    pub cleanup: CleanupObservation,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileObservation {
    pub name: String,
    pub sid: String,
    pub deleted: bool,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceObservation {
    pub canary_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub unchanged_after: bool,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeObservations {
    pub read_canary: FixedFixtureObservation,
    pub read_registry: FixedFixtureObservation,
    pub child: FixedFixtureObservation,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupObservation {
    pub baseline_job_empty: bool,
    #[serde(rename = "appContainerJobEmpty")]
    pub appcontainer_job_empty: bool,
    pub profile_deleted: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixedFixtureObservation {
    pub process_id: u32,
    pub exit_code: i32,
    pub fixture_token: TokenEvidence,
    #[serde(rename = "observation")]
    pub report: serde_json::Value,
    pub job_empty: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureWire {
    own_process_token: TokenEvidence,
}

/// Runs only the reviewed control fixture modes from the fixed guest paths.
pub fn execute_fixed_control_appcontainer()
-> Result<ControlAppContainerObservation, ControlAppContainerError> {
    if !std::env::var("USERNAME")
        .unwrap_or_default()
        .eq_ignore_ascii_case("AiwControlUser")
    {
        return Err(fixed("fixed disposable control user required"));
    }
    require_regular_file(Path::new(FIXTURE))?;
    require_empty_directory(Path::new(CHILD_DIR))?;
    let canary = CanaryBinding::open(Path::new(CANARY))?;
    let launcher_token = collect_current_process_token()
        .map_err(|error| fixed(format!("collect launcher token failed: {error}")))?;
    if launcher_token.is_app_container
        || launcher_token.is_elevated
        || launcher_token.integrity.level != IntegrityLevel::Medium
    {
        return Err(fixed(
            "launcher must be the standard non-AppContainer medium-integrity user",
        ));
    }
    let baseline_read_canary = launch_fixture(
        "read-canary",
        None,
        Path::new(CANARY_DIR),
        None,
        &launcher_token.user_sid,
    )?;
    remove_fixed_result(Path::new(CANARY_DIR), "read-canary")?;
    let baseline_read_registry = launch_fixture(
        "read-registry",
        None,
        Path::new(CANARY_DIR),
        None,
        &launcher_token.user_sid,
    )?;
    remove_fixed_result(Path::new(CANARY_DIR), "read-registry")?;
    let baseline_child = launch_fixture(
        "child",
        None,
        Path::new(CHILD_DIR),
        None,
        &launcher_token.user_sid,
    )?;
    remove_fixed_result(Path::new(CHILD_DIR), "child")?;
    fs::remove_file(CHILD_TOKEN).map_err(|error| {
        fixed(format!(
            "remove verified baseline child token failed: {error}"
        ))
    })?;
    require_empty_directory(Path::new(CHILD_DIR))?;

    let mut profile = AppContainerProfile::create_fresh()?;
    let profile_sid = profile.string_sid()?;
    let candidate = (|| {
        grant_package_access(
            Path::new(CONTROL_ROOT),
            profile.sid,
            (GENERIC_READ | GENERIC_EXECUTE).0,
        )?;
        grant_package_access(
            Path::new(FIXTURE),
            profile.sid,
            (GENERIC_READ | GENERIC_EXECUTE).0,
        )?;
        grant_package_access(
            Path::new(CANARY_DIR),
            profile.sid,
            (GENERIC_READ | GENERIC_EXECUTE).0,
        )?;
        grant_package_access(
            Path::new(CHILD_DIR),
            profile.sid,
            (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE).0,
        )?;
        let read = launch_fixture(
            "read-canary",
            Some(profile.sid),
            Path::new(CANARY_DIR),
            Some(profile.sid),
            &launcher_token.user_sid,
        )?;
        remove_fixed_result(Path::new(CANARY_DIR), "read-canary")?;
        let registry = launch_fixture(
            "read-registry",
            Some(profile.sid),
            Path::new(CANARY_DIR),
            Some(profile.sid),
            &launcher_token.user_sid,
        )?;
        remove_fixed_result(Path::new(CANARY_DIR), "read-registry")?;
        let child = launch_fixture(
            "child",
            Some(profile.sid),
            Path::new(CHILD_DIR),
            Some(profile.sid),
            &launcher_token.user_sid,
        )?;
        Ok::<_, ControlAppContainerError>((read, registry, child))
    })();
    let deleted = profile.delete();
    let (appcontainer_read_canary, appcontainer_read_registry, appcontainer_child) =
        match (candidate, deleted) {
            (Ok(result), Ok(())) => result,
            (Err(error), cleanup) => {
                return Err(fixed(format!("{error}; profile cleanup={cleanup:?}")));
            }
            (_, Err(error)) => return Err(error),
        };
    canary.verify_unchanged()?;
    Ok(ControlAppContainerObservation {
        schema_version: "aiw.dev/research/control-appcontainer/v0alpha2".to_owned(),
        production_evidence: false,
        profile: ProfileObservation {
            name: PROFILE_NAME.to_owned(),
            sid: profile_sid,
            deleted: true,
        },
        launcher_token,
        resource: ResourceObservation {
            canary_path: CANARY.to_owned(),
            sha256: canary.sha256,
            size_bytes: canary.size_bytes,
            unchanged_after: true,
        },
        baseline: ModeObservations {
            read_canary: baseline_read_canary,
            read_registry: baseline_read_registry,
            child: baseline_child,
        },
        appcontainer: ModeObservations {
            read_canary: appcontainer_read_canary,
            read_registry: appcontainer_read_registry,
            child: appcontainer_child,
        },
        cleanup: CleanupObservation {
            baseline_job_empty: true,
            appcontainer_job_empty: true,
            profile_deleted: true,
        },
    })
}
/// Guard before the agent's fixture role parses any mode or mutates a file.
pub fn validate_fixed_paired_fixture_role(mode: &str) -> Result<(), ControlAppContainerError> {
    require_paired_role_path(Path::new(FIXTURE))?;
    let directory = match mode {
        "read-canary" | "read-registry" => CANARY_DIR,
        "child" | "child-token" => CHILD_DIR,
        _ => return Err(fixed("unreviewed paired fixture role")),
    };
    if std::env::current_dir().map_err(|e| fixed(e.to_string()))? != Path::new(directory) {
        return Err(fixed("fixed paired fixture directory required"));
    }
    Ok(())
}
fn require_paired_role_path(path: &Path) -> Result<(), ControlAppContainerError> {
    if std::env::current_exe().map_err(|e| fixed(e.to_string()))? != path {
        return Err(fixed("fixed paired guest helper path required"));
    }
    let token = collect_current_process_token().map_err(|e| fixed(e.to_string()))?;
    if token.is_elevated
        || token.user_sid != fixed_account_sid(aiw_provider_wsb::STANDARD_USER_ACCOUNT_NAME)?
    {
        return Err(fixed(
            "fixed paired standard-user primary identity required",
        ));
    }
    Ok(())
}
// Account lookup is native; environment variables are never identity authority.
pub(crate) fn fixed_account_sid(name: &str) -> Result<String, ControlAppContainerError> {
    use windows::Win32::Security::{LookupAccountNameW, SID_NAME_USE};
    let name = wide(OsStr::new(name))?;
    let mut sid = [0u64; 16];
    let mut sid_size = std::mem::size_of_val(&sid) as u32;
    let mut domain = [0u16; 256];
    let mut domain_size = domain.len() as u32;
    let mut usage = SID_NAME_USE::default();
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_size,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_size,
            &mut usage,
        )
    }
    .map_err(|e| fixed(e.to_string()))?;
    sid_string(PSID(sid.as_mut_ptr().cast()))
}

/// The fixed standard-user helper writes this bounded, typed observation. The
/// elevated guest agent independently binds its held launcher process token and
/// fixed resources; this helper alone is not an assessment or completion receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedLauncherObservation {
    pub launcher_token: TokenEvidence,
    pub package_sid: String,
    pub baseline: aiw_provider_wsb::PairedVariant,
    pub candidate: aiw_provider_wsb::PairedVariant,
    pub profile_deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedLauncherAttempt {
    pub launcher_token: TokenEvidence,
    pub observation: Option<PairedLauncherObservation>,
    pub progress: Vec<aiw_provider_wsb::paired_controls::PairedCaseProgress>,
}
pub fn execute_fixed_paired_control_launcher()
-> Result<PairedLauncherAttempt, ControlAppContainerError> {
    require_paired_role_path(Path::new(r"C:\AIW\Control\aiw-control-appcontainer.exe"))?;
    require_regular_file(Path::new(FIXTURE))?;
    require_empty_directory(Path::new(CHILD_DIR))?;
    let launcher_token = collect_current_process_token().map_err(|e| fixed(e.to_string()))?;
    verify_token(
        &launcher_token,
        std::process::id(),
        None,
        &launcher_token.user_sid,
    )?;
    let mut progress = Vec::new();
    let observation = (|| {
        use aiw_provider_wsb::paired_controls::PairedVariantKind;
        let baseline = collect_paired_variant(
            None,
            &launcher_token.user_sid,
            PairedVariantKind::Baseline,
            &mut progress,
        )?;
        let mut profile = AppContainerProfile::create_paired()?;
        let package_sid = profile.string_sid()?;
        for path in [CONTROL_ROOT, FIXTURE, CANARY_DIR] {
            grant_package_access(
                Path::new(path),
                profile.sid,
                (GENERIC_READ | GENERIC_EXECUTE).0,
            )?;
        }
        grant_package_access(
            Path::new(CHILD_DIR),
            profile.sid,
            (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE).0,
        )?;
        let candidate = collect_paired_variant(
            Some(profile.sid),
            &launcher_token.user_sid,
            PairedVariantKind::Candidate,
            &mut progress,
        )?;
        let profile_deleted = profile.delete().is_ok();
        Ok::<_, ControlAppContainerError>(PairedLauncherObservation {
            launcher_token: launcher_token.clone(),
            package_sid,
            baseline,
            candidate,
            profile_deleted,
        })
    })();
    aiw_provider_wsb::paired_controls::validate_paired_progress(&progress).map_err(fixed)?;
    // A failed case/grant/profile/cleanup never erases the already collected
    // prefix. The outer agent binds this attempt to its held launcher token.
    Ok(PairedLauncherAttempt {
        launcher_token,
        observation: observation.ok(),
        progress,
    })
}
fn collect_paired_variant(
    profile: Option<PSID>,
    user_sid: &str,
    variant: aiw_provider_wsb::paired_controls::PairedVariantKind,
    progress: &mut Vec<aiw_provider_wsb::paired_controls::PairedCaseProgress>,
) -> Result<aiw_provider_wsb::PairedVariant, ControlAppContainerError> {
    use aiw_provider_wsb::paired_controls::{FixedControlCase, normalize_control_variant};
    let mut cases = Vec::new();
    for (mode, case, directory) in [
        ("read-canary", FixedControlCase::File, CANARY_DIR),
        ("read-registry", FixedControlCase::Registry, CANARY_DIR),
        ("child", FixedControlCase::Child, CHILD_DIR),
    ] {
        let collected = collect_fixture(mode, profile, Path::new(directory), profile, user_sid)?;
        if retain_collected_progress(progress, variant, case, &collected)? {
            return Err(fixed(
                "malformed fixed case report; measured prefix retained",
            ));
        }
        cases.push(collected);
        remove_fixed_result(Path::new(directory), mode)?;
    }
    match fs::remove_file(CHILD_TOKEN) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(fixed(format!("remove fixed child token failed: {e}"))),
    }
    require_empty_directory(Path::new(CHILD_DIR))?;
    let mut cases = cases.into_iter();
    normalize_control_variant(
        cases.next().expect("three fixed cases"),
        cases.next().expect("three fixed cases"),
        cases.next().expect("three fixed cases"),
    )
    .map_err(fixed)
}

fn retain_collected_progress(
    progress: &mut Vec<aiw_provider_wsb::paired_controls::PairedCaseProgress>,
    variant: aiw_provider_wsb::paired_controls::PairedVariantKind,
    case: aiw_provider_wsb::paired_controls::FixedControlCase,
    collected: &aiw_provider_wsb::paired_controls::CollectedControlCase,
) -> Result<bool, ControlAppContainerError> {
    use aiw_provider_wsb::paired_controls::{PairedCaseProgress, normalize_control_case};
    let normalized = normalize_control_case(collected.clone(), case);
    let mut malformed = normalized.is_err();
    let unmeasured = || {
        let mut value = collected.clone();
        value.report = None;
        normalize_control_case(value, case).map_err(fixed)
    };
    let (process, observation) = match normalized {
        Ok(value) => value,
        Err(_) => unmeasured()?,
    };
    let mut next = progress.clone();
    next.push(PairedCaseProgress {
        variant,
        case,
        process,
        observation,
    });
    if aiw_provider_wsb::paired_controls::validate_paired_progress(&next).is_err() {
        malformed = true;
        let (process, observation) = unmeasured()?;
        next.pop();
        next.push(PairedCaseProgress {
            variant,
            case,
            process,
            observation,
        });
    }
    aiw_provider_wsb::paired_controls::validate_paired_progress(&next).map_err(fixed)?;
    *progress = next;
    Ok(malformed)
}

fn launch_fixture(
    mode: &str,
    appcontainer: Option<PSID>,
    directory: &Path,
    expected_sid: Option<PSID>,
    expected_user_sid: &str,
) -> Result<FixedFixtureObservation, ControlAppContainerError> {
    let collected = collect_fixture(
        mode,
        appcontainer,
        directory,
        expected_sid,
        expected_user_sid,
    )?;
    let token = collected
        .process
        .held_token
        .ok_or_else(|| fixed("held fixture token absent"))?;
    let report = collected
        .report
        .ok_or_else(|| fixed("fixed fixture JSON absent"))?;
    let code = collected
        .process
        .exit_code
        .ok_or_else(|| fixed("fixture exit code absent"))?;
    if collected.process.timed_out || collected.process.job_empty != Some(true) {
        return Err(fixed("fixed fixture deadline or cleanup failed"));
    }
    let wire: FixtureWire = serde_json::from_value(report.clone())
        .map_err(|error| fixed(format!("parse fixture token failed: {error}")))?;
    if wire.own_process_token != token {
        return Err(fixed("fixture JSON token differed from held process token"));
    }
    if code != 0 {
        return Err(fixed(format!("fixed fixture {mode} exited with {code}")));
    }
    verify_fixture_report(&report, mode, &token, appcontainer.is_some())?;
    Ok(FixedFixtureObservation {
        process_id: collected.process.process_id,
        exit_code: code,
        fixture_token: token,
        report,
        job_empty: true,
    })
}

// Process authority is identical for research and production paired controls.
// Only the legacy wrapper above imposes an expected control outcome.
fn collect_fixture(
    mode: &str,
    appcontainer: Option<PSID>,
    directory: &Path,
    expected_sid: Option<PSID>,
    expected_user_sid: &str,
) -> Result<aiw_provider_wsb::paired_controls::CollectedControlCase, ControlAppContainerError> {
    if !matches!(mode, "read-canary" | "read-registry" | "child") {
        return Err(fixed("unreviewed fixture mode"));
    }
    let report_path = directory.join(format!("{mode}-result.json"));
    if report_path.exists() {
        return Err(fixed("fixed fixture result path already exists"));
    }
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&report_path)
        .map_err(|error| fixed(format!("create fixed fixture result failed: {error}")))?;
    let output_handle = HANDLE(output.as_raw_handle() as isize as *mut _);
    unsafe { SetHandleInformation(output_handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .map_err(|error| {
            fixed(format!(
                "make fixed fixture result inheritable failed: {error}"
            ))
        })?;
    let command = format!("\"{FIXTURE}\" --mode {mode}");
    let mut command_wide = wide(OsStr::new(&command))?;
    let fixture_wide = wide(OsStr::new(FIXTURE))?;
    let directory_wide = wide(directory.as_os_str())?;
    let job = Job::create()?;
    let inherited_handles = [output_handle];
    let mut capabilities = SECURITY_CAPABILITIES::default();
    if let Some(sid) = appcontainer {
        capabilities.AppContainerSid = sid;
    }
    // Attribute values must outlive CreateProcessW and deletion of the list.
    let mut attributes = Attributes::new(if appcontainer.is_some() { 2 } else { 1 })?;
    attributes.handles(&inherited_handles)?;
    if appcontainer.is_some() {
        attributes.security_capabilities(&mut capabilities)?;
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = windows::Win32::System::Threading::STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = HANDLE::default();
    startup.StartupInfo.hStdOutput = output_handle;
    startup.StartupInfo.hStdError = output_handle;
    startup.lpAttributeList = attributes.list;
    let mut info = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(fixture_wide.as_ptr()),
            Some(PWSTR(command_wide.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT
                | CREATE_NO_WINDOW,
            None,
            PCWSTR(directory_wide.as_ptr()),
            (&startup as *const STARTUPINFOEXW).cast(),
            &mut info,
        )
    }
    .map_err(|error| fixed(format!("create fixed fixture process failed: {error}")))?;
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess.0) };
    let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread.0) };
    if let Err(error) = unsafe {
        AssignProcessToJobObject(
            job.handle(),
            HANDLE(process.as_raw_handle() as isize as *mut _),
        )
    } {
        // The suspended process is not owned by the job when assignment fails.
        let cleanup = unsafe { TerminateProcess(info.hProcess, 1) };
        let waited = wait(info.hProcess, Duration::from_secs(2));
        return Err(fixed(format!(
            "assign fixture job failed: {error}; cleanup={cleanup:?}; wait={waited:?}"
        )));
    }
    let token = collect_process_token(process.as_handle())
        .map_err(|error| fixed(format!("collect suspended fixture token failed: {error}")))?;
    verify_token(&token, info.dwProcessId, expected_sid, expected_user_sid)?;
    if unsafe { ResumeThread(HANDLE(thread.as_raw_handle() as isize as *mut _)) } == u32::MAX {
        let cleanup = job.terminate();
        return Err(fixed(format!("resume fixture failed; cleanup={cleanup:?}")));
    }
    let completed = wait_completion(HANDLE(process.as_raw_handle() as isize as *mut _), TIMEOUT)?;
    let job_empty = job.terminate_and_verify_empty().ok().map(|()| true);
    let mut code = 0u32;
    let exit_code = if completed {
        unsafe {
            GetExitCodeProcess(
                HANDLE(process.as_raw_handle() as isize as *mut _),
                &mut code,
            )
        }
        .ok()
        .map(|()| code as i32)
    } else {
        None
    };
    // A timeout cannot be made successful by stale or partially written JSON.
    // Invalid/missing output remains unmeasured, never an inferred denial.
    let report = if completed && job_empty == Some(true) {
        read_bounded(&report_path, MAX_JSON)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    } else {
        None
    };
    Ok(aiw_provider_wsb::paired_controls::CollectedControlCase {
        process: aiw_provider_wsb::PairedInvocation {
            process_id: info.dwProcessId,
            exit_code,
            timed_out: !completed,
            held_token: Some(token),
            self_token: None, // Filled only by the strict shared raw normalizer.
            job_empty,
        },
        report,
    })
}

fn verify_fixture_report(
    report: &serde_json::Value,
    mode: &str,
    token: &TokenEvidence,
    candidate: bool,
) -> Result<(), ControlAppContainerError> {
    let expected_mode = match mode {
        "read-canary" => "readCanary",
        "read-registry" => "readRegistry",
        "child" => "child",
        _ => return Err(fixed("unreviewed fixture mode")),
    };
    if report.get("mode").and_then(serde_json::Value::as_str) != Some(expected_mode) {
        return Err(fixed(
            "fixture report mode differed from launched fixed mode",
        ));
    }
    let result = report
        .get("result")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| fixed("fixture report omitted result"))?;
    match mode {
        "read-registry" => {
            let expected = if candidate { "accessDenied" } else { "success" };
            if result.get("status").and_then(serde_json::Value::as_str) != Some("readRegistry")
                || result
                    .get("probe")
                    .and_then(|p| p.get("outcome"))
                    .and_then(|o| o.get("kind"))
                    .and_then(serde_json::Value::as_str)
                    != Some(expected)
            {
                return Err(fixed(format!(
                    "registry control outcome differed from expectation: {}",
                    serde_json::Value::Object(result.clone())
                )));
            }
        }
        "read-canary" => {
            if result.get("status").and_then(serde_json::Value::as_str) != Some("readCanary") {
                return Err(fixed("read-canary fixture reported another result"));
            }
            let expected = if candidate { "accessDenied" } else { "success" };
            let outcome = result
                .get("outcome")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| fixed("fixture read-canary omitted outcome"))?;
            if outcome.get("kind").and_then(serde_json::Value::as_str) != Some(expected) {
                return Err(fixed(
                    "fixture read-canary outcome differed from control expectation",
                ));
            }
        }
        "child" => {
            if result.get("status").and_then(serde_json::Value::as_str) != Some("child")
                || result
                    .get("childStdoutBytes")
                    .and_then(serde_json::Value::as_u64)
                    != Some(0)
            {
                return Err(fixed(
                    "child fixture report was not the fixed silent child result",
                ));
            }
            let child: TokenEvidence = serde_json::from_value(
                result
                    .get("childToken")
                    .cloned()
                    .ok_or_else(|| fixed("child fixture omitted child token"))?,
            )
            .map_err(|error| fixed(format!("parse child fixture token failed: {error}")))?;
            if result
                .get("childProcessId")
                .and_then(serde_json::Value::as_u64)
                != Some(child.process_id as u64)
                || child.user_sid != token.user_sid
                || child.is_elevated
                || child.token_type != TokenType::Primary
                || !child.capabilities.is_empty()
                || child.is_app_container != token.is_app_container
                || child.app_container_sid != token.app_container_sid
                || child.integrity != token.integrity
            {
                return Err(fixed(
                    "child fixture token did not retain the held root token identity",
                ));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
fn verify_token(
    token: &TokenEvidence,
    pid: u32,
    profile: Option<PSID>,
    expected_user_sid: &str,
) -> Result<(), ControlAppContainerError> {
    if token.process_id != pid
        || token.is_elevated
        || token.token_type != TokenType::Primary
        || !token.capabilities.is_empty()
        || token.user_sid != expected_user_sid
    {
        return Err(fixed(
            "held fixture token did not have expected PID, user, primary/no-capability, or non-elevated state",
        ));
    }
    match profile {
        Some(sid) => {
            if !token.is_app_container
                || token.integrity.level != IntegrityLevel::Low
                || token.app_container_sid.as_deref() != Some(&sid_string(sid)?)
            {
                return Err(fixed(
                    "held candidate token did not bind to fresh low-integrity AppContainer profile",
                ));
            }
        }
        None => {
            if token.is_app_container || token.integrity.level != IntegrityLevel::Medium {
                return Err(fixed(
                    "baseline fixture token was not the ordinary medium-integrity user",
                ));
            }
        }
    }
    Ok(())
}

struct AppContainerProfile {
    sid: PSID,
    deleted: bool,
    name: &'static str,
}
impl AppContainerProfile {
    fn create_fresh() -> Result<Self, ControlAppContainerError> {
        Self::create(PROFILE_NAME)
    }
    fn create_paired() -> Result<Self, ControlAppContainerError> {
        Self::create(PAIRED_PROFILE_NAME)
    }
    fn create(profile_name: &'static str) -> Result<Self, ControlAppContainerError> {
        let name = wide(OsStr::new(profile_name))?;
        let sid = unsafe {
            CreateAppContainerProfile(
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                None,
            )
        }
        .map_err(|error| fixed(format!("create fresh AppContainer profile failed: {error}")))?;
        Ok(Self {
            sid,
            deleted: false,
            name: profile_name,
        })
    }
    fn string_sid(&self) -> Result<String, ControlAppContainerError> {
        sid_string(self.sid)
    }
    fn delete(&mut self) -> Result<(), ControlAppContainerError> {
        let name = wide(OsStr::new(self.name))?;
        let result = unsafe { DeleteAppContainerProfile(PCWSTR(name.as_ptr())) };
        result
            .map_err(|error| fixed(format!("delete fresh AppContainer profile failed: {error}")))?;
        self.deleted = true;
        Ok(())
    }
}
impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        if !self.deleted {
            let _ = self.delete();
        }
        unsafe { windows::Win32::Security::FreeSid(self.sid) };
    }
}

fn grant_package_access(
    path: &Path,
    sid: PSID,
    rights: u32,
) -> Result<(), ControlAppContainerError> {
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: GRANT_ACCESS,
        // Only the fixed child-output directory grants its new token file access.
        grfInheritance: if path == Path::new(CHILD_DIR) {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: core::ptr::null_mut(),
            MultipleTrusteeOperation: Default::default(),
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: PWSTR(sid.0.cast()),
        },
    };
    let path = wide(path.as_os_str())?;
    let mut existing: *mut ACL = core::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut descriptor,
        )
    };
    if status.0 != 0 {
        return Err(fixed(format!(
            "read existing package ACL failed: {}",
            status.0
        )));
    }
    let mut acl: *mut ACL = core::ptr::null_mut();
    let status = unsafe { SetEntriesInAclW(Some(&[entry]), Some(existing), &mut acl) };
    unsafe { LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    if status.0 != 0 {
        return Err(fixed(format!("build package ACL failed: {}", status.0)));
    }
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        )
    };
    unsafe { LocalFree(Some(HLOCAL(acl.cast()))) };
    if status.0 != 0 {
        return Err(fixed(format!("apply package ACL failed: {}", status.0)));
    }
    Ok(())
}

struct Job {
    handle: OwnedHandle,
}
impl Job {
    fn create() -> Result<Self, ControlAppContainerError> {
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|error| fixed(format!("create fixture job failed: {error}")))?;
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                HANDLE(handle.as_raw_handle() as isize as *mut _),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        }
        .map_err(|error| fixed(format!("configure fixture job failed: {error}")))?;
        Ok(Self { handle })
    }
    fn handle(&self) -> HANDLE {
        HANDLE(self.handle.as_raw_handle() as isize as *mut _)
    }
    fn terminate(&self) -> Result<(), ControlAppContainerError> {
        unsafe { TerminateJobObject(self.handle(), 1) }
            .map_err(|error| fixed(format!("terminate fixture job failed: {error}")))
    }
    fn active_processes(&self) -> Result<u32, ControlAppContainerError> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        unsafe {
            QueryInformationJobObject(
                Some(self.handle()),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                None,
            )
        }
        .map_err(|error| fixed(format!("query fixture job failed: {error}")))?;
        Ok(accounting.ActiveProcesses)
    }
    fn terminate_and_verify_empty(&self) -> Result<(), ControlAppContainerError> {
        if self.active_processes()? > 0 {
            self.terminate()?;
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or_else(|| fixed("fixture cleanup deadline overflowed"))?;
        while self.active_processes()? != 0 {
            if Instant::now() >= deadline {
                return Err(fixed("fixture job remained active after cleanup"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}
fn wait(handle: HANDLE, timeout: Duration) -> Result<(), ControlAppContainerError> {
    if wait_completion(handle, timeout)? {
        Ok(())
    } else {
        Err(fixed("fixed fixture deadline expired"))
    }
}
fn wait_completion(handle: HANDLE, timeout: Duration) -> Result<bool, ControlAppContainerError> {
    match unsafe { WaitForSingleObject(handle, timeout.as_millis() as u32) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(fixed("wait fixed fixture failed")),
    }
}
struct Attributes {
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    _storage: Vec<usize>,
}
impl Attributes {
    fn new(count: usize) -> Result<Self, ControlAppContainerError> {
        let mut size = 0;
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, count as u32, None, &mut size);
        }
        if size == 0 {
            return Err(fixed("empty process attribute allocation"));
        }
        let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(list), count as u32, None, &mut size) }
            .map_err(|error| fixed(format!("initialize fixture attributes failed: {error}")))?;
        Ok(Self {
            list,
            _storage: storage,
        })
    }
    fn handles(&mut self, handles: &[HANDLE]) -> Result<(), ControlAppContainerError> {
        unsafe {
            UpdateProcThreadAttribute(
                self.list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                std::mem::size_of_val(handles),
                None,
                None,
            )
        }
        .map_err(|error| fixed(format!("set fixed fixture handle list failed: {error}")))
    }
    fn security_capabilities(
        &mut self,
        capabilities: &mut SECURITY_CAPABILITIES,
    ) -> Result<(), ControlAppContainerError> {
        unsafe {
            UpdateProcThreadAttribute(
                self.list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some((capabilities as *mut SECURITY_CAPABILITIES).cast()),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                None,
                None,
            )
        }
        .map_err(|error| fixed(format!("set AppContainer capabilities failed: {error}")))
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.list) };
    }
}
fn wide(value: &OsStr) -> Result<Vec<u16>, ControlAppContainerError> {
    let value: Vec<u16> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(fixed("fixed path contained NUL"));
    }
    Ok(value.into_iter().chain(Some(0)).collect())
}
fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, ControlAppContainerError> {
    let file = fs::File::open(path).map_err(|e| fixed(format!("open fixed result failed: {e}")))?;
    let len = file
        .metadata()
        .map_err(|e| fixed(format!("stat fixed result failed: {e}")))?
        .len();
    if len > maximum {
        return Err(fixed("fixed result exceeded bound"));
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| fixed(format!("read fixed result failed: {e}")))?;
    if bytes.len() as u64 > maximum {
        return Err(fixed("fixed result grew beyond bound"));
    }
    Ok(bytes)
}
struct CanaryBinding {
    _file: fs::File,
    sha256: String,
    size_bytes: u64,
}
impl CanaryBinding {
    fn open(path: &Path) -> Result<Self, ControlAppContainerError> {
        require_regular_file(path)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(path)
            .map_err(|error| fixed(format!("open fixed canary binding failed: {error}")))?;
        let metadata = file
            .metadata()
            .map_err(|error| fixed(format!("stat fixed canary binding failed: {error}")))?;
        if metadata.len() > 1024 {
            return Err(fixed("fixed canary exceeded 1 KiB bound"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| fixed(format!("read fixed canary binding failed: {error}")))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(fixed(
                "fixed canary changed while its read-only binding was opened",
            ));
        }
        use sha2::{Digest, Sha256};
        Ok(Self {
            _file: file,
            sha256: hex::encode(Sha256::digest(&bytes)),
            size_bytes: bytes.len() as u64,
        })
    }
    fn verify_unchanged(&self) -> Result<(), ControlAppContainerError> {
        let (sha256, size_bytes) = hash_file(Path::new(CANARY))?;
        if sha256 != self.sha256 || size_bytes != self.size_bytes {
            return Err(fixed("fixed canary changed during AppContainer control"));
        }
        Ok(())
    }
}
fn remove_fixed_result(directory: &Path, mode: &str) -> Result<(), ControlAppContainerError> {
    let path = directory.join(format!("{mode}-result.json"));
    fs::remove_file(&path).map_err(|error| {
        fixed(format!(
            "remove verified fixed fixture result failed: {error}"
        ))
    })
}
fn hash_file(path: &Path) -> Result<(String, u64), ControlAppContainerError> {
    use sha2::{Digest, Sha256};
    let bytes = read_bounded(path, 1024)?;
    Ok((hex::encode(Sha256::digest(&bytes)), bytes.len() as u64))
}
fn require_regular_file(path: &Path) -> Result<(), ControlAppContainerError> {
    if fs::metadata(path).map(|m| m.is_file()).unwrap_or(false) {
        Ok(())
    } else {
        Err(fixed("required fixed resource was not an ordinary file"))
    }
}
fn require_empty_directory(path: &Path) -> Result<(), ControlAppContainerError> {
    let mut entries =
        fs::read_dir(path).map_err(|e| fixed(format!("open fixed child directory failed: {e}")))?;
    if entries.next().is_some() {
        Err(fixed("fixed child directory was not empty"))
    } else {
        Ok(())
    }
}
fn sid_string(sid: PSID) -> Result<String, ControlAppContainerError> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut text) }
        .map_err(|e| fixed(format!("format AppContainer SID failed: {e}")))?;
    let value = unsafe { text.to_string() }
        .map_err(|e| fixed(format!("decode AppContainer SID failed: {e}")))?;
    unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    Ok(value)
}
fn fixed(message: impl Into<String>) -> ControlAppContainerError {
    ControlAppContainerError::Fixed(message.into())
}

#[cfg(test)]
mod paired_tests {
    use super::*;
    use aiw_provider_wsb::paired_controls::{
        CollectedControlCase, ControlAccess, FixedControlCase, PairedVariantKind,
    };
    #[test]
    fn malformed_late_case_retains_valid_prefix_and_only_held_unmeasured_case() {
        let synthetic: aiw_provider_wsb::PairedControlResult = serde_json::from_str(include_str!(
            "../../../fixtures/paired-controls/synthetic-result.json"
        ))
        .unwrap();
        let mut progress = Vec::new();
        for (case, mode, process, result) in [
            (
                FixedControlCase::File,
                "readCanary",
                synthetic.baseline.file_process.clone(),
                serde_json::json!({"status":"readCanary","outcome":{"kind":"success","sizeBytes":29,"sha256":synthetic.baseline.file.sha256}}),
            ),
            (
                FixedControlCase::Registry,
                "readRegistry",
                synthetic.baseline.registry_process.clone(),
                serde_json::json!({"status":"readRegistry","probe":{"scope":{"hive":"HKLM","view":"registry64","key":synthetic.resources.registry_key,"value":"Canary"},"outcome":{"kind":"success","sizeBytes":29,"sha256":synthetic.baseline.registry.sha256}}}),
            ),
        ] {
            let report = serde_json::json!({"schemaVersion":"aiw.dev/control-fixture-report/v0alpha1","mode":mode,"ownProcessToken":process.held_token,"result":result});
            let collected = CollectedControlCase {
                process,
                report: Some(report),
            };
            assert!(
                !retain_collected_progress(
                    &mut progress,
                    PairedVariantKind::Baseline,
                    case,
                    &collected
                )
                .unwrap()
            );
        }
        let prefix = progress.clone();
        let mut bad_child = synthetic.baseline.child_token.clone().unwrap();
        bad_child.user_sid = "S-1-5-21-9-9-9-1001".into();
        let process = synthetic.baseline.child_process.clone();
        let report = serde_json::json!({"schemaVersion":"aiw.dev/control-fixture-report/v0alpha1","mode":"child","ownProcessToken":process.held_token,"result":{"status":"child","childProcessId":bad_child.process_id,"childToken":bad_child,"childStdoutBytes":0}});
        let collected = CollectedControlCase {
            process,
            report: Some(report),
        };
        assert!(
            retain_collected_progress(
                &mut progress,
                PairedVariantKind::Baseline,
                FixedControlCase::Child,
                &collected
            )
            .unwrap()
        );
        assert_eq!(&progress[..2], prefix.as_slice());
        assert_eq!(progress[2].observation.outcome, ControlAccess::Unmeasured);
        assert!(progress[2].process.held_token.is_some());
        assert!(progress[2].process.self_token.is_none());
        assert!(progress[2].observation.child_token.is_none());
        aiw_provider_wsb::paired_controls::validate_paired_progress(&progress).unwrap();
    }
}
