//! Application-neutral portable/offline CLI execution by a privileged collector.
//! Every untrusted image is created as the fresh ordinary user; observation,
//! pipe readers, held images and journals never run in that user's process.
mod files;
mod process;
mod progress;
use crate::{
    GuestMsiExecutionError, HeldApplicationFile, guest_standard_user::StandardUserSession,
};
use aiw_provider_wsb::assessment_request::ApplicationAssessmentGuestRequest;
use aiw_provider_wsb::{assessment::*, assessment_observation::*};
use aiw_token::{IntegrityLevel, TokenType};
use std::{
    ffi::OsStr,
    os::windows::{
        ffi::OsStrExt,
        io::{FromRawHandle, OwnedHandle},
    },
    path::Path,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW,
            Isolation::{
                CreateAppContainerProfile, DeleteAppContainerProfile,
                DeriveAppContainerSidFromAppContainerName,
            },
            PSID, TOKEN_QUERY,
        },
        System::Threading::{GetCurrentThread, OpenThreadToken},
    },
    core::{HRESULT, PCWSTR, PWSTR},
};
type Result<T> = std::result::Result<T, String>;
const ROOT: &str = r"C:\AIW\Assessment";
const APP: &str = r"C:\AIW\Assessment\App";
const WORK: &str = r"C:\AIW\Assessment\Work";
const COLLECTOR: &str = r"C:\AIW\Output";
const PROFILE: &str = "AIW.Assessment.Portable.v1";
const MAX_OUTCOME: usize = 16 * 1024 * 1024;
const OUTCOME_SCHEMA: &str = "aiw.dev/assessment-native-observation/v0alpha1";
pub(super) fn bound_error(value: &str) -> String {
    value.chars().take(1024).collect()
}
fn fixed_image(actual: &Path, expected: &str) -> bool {
    actual.to_str().is_some_and(|p| {
        p.strip_prefix(r"\\?\")
            .unwrap_or(p)
            .eq_ignore_ascii_case(expected.strip_prefix(r"\\?\").unwrap_or(expected))
    })
}
fn observe_unimpersonated() -> Result<bool> {
    let mut token = HANDLE::default();
    match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) } {
        Ok(()) => {
            let _owned = unsafe { OwnedHandle::from_raw_handle(token.0) };
            Ok(false)
        }
        Err(error) if error.code() == HRESULT::from_win32(1008) => Ok(true),
        Err(error) => Err(format!("collector thread identity query: {error}")),
    }
}
#[link(name = "Advapi32")]
unsafe extern "system" {
    fn RevertToSelf() -> windows::core::BOOL;
}
pub(super) fn check_collector(fact: &mut Option<bool>) -> Result<()> {
    let failure = match observe_unimpersonated() {
        Ok(true) => return Ok(()),
        Ok(false) => {
            *fact = Some(false);
            "collector thread impersonation refused".to_string()
        }
        Err(error) => {
            if *fact != Some(false) {
                *fact = None;
            }
            error
        }
    };
    // Restore the intended collector context for owned cleanup, but never resume
    // execution after a failed observation. Failed restoration is fail-stop.
    if unsafe { RevertToSelf() }.ok().is_err() || observe_unimpersonated() != Ok(true) {
        std::process::abort();
    }
    Err(failure)
}
pub(super) fn guard_no_impersonation() -> Result<()> {
    check_collector(&mut Some(true))
}
fn empty(plan: &CompiledAssessment) -> AssessmentNativeOutcome {
    AssessmentNativeOutcome {
        schema_version: OUTCOME_SCHEMA.into(),
        semantic_sha256: plan.semantic_sha256.clone(),
        mode: plan.mode,
        windows: None,
        windows_error: None,
        setup_token: None,
        standard_context: None,
        steps: vec![],
        assertions: vec![],
        collector_write_denied: None,
        collector_access_denials: vec![],
        collector_unimpersonated: Some(true),
        profile_sid: None,
        account_cleanup: AssessmentAccountCleanup::default(),
        profile_cleanup: None,
        driver_errors: vec![],
        driver_completed: false,
        scope: ASSESSMENT_SCOPE.into(),
    }
}
fn plan_guard(plan: &CompiledAssessment) -> Result<()> {
    plan.validate()
        .map_err(|e| format!("{}: {}", e.field, e.message))?;
    let count = plan
        .steps
        .iter()
        .filter(|s| matches!(s, CompiledAssessmentStep::Launch { .. }))
        .count() as u64;
    let maximum = count
        .checked_mul(plan.settings.stdout_max_bytes + plan.settings.stderr_max_bytes)
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(2 * 1024 * 1024))
        .ok_or("capture budget overflow")?;
    if maximum > MAX_OUTCOME as u64 {
        return Err("declared capture envelope exceeds16MiB capability".into());
    }
    Ok(())
}
/// Fixed receipt-last publication only. The pending bytes are retained on any
/// no-overwrite rename failure; there is no path or command parameter.
pub fn publish_assessment_completion(bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, MOVE_FILE_FLAGS, MoveFileExW,
    };
    if bytes.len() > 1024 * 1024 || bytes.is_empty() {
        return Err("completion receipt byte bound refused".into());
    }
    guard_no_impersonation()?;
    if !fixed_image(
        &std::env::current_exe().map_err(|e| e.to_string())?,
        r"C:\AIW\Tools\aiw-guest-agent.exe",
    ) {
        return Err("fixed Sandbox assessment publisher required".into());
    }
    let token = aiw_token::collect_current_process_token().map_err(|e| e.to_string())?;
    let expected = crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")
        .map_err(|e| e.to_string())?;
    if token.user_sid != expected
        || !token.is_elevated
        || token.token_type != TokenType::Primary
        || token.impersonation_level.is_some()
        || token.is_app_container
        || token.app_container_sid.is_some()
        || !token.capabilities.is_empty()
        || token.integrity.level != IntegrityLevel::High
        || token.integrity.rid != 12288
    {
        return Err("elevated primary Sandbox receipt publisher required".into());
    }
    let _held = files::Directories::hold(Path::new(COLLECTOR))?;
    let pending = Path::new(COLLECTOR).join("completion.pending");
    let destination = Path::new(COLLECTOR).join("completion.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&pending)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    drop(file);
    let pending: Vec<_> = pending.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<_> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // No replacement, deletion, alias clearing, hardlink interval or retry.
    unsafe {
        MoveFileExW(
            PCWSTR(pending.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVE_FILE_FLAGS(0),
        )
    }
    .map_err(|e| e.to_string())
}

/// Mutates fresh guest-local resources plus the one declared collector progress
/// artifact. No untrusted process inherits or runs the observation machinery.
pub fn execute_assessment(
    request: &ApplicationAssessmentGuestRequest,
) -> Result<AssessmentNativeOutcome> {
    request.validate()?;
    let plan = &request.assessment;
    // One monotonic assessment budget, including staging/setup. Synchronous
    // filesystem/profile IO cannot be interrupted here: the outer Sandbox
    // watchdog remains its hard bound. Expiry forbids further app dispatch;
    // owned cleanup still runs after the budget has elapsed.
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(u64::from(
            plan.settings.total_timeout_seconds,
        )))
        .ok_or("assessment deadline overflow")?;
    plan_guard(plan)?;
    guard_no_impersonation()?;
    if !fixed_image(
        &std::env::current_exe().map_err(|e| e.to_string())?,
        r"C:\AIW\Tools\aiw-guest-agent.exe",
    ) {
        return Err("fixed elevated Sandbox assessment agent required".into());
    }
    let token = aiw_token::collect_current_process_token().map_err(|e| e.to_string())?;
    let expected = crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")
        .map_err(|e| e.to_string())?;
    if token.user_sid != expected
        || !token.is_elevated
        || token.token_type != TokenType::Primary
        || token.impersonation_level.is_some()
        || token.is_app_container
        || token.app_container_sid.is_some()
        || !token.capabilities.is_empty()
        || token.integrity.level != IntegrityLevel::High
        || token.integrity.rid != 12288
    {
        return Err("elevated primary Sandbox collector required".into());
    }
    let _agent = files::hold_agent(&request.agent_sha256)?;
    let mut report = empty(plan);
    report.setup_token = Some(token.clone());
    let mut progress = match progress::Progress::create(request, token) {
        Ok(value) => value,
        Err(error) => {
            report.driver_errors.push(bound_error(&error));
            return Ok(report);
        }
    };
    match crate::observe_windows_version() {
        Ok(value) => report.windows = Some(value),
        Err(error) => report.windows_error = Some(bound_error(&error.to_string())),
    }
    let operation = (|| -> Result<()> {
        progress.record(&AssessmentProgressEvent::Context {
            windows: report.windows.clone(),
            windows_error: report.windows_error.clone(),
            standard_context: None,
        })?;
        require_budget(deadline)?;
        let mut staged = files::Staged::prepare(plan)?;
        require_budget(deadline)?;
        let user = match StandardUserSession::establish_assessment() {
            Ok(user) => user,
            Err((error, cleanup)) => {
                report.account_cleanup = cleanup;
                return Err(error.to_string());
            }
        };
        report.standard_context = Some(user.context().clone());
        let mut profile = None;
        let attempt = (|| -> Result<()> {
            check_collector(&mut report.collector_unimpersonated)?;
            progress.record(&AssessmentProgressEvent::Context {
                windows: report.windows.clone(),
                windows_error: report.windows_error.clone(),
                standard_context: report.standard_context.clone(),
            })?;
            require_budget(deadline)?;
            let probes = user.impersonate(|| {
                progress::probe_access(&user.context().user_sid)
                    .map_err(GuestMsiExecutionError::Process)
            });
            check_collector(&mut report.collector_unimpersonated)?;
            report.collector_access_denials = probes.map_err(|e| e.to_string())?;
            report.collector_write_denied =
                progress::derive_denial(&report.collector_access_denials, &user.context().user_sid);
            for observation in &report.collector_access_denials {
                progress.record(&AssessmentProgressEvent::CollectorAccess {
                    observation: observation.clone(),
                })?;
            }
            if report.collector_write_denied != Some(true) {
                return Err("collector-isolation capability unavailable or unmeasured; no application dispatched".into());
            }
            progress.seal_before_apps()?;
            require_budget(deadline)?;
            if plan.mode == AssessmentMode::ClassicAppContainer {
                let created = user.impersonate(|| {
                    Profile::create().map_err(|(error, cleanup)| {
                        report.profile_cleanup = cleanup;
                        GuestMsiExecutionError::Process(error)
                    })
                });
                match created {
                    Ok(created) => {
                        report.profile_sid = Some(created.text.clone());
                        profile = Some(created);
                    }
                    Err(error) => return Err(error.to_string()),
                }
                check_collector(&mut report.collector_unimpersonated)?;
                progress.record(&AssessmentProgressEvent::ProfileCreated {
                    profile_sid: report
                        .profile_sid
                        .clone()
                        .ok_or("created profile SID absent")?,
                })?;
            }
            files::grant_declared_resources(
                plan,
                &user.context().user_sid,
                profile.as_ref().map(|p| p.text.as_str()),
            )?;
            let access = user.impersonate(|| {
                files::verify_declared_access(plan).map_err(GuestMsiExecutionError::Process)
            });
            check_collector(&mut report.collector_unimpersonated)?;
            access.map_err(|e| e.to_string())?;
            require_budget(deadline)?;
            staged.revalidate()?;
            check_collector(&mut report.collector_unimpersonated)?;
            execute_steps(
                plan,
                &user,
                &mut report,
                profile.as_ref(),
                &mut progress,
                deadline,
            )
        })();
        if let Err(error) = attempt {
            report.driver_errors.push(bound_error(&error));
        }
        let jobs_empty = report
            .steps
            .iter()
            .filter_map(|s| s.process.as_ref())
            .all(|p| p.job_empty == Some(true));
        if let Some(mut profile) = profile {
            if jobs_empty {
                let cleanup =
                    user.impersonate(|| profile.cleanup().map_err(GuestMsiExecutionError::Process));
                match cleanup {
                    Ok(()) => report.profile_cleanup = Some(true),
                    Err(error) => {
                        report.profile_cleanup = Some(false);
                        report
                            .driver_errors
                            .push(bound_error(&format!("profile cleanup: {error}")));
                    }
                }
                if let Err(error) = check_collector(&mut report.collector_unimpersonated) {
                    report.driver_errors.push(bound_error(&error));
                }
            } else {
                report.driver_errors.push(
                    "profile cleanup deferred: owned application job absence unconfirmed".into(),
                );
            }
        }
        report.account_cleanup = if jobs_empty {
            user.cleanup_assessment()
        } else {
            user.defer_assessment_cleanup()
        };
        staged.revalidate()?;
        check_collector(&mut report.collector_unimpersonated)?;
        Ok(())
    })();
    if let Err(error) = operation {
        report.driver_errors.push(bound_error(&error));
    }
    for error in &mut report.account_cleanup.errors {
        *error = bound_error(error);
    }
    report.driver_completed = report.driver_errors.is_empty()
        && report.collector_unimpersonated == Some(true)
        && report.account_cleanup.errors.is_empty()
        && report.account_cleanup.environment_destroyed == Some(true)
        && report.account_cleanup.profile_unloaded == Some(true)
        && report.account_cleanup.account_deleted == Some(true)
        && report.steps.len() == plan.steps.len()
        && report.assertions.len() == plan.settings.assertions.len();
    let terminal = AssessmentProgressEvent::Terminal {
        collector_write_denied: report.collector_write_denied,
        collector_unimpersonated: report.collector_unimpersonated,
        profile_sid: report.profile_sid.clone(),
        profile_cleanup: report.profile_cleanup,
        account_cleanup: report.account_cleanup.clone(),
        driver_completed: report.driver_completed,
        errors: report.driver_errors.clone(),
    };
    if let Err(error) = progress
        .record(&terminal)
        .and_then(|_| progress.revalidate())
    {
        report.driver_completed = false;
        report.driver_errors.push(bound_error(&error));
    }
    if serde_json::to_vec(&report)
        .map_err(|e| e.to_string())?
        .len()
        > MAX_OUTCOME
    {
        return Err("complete native report exceeds16MiB; no truncation".into());
    }
    Ok(report)
}
fn execute_steps(
    plan: &CompiledAssessment,
    user: &StandardUserSession,
    report: &mut AssessmentNativeOutcome,
    profile: Option<&Profile>,
    progress: &mut progress::Progress,
    deadline: Instant,
) -> Result<()> {
    let cwd = files::cwd(&plan.settings.working_directory)?;
    let _cwd = files::Directories::hold(&cwd)?;
    for (index, step) in plan.steps.iter().enumerate() {
        if Instant::now() >= deadline {
            return Err("assessment total deadline expired before next operation".into());
        }
        let mut row = AssessmentStepObservation {
            index,
            kind: String::new(),
            process: None,
            image: None,
            file: None,
            file_exists: None,
            assertion_passed: None,
            error: None,
        };
        let operation = (|| -> Result<()> {
            match step {
                CompiledAssessmentStep::StagePortable => {
                    row.kind = "stagePortable".into();
                    for entry in &plan.portable_entries {
                        if entry.kind == aiw_probe::PortableContentEntryKind::File {
                            let path = files::at(APP, &entry.relative_path)?;
                            let _dirs = files::Directories::hold(
                                path.parent().ok_or("app parent missing")?,
                            )?;
                            let held = HeldApplicationFile::open_bounded(&path, entry.size_bytes)
                                .map_err(|e| e.to_string())?;
                            if held.observation().sha256 != entry.sha256.as_deref().unwrap_or("")
                                || held.observation().size_bytes != entry.size_bytes
                            {
                                return Err("staged portable inventory differs".into());
                            }
                            held.revalidate().map_err(|e| e.to_string())?;
                        }
                    }
                }
                CompiledAssessmentStep::Launch {
                    path,
                    sha256,
                    size_bytes,
                    arguments,
                    ..
                } => {
                    row.kind = "launch".into();
                    let path = files::at(APP, path)?;
                    let _dirs =
                        files::Directories::hold(path.parent().ok_or("launch parent missing")?)?;
                    let image = HeldApplicationFile::open_bounded(&path, *size_bytes)
                        .map_err(|e| e.to_string())?;
                    if &image.observation().sha256 != sha256
                        || image.observation().size_bytes != *size_bytes
                    {
                        return Err("launch image differs from approved plan".into());
                    }
                    let architecture = process::observe_image(&image)?;
                    let supported = architecture.architecture_error.is_none();
                    row.image = Some(architecture);
                    if !supported {
                        return Err(
                            "measured execution image architecture unsupported; no process created"
                                .into(),
                        );
                    }
                    let observed = process::launch(process::Launch {
                        image: &image,
                        arguments,
                        cwd: &cwd,
                        context: user.context(),
                        profile: profile.map(|p| (p.sid.0, p.text.as_str())),
                        user,
                        collector_unimpersonated: &mut report.collector_unimpersonated,
                        progress,
                        step_index: index,
                        deadline: deadline.min(
                            Instant::now()
                                + Duration::from_secs(u64::from(
                                    plan.settings.process_timeout_seconds,
                                )),
                        ),
                        stdout_limit: plan.settings.stdout_max_bytes,
                        stderr_limit: plan.settings.stderr_max_bytes,
                    })?;
                    let complete = observed.errors.is_empty()
                        && !observed.timed_out
                        && observed.job_empty == Some(true)
                        && observed.stdout.complete
                        && observed.stderr.complete;
                    row.process = Some(observed);
                    if !complete {
                        return Err(
                            "application launch mechanism/capture/deadline incomplete".into()
                        );
                    }
                }
                CompiledAssessmentStep::ExpectExitCode { launch_step, value } => {
                    row.kind = "expectExitCode".into();
                    let observed = report
                        .steps
                        .iter()
                        .find(|r| r.index == *launch_step)
                        .and_then(|r| r.process.as_ref())
                        .ok_or("referenced launch observation missing")?;
                    row.assertion_passed =
                        Some(observed.exit_code == Some(*value as u32) && !observed.timed_out);
                }
                CompiledAssessmentStep::ObserveFile { path } => {
                    row.kind = "observeFile".into();
                    row.file = files::observe_work(path, plan.settings.file_max_bytes)?;
                    row.file_exists = Some(row.file.is_some());
                }
            }
            Ok(())
        })();
        let failed = operation.is_err();
        if let Err(error) = operation {
            row.error = Some(bound_error(&error));
        }
        let event = AssessmentProgressEvent::Step {
            observation: Box::new(row.clone()),
        };
        report.steps.push(row);
        check_collector(&mut report.collector_unimpersonated)?;
        let journal = progress.record(&event);
        journal?;
        if failed {
            return Err("operation failed; retained measured prefix".into());
        }
    }
    for assertion in &plan.settings.assertions {
        require_budget(deadline)?;
        let mut fact = AssessmentAssertionObservation {
            id: assertion.id.clone(),
            passed: None,
            actual_sha256: None,
            actual_size_bytes: None,
            error: None,
        };
        let observed = (|| -> Result<Option<(String, u64)>> {
            match &assertion.target {
                AssessmentAssertionTarget::Stdout { launch_step }
                | AssessmentAssertionTarget::Stderr { launch_step } => {
                    let process = report
                        .steps
                        .iter()
                        .find(|s| s.index == *launch_step)
                        .and_then(|s| s.process.as_ref())
                        .ok_or("asserted launch not measured")?;
                    let capture =
                        if matches!(assertion.target, AssessmentAssertionTarget::Stdout { .. }) {
                            &process.stdout
                        } else {
                            &process.stderr
                        };
                    if !capture.complete {
                        return Err("asserted capture incomplete".into());
                    }
                    Ok(Some((capture.sha256.clone(), capture.size_bytes)))
                }
                AssessmentAssertionTarget::WorkFile { path } => {
                    Ok(files::observe_work(path, plan.settings.file_max_bytes)?
                        .map(|f| (f.sha256, f.size_bytes)))
                }
            }
        })();
        let budget_after_observation = require_budget(deadline);
        match observed {
            Ok(Some((hash, size))) => {
                fact.passed = Some(
                    assertion
                        .expected_sha256
                        .as_ref()
                        .is_none_or(|h| h == &hash)
                        && assertion.expected_size_bytes.is_none_or(|n| n == size),
                );
                fact.actual_sha256 = Some(hash);
                fact.actual_size_bytes = Some(size);
            }
            Ok(None) => fact.passed = Some(false),
            Err(error) => {
                fact.error = Some(bound_error(&error));
                report
                    .driver_errors
                    .push("declared assertion measurement incomplete".into());
            }
        }
        let event = AssessmentProgressEvent::Assertion {
            observation: fact.clone(),
        };
        report.assertions.push(fact);
        check_collector(&mut report.collector_unimpersonated)?;
        let journal = progress.record(&event);
        journal?;
        budget_after_observation?;
    }
    require_budget(deadline)
}
fn require_budget(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err("assessment total budget expired; no next operation dispatched; blocking IO/cleanup remain outer-watchdog bounded".into())
    } else {
        Ok(())
    }
}
fn profile_name() -> Vec<u16> {
    OsStr::new(PROFILE).encode_wide().chain(Some(0)).collect()
}
struct ProfileSid(PSID);
impl ProfileSid {
    fn derive() -> Result<Self> {
        unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(profile_name().as_ptr())) }
            .map(Self)
            .map_err(|e| e.to_string())
    }
    fn text(&self) -> Result<String> {
        let mut output = PWSTR::null();
        unsafe { ConvertSidToStringSidW(self.0, &mut output) }.map_err(|e| e.to_string())?;
        let result = unsafe { output.to_string() }.map_err(|e| e.to_string());
        unsafe { LocalFree(Some(HLOCAL(output.0.cast()))) };
        result
    }
}
impl Drop for ProfileSid {
    fn drop(&mut self) {
        unsafe { windows::Win32::Security::FreeSid(self.0) };
    }
}
struct Profile {
    sid: ProfileSid,
    text: String,
    cleanup_attempted: bool,
}
impl Profile {
    fn create() -> std::result::Result<Self, (String, Option<bool>)> {
        let name = profile_name();
        let sid = unsafe {
            CreateAppContainerProfile(
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                None,
            )
        }
        .map_err(|e| (format!("fresh assessment profile refused: {e}"), None))?;
        let mut owned = Self {
            sid: ProfileSid(sid),
            text: String::new(),
            cleanup_attempted: false,
        };
        let checked = (|| -> Result<()> {
            owned.text = owned.sid.text()?;
            let derived = ProfileSid::derive()?;
            if derived.text() != Ok(owned.text.clone()) {
                return Err("fresh profile SID differs".into());
            }
            Ok(())
        })();
        if let Err(error) = checked {
            let cleanup = owned.cleanup();
            return Err((
                format!("{error}; profile cleanup={cleanup:?}"),
                Some(cleanup.is_ok()),
            ));
        }
        Ok(owned)
    }
    fn cleanup(&mut self) -> Result<()> {
        if self.cleanup_attempted {
            return Err("profile cleanup already attempted; no replay".into());
        }
        self.cleanup_attempted = true;
        unsafe { DeleteAppContainerProfile(PCWSTR(profile_name().as_ptr())) }
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_agent_spelling_has_no_path_fallback() {
        let expected = r"C:\AIW\Tools\aiw-guest-agent.exe";
        assert!(fixed_image(
            Path::new(r"\\?\C:\AIW\Tools\aiw-guest-agent.exe"),
            expected
        ));
        for path in [
            r"C:\other\aiw-guest-agent.exe",
            r"C:\AIW\Tools\..\Tools\aiw-guest-agent.exe",
            r"C:\AIW\Tools\aiw-guest-agent.exe:ads",
            r"\\server\x\aiw-guest-agent.exe",
        ] {
            assert!(!fixed_image(Path::new(path), expected));
        }
    }
    #[test]
    fn errors_are_bounded_without_splitting_utf8() {
        assert_eq!(bound_error(&"界".repeat(2048)).chars().count(), 1024);
    }
}
