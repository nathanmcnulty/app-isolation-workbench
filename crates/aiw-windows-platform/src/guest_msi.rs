//! Narrow native execution primitive used only by the Windows Sandbox guest
//! agent's fixed imported-MSI profile.  This is deliberately not a general
//! process-launch API.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use aiw_provider_wsb::CompiledMsiScenario;
use thiserror::Error;
use windows::Win32::Foundation::{
    HANDLE, HWND, LPARAM, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT, WPARAM,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

const MSIEXEC_PATH: &str = r"C:\Windows\System32\msiexec.exe";
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMsiExecutionObservation {
    pub install_exit_code: i32,
    pub launch_process_id: u32,
    pub launch_exit_code: i32,
}

#[derive(Debug, Error)]
pub enum GuestMsiExecutionError {
    #[error("compiled imported-MSI scenario is invalid: {0}")]
    Scenario(String),
    #[error("fixed guest process operation failed: {0}")]
    Process(String),
}

/// Executes only the validated Notepad++ MSI profile.  Each child starts
/// suspended and is assigned to a kill-on-close job before it can run.  Every
/// success and failure path terminates and verifies the assigned process tree.
pub fn execute_fixed_notepad_plus_plus_msi(
    scenario: &CompiledMsiScenario,
) -> Result<GuestMsiExecutionObservation, GuestMsiExecutionError> {
    scenario
        .validate()
        .map_err(|error| GuestMsiExecutionError::Scenario(error.to_string()))?;

    let installer = GuestProcess::start(MSIEXEC_PATH, &scenario.install_arguments)?;
    let install_exit_code = installer.wait_for_exit(Duration::from_secs(u64::from(
        scenario.install_timeout_seconds,
    )));
    let install_cleanup = if install_exit_code.is_ok() {
        installer.verify_empty_after_success()
    } else {
        installer.cleanup()
    };
    let install_exit_code = complete_process_operation(install_exit_code, install_cleanup)?;
    if install_exit_code != scenario.expected_exit_code {
        return Err(GuestMsiExecutionError::Process(format!(
            "fixed msiexec exited with {install_exit_code}"
        )));
    }

    let application = GuestProcess::start(&scenario.launch_path, &[])?;
    let launch_process_id = application.process_id;
    let operation = (|| {
        let window = application.wait_for_window(Duration::from_secs(u64::from(
            scenario.process_wait_timeout_seconds,
        )))?;
        unsafe { PostMessageW(Some(window), WM_CLOSE, WPARAM(0), LPARAM(0)) }.map_err(|error| {
            GuestMsiExecutionError::Process(format!("WM_CLOSE failed: {error}"))
        })?;
        let exit_code = application.wait_for_exit(Duration::from_secs(u64::from(
            scenario.graceful_close_timeout_seconds,
        )))?;
        if exit_code != scenario.expected_exit_code {
            return Err(GuestMsiExecutionError::Process(format!(
                "Notepad++ exited with {exit_code} after WM_CLOSE"
            )));
        }
        Ok(exit_code)
    })();
    let cleanup = if operation.is_ok() {
        application.verify_empty_after_success()
    } else {
        application.cleanup()
    };
    let launch_exit_code = complete_process_operation(operation, cleanup)?;
    Ok(GuestMsiExecutionObservation {
        install_exit_code,
        launch_process_id,
        launch_exit_code,
    })
}

fn complete_process_operation<T>(
    operation: Result<T, GuestMsiExecutionError>,
    cleanup: Result<(), GuestMsiExecutionError>,
) -> Result<T, GuestMsiExecutionError> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(operation), Ok(())) => Err(operation),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(operation), Err(cleanup)) => Err(GuestMsiExecutionError::Process(format!(
            "{operation}; containment cleanup also failed: {cleanup}"
        ))),
    }
}

struct GuestProcess {
    job: ScenarioJob,
    process: OwnedHandle,
    process_id: u32,
}

impl GuestProcess {
    fn start(path: &str, arguments: &[String]) -> Result<Self, GuestMsiExecutionError> {
        let executable = Path::new(path);
        let parent = executable.parent().ok_or_else(|| {
            GuestMsiExecutionError::Process("fixed executable does not have a parent".to_owned())
        })?;
        let command_line = aiw_windows_command_line::join_arguments(
            std::iter::once(path).chain(arguments.iter().map(String::as_str)),
        );
        let executable_wide = wide(path)?;
        let parent_wide = wide_os(parent.as_os_str())?;
        let mut command_line_wide = wide(&command_line)?;
        let job = ScenarioJob::create()?;
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut information = PROCESS_INFORMATION::default();
        unsafe {
            CreateProcessW(
                PCWSTR(executable_wide.as_ptr()),
                Some(PWSTR(command_line_wide.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                None,
                PCWSTR(parent_wide.as_ptr()),
                &startup,
                &mut information,
            )
        }
        .map_err(|error| {
            GuestMsiExecutionError::Process(format!("CreateProcessW failed: {error}"))
        })?;
        let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };
        let thread = unsafe { OwnedHandle::from_raw_handle(information.hThread.0) };
        if let Err(error) = unsafe { AssignProcessToJobObject(job.raw(), raw_handle(&process)) } {
            // Assignment failed, so the job cannot prove cleanup.  The child
            // is still suspended and must be terminated through its exact
            // process handle before returning.
            let cleanup = terminate_unassigned_process(&process);
            return Err(GuestMsiExecutionError::Process(format!(
                "AssignProcessToJobObject failed: {error}; cleanup={cleanup:?}"
            )));
        }
        if unsafe { ResumeThread(raw_handle(&thread)) } == u32::MAX {
            let cleanup = job.terminate_and_verify_empty();
            return Err(GuestMsiExecutionError::Process(format!(
                "ResumeThread failed; cleanup={cleanup:?}"
            )));
        }
        drop(thread);
        Ok(Self {
            job,
            process,
            process_id: information.dwProcessId,
        })
    }

    fn wait_for_exit(&self, timeout: Duration) -> Result<i32, GuestMsiExecutionError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            GuestMsiExecutionError::Process("process timeout overflowed monotonic clock".to_owned())
        })?;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(GuestMsiExecutionError::Process(
                    "fixed guest process timed out".to_owned(),
                ));
            }
            let milliseconds = deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(50))
                .as_millis()
                .clamp(1, u128::from(u32::MAX)) as u32;
            match unsafe { WaitForSingleObject(raw_handle(&self.process), milliseconds) } {
                WAIT_OBJECT_0 => {
                    let mut exit_code = 0u32;
                    unsafe { GetExitCodeProcess(raw_handle(&self.process), &mut exit_code) }
                        .map_err(|error| {
                            GuestMsiExecutionError::Process(format!(
                                "GetExitCodeProcess failed: {error}"
                            ))
                        })?;
                    return Ok(exit_code as i32);
                }
                WAIT_TIMEOUT => continue,
                WAIT_FAILED => {
                    return Err(GuestMsiExecutionError::Process(
                        "WaitForSingleObject failed".to_owned(),
                    ));
                }
                _ => {
                    return Err(GuestMsiExecutionError::Process(
                        "WaitForSingleObject returned an unexpected status".to_owned(),
                    ));
                }
            }
        }
    }

    fn wait_for_window(&self, timeout: Duration) -> Result<HWND, GuestMsiExecutionError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            GuestMsiExecutionError::Process(
                "window observation timeout overflowed monotonic clock".to_owned(),
            )
        })?;
        loop {
            let mut context = WindowSearch {
                process_id: self.process_id,
                window: None,
            };
            unsafe {
                EnumWindows(
                    Some(find_window_for_process),
                    LPARAM((&mut context as *mut WindowSearch) as isize),
                )
            }
            .map_err(|error| {
                GuestMsiExecutionError::Process(format!("EnumWindows failed: {error}"))
            })?;
            if let Some(window) = context.window {
                return Ok(window);
            }
            match unsafe { WaitForSingleObject(raw_handle(&self.process), 0) } {
                WAIT_TIMEOUT => {}
                WAIT_OBJECT_0 => {
                    return Err(GuestMsiExecutionError::Process(
                        "Notepad++ exited before a window was observed".to_owned(),
                    ));
                }
                _ => {
                    return Err(GuestMsiExecutionError::Process(
                        "could not observe the launched process".to_owned(),
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err(GuestMsiExecutionError::Process(
                    "Notepad++ window was not observed before timeout".to_owned(),
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn cleanup(&self) -> Result<(), GuestMsiExecutionError> {
        self.job.terminate_and_verify_empty()
    }

    fn verify_empty_after_success(&self) -> Result<(), GuestMsiExecutionError> {
        let deadline = Instant::now().checked_add(CLEANUP_TIMEOUT).ok_or_else(|| {
            GuestMsiExecutionError::Process("cleanup timeout overflowed monotonic clock".to_owned())
        })?;
        loop {
            match self.job.active_processes() {
                Ok(0) => return Ok(()),
                Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(_) => {
                    let cleanup = self.job.terminate_and_verify_empty();
                    return Err(GuestMsiExecutionError::Process(format!(
                        "guest child processes remained after the expected process exit; cleanup={cleanup:?}"
                    )));
                }
                Err(error) => {
                    let cleanup = self.job.terminate_and_verify_empty();
                    return Err(GuestMsiExecutionError::Process(format!(
                        "could not verify guest descendant cleanup: {error}; cleanup={cleanup:?}"
                    )));
                }
            }
        }
    }
}

fn terminate_unassigned_process(process: &OwnedHandle) -> Result<(), GuestMsiExecutionError> {
    unsafe { TerminateProcess(raw_handle(process), 1) }.map_err(|error| {
        GuestMsiExecutionError::Process(format!("TerminateProcess failed: {error}"))
    })?;
    match unsafe { WaitForSingleObject(raw_handle(process), CLEANUP_TIMEOUT.as_millis() as u32) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(GuestMsiExecutionError::Process(
            "unassigned suspended process did not exit during cleanup".to_owned(),
        )),
        _ => Err(GuestMsiExecutionError::Process(
            "could not verify unassigned suspended process cleanup".to_owned(),
        )),
    }
}

struct ScenarioJob {
    handle: OwnedHandle,
}

impl ScenarioJob {
    fn create() -> Result<Self, GuestMsiExecutionError> {
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(|error| {
            GuestMsiExecutionError::Process(format!("CreateJobObjectW failed: {error}"))
        })?;
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                raw_handle(&handle),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(|error| {
            GuestMsiExecutionError::Process(format!("SetInformationJobObject failed: {error}"))
        })?;
        Ok(Self { handle })
    }

    fn raw(&self) -> HANDLE {
        raw_handle(&self.handle)
    }

    fn active_processes(&self) -> Result<u32, GuestMsiExecutionError> {
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
        .map_err(|error| {
            GuestMsiExecutionError::Process(format!("QueryInformationJobObject failed: {error}"))
        })?;
        Ok(accounting.ActiveProcesses)
    }

    fn terminate_and_verify_empty(&self) -> Result<(), GuestMsiExecutionError> {
        if self.active_processes()? > 0 {
            unsafe { TerminateJobObject(self.raw(), 1) }.map_err(|error| {
                GuestMsiExecutionError::Process(format!("TerminateJobObject failed: {error}"))
            })?;
        }
        let deadline = Instant::now().checked_add(CLEANUP_TIMEOUT).ok_or_else(|| {
            GuestMsiExecutionError::Process("cleanup timeout overflowed monotonic clock".to_owned())
        })?;
        while self.active_processes()? != 0 {
            if Instant::now() >= deadline {
                return Err(GuestMsiExecutionError::Process(
                    "guest process job remained active after cleanup".to_owned(),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}

struct WindowSearch {
    process_id: u32,
    window: Option<HWND>,
}

unsafe extern "system" fn find_window_for_process(window: HWND, value: LPARAM) -> BOOL {
    let context = unsafe { &mut *(value.0 as *mut WindowSearch) };
    let mut process_id = 0u32;
    unsafe { GetWindowThreadProcessId(window, Some(&mut process_id)) };
    if process_id == context.process_id {
        context.window = Some(window);
        BOOL(0)
    } else {
        BOOL(1)
    }
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    use std::os::windows::io::AsRawHandle;
    HANDLE(handle.as_raw_handle() as isize as *mut core::ffi::c_void)
}

fn wide(value: &str) -> Result<Vec<u16>, GuestMsiExecutionError> {
    if value.contains('\0') {
        return Err(GuestMsiExecutionError::Process(
            "fixed process value contained NUL".to_owned(),
        ));
    }
    Ok(OsStr::new(value).encode_wide().chain(Some(0)).collect())
}

fn wide_os(value: &OsStr) -> Result<Vec<u16>, GuestMsiExecutionError> {
    let encoded: Vec<u16> = value.encode_wide().collect();
    if encoded.contains(&0) {
        return Err(GuestMsiExecutionError::Process(
            "fixed process path contained NUL".to_owned(),
        ));
    }
    Ok(encoded.into_iter().chain(Some(0)).collect())
}
