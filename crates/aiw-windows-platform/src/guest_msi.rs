//! Narrow native execution primitive used only by the Windows Sandbox guest
//! agent's fixed imported-MSI profile.  This is deliberately not a general
//! process-launch API.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsHandle as _, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use aiw_provider_wsb::{
    CompiledMsiScenario, DOCUMENT_EXERCISE_PATH, DOCUMENT_EXPECTED_TEXT, DOCUMENT_INITIAL_TEXT,
    FixedDocumentExercise, FunctionalExercise,
};
use aiw_token::{TokenEvidence, collect_process_token};
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::Win32::Foundation::{
    ERROR_SUCCESS, GetLastError, HANDLE, HWND, LPARAM, SetLastError, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT, WPARAM,
};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
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
    EnumChildWindows, EnumWindows, GetClassNameW, GetWindowThreadProcessId, IsWindowVisible,
    PostMessageW, SMTO_ABORTIFHUNG, SMTO_BLOCK, SMTO_ERRORONEXIT, SendMessageTimeoutW, WM_CHAR,
    WM_CLOSE, WM_COMMAND, WM_GETTEXT,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

const MSIEXEC_PATH: &str = r"C:\Windows\System32\msiexec.exe";
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const EDITOR_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const CHARACTER_TIMEOUT: Duration = Duration::from_millis(250);
const DOCUMENT_SAVE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_EXERCISE_TEXT_CODE_UNITS: usize = 256;
const NOTEPAD_PLUS_PLUS_SAVE_COMMAND: u16 = 41_006;
const NOTEPAD_PLUS_PLUS_SELECT_ALL_COMMAND: u16 = 42_007;
const SCINTILLA_CLASS: &[u16] = &[83, 99, 105, 110, 116, 105, 108, 108, 97];
const IO_REPARSE_TAG: u32 = 0x400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMsiExecutionObservation {
    pub install_exit_code: i32,
    pub launch_process_id: u32,
    pub launch_exit_code: i32,
    pub application_token: TokenEvidence,
    pub functional_exercise: Option<FunctionalExercise>,
    pub filesystem_observations: Option<GuestMsiFilesystemObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMsiFilesystemObservation {
    pub before_install: aiw_provider_wsb::ApplicationFilesystemSnapshot,
    pub after_install: aiw_provider_wsb::ApplicationFilesystemSnapshot,
    pub after_exercise: aiw_provider_wsb::ApplicationFilesystemSnapshot,
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

    let before_install = scenario
        .requires_application_exercise()
        .then(crate::snapshot_fixed_notepad_files);
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

    let after_install = scenario
        .requires_application_exercise()
        .then(crate::snapshot_fixed_notepad_files);
    let document_exercise = if scenario.requires_application_exercise() {
        Some(prepare_fixed_document_exercise(scenario)?)
    } else {
        None
    };
    let launch_arguments = document_exercise
        .as_ref()
        .map(|_| vec![DOCUMENT_EXERCISE_PATH.to_owned()])
        .unwrap_or_default();
    let application = GuestProcess::start(&scenario.launch_path, &launch_arguments)?;
    let launch_process_id = application.process_id;
    let operation = (|| {
        let window = application.wait_for_window(Duration::from_secs(u64::from(
            scenario.process_wait_timeout_seconds,
        )))?;
        let mut window_process_id = 0;
        unsafe { GetWindowThreadProcessId(window, Some(&mut window_process_id)) };
        if window_process_id != application.process_id {
            return Err(GuestMsiExecutionError::Process(
                "observed application window changed owner".to_owned(),
            ));
        }
        let application_token =
            collect_process_token(application.process.as_handle()).map_err(|error| {
                GuestMsiExecutionError::Process(format!(
                    "collect launched application token failed: {error}"
                ))
            })?;
        if application_token.process_id != application.process_id {
            return Err(GuestMsiExecutionError::Process(
                "collected application token changed process identity".to_owned(),
            ));
        }
        let functional_exercise = document_exercise
            .as_ref()
            .map(|plan| exercise_fixed_document(window, application.process_id, plan))
            .transpose()?;
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
        Ok((exit_code, application_token, functional_exercise))
    })();
    let cleanup = if operation.is_ok() {
        application.verify_empty_after_success()
    } else {
        application.cleanup()
    };
    let (launch_exit_code, application_token, functional_exercise) =
        complete_process_operation(operation, cleanup)?;
    let filesystem_observations =
        before_install
            .zip(after_install)
            .map(
                |(before_install, after_install)| GuestMsiFilesystemObservation {
                    before_install,
                    after_install,
                    after_exercise: crate::snapshot_fixed_notepad_files(),
                },
            );
    Ok(GuestMsiExecutionObservation {
        install_exit_code,
        launch_process_id,
        launch_exit_code,
        application_token,
        functional_exercise,
        filesystem_observations,
    })
}

struct ExercisePlan {
    expected_sha256: String,
}

fn prepare_fixed_document_exercise(
    scenario: &CompiledMsiScenario,
) -> Result<ExercisePlan, GuestMsiExecutionError> {
    let exercise = scenario.document_exercise.as_ref().ok_or_else(|| {
        GuestMsiExecutionError::Scenario(
            "current fixed scenario did not bind its document exercise".to_owned(),
        )
    })?;
    let expected_sha256 = validate_fixed_document_contract(exercise)?;

    let parent = Path::new(DOCUMENT_EXERCISE_PATH).parent().ok_or_else(|| {
        GuestMsiExecutionError::Process("fixed document path did not have a parent".to_owned())
    })?;
    match fs::create_dir(parent) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(GuestMsiExecutionError::Process(format!(
                "create fixed document directory failed: {error}"
            )));
        }
    }
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
        GuestMsiExecutionError::Process(format!("read fixed document directory failed: {error}"))
    })?;
    if !is_ordinary_directory(&parent_metadata) {
        return Err(GuestMsiExecutionError::Process(
            "fixed document directory was not an ordinary directory".to_owned(),
        ));
    }

    let mut document = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(DOCUMENT_EXERCISE_PATH)
        .map_err(|error| {
            GuestMsiExecutionError::Process(format!("create fixed document failed: {error}"))
        })?;
    document
        .write_all(DOCUMENT_INITIAL_TEXT.as_bytes())
        .map_err(|error| {
            GuestMsiExecutionError::Process(format!("write fixed document failed: {error}"))
        })?;
    document.sync_all().map_err(|error| {
        GuestMsiExecutionError::Process(format!("sync fixed document failed: {error}"))
    })?;
    Ok(ExercisePlan { expected_sha256 })
}

fn exercise_fixed_document(
    main_window: HWND,
    process_id: u32,
    plan: &ExercisePlan,
) -> Result<FunctionalExercise, GuestMsiExecutionError> {
    let editor = wait_for_ready_document_editor(main_window, process_id, EDITOR_LOOKUP_TIMEOUT)?;
    // HWNDs are reusable. Check both handles immediately before the input
    // sequence, rather than relying on the observations used for readiness.
    require_visible_process_window(main_window, process_id, "Notepad++ main window")?;
    require_visible_process_window(editor, process_id, "Notepad++ Scintilla editor")?;

    // WM_COMMAND and WM_CHAR are system messages below WM_USER. Windows
    // marshals their parameters across processes; no Scintilla custom message
    // or caller pointer is sent into the application process.
    send_window_message(
        main_window,
        WM_COMMAND,
        WPARAM(usize::from(NOTEPAD_PLUS_PLUS_SELECT_ALL_COMMAND)),
        LPARAM(0),
        COMMAND_TIMEOUT,
    )?;
    // Scintilla handles each WM_CHAR as direct input. A physical Enter sends
    // CR, then the editor emits its configured CRLF line ending; do not send
    // an additional LF that could create a second line ending.
    let replacement: Vec<u16> = fixed_editor_input_text()?.encode_utf16().collect();
    if replacement.is_empty() || replacement.len() > MAX_EXERCISE_TEXT_CODE_UNITS {
        return Err(GuestMsiExecutionError::Process(
            "fixed replacement text exceeded its bound".to_owned(),
        ));
    }
    for character in replacement {
        send_window_message(
            editor,
            WM_CHAR,
            WPARAM(usize::from(character)),
            LPARAM(0),
            CHARACTER_TIMEOUT,
        )?;
    }
    send_window_message(
        main_window,
        WM_COMMAND,
        WPARAM(usize::from(NOTEPAD_PLUS_PLUS_SAVE_COMMAND)),
        LPARAM(0),
        COMMAND_TIMEOUT,
    )?;
    let observed_sha256 = wait_for_document_sha256(&plan.expected_sha256, DOCUMENT_SAVE_TIMEOUT)?;
    Ok(FunctionalExercise {
        opened_document: true,
        saved_document: true,
        expected_sha256: plan.expected_sha256.clone(),
        observed_sha256,
    })
}

fn wait_for_ready_document_editor(
    parent: HWND,
    process_id: u32,
    timeout: Duration,
) -> Result<HWND, GuestMsiExecutionError> {
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        GuestMsiExecutionError::Process(
            "editor lookup timeout overflowed monotonic clock".to_owned(),
        )
    })?;
    loop {
        let remaining = remaining_timeout(deadline)?;
        require_visible_process_window(parent, process_id, "Notepad++ main window")?;
        let title = read_window_text(parent, remaining.min(COMMAND_TIMEOUT))?;
        if title.to_ascii_lowercase().contains("document.txt") {
            if let Some(editor) = find_scintilla_child_window(parent, process_id)? {
                require_visible_process_window(editor, process_id, "Notepad++ Scintilla editor")?;
                let initial_text =
                    read_window_text(editor, remaining_timeout(deadline)?.min(COMMAND_TIMEOUT))?;
                if initial_text == DOCUMENT_INITIAL_TEXT {
                    return Ok(editor);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(GuestMsiExecutionError::Process(
                "Notepad++ did not expose the fixed document title and initial text before timeout"
                    .to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn find_scintilla_child_window(
    parent: HWND,
    process_id: u32,
) -> Result<Option<HWND>, GuestMsiExecutionError> {
    let mut context = ScintillaSearch {
        process_id,
        editor: None,
    };
    unsafe { SetLastError(ERROR_SUCCESS) };
    let enumerated = unsafe {
        EnumChildWindows(
            Some(parent),
            Some(find_scintilla_child),
            LPARAM((&mut context as *mut ScintillaSearch) as isize),
        )
    };
    if !enumerated.as_bool() {
        let error = unsafe { GetLastError() };
        return Err(GuestMsiExecutionError::Process(format!(
            "EnumChildWindows failed: {error:?}"
        )));
    }
    Ok(context.editor)
}

fn require_visible_process_window(
    window: HWND,
    process_id: u32,
    role: &str,
) -> Result<(), GuestMsiExecutionError> {
    let mut observed_process_id = 0u32;
    unsafe { GetWindowThreadProcessId(window, Some(&mut observed_process_id)) };
    if observed_process_id != process_id || !unsafe { IsWindowVisible(window) }.as_bool() {
        return Err(GuestMsiExecutionError::Process(format!(
            "{role} no longer belongs to the launched visible process"
        )));
    }
    Ok(())
}

fn remaining_timeout(deadline: Instant) -> Result<Duration, GuestMsiExecutionError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(GuestMsiExecutionError::Process(
            "Notepad++ document readiness timed out".to_owned(),
        ));
    }
    Ok(remaining)
}

fn read_window_text(window: HWND, timeout: Duration) -> Result<String, GuestMsiExecutionError> {
    let mut text = vec![0u16; MAX_EXERCISE_TEXT_CODE_UNITS + 1];
    // WM_GETTEXT is a system message. Its bounded caller buffer is marshaled
    // by Windows for this cross-process send.
    send_window_message(
        window,
        WM_GETTEXT,
        WPARAM(text.len()),
        LPARAM(text.as_mut_ptr() as isize),
        timeout,
    )?;
    let length = text
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(text.len());
    String::from_utf16(&text[..length]).map_err(|error| {
        GuestMsiExecutionError::Process(format!("window returned invalid UTF-16 text: {error}"))
    })
}

fn send_window_message(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    timeout: Duration,
) -> Result<(), GuestMsiExecutionError> {
    let timeout_milliseconds = timeout.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
    unsafe { SetLastError(ERROR_SUCCESS) };
    let result = unsafe {
        SendMessageTimeoutW(
            window,
            message,
            wparam,
            lparam,
            SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT,
            timeout_milliseconds,
            None,
        )
    };
    if result.0 != 0 {
        return Ok(());
    }
    let error = unsafe { GetLastError() };
    if error == ERROR_SUCCESS {
        return Err(GuestMsiExecutionError::Process(
            "bounded window message did not complete".to_owned(),
        ));
    }
    Err(GuestMsiExecutionError::Process(format!(
        "bounded window message failed: {error:?}"
    )))
}

fn wait_for_document_sha256(
    expected_sha256: &str,
    timeout: Duration,
) -> Result<String, GuestMsiExecutionError> {
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        GuestMsiExecutionError::Process(
            "document save timeout overflowed monotonic clock".to_owned(),
        )
    })?;
    loop {
        if let Some(observed_sha256) = observe_fixed_document()? {
            if observed_sha256 == expected_sha256 {
                return Ok(observed_sha256);
            }
        }
        if Instant::now() >= deadline {
            return Err(GuestMsiExecutionError::Process(
                "fixed document did not save the expected bytes before timeout".to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn observe_fixed_document() -> Result<Option<String>, GuestMsiExecutionError> {
    let expected_bytes = DOCUMENT_EXPECTED_TEXT.as_bytes();
    let expected_length = u64::try_from(expected_bytes.len()).map_err(|_| {
        GuestMsiExecutionError::Process("fixed document size did not fit a u64".to_owned())
    })?;
    // Keep this handle through validation and hashing. FILE_SHARE_READ permits
    // readers only, so new write and delete opens cannot race the observation.
    let mut document = match OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(DOCUMENT_EXERCISE_PATH)
    {
        Ok(file) => file,
        Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => {
            return Err(GuestMsiExecutionError::Process(format!(
                "open fixed document for observation failed: {error}"
            )));
        }
    };
    let before = document.metadata().map_err(|error| {
        GuestMsiExecutionError::Process(format!(
            "read held fixed document metadata failed: {error}"
        ))
    })?;
    if !is_ordinary_file(&before) {
        return Err(GuestMsiExecutionError::Process(
            "held fixed document was not an ordinary file".to_owned(),
        ));
    }
    if before.len() != expected_length {
        return Ok(None);
    }
    let maximum_read = expected_length.checked_add(1).ok_or_else(|| {
        GuestMsiExecutionError::Process("fixed document read bound overflowed".to_owned())
    })?;
    let capacity = usize::try_from(maximum_read).map_err(|_| {
        GuestMsiExecutionError::Process(
            "fixed document read bound did not fit memory size".to_owned(),
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut document)
        .take(maximum_read)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            GuestMsiExecutionError::Process(format!("read held fixed document failed: {error}"))
        })?;
    let after = document.metadata().map_err(|error| {
        GuestMsiExecutionError::Process(format!(
            "revalidate held fixed document metadata failed: {error}"
        ))
    })?;
    if !is_ordinary_file(&after) || after.len() != expected_length {
        return Err(GuestMsiExecutionError::Process(
            "held fixed document changed while it was observed".to_owned(),
        ));
    }
    if bytes.len() != expected_bytes.len() || bytes != expected_bytes {
        return Ok(None);
    }
    Ok(Some(sha256(&bytes)))
}

fn has_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & IO_REPARSE_TAG != 0
}

fn is_ordinary_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir() && !metadata.file_type().is_symlink() && !has_reparse_point(metadata)
}

fn is_ordinary_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file() && !metadata.file_type().is_symlink() && !has_reparse_point(metadata)
}

fn fixed_editor_input_text() -> Result<&'static str, GuestMsiExecutionError> {
    let input = DOCUMENT_EXPECTED_TEXT.strip_suffix('\n').ok_or_else(|| {
        GuestMsiExecutionError::Scenario(
            "fixed document output did not end in the expected CRLF sequence".to_owned(),
        )
    })?;
    if !input.ends_with('\r') || !input.is_ascii() {
        return Err(GuestMsiExecutionError::Scenario(
            "fixed document input was not ASCII text ending in carriage return".to_owned(),
        ));
    }
    Ok(input)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_fixed_document_contract(
    exercise: &FixedDocumentExercise,
) -> Result<String, GuestMsiExecutionError> {
    let initial_sha256 = sha256(DOCUMENT_INITIAL_TEXT.as_bytes());
    let expected_sha256 = sha256(DOCUMENT_EXPECTED_TEXT.as_bytes());
    if exercise.document_path != DOCUMENT_EXERCISE_PATH
        || exercise.initial_sha256 != initial_sha256
        || exercise.expected_sha256 != expected_sha256
    {
        return Err(GuestMsiExecutionError::Scenario(
            "compiled document exercise did not match the fixed guest contract".to_owned(),
        ));
    }
    Ok(expected_sha256)
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
    if process_id == context.process_id
        && context.window.is_none()
        && unsafe { IsWindowVisible(window) }.as_bool()
    {
        context.window = Some(window);
    }
    // Returning FALSE also makes EnumWindows return FALSE. Continue the bounded
    // enumeration so discovering the window is not misreported as API failure.
    BOOL(1)
}

struct ScintillaSearch {
    process_id: u32,
    editor: Option<HWND>,
}

unsafe extern "system" fn find_scintilla_child(window: HWND, value: LPARAM) -> BOOL {
    let context = unsafe { &mut *(value.0 as *mut ScintillaSearch) };
    if context.editor.is_some() || !unsafe { IsWindowVisible(window) }.as_bool() {
        return BOOL(1);
    }
    let mut process_id = 0u32;
    unsafe { GetWindowThreadProcessId(window, Some(&mut process_id)) };
    if process_id != context.process_id {
        return BOOL(1);
    }
    let mut class_name = [0u16; 32];
    let length = unsafe { GetClassNameW(window, &mut class_name) };
    if length > 0 && class_name[..length as usize] == *SCINTILLA_CLASS {
        context.editor = Some(window);
    }
    // Continue enumeration so the API does not report the intentional match
    // as an enumeration failure.
    BOOL(1)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_exercise() -> FixedDocumentExercise {
        FixedDocumentExercise {
            document_path: DOCUMENT_EXERCISE_PATH.to_owned(),
            initial_sha256: sha256(DOCUMENT_INITIAL_TEXT.as_bytes()),
            expected_sha256: sha256(DOCUMENT_EXPECTED_TEXT.as_bytes()),
        }
    }

    #[test]
    fn fixed_document_contract_accepts_only_the_reviewed_values() {
        let exercise = fixed_exercise();
        assert_eq!(
            validate_fixed_document_contract(&exercise).expect("fixed exercise must validate"),
            sha256(DOCUMENT_EXPECTED_TEXT.as_bytes())
        );

        let mut altered = exercise;
        altered.document_path = r"C:\AIW\Scenario\other.txt".to_owned();
        assert!(validate_fixed_document_contract(&altered).is_err());
    }

    #[test]
    fn fixed_editor_input_uses_one_carriage_return_for_the_expected_crlf() {
        let input = fixed_editor_input_text().expect("fixed editor input must validate");
        assert!(input.ends_with('\r'));
        assert_eq!(format!("{input}\n"), DOCUMENT_EXPECTED_TEXT);
    }
}
