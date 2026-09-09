//! Narrow native execution primitive used only by the Windows Sandbox guest
//! agent's fixed imported-MSI profile.  This is deliberately not a general
//! process-launch API.

use std::ffi::OsStr;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle as _, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use aiw_provider_wsb::{
    CompiledMsiScenario, DOCUMENT_EXERCISE_PATH, DOCUMENT_EXPECTED_TEXT, DOCUMENT_INITIAL_TEXT,
    FixedDocumentExercise, FunctionalExercise, StandardUserRuntimeContext,
};
use aiw_token::{TokenEvidence, collect_process_token};
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::Win32::Foundation::{
    ERROR_SUCCESS, GetLastError, HANDLE, HWND, LPARAM, SetLastError, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT, WPARAM,
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
    EnumChildWindows, EnumWindows, GetClassNameW, GetWindowThreadProcessId, IsWindowVisible,
    PostMessageW, SMTO_ABORTIFHUNG, SMTO_BLOCK, SMTO_ERRORONEXIT, SendMessageTimeoutW, WM_CHAR,
    WM_CLOSE, WM_COMMAND, WM_GETTEXT, WM_KEYDOWN, WM_KEYUP,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::guest_standard_user::StandardUserSession;

#[link(name = "Advapi32")]
unsafe extern "system" {
    fn CreateProcessWithTokenW(
        token: HANDLE,
        logon_flags: u32,
        application_name: PCWSTR,
        command_line: PWSTR,
        creation_flags: u32,
        environment: *const c_void,
        current_directory: PCWSTR,
        startup_info: *const STARTUPINFOW,
        process_information: *mut PROCESS_INFORMATION,
    ) -> BOOL;
}

const MSIEXEC_PATH: &str = r"C:\Windows\System32\msiexec.exe";
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const EDITOR_LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const CHARACTER_TIMEOUT: Duration = Duration::from_millis(250);
const DOCUMENT_SAVE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_EXERCISE_TEXT_CODE_UNITS: usize = 256;
const NOTEPAD_PLUS_PLUS_SAVE_COMMAND: u16 = 41_006;
const NOTEPAD_PLUS_PLUS_SELECT_ALL_COMMAND: u16 = 42_007;
const SCINTILLA_CLASS: &[u16] = &[83, 99, 105, 110, 116, 105, 108, 108, 97];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMsiExecutionObservation {
    pub install_exit_code: i32,
    pub launch_process_id: u32,
    pub launch_exit_code: i32,
    pub application_token: TokenEvidence,
    pub functional_exercise: Option<FunctionalExercise>,
    pub filesystem_observations: Option<GuestMsiFilesystemObservation>,
    pub standard_user_context: Option<StandardUserRuntimeContext>,
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
    #[error("fixed guest window identity changed: {0}")]
    WindowIdentity(String),
}

/// The fixed v0alpha3 guest profile's observable execution boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestMsiStage {
    BeforeInstallCapture,
    Install,
    AfterInstallCapture,
    PrepareDocument,
    Launch,
    OpenDocument,
    EditSaveDocument,
    Close,
    AfterExerciseCapture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestMsiStageStatus {
    Passed,
    Failed,
    NotReached,
}

#[derive(Debug)]
pub struct GuestMsiAttempt {
    pub result: Result<GuestMsiExecutionObservation, GuestMsiExecutionError>,
    pub stages: Vec<(GuestMsiStage, GuestMsiStageStatus)>,
}

const V3_STAGES: [GuestMsiStage; 9] = [
    GuestMsiStage::BeforeInstallCapture,
    GuestMsiStage::Install,
    GuestMsiStage::AfterInstallCapture,
    GuestMsiStage::PrepareDocument,
    GuestMsiStage::Launch,
    GuestMsiStage::OpenDocument,
    GuestMsiStage::EditSaveDocument,
    GuestMsiStage::Close,
    GuestMsiStage::AfterExerciseCapture,
];

struct StageRecorder {
    stages: Vec<(GuestMsiStage, GuestMsiStageStatus)>,
    current: Option<usize>,
}

impl StageRecorder {
    fn for_scenario(records_stages: bool) -> Self {
        Self {
            stages: if records_stages {
                V3_STAGES
                    .into_iter()
                    .map(|stage| (stage, GuestMsiStageStatus::NotReached))
                    .collect()
            } else {
                Vec::new()
            },
            current: None,
        }
    }

    fn run<T>(
        &mut self,
        stage: GuestMsiStage,
        operation: impl FnOnce() -> Result<T, GuestMsiExecutionError>,
    ) -> Result<T, GuestMsiExecutionError> {
        self.begin(stage);
        self.finish(operation())
    }

    fn begin(&mut self, stage: GuestMsiStage) {
        let Some(index) = self
            .stages
            .iter()
            .position(|(candidate, _)| *candidate == stage)
        else {
            return;
        };
        debug_assert!(self.current.is_none());
        debug_assert_eq!(self.stages[index].1, GuestMsiStageStatus::NotReached);
        debug_assert!(
            self.stages[..index]
                .iter()
                .all(|(_, status)| *status == GuestMsiStageStatus::Passed)
        );
        self.current = Some(index);
    }

    fn finish<T>(
        &mut self,
        result: Result<T, GuestMsiExecutionError>,
    ) -> Result<T, GuestMsiExecutionError> {
        if let Some(index) = self.current.take() {
            self.stages[index].1 = if result.is_ok() {
                GuestMsiStageStatus::Passed
            } else {
                GuestMsiStageStatus::Failed
            };
        }
        result
    }
}

/// Executes only the validated Notepad++ MSI profile.  Each child starts
/// suspended and is assigned to a kill-on-close job before it can run.  Every
/// success and failure path terminates and verifies the assigned process tree.
pub fn execute_fixed_notepad_plus_plus_msi(
    scenario: &CompiledMsiScenario,
) -> Result<GuestMsiExecutionObservation, GuestMsiExecutionError> {
    execute_fixed_notepad_plus_plus_msi_attempt(scenario).result
}

/// Executes the fixed profile and retains its reached native stages when an
/// operation fails.  Stage claims exist only for the v0alpha3 document profile.
pub fn execute_fixed_notepad_plus_plus_msi_attempt(
    scenario: &CompiledMsiScenario,
) -> GuestMsiAttempt {
    if let Err(error) = scenario.validate() {
        return GuestMsiAttempt {
            result: Err(GuestMsiExecutionError::Scenario(error.to_string())),
            stages: Vec::new(),
        };
    }

    let mut stages = StageRecorder::for_scenario(scenario.requires_application_exercise());
    let result = execute_validated_fixed_notepad_plus_plus_msi(scenario, &mut stages);
    GuestMsiAttempt {
        result,
        stages: stages.stages,
    }
}

fn execute_validated_fixed_notepad_plus_plus_msi(
    scenario: &CompiledMsiScenario,
    stages: &mut StageRecorder,
) -> Result<GuestMsiExecutionObservation, GuestMsiExecutionError> {
    let (standard_user, before_install) = if scenario.requires_standard_user() {
        stages.run(GuestMsiStage::BeforeInstallCapture, || {
            let standard_user = StandardUserSession::establish()?;
            // Capture issues are observation data, not failed capture attempts.
            let snapshot = crate::guest_filesystem::snapshot_fixed_notepad_files_for_user(
                standard_user.roaming_app_data(),
                standard_user.local_app_data(),
            );
            Ok((Some(standard_user), Some(snapshot)))
        })?
    } else {
        (
            None,
            scenario
                .requires_application_exercise()
                .then(|| {
                    stages.run(GuestMsiStage::BeforeInstallCapture, || {
                        Ok(crate::snapshot_fixed_notepad_files())
                    })
                })
                .transpose()?,
        )
    };
    let install_exit_code = stages.run(GuestMsiStage::Install, || {
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
        Ok(install_exit_code)
    })?;

    let after_install = scenario
        .requires_application_exercise()
        .then(|| {
            stages.run(GuestMsiStage::AfterInstallCapture, || {
                Ok(if let Some(standard_user) = &standard_user {
                    crate::guest_filesystem::snapshot_fixed_notepad_files_for_user(
                        standard_user.roaming_app_data(),
                        standard_user.local_app_data(),
                    )
                } else {
                    crate::snapshot_fixed_notepad_files()
                })
            })
        })
        .transpose()?;
    let document_exercise = if scenario.requires_application_exercise() {
        Some(stages.run(GuestMsiStage::PrepareDocument, || {
            prepare_fixed_document_exercise(scenario, standard_user.as_ref())
        })?)
    } else {
        None
    };
    let launch_arguments = document_exercise
        .as_ref()
        .map(|plan| vec![plan.document_path.clone()])
        .unwrap_or_default();
    let application = stages.run(GuestMsiStage::Launch, || {
        if let Some(standard_user) = &standard_user {
            GuestProcess::start_standard_user(
                &scenario.launch_path,
                &launch_arguments,
                standard_user,
            )
        } else {
            GuestProcess::start(&scenario.launch_path, &launch_arguments)
        }
    })?;
    let launch_process_id = application.process_id;
    let pre_close = (|| {
        let (window, application_token, editor) =
            stages.run(GuestMsiStage::OpenDocument, || {
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
                let application_token = collect_process_token(application.process.as_handle())
                    .map_err(|error| {
                        GuestMsiExecutionError::Process(format!(
                            "collect launched application token failed: {error}"
                        ))
                    })?;
                if application_token.process_id != application.process_id {
                    return Err(GuestMsiExecutionError::Process(
                        "collected application token changed process identity".to_owned(),
                    ));
                }
                let editor = document_exercise
                    .as_ref()
                    .map(|_| {
                        wait_for_ready_document_editor(
                            window,
                            application.process_id,
                            EDITOR_LOOKUP_TIMEOUT,
                        )
                    })
                    .transpose()?;
                Ok((window, application_token, editor))
            })?;
        let functional_exercise = document_exercise
            .as_ref()
            .zip(editor)
            .map(|(plan, editor)| {
                stages.run(GuestMsiStage::EditSaveDocument, || {
                    edit_save_fixed_document(window, application.process_id, editor, plan)
                })
            })
            .transpose()?;
        Ok((window, application_token, functional_exercise))
    })();
    let (window, application_token, functional_exercise) = match pre_close {
        Ok(value) => value,
        Err(error) => {
            return match complete_process_operation::<()>(Err(error), application.cleanup()) {
                Err(error) => Err(error),
                Ok(()) => unreachable!("failed application operation cannot succeed"),
            };
        }
    };
    stages.begin(GuestMsiStage::Close);
    let operation = (|| {
        require_visible_process_window(window, application.process_id, "Notepad++ main window")?;
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
        if let Some(plan) = &document_exercise {
            plan.document
                .revalidate()
                .map_err(GuestMsiExecutionError::Process)?;
        }
        Ok(exit_code)
    })();
    let cleanup = if operation.is_ok() {
        application.verify_empty_after_success()
    } else {
        application.cleanup()
    };
    let launch_exit_code = stages.finish(complete_process_operation(operation, cleanup))?;
    let filesystem_observations =
        if let Some((before_install, after_install)) = before_install.zip(after_install) {
            Some(GuestMsiFilesystemObservation {
                before_install,
                after_install,
                after_exercise: stages.run(GuestMsiStage::AfterExerciseCapture, || {
                    Ok(if let Some(standard_user) = &standard_user {
                        crate::guest_filesystem::snapshot_fixed_notepad_files_for_user(
                            standard_user.roaming_app_data(),
                            standard_user.local_app_data(),
                        )
                    } else {
                        crate::snapshot_fixed_notepad_files()
                    })
                })?,
            })
        } else {
            None
        };
    Ok(GuestMsiExecutionObservation {
        install_exit_code,
        launch_process_id,
        launch_exit_code,
        application_token,
        functional_exercise,
        filesystem_observations,
        standard_user_context: standard_user.as_ref().map(|value| value.context().clone()),
    })
}

struct ExercisePlan {
    expected_sha256: String,
    document: crate::FixedGuestDocument,
    document_path: String,
}

fn prepare_fixed_document_exercise(
    scenario: &CompiledMsiScenario,
    standard_user: Option<&StandardUserSession>,
) -> Result<ExercisePlan, GuestMsiExecutionError> {
    let exercise = scenario.document_exercise.as_ref().ok_or_else(|| {
        GuestMsiExecutionError::Scenario(
            "current fixed scenario did not bind its document exercise".to_owned(),
        )
    })?;
    let expected_path = if scenario.requires_standard_user() {
        aiw_provider_wsb::STANDARD_USER_DOCUMENT_EXERCISE_PATH
    } else {
        DOCUMENT_EXERCISE_PATH
    };
    let expected_sha256 = validate_fixed_document_contract(exercise, expected_path)?;
    let document = if let Some(standard_user) = standard_user {
        standard_user.impersonate(|| {
            crate::FixedGuestDocument::prepare_at(standard_user.document_root())
                .map_err(GuestMsiExecutionError::Process)
        })?
    } else {
        crate::FixedGuestDocument::prepare().map_err(GuestMsiExecutionError::Process)?
    };
    Ok(ExercisePlan {
        expected_sha256,
        document,
        document_path: expected_path.to_owned(),
    })
}

fn edit_save_fixed_document(
    main_window: HWND,
    process_id: u32,
    editor: HWND,
    plan: &ExercisePlan,
) -> Result<FunctionalExercise, GuestMsiExecutionError> {
    // HWNDs are reusable. Check both handles immediately before the input
    // sequence, rather than relying on the observations used for readiness.
    require_visible_process_window(main_window, process_id, "Notepad++ main window")?;
    require_visible_process_window(editor, process_id, "Notepad++ Scintilla editor")?;

    // WM_COMMAND and WM_CHAR are system messages below WM_USER. Windows
    // marshals their parameters across processes; no Scintilla custom message
    // or caller pointer is sent into the application process.
    send_window_message(
        main_window,
        process_id,
        WM_COMMAND,
        WPARAM(usize::from(NOTEPAD_PLUS_PLUS_SELECT_ALL_COMMAND)),
        LPARAM(0),
        COMMAND_TIMEOUT,
    )?;
    // Scintilla suppresses control WM_CHAR messages after a consumed keydown.
    // Type the printable fixed body, then exercise Enter through its normal
    // key path; the exact editor and saved CRLF bytes are still verified.
    let body = DOCUMENT_EXPECTED_TEXT.strip_suffix("\r\n").ok_or_else(|| {
        GuestMsiExecutionError::Scenario("fixed text must end in CRLF".to_owned())
    })?;
    let replacement: Vec<u16> = body.encode_utf16().collect();
    if replacement.is_empty() || replacement.len() > MAX_EXERCISE_TEXT_CODE_UNITS {
        return Err(GuestMsiExecutionError::Process(
            "fixed replacement text exceeded its bound".to_owned(),
        ));
    }
    for character in replacement {
        send_window_message(
            editor,
            process_id,
            WM_CHAR,
            WPARAM(usize::from(character)),
            LPARAM(0),
            CHARACTER_TIMEOUT,
        )?;
    }
    // VK_RETURN, scan code 0x1c, repeat count one; key-up sets the previous
    // and transition state bits. No global keyboard state is synthesized.
    send_window_message(
        editor,
        process_id,
        WM_KEYDOWN,
        WPARAM(0x0d),
        LPARAM(0x001c0001),
        COMMAND_TIMEOUT,
    )?;
    send_window_message(
        editor,
        process_id,
        WM_KEYUP,
        WPARAM(0x0d),
        LPARAM(0xc01c0001),
        COMMAND_TIMEOUT,
    )?;
    let edited = read_window_text(editor, process_id, COMMAND_TIMEOUT)?;
    if edited != DOCUMENT_EXPECTED_TEXT {
        return Err(GuestMsiExecutionError::Process(format!(
            "fixed editor content mismatch after input: observed {}; expected {}",
            text_shape(&edited),
            text_shape(DOCUMENT_EXPECTED_TEXT),
        )));
    }
    send_window_message(
        main_window,
        process_id,
        WM_COMMAND,
        WPARAM(usize::from(NOTEPAD_PLUS_PLUS_SAVE_COMMAND)),
        LPARAM(0),
        COMMAND_TIMEOUT,
    )?;
    let observed_sha256 = wait_for_document_sha256(plan, DOCUMENT_SAVE_TIMEOUT)?;
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
        let title = match read_window_text(parent, process_id, remaining.min(COMMAND_TIMEOUT)) {
            Ok(title) => title,
            Err(error) => {
                retry_readiness_error(error, deadline)?;
                continue;
            }
        };
        if title.to_ascii_lowercase().contains("document.txt") {
            let editor = match find_scintilla_child_window(parent, process_id) {
                Ok(editor) => editor,
                Err(error) => {
                    retry_readiness_error(error, deadline)?;
                    continue;
                }
            };
            if let Some(editor) = editor {
                require_visible_process_window(editor, process_id, "Notepad++ Scintilla editor")?;
                let initial_text = match read_window_text(
                    editor,
                    process_id,
                    remaining_timeout(deadline)?.min(COMMAND_TIMEOUT),
                ) {
                    Ok(initial_text) => initial_text,
                    Err(error) => {
                        retry_readiness_error(error, deadline)?;
                        continue;
                    }
                };
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
        return Err(GuestMsiExecutionError::WindowIdentity(format!(
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

fn retry_readiness_error(
    error: GuestMsiExecutionError,
    deadline: Instant,
) -> Result<(), GuestMsiExecutionError> {
    if matches!(error, GuestMsiExecutionError::WindowIdentity(_)) || Instant::now() >= deadline {
        return Err(error);
    }
    thread::sleep(Duration::from_millis(25));
    Ok(())
}

fn read_window_text(
    window: HWND,
    process_id: u32,
    timeout: Duration,
) -> Result<String, GuestMsiExecutionError> {
    let mut text = vec![0u16; MAX_EXERCISE_TEXT_CODE_UNITS + 1];
    // WM_GETTEXT is a system message. Its bounded caller buffer is marshaled
    // by Windows for this cross-process send.
    send_window_message(
        window,
        process_id,
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
    process_id: u32,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    timeout: Duration,
) -> Result<(), GuestMsiExecutionError> {
    // Validate immediately before every cross-process message; a destroyed
    // HWND could otherwise be reused by a different process between polling
    // and input.
    require_visible_process_window(window, process_id, "window message target")?;
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
        return Err(GuestMsiExecutionError::Process(format!(
            "bounded {} did not complete: WIN32_ERROR(0x00000000; ERROR_SUCCESS)",
            window_message_phase(message, wparam)
        )));
    }
    let code = error.0;
    let name = if code == 1460 {
        "ERROR_TIMEOUT"
    } else {
        "WIN32_ERROR"
    };
    Err(GuestMsiExecutionError::Process(format!(
        "bounded {} failed: WIN32_ERROR(0x{code:08X}; {name})",
        window_message_phase(message, wparam),
    )))
}

fn window_message_phase(message: u32, wparam: WPARAM) -> &'static str {
    match message {
        WM_GETTEXT => "WM_GETTEXT",
        WM_CHAR => "WM_CHAR",
        WM_KEYDOWN => "WM_KEYDOWN/Enter",
        WM_KEYUP => "WM_KEYUP/Enter",
        WM_COMMAND if wparam.0 == usize::from(NOTEPAD_PLUS_PLUS_SAVE_COMMAND) => "WM_COMMAND/Save",
        WM_COMMAND if wparam.0 == usize::from(NOTEPAD_PLUS_PLUS_SELECT_ALL_COMMAND) => {
            "WM_COMMAND/SelectAll"
        }
        WM_COMMAND => "WM_COMMAND",
        _ => "window message",
    }
}

fn wait_for_document_sha256(
    plan: &ExercisePlan,
    timeout: Duration,
) -> Result<String, GuestMsiExecutionError> {
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        GuestMsiExecutionError::Process(
            "document save timeout overflowed monotonic clock".to_owned(),
        )
    })?;
    loop {
        if let Some(observed_sha256) = plan
            .document
            .observe_expected()
            .map_err(GuestMsiExecutionError::Process)?
        {
            if observed_sha256 == plan.expected_sha256 {
                return Ok(observed_sha256);
            }
        }
        if Instant::now() >= deadline {
            return Err(GuestMsiExecutionError::Process(format!(
                "fixed document did not save the expected bytes before timeout: {}",
                plan.document
                    .describe_observed()
                    .unwrap_or_else(|e| format!("unavailable: {e}"))
            )));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn text_shape(text: &str) -> String {
    format!(
        "bytes={}, sha256={}, CR={}, LF={}",
        text.len(),
        sha256(text.as_bytes()),
        text.bytes().filter(|b| *b == b'\r').count(),
        text.bytes().filter(|b| *b == b'\n').count()
    )
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_fixed_document_contract(
    exercise: &FixedDocumentExercise,
    expected_path: &str,
) -> Result<String, GuestMsiExecutionError> {
    let initial_sha256 = sha256(DOCUMENT_INITIAL_TEXT.as_bytes());
    let expected_sha256 = sha256(DOCUMENT_EXPECTED_TEXT.as_bytes());
    if exercise.document_path != expected_path
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
    fn start_standard_user(
        path: &str,
        arguments: &[String],
        standard_user: &StandardUserSession,
    ) -> Result<Self, GuestMsiExecutionError> {
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
        // SAFETY: the token, explicit user environment, fixed executable and
        // writable command line remain valid for this call.  A null desktop
        // requests the inherited guest desktop, whose target-user ACE is added
        // by CreateProcessWithTokenW.
        if unsafe {
            CreateProcessWithTokenW(
                standard_user.token(),
                0,
                PCWSTR(executable_wide.as_ptr()),
                PWSTR(command_line_wide.as_mut_ptr()),
                (CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT).0,
                standard_user.environment(),
                PCWSTR(parent_wide.as_ptr()),
                &startup,
                &mut information,
            )
        }
        .0 == 0
        {
            return Err(GuestMsiExecutionError::Process(format!(
                "CreateProcessWithTokenW failed: {}",
                windows::core::Error::from_thread()
            )));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };
        let thread = unsafe { OwnedHandle::from_raw_handle(information.hThread.0) };
        if let Err(error) = standard_user.validate_suspended_child(process.as_handle()) {
            let cleanup = terminate_unassigned_process(&process);
            return Err(GuestMsiExecutionError::Process(format!(
                "standard-user child token validation failed: {error}; cleanup={cleanup:?}"
            )));
        }
        if let Err(error) = unsafe { AssignProcessToJobObject(job.raw(), raw_handle(&process)) } {
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
            validate_fixed_document_contract(&exercise, DOCUMENT_EXERCISE_PATH)
                .expect("fixed exercise must validate"),
            sha256(DOCUMENT_EXPECTED_TEXT.as_bytes())
        );

        let mut altered = exercise;
        altered.document_path = r"C:\AIW\Scenario\other.txt".to_owned();
        assert!(validate_fixed_document_contract(&altered, DOCUMENT_EXERCISE_PATH).is_err());
    }

    #[test]
    fn stage_recorder_keeps_a_passed_prefix_and_one_failed_stage() {
        let mut stages = StageRecorder::for_scenario(true);
        stages
            .run(GuestMsiStage::BeforeInstallCapture, || Ok(()))
            .expect("capture stage must pass");
        stages
            .run(GuestMsiStage::Install, || Ok(()))
            .expect("install stage must pass");
        let error = stages
            .run(GuestMsiStage::AfterInstallCapture, || {
                Err::<(), _>(GuestMsiExecutionError::Process("capture failed".to_owned()))
            })
            .expect_err("capture failure must be retained");
        assert!(matches!(error, GuestMsiExecutionError::Process(_)));
        assert_eq!(
            stages.stages,
            vec![
                (
                    GuestMsiStage::BeforeInstallCapture,
                    GuestMsiStageStatus::Passed
                ),
                (GuestMsiStage::Install, GuestMsiStageStatus::Passed),
                (
                    GuestMsiStage::AfterInstallCapture,
                    GuestMsiStageStatus::Failed
                ),
                (
                    GuestMsiStage::PrepareDocument,
                    GuestMsiStageStatus::NotReached
                ),
                (GuestMsiStage::Launch, GuestMsiStageStatus::NotReached),
                (GuestMsiStage::OpenDocument, GuestMsiStageStatus::NotReached),
                (
                    GuestMsiStage::EditSaveDocument,
                    GuestMsiStageStatus::NotReached
                ),
                (GuestMsiStage::Close, GuestMsiStageStatus::NotReached),
                (
                    GuestMsiStage::AfterExerciseCapture,
                    GuestMsiStageStatus::NotReached
                ),
            ]
        );
    }

    #[test]
    fn legacy_stage_recorder_makes_no_claims() {
        let mut stages = StageRecorder::for_scenario(false);
        stages
            .run(GuestMsiStage::Install, || Ok(()))
            .expect("legacy operation must remain usable");
        assert!(stages.stages.is_empty());
    }
}
