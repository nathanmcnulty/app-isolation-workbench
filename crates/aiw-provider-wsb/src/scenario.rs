//! Typed, non-executing scenario compilation for approved Windows Sandbox runs.
//!
//! This module intentionally recognizes one reviewed application profile.  It
//! is not a command-line or scenario-step interpreter: all executable paths,
//! installer arguments, and observation targets are selected by the profile.
//! The requested process-wait timeout is preserved within a fixed bound and
//! included in the canonical hash; install and close deadlines are fixed.

use aiw_evidence::canonical_json_bytes;
use aiw_schema::{
    ApplicationArchitecture, ApplicationSource, NetworkIntent, Project, RuntimeBoundary,
    ScenarioStep,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const COMPILED_MSI_SCENARIO_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha11";
pub const NOTEPAD_PLUS_PLUS_MSI_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha7";
pub(crate) const LEGACY_COMPILED_MSI_SCENARIO_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha6";
pub(crate) const LEGACY_NOTEPAD_PLUS_PLUS_MSI_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha6";
pub const NOTEPAD_PLUS_PLUS_INTERACTIVE_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-interactive/v0alpha1";
pub const NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-interactive-document/v0alpha2";
pub(crate) const LEGACY_INTERACTIVE_DOCUMENT_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-interactive-document/v0alpha1";
pub const COMPILED_MSI_INTERACTIVE_DOCUMENT_SCENARIO_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha12";
pub const INTERACTIVE_MSI_INSTALL_LOG_PATH: &str = r"C:\AIW\interactive-msi-install.log";
pub const COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha10";
pub const NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-local-settings/v0alpha2";
pub(crate) const LEGACY_COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha9";
pub(crate) const LEGACY_NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-local-settings/v0alpha1";

const NOTEPAD_PLUS_PLUS_ENTRYPOINT_ID: &str = "notepad-plus-plus";
const NOTEPAD_PLUS_PLUS_ENTRYPOINT_PATH: &str = "notepad++.exe";
const NOTEPAD_PLUS_PLUS_INSTALLED_PATH: &str = r"C:\Program Files\Notepad++\notepad++.exe";
const NOTEPAD_PLUS_PLUS_PROCESS_IMAGE: &str = "notepad++.exe";
pub const NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_DIRECTORY: &str =
    r"C:\Users\AiwStandardUser\AppData\Local\Notepad++";
pub const NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT: &str =
    "-settingsDir=C:\\Users\\AiwStandardUser\\AppData\\Local\\Notepad++";
const STAGED_INSTALLER_PATH: &str = r"C:\AIW\Tools\application.msi";
pub const INTERACTIVE_DOCUMENT_INPUT_PATH: &str = r"C:\AIW\Tools\document-input.txt";
pub const INTERACTIVE_DOCUMENT_OUTPUT_PATH: &str = r"C:\AIW\Output\document-output.txt";
pub const MAX_INTERACTIVE_DOCUMENT_BYTES: u64 = 1024 * 1024;
const INSTALL_TIMEOUT_SECONDS: u32 = 120;
const CURRENT_INSTALL_TIMEOUT_SECONDS: u32 = 300;
const MAX_PROCESS_WAIT_TIMEOUT_SECONDS: u32 = 60;
const GRACEFUL_CLOSE_TIMEOUT_SECONDS: u32 = 15;

/// A fully resolved, non-executable description of the one supported MSI
/// scenario.  Public fields are validated before use or hashing so callers
/// cannot turn this value into a command surface by constructing it directly.
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledMsiScenario {
    pub schema_version: String,
    pub profile: String,
    pub scenario_id: String,
    pub application_sha256: String,
    pub installer_path: String,
    pub install_arguments: Vec<String>,
    pub install_timeout_seconds: u32,
    pub launch_path: String,
    pub launch_arguments: Vec<String>,
    pub process_image: String,
    pub process_wait_timeout_seconds: u32,
    pub graceful_close_timeout_seconds: u32,
    pub expected_exit_code: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_exercise: Option<FixedDocumentExercise>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interactive_session_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interactive_document: Option<InteractiveDocumentTransfer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_entry_point: Option<crate::MsiReviewedEntryPoint>,
}

/// The only caller supplied value admitted by the interactive transfer
/// profile.  The guest and output paths remain fixed profile constants.
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InteractiveDocumentTransfer {
    pub input_sha256: String,
    pub input_size_bytes: u64,
}

impl InteractiveDocumentTransfer {
    pub fn validate(&self) -> Result<(), ScenarioCompileError> {
        if !lower_hex_sha256(&self.input_sha256)
            || self.input_size_bytes > MAX_INTERACTIVE_DOCUMENT_BYTES
        {
            return Err(ScenarioCompileError::InvalidCompiledProfile);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixedDocumentExercise {
    pub document_path: String,
    pub initial_sha256: String,
    pub expected_sha256: String,
}

impl FixedDocumentExercise {
    fn fixed_for(path: &str) -> Self {
        Self {
            document_path: path.to_owned(),
            initial_sha256: hex::encode(Sha256::digest(crate::DOCUMENT_INITIAL_TEXT.as_bytes())),
            expected_sha256: hex::encode(Sha256::digest(crate::DOCUMENT_EXPECTED_TEXT.as_bytes())),
        }
    }

    fn legacy() -> Self {
        Self::fixed_for(crate::DOCUMENT_EXERCISE_PATH)
    }
    fn standard_user() -> Self {
        Self::fixed_for(crate::STANDARD_USER_DOCUMENT_EXERCISE_PATH)
    }
}

/// Application-neutral install-only contract. The readonly staging mapping is
/// the source; Windows Installer uses a worker-local copy held by the agent.
pub const GENERIC_MSI_INSTALL_PROFILE: &str =
    "aiw.dev/windows-sandbox/msi-install-discovery/v0alpha1";
const GENERIC_MSI_SCENARIO_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha12";
const REVIEWED_MSI_LAUNCH_PROFILE: &str = "aiw.dev/windows-sandbox/msi-reviewed-launch/v0alpha1";
const REVIEWED_MSI_SCENARIO_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha13";
const REVIEWED_MSI_OPERATOR_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha14";
const MSI_PROGRAM_FILES: &str = r"C:\Program Files";
pub const GENERIC_MSI_LOCAL_ROOT: &str = r"C:\AIW\InstallerStage";
pub const GENERIC_MSI_LOCAL_PACKAGE: &str = r"C:\AIW\InstallerStage\application.msi";
pub const GENERIC_MSI_LOCAL_LOG: &str = r"C:\AIW\InstallerStage\install.log";

fn generic_install_arguments(buffered: bool) -> Vec<String> {
    [
        "/i",
        GENERIC_MSI_LOCAL_PACKAGE,
        "/qn",
        "/norestart",
        "ALLUSERS=1",
        if buffered {
            crate::msi_diagnostics::MSI_INSTALL_BUFFERED_LOG_ARGUMENT
        } else {
            crate::msi_diagnostics::MSI_INSTALL_LOG_ARGUMENT
        },
        GENERIC_MSI_LOCAL_LOG,
    ]
    .map(str::to_owned)
    .to_vec()
}

/// Compile an install-only scenario without selecting a discovered executable.
pub fn compile_generic_msi_install(
    project: &Project,
    scenario_id: &str,
    timeout_seconds: u32,
    buffered: bool,
) -> Result<CompiledMsiScenario, ScenarioCompileError> {
    let operation = generic_msi_operation(project, scenario_id, timeout_seconds, buffered)?;
    if !project
        .scenarios
        .iter()
        .any(|scenario| scenario.id == scenario_id && scenario.steps == [ScenarioStep::Install])
    {
        return Err(ScenarioCompileError::UnsupportedScenario);
    }
    operation.validate()?;
    Ok(operation)
}

/// Compile the explicit app-neutral sequence. No arbitrary executable path
/// or command line is carried into the plan. The runner must reverify the
/// source run before supplying this selection; compilation itself has no
/// execution authority.
pub fn compile_reviewed_msi_launch(
    project: &Project,
    scenario_id: &str,
    run_id: &str,
    reviewed: &crate::MsiReviewedEntryPoint,
) -> Result<CompiledMsiScenario, ScenarioCompileError> {
    let mut operation = generic_msi_operation(project, scenario_id, 300, true)?;
    let ApplicationSource::Msi(application) = &project.application else {
        return Err(ScenarioCompileError::UnsupportedApplicationSource);
    };
    reviewed
        .validate_for_fresh_run(run_id, &operation.application_sha256)
        .map_err(|_| ScenarioCompileError::InvalidCompiledProfile)?;
    let path = &reviewed.candidate.relative_path;
    let leaf = path.rsplit('\\').next().unwrap_or_default();
    let scenario = project
        .scenarios
        .iter()
        .find(|scenario| scenario.id == scenario_id)
        .ok_or(ScenarioCompileError::UnsupportedScenario)?;
    let [
        ScenarioStep::Install,
        ScenarioStep::Launch {
            entrypoint,
            arguments,
        },
        ScenarioStep::WaitForProcess {
            image,
            timeout_seconds,
        },
        close_step,
        ScenarioStep::ExpectExitCode { value: 0 },
    ] = scenario.steps.as_slice()
    else {
        return Err(ScenarioCompileError::UnsupportedScenario);
    };
    if !arguments.is_empty()
        || image != leaf
        || !application.entry_points.iter().any(|entry| {
            &entry.id == entrypoint && &entry.path == path && entry.arguments.is_empty()
        })
    {
        return Err(ScenarioCompileError::UnsupportedScenario);
    }
    let (schema_version, graceful_close, operator_seconds) = match close_step {
        ScenarioStep::GracefulClose => (
            REVIEWED_MSI_SCENARIO_VERSION,
            GRACEFUL_CLOSE_TIMEOUT_SECONDS,
            None,
        ),
        ScenarioStep::WaitForUserClose { timeout_seconds } => {
            (REVIEWED_MSI_OPERATOR_VERSION, 0, Some(*timeout_seconds))
        }
        _ => return Err(ScenarioCompileError::UnsupportedScenario),
    };
    operation.schema_version = schema_version.into();
    operation.profile = REVIEWED_MSI_LAUNCH_PROFILE.into();
    operation.launch_path = format!(r"{MSI_PROGRAM_FILES}\{path}");
    operation.process_image = leaf.into();
    operation.process_wait_timeout_seconds = *timeout_seconds;
    operation.graceful_close_timeout_seconds = graceful_close;
    operation.interactive_session_seconds = operator_seconds;
    operation.reviewed_entry_point = Some(reviewed.clone());
    operation.validate()?;
    Ok(operation)
}

fn generic_msi_operation(
    project: &Project,
    scenario_id: &str,
    timeout_seconds: u32,
    buffered: bool,
) -> Result<CompiledMsiScenario, ScenarioCompileError> {
    if !aiw_schema::validate_project_for_planning(project).is_empty() {
        return Err(ScenarioCompileError::InvalidProject);
    }
    require_project_semantics(project)?;
    if !project.extensions.is_empty()
        || project.analyst.is_some()
        || project
            .candidates
            .iter()
            .any(|entry| !entry.extensions.is_empty())
    {
        return Err(ScenarioCompileError::UnsupportedProjectSemantics);
    }
    let ApplicationSource::Msi(application) = &project.application else {
        return Err(ScenarioCompileError::UnsupportedApplicationSource);
    };
    if application.architecture != ApplicationArchitecture::X64
        || application.may_reboot
        || !application.silent_arguments.is_empty()
        || application.update_uninstall.is_some()
        || application.expected_signer.is_some()
    {
        return Err(ScenarioCompileError::UnsupportedInstallerSemantics);
    }
    Ok(CompiledMsiScenario {
        schema_version: GENERIC_MSI_SCENARIO_VERSION.into(),
        profile: GENERIC_MSI_INSTALL_PROFILE.into(),
        scenario_id: scenario_id.into(),
        application_sha256: application.sha256.clone(),
        installer_path: STAGED_INSTALLER_PATH.into(),
        install_arguments: generic_install_arguments(buffered),
        install_timeout_seconds: timeout_seconds,
        launch_path: String::new(),
        launch_arguments: Vec::new(),
        process_image: String::new(),
        process_wait_timeout_seconds: 0,
        graceful_close_timeout_seconds: 0,
        expected_exit_code: 0,
        document_exercise: None,
        interactive_session_seconds: None,
        interactive_document: None,
        reviewed_entry_point: None,
    })
}

impl CompiledMsiScenario {
    pub fn is_generic_install_only(&self) -> bool {
        self.profile == GENERIC_MSI_INSTALL_PROFILE
    }

    pub fn uses_generic_installer(&self) -> bool {
        self.is_generic_install_only() || self.is_reviewed_launch()
    }

    pub fn is_reviewed_launch(&self) -> bool {
        self.profile == REVIEWED_MSI_LAUNCH_PROFILE
    }

    pub fn is_reviewed_operator_session(&self) -> bool {
        self.is_reviewed_launch() && self.schema_version == REVIEWED_MSI_OPERATOR_VERSION
    }

    fn validate_reviewed_launch(&self) -> Result<(), ScenarioCompileError> {
        let reviewed = self
            .reviewed_entry_point
            .as_ref()
            .ok_or(ScenarioCompileError::InvalidCompiledProfile)?;
        reviewed
            .validate_for_installer(&self.application_sha256)
            .map_err(|_| ScenarioCompileError::InvalidCompiledProfile)?;
        let path = &reviewed.candidate.relative_path;
        let valid_close = if self.is_reviewed_operator_session() {
            self.graceful_close_timeout_seconds == 0
                && self
                    .interactive_session_seconds
                    .is_some_and(|seconds| (30..=600).contains(&seconds))
        } else {
            self.schema_version == REVIEWED_MSI_SCENARIO_VERSION
                && self.graceful_close_timeout_seconds == GRACEFUL_CLOSE_TIMEOUT_SECONDS
                && self.interactive_session_seconds.is_none()
        };
        if !valid_close
            || !valid_id(&self.scenario_id)
            || self.installer_path != STAGED_INSTALLER_PATH
            || self.install_arguments != generic_install_arguments(true)
            || self.install_timeout_seconds != 300
            || self.launch_path != format!(r"{MSI_PROGRAM_FILES}\{path}")
            || !self.launch_arguments.is_empty()
            || self.process_image != path.rsplit('\\').next().unwrap_or_default()
            || !(1..=MAX_PROCESS_WAIT_TIMEOUT_SECONDS).contains(&self.process_wait_timeout_seconds)
            || self.expected_exit_code != 0
            || self.document_exercise.is_some()
            || self.interactive_document.is_some()
        {
            return Err(ScenarioCompileError::InvalidCompiledProfile);
        }
        Ok(())
    }

    fn validate_generic_install(&self) -> Result<(), ScenarioCompileError> {
        if self.schema_version != GENERIC_MSI_SCENARIO_VERSION
            || !valid_id(&self.scenario_id)
            || !lower_hex_sha256(&self.application_sha256)
            || self.installer_path != STAGED_INSTALLER_PATH
            || (self.install_arguments != generic_install_arguments(true)
                && self.install_arguments != generic_install_arguments(false))
            || !(1..=300).contains(&self.install_timeout_seconds)
            || !self.launch_path.is_empty()
            || !self.launch_arguments.is_empty()
            || !self.process_image.is_empty()
            || self.process_wait_timeout_seconds != 0
            || self.graceful_close_timeout_seconds != 0
            || self.expected_exit_code != 0
            || self.document_exercise.is_some()
            || self.interactive_session_seconds.is_some()
            || self.interactive_document.is_some()
        {
            return Err(ScenarioCompileError::InvalidCompiledProfile);
        }
        Ok(())
    }
    /// Validates the fixed profile constants and the copied source binding.
    pub fn validate(&self) -> Result<(), ScenarioCompileError> {
        if self.is_generic_install_only() {
            if self.reviewed_entry_point.is_some() {
                return Err(ScenarioCompileError::InvalidCompiledProfile);
            }
            return self.validate_generic_install();
        }
        if self.is_reviewed_launch() {
            return self.validate_reviewed_launch();
        }
        if self.reviewed_entry_point.is_some() {
            return Err(ScenarioCompileError::InvalidCompiledProfile);
        }
        let current = self.schema_version == COMPILED_MSI_SCENARIO_SCHEMA_VERSION
            && self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE;
        let legacy_current = self.schema_version == LEGACY_COMPILED_MSI_SCENARIO_SCHEMA_VERSION
            && self.profile == LEGACY_NOTEPAD_PLUS_PLUS_MSI_PROFILE;
        let local_settings = self.schema_version
            == COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION
            && self.profile == NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE;
        let legacy_local_settings = self.schema_version
            == LEGACY_COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION
            && self.profile == LEGACY_NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE;
        let interactive = self.schema_version
            == "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha7"
            && self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_PROFILE;
        let current_interactive_document = self.schema_version
            == COMPILED_MSI_INTERACTIVE_DOCUMENT_SCENARIO_SCHEMA_VERSION
            && self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE;
        let legacy_interactive_document = self.schema_version
            == "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha8"
            && self.profile == LEGACY_INTERACTIVE_DOCUMENT_PROFILE;
        let interactive_document = current_interactive_document || legacy_interactive_document;
        let mut install_arguments = vec![
            "/i".to_owned(),
            STAGED_INSTALLER_PATH.to_owned(),
            "/qn".to_owned(),
            "/norestart".to_owned(),
        ];
        if current_interactive_document {
            install_arguments.extend([
                "/L*V".to_owned(),
                INTERACTIVE_MSI_INSTALL_LOG_PATH.to_owned(),
            ]);
        }
        let registry_profile = self.schema_version
            == "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha5"
            && self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha5";
        let token_profile = self.schema_version
            == "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha2"
            && self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha2";
        let legacy_exercise = self.schema_version
            == "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha3"
            && self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha3";
        let standard_user_legacy = self.schema_version
            == "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha4"
            && self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha4";
        let legacy = self.schema_version
            == "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha1"
            && self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha1";
        if !(current
            || legacy_current
            || local_settings
            || legacy_local_settings
            || interactive
            || interactive_document
            || registry_profile
            || standard_user_legacy
            || legacy_exercise
            || token_profile
            || legacy)
            || (legacy_exercise
                && self.document_exercise.as_ref() != Some(&FixedDocumentExercise::legacy()))
            || ((current
                || legacy_current
                || local_settings
                || legacy_local_settings
                || registry_profile
                || standard_user_legacy)
                && self.document_exercise.as_ref() != Some(&FixedDocumentExercise::standard_user()))
            || (!current
                && !legacy_current
                && !local_settings
                && !legacy_local_settings
                && !registry_profile
                && !standard_user_legacy
                && !legacy_exercise
                && self.document_exercise.is_some())
            || ((interactive || interactive_document) && self.document_exercise.is_some())
            || !valid_id(&self.scenario_id)
            || ((interactive || interactive_document)
                && !self
                    .interactive_session_seconds
                    .is_some_and(|seconds| (30..=600).contains(&seconds)))
            || (!interactive && !interactive_document && self.interactive_session_seconds.is_some())
            || (interactive_document
                && self
                    .interactive_document
                    .as_ref()
                    .is_none_or(|value| value.validate().is_err()))
            || (!interactive_document && self.interactive_document.is_some())
            || !lower_hex_sha256(&self.application_sha256)
            || self.installer_path != STAGED_INSTALLER_PATH
            || self.install_arguments != install_arguments
            || self.install_timeout_seconds
                != if current || local_settings || current_interactive_document {
                    CURRENT_INSTALL_TIMEOUT_SECONDS
                } else {
                    INSTALL_TIMEOUT_SECONDS
                }
            || self.launch_path != NOTEPAD_PLUS_PLUS_INSTALLED_PATH
            || if local_settings || legacy_local_settings {
                !has_local_settings_argument(&self.launch_arguments)
            } else {
                !self.launch_arguments.is_empty()
            }
            || self.process_image != NOTEPAD_PLUS_PLUS_PROCESS_IMAGE
            || self.process_wait_timeout_seconds == 0
            || self.process_wait_timeout_seconds > MAX_PROCESS_WAIT_TIMEOUT_SECONDS
            || self.graceful_close_timeout_seconds != GRACEFUL_CLOSE_TIMEOUT_SECONDS
            || self.expected_exit_code != 0
        {
            return Err(ScenarioCompileError::InvalidCompiledProfile);
        }
        Ok(())
    }

    /// The versioned profile is part of the approved scenario hash.
    pub fn requires_application_token(&self) -> bool {
        self.is_reviewed_launch()
            || self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_PROFILE
            || self.requires_document_transfer()
            || self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.profile == LEGACY_NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.is_local_settings_profile()
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha5"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha3"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha4"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha2"
    }

    pub fn requires_application_exercise(&self) -> bool {
        self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.profile == LEGACY_NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.is_local_settings_profile()
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha5"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha3"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha4"
    }

    pub fn requires_standard_user(&self) -> bool {
        self.is_reviewed_operator_session()
            || self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_PROFILE
            || self.requires_document_transfer()
            || self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.profile == LEGACY_NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.is_local_settings_profile()
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha5"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha4"
    }

    pub fn requires_registry_observations(&self) -> bool {
        self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.profile == LEGACY_NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.is_local_settings_profile()
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha5"
    }

    pub fn requires_product_registration(&self) -> bool {
        self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.profile == LEGACY_NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.is_local_settings_profile()
    }

    pub fn requires_document_transfer(&self) -> bool {
        self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE
            || self.profile == LEGACY_INTERACTIVE_DOCUMENT_PROFILE
    }

    pub fn requires_local_settings(&self) -> bool {
        self.is_local_settings_profile()
    }

    fn is_local_settings_profile(&self) -> bool {
        self.profile == NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE
            || self.profile == LEGACY_NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE
    }

    /// The exact application argument array the fixed guest supplies after it
    /// has prepared its profile-bound document, if any.
    pub fn effective_launch_arguments(&self) -> Vec<String> {
        let mut arguments = self.launch_arguments.clone();
        if self.interactive_document.is_some() {
            arguments.push(crate::STANDARD_USER_DOCUMENT_EXERCISE_PATH.to_owned());
        } else if let Some(exercise) = &self.document_exercise {
            arguments.push(exercise.document_path.clone());
        }
        arguments
    }

    /// Returns the canonical digest used by later plan/approval layers.
    pub fn canonical_sha256(&self) -> Result<String, ScenarioCompileError> {
        self.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|error| ScenarioCompileError::Canonicalization(error.to_string()))?;
        let bytes = canonical_json_bytes(&value)
            .map_err(|error| ScenarioCompileError::Canonicalization(error.to_string()))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScenarioCompileError {
    #[error("project is invalid or awaits migration review")]
    InvalidProject,
    #[error("only MSI application sources are supported by this Windows Sandbox scenario profile")]
    UnsupportedApplicationSource,
    #[error(
        "the imported MSI profile does not accept caller-supplied silent arguments or reboot semantics"
    )]
    UnsupportedInstallerSemantics,
    #[error(
        "the project requests unsupported secrets, host resources, network access, or runtime boundary"
    )]
    UnsupportedProjectSemantics,
    #[error("the requested scenario does not exist or is not the exact Notepad++ MSI sequence")]
    UnsupportedScenario,
    #[error("compiled MSI scenario does not match the fixed profile")]
    InvalidCompiledProfile,
    #[error("compiled MSI scenario could not be canonicalized: {0}")]
    Canonicalization(String),
}

/// Recompile the exact scenario for preparation, approval and Start.
pub fn compile_imported_msi_scenario(
    project: &Project,
    scenario_id: &str,
) -> Result<CompiledMsiScenario, ScenarioCompileError> {
    if project
        .scenarios
        .iter()
        .any(|scenario| scenario.id == scenario_id && scenario.steps == [ScenarioStep::Install])
    {
        compile_generic_msi_install(project, scenario_id, 300, true)
    } else {
        compile_notepad_plus_plus_msi_scenario(project, scenario_id)
    }
}

/// Compiles exactly `Install -> Launch -> WaitForProcess -> GracefulClose ->
/// ExpectExitCode(0)` for one imported Notepad++ MSI.  It performs no file,
/// process, provider, or host mutation.
pub fn compile_notepad_plus_plus_msi_scenario(
    project: &Project,
    scenario_id: &str,
) -> Result<CompiledMsiScenario, ScenarioCompileError> {
    if !aiw_schema::validate_project_for_planning(project).is_empty() {
        return Err(ScenarioCompileError::InvalidProject);
    }
    require_project_semantics(project)?;
    let ApplicationSource::Msi(application) = &project.application else {
        return Err(ScenarioCompileError::UnsupportedApplicationSource);
    };
    if !application.silent_arguments.is_empty()
        || application.architecture != ApplicationArchitecture::X64
        || application.may_reboot
        || application
            .update_uninstall
            .as_ref()
            .is_some_and(|value| value.requires_reboot)
        || !lower_hex_sha256(&application.sha256)
        || !application.entry_points.iter().any(|entrypoint| {
            entrypoint.id == NOTEPAD_PLUS_PLUS_ENTRYPOINT_ID
                && entrypoint.path == NOTEPAD_PLUS_PLUS_ENTRYPOINT_PATH
                && entrypoint.arguments.is_empty()
        })
    {
        return Err(ScenarioCompileError::UnsupportedInstallerSemantics);
    }
    let scenario = project
        .scenarios
        .iter()
        .find(|scenario| scenario.id == scenario_id)
        .ok_or(ScenarioCompileError::UnsupportedScenario)?;
    let interactive_seconds = match scenario.steps.as_slice() {
        [
            ScenarioStep::Install,
            ScenarioStep::Launch {
                entrypoint,
                arguments,
            },
            ScenarioStep::WaitForProcess {
                image,
                timeout_seconds,
            },
            ScenarioStep::WaitForUserClose {
                timeout_seconds: lifetime,
            },
            ScenarioStep::ExpectExitCode { value: 0 },
        ] if entrypoint == NOTEPAD_PLUS_PLUS_ENTRYPOINT_ID
            && arguments.is_empty()
            && image == NOTEPAD_PLUS_PLUS_PROCESS_IMAGE
            && (1..=60).contains(timeout_seconds)
            && (30..=600).contains(lifetime) =>
        {
            Some(*lifetime)
        }
        _ => None,
    };
    if !valid_id(scenario_id)
        || (!matches_notepad_plus_plus_sequence(&scenario.steps) && interactive_seconds.is_none())
    {
        return Err(ScenarioCompileError::UnsupportedScenario);
    }
    let ScenarioStep::WaitForProcess {
        timeout_seconds, ..
    } = &scenario.steps[2]
    else {
        return Err(ScenarioCompileError::UnsupportedScenario);
    };
    let mut compiled = CompiledMsiScenario {
        schema_version: COMPILED_MSI_SCENARIO_SCHEMA_VERSION.to_owned(),
        profile: NOTEPAD_PLUS_PLUS_MSI_PROFILE.to_owned(),
        scenario_id: scenario.id.clone(),
        application_sha256: application.sha256.clone(),
        installer_path: STAGED_INSTALLER_PATH.to_owned(),
        install_arguments: vec![
            "/i".to_owned(),
            STAGED_INSTALLER_PATH.to_owned(),
            "/qn".to_owned(),
            "/norestart".to_owned(),
        ],
        install_timeout_seconds: CURRENT_INSTALL_TIMEOUT_SECONDS,
        launch_path: NOTEPAD_PLUS_PLUS_INSTALLED_PATH.to_owned(),
        launch_arguments: match scenario.steps.as_slice() {
            [
                ScenarioStep::Install,
                ScenarioStep::Launch { arguments, .. },
                ScenarioStep::WaitForProcess { .. },
                ScenarioStep::GracefulClose,
                ScenarioStep::ExpectExitCode { value: 0 },
            ] => arguments.clone(),
            _ => Vec::new(),
        },
        process_image: NOTEPAD_PLUS_PLUS_PROCESS_IMAGE.to_owned(),
        process_wait_timeout_seconds: *timeout_seconds,
        graceful_close_timeout_seconds: GRACEFUL_CLOSE_TIMEOUT_SECONDS,
        expected_exit_code: 0,
        document_exercise: Some(FixedDocumentExercise::standard_user()),
        interactive_session_seconds: interactive_seconds,
        interactive_document: None,
        reviewed_entry_point: None,
    };
    if interactive_seconds.is_some() {
        compiled.schema_version = "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha7".into();
        compiled.profile = NOTEPAD_PLUS_PLUS_INTERACTIVE_PROFILE.into();
        compiled.document_exercise = None;
        compiled.install_timeout_seconds = INSTALL_TIMEOUT_SECONDS;
    } else if has_local_settings_argument(&compiled.launch_arguments) {
        compiled.schema_version = COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION.to_owned();
        compiled.profile = NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE.to_owned();
        compiled.install_timeout_seconds = CURRENT_INSTALL_TIMEOUT_SECONDS;
    }
    compiled.validate()?;
    Ok(compiled)
}

/// Compiles the reviewed interactive sequence with one bounded UTF-8 text
/// document copied into the worker and a receipt-bound output artifact.
pub fn compile_notepad_plus_plus_msi_scenario_with_document(
    project: &Project,
    scenario_id: &str,
    input_sha256: &str,
    input_size_bytes: u64,
) -> Result<CompiledMsiScenario, ScenarioCompileError> {
    let mut compiled = compile_notepad_plus_plus_msi_scenario(project, scenario_id)?;
    if compiled.interactive_session_seconds.is_none()
        || !lower_hex_sha256(input_sha256)
        || input_size_bytes > MAX_INTERACTIVE_DOCUMENT_BYTES
    {
        return Err(ScenarioCompileError::UnsupportedScenario);
    }
    compiled.schema_version = COMPILED_MSI_INTERACTIVE_DOCUMENT_SCENARIO_SCHEMA_VERSION.to_owned();
    compiled.profile = NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE.to_owned();
    compiled.install_timeout_seconds = CURRENT_INSTALL_TIMEOUT_SECONDS;
    compiled.install_arguments.extend([
        "/L*V".to_owned(),
        INTERACTIVE_MSI_INSTALL_LOG_PATH.to_owned(),
    ]);
    compiled.interactive_document = Some(InteractiveDocumentTransfer {
        input_sha256: input_sha256.to_owned(),
        input_size_bytes,
    });
    compiled.validate()?;
    Ok(compiled)
}

fn require_project_semantics(project: &Project) -> Result<(), ScenarioCompileError> {
    let intent = &project.isolation_intent;
    if !project.secrets.is_empty()
        || intent.runtime_boundary != RuntimeBoundary::WindowsSandbox
        || intent.network != NetworkIntent::Blocked
        || intent.allow_clipboard
        || intent.allow_host_file_access
        || intent.allow_host_registry_access
    {
        return Err(ScenarioCompileError::UnsupportedProjectSemantics);
    }
    Ok(())
}

fn matches_notepad_plus_plus_sequence(steps: &[ScenarioStep]) -> bool {
    matches!(
        steps,
        [
            ScenarioStep::Install,
            ScenarioStep::Launch { entrypoint, arguments },
            ScenarioStep::WaitForProcess { image, timeout_seconds },
            ScenarioStep::GracefulClose,
            ScenarioStep::ExpectExitCode { value: 0 },
        ] if entrypoint == NOTEPAD_PLUS_PLUS_ENTRYPOINT_ID
            && (arguments.is_empty()
                || has_local_settings_argument(arguments))
            && image == NOTEPAD_PLUS_PLUS_PROCESS_IMAGE
            && *timeout_seconds > 0
            && *timeout_seconds <= MAX_PROCESS_WAIT_TIMEOUT_SECONDS
    )
}

fn lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn has_local_settings_argument(arguments: &[String]) -> bool {
    arguments.len() == 1 && arguments[0] == NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_msi_plan_binds_exact_source_entry_and_closed_steps() {
        let mut project = project();
        let ApplicationSource::Msi(application) = &mut project.application else {
            unreachable!()
        };
        application.entry_points[0].path = r"Vendor\Tool.exe".into();
        let ScenarioStep::WaitForProcess { image, .. } = &mut project.scenarios[0].steps[2] else {
            unreachable!()
        };
        *image = "Tool.exe".into();
        let code = "{A1234567-89AB-CDEF-0123-456789ABCDEF}".to_owned();
        let reviewed = crate::MsiReviewedEntryPoint {
            schema_version: crate::MSI_ENTRY_POINT_SELECTION_VERSION.into(),
            source_run_id: "prior".into(),
            source_receipt_sha256: "b".repeat(64),
            source_evidence_root_hash: "c".repeat(64),
            source_project_revision_sha256: "d".repeat(64),
            installer_sha256: "a".repeat(64),
            product_code: code.clone(),
            candidate: crate::MsiLaunchCandidate {
                component_code: code,
                relative_path: r"Vendor\Tool.exe".into(),
                size_bytes: 1024,
                sha256: "e".repeat(64),
            },
        };
        let op = compile_reviewed_msi_launch(&project, "first-run", "fresh", &reviewed).unwrap();
        assert_eq!(op.launch_path, r"C:\Program Files\Vendor\Tool.exe");
        assert!(op.is_reviewed_launch());
        let bytes = serde_json::to_vec(&op).unwrap();
        assert_eq!(
            serde_json::from_slice::<CompiledMsiScenario>(&bytes).unwrap(),
            op
        );
        let mut operator_project = project.clone();
        operator_project.scenarios[0].steps[3] = ScenarioStep::WaitForUserClose {
            timeout_seconds: 60,
        };
        let operator =
            compile_reviewed_msi_launch(&operator_project, "first-run", "fresh", &reviewed)
                .unwrap();
        assert!(operator.is_reviewed_operator_session());
        assert!(operator.requires_standard_user());
        assert_eq!(operator.reviewed_entry_point, op.reviewed_entry_point);
        assert_eq!(operator.interactive_session_seconds, Some(60));
        assert_eq!(operator.graceful_close_timeout_seconds, 0);
        assert_ne!(
            operator.canonical_sha256().unwrap(),
            op.canonical_sha256().unwrap()
        );
        let mut auto_close_drift = operator.clone();
        auto_close_drift.graceful_close_timeout_seconds = GRACEFUL_CLOSE_TIMEOUT_SECONDS;
        assert!(auto_close_drift.validate().is_err());
        for timeout_seconds in [0, 29, 601] {
            operator_project.scenarios[0].steps[3] =
                ScenarioStep::WaitForUserClose { timeout_seconds };
            assert!(
                compile_reviewed_msi_launch(&operator_project, "first-run", "fresh", &reviewed)
                    .is_err()
            );
        }
        let operator_request = crate::ImportedMsiGuestRequest::new(
            "fresh",
            "00112233-4455-6677-8899-aabbccddeeff",
            "1".repeat(64),
            "2".repeat(64),
            operator,
            "a".repeat(64),
            1024,
            "3".repeat(64),
        )
        .unwrap();
        let mut changed = reviewed.clone();
        changed.source_receipt_sha256 = "f".repeat(64);
        let changed =
            compile_reviewed_msi_launch(&project, "first-run", "fresh", &changed).unwrap();
        assert_ne!(
            op.canonical_sha256().unwrap(),
            changed.canonical_sha256().unwrap()
        );
        assert!(compile_reviewed_msi_launch(&project, "first-run", "prior", &reviewed).is_err());
        let mut tampered = op.clone();
        tampered.launch_path = r"C:\Windows\System32\cmd.exe".into();
        assert!(tampered.validate().is_err());
        let ScenarioStep::Launch { arguments, .. } = &mut project.scenarios[0].steps[1] else {
            unreachable!()
        };
        arguments.push("unreviewed".into());
        assert!(compile_reviewed_msi_launch(&project, "first-run", "fresh", &reviewed).is_err());
        let request = crate::ImportedMsiGuestRequest::new(
            "fresh",
            "00112233-4455-6677-8899-aabbccddeeff",
            "1".repeat(64),
            "2".repeat(64),
            op,
            "a".repeat(64),
            1024,
            "3".repeat(64),
        )
        .unwrap();
        assert_eq!(
            request.schema_version,
            crate::REVIEWED_MSI_LAUNCH_REQUEST_VERSION
        );
        let mut legacy = request.clone();
        legacy.schema_version = crate::IMPORTED_MSI_GUEST_REQUEST_SCHEMA_VERSION.into();
        assert!(legacy.recompute_request_sha256().is_err());
        let mut reused = request.clone();
        reused.run_id = "prior".into();
        assert!(reused.recompute_request_sha256().is_err());
        let mut discovery = crate::MsiInstallDiscovery {
            product_code: reviewed.product_code.clone(),
            before_install: crate::MsiMachineProductState::NotRegistered,
            after_install: crate::MsiMachineProductState::Installed,
            candidates: vec![reviewed.candidate],
            candidate_scan_complete: true,
        };
        let result =
            crate::ImportedMsiScenarioResult::reviewed_launch(&request, discovery.clone(), 42, 0)
                .unwrap();
        assert!(result.successful());
        assert!(result.graceful_close_requested);
        let operator_result = crate::ImportedMsiScenarioResult::reviewed_launch(
            &operator_request,
            discovery.clone(),
            42,
            0,
        )
        .unwrap();
        assert!(operator_result.process_observed && operator_result.process_closed);
        assert!(!operator_result.graceful_close_requested);
        assert!(result.validate_for_request(&operator_request).is_err());
        assert!(operator_result.validate_for_request(&request).is_err());
        let mut unexpected_close = operator_result;
        unexpected_close.graceful_close_requested = true;
        assert!(
            unexpected_close
                .validate_for_request(&operator_request)
                .is_err()
        );
        assert!(crate::ImportedMsiScenarioResult::discovered(&request, discovery.clone()).is_err());
        discovery.candidates[0].sha256 = "1".repeat(64);
        assert!(
            crate::ImportedMsiScenarioResult::reviewed_launch(&request, discovery, 42, 0).is_err()
        );
    }

    fn project() -> Project {
        serde_json::from_value(serde_json::json!({
            "schemaVersion": "aiw.dev/v0alpha2",
            "kind": "AppIsolationProject",
            "metadata": {
                "name": "notepad-plus-plus",
                "displayName": "Notepad++ MSI scenario",
                "owner": "test"
            },
            "application": {
                "type": "msi",
                "path": "inputs/notepad-plus-plus.msi",
                "sha256": "a".repeat(64),
                "silentArguments": [],
                "entryPoints": [{
                    "id": "notepad-plus-plus",
                    "path": "notepad++.exe",
                    "arguments": []
                }],
                "architecture": "x64",
                "mayReboot": false
            },
            "isolationIntent": {
                "runtimeBoundary": "windowsSandbox",
                "network": "blocked",
                "allowClipboard": false,
                "allowHostFileAccess": false,
                "allowHostRegistryAccess": false,
                "requireDescendantCoverage": false
            },
            "candidates": [{"id": "baseline", "type": "unpackagedBaseline", "config": {"type": "baseline"}}],
            "scenarios": [{
                "id": "first-run",
                "description": "Install, launch, observe, and close Notepad++.",
                "required": true,
                "steps": [
                    {"type": "install"},
                    {"type": "launch", "entrypoint": "notepad-plus-plus", "arguments": []},
                    {"type": "waitForProcess", "image": "notepad++.exe", "timeoutSeconds": 30},
                    {"type": "gracefulClose"},
                    {"type": "expectExitCode", "value": 0}
                ]
            }],
            "assertions": {
                "requireEffectiveBackendMatch": false,
                "requireTargetTokenEvidence": false,
                "requireExpectedChildCoverage": false,
                "requireOfflineCanaryDenied": false,
                "failOnEvidenceTruncation": false
            }
        }))
        .unwrap()
    }

    #[test]
    fn compiles_the_fixed_notepad_plus_plus_profile() {
        let compiled = compile_notepad_plus_plus_msi_scenario(&project(), "first-run").unwrap();
        assert_eq!(compiled.profile, NOTEPAD_PLUS_PLUS_MSI_PROFILE);
        assert_eq!(compiled.installer_path, STAGED_INSTALLER_PATH);
        assert_eq!(
            compiled.install_timeout_seconds,
            CURRENT_INSTALL_TIMEOUT_SECONDS
        );
        assert_eq!(compiled.process_wait_timeout_seconds, 30);
        assert_eq!(
            compiled.graceful_close_timeout_seconds,
            GRACEFUL_CLOSE_TIMEOUT_SECONDS
        );
        assert!(compiled.requires_product_registration());
        let hash = compiled.canonical_sha256().unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(compiled.canonical_sha256().unwrap(), hash);

        let mut changed = project();
        let ApplicationSource::Msi(application) = &mut changed.application else {
            unreachable!();
        };
        application.sha256 = "b".repeat(64);
        assert_ne!(
            compile_notepad_plus_plus_msi_scenario(&changed, "first-run")
                .unwrap()
                .canonical_sha256()
                .unwrap(),
            hash
        );
    }

    #[test]
    fn legacy_baseline_retains_its_original_deadline_and_observations() {
        let mut compiled = compile_notepad_plus_plus_msi_scenario(&project(), "first-run").unwrap();
        compiled.schema_version = LEGACY_COMPILED_MSI_SCENARIO_SCHEMA_VERSION.to_owned();
        compiled.profile = LEGACY_NOTEPAD_PLUS_PLUS_MSI_PROFILE.to_owned();
        compiled.install_timeout_seconds = INSTALL_TIMEOUT_SECONDS;
        compiled.validate().unwrap();
        assert!(compiled.requires_application_token());
        assert!(compiled.requires_application_exercise());
        assert!(compiled.requires_standard_user());
        assert!(compiled.requires_registry_observations());
        assert!(compiled.requires_product_registration());
        compiled.install_timeout_seconds = CURRENT_INSTALL_TIMEOUT_SECONDS;
        assert_eq!(
            compiled.validate(),
            Err(ScenarioCompileError::InvalidCompiledProfile)
        );
    }

    #[test]
    fn compiles_the_fixed_local_settings_profile() {
        let compiled =
            compile_notepad_plus_plus_msi_scenario(&local_settings_project(), "first-run").unwrap();
        assert_eq!(
            compiled.schema_version,
            COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION
        );
        assert_eq!(compiled.profile, NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE);
        assert_eq!(
            compiled.install_timeout_seconds,
            CURRENT_INSTALL_TIMEOUT_SECONDS
        );
        assert_eq!(
            compiled.launch_arguments,
            vec![NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT.to_owned()]
        );
        assert_eq!(
            compiled.effective_launch_arguments(),
            vec![
                NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT.to_owned(),
                crate::STANDARD_USER_DOCUMENT_EXERCISE_PATH.to_owned(),
            ]
        );
        assert!(compiled.requires_local_settings());
        assert!(compiled.requires_application_token());
        assert!(compiled.requires_application_exercise());
        assert!(compiled.requires_standard_user());
        assert!(compiled.requires_registry_observations());
        assert!(compiled.requires_product_registration());
        assert!(!compiled.requires_document_transfer());
    }

    #[test]
    fn validates_legacy_local_settings_profile_with_its_original_deadline() {
        let mut compiled =
            compile_notepad_plus_plus_msi_scenario(&local_settings_project(), "first-run").unwrap();
        compiled.schema_version =
            LEGACY_COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION.to_owned();
        compiled.profile = LEGACY_NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE.to_owned();
        compiled.install_timeout_seconds = INSTALL_TIMEOUT_SECONDS;

        compiled.validate().unwrap();
        assert!(compiled.requires_local_settings());
        assert!(compiled.requires_application_exercise());
    }

    #[test]
    fn current_local_settings_profile_rejects_legacy_deadline() {
        let mut compiled =
            compile_notepad_plus_plus_msi_scenario(&local_settings_project(), "first-run").unwrap();
        compiled.install_timeout_seconds = INSTALL_TIMEOUT_SECONDS;

        assert_eq!(
            compiled.validate(),
            Err(ScenarioCompileError::InvalidCompiledProfile)
        );
    }

    #[test]
    fn local_settings_rejects_unknown_extra_and_interactive_arguments() {
        for arguments in [
            vec!["-settingsDir=C:\\Users\\AiwStandardUser\\AppData\\Roaming\\Notepad++".to_owned()],
            vec![
                NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT.to_owned(),
                "-pluginMessage=1".to_owned(),
            ],
        ] {
            let mut value = project();
            let ScenarioStep::Launch {
                arguments: target, ..
            } = &mut value.scenarios[0].steps[1]
            else {
                unreachable!();
            };
            *target = arguments;
            assert_eq!(
                compile_notepad_plus_plus_msi_scenario(&value, "first-run"),
                Err(ScenarioCompileError::UnsupportedScenario)
            );
        }

        let mut interactive = interactive_project();
        let ScenarioStep::Launch { arguments, .. } = &mut interactive.scenarios[0].steps[1] else {
            unreachable!();
        };
        *arguments = vec![NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT.to_owned()];
        assert_eq!(
            compile_notepad_plus_plus_msi_scenario(&interactive, "interactive"),
            Err(ScenarioCompileError::UnsupportedScenario)
        );

        let mut compiled =
            compile_notepad_plus_plus_msi_scenario(&local_settings_project(), "first-run").unwrap();
        compiled.launch_arguments[0] =
            "-settingsDir=C:\\Users\\AiwStandardUser\\AppData\\Roaming\\Notepad++".to_owned();
        assert_eq!(
            compiled.validate(),
            Err(ScenarioCompileError::InvalidCompiledProfile)
        );
        compiled.launch_arguments = vec![
            NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT.to_owned(),
            "-pluginMessage=1".to_owned(),
        ];
        assert_eq!(
            compiled.validate(),
            Err(ScenarioCompileError::InvalidCompiledProfile)
        );
    }

    #[test]
    fn local_settings_does_not_change_the_v6_compiled_hash() {
        let mut compiled = compile_notepad_plus_plus_msi_scenario(&project(), "first-run").unwrap();
        compiled.schema_version = LEGACY_COMPILED_MSI_SCENARIO_SCHEMA_VERSION.to_owned();
        compiled.profile = LEGACY_NOTEPAD_PLUS_PLUS_MSI_PROFILE.to_owned();
        compiled.install_timeout_seconds = INSTALL_TIMEOUT_SECONDS;
        assert_eq!(
            compiled.canonical_sha256().unwrap(),
            "20919d9d2a6de4de3723b567c25fc18e220f984b050fd3e8983d504f70b3bda8"
        );
    }

    #[test]
    fn compiles_the_bounded_interactive_document_profile() {
        let input = b"hello from the approved worker\r\n";
        let hash = hex::encode(Sha256::digest(input));
        let compiled = compile_notepad_plus_plus_msi_scenario_with_document(
            &interactive_project(),
            "interactive",
            &hash,
            input.len() as u64,
        )
        .unwrap();
        assert_eq!(
            compiled.profile,
            NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE
        );
        assert!(compiled.requires_document_transfer());
        assert!(compiled.requires_standard_user());
        assert!(compiled.requires_application_token());
        assert_eq!(compiled.interactive_session_seconds, Some(60));
        assert_eq!(
            compiled.interactive_document.as_ref().unwrap().input_sha256,
            hash
        );
        assert_eq!(compiled.canonical_sha256().unwrap().len(), 64);
        assert_eq!(compiled.install_timeout_seconds, 300);
        assert_eq!(compiled.install_arguments[4], "/L*V");
        assert_eq!(
            compiled.install_arguments[5],
            INTERACTIVE_MSI_INSTALL_LOG_PATH
        );

        let mut changed = compiled.clone();
        changed.install_timeout_seconds = 120;
        assert!(changed.validate().is_err());
        changed = compiled.clone();
        changed.install_arguments[5] = r"C:\other.log".into();
        assert!(changed.validate().is_err());

        let mut historical = compiled;
        historical.schema_version = "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha8".into();
        historical.profile = LEGACY_INTERACTIVE_DOCUMENT_PROFILE.into();
        historical.install_timeout_seconds = 120;
        historical.install_arguments.truncate(4);
        historical.validate().unwrap();
        assert!(historical.requires_document_transfer());
        assert!(historical.requires_standard_user());
        assert!(historical.requires_application_token());
        historical.install_timeout_seconds = 300;
        assert!(historical.validate().is_err());
    }

    #[test]
    fn rejects_unbounded_or_noninteractive_document_bindings() {
        let interactive = interactive_project();
        assert_eq!(
            compile_notepad_plus_plus_msi_scenario_with_document(
                &interactive,
                "interactive",
                &"0".repeat(64),
                MAX_INTERACTIVE_DOCUMENT_BYTES + 1,
            ),
            Err(ScenarioCompileError::UnsupportedScenario)
        );
        assert_eq!(
            compile_notepad_plus_plus_msi_scenario_with_document(
                &project(),
                "first-run",
                &"0".repeat(64),
                1,
            ),
            Err(ScenarioCompileError::UnsupportedScenario)
        );
    }

    fn interactive_project() -> Project {
        let mut value = project();
        value.scenarios[0].id = "interactive".to_owned();
        value.scenarios[0].steps = vec![
            ScenarioStep::Install,
            ScenarioStep::Launch {
                entrypoint: NOTEPAD_PLUS_PLUS_ENTRYPOINT_ID.to_owned(),
                arguments: Vec::new(),
            },
            ScenarioStep::WaitForProcess {
                image: NOTEPAD_PLUS_PLUS_PROCESS_IMAGE.to_owned(),
                timeout_seconds: 30,
            },
            ScenarioStep::WaitForUserClose {
                timeout_seconds: 60,
            },
            ScenarioStep::ExpectExitCode { value: 0 },
        ];
        value
    }

    fn local_settings_project() -> Project {
        let mut value = project();
        let ScenarioStep::Launch { arguments, .. } = &mut value.scenarios[0].steps[1] else {
            unreachable!();
        };
        *arguments = vec![NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT.to_owned()];
        value
    }

    #[test]
    fn rejects_unreviewed_source_and_scenario_semantics() {
        let mut value = project();
        let ApplicationSource::Msi(application) = &mut value.application else {
            unreachable!();
        };
        application.silent_arguments.push("/passive".to_owned());
        assert_eq!(
            compile_notepad_plus_plus_msi_scenario(&value, "first-run"),
            Err(ScenarioCompileError::UnsupportedInstallerSemantics)
        );

        let mut value = project();
        value.scenarios[0].steps.pop();
        assert_eq!(
            compile_notepad_plus_plus_msi_scenario(&value, "first-run"),
            Err(ScenarioCompileError::UnsupportedScenario)
        );

        let mut value = project();
        let ScenarioStep::WaitForProcess {
            timeout_seconds, ..
        } = &mut value.scenarios[0].steps[2]
        else {
            unreachable!();
        };
        *timeout_seconds = MAX_PROCESS_WAIT_TIMEOUT_SECONDS + 1;
        assert_eq!(
            compile_notepad_plus_plus_msi_scenario(&value, "first-run"),
            Err(ScenarioCompileError::UnsupportedScenario)
        );

        let mut value = project();
        value.isolation_intent.network = NetworkIntent::Allowed;
        assert_eq!(
            compile_notepad_plus_plus_msi_scenario(&value, "first-run"),
            Err(ScenarioCompileError::UnsupportedProjectSemantics)
        );
    }

    #[test]
    fn validation_prevents_constructed_values_from_widening_the_profile() {
        let mut compiled = compile_notepad_plus_plus_msi_scenario(&project(), "first-run").unwrap();
        compiled.launch_arguments.push("--arbitrary".to_owned());
        assert_eq!(
            compiled.validate(),
            Err(ScenarioCompileError::InvalidCompiledProfile)
        );
        assert_eq!(
            compiled.canonical_sha256(),
            Err(ScenarioCompileError::InvalidCompiledProfile)
        );
    }

    #[test]
    fn rejects_ambiguous_project_authority() {
        let mut value = project();
        value.scenarios.push(value.scenarios[0].clone());
        assert_eq!(
            compile_notepad_plus_plus_msi_scenario(&value, "first-run"),
            Err(ScenarioCompileError::InvalidProject)
        );
        let mut value = project();
        let ApplicationSource::Msi(application) = &mut value.application else {
            unreachable!()
        };
        application
            .entry_points
            .push(application.entry_points[0].clone());
        assert_eq!(
            compile_notepad_plus_plus_msi_scenario(&value, "first-run"),
            Err(ScenarioCompileError::InvalidProject)
        );
    }

    #[test]
    fn retains_assessment_requirements_without_claiming_to_satisfy_them() {
        let mut value = project();
        value.isolation_intent.require_descendant_coverage = true;
        value.assertions = aiw_schema::Assertions::default();
        let before = value.clone();
        compile_notepad_plus_plus_msi_scenario(&value, "first-run").unwrap();
        assert_eq!(value, before);
    }

    #[test]
    fn strict_wire_rejects_unknown_command_fields() {
        let compiled = compile_notepad_plus_plus_msi_scenario(&project(), "first-run").unwrap();
        let mut value = serde_json::to_value(&compiled).unwrap();
        value["command"] = serde_json::json!("cmd.exe");
        assert!(serde_json::from_value::<CompiledMsiScenario>(value).is_err());
        let mut changed = compiled.clone();
        changed.process_wait_timeout_seconds += 1;
        assert_ne!(
            compiled.canonical_sha256().unwrap(),
            changed.canonical_sha256().unwrap()
        );
        changed.process_wait_timeout_seconds = 61;
        assert!(changed.canonical_sha256().is_err());
    }
}
