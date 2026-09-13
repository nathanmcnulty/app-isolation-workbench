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
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha6";
pub const NOTEPAD_PLUS_PLUS_MSI_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha6";
pub const NOTEPAD_PLUS_PLUS_INTERACTIVE_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-interactive/v0alpha1";
pub const NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-interactive-document/v0alpha1";
pub const COMPILED_MSI_INTERACTIVE_DOCUMENT_SCENARIO_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha8";

const NOTEPAD_PLUS_PLUS_ENTRYPOINT_ID: &str = "notepad-plus-plus";
const NOTEPAD_PLUS_PLUS_ENTRYPOINT_PATH: &str = "notepad++.exe";
const NOTEPAD_PLUS_PLUS_INSTALLED_PATH: &str = r"C:\Program Files\Notepad++\notepad++.exe";
const NOTEPAD_PLUS_PLUS_PROCESS_IMAGE: &str = "notepad++.exe";
const STAGED_INSTALLER_PATH: &str = r"C:\AIW\Tools\application.msi";
pub const INTERACTIVE_DOCUMENT_INPUT_PATH: &str = r"C:\AIW\Tools\document-input.txt";
pub const INTERACTIVE_DOCUMENT_OUTPUT_PATH: &str = r"C:\AIW\Output\document-output.txt";
pub const MAX_INTERACTIVE_DOCUMENT_BYTES: u64 = 1024 * 1024;
const INSTALL_TIMEOUT_SECONDS: u32 = 120;
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

impl CompiledMsiScenario {
    /// Validates the fixed profile constants and the copied source binding.
    pub fn validate(&self) -> Result<(), ScenarioCompileError> {
        let current = self.schema_version == COMPILED_MSI_SCENARIO_SCHEMA_VERSION
            && self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE;
        let interactive = self.schema_version
            == "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha7"
            && self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_PROFILE;
        let interactive_document = self.schema_version
            == COMPILED_MSI_INTERACTIVE_DOCUMENT_SCENARIO_SCHEMA_VERSION
            && self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE;
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
            || interactive
            || interactive_document
            || registry_profile
            || standard_user_legacy
            || legacy_exercise
            || token_profile
            || legacy)
            || (legacy_exercise
                && self.document_exercise.as_ref() != Some(&FixedDocumentExercise::legacy()))
            || ((current || registry_profile || standard_user_legacy)
                && self.document_exercise.as_ref() != Some(&FixedDocumentExercise::standard_user()))
            || (!current
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
            || self.install_arguments
                != [
                    "/i".to_owned(),
                    STAGED_INSTALLER_PATH.to_owned(),
                    "/qn".to_owned(),
                    "/norestart".to_owned(),
                ]
            || self.install_timeout_seconds != INSTALL_TIMEOUT_SECONDS
            || self.launch_path != NOTEPAD_PLUS_PLUS_INSTALLED_PATH
            || !self.launch_arguments.is_empty()
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
        self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_PROFILE
            || self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE
            || self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha5"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha3"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha4"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha2"
    }

    pub fn requires_application_exercise(&self) -> bool {
        self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha5"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha3"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha4"
    }

    pub fn requires_standard_user(&self) -> bool {
        self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_PROFILE
            || self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE
            || self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha5"
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha4"
    }

    pub fn requires_registry_observations(&self) -> bool {
        self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || self.profile == "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha5"
    }

    pub fn requires_product_registration(&self) -> bool {
        self.profile == NOTEPAD_PLUS_PLUS_MSI_PROFILE
    }

    pub fn requires_document_transfer(&self) -> bool {
        self.profile == NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE
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
        install_timeout_seconds: INSTALL_TIMEOUT_SECONDS,
        launch_path: NOTEPAD_PLUS_PLUS_INSTALLED_PATH.to_owned(),
        launch_arguments: Vec::new(),
        process_image: NOTEPAD_PLUS_PLUS_PROCESS_IMAGE.to_owned(),
        process_wait_timeout_seconds: *timeout_seconds,
        graceful_close_timeout_seconds: GRACEFUL_CLOSE_TIMEOUT_SECONDS,
        expected_exit_code: 0,
        document_exercise: Some(FixedDocumentExercise::standard_user()),
        interactive_session_seconds: interactive_seconds,
        interactive_document: None,
    };
    if interactive_seconds.is_some() {
        compiled.schema_version = "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha7".into();
        compiled.profile = NOTEPAD_PLUS_PLUS_INTERACTIVE_PROFILE.into();
        compiled.document_exercise = None;
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
            && arguments.is_empty()
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
        assert_eq!(compiled.install_timeout_seconds, INSTALL_TIMEOUT_SECONDS);
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
