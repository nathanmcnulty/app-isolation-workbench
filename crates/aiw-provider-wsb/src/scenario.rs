//! Typed, non-executing scenario compilation for approved Windows Sandbox runs.
//!
//! This module intentionally recognizes one reviewed application profile.  It
//! is not a command-line or scenario-step interpreter: all executable paths,
//! installer arguments, timeouts, and observations in the compiled value are
//! constants selected by the profile.

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
    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha1";
pub const NOTEPAD_PLUS_PLUS_MSI_PROFILE: &str =
    "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha1";

const NOTEPAD_PLUS_PLUS_ENTRYPOINT_ID: &str = "notepad-plus-plus";
const NOTEPAD_PLUS_PLUS_ENTRYPOINT_PATH: &str = "notepad++.exe";
const NOTEPAD_PLUS_PLUS_INSTALLED_PATH: &str = r"C:\Program Files\Notepad++\notepad++.exe";
const NOTEPAD_PLUS_PLUS_PROCESS_IMAGE: &str = "notepad++.exe";
const STAGED_INSTALLER_PATH: &str = r"C:\AIW\Tools\application.msi";
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
}

impl CompiledMsiScenario {
    /// Validates the fixed profile constants and the copied source binding.
    pub fn validate(&self) -> Result<(), ScenarioCompileError> {
        if self.schema_version != COMPILED_MSI_SCENARIO_SCHEMA_VERSION
            || self.profile != NOTEPAD_PLUS_PLUS_MSI_PROFILE
            || !valid_id(&self.scenario_id)
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
    #[error("only MSI application sources are supported by this Windows Sandbox scenario profile")]
    UnsupportedApplicationSource,
    #[error(
        "the imported MSI profile does not accept caller-supplied silent arguments or reboot semantics"
    )]
    UnsupportedInstallerSemantics,
    #[error(
        "the project requests secrets, host resources, network access, or unsupported evidence semantics"
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
    if !valid_id(scenario_id) || !matches_notepad_plus_plus_sequence(&scenario.steps) {
        return Err(ScenarioCompileError::UnsupportedScenario);
    }
    let ScenarioStep::WaitForProcess {
        timeout_seconds, ..
    } = &scenario.steps[2]
    else {
        return Err(ScenarioCompileError::UnsupportedScenario);
    };
    let compiled = CompiledMsiScenario {
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
    };
    compiled.validate()?;
    Ok(compiled)
}

fn require_project_semantics(project: &Project) -> Result<(), ScenarioCompileError> {
    let intent = &project.isolation_intent;
    let assertions = &project.assertions;
    if !project.secrets.is_empty()
        || intent.runtime_boundary != RuntimeBoundary::WindowsSandbox
        || intent.network != NetworkIntent::Blocked
        || intent.allow_clipboard
        || intent.allow_host_file_access
        || intent.allow_host_registry_access
        || intent.require_descendant_coverage
        || assertions.require_effective_backend_match
        || assertions.require_target_token_evidence
        || assertions.require_expected_child_coverage
        || assertions.require_offline_canary_denied
        || assertions.fail_on_evidence_truncation
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
            "candidates": [],
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
}
