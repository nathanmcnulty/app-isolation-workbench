//! Typed compilation for the approved Bambu Studio model-export
//! scenario. This is deliberately separate from the MSI profile: it binds one
//! supplied EXE and one local STL project export, without treating Bambu
//! Studio's experimental runtime capability as established.

use aiw_evidence::canonical_json_bytes;
use aiw_schema::{
    ApplicationArchitecture, ApplicationSource, NetworkIntent, Project, RuntimeBoundary,
    ScenarioStep,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const COMPILED_BAMBU_EXPORT_SCENARIO_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-bambu-export-scenario/v0alpha1";
pub const BAMBU_STUDIO_EXPORT_PROFILE: &str =
    "aiw.dev/windows-sandbox/bambu-studio-export/v0alpha1";
pub const BAMBU_STUDIO_APPLICATION_SHA256: &str =
    "cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7";
pub const BAMBU_STUDIO_ENTRYPOINT_ID: &str = "bambu-studio";
pub const BAMBU_STUDIO_ENTRYPOINT_PATH: &str = "bambu-studio.exe";
pub const BAMBU_STUDIO_STAGED_INSTALLER_PATH: &str = r"C:\AIW\Tools\application.exe";
pub const BAMBU_STUDIO_INSTALLED_PATH: &str = r"C:\Program Files\Bambu Studio\bambu-studio.exe";
pub const BAMBU_STUDIO_EXPORT_FIXTURE_PATH: &str =
    r"C:\Users\AiwStandardUser\AppData\Local\AIW\Scenario\aiw-tetrahedron.stl";
pub const BAMBU_STUDIO_EXPORT_FIXTURE_SHA256: &str =
    "2cb47e4cd9e465a162b4e60e6f15708f4ee15ef28477737c807283176a057450";

pub const BAMBU_STUDIO_EXPORT_OUTPUT_PATH: &str =
    r"C:\Users\AiwStandardUser\AppData\Local\AIW\Scenario\aiw-tetrahedron.3mf";
pub const BAMBU_EXPORT_ARTIFACT_PATH: &str = "aiw-tetrahedron.3mf";
pub const BAMBU_MAX_ARTIFACT_BYTES: u64 = 1024 * 1024;
const INSTALL_TIMEOUT_SECONDS: u32 = 300;
const CLI_TIMEOUT_SECONDS: u32 = 60;

/// Fully resolved, non-executable Bambu Studio smoke scenario. `--export-3mf` uses
/// the profile-owned fixture; slicing, printing, cloud access, and
/// hardware discovery remain unmeasured.
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledBambuExportScenario {
    pub schema_version: String,
    pub profile: String,
    pub scenario_id: String,
    pub application_sha256: String,
    pub installer_path: String,
    pub install_arguments: Vec<String>,
    pub install_timeout_seconds: u32,
    pub launch_path: String,
    pub launch_arguments: Vec<String>,
    pub cli_timeout_seconds: u32,
    pub expected_exit_code: i32,
    pub fixture_path: String,
    pub fixture_sha256: String,
}

impl CompiledBambuExportScenario {
    /// Rejects constructed values that could widen this fixed command surface.
    pub fn validate(&self) -> Result<(), BambuExportCompileError> {
        if self.schema_version != COMPILED_BAMBU_EXPORT_SCENARIO_SCHEMA_VERSION
            || self.profile != BAMBU_STUDIO_EXPORT_PROFILE
            || !valid_id(&self.scenario_id)
            || self.application_sha256 != BAMBU_STUDIO_APPLICATION_SHA256
            || self.installer_path != BAMBU_STUDIO_STAGED_INSTALLER_PATH
            || self.install_arguments != ["/S".to_owned()]
            || self.install_timeout_seconds != INSTALL_TIMEOUT_SECONDS
            || self.launch_path != BAMBU_STUDIO_INSTALLED_PATH
            || self.launch_arguments
                != [
                    "--export-3mf".to_owned(),
                    BAMBU_STUDIO_EXPORT_OUTPUT_PATH.to_owned(),
                    BAMBU_STUDIO_EXPORT_FIXTURE_PATH.to_owned(),
                ]
            || self.cli_timeout_seconds != CLI_TIMEOUT_SECONDS
            || self.expected_exit_code != 0
            || self.fixture_path != BAMBU_STUDIO_EXPORT_FIXTURE_PATH
            || self.fixture_sha256 != BAMBU_STUDIO_EXPORT_FIXTURE_SHA256
        {
            return Err(BambuExportCompileError::InvalidCompiledProfile);
        }
        Ok(())
    }

    /// The versioned, fully fixed scenario is the only hashable execution intent.
    pub fn canonical_sha256(&self) -> Result<String, BambuExportCompileError> {
        self.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|error| BambuExportCompileError::Canonicalization(error.to_string()))?;
        let bytes = canonical_json_bytes(&value)
            .map_err(|error| BambuExportCompileError::Canonicalization(error.to_string()))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BambuExportCompileError {
    #[error("project is invalid or awaits migration review")]
    InvalidProject,
    #[error("only the reviewed Bambu Studio EXE source is supported")]
    UnsupportedApplicationSource,
    #[error(
        "the Bambu Studio profile does not accept caller-supplied installer arguments or reboot semantics"
    )]
    UnsupportedInstallerSemantics,
    #[error(
        "the project requests unsupported secrets, host resources, network access, or runtime boundary"
    )]
    UnsupportedProjectSemantics,
    #[error("the requested scenario is not the exact Bambu Studio local-file information sequence")]
    UnsupportedScenario,
    #[error("compiled Bambu Studio scenario does not match the fixed profile")]
    InvalidCompiledProfile,
    #[error("compiled Bambu Studio scenario could not be canonicalized: {0}")]
    Canonicalization(String),
}

/// Compiles exactly `Install -> Launch(--export-3mf output fixture) -> ExpectExitCode(0)`.
/// It performs no file, process, provider, or host mutation.
pub fn compile_bambu_studio_export_scenario(
    project: &Project,
    scenario_id: &str,
) -> Result<CompiledBambuExportScenario, BambuExportCompileError> {
    if !aiw_schema::validate_project_for_planning(project).is_empty() {
        return Err(BambuExportCompileError::InvalidProject);
    }
    require_project_semantics(project)?;
    let ApplicationSource::Exe(application) = &project.application else {
        return Err(BambuExportCompileError::UnsupportedApplicationSource);
    };
    if application.sha256 != BAMBU_STUDIO_APPLICATION_SHA256
        || !application.silent_arguments.is_empty()
        || application.architecture != ApplicationArchitecture::X64
        || application.may_reboot
        || application.update_uninstall.is_some()
        || !application.entry_points.iter().any(|entrypoint| {
            entrypoint.id == BAMBU_STUDIO_ENTRYPOINT_ID
                && entrypoint.path == BAMBU_STUDIO_ENTRYPOINT_PATH
                && entrypoint.arguments.is_empty()
        })
    {
        return Err(BambuExportCompileError::UnsupportedInstallerSemantics);
    }
    let scenario = project
        .scenarios
        .iter()
        .find(|scenario| scenario.id == scenario_id)
        .ok_or(BambuExportCompileError::UnsupportedScenario)?;
    if !valid_id(scenario_id) || !matches_bambu_export_sequence(&scenario.steps) {
        return Err(BambuExportCompileError::UnsupportedScenario);
    }
    let compiled = CompiledBambuExportScenario {
        schema_version: COMPILED_BAMBU_EXPORT_SCENARIO_SCHEMA_VERSION.to_owned(),
        profile: BAMBU_STUDIO_EXPORT_PROFILE.to_owned(),
        scenario_id: scenario.id.clone(),
        application_sha256: application.sha256.clone(),
        installer_path: BAMBU_STUDIO_STAGED_INSTALLER_PATH.to_owned(),
        install_arguments: vec!["/S".to_owned()],
        install_timeout_seconds: INSTALL_TIMEOUT_SECONDS,
        launch_path: BAMBU_STUDIO_INSTALLED_PATH.to_owned(),
        launch_arguments: vec![
            "--export-3mf".to_owned(),
            BAMBU_STUDIO_EXPORT_OUTPUT_PATH.to_owned(),
            BAMBU_STUDIO_EXPORT_FIXTURE_PATH.to_owned(),
        ],
        cli_timeout_seconds: CLI_TIMEOUT_SECONDS,
        expected_exit_code: 0,
        fixture_path: BAMBU_STUDIO_EXPORT_FIXTURE_PATH.to_owned(),
        fixture_sha256: BAMBU_STUDIO_EXPORT_FIXTURE_SHA256.to_owned(),
    };
    compiled.validate()?;
    Ok(compiled)
}

fn require_project_semantics(project: &Project) -> Result<(), BambuExportCompileError> {
    let intent = &project.isolation_intent;
    if !project.secrets.is_empty()
        || intent.runtime_boundary != RuntimeBoundary::WindowsSandbox
        || intent.network != NetworkIntent::Blocked
        || intent.allow_clipboard
        || intent.allow_host_file_access
        || intent.allow_host_registry_access
    {
        return Err(BambuExportCompileError::UnsupportedProjectSemantics);
    }
    Ok(())
}

fn matches_bambu_export_sequence(steps: &[ScenarioStep]) -> bool {
    matches!(
        steps,
        [
            ScenarioStep::Install,
            ScenarioStep::Launch { entrypoint, arguments },
            ScenarioStep::ExpectExitCode { value: 0 },
        ] if entrypoint == BAMBU_STUDIO_ENTRYPOINT_ID
            && arguments.is_empty()
    )
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
