//! Typed, non-executing compilation for the reviewed Bambu Studio CLI smoke
//! scenario. This is deliberately separate from the MSI profile: it binds one
//! supplied EXE and one local STL information query, without treating Bambu
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

pub const COMPILED_BAMBU_SCENARIO_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-compiled-bambu-scenario/v0alpha1";
pub const BAMBU_STUDIO_INFO_PROFILE: &str = "aiw.dev/windows-sandbox/bambu-studio-info/v0alpha1";
pub const BAMBU_STUDIO_APPLICATION_SHA256: &str =
    "cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7";
pub const BAMBU_STUDIO_ENTRYPOINT_ID: &str = "bambu-studio";
pub const BAMBU_STUDIO_ENTRYPOINT_PATH: &str = "bambu-studio.exe";
pub const BAMBU_STUDIO_STAGED_INSTALLER_PATH: &str = r"C:\AIW\Tools\application.exe";
pub const BAMBU_STUDIO_INSTALLED_PATH: &str = r"C:\Program Files\Bambu Studio\bambu-studio.exe";
pub const BAMBU_STUDIO_INFO_FIXTURE_PATH: &str = r"C:\AIW\Scenario\fixtures\aiw-tetrahedron.stl";
pub const BAMBU_STUDIO_INFO_FIXTURE_SHA256: &str =
    "2cb47e4cd9e465a162b4e60e6f15708f4ee15ef28477737c807283176a057450";

const INSTALL_TIMEOUT_SECONDS: u32 = 300;
const CLI_TIMEOUT_SECONDS: u32 = 60;

/// Fully resolved, non-executable Bambu Studio smoke scenario. `--info` only
/// reads the profile-owned fixture; slicing, printing, cloud access, and
/// hardware discovery remain unmeasured.
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledBambuScenario {
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

impl CompiledBambuScenario {
    /// Rejects constructed values that could widen this fixed command surface.
    pub fn validate(&self) -> Result<(), BambuScenarioCompileError> {
        if self.schema_version != COMPILED_BAMBU_SCENARIO_SCHEMA_VERSION
            || self.profile != BAMBU_STUDIO_INFO_PROFILE
            || !valid_id(&self.scenario_id)
            || self.application_sha256 != BAMBU_STUDIO_APPLICATION_SHA256
            || self.installer_path != BAMBU_STUDIO_STAGED_INSTALLER_PATH
            || self.install_arguments != ["/S".to_owned()]
            || self.install_timeout_seconds != INSTALL_TIMEOUT_SECONDS
            || self.launch_path != BAMBU_STUDIO_INSTALLED_PATH
            || self.launch_arguments
                != [
                    "--info".to_owned(),
                    BAMBU_STUDIO_INFO_FIXTURE_PATH.to_owned(),
                ]
            || self.cli_timeout_seconds != CLI_TIMEOUT_SECONDS
            || self.expected_exit_code != 0
            || self.fixture_path != BAMBU_STUDIO_INFO_FIXTURE_PATH
            || self.fixture_sha256 != BAMBU_STUDIO_INFO_FIXTURE_SHA256
        {
            return Err(BambuScenarioCompileError::InvalidCompiledProfile);
        }
        Ok(())
    }

    /// The versioned, fully fixed scenario is the only hashable execution intent.
    pub fn canonical_sha256(&self) -> Result<String, BambuScenarioCompileError> {
        self.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|error| BambuScenarioCompileError::Canonicalization(error.to_string()))?;
        let bytes = canonical_json_bytes(&value)
            .map_err(|error| BambuScenarioCompileError::Canonicalization(error.to_string()))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BambuScenarioCompileError {
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

/// Compiles exactly `Install -> Launch(--info fixture) -> ExpectExitCode(0)`.
/// It performs no file, process, provider, or host mutation.
pub fn compile_bambu_studio_info_scenario(
    project: &Project,
    scenario_id: &str,
) -> Result<CompiledBambuScenario, BambuScenarioCompileError> {
    if !aiw_schema::validate_project_for_planning(project).is_empty() {
        return Err(BambuScenarioCompileError::InvalidProject);
    }
    require_project_semantics(project)?;
    let ApplicationSource::Exe(application) = &project.application else {
        return Err(BambuScenarioCompileError::UnsupportedApplicationSource);
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
        return Err(BambuScenarioCompileError::UnsupportedInstallerSemantics);
    }
    let scenario = project
        .scenarios
        .iter()
        .find(|scenario| scenario.id == scenario_id)
        .ok_or(BambuScenarioCompileError::UnsupportedScenario)?;
    if !valid_id(scenario_id) || !matches_bambu_info_sequence(&scenario.steps) {
        return Err(BambuScenarioCompileError::UnsupportedScenario);
    }
    let compiled = CompiledBambuScenario {
        schema_version: COMPILED_BAMBU_SCENARIO_SCHEMA_VERSION.to_owned(),
        profile: BAMBU_STUDIO_INFO_PROFILE.to_owned(),
        scenario_id: scenario.id.clone(),
        application_sha256: application.sha256.clone(),
        installer_path: BAMBU_STUDIO_STAGED_INSTALLER_PATH.to_owned(),
        install_arguments: vec!["/S".to_owned()],
        install_timeout_seconds: INSTALL_TIMEOUT_SECONDS,
        launch_path: BAMBU_STUDIO_INSTALLED_PATH.to_owned(),
        launch_arguments: vec![
            "--info".to_owned(),
            BAMBU_STUDIO_INFO_FIXTURE_PATH.to_owned(),
        ],
        cli_timeout_seconds: CLI_TIMEOUT_SECONDS,
        expected_exit_code: 0,
        fixture_path: BAMBU_STUDIO_INFO_FIXTURE_PATH.to_owned(),
        fixture_sha256: BAMBU_STUDIO_INFO_FIXTURE_SHA256.to_owned(),
    };
    compiled.validate()?;
    Ok(compiled)
}

fn require_project_semantics(project: &Project) -> Result<(), BambuScenarioCompileError> {
    let intent = &project.isolation_intent;
    if !project.secrets.is_empty()
        || intent.runtime_boundary != RuntimeBoundary::WindowsSandbox
        || intent.network != NetworkIntent::Blocked
        || intent.allow_clipboard
        || intent.allow_host_file_access
        || intent.allow_host_registry_access
    {
        return Err(BambuScenarioCompileError::UnsupportedProjectSemantics);
    }
    Ok(())
}

fn matches_bambu_info_sequence(steps: &[ScenarioStep]) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> Project {
        serde_json::from_value(serde_json::json!({
            "schemaVersion": "aiw.dev/v0alpha2",
            "kind": "AppIsolationProject",
            "metadata": {
                "name": "bambu-studio",
                "displayName": "Bambu Studio local-file information",
                "owner": "test"
            },
            "application": {
                "type": "exe",
                "path": "inputs/Bambu_Studio_win-v02.08.02.60.exe",
                "sha256": BAMBU_STUDIO_APPLICATION_SHA256,
                "silentArguments": [],
                "entryPoints": [{
                    "id": BAMBU_STUDIO_ENTRYPOINT_ID,
                    "path": BAMBU_STUDIO_ENTRYPOINT_PATH,
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
                "id": "local-file-info",
                "description": "Install Bambu Studio and inspect the fixed local tetrahedron STL.",
                "required": true,
                "steps": [
                    {"type": "install"},
                    {"type": "launch", "entrypoint": BAMBU_STUDIO_ENTRYPOINT_ID, "arguments": []},
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
    fn compiles_the_fixed_bambu_studio_profile() {
        let compiled = compile_bambu_studio_info_scenario(&project(), "local-file-info").unwrap();
        assert_eq!(compiled.profile, BAMBU_STUDIO_INFO_PROFILE);
        assert_eq!(compiled.application_sha256, BAMBU_STUDIO_APPLICATION_SHA256);
        assert_eq!(compiled.install_arguments, ["/S"]);
        assert_eq!(compiled.launch_arguments[1], BAMBU_STUDIO_INFO_FIXTURE_PATH);
        assert_eq!(compiled.fixture_sha256, BAMBU_STUDIO_INFO_FIXTURE_SHA256);
        let hash = compiled.canonical_sha256().unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(compiled.canonical_sha256().unwrap(), hash);
    }

    #[test]
    fn reviewed_example_and_fixture_bind_the_fixed_profile() {
        let project: Project =
            serde_json::from_str(include_str!("../../../examples/bambu-studio-info.json")).unwrap();
        let compiled = compile_bambu_studio_info_scenario(&project, "local-file-info").unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(include_bytes!(
                "../../../fixtures/bambu-studio/aiw-tetrahedron.stl"
            ))),
            compiled.fixture_sha256
        );
    }

    #[test]
    fn rejects_unreviewed_source_and_scenario_semantics() {
        let mut value = project();
        let ApplicationSource::Exe(application) = &mut value.application else {
            unreachable!();
        };
        application.silent_arguments.push("/D=C:\\other".to_owned());
        assert_eq!(
            compile_bambu_studio_info_scenario(&value, "local-file-info"),
            Err(BambuScenarioCompileError::UnsupportedInstallerSemantics)
        );

        let mut value = project();
        let ApplicationSource::Exe(application) = &mut value.application else {
            unreachable!();
        };
        application.sha256 = "a".repeat(64);
        assert_eq!(
            compile_bambu_studio_info_scenario(&value, "local-file-info"),
            Err(BambuScenarioCompileError::UnsupportedInstallerSemantics)
        );

        let mut value = project();
        value.scenarios[0]
            .steps
            .insert(2, ScenarioStep::GracefulClose);
        assert_eq!(
            compile_bambu_studio_info_scenario(&value, "local-file-info"),
            Err(BambuScenarioCompileError::UnsupportedScenario)
        );

        let mut value = project();
        value.isolation_intent.network = NetworkIntent::Allowed;
        assert_eq!(
            compile_bambu_studio_info_scenario(&value, "local-file-info"),
            Err(BambuScenarioCompileError::UnsupportedProjectSemantics)
        );
    }

    #[test]
    fn validation_prevents_constructed_values_from_widening_the_profile() {
        let mut compiled =
            compile_bambu_studio_info_scenario(&project(), "local-file-info").unwrap();
        compiled.launch_arguments.push("--slice".to_owned());
        assert_eq!(
            compiled.validate(),
            Err(BambuScenarioCompileError::InvalidCompiledProfile)
        );
        assert_eq!(
            compiled.canonical_sha256(),
            Err(BambuScenarioCompileError::InvalidCompiledProfile)
        );

        let compiled = compile_bambu_studio_info_scenario(&project(), "local-file-info").unwrap();
        let mut value = serde_json::to_value(&compiled).unwrap();
        value["command"] = serde_json::json!("cmd.exe");
        assert!(serde_json::from_value::<CompiledBambuScenario>(value).is_err());
    }
}
