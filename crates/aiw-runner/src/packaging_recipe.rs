//! Read-only inspection of the existing fixed MSI preparation. This output is
//! neither an executable recipe language nor a substitute for run approval.

use aiw_evidence::canonical_json_bytes;
use aiw_provider_wsb::{CompiledMsiScenario, RenderedWindowsSandboxConfig, render_config};
use schemars::JsonSchema;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{PreparedWsbArtifacts, WsbPreparationError, WsbPreparationReceipt};

pub const WSB_MSI_RECIPE_SCHEMA_VERSION: &str = "aiw.dev/wsb-msi-recipe-inspection/v0alpha1";

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbMsiRecipeInspection {
    pub schema_version: String,
    /// Hash of canonical `recipe` JSON, not an approval or compatibility verdict.
    pub recipe_sha256: String,
    pub recipe: WsbMsiRecipe,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbMsiRecipe {
    pub preparation: WsbPreparationReceipt,
    pub scenario: CompiledMsiScenario,
    /// Exact provider renderer output, including every host mapping and switch.
    pub sandbox_config: RenderedWindowsSandboxConfig,
    pub working_directory: String,
    /// The fixed guest appends the document path when the profile uses one.
    pub effective_launch_arguments: Vec<String>,
    pub application_profile_directory: String,
    pub data: WsbMsiRecipeData,
    pub trust_deltas: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbMsiRecipeData {
    pub mode: String,
    pub guest_document_path: Option<String>,
    pub staged_input_path: Option<String>,
    pub retained_output_path: Option<String>,
    pub maximum_document_bytes: Option<u64>,
    pub lifetime: String,
}

#[cfg(windows)]
pub fn inspect_windows_sandbox_msi_recipe(
    root: &std::path::Path,
    project: &aiw_schema::Project,
    guest_agent_sha256: &str,
) -> Result<WsbMsiRecipeInspection, WsbPreparationError> {
    // Reuse the preparation verifier's held files, current provider identity,
    // staged payload/input hashes, project binding and workspace allowlists.
    // Inspection is deliberately before planning import. This excludes active,
    // failed and recovery runs even when they have not published guest output.
    let artifacts = crate::verify_windows_sandbox_preparation(root, project, guest_agent_sha256)?;
    inspect_artifacts(&artifacts)
}

pub(crate) fn inspect_artifacts(
    artifacts: &PreparedWsbArtifacts,
) -> Result<WsbMsiRecipeInspection, WsbPreparationError> {
    artifacts.validate()?;
    let msi = artifacts.receipt.msi.as_ref().ok_or_else(|| {
        WsbPreparationError::Contract("recipe inspection requires an MSI preparation".into())
    })?;
    let scenario = &msi.scenario;
    let data = if scenario.requires_document_transfer() {
        WsbMsiRecipeData {
            mode: "boundedUtf8DocumentTransfer".into(),
            guest_document_path: Some(aiw_provider_wsb::STANDARD_USER_DOCUMENT_EXERCISE_PATH.into()),
            staged_input_path: Some(aiw_provider_wsb::INTERACTIVE_DOCUMENT_INPUT_PATH.into()),
            retained_output_path: Some(aiw_provider_wsb::INTERACTIVE_DOCUMENT_OUTPUT_PATH.into()),
            maximum_document_bytes: Some(aiw_provider_wsb::MAX_INTERACTIVE_DOCUMENT_BYTES),
            lifetime: "The worker is discarded on close or timeout. The staged input and verified output remain in the host run workspace; exporting to another host file requires an explicit command.".into(),
        }
    } else if scenario.interactive_session_seconds.is_some() {
        WsbMsiRecipeData {
            mode: "ephemeralInteractiveScratch".into(),
            guest_document_path: None,
            staged_input_path: None,
            retained_output_path: None,
            maximum_document_bytes: None,
            lifetime: "Scratch documents and the installed application are discarded with the worker. Diagnostic evidence remains in the host run workspace.".into(),
        }
    } else {
        WsbMsiRecipeData {
            mode: "fixedDocumentAssessment".into(),
            guest_document_path: scenario.document_exercise.as_ref().map(|value| value.document_path.clone()),
            staged_input_path: None,
            retained_output_path: None,
            maximum_document_bytes: None,
            lifetime: "The fixed test document and installed application are discarded with the worker; receipt-bound assessment evidence remains in the host run workspace.".into(),
        }
    };
    let recipe = WsbMsiRecipe {
        preparation: artifacts.receipt.clone(),
        scenario: scenario.clone(),
        sandbox_config: render_config(&artifacts.wsb_plan)
            .map_err(|error| WsbPreparationError::Contract(error.to_string()))?,
        // The fixed native MSI launcher uses the executable's parent for CWD.
        working_directory: scenario.launch_path.rsplit_once('\\').ok_or_else(|| {
            WsbPreparationError::Contract("fixed launch path has no parent".into())
        })?.0.into(),
        application_profile_directory: aiw_provider_wsb::STANDARD_USER_PROFILE_PATH.into(),
        effective_launch_arguments: data.guest_document_path.iter().cloned().collect(),
        data,
        trust_deltas: artifacts.run_plan.trust_deltas.clone(),
        limitations: vec![
            "Inspection only: no installation, approval, execution, adaptation, or compatibility verdict. This JSON is not accepted as launch instructions.".into(),
            "Installation is privileged inside Windows Sandbox; the application runs as its fixed standard user. Sandbox configuration describes requested containment, not measured effective isolation.".into(),
            "No validation run is attached. Successful transfer evidence alone does not prove an adaptation comparison, boundary canaries, or deployment compatibility.".into(),
            "This snapshot binds one workspace and current provider/agent identities. Fresh replay requires preparation, drift checks, and a new bound approval. OS compatibility beyond preparation readiness remains unmeasured.".into(),
        ],
    };
    let value = serde_json::to_value(&recipe)
        .map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    Ok(WsbMsiRecipeInspection {
        schema_version: WSB_MSI_RECIPE_SCHEMA_VERSION.into(),
        recipe_sha256: hex::encode(Sha256::digest(bytes)),
        recipe,
    })
}

impl WsbMsiRecipeInspection {
    pub fn to_markdown(&self) -> String {
        // Pretty JSON retains exact argument arrays and mapping paths without
        // inventing shell quoting or hiding fields behind a prose summary.
        let json = serde_json::to_string_pretty(self).expect("recipe serialization is infallible");
        // Four-space indentation safely contains arbitrary strings, including
        // markdown fences in host paths or project metadata.
        let indented = json
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect::<String>();
        let details = [
            format!("Recipe SHA-256: {}", self.recipe_sha256),
            format!(
                "Application SHA-256: {}",
                self.recipe.scenario.application_sha256
            ),
            format!("Launch executable: {}", self.recipe.scenario.launch_path),
            format!(
                "Launch argument array: {}",
                serde_json::to_string(&self.recipe.effective_launch_arguments)
                    .expect("string array serializes")
            ),
            format!("Working directory: {}", self.recipe.working_directory),
            format!(
                "Application profile: {}",
                self.recipe.application_profile_directory
            ),
            format!("Data mode: {}", self.recipe.data.mode),
        ]
        .join("\n")
        .lines()
        .map(|line| format!("    {line}\n"))
        .collect::<String>();
        format!(
            "# Inspectable Windows Sandbox MSI recipe\n\nRead-only preparation snapshot. Installation is privileged inside the worker; the application runs as its fixed standard user.\n\n{details}\n{}\n\nReview the exact Sandbox XML below for all mappings and requested restrictions. This is not a validated adaptation or a portable launch authorization.\n\n## Complete inspection\n\n{indented}",
            self.recipe.data.lifetime
        )
    }
}
