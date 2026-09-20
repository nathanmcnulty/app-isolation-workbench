//! Evidence-backed preflight for the fixed local-settings replay. Profiles
//! select retained evidence; they never replace preparation or run approval.

use aiw_evidence::canonical_json_bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::settings_comparison::WsbSettingsComparisonCoverage;
use crate::{WsbMsiReportSetInput, WsbSettingsComparison};

const PROFILE_SCHEMA: &str = "aiw.dev/wsb-local-settings-launch-profile/v0alpha1";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbLaunchProfile {
    pub schema_version: String,
    pub evidence: WsbMsiReportSetInput,
    pub comparison_sha256: String,
    pub application_sha256: String,
    pub project_revision_sha256: String,
    pub scenario_sha256: String,
    pub guest_agent_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbLaunchProfileExport {
    pub profile_sha256: String,
    pub profile: WsbLaunchProfile,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbLaunchPreflight {
    pub schema_version: String,
    pub profile_sha256: String,
    pub preparation_sha256: String,
    pub recipe: crate::WsbMsiRecipeInspection,
    pub next_step: String,
    pub limitations: Vec<String>,
}

fn digest(value: &impl Serialize) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|e| e.to_string())?;
    let bytes = canonical_json_bytes(&value).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn from_comparison(
    input: &WsbMsiReportSetInput,
    comparison: &WsbSettingsComparison,
) -> Result<WsbLaunchProfileExport, String> {
    if !matches!(
        comparison.boundary_coverage.operating_system,
        WsbSettingsComparisonCoverage::MatchedRecordedVersion
    ) || !matches!(
        comparison.boundary_coverage.canaries,
        WsbSettingsComparisonCoverage::MeasuredStandardUserFileAclOnly
    ) {
        return Err("launch profile requires recorded OS versions and measured file ACL controls in all three trials".into());
    }
    let trial = &comparison.replay;
    let profile = WsbLaunchProfile {
        schema_version: PROFILE_SCHEMA.into(),
        evidence: input.clone(),
        comparison_sha256: digest(comparison)?,
        application_sha256: trial.installer_sha256.clone(),
        project_revision_sha256: trial.project_revision_sha256.clone(),
        scenario_sha256: trial.scenario_sha256.clone(),
        guest_agent_sha256: trial.guest_agent_sha256.clone(),
    };
    Ok(WsbLaunchProfileExport {
        profile_sha256: digest(&profile)?,
        profile,
    })
}

#[cfg(windows)]
pub fn create_windows_sandbox_launch_profile(
    input: &WsbMsiReportSetInput,
) -> Result<WsbLaunchProfileExport, String> {
    let comparison = crate::report_windows_sandbox_settings_comparison(input)?;
    from_comparison(input, &comparison)
}

pub(crate) fn verify_profile_hash(
    profile: &WsbLaunchProfileExport,
    expected: &str,
) -> Result<(), String> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || profile.profile.schema_version != PROFILE_SCHEMA
        || profile.profile_sha256 != expected
        || digest(&profile.profile)? != expected
    {
        return Err("launch profile differs from the independently retained profile hash".into());
    }
    profile.profile.evidence.validate()
}

#[cfg(windows)]
pub(crate) fn reverify_profile(
    profile: &WsbLaunchProfileExport,
    expected: &str,
) -> Result<WsbSettingsComparison, String> {
    verify_profile_hash(profile, expected)?;
    let comparison = crate::report_windows_sandbox_settings_comparison(&profile.profile.evidence)?;
    if from_comparison(&profile.profile.evidence, &comparison)?.profile_sha256 != expected {
        return Err("retained validation evidence changed; create and review a new profile".into());
    }
    Ok(comparison)
}

#[cfg(windows)]
pub(crate) fn verify_bound_profile(artifacts: &crate::PreparedWsbArtifacts) -> Result<(), String> {
    if let Some(profile) = artifacts
        .receipt
        .msi
        .as_ref()
        .and_then(|msi| msi.launch_profile.as_ref())
    {
        let comparison = reverify_profile(profile, &profile.profile_sha256)?;
        match_preparation(
            &profile.profile,
            &comparison.replay.recorded_execution,
            artifacts,
        )?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn check_windows_sandbox_launch_profile(
    profile: &WsbLaunchProfileExport,
    expected: &str,
    root: &std::path::Path,
    project: &aiw_schema::Project,
    guest_hash: &str,
) -> Result<WsbLaunchPreflight, String> {
    // Check the trusted hash before following caller-supplied evidence paths.
    let comparison = reverify_profile(profile, expected)?;
    let artifacts = crate::verify_windows_sandbox_preparation(root, project, guest_hash)
        .map_err(|e| e.to_string())?;
    let current_os = aiw_windows_platform::observe_windows_version()?;
    artifacts
        .receipt
        .verify_host_os_version(Some(&current_os))
        .map_err(|e| e.to_string())?;
    match_preparation(
        &profile.profile,
        &comparison.replay.recorded_execution,
        &artifacts,
    )?;
    Ok(WsbLaunchPreflight {
        schema_version: "aiw.dev/wsb-launch-preflight/v0alpha1".into(),
        profile_sha256: expected.into(),
        preparation_sha256: digest(&artifacts.receipt)?,
        recipe: crate::packaging_recipe::inspect_artifacts(&artifacts).map_err(|e| e.to_string())?,
        next_step: preflight_next_step(
            artifacts.receipt.msi.as_ref().and_then(|msi| msi.launch_profile.as_ref()).map(|bound| bound.profile_sha256.as_str()),
            expected,
        ).into(),
        limitations: vec![
            "Only the fixed Notepad++ local-settings document workflow and guest standard-user file ACL controls were validated. Other functions and isolation boundaries remain unmeasured.".into(),
            "This is a point-in-time check. Normal import, approval, and start must recheck preparation authority; this output is not accepted as execution authority.".into(),
            "The installed application and settings are discarded with the Sandbox. Persistent data and general installer conversion are unsupported.".into(),
            "Retained evidence must remain accessible on this host. Guest OS and workflow results must be verified after the new run; no cross-host deployment claim is made.".into(),
        ],
    })
}

#[cfg(any(windows, test))]
fn preflight_next_step(bound_hash: Option<&str>, checked_hash: &str) -> &'static str {
    if bound_hash == Some(checked_hash) {
        "This preparation binds the checked profile. Import it and obtain a fresh run approval. Start re-verifies the bound profile; preflight does not approve or launch a worker."
    } else {
        "This preparation does not bind the checked profile. Prepare a new workspace using run prepare-wsb-msi with --launch-profile and --launch-profile-sha256 for this profile, then import it and obtain a fresh run approval. This preflight alone does not bind profile revalidation into execution."
    }
}

pub(crate) fn match_preparation(
    profile: &WsbLaunchProfile,
    recorded: &crate::WsbMsiRecordedExecution,
    artifacts: &crate::PreparedWsbArtifacts,
) -> Result<(), String> {
    artifacts.validate().map_err(|e| e.to_string())?;
    let msi = artifacts
        .receipt
        .msi
        .as_ref()
        .ok_or("MSI preparation required")?;
    for (name, actual, expected) in [
        (
            "application",
            &msi.staged_payload.sha256,
            &profile.application_sha256,
        ),
        (
            "project",
            &artifacts.receipt.project_revision_sha256,
            &profile.project_revision_sha256,
        ),
        ("scenario", &msi.scenario_sha256, &profile.scenario_sha256),
        (
            "guest agent",
            &artifacts.receipt.guest_agent.sha256,
            &profile.guest_agent_sha256,
        ),
    ] {
        if actual != expected {
            return Err(format!("{name} drift requires a new validation profile"));
        }
    }
    let execution =
        crate::assessment_report::recorded_execution(artifacts).map_err(|e| e.to_string())?;
    if &execution != recorded {
        return Err("provider, OS, required observations, or Sandbox configuration drift requires revalidation".into());
    }
    Ok(())
}

impl WsbLaunchProfileExport {
    pub fn to_markdown(&self) -> String {
        format!(
            "# Reusable Sandbox trial profile\n\nValidated: Notepad++ install, open, edit, save, close; local settings placement; guest standard-user file ACL controls.\n\nProfile SHA-256: `{}`\n\nApplication SHA-256: `{}`\n\nBind this profile with `run prepare-wsb-msi --launch-profile <profile.json> --launch-profile-sha256 <independently-retained-hash>` alongside the normal preparation options. Import that preparation and obtain a fresh approval. `package check-wsb-launch-profile` can inspect a preparation but does not add a profile binding to it. Preparation and start reverify the original three trials.\n\nSession data is discarded. Other application functions, broader containment, and cross-host deployment remain unvalidated. This profile supports replay of the fixed assessment; it does not enable arbitrary interactive launch.\n",
            self.profile_sha256, self.profile.application_sha256
        )
    }
}

impl WsbLaunchPreflight {
    pub fn to_markdown(&self) -> String {
        let mut text = format!(
            "# Sandbox replay preflight passed\n\nApplication, scenario, agent, provider, recorded host version, and requested Sandbox configuration match the validated replay.\n\n{}\n\n",
            self.next_step
        );
        for limitation in &self.limitations {
            text.push_str(&format!("- {limitation}\n"));
        }
        text.push_str(&format!("\n{}", self.recipe.to_markdown()));
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_advice_requires_the_checked_profile_to_be_bound() {
        for bound in [None, Some("different-profile")] {
            let advice = preflight_next_step(bound, "checked-profile");
            assert!(advice.contains("does not bind the checked profile"));
            assert!(advice.contains("--launch-profile-sha256"));
        }
        let advice = preflight_next_step(Some("checked-profile"), "checked-profile");
        assert!(advice.contains("This preparation binds the checked profile"));
        assert!(advice.contains("fresh run approval"));
    }

    pub(crate) fn profile() -> WsbLaunchProfileExport {
        let profile = WsbLaunchProfile {
            schema_version: PROFILE_SCHEMA.into(),
            evidence: WsbMsiReportSetInput {
                schema_version: crate::WSB_MSI_REPORT_SET_INPUT_SCHEMA.into(),
                entries: vec![crate::WsbMsiReportSetEntry {
                    id: "baseline".into(),
                    run_id: "run-one".into(),
                    workspace_root: std::env::temp_dir(),
                    project_path: std::env::temp_dir().join("project.json"),
                    guest_agent_sha256: "a".repeat(64),
                }],
            },
            comparison_sha256: "b".repeat(64),
            application_sha256: "c".repeat(64),
            project_revision_sha256: "d".repeat(64),
            scenario_sha256: "e".repeat(64),
            guest_agent_sha256: "a".repeat(64),
        };
        WsbLaunchProfileExport {
            profile_sha256: digest(&profile).unwrap(),
            profile,
        }
    }

    #[test]
    fn launch_profile_hash_binds_evidence_selectors_and_claims() {
        let original = profile();
        let expected = original.profile_sha256.clone();
        verify_profile_hash(&original, &expected).unwrap();
        for field in [
            "schemaVersion",
            "comparisonSha256",
            "applicationSha256",
            "projectRevisionSha256",
            "scenarioSha256",
            "guestAgentSha256",
        ] {
            let mut value = serde_json::to_value(&original).unwrap();
            value["profile"][field] = serde_json::json!("f".repeat(64));
            let mut changed: WsbLaunchProfileExport = serde_json::from_value(value).unwrap();
            changed.profile_sha256 = digest(&changed.profile).unwrap();
            assert!(verify_profile_hash(&changed, &expected).is_err(), "{field}");
        }
        let mut changed = original.clone();
        changed.profile.evidence.entries[0].workspace_root = std::env::temp_dir().join("other");
        changed.profile_sha256 = digest(&changed.profile).unwrap();
        assert!(verify_profile_hash(&changed, &expected).is_err());
        assert!(verify_profile_hash(&original, &"A".repeat(64)).is_err());
    }

    #[test]
    fn launch_profile_rejects_unknown_execution_fields() {
        let mut value = serde_json::to_value(profile()).unwrap();
        value["profile"]["command"] = serde_json::json!("arbitrary.exe");
        assert!(serde_json::from_value::<WsbLaunchProfileExport>(value).is_err());
    }
}
