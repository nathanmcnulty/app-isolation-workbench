//! Read-only comparison of three independently reverified local-settings trials.
//!
//! This module accepts the existing retained-report selectors, reopens every
//! selected report through the normal verifier, and compares only the fixed
//! baseline, candidate, and replay profiles. It neither starts a provider nor
//! grants any new execution authority.

use std::collections::BTreeSet;

use aiw_provider_wsb::{
    ApplicationFileEntry, ApplicationFileRoot, COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION,
    COMPILED_MSI_SCENARIO_SCHEMA_VERSION, CompiledMsiScenario, FilesystemCaptureIssue,
    NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT, NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE,
    NOTEPAD_PLUS_PLUS_MSI_PROFILE,
};
use aiw_schema::{Project, ProjectMetadata, RuntimeBoundary, ScenarioStep};
use schemars::JsonSchema;
use serde::Serialize;

use crate::WsbMsiReportSetInput;

pub const WSB_SETTINGS_COMPARISON_SCHEMA_VERSION: &str = "aiw.dev/wsb-settings-comparison/v0alpha2";

/// A retained, fixed-profile settings-placement comparison.
///
/// It reports three independently verified completed runs. It does not
/// establish a compatibility, packaging, effective-isolation, or authorization
/// conclusion.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbSettingsComparison {
    pub schema_version: String,
    pub baseline: WsbSettingsComparisonTrial,
    pub candidate: WsbSettingsComparisonTrial,
    pub replay: WsbSettingsComparisonTrial,
    pub comparable_evidence: WsbSettingsComparableEvidence,
    /// What the retained reports do not measure. These gaps must remain
    /// explicit rather than being inferred from matching setting files.
    pub boundary_coverage: WsbSettingsBoundaryCoverage,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbSettingsComparisonTrial {
    pub id: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub project_revision_sha256: String,
    pub request_sha256: String,
    pub scenario_sha256: String,
    pub receipt_sha256: String,
    pub evidence_root_hash: String,
    pub installer_sha256: String,
    pub guest_agent_sha256: String,
    pub config_sha256: String,
    pub compiled_scenario_schema: String,
    pub compiled_profile: String,
    pub settings_file: WsbSettingsComparisonFile,
    pub recorded_execution: crate::WsbMsiRecordedExecution,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbSettingsComparisonFile {
    pub root: ApplicationFileRoot,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbSettingsComparableEvidence {
    pub installer_sha256: String,
    pub guest_agent_sha256: String,
    pub runtime_boundary: RuntimeBoundary,
    pub provider_identity: WsbSettingsComparisonCoverage,
    pub requested_configuration: WsbSettingsComparisonCoverage,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum WsbSettingsComparisonCoverage {
    Unmeasured,
    MatchedRecordedIdentity,
    MatchedRequestedConfiguration,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbSettingsBoundaryCoverage {
    pub provider_identity: WsbSettingsComparisonCoverage,
    pub operating_system: WsbSettingsComparisonCoverage,
    pub effective_isolation: WsbSettingsComparisonCoverage,
    pub network: WsbSettingsComparisonCoverage,
    pub host_mappings: WsbSettingsComparisonCoverage,
    pub registry: WsbSettingsComparisonCoverage,
    pub descendant_processes: WsbSettingsComparisonCoverage,
    pub canaries: WsbSettingsComparisonCoverage,
}

/// Reverify exactly the baseline, candidate, and replay retained runs and
/// compare their fixed settings-placement observations.
#[cfg(windows)]
pub fn report_windows_sandbox_settings_comparison(
    input: &WsbMsiReportSetInput,
) -> Result<WsbSettingsComparison, String> {
    input.validate()?;
    if input.entries.len() != 3
        || input.entries.iter().map(|entry| entry.id.as_str()).ne([
            "baseline",
            "candidate",
            "replay",
        ])
    {
        return Err(
            "settings comparison requires exactly ordered baseline, candidate, and replay entries"
                .into(),
        );
    }

    let mut trials = Vec::with_capacity(3);
    for entry in &input.entries {
        let project = crate::report_set::read_report_project(&entry.project_path)
            .map_err(|reason| format!("{} project was not accepted: {reason:?}", entry.id))?;
        let report = crate::report_windows_sandbox_msi_run(
            &entry.workspace_root,
            &entry.run_id,
            &project,
            &entry.guest_agent_sha256,
        )
        .map_err(|error| format!("{} retained run was not accepted: {error}", entry.id))?;
        let crate::WsbMsiRunReport::CompletedAssessment(report) = report else {
            return Err(format!(
                "{} must be a completed non-interactive assessment",
                entry.id
            ));
        };
        if !report.recorded_cleanup_verified {
            return Err(format!(
                "{} does not record exact-session cleanup verification",
                entry.id
            ));
        }
        let compiled = aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario(
            &project,
            &report.scenario.scenario_id,
        )
        .map_err(|error| {
            format!(
                "{} project did not compile the retained scenario: {error}",
                entry.id
            )
        })?;
        let compiled_hash = compiled
            .canonical_sha256()
            .map_err(|_| format!("{} scenario could not be canonicalized", entry.id))?;
        if compiled_hash != report.scenario.scenario_sha256 {
            return Err(format!(
                "{} project scenario differs from the retained request",
                entry.id
            ));
        }
        let expected_root = if entry.id == "baseline" {
            ApplicationFileRoot::RoamingAppData
        } else {
            ApplicationFileRoot::LocalAppData
        };
        let settings_file = select_settings_file(
            &entry.id,
            report
                .behavior
                .as_ref()
                .ok_or_else(|| format!("{} has no verified functional evidence", entry.id))?,
            expected_root,
        )?;
        trials.push(VerifiedTrial {
            id: entry.id.clone(),
            project,
            compiled,
            report: *report,
            settings_file,
        });
    }

    let trials: [VerifiedTrial; 3] = trials
        .try_into()
        .map_err(|_| "settings comparison required three retained trials".to_owned())?;
    validate_trials(&trials)?;

    Ok(WsbSettingsComparison {
        schema_version: WSB_SETTINGS_COMPARISON_SCHEMA_VERSION.to_owned(),
        baseline: trial_report(&trials[0]),
        candidate: trial_report(&trials[1]),
        replay: trial_report(&trials[2]),
        comparable_evidence: WsbSettingsComparableEvidence {
            installer_sha256: trials[0].report.scenario.installer_sha256.clone(),
            guest_agent_sha256: trials[0].report.scenario.agent_sha256.clone(),
            runtime_boundary: trials[0].project.isolation_intent.runtime_boundary,
            requested_configuration: WsbSettingsComparisonCoverage::MatchedRequestedConfiguration,
            provider_identity: WsbSettingsComparisonCoverage::MatchedRecordedIdentity,
        },
        boundary_coverage: WsbSettingsBoundaryCoverage {
            provider_identity: WsbSettingsComparisonCoverage::MatchedRecordedIdentity,
            operating_system: WsbSettingsComparisonCoverage::Unmeasured,
            effective_isolation: WsbSettingsComparisonCoverage::Unmeasured,
            network: WsbSettingsComparisonCoverage::Unmeasured,
            host_mappings: WsbSettingsComparisonCoverage::Unmeasured,
            registry: WsbSettingsComparisonCoverage::Unmeasured,
            descendant_processes: WsbSettingsComparisonCoverage::Unmeasured,
            canaries: WsbSettingsComparisonCoverage::Unmeasured,
        },
        limitations: vec![
            "This report reuses three retained fixed workflow observations; it does not authorize execution, packaging, host mappings, or a retry.".into(),
            "Recorded provider identity and requested configuration match across these runs; current host state, operating-system equivalence, and effective enforcement remain unmeasured.".into(),
            "Boundary coverage for effective isolation, network, host mappings, registry, descendant processes, and canaries is unmeasured.".into(),
            "The fixed document workflow is not a complete adaptation validation or a general application compatibility verdict.".into(),
        ],
    })
}

struct VerifiedTrial {
    id: String,
    project: Project,
    compiled: CompiledMsiScenario,
    report: crate::WsbMsiAssessmentReport,
    settings_file: WsbSettingsComparisonFile,
}

fn trial_report(trial: &VerifiedTrial) -> WsbSettingsComparisonTrial {
    WsbSettingsComparisonTrial {
        id: trial.id.clone(),
        run_id: trial.report.run_id.clone(),
        sandbox_id: trial.report.scenario.sandbox_id.clone(),
        project_revision_sha256: trial.report.project_revision_sha256.clone(),
        request_sha256: trial.report.scenario.request_sha256.clone(),
        scenario_sha256: trial.report.scenario.scenario_sha256.clone(),
        receipt_sha256: trial.report.receipt_sha256.clone(),
        evidence_root_hash: trial.report.evidence_root_hash.clone(),
        installer_sha256: trial.report.scenario.installer_sha256.clone(),
        guest_agent_sha256: trial.report.scenario.agent_sha256.clone(),
        config_sha256: trial.report.scenario.config_sha256.clone(),
        compiled_scenario_schema: trial.compiled.schema_version.clone(),
        compiled_profile: trial.compiled.profile.clone(),
        settings_file: trial.settings_file.clone(),
        recorded_execution: trial.report.recorded_execution.clone(),
    }
}

fn select_settings_file(
    id: &str,
    behavior: &aiw_provider_wsb::ImportedMsiBehaviorEvidence,
    expected_root: ApplicationFileRoot,
) -> Result<WsbSettingsComparisonFile, String> {
    behavior
        .functional_exercise
        .validate()
        .map_err(|_| format!("{id} did not retain the fixed successful document exercise"))?;
    let relevant_roots = [
        ApplicationFileRoot::RoamingAppData,
        ApplicationFileRoot::LocalAppData,
    ];
    if behavior
        .after_exercise
        .issues
        .iter()
        .any(|issue| relevant_roots.contains(&issue.root))
    {
        return Err(format!(
            "{id} settings capture is incomplete in an application-data root"
        ));
    }

    let other_root = match expected_root {
        ApplicationFileRoot::RoamingAppData => ApplicationFileRoot::LocalAppData,
        ApplicationFileRoot::LocalAppData => ApplicationFileRoot::RoamingAppData,
        ApplicationFileRoot::Installation => {
            return Err("settings comparison has no installation-root placement".into());
        }
    };
    let expected = matching_config_files(&behavior.after_exercise.entries, expected_root);
    let other = matching_config_files(&behavior.after_exercise.entries, other_root);
    if expected.len() != 1 || !other.is_empty() || expected[0].size_bytes == 0 {
        return Err(format!(
            "{id} settings capture must contain exactly one nonempty config.xml only in the expected application-data root"
        ));
    }
    let file = expected[0];
    Ok(WsbSettingsComparisonFile {
        root: file.root,
        path: file.path.clone(),
        size_bytes: file.size_bytes,
        sha256: file.sha256.clone(),
    })
}

fn matching_config_files(
    entries: &[ApplicationFileEntry],
    root: ApplicationFileRoot,
) -> Vec<&ApplicationFileEntry> {
    entries
        .iter()
        .filter(|entry| entry.root == root && entry.path.eq_ignore_ascii_case("config.xml"))
        .collect()
}

fn validate_trials(trials: &[VerifiedTrial; 3]) -> Result<(), String> {
    if trials[0].id != "baseline" || trials[1].id != "candidate" || trials[2].id != "replay" {
        return Err("settings comparison trial labels changed after retained verification".into());
    }
    let all_distinct = |values: Vec<&str>| values.iter().collect::<BTreeSet<_>>().len() == 3;
    if !all_distinct(
        trials
            .iter()
            .map(|trial| trial.report.run_id.as_str())
            .collect(),
    ) || !all_distinct(
        trials
            .iter()
            .map(|trial| trial.report.scenario.request_sha256.as_str())
            .collect(),
    ) || !all_distinct(
        trials
            .iter()
            .map(|trial| trial.report.scenario.sandbox_id.as_str())
            .collect(),
    ) {
        return Err(
            "settings comparison requires distinct verified run, request, and sandbox identities"
                .into(),
        );
    }

    let baseline = &trials[0];
    if trials[1..]
        .iter()
        .any(|trial| trial.report.recorded_execution != baseline.report.recorded_execution)
    {
        return Err(
            "recorded provider identity, protocol, or requested Sandbox configuration differs"
                .into(),
        );
    }
    if baseline.compiled.schema_version != COMPILED_MSI_SCENARIO_SCHEMA_VERSION
        || baseline.compiled.profile != NOTEPAD_PLUS_PLUS_MSI_PROFILE
        || !baseline.compiled.launch_arguments.is_empty()
        || baseline.settings_file.root != ApplicationFileRoot::RoamingAppData
    {
        return Err("baseline is not the fixed no-argument automated profile".into());
    }
    for trial in &trials[1..] {
        if trial.compiled.schema_version != COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION
            || trial.compiled.profile != NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_PROFILE
            || trial.compiled.launch_arguments
                != [NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT.to_owned()]
            || trial.settings_file.root != ApplicationFileRoot::LocalAppData
        {
            return Err(format!(
                "{} is not the fixed local-settings automated profile",
                trial.id
            ));
        }
    }
    if trials[1].compiled != trials[2].compiled {
        return Err("candidate and replay compiled scenarios differ".into());
    }
    if trials
        .iter()
        .skip(1)
        .any(|trial| normalized_compiled(&trial.compiled) != baseline.compiled)
    {
        return Err(
            "baseline and local-settings scenarios differ beyond the fixed adaptation".into(),
        );
    }
    if trials
        .iter()
        .skip(1)
        .any(|trial| trial.project.isolation_intent != baseline.project.isolation_intent)
        || trials
            .iter()
            .skip(1)
            .any(|trial| trial.project.assertions != baseline.project.assertions)
    {
        return Err("comparison projects differ in requested isolation or assertions".into());
    }

    let metadata = baseline.project.metadata.clone();
    let baseline_project = normalized_project(
        &baseline.project,
        &baseline.compiled.scenario_id,
        false,
        &metadata,
    )?;
    for trial in &trials[1..] {
        if normalized_project(&trial.project, &trial.compiled.scenario_id, true, &metadata)?
            != baseline_project
        {
            return Err(
                "comparison projects differ beyond metadata and the fixed settings argument".into(),
            );
        }
    }

    if trials.iter().skip(1).any(|trial| {
        trial.report.scenario.installer_sha256 != baseline.report.scenario.installer_sha256
            || trial.report.scenario.agent_sha256 != baseline.report.scenario.agent_sha256
    }) {
        return Err(
            "comparison requires matching verified installer and guest-agent hashes".into(),
        );
    }
    Ok(())
}

fn normalized_compiled(scenario: &CompiledMsiScenario) -> CompiledMsiScenario {
    let mut normalized = scenario.clone();
    normalized.schema_version = COMPILED_MSI_SCENARIO_SCHEMA_VERSION.to_owned();
    normalized.profile = NOTEPAD_PLUS_PLUS_MSI_PROFILE.to_owned();
    normalized.launch_arguments.clear();
    normalized
}

fn normalized_project(
    project: &Project,
    scenario_id: &str,
    local_settings: bool,
    metadata: &ProjectMetadata,
) -> Result<Project, String> {
    let mut normalized = project.clone();
    normalized.metadata = metadata.clone();
    let scenario = normalized
        .scenarios
        .iter_mut()
        .find(|scenario| scenario.id == scenario_id)
        .ok_or_else(|| "comparison project lacks the compiled scenario".to_owned())?;
    // The human-readable description is not execution authority. Preserve all
    // scenario IDs, required flags, actions, and unrelated scenarios exactly.
    scenario.description.clear();
    let Some(ScenarioStep::Launch { arguments, .. }) = scenario.steps.get_mut(1) else {
        return Err("comparison scenario does not have the fixed launch step".into());
    };
    if local_settings {
        if arguments.as_slice() != [NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT.to_owned()] {
            return Err("comparison candidate does not use the exact settings argument".into());
        }
        arguments.clear();
    } else if !arguments.is_empty() {
        return Err("comparison baseline has launch arguments".into());
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution_context() -> crate::WsbMsiRecordedExecution {
        crate::WsbMsiRecordedExecution {
            provider: aiw_probe::BinaryIdentity {
                canonical_path: r"C:\Provider\wsb.exe".into(),
                sha256: "a".repeat(64),
                size_bytes: 123,
                version: Some("1".into()),
                signature_status: aiw_probe::ReadinessState::Available,
            },
            provider_package: aiw_probe::WindowsPackageIdentity {
                name: "provider".into(),
                full_name: "provider_1_x64".into(),
                family_name: "provider_family".into(),
                publisher: "publisher".into(),
                publisher_id: "id".into(),
                version: "1".into(),
                architecture: "x64".into(),
                signature_kind: "Store".into(),
                status_ok: true,
                install_location: r"C:\Provider".into(),
            },
            provider_protocol: aiw_probe::WindowsSandboxCliProtocol {
                cli_version: "1".into(),
                protocol: "test".into(),
                list_schema: "test".into(),
            },
            normalized_sandbox_config_sha256: "b".repeat(64),
        }
    }
    use sha2::Digest as _;

    fn project(local_settings: bool) -> Project {
        let mut project: Project = serde_yaml::from_slice(include_bytes!(
            "../../../examples/notepad-plus-plus-msi.aiw.yaml"
        ))
        .unwrap();
        if local_settings {
            let ScenarioStep::Launch { arguments, .. } = &mut project.scenarios[0].steps[1] else {
                panic!("example launch");
            };
            arguments.push(NOTEPAD_PLUS_PLUS_LOCAL_SETTINGS_ARGUMENT.to_owned());
        }
        project
    }

    fn compiled(local_settings: bool) -> CompiledMsiScenario {
        let project = project(local_settings);
        aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario(&project, "install-launch-close")
            .unwrap()
    }

    fn trial(id: &str, local_settings: bool, marker: char) -> VerifiedTrial {
        let mut project = project(local_settings);
        if local_settings {
            project.scenarios[0].description = "Local settings trial".into();
        }
        let compiled = compiled(local_settings);
        let hash = marker.to_string().repeat(64);
        let root = if local_settings {
            ApplicationFileRoot::LocalAppData
        } else {
            ApplicationFileRoot::RoamingAppData
        };
        let scenario = aiw_provider_wsb::ImportedMsiScenarioResult {
            schema_version: "aiw.dev/windows-sandbox-imported-msi-scenario-result/v0alpha1".into(),
            run_id: format!("run-{marker}"),
            sandbox_id: format!("00000000-0000-0000-0000-00000000000{marker}"),
            config_sha256: hash.clone(),
            request_sha256: hash.clone(),
            agent_sha256: "a".repeat(64),
            scenario_id: compiled.scenario_id.clone(),
            scenario_sha256: compiled.canonical_sha256().unwrap(),
            installer_sha256: compiled.application_sha256.clone(),
            status: aiw_provider_wsb::ImportedMsiScenarioStatus::Succeeded,
            install_exit_code: 0,
            launch_process_id: 1,
            launch_exit_code: 0,
            process_observed: true,
            graceful_close_requested: true,
            process_closed: true,
            document_transfer: None,
        };
        VerifiedTrial {
            id: id.into(),
            project,
            compiled,
            report: crate::WsbMsiAssessmentReport {
                schema_version: "test".into(),
                recorded_execution: execution_context(),
                run_id: scenario.run_id.clone(),
                project_revision_sha256: hash.clone(),
                outcome: aiw_orchestrator::RunOutcome::InsufficientEvidence,
                recorded_cleanup_verified: true,
                download_metadata_policy: None,
                receipt_sha256: hash.clone(),
                evidence_root_hash: hash.clone(),
                scenario,
                application_token: None,
                standard_user_context: None,
                behavior: None,
                stage_progress: None,
                installation_file_changes: None,
                exercise_file_changes: None,
                registry_evidence: None,
                product_registration: None,
                installation_registry_changes: None,
                exercise_registry_changes: None,
                requested_assertions: aiw_schema::Assertions::default(),
                requested_isolation: aiw_schema::IsolationIntent::default(),
                unmeasured_scenarios: vec![],
                missing_evidence: vec![],
            },
            settings_file: WsbSettingsComparisonFile {
                root,
                path: "config.xml".into(),
                size_bytes: 1,
                sha256: hash,
            },
        }
    }

    fn valid_trials() -> [VerifiedTrial; 3] {
        [
            trial("baseline", false, '1'),
            trial("candidate", true, '2'),
            trial("replay", true, '3'),
        ]
    }

    #[test]
    fn accepts_only_the_fixed_comparable_profiles() {
        validate_trials(&valid_trials()).unwrap();
    }

    #[test]
    fn rejects_policy_drift_and_reused_identity() {
        let mut policy_drift = valid_trials();
        policy_drift[1]
            .project
            .assertions
            .require_target_token_evidence = false;
        assert!(validate_trials(&policy_drift).is_err());

        let mut reused_identity = valid_trials();
        reused_identity[2].report.scenario.request_sha256 =
            reused_identity[1].report.scenario.request_sha256.clone();
        assert!(validate_trials(&reused_identity).is_err());
    }

    #[test]
    fn rejects_recorded_provider_and_configuration_drift() {
        for change in 0..4 {
            let mut trials = valid_trials();
            let context = &mut trials[2].report.recorded_execution;
            match change {
                0 => context.provider.sha256 = "c".repeat(64),
                1 => context.provider_package.version = "different".into(),
                2 => context.provider_protocol.protocol = "different".into(),
                _ => context.normalized_sandbox_config_sha256 = "c".repeat(64),
            }
            assert!(validate_trials(&trials).is_err());
        }
    }

    #[test]
    fn rejects_incomplete_or_nonexclusive_settings_capture() {
        let entry = |root| ApplicationFileEntry {
            root,
            path: "config.xml".into(),
            size_bytes: 1,
            sha256: "a".repeat(64),
        };
        let behavior = |entries, issues| aiw_provider_wsb::ImportedMsiBehaviorEvidence {
            schema_version: aiw_provider_wsb::IMPORTED_MSI_BEHAVIOR_SCHEMA.into(),
            run_id: "run".into(),
            sandbox_id: "00000000-0000-0000-0000-000000000001".into(),
            request_sha256: "a".repeat(64),
            scenario_sha256: "b".repeat(64),
            functional_exercise: aiw_provider_wsb::FunctionalExercise {
                opened_document: true,
                saved_document: true,
                expected_sha256: hex::encode(sha2::Sha256::digest(
                    aiw_provider_wsb::DOCUMENT_EXPECTED_TEXT.as_bytes(),
                )),
                observed_sha256: hex::encode(sha2::Sha256::digest(
                    aiw_provider_wsb::DOCUMENT_EXPECTED_TEXT.as_bytes(),
                )),
            },
            before_install: aiw_provider_wsb::ApplicationFilesystemSnapshot {
                entries: vec![],
                issues: vec![],
            },
            after_install: aiw_provider_wsb::ApplicationFilesystemSnapshot {
                entries: vec![],
                issues: vec![],
            },
            after_exercise: aiw_provider_wsb::ApplicationFilesystemSnapshot { entries, issues },
        };
        let incomplete = behavior(
            vec![entry(ApplicationFileRoot::RoamingAppData)],
            vec![FilesystemCaptureIssue {
                root: ApplicationFileRoot::LocalAppData,
                reason: aiw_provider_wsb::FilesystemCaptureIssueReason::Unreadable,
            }],
        );
        let mut valid = behavior(vec![entry(ApplicationFileRoot::RoamingAppData)], vec![]);
        assert!(
            select_settings_file("baseline", &valid, ApplicationFileRoot::RoamingAppData).is_ok()
        );
        valid.functional_exercise.saved_document = false;
        assert!(
            select_settings_file("baseline", &valid, ApplicationFileRoot::RoamingAppData).is_err()
        );
        valid.functional_exercise.saved_document = true;
        valid.functional_exercise.observed_sha256 = "0".repeat(64);
        assert!(
            select_settings_file("baseline", &valid, ApplicationFileRoot::RoamingAppData).is_err()
        );
        assert!(
            select_settings_file("baseline", &incomplete, ApplicationFileRoot::RoamingAppData)
                .is_err()
        );

        let nonexclusive = behavior(
            vec![
                entry(ApplicationFileRoot::RoamingAppData),
                entry(ApplicationFileRoot::LocalAppData),
            ],
            vec![],
        );
        assert!(
            select_settings_file(
                "baseline",
                &nonexclusive,
                ApplicationFileRoot::RoamingAppData
            )
            .is_err()
        );
    }
}
