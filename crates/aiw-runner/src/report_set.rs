//! Bounded, read-only summaries of explicitly selected retained MSI runs.
use std::{collections::BTreeSet, path::PathBuf};

use aiw_provider_wsb::{FilesystemDiffKind, FilesystemSnapshotDiffResult, MsiStageResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{FailureProgressEvidence, WsbMsiRunReport};

pub const WSB_MSI_REPORT_SET_INPUT_SCHEMA: &str = "aiw.dev/wsb-msi-report-set-input/v0alpha1";
pub const WSB_MSI_REPORT_SET_SCHEMA: &str = "aiw.dev/wsb-msi-report-set/v0alpha1";

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbMsiReportSetInput {
    pub schema_version: String,
    pub entries: Vec<WsbMsiReportSetEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbMsiReportSetEntry {
    pub id: String,
    pub workspace_root: PathBuf,
    pub run_id: String,
    pub project_path: PathBuf,
    pub guest_agent_sha256: String,
}

impl WsbMsiReportSetInput {
    pub fn validate(&self) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        if self.schema_version != WSB_MSI_REPORT_SET_INPUT_SCHEMA
            || self.entries.is_empty()
            || self.entries.len() > 32
        {
            return Err("report set requires the supported schema and 1-32 entries".into());
        }
        for entry in &self.entries {
            let safe_id = |s: &str| {
                !s.is_empty()
                    && s.len() <= 128
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            };
            if !safe_id(&entry.id)
                || !safe_id(&entry.run_id)
                || !ids.insert(entry.id.to_ascii_lowercase())
                || entry.guest_agent_sha256.len() != 64
                || !entry
                    .guest_agent_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("report set contains an invalid or duplicate ID or guest hash".into());
            }
            for path in [&entry.workspace_root, &entry.project_path] {
                let Some(text) = path.to_str() else {
                    return Err("report set paths must be Unicode".into());
                };
                if !path.is_absolute() || text.len() > 32_767 || text.chars().any(char::is_control)
                {
                    return Err("report set paths must be bounded absolute paths".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbMsiReportSet {
    pub schema_version: String,
    pub entries: Vec<WsbMsiReportSetRow>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbMsiReportSetRow {
    pub id: String,
    pub result: WsbMsiReportSetResult,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "status", content = "summary", rename_all = "camelCase")]
pub enum WsbMsiReportSetResult {
    CompletedScenario(Box<WsbMsiReportSetSummary>),
    UnsuccessfulAttempt(Box<WsbMsiReportSetSummary>),
    Unavailable(ReportSetUnavailableReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ReportSetUnavailableReason {
    ProjectUnreadable,
    ProjectInvalid,
    EvidenceRejected,
    InteractiveSessionNotAssessment,
    DuplicateRun,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbMsiReportSetSummary {
    pub application_name: String,
    pub run_id: String,
    pub installer_sha256: String,
    pub guest_agent_sha256: String,
    pub scenario_sha256: String,
    pub project_revision_sha256: String,
    pub request_sha256: String,
    pub recorded_outcome: aiw_orchestrator::RunOutcome,
    pub recorded_cleanup_verified: bool,
    pub application_token: Option<aiw_provider_wsb::ImportedMsiApplicationToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_registration: Option<aiw_provider_wsb::ImportedMsiProductRegistrationEvidence>,
    pub failure_evidence: Option<ReportSetFailureEvidence>,
    pub receipt_sha256: Option<String>,
    pub evidence_root_hash: Option<String>,
    pub functions: ReportSetFunctions,
    pub stage_progress: Option<Vec<MsiStageResult>>,
    pub installation_files: Option<ReportSetFileChanges>,
    pub exercise_files: Option<ReportSetFileChanges>,
    pub installation_registry: Option<ReportSetRegistryChanges>,
    pub exercise_registry: Option<ReportSetRegistryChanges>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportSetRegistryChanges {
    pub key_changes: usize,
    pub value_changes: usize,
    pub incomplete_scopes: Vec<aiw_provider_wsb::RegistryScope>,
}

fn registry_summary(diff: &aiw_provider_wsb::RegistrySnapshotDiff) -> ReportSetRegistryChanges {
    ReportSetRegistryChanges {
        key_changes: diff.key_changes.len(),
        value_changes: diff.value_changes.len(),
        incomplete_scopes: diff.incomplete_scopes.clone(),
    }
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ReportSetFailureEvidence {
    Verified,
    Absent,
    Rejected,
}

/// None means no verified result for this function, including on failed runs.
#[derive(Debug, Clone, Default, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportSetFunctions {
    pub install: Option<bool>,
    pub launch: Option<bool>,
    pub open_document: Option<bool>,
    pub edit_save_document: Option<bool>,
    pub close: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportSetFileChanges {
    pub added: usize,
    pub modified: usize,
    pub removed: usize,
    pub incomplete_roots: Vec<aiw_provider_wsb::ApplicationFileRoot>,
}

fn file_summary(diff: &FilesystemSnapshotDiffResult) -> ReportSetFileChanges {
    let count = |kind| diff.diffs.iter().filter(|d| d.kind == kind).count();
    ReportSetFileChanges {
        added: count(FilesystemDiffKind::Added),
        modified: count(FilesystemDiffKind::Modified),
        removed: count(FilesystemDiffKind::Removed),
        incomplete_roots: diff.incomplete_roots.clone(),
    }
}

fn summarize(name: String, report: WsbMsiRunReport) -> WsbMsiReportSetResult {
    match report {
        WsbMsiRunReport::InteractiveSession(_) => WsbMsiReportSetResult::Unavailable(
            ReportSetUnavailableReason::InteractiveSessionNotAssessment,
        ),
        WsbMsiRunReport::CompletedAssessment(report) => {
            let scenario = &report.scenario;
            WsbMsiReportSetResult::CompletedScenario(Box::new(WsbMsiReportSetSummary {
                application_name: name,
                run_id: report.run_id,
                installer_sha256: scenario.installer_sha256.clone(),
                guest_agent_sha256: scenario.agent_sha256.clone(),
                scenario_sha256: scenario.scenario_sha256.clone(),
                project_revision_sha256: report.project_revision_sha256,
                request_sha256: scenario.request_sha256.clone(),
                recorded_outcome: report.outcome,
                recorded_cleanup_verified: report.recorded_cleanup_verified,
                application_token: report.application_token,
                product_registration: report.product_registration,
                failure_evidence: None,
                receipt_sha256: Some(report.receipt_sha256),
                evidence_root_hash: Some(report.evidence_root_hash),
                functions: ReportSetFunctions {
                    install: Some(scenario.install_exit_code == 0),
                    launch: Some(scenario.process_observed),
                    open_document: report
                        .behavior
                        .as_ref()
                        .map(|b| b.functional_exercise.opened_document),
                    edit_save_document: report
                        .behavior
                        .as_ref()
                        .map(|b| b.functional_exercise.saved_document),
                    close: Some(scenario.process_closed),
                },
                stage_progress: report.stage_progress.map(|p| p.stages),
                installation_files: report.installation_file_changes.as_ref().map(file_summary),
                exercise_files: report.exercise_file_changes.as_ref().map(file_summary),
                installation_registry: report
                    .installation_registry_changes
                    .as_ref()
                    .map(registry_summary),
                exercise_registry: report
                    .exercise_registry_changes
                    .as_ref()
                    .map(registry_summary),
            }))
        }
        WsbMsiRunReport::UnsuccessfulAttempt(report) => {
            if report.interactive_session_seconds.is_some() {
                return WsbMsiReportSetResult::Unavailable(
                    ReportSetUnavailableReason::InteractiveSessionNotAssessment,
                );
            }
            let progress = match &report.failure_progress {
                FailureProgressEvidence::Verified(progress) => Some(progress),
                _ => None,
            };
            WsbMsiReportSetResult::UnsuccessfulAttempt(Box::new(WsbMsiReportSetSummary {
                application_name: name,
                run_id: report.run_id,
                installer_sha256: report.installer_sha256,
                guest_agent_sha256: report.guest_agent_sha256,
                scenario_sha256: report.scenario_sha256,
                project_revision_sha256: report.project_revision_sha256,
                request_sha256: report.request_sha256,
                recorded_outcome: report.outcome,
                recorded_cleanup_verified: report.recorded_cleanup_verified,
                application_token: None,
                product_registration: None,
                failure_evidence: Some(match &report.failure_progress {
                    FailureProgressEvidence::Verified(_) => ReportSetFailureEvidence::Verified,
                    FailureProgressEvidence::Absent => ReportSetFailureEvidence::Absent,
                    FailureProgressEvidence::Rejected => ReportSetFailureEvidence::Rejected,
                }),
                receipt_sha256: progress.map(|p| p.receipt_sha256.clone()),
                evidence_root_hash: progress.map(|p| p.evidence_root_hash.clone()),
                functions: ReportSetFunctions::default(),
                stage_progress: progress.map(|p| p.attempt.progress.stages.clone()),
                installation_files: progress
                    .and_then(|p| p.installation_file_changes.as_ref())
                    .map(file_summary),
                exercise_files: progress
                    .and_then(|p| p.exercise_file_changes.as_ref())
                    .map(file_summary),
                installation_registry: progress
                    .and_then(|p| p.installation_registry_changes.as_ref())
                    .map(registry_summary),
                exercise_registry: progress
                    .and_then(|p| p.exercise_registry_changes.as_ref())
                    .map(registry_summary),
            }))
        }
    }
}

#[cfg(windows)]
pub fn report_windows_sandbox_msi_set(
    input: &WsbMsiReportSetInput,
) -> Result<WsbMsiReportSet, String> {
    input.validate()?;
    let mut seen = BTreeSet::new();
    let mut entries = Vec::with_capacity(input.entries.len());
    for entry in &input.entries {
        let read = || -> Result<WsbMsiReportSetResult, ReportSetUnavailableReason> {
            let project = read_report_project(&entry.project_path)?;
            let report = crate::report_windows_sandbox_msi_run(
                &entry.workspace_root,
                &entry.run_id,
                &project,
                &entry.guest_agent_sha256,
            )
            .map_err(|_| ReportSetUnavailableReason::EvidenceRejected)?;
            Ok(summarize(project.metadata.name, report))
        };
        let mut result = read().unwrap_or_else(WsbMsiReportSetResult::Unavailable);
        if let WsbMsiReportSetResult::CompletedScenario(summary)
        | WsbMsiReportSetResult::UnsuccessfulAttempt(summary) = &result
        {
            // Compare verified run identity, not caller path spelling or labels.
            if !seen.insert((summary.run_id.clone(), summary.request_sha256.clone())) {
                result =
                    WsbMsiReportSetResult::Unavailable(ReportSetUnavailableReason::DuplicateRun);
            }
        }
        entries.push(WsbMsiReportSetRow {
            id: entry.id.clone(),
            result,
        });
    }
    Ok(WsbMsiReportSet {
        schema_version: WSB_MSI_REPORT_SET_SCHEMA.into(),
        entries,
    })
}

impl WsbMsiReportSet {
    /// Rendering does not verify caller-constructed values; use the retained-run reader first.
    pub fn to_markdown(&self) -> String {
        fn cell(value: &str) -> String {
            value
                .chars()
                .flat_map(|c| match c {
                    '&' => "&amp;".chars().collect::<Vec<_>>(),
                    '<' => "&lt;".chars().collect(),
                    '>' => "&gt;".chars().collect(),
                    '|' => "&#124;".chars().collect(),
                    '\\' | '`' | '*' | '_' | '[' | ']' => vec!['\\', c],
                    c if c.is_control() => vec![' '],
                    c => vec![c],
                })
                .collect()
        }
        let observed = |value| match value {
            Some(true) => "Passed",
            Some(false) => "Failed",
            None => "Unmeasured",
        };
        let mut out = "# Retained Windows Sandbox MSI run results\n\nEach entry is independently reverified from its retained workspace. Function results are guest-reported observations of the fixed workflow. This set does not establish comparison eligibility, an isolation verdict, or general application compatibility. Cleanup is a historical record, not a current-session query.\n\n| Entry | Application | Scenario | Install | Launch | Open document | Edit/save | Close |\n|---|---|---|---|---|---|---|---|\n".to_owned();
        for row in &self.entries {
            match &row.result {
                WsbMsiReportSetResult::CompletedScenario(s) | WsbMsiReportSetResult::UnsuccessfulAttempt(s) => {
                    let status = if matches!(row.result, WsbMsiReportSetResult::CompletedScenario(_)) { "Completed" } else { "Unsuccessful" };
                    let f = &s.functions;
                    out.push_str(&format!("| {} | {} | {status} | {} | {} | {} | {} | {} |\n", cell(&row.id), cell(&s.application_name), observed(f.install), observed(f.launch), observed(f.open_document), observed(f.edit_save_document), observed(f.close)));
                }
                WsbMsiReportSetResult::Unavailable(reason) => out.push_str(&format!("| {} | Unverified | Unavailable: {reason:?} | Unmeasured | Unmeasured | Unmeasured | Unmeasured | Unmeasured |\n", cell(&row.id))),
            }
        }
        for row in &self.entries {
            let (WsbMsiReportSetResult::CompletedScenario(s)
            | WsbMsiReportSetResult::UnsuccessfulAttempt(s)) = &row.result
            else {
                continue;
            };
            out.push_str(&format!("\n## {}\n\nRun: {}. Recorded outcome: {:?}. Cleanup recorded verified: {}.\n\nInstaller SHA-256: `{}`\n\nScenario SHA-256: `{}`\n\nGuest SHA-256: `{}`\n\nReceipt SHA-256: {}\n", cell(&row.id), cell(&s.run_id), s.recorded_outcome, s.recorded_cleanup_verified, cell(&s.installer_sha256), cell(&s.scenario_sha256), cell(&s.guest_agent_sha256), s.receipt_sha256.as_deref().map(cell).unwrap_or_else(|| "Unmeasured or rejected".into())));
            if let Some(token) = &s.application_token {
                out.push_str(&format!("\nObserved application token: integrity {:?}; elevated {}; AppContainer {}. This guest observation does not independently verify an isolation boundary.\n", token.token.integrity.level, token.token.is_elevated, token.token.is_app_container));
            } else {
                out.push_str("\nApplication token: unmeasured.\n");
            }
            if let Some(registration) = &s.product_registration {
                out.push_str(&format!(
                    "\nMachine product-registration observation for `{}`: before installation {}; after installation {}. This is scoped machine state metadata, not a dependency or isolation claim.\n",
                    cell(&registration.product_code),
                    crate::assessment_report_markdown::product_state_label(&registration.before_install),
                    crate::assessment_report_markdown::product_state_label(&registration.after_install),
                ));
            } else {
                out.push_str("\nMachine product-registration observation: unmeasured.\n");
            }
            if let Some(status) = s.failure_evidence {
                out.push_str(&format!("\nFailed-attempt evidence: {status:?}. Completed stages do not verify the full application workflow.\n"));
            }
            if let Some(stages) = &s.stage_progress {
                out.push_str("\n| Stage | Observation |\n|---|---|\n");
                for stage in stages {
                    out.push_str(&format!("| {:?} | {:?} |\n", stage.stage, stage.status));
                }
            } else {
                out.push_str("\nStage evidence: unmeasured or rejected.\n");
            }
            for (phase, files) in [
                ("Installation", &s.installation_files),
                ("Application exercise", &s.exercise_files),
            ] {
                if let Some(files) = files {
                    out.push_str(&format!("\n{phase} files: {} added, {} modified, {} removed; {} incomplete roots excluded.\n", files.added, files.modified, files.removed, files.incomplete_roots.len()));
                } else {
                    out.push_str(&format!("\n{phase} files: unmeasured or rejected.\n"));
                }
            }
            for (phase, registry) in [
                ("Installation", &s.installation_registry),
                ("Application exercise", &s.exercise_registry),
            ] {
                if let Some(registry) = registry {
                    out.push_str(&format!("\n{phase} registry: {} key changes, {} value changes; {} incomplete scopes excluded.\n", registry.key_changes, registry.value_changes, registry.incomplete_scopes.len()));
                } else {
                    out.push_str(&format!("\n{phase} registry: unmeasured or rejected.\n"));
                }
            }
        }
        out
    }
}

#[cfg(windows)]
pub(crate) fn read_report_project(
    path: &std::path::Path,
) -> Result<aiw_schema::Project, ReportSetUnavailableReason> {
    use std::{fs::File, io::Read};
    // Projects are explicit selectors and may live outside the retained workspace.
    // Bound reads from the opened regular file; the report verifier binds parsed content.
    let file = File::open(path).map_err(|_| ReportSetUnavailableReason::ProjectUnreadable)?;
    let metadata = file
        .metadata()
        .map_err(|_| ReportSetUnavailableReason::ProjectUnreadable)?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(ReportSetUnavailableReason::ProjectUnreadable);
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReportSetUnavailableReason::ProjectUnreadable)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ReportSetUnavailableReason::ProjectUnreadable);
    }
    let project: aiw_schema::Project =
        serde_yaml::from_slice(&bytes).map_err(|_| ReportSetUnavailableReason::ProjectInvalid)?;
    Ok(project)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> WsbMsiReportSetEntry {
        WsbMsiReportSetEntry {
            id: "sample".into(),
            workspace_root: std::env::temp_dir(),
            run_id: "run-1".into(),
            project_path: std::env::temp_dir().join("project.json"),
            guest_agent_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn selectors_are_strict_bounded_and_unambiguous() {
        let valid = WsbMsiReportSetInput {
            schema_version: WSB_MSI_REPORT_SET_INPUT_SCHEMA.into(),
            entries: vec![entry()],
        };
        valid.validate().unwrap();
        let mut value = serde_json::to_value(&valid).unwrap();
        value["entries"][0]["command"] = "execute".into();
        assert!(serde_json::from_value::<WsbMsiReportSetInput>(value).is_err());
        let mut duplicate = valid.clone();
        let mut alias = entry();
        alias.id = "SAMPLE".into();
        duplicate.entries.push(alias);
        assert!(duplicate.validate().is_err());
        for id in ["../escape", "", "a|b", "a\nb"] {
            let mut bad = valid.clone();
            bad.entries[0].run_id = id.into();
            assert!(bad.validate().is_err());
        }
        let mut bad = valid.clone();
        bad.entries[0].workspace_root = "relative".into();
        assert!(bad.validate().is_err());
        bad = valid.clone();
        bad.entries[0].guest_agent_sha256 = "A".repeat(64);
        assert!(bad.validate().is_err());
        bad = valid;
        bad.entries = vec![entry(); 33];
        assert!(bad.validate().is_err());
    }

    #[test]
    fn absent_and_rejected_failure_evidence_never_become_function_results() {
        for progress in [
            FailureProgressEvidence::Absent,
            FailureProgressEvidence::Rejected,
        ] {
            let report = crate::WsbMsiUnsuccessfulReport {
                interactive_session_seconds: None,
                schema_version: "legacy".into(),
                run_id: "run-1".into(),
                project_revision_sha256: "a".repeat(64),
                outcome: aiw_orchestrator::RunOutcome::Failed,
                recorded_cleanup_verified: true,
                download_metadata_policy: None,
                session_id: "session".into(),
                request_sha256: "b".repeat(64),
                installer_sha256: "c".repeat(64),
                guest_agent_sha256: "d".repeat(64),
                scenario_sha256: "e".repeat(64),
                lifecycle: vec![],
                guest_diagnostic: crate::UnverifiedGuestDiagnostic::Available {
                    summary: "untrusted success".into(),
                },
                failure_progress: progress,
            };
            let result = summarize(
                "application".into(),
                WsbMsiRunReport::UnsuccessfulAttempt(Box::new(report)),
            );
            let WsbMsiReportSetResult::UnsuccessfulAttempt(summary) = result else {
                panic!("failure promoted");
            };
            assert!(summary.receipt_sha256.is_none());
            assert!(summary.evidence_root_hash.is_none());
            assert!(summary.stage_progress.is_none());
            assert!(summary.functions.install.is_none());
            assert!(summary.functions.open_document.is_none());
            assert!(summary.installation_files.is_none());
            assert!(summary.installation_registry.is_none());
            assert!(summary.application_token.is_none());
        }
    }

    #[test]
    fn markdown_keeps_rejected_rows_visible_and_escapes_caller_labels() {
        let set = WsbMsiReportSet {
            schema_version: WSB_MSI_REPORT_SET_SCHEMA.into(),
            entries: vec![WsbMsiReportSetRow {
                id: "<script>|[click](https://example.test)".into(),
                result: WsbMsiReportSetResult::Unavailable(
                    ReportSetUnavailableReason::EvidenceRejected,
                ),
            }],
        };
        let markdown = set.to_markdown();
        assert!(markdown.contains("EvidenceRejected"));
        assert!(markdown.contains("Unmeasured"));
        assert!(!markdown.contains("<script>"));
        assert!(!markdown.contains("[click]"));
    }

    #[cfg(windows)]
    #[test]
    fn invalid_and_oversized_projects_remain_unavailable_rows() {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!(
            "aiw-report-set-project-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"{}").unwrap();
        drop(file);
        let mut selected = entry();
        selected.project_path = path.clone();
        let input = WsbMsiReportSetInput {
            schema_version: WSB_MSI_REPORT_SET_INPUT_SCHEMA.into(),
            entries: vec![selected],
        };
        let result = report_windows_sandbox_msi_set(&input).unwrap();
        assert!(matches!(
            result.entries[0].result,
            WsbMsiReportSetResult::Unavailable(ReportSetUnavailableReason::ProjectInvalid)
        ));
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(1024 * 1024 + 1)
            .unwrap();
        let result = report_windows_sandbox_msi_set(&input).unwrap();
        assert!(matches!(
            result.entries[0].result,
            WsbMsiReportSetResult::Unavailable(ReportSetUnavailableReason::ProjectUnreadable)
        ));
        std::fs::remove_file(path).unwrap();
    }
}
