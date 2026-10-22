//! One function matrix for retained Sandbox and reviewed MSIX research evidence.
//! Readers retain their authority contracts; this layer does not invent verdicts.
use crate::{
    ApplicationReportFunctions, AssessmentEvidenceGap, MsixLifecycleReport, MsixResearchProfile,
    ReportSetUnavailableReason, WsbReportSetInput, WsbReportSetRow,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

pub const APPLICATION_ASSESSMENT_INPUT_SCHEMA: &str =
    "aiw.dev/application-assessment-input/v0alpha1";
pub const APPLICATION_ASSESSMENT_SCHEMA: &str = "aiw.dev/application-assessment/v0alpha1";

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MsixAssessmentSelection {
    pub id: String,
    pub profile: MsixResearchProfile,
    pub archive: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationAssessmentInput {
    pub schema_version: String,
    #[serde(default)]
    pub msix_research: Vec<MsixAssessmentSelection>,
    #[serde(default)]
    pub windows_sandbox: Option<WsbReportSetInput>,
}

impl ApplicationAssessmentInput {
    pub fn validate(&self) -> Result<(), String> {
        let count = self.msix_research.len()
            + self
                .windows_sandbox
                .as_ref()
                .map_or(0, |input| input.entries.len());
        if self.schema_version != APPLICATION_ASSESSMENT_INPUT_SCHEMA || count == 0 || count > 32 {
            return Err(
                "Application assessment requires the supported schema and 1-32 explicit entries"
                    .into(),
            );
        }
        let mut ids = BTreeSet::new();
        if let Some(input) = &self.windows_sandbox {
            input.validate()?;
            ids.extend(
                input
                    .entries
                    .iter()
                    .map(|entry| entry.run.id.to_ascii_lowercase()),
            );
        }
        for entry in &self.msix_research {
            if entry.id.is_empty()
                || entry.id.len() > 128
                || !entry
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || !ids.insert(entry.id.to_ascii_lowercase())
            {
                return Err("Invalid or duplicate application assessment ID".into());
            }
            let path = entry
                .archive
                .to_str()
                .ok_or("MSIX archive path must be Unicode")?;
            if !entry.archive.is_absolute()
                || path.len() > 32767
                || path.chars().any(char::is_control)
            {
                return Err("MSIX archive requires a bounded absolute path".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "kind", content = "evidence", rename_all = "camelCase")]
pub enum ApplicationAssessmentSource {
    WindowsSandbox(Box<WsbReportSetRow>),
    MsixResearch(Box<MsixLifecycleReport>),
    Unavailable(ReportSetUnavailableReason),
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationAssessmentRow {
    pub id: String,
    pub functions: ApplicationReportFunctions,
    pub source: ApplicationAssessmentSource,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationAssessmentReport {
    pub schema_version: String,
    pub outcome: aiw_orchestrator::RunOutcome,
    /// A function result is never promoted to general compatibility or isolation.
    pub compatibility: String,
    pub isolation: String,
    pub missing_evidence: Vec<AssessmentEvidenceGap>,
    pub cleanup_scope: String,
    pub entries: Vec<ApplicationAssessmentRow>,
}

pub fn report_application_assessment(
    input: &ApplicationAssessmentInput,
) -> Result<ApplicationAssessmentReport, String> {
    input.validate()?;
    let mut entries = Vec::new();
    if let Some(sandbox) = &input.windows_sandbox {
        #[cfg(windows)]
        for row in crate::report_windows_sandbox_set(sandbox)?.entries {
            entries.push(ApplicationAssessmentRow {
                id: row.id.clone(),
                functions: row.functions.clone(),
                source: ApplicationAssessmentSource::WindowsSandbox(Box::new(row)),
            });
        }
        #[cfg(not(windows))]
        {
            let _ = sandbox;
            return Err("Retained Sandbox workspaces require their original Windows host".into());
        }
    }
    let mut seen_archives = BTreeSet::new();
    for selection in &input.msix_research {
        let source = match crate::report_msix_lifecycle(&selection.archive, selection.profile) {
            Ok(report) if seen_archives.insert(report.archive_sha256.clone()) => {
                ApplicationAssessmentSource::MsixResearch(Box::new(report))
            }
            Ok(_) => {
                ApplicationAssessmentSource::Unavailable(ReportSetUnavailableReason::DuplicateRun)
            }
            Err(_) => ApplicationAssessmentSource::Unavailable(
                ReportSetUnavailableReason::EvidenceRejected,
            ),
        };
        let functions = match &source {
            ApplicationAssessmentSource::MsixResearch(report) => report.functions.clone(),
            _ => ApplicationReportFunctions::default(),
        };
        entries.push(ApplicationAssessmentRow {
            id: selection.id.clone(),
            functions,
            source,
        });
    }
    use AssessmentEvidenceGap::*;
    Ok(ApplicationAssessmentReport {
        schema_version: APPLICATION_ASSESSMENT_SCHEMA.into(),
        outcome: aiw_orchestrator::RunOutcome::InsufficientEvidence,
        compatibility: "notMeasured".into(),
        isolation: "notMeasured".into(),
        missing_evidence: vec![
            OrdinaryBaseline,
            IndependentHostMeasurements,
            FilesystemRegistryChanges,
            NetworkUiIpcObservations,
            PersistenceResidue,
            DescendantCoverage,
            EffectiveBackendVerification,
            CaptureCompleteness,
        ],
        cleanup_scope: "historical per-source receipts; no current worker or host-state claim"
            .into(),
        entries,
    })
}

impl ApplicationAssessmentReport {
    pub fn to_markdown(&self) -> String {
        let mut out = "# Application assessment observations\n\nOverall assessment: insufficient evidence. General compatibility and isolation: unmeasured. Function results apply only to the retained workflow. Cleanup is historical; no worker was contacted. MSIX entries are reviewed research evidence, not production assessment runs.\n\n| Entry | Evidence | Install | Launch | Open document | Edit/save | Close | Uninstall | STL to 3MF |\n|---|---|---|---|---|---|---|---|---|\n".to_owned();
        for row in &self.entries {
            let source = match &row.source {
                ApplicationAssessmentSource::MsixResearch(_) => "Reviewed MSIX research",
                ApplicationAssessmentSource::WindowsSandbox(_) => "Retained Windows Sandbox",
                ApplicationAssessmentSource::Unavailable(
                    ReportSetUnavailableReason::DuplicateRun,
                ) => "Unavailable: duplicate run",
                ApplicationAssessmentSource::Unavailable(_) => "Unavailable: evidence rejected",
            };
            let f = &row.functions;
            let cells = [
                f.install,
                f.launch,
                f.open_document,
                f.edit_save_document,
                f.close,
                f.uninstall,
                f.stl_to_3mf_export,
            ]
            .map(|value| match value {
                Some(true) => "Passed",
                Some(false) => "Failed",
                None => "Unmeasured",
            });
            // IDs were validated before reading, but rendering remains safe for
            // manually constructed reports too.
            let id: String = row
                .id
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        ' '
                    }
                })
                .collect();
            out.push_str(&format!("| {id} | {source} | {} |\n", cells.join(" | ")));
        }
        for row in &self.entries {
            if let ApplicationAssessmentSource::MsixResearch(report) = &row.source {
                out.push_str(&format!("\nMSIX archive `{}`, source `{}`; native `{}`. Observed package `{}`, process {}, session {}, integrity `{}`, elevated {}, AppContainer {}. Exact saved document: {} bytes, SHA-256 `{}`. Payload unchanged: {} files. Configuration: {} retained per-user files. Registration/install-path/process/job/task cleanup verified. User-data deletion: not inferred from uninstall. Editing used the VM console. Detailed JSON retains source adaptation, observed paths, and archive-entry hashes.\n\n", report.archive_sha256, report.source_commit, report.native_sha256, report.package.full_name, report.package.observed_process_id, report.package.observed_session_id, report.package.observed_integrity_sid, report.package.observed_elevated, report.package.observed_app_container, report.document.bytes, report.document.sha256, report.unchanged_payload_files, report.configuration.len()));
            }
        }
        out.push_str("\nMissing evidence: ordinary baseline, independent host measurements, general filesystem/registry changes, network/UI/IPC boundaries, persistence, descendant coverage, effective backend verification and capture completeness. Unmeasured does not mean failed.\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> ApplicationAssessmentInput {
        ApplicationAssessmentInput {
            schema_version: APPLICATION_ASSESSMENT_INPUT_SCHEMA.into(),
            windows_sandbox: None,
            msix_research: vec![MsixAssessmentSelection {
                id: "notepad-msix-r5".into(),
                profile: MsixResearchProfile::Worker107NotepadR5,
                archive: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/msix-lifecycle/worker107-r5.zip"),
            }],
        }
    }
    #[test]
    fn shared_assessment_uses_same_matrix_and_never_upgrades_overall_verdict() {
        let report = report_application_assessment(&input()).unwrap();
        assert_eq!(
            report.outcome,
            aiw_orchestrator::RunOutcome::InsufficientEvidence
        );
        assert_eq!(report.isolation, "notMeasured");
        assert_eq!(report.compatibility, "notMeasured");
        assert_eq!(report.entries[0].functions.edit_save_document, Some(true));
        assert_eq!(report.entries[0].functions.uninstall, Some(true));
        assert!(
            report
                .missing_evidence
                .contains(&AssessmentEvidenceGap::OrdinaryBaseline)
        );
        let markdown = report.to_markdown();
        assert!(markdown.contains("Reviewed MSIX research"));
        assert!(markdown.contains("53 bytes"));
        assert!(markdown.contains("AppContainer false"));
        assert!(markdown.contains("Uninstall"));
        assert!(markdown.contains("insufficient evidence"));
    }
    #[test]
    fn missing_rejected_and_duplicate_archives_never_gain_functions() {
        let mut selection = input();
        let mut duplicate = selection.msix_research[0].clone();
        duplicate.id = "duplicate".into();
        selection.msix_research.push(duplicate);
        let mut absent = selection.msix_research[0].clone();
        absent.id = "missing".into();
        absent.archive = absent.archive.with_file_name("absent.zip");
        selection.msix_research.insert(0, absent);
        let report = report_application_assessment(&selection).unwrap();
        assert!(matches!(
            report.entries[0].source,
            ApplicationAssessmentSource::Unavailable(ReportSetUnavailableReason::EvidenceRejected)
        ));
        assert_eq!(report.entries[1].functions.install, Some(true));
        assert!(matches!(
            report.entries[2].source,
            ApplicationAssessmentSource::Unavailable(ReportSetUnavailableReason::DuplicateRun)
        ));
        for i in [0, 2] {
            assert!(
                serde_json::to_value(&report.entries[i].functions)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .values()
                    .all(|v| v.is_null())
            );
        }
    }
    #[test]
    fn input_is_closed_bounded_and_checks_ids_across_sources() {
        let original = input();
        original.validate().unwrap();
        let mut value = serde_json::to_value(&original).unwrap();
        value["command"] = "anything".into();
        assert!(serde_json::from_value::<ApplicationAssessmentInput>(value).is_err());
        let mut value = serde_json::to_value(&original).unwrap();
        value["msixResearch"][0]["archiveSha256"] = "a".repeat(64).into();
        assert!(serde_json::from_value::<ApplicationAssessmentInput>(value).is_err());
        let mut value = serde_json::to_value(&original).unwrap();
        value["msixResearch"][0]["profile"] = "auto".into();
        assert!(serde_json::from_value::<ApplicationAssessmentInput>(value).is_err());
        let mut invalid = input();
        invalid.msix_research[0].archive = "relative.zip".into();
        assert!(invalid.validate().is_err());
        let mut invalid = input();
        invalid.msix_research = vec![invalid.msix_research[0].clone(); 33];
        assert!(invalid.validate().is_err());
        let mut invalid = input();
        invalid.msix_research.clear();
        assert!(invalid.validate().is_err());
        let mut invalid = input();
        invalid.windows_sandbox = Some(WsbReportSetInput {
            schema_version: crate::WSB_REPORT_SET_INPUT_SCHEMA.into(),
            entries: vec![crate::WsbReportSetEntry {
                profile: crate::ReportSetProfile::NotepadMsi,
                run: crate::WsbMsiReportSetEntry {
                    id: "NOTEPAD-MSIX-R5".into(),
                    run_id: "retained".into(),
                    workspace_root: invalid.msix_research[0].archive.clone(),
                    project_path: invalid.msix_research[0].archive.clone(),
                    guest_agent_sha256: "a".repeat(64),
                },
            }],
        });
        assert!(invalid.validate().is_err());
    }

    #[cfg(windows)]
    #[test]
    fn mixed_sources_keep_rejected_sandbox_separate_from_accepted_msix() {
        let mut selection = input();
        let absent = selection.msix_research[0]
            .archive
            .with_file_name("no-project.json");
        selection.windows_sandbox = Some(WsbReportSetInput {
            schema_version: crate::WSB_REPORT_SET_INPUT_SCHEMA.into(),
            entries: vec![crate::WsbReportSetEntry {
                profile: crate::ReportSetProfile::NotepadMsi,
                run: crate::WsbMsiReportSetEntry {
                    id: "sandbox-missing".into(),
                    run_id: "retained".into(),
                    project_path: absent.clone(),
                    workspace_root: absent,
                    guest_agent_sha256: "a".repeat(64),
                },
            }],
        });
        let report = report_application_assessment(&selection).unwrap();
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].functions.install, None);
        assert_eq!(report.entries[1].functions.install, Some(true));
        assert_eq!(report.entries[1].functions.uninstall, Some(true));
        let markdown = report.to_markdown();
        let last_row = markdown.find("| notepad-msix-r5 |").unwrap();
        assert!(last_row < markdown.find("MSIX archive").unwrap());
        let legacy = serde_json::to_value(&report.entries[0].functions).unwrap();
        assert!(legacy.get("uninstall").is_none());
    }
}
