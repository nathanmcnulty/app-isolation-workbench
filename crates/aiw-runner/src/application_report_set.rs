//! Application-specific verification with a shared, deliberately narrow function matrix.
use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ReportSetUnavailableReason, WSB_MSI_REPORT_SET_INPUT_SCHEMA, WsbBambuRunReport,
    WsbMsiReportSetEntry, WsbMsiReportSetInput, WsbMsiReportSetResult,
};

pub const WSB_REPORT_SET_INPUT_SCHEMA: &str = "aiw.dev/wsb-report-set-input/v0alpha1";
pub const WSB_REPORT_SET_SCHEMA: &str = "aiw.dev/wsb-report-set/v0alpha1";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ReportSetProfile {
    NotepadMsi,
    BambuExport,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbReportSetEntry {
    pub profile: ReportSetProfile,
    /// Same explicit retained-run selector as the legacy MSI manifest.
    pub run: WsbMsiReportSetEntry,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbReportSetInput {
    pub schema_version: String,
    pub entries: Vec<WsbReportSetEntry>,
}

impl WsbReportSetInput {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != WSB_REPORT_SET_INPUT_SCHEMA {
            return Err("unsupported application report set schema".into());
        }
        WsbMsiReportSetInput {
            schema_version: WSB_MSI_REPORT_SET_INPUT_SCHEMA.into(),
            entries: self.entries.iter().map(|entry| entry.run.clone()).collect(),
        }
        .validate()
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbReportSet {
    pub schema_version: String,
    pub entries: Vec<WsbReportSetRow>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsbReportSetRow {
    pub guest_agent_sha256: String,
    pub id: String,
    pub profile: ReportSetProfile,
    pub functions: ApplicationReportFunctions,
    pub result: WsbReportSetResult,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "kind", content = "report", rename_all = "camelCase")]
pub enum WsbReportSetResult {
    NotepadMsi(WsbMsiReportSetResult),
    BambuExport(Box<WsbBambuRunReport>),
    Unavailable(ReportSetUnavailableReason),
}

/// Null means unmeasured, including incomplete attempts. A completed stage is not a passed workflow.
#[derive(Debug, Clone, Default, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationReportFunctions {
    pub install: Option<bool>,
    pub launch: Option<bool>,
    pub open_document: Option<bool>,
    pub edit_save_document: Option<bool>,
    pub close: Option<bool>,
    pub stl_to_3mf_export: Option<bool>,
}

impl WsbReportSetResult {
    fn identity(&self) -> Option<(&str, &str)> {
        match self {
            Self::NotepadMsi(
                WsbMsiReportSetResult::CompletedScenario(s)
                | WsbMsiReportSetResult::UnsuccessfulAttempt(s),
            ) => Some((&s.run_id, &s.request_sha256)),
            Self::BambuExport(s) => Some((&s.run_id, &s.request_sha256)),
            _ => None,
        }
    }

    fn functions(&self) -> ApplicationReportFunctions {
        match self {
            Self::NotepadMsi(WsbMsiReportSetResult::CompletedScenario(s)) => {
                ApplicationReportFunctions {
                    install: s.functions.install,
                    launch: s.functions.launch,
                    open_document: s.functions.open_document,
                    edit_save_document: s.functions.edit_save_document,
                    close: s.functions.close,
                    stl_to_3mf_export: None,
                }
            }
            Self::BambuExport(s)
                if s.outcome == aiw_orchestrator::RunOutcome::InsufficientEvidence
                    && s.evidence_status == crate::BambuReportEvidenceStatus::Verified
                    && s.scenario
                        .as_ref()
                        .is_some_and(|scenario| scenario.successful())
                    && s.artifact.is_some() =>
            {
                ApplicationReportFunctions {
                    install: Some(true),
                    launch: Some(true),
                    stl_to_3mf_export: Some(true),
                    ..Default::default()
                }
            }
            _ => ApplicationReportFunctions::default(),
        }
    }
}

#[cfg(windows)]
pub fn report_windows_sandbox_set(input: &WsbReportSetInput) -> Result<WsbReportSet, String> {
    input.validate()?;
    let mut seen = BTreeSet::new();
    let mut entries = Vec::with_capacity(input.entries.len());
    for entry in &input.entries {
        let run = &entry.run;
        let mut result = match entry.profile {
            ReportSetProfile::NotepadMsi => {
                let set = crate::report_windows_sandbox_msi_set(&WsbMsiReportSetInput {
                    schema_version: WSB_MSI_REPORT_SET_INPUT_SCHEMA.into(),
                    entries: vec![run.clone()],
                })?;
                match set
                    .entries
                    .into_iter()
                    .next()
                    .ok_or("missing MSI row")?
                    .result
                {
                    WsbMsiReportSetResult::Unavailable(reason) => {
                        WsbReportSetResult::Unavailable(reason)
                    }
                    report => WsbReportSetResult::NotepadMsi(report),
                }
            }
            ReportSetProfile::BambuExport => {
                let read =
                    crate::report_set::read_report_project(&run.project_path).and_then(|project| {
                        crate::report_windows_sandbox_bambu_run(
                            &run.workspace_root,
                            &run.run_id,
                            &project,
                            &run.guest_agent_sha256,
                        )
                        .map_err(|_| ReportSetUnavailableReason::EvidenceRejected)
                    });
                match read {
                    Ok(report) => WsbReportSetResult::BambuExport(Box::new(report)),
                    Err(reason) => WsbReportSetResult::Unavailable(reason),
                }
            }
        };
        // A rejected selector cannot reserve the identity of a later valid entry.
        if let Some((run_id, request)) = result.identity() {
            if !seen.insert((run_id.to_owned(), request.to_owned())) {
                result = WsbReportSetResult::Unavailable(ReportSetUnavailableReason::DuplicateRun);
            }
        }
        entries.push(WsbReportSetRow {
            guest_agent_sha256: run.guest_agent_sha256.clone(),
            id: run.id.clone(),
            profile: entry.profile,
            functions: result.functions(),
            result,
        });
    }
    Ok(WsbReportSet {
        schema_version: WSB_REPORT_SET_SCHEMA.into(),
        entries,
    })
}

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

impl WsbReportSet {
    /// Rendering is not verification. Construct a verified set through the retained reader first.
    pub fn to_markdown(&self) -> String {
        let mut out = "# Retained application workflow results\n\nEach run is independently reverified. These are fixed workflow observations inside Windows Sandbox, not general compatibility or application-level isolation verdicts. Baseline/candidate comparison remains unmeasured. Cleanup is a historical record. Null or unavailable evidence never means a function passed.\n\n| Entry | Application | Result | Install | Launch | Open document | Edit/save | Close | STL to 3MF |\n|---|---|---|---|---|---|---|---|---|\n".to_owned();
        for row in &self.entries {
            let (app, status) = match &row.result {
                WsbReportSetResult::NotepadMsi(WsbMsiReportSetResult::CompletedScenario(s)) => {
                    (s.application_name.as_str(), "Completed".to_owned())
                }
                WsbReportSetResult::NotepadMsi(WsbMsiReportSetResult::UnsuccessfulAttempt(s)) => {
                    (s.application_name.as_str(), "Unsuccessful".to_owned())
                }
                WsbReportSetResult::BambuExport(s) => (
                    "Bambu Studio",
                    if row.functions.stl_to_3mf_export == Some(true) {
                        "Completed".into()
                    } else {
                        format!("Unsuccessful; evidence {:?}", s.evidence_status)
                    },
                ),
                WsbReportSetResult::Unavailable(reason)
                | WsbReportSetResult::NotepadMsi(WsbMsiReportSetResult::Unavailable(reason)) => {
                    ("Unverified", format!("Unavailable: {reason:?}"))
                }
            };
            let f = &row.functions;
            let values = [
                f.install,
                f.launch,
                f.open_document,
                f.edit_save_document,
                f.close,
                f.stl_to_3mf_export,
            ]
            .map(|value| match value {
                Some(true) => "Passed",
                Some(false) => "Failed",
                None => "Unmeasured",
            });
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                cell(&row.id),
                cell(app),
                cell(&status),
                values.join(" | ")
            ));
        }
        out.push_str("\nApplication-specific JSON retains token, stage, failure, artifact, and available file/registry observations. An unmeasured function may be outside the selected profile; it does not imply incompatibility.\n");
        for row in &self.entries {
            let (run, installer, guest, outcome, cleanup, receipt) = match &row.result {
                WsbReportSetResult::NotepadMsi(
                    WsbMsiReportSetResult::CompletedScenario(s)
                    | WsbMsiReportSetResult::UnsuccessfulAttempt(s),
                ) => (
                    &s.run_id,
                    &s.installer_sha256,
                    &s.guest_agent_sha256,
                    s.recorded_outcome,
                    s.recorded_cleanup_verified,
                    s.receipt_sha256.as_deref(),
                ),
                WsbReportSetResult::BambuExport(s) => (
                    &s.run_id,
                    &s.compiled_scenario.application_sha256,
                    &row.guest_agent_sha256,
                    s.outcome,
                    s.recorded_cleanup_verified,
                    s.receipt_sha256.as_deref(),
                ),
                _ => continue,
            };
            out.push_str(&format!("\n## {}\n\nRun: {}. Recorded outcome: {outcome:?}. Cleanup recorded verified: {cleanup}.\n\nInstaller SHA-256: `{}`\n\nGuest SHA-256: `{}`\n\nReceipt SHA-256: {}\n", cell(&row.id), cell(run), cell(installer), cell(guest), receipt.map(cell).unwrap_or_else(|| "Unmeasured or rejected".into())));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> WsbReportSetInput {
        WsbReportSetInput {
            schema_version: WSB_REPORT_SET_INPUT_SCHEMA.into(),
            entries: vec![WsbReportSetEntry {
                profile: ReportSetProfile::BambuExport,
                run: WsbMsiReportSetEntry {
                    id: "bambu".into(),
                    run_id: "retained-run".into(),
                    workspace_root: std::env::temp_dir(),
                    project_path: std::env::temp_dir().join("project.json"),
                    guest_agent_sha256: "a".repeat(64),
                },
            }],
        }
    }

    #[test]
    fn mixed_manifest_is_explicit_strict_and_bounded() {
        let mut manifest = input();
        manifest.validate().unwrap();
        let mut wire = serde_json::to_value(&manifest).unwrap();
        wire["entries"][0]["profile"] = "auto".into();
        assert!(serde_json::from_value::<WsbReportSetInput>(wire).is_err());
        let mut wire = serde_json::to_value(&manifest).unwrap();
        wire["entries"][0]["run"]["command"] = "anything".into();
        assert!(serde_json::from_value::<WsbReportSetInput>(wire).is_err());
        manifest.entries.push(manifest.entries[0].clone());
        manifest.entries[1].profile = ReportSetProfile::NotepadMsi;
        assert!(manifest.validate().is_err()); // IDs remain unique across profiles.
        manifest.entries = vec![manifest.entries[0].clone(); 33];
        assert!(manifest.validate().is_err());
        manifest.entries.clear();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn unavailable_rows_never_gain_functions_or_render_markup() {
        let result = WsbReportSetResult::Unavailable(ReportSetUnavailableReason::EvidenceRejected);
        assert!(result.identity().is_none());
        let functions = result.functions();
        assert!(
            serde_json::to_value(&functions)
                .unwrap()
                .as_object()
                .unwrap()
                .values()
                .all(|value| value.is_null())
        );
        let set = WsbReportSet {
            schema_version: WSB_REPORT_SET_SCHEMA.into(),
            entries: vec![WsbReportSetRow {
                id: "<script>|[link](x)\n".into(),
                profile: ReportSetProfile::BambuExport,
                guest_agent_sha256: "a".repeat(64),
                functions,
                result,
            }],
        };
        let markdown = set.to_markdown();
        assert!(!markdown.contains("<script>"));
        assert!(!markdown.contains("[link]"));
        assert!(!markdown.contains("Passed"));
        assert!(markdown.contains("Unmeasured"));
    }

    #[test]
    fn bambu_missing_or_failed_evidence_stays_unmeasured() {
        let project: aiw_schema::Project =
            serde_json::from_str(include_str!("../../../examples/bambu-studio-export.json"))
                .unwrap();
        let scenario =
            aiw_provider_wsb::compile_bambu_studio_export_scenario(&project, "local-file-export")
                .unwrap();
        for outcome in [
            aiw_orchestrator::RunOutcome::Failed,
            aiw_orchestrator::RunOutcome::Cancelled,
            aiw_orchestrator::RunOutcome::InsufficientEvidence,
        ] {
            for status in [
                crate::BambuReportEvidenceStatus::Absent,
                crate::BambuReportEvidenceStatus::Rejected,
                crate::BambuReportEvidenceStatus::Verified,
            ] {
                let result = WsbReportSetResult::BambuExport(Box::new(WsbBambuRunReport {
                    schema_version: "aiw.dev/wsb-bambu-run-report/v0alpha1".into(),
                    run_id: "retained".into(),
                    project_revision_sha256: "a".repeat(64),
                    request_sha256: "b".repeat(64),
                    compiled_scenario: scenario.clone(),
                    requested_assertions: project.assertions.clone(),
                    outcome,
                    recorded_cleanup_verified: true,
                    evidence_status: status,
                    receipt_sha256: None,
                    evidence_root_hash: None,
                    scenario: None,
                    artifact: None,
                    missing_evidence: vec!["ordinary baseline".into()],
                }));
                assert!(
                    serde_json::to_value(result.functions())
                        .unwrap()
                        .as_object()
                        .unwrap()
                        .values()
                        .all(|value| value.is_null())
                );
            }
        }
    }
}
