use crate::{AssessmentEvidenceGap, WsbMsiAssessmentReport};
use aiw_provider_wsb::{ApplicationFileRoot, FilesystemDiffKind, FilesystemSnapshotDiffResult};

impl WsbMsiAssessmentReport {
    /// Human-readable rendering of an already reverified report. This does not
    /// independently verify a constructed report or promote guest observations.
    pub fn to_markdown(&self) -> String {
        let mut out = format!(
            "# Notepad++ Windows Sandbox assessment\n\nRun: {}\n\nThese are guest-reported observations from one approved scenario. The assessment remains **insufficient evidence** for an isolation verdict or a general compatibility recommendation.\n\n| Function | Observed result |\n|---|---|\n",
            cell(&self.run_id)
        );
        for (name, observed) in [
            (
                "Silent installation",
                Some(self.scenario.install_exit_code == 0),
            ),
            (
                "Launch and visible window",
                Some(self.scenario.process_observed),
            ),
            (
                "Open fixed text document",
                self.behavior
                    .as_ref()
                    .map(|b| b.functional_exercise.opened_document),
            ),
            (
                "Edit and save expected bytes",
                self.behavior
                    .as_ref()
                    .map(|b| b.functional_exercise.saved_document),
            ),
            (
                "Graceful close",
                Some(
                    self.scenario.process_closed
                        && self.scenario.graceful_close_requested
                        && self.scenario.launch_exit_code == 0,
                ),
            ),
        ] {
            let status = match observed {
                Some(true) => "Passed",
                Some(false) => "Failed",
                None => "Not measured",
            };
            out.push_str(&format!("| {name} | {status} |\n"));
        }
        out.push_str(&format!("\nRecorded exact-session cleanup verified: **{}**. This is the retained cleanup record, not a current-session query.\n", self.recorded_cleanup_verified));
        if let Some(token) = &self.application_token {
            out.push_str(&format!("\nLaunched guest process: PID {}, {:?} integrity, elevated {}, AppContainer {}. This root-process token does not satisfy independent host or descendant checks.\n", token.token.process_id, token.token.integrity.level, token.token.is_elevated, token.token.is_app_container));
        }
        out.push_str("\n## Filesystem changes\n\nScope: the Notepad++ installation directory and its guest roaming/local application-data directories. Entries contain paths, sizes, and hashes; contents and registry changes are not captured.\n");
        append_changes(
            &mut out,
            "Installation",
            self.installation_file_changes.as_ref(),
        );
        append_changes(
            &mut out,
            "Application exercise",
            self.exercise_file_changes.as_ref(),
        );
        out.push_str("\nThese changes identify files to investigate for packaging. They do not establish a complete package recipe or dependencies outside the captured roots.\n\n## Unresolved assessment evidence\n\n");
        for gap in &self.missing_evidence {
            out.push_str(&format!("- {}\n", gap_label(*gap)));
        }
        if !self.unmeasured_scenarios.is_empty() {
            out.push_str("\nUnmeasured project scenarios:\n\n");
            for scenario in &self.unmeasured_scenarios {
                out.push_str(&format!("- {}\n", cell(scenario)));
            }
        }
        out.push_str(&format!("\n## Evidence identity\n\n- Installer SHA-256: {}\n- Guest-agent SHA-256: {}\n- Scenario SHA-256: {}\n- Completion receipt SHA-256: {}\n- Evidence root: {}\n\nThe JSON report retains the complete observations and file-change lists. Failed or recovered attempts without accepted evidence are not promoted into this completed assessment report.\n", cell(&self.scenario.installer_sha256), cell(&self.scenario.agent_sha256), cell(&self.scenario.scenario_sha256), cell(&self.receipt_sha256), cell(&self.evidence_root_hash)));
        out
    }
}

fn append_changes(out: &mut String, title: &str, changes: Option<&FilesystemSnapshotDiffResult>) {
    out.push_str(&format!("\n### {title}\n\n"));
    let Some(changes) = changes else {
        out.push_str("Not measured by this scenario version.\n");
        return;
    };
    let added = changes
        .diffs
        .iter()
        .filter(|d| d.kind == FilesystemDiffKind::Added)
        .count();
    let removed = changes
        .diffs
        .iter()
        .filter(|d| d.kind == FilesystemDiffKind::Removed)
        .count();
    let modified = changes
        .diffs
        .iter()
        .filter(|d| d.kind == FilesystemDiffKind::Modified)
        .count();
    out.push_str(&format!(
        "{added} added, {modified} modified, {removed} removed in complete roots.\n"
    ));
    for root in &changes.incomplete_roots {
        out.push_str(&format!(
            "\n**Incomplete capture: {}.** Changes for this root are omitted.\n",
            root_label(*root)
        ));
    }
    if !changes.diffs.is_empty() {
        out.push_str("\n| Change | Root | Relative path |\n|---|---|---|\n");
        for diff in changes.diffs.iter().take(100) {
            if let Some(entry) = diff.after.as_ref().or(diff.before.as_ref()) {
                out.push_str(&format!(
                    "| {:?} | {} | {} |\n",
                    diff.kind,
                    root_label(entry.root),
                    cell(&entry.path)
                ));
            }
        }
        if changes.diffs.len() > 100 {
            out.push_str(&format!(
                "\n{} additional changes are in the JSON report.\n",
                changes.diffs.len() - 100
            ));
        }
    }
}

fn root_label(root: ApplicationFileRoot) -> &'static str {
    match root {
        ApplicationFileRoot::Installation => "Installation",
        ApplicationFileRoot::RoamingAppData => "Guest roaming app data",
        ApplicationFileRoot::LocalAppData => "Guest local app data",
    }
}

fn gap_label(gap: AssessmentEvidenceGap) -> &'static str {
    use AssessmentEvidenceGap::*;
    match gap {
        OrdinaryBaseline => "Comparable ordinary execution baseline",
        IndependentHostMeasurements => "Independent host measurements",
        FilesystemRegistryChanges => "Broader filesystem and registry activity",
        NetworkUiIpcObservations => "Broader network, UI, and IPC behavior",
        PersistenceResidue => "Persistence and residue checks",
        DescendantCoverage => "Required descendant-process coverage",
        OfflineCanary => "Required offline canary denial",
        EffectiveBackendVerification => "Required effective isolation backend verification",
        CaptureCompleteness => "Required complete evidence capture",
        TargetToken => "Required independently verified target token",
    }
}

fn cell(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\\' | '|' | '`' | '[' | ']' | '*' | '_' | '!' | '#' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            ch if ch.is_control() => escaped.push(' '),
            ch => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filenames_cannot_inject_report_markup() {
        assert_eq!(
            cell("[x](url)|<script>\n`"),
            "\\[x\\](url)\\|&lt;script&gt; \\`"
        );
        let mut out = String::new();
        append_changes(
            &mut out,
            "Installation",
            Some(&FilesystemSnapshotDiffResult {
                diffs: vec![],
                incomplete_roots: vec![ApplicationFileRoot::Installation],
            }),
        );
        assert!(out.contains("Incomplete capture: Installation"));
        assert!(out.contains("Changes for this root are omitted"));
    }
}
