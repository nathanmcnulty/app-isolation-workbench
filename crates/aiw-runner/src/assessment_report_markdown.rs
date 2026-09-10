use crate::{
    AssessmentEvidenceGap, FailureProgressEvidence, UnverifiedGuestDiagnostic,
    WsbMsiAssessmentReport, WsbMsiRunReport, WsbMsiUnsuccessfulReport,
};
use aiw_provider_wsb::{
    ApplicationFileRoot, ApplicationRegistryRoot, FilesystemDiffKind, FilesystemSnapshotDiffResult,
    RegistryDiffKind, RegistryScope, RegistrySnapshotDiff, RegistryView,
};

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
        if let Some(runtime) = &self.standard_user_context {
            out.push_str(&format!("\nStandard-user runtime: **AiwStandardUser**, SID {}. Profile: {}. Roaming application data: {}. Local application data: {}. Installation used the elevated guest agent; the application used the separately verified standard-user token. These are guest observations, not independent boundary or descendant attestation.\n", cell(&runtime.context.user_sid), cell(&runtime.context.profile_path), cell(&runtime.context.roaming_app_data), cell(&runtime.context.local_app_data)));
        }
        if let Some(progress) = &self.stage_progress {
            append_stages(&mut out, progress);
        }
        out.push_str("\n## Filesystem changes\n\nScope: the Notepad++ installation directory and its guest roaming/local application-data directories. Entries contain paths, sizes, and hashes; contents are not captured.\n");
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
        out.push_str("\n## Registry changes\n\nScope: `HKLM\\Software\\Notepad++` and the exact standard-user `HKU\\<SID>\\Software\\Notepad++`, each through the 64-bit and 32-bit views. Entries retain keys and value metadata (name, type, size, and SHA-256), never raw registry values. The 32-bit and 64-bit views can share backing keys, so counts are observations per view rather than unique physical dependencies. MSI dependency records and other uninstall registration remain outside this scope. Snapshot comparison is non-atomic; incomplete scopes are explicitly omitted from change rows.\n");
        append_registry_changes(
            &mut out,
            "Installation",
            self.installation_registry_changes.as_ref(),
        );
        append_registry_changes(
            &mut out,
            "Application exercise",
            self.exercise_registry_changes.as_ref(),
        );
        if let Some(registration) = &self.product_registration {
            out.push_str(&format!(
                "\n## Machine product registration\n\nProduct code: `{}`. Before installation: **{:?}**. After installation: **{:?}**. This is scoped machine state metadata; it is not a dependency or isolation claim.\n",
                cell(&registration.product_code),
                registration.before_install,
                registration.after_install,
            ));
        }
        out.push_str("\nThese changes identify files and settings to investigate for packaging. They do not establish a complete package recipe or dependencies outside the captured roots.\n\n## Unresolved assessment evidence\n\n");
        for gap in &self.missing_evidence {
            out.push_str(&format!("- {}\n", gap_label(*gap)));
        }
        if !self.unmeasured_scenarios.is_empty() {
            out.push_str("\nUnmeasured project scenarios:\n\n");
            for scenario in &self.unmeasured_scenarios {
                out.push_str(&format!("- {}\n", cell(scenario)));
            }
        }
        append_download_metadata_policy(&mut out, self.download_metadata_policy.as_ref());
        out.push_str(&format!("\n## Evidence identity\n\n- Installer SHA-256: {}\n- Guest-agent SHA-256: {}\n- Scenario SHA-256: {}\n- Completion receipt SHA-256: {}\n- Evidence root: {}\n\nThe JSON report retains the complete observations and file-change lists. Failed or recovered attempts without accepted evidence are not promoted into this completed assessment report.\n", cell(&self.scenario.installer_sha256), cell(&self.scenario.agent_sha256), cell(&self.scenario.scenario_sha256), cell(&self.receipt_sha256), cell(&self.evidence_root_hash)));
        out
    }
}

impl WsbMsiRunReport {
    pub fn to_markdown(&self) -> String {
        match self {
            Self::CompletedAssessment(report) => report.to_markdown(),
            Self::UnsuccessfulAttempt(report) => report.to_markdown(),
        }
    }
}

impl WsbMsiUnsuccessfulReport {
    pub fn to_markdown(&self) -> String {
        let mut out = format!(
            "# Notepad++ Windows Sandbox unsuccessful attempt\n\nRun: {}\n\nRecorded outcome: **{:?}**. No completed application assessment is available. Application functions are **not verified**; this does not establish application incompatibility.\n\nRecorded exact-session cleanup verified: **{}**. This historical record is not a current-session query.\n\n## Recorded provider lifecycle\n\n| Sequence | State | Reason code |\n|---|---|---|\n",
            cell(&self.run_id),
            self.outcome,
            self.recorded_cleanup_verified,
        );
        for transition in &self.lifecycle {
            out.push_str(&format!(
                "| {} | {:?} | {} |\n",
                transition.sequence,
                transition.state,
                cell(&transition.reason_code)
            ));
        }
        match &self.failure_progress {
            FailureProgressEvidence::Absent => out.push_str("\nNo receipt-bound stage progress was retained.\n"),
            FailureProgressEvidence::Rejected => out.push_str("\n**Stage progress rejected:** the completion or its artifacts could not be verified as a bound failed attempt. No stage results are inferred.\n"),
            FailureProgressEvidence::Verified(verified) => {
                append_stages(&mut out, &verified.attempt.progress);
                out.push_str(&format!("\nReceipt-bound failure diagnostic (guest-reported):\n\n> {}\n\nFailed receipt SHA-256: {}\n\nFailed-attempt evidence root: {}\n", cell(&verified.attempt.diagnostic), cell(&verified.receipt_sha256), cell(&verified.evidence_root_hash)));
                if let Some(snapshots) = &verified.snapshots {
                    out.push_str("\n## Retained failed-run snapshots\n\nThese receipt-bound snapshots retain metadata only: file contents and raw registry values are never included. A phase is shown as missing when the failed run did not complete that capture stage.\n\n");
                    for (label, present) in [
                        ("Before installation", snapshots.before_install.is_some()),
                        ("After installation", snapshots.after_install.is_some()),
                        ("After application exercise", snapshots.after_exercise.is_some()),
                    ] {
                        out.push_str(&format!("- {label}: {}\n", if present { "retained" } else { "missing" }));
                    }
                    if let Some(context) = &snapshots.capture_context {
                        out.push_str(&format!("\nCapture account: SID {}; profile {}; roaming application data {}; local application data {}. These are capture-account observations, not the launched application token.\n", cell(&context.user_sid), cell(&context.profile_path), cell(&context.roaming_app_data), cell(&context.local_app_data)));
                    }
                    out.push_str("\n### Retained filesystem changes\n");
                    append_failed_changes(&mut out, "Installation", verified.installation_file_changes.as_ref(), snapshots.before_install.is_some() && snapshots.after_install.is_some());
                    append_failed_changes(&mut out, "Application exercise", verified.exercise_file_changes.as_ref(), snapshots.after_install.is_some() && snapshots.after_exercise.is_some());
                    out.push_str("\n### Retained registry changes\n");
                    append_failed_registry_changes(&mut out, "Installation", verified.installation_registry_changes.as_ref(), snapshots.before_install.is_some() && snapshots.after_install.is_some());
                    append_failed_registry_changes(&mut out, "Application exercise", verified.exercise_registry_changes.as_ref(), snapshots.after_install.is_some() && snapshots.after_exercise.is_some());
                }
            }
        }
        out.push_str("\n## Unverified guest diagnostic\n\n");
        match &self.guest_diagnostic {
            UnverifiedGuestDiagnostic::Absent => out.push_str("No separate unverified guest diagnostic was present when reporting.\n"),
            UnverifiedGuestDiagnostic::Rejected => out.push_str("The guest diagnostic was unreadable, unsafe, malformed, or exceeded its bounds. Its contents were not included.\n"),
            UnverifiedGuestDiagnostic::Available { summary } => {
                out.push_str("The following message is untrusted guest output read at report time. It has no completion-receipt or evidence-chain binding and cannot prove that any application stage passed.\n\n");
                out.push_str(&format!("> {}\n", cell(summary)));
            }
        }
        append_download_metadata_policy(&mut out, self.download_metadata_policy.as_ref());
        out.push_str(&format!("\n## Attempt identity\n\n- Session ID: {}\n- Project revision SHA-256: {}\n- Installer SHA-256: {}\n- Guest-agent SHA-256: {}\n- Scenario SHA-256: {}\n- Request SHA-256: {}\n\nOnly a fully verified failed receipt can supply the stage progress above. Other guest output cannot establish an accepted compatibility assessment, application token, or file-change claim.\n", cell(&self.session_id), cell(&self.project_revision_sha256), cell(&self.installer_sha256), cell(&self.guest_agent_sha256), cell(&self.scenario_sha256), cell(&self.request_sha256)));
        out
    }
}

fn append_failed_changes(
    out: &mut String,
    title: &str,
    changes: Option<&FilesystemSnapshotDiffResult>,
    phases_complete: bool,
) {
    if !phases_complete {
        out.push_str(&format!(
            "\n### {title}\n\nNot measured: required capture phases did not complete.\n"
        ));
    } else {
        append_changes(out, title, changes);
    }
}

fn append_failed_registry_changes(
    out: &mut String,
    title: &str,
    changes: Option<&RegistrySnapshotDiff>,
    phases_complete: bool,
) {
    if !phases_complete {
        out.push_str(&format!(
            "\n### {title}\n\nNot measured: required capture phases did not complete.\n"
        ));
    } else {
        append_registry_changes(out, title, changes);
    }
}

fn append_stages(out: &mut String, progress: &aiw_provider_wsb::ImportedMsiStageProgress) {
    use aiw_provider_wsb::{MsiExecutionStage as Stage, MsiStageStatus as Status};
    out.push_str("\n## Scenario stage progress\n\nThese guest-reported observations are bound to the completion receipt. A failed stage can reflect an installer, application, or test-driver failure; it is not an incompatibility verdict. A completed capture stage does not guarantee complete filesystem coverage.\n\n| Stage | Guest-reported result |\n|---|---|\n");
    for result in &progress.stages {
        let stage = match result.stage {
            Stage::BeforeInstallCapture => "Capture before installation",
            Stage::Install => "Install application",
            Stage::AfterInstallCapture => "Capture installed state",
            Stage::PrepareDocument => "Prepare test document",
            Stage::Launch => "Launch application process",
            Stage::OpenDocument => "Open and verify document",
            Stage::EditSaveDocument => "Edit, save, and verify bytes",
            Stage::Close => "Close application and verify job cleanup",
            Stage::AfterExerciseCapture => "Capture state after use",
        };
        let status = match result.status {
            Status::Passed => "Passed",
            Status::Failed => "Failed",
            Status::NotReached => "Not reached",
        };
        out.push_str(&format!("| {stage} | {status} |\n"));
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

fn append_registry_changes(out: &mut String, title: &str, changes: Option<&RegistrySnapshotDiff>) {
    out.push_str(&format!("\n### {title}\n\n"));
    let Some(changes) = changes else {
        out.push_str("Not measured by this scenario version.\n");
        return;
    };
    for (label, kinds) in [
        (
            "Keys",
            changes
                .key_changes
                .iter()
                .map(|change| change.kind)
                .collect::<Vec<_>>(),
        ),
        (
            "Values",
            changes
                .value_changes
                .iter()
                .map(|change| change.kind)
                .collect::<Vec<_>>(),
        ),
    ] {
        let added = kinds
            .iter()
            .filter(|kind| **kind == RegistryDiffKind::Added)
            .count();
        let modified = kinds
            .iter()
            .filter(|kind| **kind == RegistryDiffKind::Modified)
            .count();
        let removed = kinds
            .iter()
            .filter(|kind| **kind == RegistryDiffKind::Removed)
            .count();
        out.push_str(&format!(
            "{label}: {added} added, {modified} modified, {removed} removed in complete scopes.\n\n"
        ));
    }
    for scope in &changes.incomplete_scopes {
        out.push_str(&format!(
            "\n**Incomplete capture: {}.** Changes for this scope are omitted.\n",
            registry_scope_label(*scope)
        ));
    }
    if !changes.key_changes.is_empty() {
        out.push_str("\nKey changes:\n\n| Change | Scope | Relative key |\n|---|---|---|\n");
        for change in changes.key_changes.iter().take(100) {
            out.push_str(&format!(
                "| {:?} | {} | {} |\n",
                change.kind,
                registry_scope_label(RegistryScope {
                    root: change.entry.root,
                    view: change.entry.view,
                }),
                registry_path_label(&change.entry.path)
            ));
        }
        if changes.key_changes.len() > 100 {
            out.push_str(&format!(
                "\n{} additional key changes are in the JSON report.\n",
                changes.key_changes.len() - 100
            ));
        }
    }
    if !changes.value_changes.is_empty() {
        out.push_str("\nValue changes:\n\n| Change | Scope | Relative key | Value name | Type | Bytes | SHA-256 |\n|---|---|---|---|---:|---:|---|\n");
        for change in changes.value_changes.iter().take(100) {
            if let Some(value) = change.after.as_ref().or(change.before.as_ref()) {
                out.push_str(&format!(
                    "| {:?} | {} | {} | {} | {} | {} | {} |\n",
                    change.kind,
                    registry_scope_label(RegistryScope {
                        root: value.root,
                        view: value.view,
                    }),
                    registry_path_label(&value.path),
                    registry_value_name_label(&value.name),
                    value.value_type,
                    value.size_bytes,
                    cell(&value.sha256),
                ));
            }
        }
        if changes.value_changes.len() > 100 {
            out.push_str(&format!(
                "\n{} additional value changes are in the JSON report.\n",
                changes.value_changes.len() - 100
            ));
        }
    }
}

fn registry_scope_label(scope: RegistryScope) -> &'static str {
    match (scope.root, scope.view) {
        (ApplicationRegistryRoot::MachineApplication, RegistryView::Registry64) => {
            "Machine application, 64-bit view"
        }
        (ApplicationRegistryRoot::MachineApplication, RegistryView::Registry32) => {
            "Machine application, 32-bit view"
        }
        (ApplicationRegistryRoot::UserApplication, RegistryView::Registry64) => {
            "Standard-user application, 64-bit view"
        }
        (ApplicationRegistryRoot::UserApplication, RegistryView::Registry32) => {
            "Standard-user application, 32-bit view"
        }
    }
}

fn registry_path_label(path: &str) -> String {
    if path.is_empty() {
        "(root)".to_owned()
    } else {
        cell(path)
    }
}

fn registry_value_name_label(name: &str) -> String {
    if name.is_empty() {
        "(Default)".to_owned()
    } else {
        cell(name)
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

fn append_download_metadata_policy(
    out: &mut String,
    policy: Option<&aiw_probe::DownloadMetadataPolicy>,
) {
    if policy.is_some() {
        out.push_str("\nDownload metadata policy: **archive for Sandbox**. Supported source streams were preserved as protected intake sidecars. The tested payload has no named streams; this run does not test the original download's Mark-of-the-Web or SmartScreen handling.\n");
    }
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

    #[test]
    fn registry_markdown_is_metadata_only_and_escaped() {
        use aiw_provider_wsb::{
            RegistryKeyDiff, RegistryKeyEntry, RegistryValueDiff, RegistryValueEntry,
        };
        let scope = RegistryScope {
            root: ApplicationRegistryRoot::MachineApplication,
            view: RegistryView::Registry64,
        };
        let mut out = String::new();
        append_registry_changes(
            &mut out,
            "Installation",
            Some(&RegistrySnapshotDiff {
                key_changes: vec![RegistryKeyDiff {
                    kind: RegistryDiffKind::Added,
                    entry: RegistryKeyEntry {
                        root: scope.root,
                        view: scope.view,
                        path: "[key]|<markup>".to_owned(),
                    },
                }],
                value_changes: vec![RegistryValueDiff {
                    kind: RegistryDiffKind::Modified,
                    before: None,
                    after: Some(RegistryValueEntry {
                        root: scope.root,
                        view: scope.view,
                        path: String::new(),
                        name: String::new(),
                        value_type: 1,
                        size_bytes: 4,
                        sha256: "a".repeat(64),
                    }),
                }],
                incomplete_scopes: vec![scope],
            }),
        );
        assert!(out.contains("\\[key\\]\\|&lt;markup&gt;"));
        assert!(out.contains("(root)"));
        assert!(out.contains("(Default)"));
        assert!(out.contains("Incomplete capture: Machine application, 64-bit view"));
    }
}
