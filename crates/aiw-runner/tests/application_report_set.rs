#![cfg(windows)]
#![forbid(unsafe_code)]

use aiw_runner::{
    ReportSetProfile, ReportSetUnavailableReason, WsbMsiReportSetResult, WsbReportSetInput,
    WsbReportSetResult, report_windows_sandbox_set,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

fn inventory(root: &Path, directory: &Path, files: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if path.is_dir() {
            files.insert(relative, "directory".into());
            inventory(root, &path, files);
        } else {
            files.insert(
                relative,
                hex::encode(Sha256::digest(fs::read(path).unwrap())),
            );
        }
    }
}

#[test]
#[ignore = "reads explicit retained MSI success/failures and Bambu export; never starts Sandbox"]
fn mixed_retained_reports_preserve_functions_failures_and_identity() {
    let input_path =
        std::path::PathBuf::from(std::env::var_os("AIW_MIXED_REPORT_SET_INPUT").unwrap());
    let input: WsbReportSetInput = serde_json::from_slice(&fs::read(&input_path).unwrap()).unwrap();
    assert_eq!(
        input.entries.len(),
        4,
        "provide MSI success, failed snapshot, legacy failure, Bambu success"
    );
    let before: Vec<_> = input
        .entries
        .iter()
        .map(|entry| {
            let mut files = BTreeMap::new();
            inventory(
                &entry.run.workspace_root,
                &entry.run.workspace_root,
                &mut files,
            );
            files
        })
        .collect();
    let mut augmented = input.clone();
    for (id, profile, hash, missing) in [
        ("wrong-profile", ReportSetProfile::NotepadMsi, false, false),
        ("wrong-hash", ReportSetProfile::BambuExport, true, false),
        ("unreadable", ReportSetProfile::BambuExport, false, true),
        ("duplicate", ReportSetProfile::BambuExport, false, false),
    ] {
        let mut entry = input.entries[3].clone();
        entry.run.id = id.into();
        entry.profile = profile;
        if hash {
            entry.run.guest_agent_sha256 = "0".repeat(64);
        }
        if missing {
            entry.run.project_path = entry.run.workspace_root.join("missing-project.json");
        }
        entry.run.workspace_root = entry.run.workspace_root.join(".");
        augmented.entries.push(entry);
    }
    let mut set = report_windows_sandbox_set(&augmented).unwrap();
    let first = &set.entries[0];
    assert_eq!(first.functions.edit_save_document, Some(true));
    assert!(first.functions.stl_to_3mf_export.is_none());
    for row in &set.entries[1..3] {
        assert!(
            serde_json::to_value(&row.functions)
                .unwrap()
                .as_object()
                .unwrap()
                .values()
                .all(|value| value.is_null())
        );
        assert!(matches!(
            row.result,
            WsbReportSetResult::NotepadMsi(WsbMsiReportSetResult::UnsuccessfulAttempt(_))
        ));
    }
    let WsbReportSetResult::NotepadMsi(WsbMsiReportSetResult::UnsuccessfulAttempt(failed)) =
        &set.entries[1].result
    else {
        panic!("failure missing")
    };
    assert_eq!(failed.installation_files.as_ref().unwrap().added, 215);
    assert!(failed.exercise_files.is_none());
    let bambu = &set.entries[3];
    assert_eq!(bambu.functions.stl_to_3mf_export, Some(true));
    assert!(bambu.functions.edit_save_document.is_none());
    assert!(bambu.functions.close.is_none());
    let WsbReportSetResult::BambuExport(report) = &bambu.result else {
        panic!("Bambu missing")
    };
    assert_eq!(report.artifact.as_ref().unwrap().triangle_count, 4);
    assert_eq!(
        report.outcome,
        aiw_orchestrator::RunOutcome::InsufficientEvidence
    );
    for (row, expected) in set.entries[4..].iter().zip([
        ReportSetUnavailableReason::EvidenceRejected,
        ReportSetUnavailableReason::EvidenceRejected,
        ReportSetUnavailableReason::ProjectUnreadable,
        ReportSetUnavailableReason::DuplicateRun,
    ]) {
        assert!(
            matches!(row.result, WsbReportSetResult::Unavailable(reason) if reason == expected)
        );
        assert!(row.functions.stl_to_3mf_export.is_none());
    }
    set.entries.truncate(4);
    assert_eq!(
        serde_json::to_value(&set).unwrap(),
        serde_json::to_value(report_windows_sandbox_set(&input).unwrap()).unwrap()
    );
    for (entry, expected) in input.entries.iter().zip(before) {
        let mut after = BTreeMap::new();
        inventory(
            &entry.run.workspace_root,
            &entry.run.workspace_root,
            &mut after,
        );
        assert_eq!(expected, after);
    }
    fs::write(
        input_path.with_extension("report.json"),
        serde_json::to_vec_pretty(&set).unwrap(),
    )
    .unwrap();
    fs::write(input_path.with_extension("report.md"), set.to_markdown()).unwrap();
}
