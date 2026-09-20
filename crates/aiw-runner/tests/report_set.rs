#![cfg(windows)]
#![forbid(unsafe_code)]

use aiw_runner::{
    ReportSetUnavailableReason, WsbMsiReportSetInput, WsbMsiReportSetResult,
    report_windows_sandbox_msi_set,
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
#[ignore = "reads explicit retained successful, failed and legacy fixtures; never starts Sandbox"]
fn retained_set_preserves_failures_missing_evidence_and_verified_identity() {
    let input: WsbMsiReportSetInput = serde_json::from_slice(
        &fs::read(std::env::var_os("AIW_REPORT_SET_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        input.entries.len(),
        3,
        "provide current success, retained-snapshot failure, legacy failure"
    );
    let mut before = Vec::new();
    for entry in &input.entries {
        let mut inventory_map = BTreeMap::new();
        inventory(
            &entry.workspace_root,
            &entry.workspace_root,
            &mut inventory_map,
        );
        before.push(inventory_map);
    }
    let first = report_windows_sandbox_msi_set(&input).unwrap();
    let WsbMsiReportSetResult::CompletedScenario(success) = &first.entries[0].result else {
        panic!("expected success fixture");
    };
    assert_eq!(success.functions.edit_save_document, Some(true));
    assert_eq!(
        success.recorded_outcome,
        aiw_orchestrator::RunOutcome::InsufficientEvidence
    );
    let WsbMsiReportSetResult::UnsuccessfulAttempt(failed) = &first.entries[1].result else {
        panic!("expected failure fixture");
    };
    assert_eq!(failed.installation_files.as_ref().unwrap().added, 215);
    assert!(failed.exercise_files.is_none());
    assert!(failed.functions.launch.is_none());
    assert!(failed.receipt_sha256.is_some());
    let WsbMsiReportSetResult::UnsuccessfulAttempt(legacy) = &first.entries[2].result else {
        panic!("expected legacy failure");
    };
    assert!(legacy.installation_files.is_none());
    assert!(legacy.installation_registry.is_none());
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(report_windows_sandbox_msi_set(&input).unwrap()).unwrap()
    );

    let mut changed = input.clone();
    let mut duplicate = input.entries[0].clone();
    duplicate.id = "duplicate-label".into();
    // A distinct caller path spelling still selects the same verified run identity.
    duplicate.workspace_root = duplicate.workspace_root.join(".");
    changed.entries.push(duplicate);
    let mut wrong_hash = input.entries[0].clone();
    wrong_hash.id = "wrong-hash".into();
    wrong_hash.guest_agent_sha256 = "0".repeat(64);
    changed.entries.push(wrong_hash);
    let mut unreadable = input.entries[0].clone();
    unreadable.id = "unreadable-project".into();
    unreadable.project_path = unreadable.workspace_root.join("no-such-project.json");
    changed.entries.push(unreadable);
    let changed = report_windows_sandbox_msi_set(&changed).unwrap();
    assert_eq!(changed.entries.len(), 6);
    assert!(matches!(
        changed.entries[3].result,
        WsbMsiReportSetResult::Unavailable(ReportSetUnavailableReason::DuplicateRun)
    ));
    assert!(matches!(
        changed.entries[4].result,
        WsbMsiReportSetResult::Unavailable(ReportSetUnavailableReason::EvidenceRejected)
    ));
    assert!(matches!(
        changed.entries[5].result,
        WsbMsiReportSetResult::Unavailable(ReportSetUnavailableReason::ProjectUnreadable)
    ));
    assert_eq!(
        serde_json::to_value(&first.entries).unwrap(),
        serde_json::to_value(&changed.entries[..3]).unwrap()
    );
    for (index, entry) in input.entries.iter().enumerate() {
        let mut after = BTreeMap::new();
        inventory(&entry.workspace_root, &entry.workspace_root, &mut after);
        assert_eq!(before[index], after);
    }
}
