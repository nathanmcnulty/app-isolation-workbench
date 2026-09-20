#![cfg(windows)]
#![forbid(unsafe_code)]

use aiw_runner::{SandboxBundleImport, WsbMsiRunReport, report_notepad_plus_plus_msi_bundle};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

fn inventory(root: &Path) -> BTreeMap<String, String> {
    fn visit(root: &Path, dir: &Path, files: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if path.is_dir() {
                files.insert(name, "directory".into());
                visit(root, &path, files);
            } else {
                files.insert(name, hex::encode(Sha256::digest(fs::read(path).unwrap())));
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

#[test]
#[ignore = "reads retained bundle/import/completed run evidence; never executes or changes evidence"]
fn bundle_report_matches_exact_replay_and_rejects_substituted_provenance() {
    let bundle = std::path::PathBuf::from(std::env::var_os("AIW_REPORT_BUNDLE").unwrap());
    let root = std::path::PathBuf::from(std::env::var_os("AIW_REPORT_WORKSPACE").unwrap());
    let imported: SandboxBundleImport = serde_json::from_slice(
        &fs::read(std::env::var_os("AIW_REPORT_BUNDLE_IMPORT").unwrap()).unwrap(),
    )
    .unwrap();
    let expected = std::env::var("AIW_REPORT_MANIFEST_SHA256").unwrap();
    let guest = std::env::var("AIW_REPORT_GUEST_SHA256").unwrap();
    let run_id = root.file_name().unwrap().to_str().unwrap();
    let before = (inventory(&bundle), inventory(&root));
    let report =
        report_notepad_plus_plus_msi_bundle(&bundle, &expected, &imported, &root, run_id, &guest)
            .unwrap();
    assert_eq!(report.manifest_sha256, expected);
    assert_eq!(report.manifest, imported.verification.manifest);
    let WsbMsiRunReport::CompletedAssessment(assessment) = &report.report else {
        panic!("expected retained completed fixture");
    };
    assert!(assessment.stage_progress.as_ref().unwrap().successful());
    assert_eq!(
        assessment.outcome,
        aiw_orchestrator::RunOutcome::InsufficientEvidence
    );
    assert!(!assessment.missing_evidence.is_empty());
    let markdown = report.to_markdown();
    assert!(markdown.contains(&expected));
    assert!(markdown.contains(&report.replay_import_receipt_sha256));
    assert!(markdown.contains(&assessment.to_markdown()));
    let again =
        report_notepad_plus_plus_msi_bundle(&bundle, &expected, &imported, &root, run_id, &guest)
            .unwrap();
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        serde_json::to_value(again).unwrap()
    );
    assert!(
        report_notepad_plus_plus_msi_bundle(
            &bundle,
            &"0".repeat(64),
            &imported,
            &root,
            run_id,
            &guest
        )
        .is_err()
    );
    assert!(
        report_notepad_plus_plus_msi_bundle(
            &bundle,
            &expected,
            &imported,
            &root,
            run_id,
            &"0".repeat(64)
        )
        .is_err()
    );

    let mut changed = imported.clone();
    changed.project.metadata.name.push_str("-different");
    assert!(
        report_notepad_plus_plus_msi_bundle(&bundle, &expected, &changed, &root, run_id, &guest)
            .is_err()
    );
    let mut changed = imported.clone();
    changed.scenario.scenario_id.push_str("-different");
    assert!(
        report_notepad_plus_plus_msi_bundle(&bundle, &expected, &changed, &root, run_id, &guest)
            .is_err()
    );
    let mut changed = imported.clone();
    changed.import_receipt.intake_root.file_id = "0".repeat(32);
    assert!(
        report_notepad_plus_plus_msi_bundle(&bundle, &expected, &changed, &root, run_id, &guest)
            .is_err(),
        "same bytes must not substitute a different intake"
    );
    let mut changed = imported.clone();
    changed.verification.manifest.source_import_receipt_sha256 = "0".repeat(64);
    assert!(
        report_notepad_plus_plus_msi_bundle(&bundle, &expected, &changed, &root, run_id, &guest)
            .is_err()
    );
    assert_eq!(before, (inventory(&bundle), inventory(&root)));
}
