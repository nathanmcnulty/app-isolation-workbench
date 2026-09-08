#![cfg(windows)]
#![forbid(unsafe_code)]

use aiw_runner::{AssessmentEvidenceGap, report_windows_sandbox_msi};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Write, path::Path};

fn inventory(root: &Path, directory: &Path, files: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if path.is_dir() {
            files.insert(relative, "directory".to_owned());
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
#[ignore = "reads a retained completed MSI fixture; temporarily creates one extra output file; never starts Sandbox"]
fn completed_msi_report_is_readonly_and_rejects_drift() {
    let root = std::path::PathBuf::from(std::env::var_os("AIW_REPORT_WORKSPACE").unwrap());
    let project_path = std::env::var_os("AIW_REPORT_PROJECT").unwrap();
    let guest_hash = std::env::var("AIW_REPORT_GUEST_SHA256").unwrap();
    let project: aiw_schema::Project =
        serde_json::from_slice(&fs::read(project_path).unwrap()).unwrap();
    let run_id = root.file_name().unwrap().to_str().unwrap();
    let mut before = BTreeMap::new();
    inventory(&root, &root, &mut before);
    let report = report_windows_sandbox_msi(&root, run_id, &project, &guest_hash).unwrap();
    assert_eq!(
        report.outcome,
        aiw_orchestrator::RunOutcome::InsufficientEvidence
    );
    assert!(report.recorded_cleanup_verified);
    assert!(
        report
            .missing_evidence
            .contains(&AssessmentEvidenceGap::OrdinaryBaseline)
    );
    assert!(
        report
            .missing_evidence
            .contains(&AssessmentEvidenceGap::IndependentHostMeasurements)
    );
    assert_eq!(report.requested_assertions, project.assertions);
    assert!(
        report
            .missing_evidence
            .contains(&AssessmentEvidenceGap::TargetToken)
    );
    assert_eq!(
        report.application_token.as_ref().unwrap().token.process_id,
        report.scenario.launch_process_id
    );
    let preparation: aiw_runner::WsbPreparationReceipt =
        serde_json::from_slice(&fs::read(root.join("preparation.json")).unwrap()).unwrap();
    if preparation
        .msi
        .unwrap()
        .scenario
        .requires_application_exercise()
    {
        assert_eq!(
            report.schema_version,
            "aiw.dev/wsb-msi-assessment-report/v0alpha2"
        );
        let behavior = report
            .behavior
            .as_ref()
            .expect("v3 report must retain functional evidence");
        assert!(
            behavior.functional_exercise.opened_document
                && behavior.functional_exercise.saved_document
        );
        assert!(
            !report
                .installation_file_changes
                .as_ref()
                .unwrap()
                .diffs
                .is_empty()
        );
        assert!(report.exercise_file_changes.is_some());
        assert!(
            report
                .missing_evidence
                .contains(&AssessmentEvidenceGap::FilesystemRegistryChanges)
        );
    } else {
        assert_eq!(
            report.schema_version,
            "aiw.dev/wsb-msi-assessment-report/v0alpha1"
        );
        assert!(report.behavior.is_none());
        assert!(report.installation_file_changes.is_none());
        assert!(report.exercise_file_changes.is_none());
    }
    let aiw_runner::WsbMsiRunReport::CompletedAssessment(general) =
        aiw_runner::report_windows_sandbox_msi_run(&root, run_id, &project, &guest_hash).unwrap()
    else {
        panic!("completed assessment downgraded");
    };
    assert_eq!(
        serde_json::to_vec(&report).unwrap(),
        serde_json::to_vec(&general).unwrap()
    );
    let repeated = report_windows_sandbox_msi(&root, run_id, &project, &guest_hash).unwrap();
    assert_eq!(
        serde_json::to_vec(&report).unwrap(),
        serde_json::to_vec(&repeated).unwrap()
    );
    assert!(report_windows_sandbox_msi(&root, run_id, &project, &"0".repeat(64)).is_err());
    let mut foreign_project = project.clone();
    foreign_project.metadata.name = "foreign-project".to_owned();
    assert!(report_windows_sandbox_msi(&root, run_id, &foreign_project, &guest_hash).is_err());
    let extra = root.join("output/report-test-unexpected.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&extra)
        .unwrap();
    file.write_all(b"{}").unwrap();
    drop(file);
    let rejected = report_windows_sandbox_msi(&root, run_id, &project, &guest_hash);
    fs::remove_file(&extra).unwrap();
    assert!(rejected.is_err());
    let mut after = BTreeMap::new();
    inventory(&root, &root, &mut after);
    assert_eq!(before, after);
    eprintln!(
        "MSI_ASSESSMENT_REPORT={}",
        serde_json::to_string(&report).unwrap()
    );
}

#[test]
#[ignore = "reads a retained failed MSI fixture; creates only one temporary fake completion; never starts Sandbox"]
fn unsuccessful_msi_report_is_readonly_and_never_promotes_guest_outputs() {
    use aiw_runner::{UnverifiedGuestDiagnostic, WsbMsiRunReport, report_windows_sandbox_msi_run};
    let root = std::path::PathBuf::from(std::env::var_os("AIW_REPORT_WORKSPACE").unwrap());
    let project_path = std::env::var_os("AIW_REPORT_PROJECT").unwrap();
    let guest_hash = std::env::var("AIW_REPORT_GUEST_SHA256").unwrap();
    let project: aiw_schema::Project =
        serde_json::from_slice(&fs::read(project_path).unwrap()).unwrap();
    let run_id = root.file_name().unwrap().to_str().unwrap();
    let mut before = BTreeMap::new();
    inventory(&root, &root, &mut before);
    let report = report_windows_sandbox_msi_run(&root, run_id, &project, &guest_hash).unwrap();
    let WsbMsiRunReport::UnsuccessfulAttempt(attempt) = &report else {
        panic!("failure promoted to assessment");
    };
    assert_eq!(attempt.outcome, aiw_orchestrator::RunOutcome::Failed);
    assert!(attempt.recorded_cleanup_verified);
    assert_eq!(
        attempt.lifecycle.last().unwrap().state,
        aiw_runner::SessionTransactionState::CleanupVerified
    );
    assert!(matches!(
        attempt.guest_diagnostic,
        UnverifiedGuestDiagnostic::Available { .. }
    ));
    let bytes = serde_json::to_vec(&report).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for field in [
        "evidenceRootHash",
        "receiptSha256",
        "applicationToken",
        "behavior",
        "scenario",
        "installationFileChanges",
    ] {
        assert!(value["report"].get(field).is_none());
    }
    assert!(
        report
            .to_markdown()
            .contains("functions are **not verified**")
    );
    assert!(report_windows_sandbox_msi(&root, run_id, &project, &guest_hash).is_err());
    assert!(report_windows_sandbox_msi_run(&root, run_id, &project, &"0".repeat(64)).is_err());
    let mut foreign = project.clone();
    foreign.metadata.name = "foreign-project".to_owned();
    assert!(report_windows_sandbox_msi_run(&root, run_id, &foreign, &guest_hash).is_err());
    let extra = root.join("output/completion.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&extra)
        .unwrap();
    file.write_all(br#"{"successful":true,"evidenceRootHash":"unaccepted"}"#)
        .unwrap();
    drop(file);
    let repeated = report_windows_sandbox_msi_run(&root, run_id, &project, &guest_hash);
    fs::remove_file(&extra).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&repeated.unwrap()).unwrap());
    let mut after = BTreeMap::new();
    inventory(&root, &root, &mut after);
    assert_eq!(before, after);
    eprintln!(
        "MSI_UNSUCCESSFUL_REPORT={}",
        String::from_utf8(bytes).unwrap()
    );
}
