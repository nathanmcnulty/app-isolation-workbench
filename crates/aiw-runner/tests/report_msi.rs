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
    if let Some(product) = &report.product_registration {
        aiw_provider_wsb::validate_msi_product_code(&product.product_code).unwrap();
        assert_eq!(product.installer_sha256, report.scenario.installer_sha256);
        assert_eq!(
            product.before_install,
            aiw_provider_wsb::MsiMachineProductState::NotRegistered
        );
        assert_eq!(
            product.after_install,
            aiw_provider_wsb::MsiMachineProductState::Installed
        );
        assert!(
            report
                .to_markdown()
                .contains("Machine product registration")
        );
    }
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
    assert_eq!(
        report.schema_version,
        "aiw.dev/wsb-msi-assessment-report/v0alpha11"
    );
    assert_eq!(report.recorded_execution.provider, preparation.provider);
    assert_eq!(
        report.recorded_execution.provider_package,
        preparation.provider_package
    );
    assert_eq!(
        report.recorded_execution.provider_protocol,
        preparation.provider_protocol
    );
    assert_eq!(
        report
            .recorded_execution
            .normalized_sandbox_config_sha256
            .len(),
        64
    );
    assert!(report.to_markdown().contains(&preparation.provider.sha256));
    let markdown = report.to_markdown();
    assert!(markdown.contains("## Administrator overview"));
    assert!(markdown.contains(&format!(
        "Installer SHA-256: `{}`",
        report.scenario.installer_sha256
    )));
    assert!(markdown.contains("Assessment: **insufficientEvidence** for broader isolation"));
    assert!(markdown.contains("Safe next action:"));
    assert!(markdown.contains("| Edit and save expected bytes | Passed |"));
    let prepared_scenario = preparation.msi.unwrap().scenario;
    if prepared_scenario.requires_application_exercise() {
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
        if prepared_scenario.requires_registry_observations() {
            let registry = report
                .registry_evidence
                .as_ref()
                .expect("v5 report must retain registry evidence");
            assert_eq!(
                registry.user_sid,
                report
                    .standard_user_context
                    .as_ref()
                    .expect("v5 report requires standard-user context")
                    .context
                    .user_sid
            );
            registry.before_install.validate().unwrap();
            registry.after_install.validate().unwrap();
            registry.after_exercise.validate().unwrap();
            assert!(report.installation_registry_changes.is_some());
            assert!(report.exercise_registry_changes.is_some());
        } else {
            assert!(report.registry_evidence.is_none());
            assert!(report.installation_registry_changes.is_none());
            assert!(report.exercise_registry_changes.is_none());
        }
        assert!(
            report
                .missing_evidence
                .contains(&AssessmentEvidenceGap::FilesystemRegistryChanges)
        );
    } else {
        assert_eq!(
            report.schema_version,
            "aiw.dev/wsb-msi-assessment-report/v0alpha11"
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
    match &attempt.guest_diagnostic {
        UnverifiedGuestDiagnostic::Available { .. } => {}
        UnverifiedGuestDiagnostic::Absent => assert!(matches!(
            attempt.failure_progress,
            aiw_runner::FailureProgressEvidence::Verified(_)
        )),
        UnverifiedGuestDiagnostic::Rejected => panic!("fixture diagnostic rejected"),
    }
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
    let markdown = report.to_markdown();
    assert!(markdown.contains(&format!(
        "Installer SHA-256: `{}`",
        attempt.installer_sha256
    )));
    assert!(markdown.contains(
        "may be in setup, the worker, the installer, the application, or the test driver"
    ));
    assert!(markdown.contains("Safe next action:"));
    assert!(report_windows_sandbox_msi(&root, run_id, &project, &guest_hash).is_err());
    assert!(report_windows_sandbox_msi_run(&root, run_id, &project, &"0".repeat(64)).is_err());
    let mut foreign = project.clone();
    foreign.metadata.name = "foreign-project".to_owned();
    assert!(report_windows_sandbox_msi_run(&root, run_id, &foreign, &guest_hash).is_err());
    let extra = root.join("output/unexpected-completion.json");
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
    let repeated = repeated.unwrap();
    let WsbMsiRunReport::UnsuccessfulAttempt(repeated) = repeated else {
        panic!("fake completion promoted failure");
    };
    assert!(matches!(
        repeated.failure_progress,
        aiw_runner::FailureProgressEvidence::Rejected
    ));
    let mut repeated_json = serde_json::to_value(&*repeated).unwrap();
    if value["report"]["schemaVersion"] == "aiw.dev/wsb-msi-unsuccessful-report/v0alpha4" {
        assert_eq!(
            repeated.schema_version,
            if repeated.download_metadata_policy.is_some() {
                "aiw.dev/wsb-msi-unsuccessful-report/v0alpha3"
            } else {
                "aiw.dev/wsb-msi-unsuccessful-report/v0alpha2"
            }
        );
        repeated_json["schemaVersion"] = value["report"]["schemaVersion"].clone();
    }
    repeated_json["failureProgress"] = value["report"]["failureProgress"].clone();
    assert_eq!(value["report"], repeated_json);
    let mut after = BTreeMap::new();
    inventory(&root, &root, &mut after);
    assert_eq!(before, after);
    eprintln!(
        "MSI_UNSUCCESSFUL_REPORT={}",
        String::from_utf8(bytes).unwrap()
    );
}
