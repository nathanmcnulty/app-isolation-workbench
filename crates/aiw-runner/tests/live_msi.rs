#![cfg(windows)]
#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use aiw_orchestrator::{ApprovalRecord, RunLayout, RunOutcome};
use aiw_runner::{WsbApprovedExecution, WsbMsiPreparationInput};

fn prepare() -> (RunLayout, PathBuf, aiw_schema::Project, String) {
    assert_eq!(std::env::var("AIW_RUN_LIVE_WSB_MSI").as_deref(), Ok("1"));
    let guest =
        PathBuf::from(std::env::var_os("AIW_LIVE_GUEST_AGENT").expect("guest agent required"));
    let guest_hash =
        std::env::var("AIW_LIVE_GUEST_AGENT_SHA256").expect("independent agent hash required");
    let intake = PathBuf::from(
        std::env::var_os("AIW_LIVE_MSI_RECEIPT").expect("verified MSI receipt required"),
    );
    let receipt: aiw_probe::ApplicationFileImportReceipt =
        serde_json::from_slice(&fs::read(intake).unwrap()).unwrap();
    let project: aiw_schema::Project = serde_yaml::from_str(include_str!(
        "../../../examples/notepad-plus-plus-msi.aiw.yaml"
    ))
    .unwrap();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let run_id = format!("aiw-msi-live-{}-{stamp}", std::process::id());
    let parent = std::env::temp_dir().canonicalize().unwrap();
    let project_path = parent.join(format!("{run_id}.project.json"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&project_path)
        .unwrap();
    file.write_all(&serde_json::to_vec(&project).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    drop(file);
    let prepared = aiw_runner::prepare_windows_sandbox_msi_bundle(
        &run_id,
        &project,
        &guest,
        &guest_hash,
        &parent,
        &format!("unix-ns:{stamp}"),
        WsbMsiPreparationInput {
            import_receipt: &receipt,
            scenario_id: "install-launch-close",
        },
    )
    .unwrap();
    let root = PathBuf::from(&prepared.receipt.workspace.root.final_path);
    eprintln!("MSI_LIVE_WORKSPACE={}", root.display());
    aiw_runner::import_windows_sandbox_preparation(
        &root,
        &project,
        &guest_hash,
        "live-test-import",
    )
    .unwrap();
    let layout = RunLayout::new(&root, &run_id).unwrap();
    let approval = ApprovalRecord::for_plan(
        &prepared.run_plan,
        "Codex live validation authorized by user",
        "live-test-approval",
    )
    .unwrap();
    layout.write_approval(&approval).unwrap();
    let golden = aiw_runner::start_approved_windows_sandbox_golden_probe(
        &root,
        &project_path,
        &project,
        &guest_hash,
        300,
    );
    assert!(
        matches!(golden, Err(aiw_runner::RunnerError::ApprovalBinding)),
        "{golden:?}"
    );
    (layout, project_path, project, guest_hash)
}

#[test]
#[ignore = "installs and exercises the recorded MSI only inside Windows Sandbox; requires explicit live env inputs"]
fn live_imported_msi_install_observe_close_and_cleanup() {
    let (layout, project_path, project, guest_hash) = prepare();
    let root = layout
        .run_dir()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let result = aiw_runner::start_approved_windows_sandbox(
        &root,
        &project_path,
        &project,
        &guest_hash,
        300,
    );
    if matches!(&result, Err(aiw_runner::RunnerError::RecoveryRequired(_))) {
        eprintln!(
            "MSI_LIVE_RECOVERY={:?}",
            aiw_runner::recover_windows_sandbox(&layout)
        );
    }
    let WsbApprovedExecution::ImportedMsi(result) = result.unwrap() else {
        panic!("wrong execution profile")
    };
    assert!(result.scenario.successful());
    assert_eq!(
        result.schema_version,
        "aiw.dev/wsb-imported-msi-execution/v0alpha5"
    );
    let token = result
        .application_token
        .as_ref()
        .expect("approved profile requires application token");
    assert_eq!(token.token.process_id, result.scenario.launch_process_id);
    assert_eq!(token.request_sha256, result.request_sha256);
    assert!(!token.token.is_elevated);
    assert_eq!(token.token.integrity.rid, 8192);
    let runtime = result
        .standard_user_context
        .as_ref()
        .expect("standard-user context required");
    assert_eq!(runtime.context.user_sid, token.token.user_sid);
    assert_eq!(runtime.context.profile_path, r"C:\Users\AiwStandardUser");
    assert!(!runtime.context.administrators_enabled);
    let registry = result
        .registry_evidence
        .as_ref()
        .expect("v5 scenario requires registry evidence");
    assert_eq!(registry.user_sid, runtime.context.user_sid);
    registry.before_install.validate().unwrap();
    registry.after_install.validate().unwrap();
    registry.after_exercise.validate().unwrap();
    assert!(registry.before_install.issues.is_empty());
    assert!(registry.after_install.issues.is_empty());
    assert!(registry.after_exercise.issues.is_empty());
    let behavior = result
        .behavior
        .as_ref()
        .expect("approved profile requires functional and filesystem observations");
    assert!(behavior.functional_exercise.opened_document);
    assert!(behavior.functional_exercise.saved_document);
    assert_eq!(
        behavior.functional_exercise.expected_sha256,
        behavior.functional_exercise.observed_sha256
    );
    assert!(behavior.before_install.entries.is_empty());
    assert!(!behavior.after_install.entries.is_empty());
    assert!(behavior.before_install.issues.is_empty());
    assert!(behavior.after_install.issues.is_empty());
    assert!(behavior.after_exercise.issues.is_empty());
    assert_eq!(result.scenario.install_exit_code, 0);
    assert_eq!(result.scenario.launch_exit_code, 0);
    assert!(result.cleanup_complete);
    let report =
        aiw_runner::report_windows_sandbox_msi(&root, layout.run_id(), &project, &guest_hash)
            .unwrap();
    let intake: aiw_probe::ApplicationFileImportReceipt = serde_json::from_slice(
        &fs::read(PathBuf::from(
            std::env::var_os("AIW_LIVE_MSI_RECEIPT").unwrap(),
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        report.download_metadata_policy,
        intake
            .download_metadata_archive
            .map(|archive| archive.policy)
    );
    assert_eq!(
        report.schema_version,
        "aiw.dev/wsb-msi-assessment-report/v0alpha6"
    );
    if report.download_metadata_policy.is_some() {
        assert!(
            report
                .to_markdown()
                .contains("does not test the original download")
        );
    }
    assert!(report.standard_user_context.is_some());
    assert!(report.registry_evidence.is_some());
    assert!(report.installation_registry_changes.is_some());
    assert!(report.exercise_registry_changes.is_some());
    assert!(report.to_markdown().contains("Registry changes"));
    assert!(report.to_markdown().contains("Standard-user runtime"));
    let stages = report
        .stage_progress
        .as_ref()
        .expect("current guest emits stage progress");
    assert!(stages.successful());
    assert_eq!(stages.stages.len(), 9);
    eprintln!(
        "MSI_STAGE_PROGRESS={}",
        serde_json::to_string(stages).unwrap()
    );

    assert!(!root.join("tools/request.json").exists());
    assert_eq!(
        layout.read_result().unwrap().outcome,
        RunOutcome::InsufficientEvidence
    );
    assert!(
        aiw_windows_platform::assess_windows_sandbox()
            .current_session_ids
            .is_empty()
    );
    eprintln!(
        "MSI_LIVE_RESULT={}",
        serde_json::to_string(&result).unwrap()
    );
    // MSI workspace deletion is deliberately outside the golden-only discard contract.
    // Preserve the project, imported preparation, journal, and guest artifacts for review.
}

#[test]
#[ignore = "runs the controlled instrumented guest failure inside Windows Sandbox; requires explicit live env inputs and a guest that fails after installation capture"]
fn live_imported_msi_failed_run_retains_install_snapshots_only() {
    let (layout, project_path, project, guest_hash) = prepare();
    let root = layout
        .run_dir()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let result = aiw_runner::start_approved_windows_sandbox(
        &root,
        &project_path,
        &project,
        &guest_hash,
        300,
    );
    if matches!(&result, Err(aiw_runner::RunnerError::RecoveryRequired(_))) {
        eprintln!(
            "MSI_LIVE_RECOVERY={:?}",
            aiw_runner::recover_windows_sandbox(&layout)
        );
    }
    assert!(
        result.is_err(),
        "controlled guest failure must remain failed"
    );
    let report =
        aiw_runner::report_windows_sandbox_msi_run(&root, layout.run_id(), &project, &guest_hash)
            .unwrap();
    let aiw_runner::WsbMsiRunReport::UnsuccessfulAttempt(attempt) = report else {
        panic!("failed execution was promoted to an assessment");
    };
    assert_eq!(attempt.outcome, RunOutcome::Failed);
    assert!(attempt.recorded_cleanup_verified);
    let aiw_runner::FailureProgressEvidence::Verified(progress) = attempt.failure_progress else {
        panic!("controlled failure did not retain a verified failed receipt");
    };
    assert_eq!(
        progress.attempt.progress.stages[3],
        aiw_provider_wsb::MsiStageResult {
            stage: aiw_provider_wsb::MsiExecutionStage::PrepareDocument,
            status: aiw_provider_wsb::MsiStageStatus::Failed,
        }
    );
    let snapshots = progress.snapshots.expect("failed snapshots retained");
    assert!(snapshots.before_install.is_some());
    assert!(snapshots.after_install.is_some());
    assert!(snapshots.after_exercise.is_none());
    assert!(snapshots.capture_context.is_some());
    assert!(
        !progress
            .installation_file_changes
            .as_ref()
            .unwrap()
            .diffs
            .is_empty()
    );
    assert!(progress.installation_registry_changes.is_some());
    assert!(progress.exercise_file_changes.is_none());
    assert!(progress.exercise_registry_changes.is_none());
    assert_eq!(
        attempt.schema_version,
        "aiw.dev/wsb-msi-unsuccessful-report/v0alpha4"
    );
    assert!(
        aiw_windows_platform::assess_windows_sandbox()
            .current_session_ids
            .is_empty()
    );
}

#[test]
#[ignore = "native preparation/approval tamper proof; no installer or Sandbox is started"]
fn live_imported_msi_tamper_rejects_before_start() {
    let (layout, project_path, project, guest_hash) = prepare();
    let root = layout
        .run_dir()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let mut file = OpenOptions::new()
        .append(true)
        .open(root.join("tools/application.msi"))
        .unwrap();
    file.write_all(b"tampered").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(matches!(
        aiw_runner::start_approved_windows_sandbox(
            &root,
            &project_path,
            &project,
            &guest_hash,
            300
        ),
        Err(aiw_runner::RunnerError::Preparation(_))
    ));
    assert!(!layout.result_path().exists());
    assert!(!layout.run_dir().join("wsb-session-transaction").exists());
    assert!(!root.join("tools/request.json").exists());
    assert!(
        aiw_windows_platform::assess_windows_sandbox()
            .current_session_ids
            .is_empty()
    );
}
