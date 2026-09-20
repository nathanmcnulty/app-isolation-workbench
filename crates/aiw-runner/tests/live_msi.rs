#![cfg(windows)]
#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use aiw_orchestrator::{ApprovalRecord, RunLayout, RunOutcome};
use aiw_runner::{WsbApprovedExecution, WsbMsiPreparationInput};

fn prepare() -> (RunLayout, PathBuf, aiw_schema::Project, String) {
    prepare_with_bundle(false)
}

fn prepare_with_bundle(bundle: bool) -> (RunLayout, PathBuf, aiw_schema::Project, String) {
    prepare_profile(bundle, None)
}

fn prepare_profile(
    bundle: bool,
    interactive_seconds: Option<u32>,
) -> (RunLayout, PathBuf, aiw_schema::Project, String) {
    assert_eq!(std::env::var("AIW_RUN_LIVE_WSB_MSI").as_deref(), Ok("1"));
    let guest =
        PathBuf::from(std::env::var_os("AIW_LIVE_GUEST_AGENT").expect("guest agent required"));
    let guest_hash =
        std::env::var("AIW_LIVE_GUEST_AGENT_SHA256").expect("independent agent hash required");
    let intake = PathBuf::from(
        std::env::var_os("AIW_LIVE_MSI_RECEIPT").expect("verified MSI receipt required"),
    );
    let mut receipt: aiw_probe::ApplicationFileImportReceipt =
        serde_json::from_slice(&fs::read(intake).unwrap()).unwrap();
    let mut project: aiw_schema::Project = serde_yaml::from_str(include_str!(
        "../../../examples/notepad-plus-plus-msi.aiw.yaml"
    ))
    .unwrap();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let run_id = format!("aiw-msi-live-{}-{stamp}", std::process::id());
    let parent = std::env::temp_dir().canonicalize().unwrap();
    if let Some(seconds) = interactive_seconds {
        project = serde_yaml::from_str(include_str!(
            "../../../examples/notepad-plus-plus-interactive.aiw.yaml"
        ))
        .unwrap();
        project.scenarios[0].steps[3] = aiw_schema::ScenarioStep::WaitForUserClose {
            timeout_seconds: seconds,
        };
    }
    if bundle {
        let exported = aiw_runner::export_notepad_plus_plus_msi_bundle(
            &parent,
            &format!("{run_id}-bundle"),
            &project,
            "install-launch-close",
            &receipt,
        )
        .unwrap();
        let bundle_root = parent.join(format!("{run_id}-bundle"));
        let relocated = parent.join(format!("{run_id}-bundle-relocated"));
        fs::create_dir(&relocated).unwrap();
        for leaf in ["manifest.aiw", "project.aiw", "app.msi"] {
            fs::copy(bundle_root.join(leaf), relocated.join(leaf)).unwrap();
        }
        let intake_parent = parent.join(format!("{run_id}-intakes"));
        fs::create_dir(&intake_parent).unwrap();
        let imported = aiw_runner::import_notepad_plus_plus_msi_bundle(
            &relocated,
            &intake_parent,
            "replay",
            &exported.manifest_sha256,
        )
        .unwrap();
        eprintln!("MSI_PACKAGE_BUNDLE={}", bundle_root.display());
        eprintln!("MSI_PACKAGE_RELOCATED={}", relocated.display());
        eprintln!("MSI_PACKAGE_MANIFEST_SHA256={}", exported.manifest_sha256);
        fs::write(
            parent.join(format!("{run_id}.bundle-import.json")),
            serde_json::to_vec(&imported).unwrap(),
        )
        .unwrap();
        receipt = imported.import_receipt;
        project = imported.project;
    }
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
            launch_profile: None,
            import_receipt: &receipt,
            scenario_id: "install-launch-close",
            document_input: None,
        },
    )
    .unwrap();
    let root = PathBuf::from(&prepared.receipt.workspace.root.final_path);
    if let Some(seconds) = interactive_seconds {
        assert_eq!(
            prepared.run_plan.lifecycle,
            aiw_orchestrator::RunLifecycleKind::Launch
        );
        assert!(prepared.run_plan.trust_deltas[0].contains(&seconds.to_string()));
        assert!(prepared.run_plan.trust_deltas[0].contains("discarded"));
    }
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
    exercise(false);
}

#[test]
#[ignore = "exports/imports a real MSI bundle and exercises it only inside Sandbox; requires explicit live env inputs"]
fn live_packaged_msi_import_replay_and_cleanup() {
    exercise(true);
}

#[test]
#[ignore = "opens scratch-only Notepad++ in a disposable Sandbox; explicit env selects natural-close or timeout validation"]
fn live_interactive_msi_session_and_cleanup() {
    let expect_closed = match std::env::var("AIW_LIVE_INTERACTIVE_EXPECT").as_deref() {
        Ok("closed") => true,
        Ok("timeout") => false,
        _ => panic!("AIW_LIVE_INTERACTIVE_EXPECT must be closed or timeout"),
    };
    let seconds = if expect_closed { 120 } else { 30 };
    let (layout, project_path, project, guest_hash) = prepare_profile(true, Some(seconds));
    let run_dir = layout.run_dir();
    let root = run_dir.parent().unwrap().parent().unwrap();
    let mut changed = project.clone();
    changed.scenarios[0].steps[3] = aiw_schema::ScenarioStep::WaitForUserClose {
        timeout_seconds: seconds + 1,
    };
    assert!(
        aiw_runner::start_approved_windows_sandbox(root, &project_path, &changed, &guest_hash, 300)
            .is_err()
    );
    assert!(!root.join("tools/request.json").exists());
    let result =
        aiw_runner::start_approved_windows_sandbox(root, &project_path, &project, &guest_hash, 300);
    if matches!(&result, Err(aiw_runner::RunnerError::RecoveryRequired(_))) {
        aiw_runner::recover_windows_sandbox(&layout).unwrap();
    }
    let report =
        aiw_runner::report_windows_sandbox_msi_run(root, layout.run_id(), &project, &guest_hash)
            .unwrap();
    if expect_closed {
        let aiw_runner::WsbMsiRunReport::InteractiveSession(session) = &report else {
            panic!("expected interactive completion: {report:?}");
        };
        assert!(result.is_ok());
        assert!(!session.scenario.graceful_close_requested);
        assert_eq!(session.session_limit_seconds, seconds);
        assert!(!session.application_token.token.is_elevated);
        assert!(session.recorded_cleanup_verified);
    } else {
        assert!(result.is_err());
        let aiw_runner::WsbMsiRunReport::UnsuccessfulAttempt(attempt) = &report else {
            panic!("timeout promoted to completion");
        };
        assert!(attempt.recorded_cleanup_verified);
        assert_eq!(attempt.outcome, RunOutcome::Failed);
        assert_eq!(attempt.interactive_session_seconds, Some(seconds));
        let aiw_runner::UnverifiedGuestDiagnostic::Available { summary } =
            &attempt.guest_diagnostic
        else {
            panic!("expected timeout diagnostic from controlled live trial");
        };
        assert!(
            summary.contains("interactive session wait failed") && summary.contains("timed out"),
            "{summary}"
        );
    }
    assert!(
        aiw_runner::report_windows_sandbox_msi(root, layout.run_id(), &project, &guest_hash)
            .is_err()
    );
    assert!(
        aiw_windows_platform::assess_windows_sandbox()
            .current_session_ids
            .is_empty()
    );
    let parent = root.parent().unwrap();
    let imported: aiw_runner::SandboxBundleImport = serde_json::from_slice(
        &fs::read(parent.join(format!("{}.bundle-import.json", layout.run_id()))).unwrap(),
    )
    .unwrap();
    let packaged = aiw_runner::report_notepad_plus_plus_msi_bundle(
        &parent.join(format!("{}-bundle-relocated", layout.run_id())),
        &imported.verification.manifest_sha256,
        &imported,
        root,
        layout.run_id(),
        &guest_hash,
    )
    .unwrap();
    assert_eq!(
        packaged.manifest.data_contract,
        "ephemeralInteractiveScratch"
    );
    assert_eq!(
        serde_json::to_value(&packaged.report).unwrap(),
        serde_json::to_value(&report).unwrap()
    );
    let set = aiw_runner::report_windows_sandbox_msi_set(&aiw_runner::WsbMsiReportSetInput {
        schema_version: aiw_runner::WSB_MSI_REPORT_SET_INPUT_SCHEMA.into(),
        entries: vec![aiw_runner::WsbMsiReportSetEntry {
            id: "interactive".into(),
            run_id: layout.run_id().into(),
            workspace_root: root.into(),
            project_path,
            guest_agent_sha256: guest_hash,
        }],
    })
    .unwrap();
    assert!(matches!(
        set.entries[0].result,
        aiw_runner::WsbMsiReportSetResult::Unavailable(
            aiw_runner::ReportSetUnavailableReason::InteractiveSessionNotAssessment
        )
    ));
    eprintln!(
        "INTERACTIVE_SESSION_REPORT={}",
        serde_json::to_string(&report).unwrap()
    );
}

fn exercise(bundle: bool) {
    let (layout, project_path, project, guest_hash) = prepare_with_bundle(bundle);
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
    let registration = result
        .product_registration
        .as_ref()
        .expect("v6 product registration required");
    aiw_provider_wsb::validate_msi_product_code(&registration.product_code).unwrap();
    assert_eq!(
        registration.before_install,
        aiw_provider_wsb::MsiMachineProductState::NotRegistered
    );
    assert_eq!(
        registration.after_install,
        aiw_provider_wsb::MsiMachineProductState::Installed
    );
    assert_eq!(
        result.schema_version,
        "aiw.dev/wsb-imported-msi-execution/v0alpha6"
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
    let expected_policy = if bundle {
        None
    } else {
        intake
            .download_metadata_archive
            .map(|archive| archive.policy)
    };
    assert_eq!(report.download_metadata_policy, expected_policy);
    assert_eq!(
        report.schema_version,
        "aiw.dev/wsb-msi-assessment-report/v0alpha11"
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
