#![cfg(windows)]
#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use aiw_orchestrator::{ApprovalRecord, RunLayout, RunOutcome};
use aiw_runner::{WsbApprovedExecution, WsbBambuPreparationInput};

#[test]
#[ignore = "reverifies an explicit retained Bambu run without starting Sandbox"]
fn retained_bambu_report() {
    let root = PathBuf::from(std::env::var_os("AIW_BAMBU_REPORT_WORKSPACE").unwrap());
    let project: aiw_schema::Project = serde_json::from_slice(
        &fs::read(std::env::var_os("AIW_BAMBU_REPORT_PROJECT").unwrap()).unwrap(),
    )
    .unwrap();
    let hash = std::env::var("AIW_BAMBU_REPORT_GUEST_SHA256").unwrap();
    let run_id = root.file_name().unwrap().to_str().unwrap();
    let report =
        aiw_runner::report_windows_sandbox_bambu_run(&root, run_id, &project, &hash).unwrap();
    assert_eq!(report.outcome, RunOutcome::InsufficientEvidence);
    assert!(report.recorded_cleanup_verified);
    assert!(report.scenario.as_ref().unwrap().successful());
    assert_eq!(report.artifact.as_ref().unwrap().vertex_count, 4);
    assert_eq!(report.artifact.as_ref().unwrap().triangle_count, 4);
    assert_eq!(report.requested_assertions, project.assertions);
    assert!(
        report
            .missing_evidence
            .iter()
            .any(|gap| gap.contains("target token"))
    );
    fs::write(
        root.with_extension("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    fs::write(
        root.with_extension("report.md"),
        aiw_runner::render_bambu_run_report_markdown(&report),
    )
    .unwrap();
}

fn prepare() -> (RunLayout, PathBuf, aiw_schema::Project, String) {
    assert_eq!(std::env::var("AIW_RUN_LIVE_WSB_BAMBU").as_deref(), Ok("1"));
    let guest =
        PathBuf::from(std::env::var_os("AIW_LIVE_GUEST_AGENT").expect("guest agent required"));
    let guest_hash =
        std::env::var("AIW_LIVE_GUEST_AGENT_SHA256").expect("independent agent hash required");
    let intake = PathBuf::from(
        std::env::var_os("AIW_LIVE_BAMBU_RECEIPT").expect("verified Bambu receipt required"),
    );
    let receipt: aiw_probe::ApplicationFileImportReceipt =
        serde_json::from_slice(&fs::read(intake).unwrap()).unwrap();
    let project: aiw_schema::Project =
        serde_yaml::from_str(include_str!("../../../examples/bambu-studio-export.json")).unwrap();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let run_id = format!("aiw-bambu-live-{}-{stamp}", std::process::id());
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
    let prepared = aiw_runner::prepare_windows_sandbox_bambu_bundle(
        &run_id,
        &project,
        &guest,
        &guest_hash,
        &parent,
        &format!("unix-ns:{stamp}"),
        WsbBambuPreparationInput {
            import_receipt: &receipt,
            scenario_id: "local-file-export",
        },
    )
    .unwrap();
    let root = PathBuf::from(&prepared.receipt.workspace.root.final_path);
    eprintln!("BAMBU_LIVE_WORKSPACE={}", root.display());
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
#[ignore = "installs the approved Bambu EXE only inside Windows Sandbox; explicit live env inputs required"]
fn live_bambu_export_report_and_cleanup() {
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
        600,
    );
    if matches!(&result, Err(aiw_runner::RunnerError::RecoveryRequired(_))) {
        eprintln!(
            "BAMBU_LIVE_RECOVERY={:?}",
            aiw_runner::recover_windows_sandbox(&layout)
        );
    }
    let execution = match result {
        Ok(WsbApprovedExecution::ImportedBambu(value)) => value,
        other => {
            eprintln!(
                "BAMBU_FAILURE_REPORT={:?}",
                aiw_runner::report_windows_sandbox_bambu_run(
                    &root,
                    layout.run_id(),
                    &project,
                    &guest_hash
                )
            );
            panic!("Bambu execution failed: {other:?}")
        }
    };
    assert!(execution.cleanup_complete);
    assert!(execution.scenario.successful());
    assert_eq!(execution.artifact.vertex_count, 4);
    assert_eq!(execution.artifact.triangle_count, 4);
    let report =
        aiw_runner::report_windows_sandbox_bambu_run(&root, layout.run_id(), &project, &guest_hash)
            .unwrap();
    assert_eq!(report.outcome, RunOutcome::InsufficientEvidence);
    assert_eq!(report.artifact.as_ref(), Some(&execution.artifact));
    assert_eq!(
        report.evidence_root_hash.as_ref(),
        Some(&execution.evidence_root_hash)
    );
    let json = serde_json::to_vec_pretty(&report).unwrap();
    assert_eq!(
        json,
        serde_json::to_vec_pretty(
            &aiw_runner::report_windows_sandbox_bambu_run(
                &root,
                layout.run_id(),
                &project,
                &guest_hash
            )
            .unwrap()
        )
        .unwrap()
    );
    assert!(
        aiw_runner::report_windows_sandbox_bambu_run(
            &root,
            layout.run_id(),
            &project,
            &"f".repeat(64)
        )
        .is_err()
    );
    let artifact_path = root.join("output/aiw-tetrahedron.3mf");
    let original = fs::read(&artifact_path).unwrap();
    fs::write(&artifact_path, b"invalid model").unwrap();
    let rejected =
        aiw_runner::report_windows_sandbox_bambu_run(&root, layout.run_id(), &project, &guest_hash)
            .is_err();
    fs::write(&artifact_path, original).unwrap();
    assert!(rejected);
    aiw_runner::report_windows_sandbox_bambu_run(&root, layout.run_id(), &project, &guest_hash)
        .unwrap();
    fs::write(root.with_extension("report.json"), &json).unwrap();
    fs::write(
        root.with_extension("report.md"),
        aiw_runner::render_bambu_run_report_markdown(&report),
    )
    .unwrap();
    eprintln!("BAMBU_LIVE_SUCCESS={}", root.display());
}
