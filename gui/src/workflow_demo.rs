//! Opt-in replay producer. Reads only an explicit synthetic service fixture.
use super::*;
use aiw_admin_workflow::paired;
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
fn read(path: &Path, limit: u64) -> Vec<u8> {
    let mut bytes = vec![];
    File::open(path)
        .unwrap()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() as u64 <= limit);
    bytes
}
fn write(path: &Path, value: &impl serde::Serialize) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(value).unwrap())
        .unwrap();
    file.sync_all().unwrap();
}
fn normalized(path: &Path) -> String {
    let value = path.to_string_lossy();
    value
        .strip_prefix(r"\\?\")
        .unwrap_or(&value)
        .trim_end_matches('\\')
        .to_lowercase()
}
#[test]
#[ignore = "creates fresh controller snapshots for explicit synthetic UI replay; no provider backend"]
fn demonstrate_paired_workflow() {
    let source = PathBuf::from(
        std::env::var_os("AIW_PAIRED_UI_SOURCE").expect("explicit synthetic service fixture"),
    );
    assert!(
        source
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("aiw-paired-service-")
    );
    let marker: Value =
        serde_json::from_slice(&read(&source.join("synthetic-demo.json"), 16384)).unwrap();
    assert_eq!(
        marker["schemaVersion"],
        "aiw.dev/paired-synthetic-demo/v0alpha1"
    );
    assert_eq!(marker["origin"], "syntheticRehearsal");
    assert_eq!(marker["realProviderApplicationControlCalls"], 0);
    let bytes = read(&source.join("ui-review-source.json"), 1024 * 1024);
    let data: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        data["schemaVersion"],
        "aiw.dev/paired-ui-review-source/v0alpha1"
    );
    let run: paired::PairedRun = serde_json::from_value(data["run"].clone()).unwrap();
    assert_eq!(
        run.evidence_root.canonicalize().unwrap(),
        source.canonicalize().unwrap()
    );
    assert_eq!(
        paired::open_retained(&run.workspace, &run.run_id).unwrap(),
        run
    );
    let plan: aiw_orchestrator::RunPlan = serde_json::from_value(data["plan"].clone()).unwrap();
    assert_eq!(plan.hash().unwrap().as_str(), run.plan_sha256);
    let approval: aiw_orchestrator::ApprovalRecord =
        serde_json::from_value(data["approval"].clone()).unwrap();
    assert_eq!(approval.plan_hash, run.plan_sha256);
    assert_eq!(
        run.validate()
            .unwrap()
            .retained_snapshot()
            .unwrap()
            .approval,
        Some(approval.clone())
    );
    let report = paired::report(&run).unwrap();
    assert_eq!(
        serde_json::to_value(&report.profile).unwrap()["origin"],
        "syntheticRehearsal"
    );
    assert!(report.comparison.as_ref().unwrap().eligible);
    assert!(!report.comparison.as_ref().unwrap().production_acceptance);
    let parent =
        PathBuf::from(std::env::var_os("AIW_RESULTS_DEMO").expect("explicit output parent"))
            .canonicalize()
            .unwrap();
    let source_path = normalized(&source.canonicalize().unwrap());
    let output_path = normalized(&parent);
    assert!(
        output_path != source_path && !output_path.starts_with(&(source_path + "\\")),
        "UI output must be outside source fixture"
    );
    let root = parent.join(format!("paired-ui-replay-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let controller = Controller::new(run.evidence_root.to_string_lossy().into_owned());
    let idle = controller.snapshot();
    let id = controller.begin().unwrap();
    controller
        .register_paired(&id, &run.plan_sha256, serde_json::to_string(&run).unwrap())
        .unwrap();
    controller.progress(
        &id,
        "SYNTHETIC UI replay: preparation records exist; no provider is invoked.",
    );
    let preparing = controller.snapshot();
    let rx = controller
        .offer_review(
            &id,
            Review {
                workflow_name: "SYNTHETIC replay · fixed paired controls".into(),
                challenge_id: String::new(),
                plan_hash: run.plan_sha256.clone(),
                exact_confirmation: format!("approve {}", run.plan_sha256),
                operator_identity: approval.approved_by.to_string(),
                recipe_json: serde_json::to_string_pretty(&data["recipe"]).unwrap(),
                plan_json: serde_json::to_string_pretty(&plan).unwrap(),
                approval_json: serde_json::to_string_pretty(&approval).unwrap(),
                evidence_root: run.evidence_root.to_string_lossy().into_owned(),
                workspace: run.workspace.to_string_lossy().into_owned(),
            },
        )
        .unwrap();
    let review = controller.snapshot();
    let r = review.review.as_ref().unwrap();
    assert!(controller.start(&id, &r.challenge_id).is_err());
    controller
        .approve(&id, &r.challenge_id, &r.exact_confirmation)
        .unwrap();
    assert_eq!(rx.recv().unwrap(), Some(r.exact_confirmation.clone()));
    let start = controller.offer_start(&id).unwrap();
    let approved = controller.snapshot();
    controller
        .start(&id, approved.start_challenge_id.as_ref().unwrap())
        .unwrap();
    assert!(start.recv().unwrap());
    controller.progress(&id,"SYNTHETIC UI replay: retained fake-kernel fixture; zero real provider/application/control calls.");
    let running = controller.snapshot();
    controller.settle_paired(&id, &run.plan_sha256, false);
    let summary = paired::summary(&report);
    controller.finish(
        &id,
        Phase::Completed,
        Some(ResultView {
            outcome: ResultOutcome::Incomplete,
            run_id: run.run_id.clone(),
            workspace: run.workspace.to_string_lossy().into_owned(),
            evidence_root: run.evidence_root.to_string_lossy().into_owned(),
            summary: summary.clone(),
            can_export_document: false,
            report_markdown: summary,
        }),
        None,
    );
    let completed = controller.snapshot();
    let store = crate::results::ResultsStore::default();
    let results = store
        .load(&source.join("paired-assessment-selection.json"))
        .unwrap();
    store
        .export(&results.token, &root.join("verified-summary.json"), "json")
        .unwrap();
    store
        .export(
            &results.token,
            &root.join("verified-summary.md"),
            "markdown",
        )
        .unwrap();
    let replay = json!({"schemaVersion":"aiw.dev/paired-workflow-ui-replay/v0alpha1","scope":"SYNTHETIC UI REPLAY: actual Controller snapshots from an explicitly retained synthetic admin/kernel fixture. Browser clicks replay states only; there is no provider backend, new durable approval, assessment execution or native acceptance.","realProviderApplicationControlCalls":0,"states":{"idle":idle,"preparing":preparing,"review":review,"approved":approved,"running":running,"completed":completed},"results":results});
    write(&root.join("workflow-demo.json"), &replay);
    assert_eq!(
        read(&source.join("ui-review-source.json"), 1024 * 1024),
        bytes
    );
    assert_eq!(
        serde_json::to_value(paired::report(&run).unwrap()).unwrap(),
        serde_json::to_value(report).unwrap()
    );
    println!("PAIRED_UI_REPLAY={}", root.display());
}
