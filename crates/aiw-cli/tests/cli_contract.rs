#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use aiw_evidence::canonical_json_bytes;
use aiw_orchestrator::{
    ApprovalRecord, PlannedAction, RunLayout, RunLifecycleKind, RunOutcome, RunPlan, RunResult,
    WSB_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION, WsbPlanningImportReceipt, WsbPlanningImportStatus,
    project_revision_hash,
};
use aiw_schema::Project;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "aiw-cli-integration-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn aiw() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aiw"))
}

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(path)
}

fn parse_one_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("expected exactly one JSON document")
}

fn canonical_hash<T: Serialize>(value: &T) -> String {
    let value = serde_json::to_value(value).unwrap();
    hex::encode(Sha256::digest(canonical_json_bytes(&value).unwrap()))
}

fn write_plan(path: &Path, project_path: &Path, hash: Option<String>) {
    let project: Project = serde_yaml::from_slice(&fs::read(project_path).unwrap()).unwrap();
    let revision_hash = hash.unwrap_or_else(|| project_revision_hash(&project).unwrap());
    let plan = RunPlan::new(
        "run-one",
        project.metadata.name,
        revision_hash,
        RunLifecycleKind::Assessment,
        "2026-08-27T00:00:00Z",
        vec![PlannedAction::AssessHost],
        Vec::new(),
    )
    .unwrap();
    fs::write(path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
}

fn write_wsb_plan(path: &Path, project_path: &Path) -> RunPlan {
    let project: Project = serde_yaml::from_slice(&fs::read(project_path).unwrap()).unwrap();
    let revision_hash = project_revision_hash(&project).unwrap();
    let owner = "S-1-5-21-1".to_owned();
    let identity = |path: &str, marker: u8| aiw_probe::WindowsFileIdentity {
        final_path: path.to_owned(),
        volume_serial_number: "1".repeat(16),
        file_id: format!("{marker:032x}"),
    };
    let workspace = aiw_probe::WorkspaceBindingEvidence {
        schema_version: aiw_probe::WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
        policy: aiw_probe::WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
        security_policy_sha256: aiw_probe::workspace_policy_hash(&owner),
        owner_sid: owner.clone(),
        dacl_protected: true,
        allowed_sids: vec![aiw_probe::WINDOWS_SYSTEM_SID.to_owned(), owner],
        parent: identity(r"C:\AIW", 1),
        root: identity(r"C:\AIW\run-one", 2),
        tools: identity(r"C:\AIW\run-one\tools", 3),
        output: identity(r"C:\AIW\run-one\output", 4),
    };
    let workspace_identity_sha256 = canonical_hash(&workspace);
    let plan = RunPlan::new(
        "run-one",
        project.metadata.name,
        revision_hash,
        RunLifecycleKind::Assessment,
        "2026-08-27T00:00:00Z",
        vec![
            PlannedAction::AssessHost,
            PlannedAction::PrepareWorkspace,
            PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                sandbox_plan_sha256: "b".repeat(64),
                provider_sha256: "a".repeat(64),
                guest_agent_sha256: "c".repeat(64),
                workspace: Box::new(workspace),
                workspace_identity_sha256,
            },
            PlannedAction::CollectEvidence,
        ],
        vec!["starts an approved Windows Sandbox golden probe".to_owned()],
    )
    .unwrap();
    fs::write(path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
    plan
}

fn write_clean_wsb_transaction(run_dir: &Path, plan: &RunPlan) {
    let directory = run_dir.join("wsb-session-transaction");
    fs::create_dir(&directory).unwrap();
    let plan_hash = plan.hash().unwrap();
    let workspace_identity_sha256 = plan
        .actions
        .iter()
        .find_map(|action| match action {
            PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                workspace_identity_sha256,
                ..
            } => Some(workspace_identity_sha256.clone()),
            _ => None,
        })
        .unwrap();
    let zero_hash = "0".repeat(64);
    let mut previous_hash = zero_hash;
    let mut transitions = Vec::new();
    for (index, (state, reason_code)) in [
        ("startIntent", "approved-start"),
        ("active", "start-confirmed"),
        ("cleanupIntent", "cleanup-attempt"),
        ("cleanupVerified", "cleanup-verified"),
    ]
    .into_iter()
    .enumerate()
    {
        let sequence = index + 1;
        let hash_input = serde_json::json!({
            "schemaVersion": "aiw.dev/wsb-session-transaction/v0alpha2",
            "runId": "run-one",
            "planHash": plan_hash,
            "projectRevisionHash": plan.project_revision_hash,
            "providerSha256": "a".repeat(64),
            "configSha256": "d".repeat(64),
            "sessionId": "11111111-1111-1111-1111-111111111111",
            "requestSha256": "e".repeat(64),
            "workspaceIdentitySha256": workspace_identity_sha256,
            "sequence": sequence,
            "state": state,
            "reasonCode": reason_code,
            "previousHash": previous_hash,
        });
        let hash = hex::encode(Sha256::digest(canonical_json_bytes(&hash_input).unwrap()));
        transitions.push(serde_json::json!({
            "sequence": sequence,
            "state": state,
            "reasonCode": reason_code,
            "previousHash": previous_hash,
            "hash": hash,
        }));
        previous_hash = hash;
        let transaction = serde_json::json!({
            "schemaVersion": "aiw.dev/wsb-session-transaction/v0alpha2",
            "runId": "run-one",
            "planHash": plan_hash,
            "projectRevisionHash": plan.project_revision_hash,
            "providerSha256": "a".repeat(64),
            "configSha256": "d".repeat(64),
            "sessionId": "11111111-1111-1111-1111-111111111111",
            "requestSha256": "e".repeat(64),
            "workspaceIdentitySha256": workspace_identity_sha256,
            "transitions": transitions,
        });
        fs::write(
            directory.join(format!("{sequence:020}.json")),
            serde_json::to_vec_pretty(&transaction).unwrap(),
        )
        .unwrap();
    }
}

fn persist_test_wsb_import(root: &Path, plan: &RunPlan) -> RunLayout {
    let PlannedAction::ExecuteWindowsSandboxGoldenProbe {
        sandbox_plan_sha256,
        provider_sha256,
        guest_agent_sha256,
        workspace,
        workspace_identity_sha256,
    } = &plan.actions[2]
    else {
        unreachable!();
    };
    let receipt = WsbPlanningImportReceipt {
        schema_version: WSB_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION.to_owned(),
        run_id: plan.run_id.clone(),
        imported_at: "2026-08-29T00:01:00Z".to_owned(),
        status: WsbPlanningImportStatus::PendingApproval,
        project_revision_sha256: plan.project_revision_hash.clone(),
        workspace_root: workspace.root.final_path.clone(),
        workspace_identity_sha256: workspace_identity_sha256.clone(),
        preparation_receipt_sha256: "d".repeat(64),
        run_plan_sha256: plan.hash().unwrap(),
        windows_sandbox_plan_sha256: sandbox_plan_sha256.clone(),
        guest_agent_sha256: guest_agent_sha256.clone(),
        provider_sha256: provider_sha256.clone(),
        run_root: workspace.root.final_path.clone(),
        journal_sequence: 1,
        approval_present: false,
        provider_acquired: false,
        provider_mutated: false,
    };
    let layout = RunLayout::new(root, &plan.run_id).unwrap();
    layout
        .create_or_verify_pending_wsb_import(plan, &receipt)
        .unwrap();
    layout
}

#[test]
fn clap_failures_emit_one_json_envelope_and_no_stdout() {
    let output = Command::new(aiw())
        .args(["run", "status", "--root", "."])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let envelope = parse_one_json(&output.stderr);
    assert_eq!(envelope["code"], "AIW_CLI_ARGUMENT_INVALID");
    assert_eq!(envelope["stage"], "cliParse");
}

#[test]
fn application_inspection_is_json_only_and_type_bound() {
    let temp = TempDir::new();
    let source = temp.path().join("aiw-fixture.exe");
    fs::copy(aiw(), &source).unwrap();
    let inspected = Command::new(aiw())
        .args(["application", "inspect", "--source"])
        .arg(&source)
        .args(["--kind", "exe"])
        .output()
        .unwrap();
    assert!(inspected.status.success());
    assert!(inspected.stderr.is_empty());
    let value = parse_one_json(&inspected.stdout);
    assert_eq!(
        value["schemaVersion"],
        "aiw.dev/application-inspection/v0alpha1"
    );
    assert_eq!(value["kind"], "exe");
    assert_eq!(value["architecture"], "x64");
    assert_eq!(value["signatureStatus"], "unknown");
    assert_eq!(
        value["fileAuthority"]["schemaVersion"],
        "aiw.dev/application-file-authority/v0alpha1"
    );
    assert_eq!(value["fileAuthority"]["linkCount"], 1);
    assert_eq!(value["fileAuthority"]["sha256"], value["sha256"]);
    assert_eq!(value["fileAuthority"]["sizeBytes"], value["sizeBytes"]);
    assert_eq!(value["fileAuthority"]["onlyUnnamedDataStream"], true);

    let portable = temp.path().join("portable");
    fs::create_dir(&portable).unwrap();
    fs::write(portable.join("app.txt"), b"portable").unwrap();
    let inspected_portable = Command::new(aiw())
        .args(["application", "inspect", "--source"])
        .arg(&portable)
        .args(["--kind", "portable-directory"])
        .output()
        .unwrap();
    assert!(inspected_portable.status.success());
    assert!(inspected_portable.stderr.is_empty());
    let portable_value = parse_one_json(&inspected_portable.stdout);
    assert_eq!(portable_value["kind"], "portableDirectory");
    assert_eq!(
        portable_value["portableDirectoryAuthority"]["schemaVersion"],
        "aiw.dev/portable-directory-authority/v0alpha1"
    );
    assert_eq!(
        portable_value["portableDirectoryAuthority"]["manifestSha256"],
        portable_value["portableManifest"]["manifestSha256"]
    );
    assert_eq!(
        portable_value["portableDirectoryAuthority"]["entries"][0]["relativePath"],
        "app.txt"
    );

    let rejected = Command::new(aiw())
        .args(["application", "inspect", "--source"])
        .arg(&source)
        .args(["--kind", "msi"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let error = parse_one_json(&rejected.stderr);
    assert_eq!(error["code"], "AIW_APPLICATION_INSPECTION_REJECTED");
    assert_eq!(error["stage"], "applicationInspection");

    #[cfg(windows)]
    {
        fs::write(format!("{}:extra", source.display()), b"untrusted").unwrap();
        let streamed = Command::new(aiw())
            .args(["application", "inspect", "--source"])
            .arg(&source)
            .args(["--kind", "exe"])
            .output()
            .unwrap();
        assert!(!streamed.status.success());
        assert!(streamed.stdout.is_empty());
        let error = parse_one_json(&streamed.stderr);
        assert_eq!(error["code"], "AIW_APPLICATION_AUTHORITY_REJECTED");
    }
}

#[cfg(windows)]
#[test]
fn protected_file_import_is_receipt_last_create_new_and_read_only_verifiable() {
    let temp = TempDir::new();
    let source = temp.path().join("fixture.exe");
    fs::copy(aiw(), &source).unwrap();
    let intake_parent = temp.path().join("intakes");
    fs::create_dir(&intake_parent).unwrap();
    let imported = Command::new(aiw())
        .args(["application", "import", "--source"])
        .arg(&source)
        .args(["--kind", "exe", "--intake-parent"])
        .arg(&intake_parent)
        .args(["--intake-id", "cli-intake-001"])
        .output()
        .unwrap();
    assert!(imported.status.success());
    assert!(imported.stderr.is_empty());
    let receipt = parse_one_json(&imported.stdout);
    assert_eq!(
        receipt["schemaVersion"],
        "aiw.dev/application-file-import-receipt/v0alpha1"
    );
    assert_eq!(receipt["sourceKind"], "exe");
    assert_eq!(receipt["payloadRelativePath"], "source/payload.exe");
    let receipt_path = temp.path().join("receipt.json");
    fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();

    let verified = Command::new(aiw())
        .args(["application", "verify-import", "--receipt"])
        .arg(&receipt_path)
        .output()
        .unwrap();
    assert!(verified.status.success());
    assert!(verified.stderr.is_empty());
    let verification = parse_one_json(&verified.stdout);
    assert_eq!(verification["verified"], true);
    assert_eq!(
        verification["schemaVersion"],
        "aiw.dev/application-file-import-verification/v0alpha1"
    );

    let collision = Command::new(aiw())
        .args(["application", "import", "--source"])
        .arg(&source)
        .args(["--kind", "exe", "--intake-parent"])
        .arg(&intake_parent)
        .args(["--intake-id", "cli-intake-001"])
        .output()
        .unwrap();
    assert!(!collision.status.success());
    assert!(collision.stdout.is_empty());
    let collision_error = parse_one_json(&collision.stderr);
    assert_eq!(collision_error["code"], "AIW_APPLICATION_IMPORT_REJECTED");
    assert_eq!(collision_error["retryable"], false);

    let payload = receipt["payload"]["finalPath"].as_str().unwrap();
    fs::write(payload, b"tampered").unwrap();
    let rejected = Command::new(aiw())
        .args(["application", "verify-import", "--receipt"])
        .arg(&receipt_path)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let rejected_error = parse_one_json(&rejected.stderr);
    assert_eq!(
        rejected_error["code"],
        "AIW_APPLICATION_IMPORT_VERIFICATION_REJECTED"
    );
    assert_eq!(rejected_error["stage"], "applicationImportVerification");
}

#[test]
fn protected_portable_import_is_json_only_and_read_only_verifiable() {
    let temp = TempDir::new();
    let source = temp.path().join("portable");
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("bin")).unwrap();
    fs::create_dir(source.join("empty")).unwrap();
    fs::write(source.join("bin").join("app.exe"), b"portable-app").unwrap();
    fs::write(source.join("readme.txt"), b"readme").unwrap();
    let intake_parent = temp.path().join("intakes");
    fs::create_dir(&intake_parent).unwrap();

    let imported = Command::new(aiw())
        .args(["application", "import-portable", "--source"])
        .arg(&source)
        .arg("--intake-parent")
        .arg(&intake_parent)
        .args(["--intake-id", "portable-001"])
        .output()
        .unwrap();
    assert!(imported.status.success());
    assert!(imported.stderr.is_empty());
    let receipt = parse_one_json(&imported.stdout);
    assert_eq!(
        receipt["schemaVersion"],
        "aiw.dev/portable-directory-import-receipt/v0alpha1"
    );
    assert_eq!(receipt["sourceKind"], "portableDirectory");
    assert_eq!(receipt["entryCount"], 4);
    let receipt_path = temp.path().join("portable-receipt.json");
    fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();

    let verified = Command::new(aiw())
        .args(["application", "verify-portable-import", "--receipt"])
        .arg(&receipt_path)
        .output()
        .unwrap();
    assert!(verified.status.success());
    assert!(verified.stderr.is_empty());
    assert_eq!(parse_one_json(&verified.stdout)["verified"], true);

    let payload = receipt["payloadDirectory"]["finalPath"].as_str().unwrap();
    fs::write(Path::new(payload).join("readme.txt"), b"tampered").unwrap();
    let rejected = Command::new(aiw())
        .args(["application", "verify-portable-import", "--receipt"])
        .arg(&receipt_path)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let error = parse_one_json(&rejected.stderr);
    assert_eq!(error["code"], "AIW_PORTABLE_IMPORT_VERIFICATION_REJECTED");
    assert_eq!(error["stage"], "portableImportVerification");
}

#[test]
fn legacy_validation_reports_pending_review_as_one_success_result() {
    let project = repo_path("examples/minimal-v0alpha1.aiw.yaml");
    let output = Command::new(aiw())
        .args(["project", "validate", "--path"])
        .arg(project)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let result = parse_one_json(&output.stdout);
    assert_eq!(result["valid"], false);
    assert_eq!(result["sourceSchemaVersion"], "aiw.dev/v0alpha1");
    assert_eq!(result["effectiveSchemaVersion"], "aiw.dev/v0alpha2");
    assert_eq!(result["migrationReview"], "pending");
    assert!(
        result["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"] == "migrationReviewPending")
    );
}

#[test]
fn migration_is_non_destructive_create_new_and_returns_bounded_receipt() {
    let temp = TempDir::new();
    let source = repo_path("examples/minimal-v0alpha1.aiw.yaml");
    let original_source = fs::read(&source).unwrap();
    let destination = temp.path().join("migrated.aiw.yaml");

    let first = Command::new(aiw())
        .args(["project", "migrate", "--path"])
        .arg(&source)
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(first.status.success());
    assert!(first.stderr.is_empty());
    let receipt = parse_one_json(&first.stdout);
    assert_eq!(receipt["migrationReview"], "pending");
    assert_eq!(receipt["planningValid"], false);
    assert!(receipt.get("project").is_none());
    let migrated = fs::read(&destination).unwrap();
    assert_ne!(migrated, original_source);
    assert_eq!(fs::read(&source).unwrap(), original_source);

    let second = Command::new(aiw())
        .args(["project", "migrate", "--path"])
        .arg(&source)
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(second.stdout.is_empty());
    assert_eq!(parse_one_json(&second.stderr)["code"], "AIW_CLI_FAILED");
    assert_eq!(fs::read(&destination).unwrap(), migrated);
}

#[test]
fn run_plan_rejects_pending_migration_and_project_hash_drift_before_persisting() {
    let temp = TempDir::new();
    let root = temp.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let plan = temp.path().join("plan.json");
    let current = temp.path().join("project.yaml");
    fs::copy(repo_path("examples/minimal.aiw.yaml"), &current).unwrap();
    write_plan(&plan, &current, None);
    let changed = fs::read_to_string(&current).unwrap().replace(
        "Contoso Editor isolation assessment",
        "Changed project revision",
    );
    fs::write(&current, changed).unwrap();

    let mismatch = Command::new(aiw())
        .args(["run", "plan", "--root"])
        .arg(&root)
        .arg("--plan")
        .arg(&plan)
        .arg("--project")
        .arg(&current)
        .output()
        .unwrap();
    assert!(!mismatch.status.success());
    assert!(!root.join("runs").exists());

    let legacy = repo_path("examples/minimal-v0alpha1.aiw.yaml");
    let pending = Command::new(aiw())
        .args(["run", "plan", "--root"])
        .arg(&root)
        .arg("--plan")
        .arg(&plan)
        .arg("--project")
        .arg(&legacy)
        .output()
        .unwrap();
    assert!(!pending.status.success());
    assert!(!root.join("runs").exists());
}

#[test]
fn legacy_unbound_run_plan_fails_with_stable_schema_error() {
    let temp = TempDir::new();
    let root = temp.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let plan = temp.path().join("legacy-plan.json");
    fs::write(
        &plan,
        br#"{"schema":"aiw.dev/run-plan/v0alpha1","runId":"run-one","projectId":"contoso-editor","lifecycle":"assessment","createdAt":"now","actions":[{"kind":"assessHost"}],"trustDeltas":[]}"#,
    )
    .unwrap();
    let output = Command::new(aiw())
        .args(["run", "plan", "--root"])
        .arg(&root)
        .arg("--plan")
        .arg(&plan)
        .arg("--project")
        .arg(repo_path("examples/minimal.aiw.yaml"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        parse_one_json(&output.stderr)["code"],
        "AIW_PLAN_SCHEMA_UNSUPPORTED"
    );
    assert!(!root.join("runs").exists());
}

#[test]
fn generic_run_plan_rejects_wsb_before_creating_storage() {
    let temp = TempDir::new();
    let root = temp.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let project = repo_path("examples/minimal.aiw.yaml");
    let plan_path = temp.path().join("wsb-plan.json");
    write_wsb_plan(&plan_path, &project);
    let output = Command::new(aiw())
        .args(["run", "plan", "--root"])
        .arg(&root)
        .arg("--plan")
        .arg(&plan_path)
        .arg("--project")
        .arg(&project)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = parse_one_json(&output.stderr);
    assert_eq!(error["code"], "AIW_WSB_IMPORT_REQUIRED");
    assert_eq!(error["runId"], "run-one");
    assert!(!root.join("runs").exists());
}

#[test]
fn run_status_is_read_only_for_missing_and_existing_runs() {
    let temp = TempDir::new();
    let root = temp.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let missing = Command::new(aiw())
        .args(["run", "status", "--root"])
        .arg(&root)
        .args(["--run-id", "missing"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(!root.join("runs").exists());

    let project = repo_path("examples/minimal.aiw.yaml");
    let plan = temp.path().join("plan.json");
    write_plan(&plan, &project, None);
    let created = Command::new(aiw())
        .args(["run", "plan", "--root"])
        .arg(&root)
        .arg("--plan")
        .arg(&plan)
        .arg("--project")
        .arg(&project)
        .output()
        .unwrap();
    assert!(created.status.success());
    let journal = root.join("runs/run-one/events.jsonl");
    let before = fs::read(&journal).unwrap();
    let status = Command::new(aiw())
        .args(["run", "status", "--root"])
        .arg(&root)
        .args(["--run-id", "run-one"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let status_json = parse_one_json(&status.stdout);
    assert_eq!(status_json["schemaVersion"], "aiw.dev/run-status/v0alpha1");
    assert_eq!(status_json["runId"], "run-one");
    assert_eq!(status_json["core"]["status"], "pendingApproval");
    assert_eq!(status_json["windowsSandbox"]["status"], "none");
    assert_eq!(fs::read(journal).unwrap(), before);
}

#[test]
fn corrupt_wsb_transaction_errors_preserve_run_identity() {
    let temp = TempDir::new();
    let root = temp.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let project = repo_path("examples/minimal.aiw.yaml");
    let plan = temp.path().join("plan.json");
    write_plan(&plan, &project, None);
    let created = Command::new(aiw())
        .args(["run", "plan", "--root"])
        .arg(&root)
        .arg("--plan")
        .arg(&plan)
        .arg("--project")
        .arg(&project)
        .output()
        .unwrap();
    assert!(created.status.success());
    let transaction_dir = root.join("runs/run-one/wsb-session-transaction");
    fs::create_dir(&transaction_dir).unwrap();
    fs::write(transaction_dir.join("00000000000000000001.json"), b"{}").unwrap();

    for command in ["status", "recover"] {
        let output = Command::new(aiw())
            .args(["run", command, "--root"])
            .arg(&root)
            .args(["--run-id", "run-one"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = parse_one_json(&output.stderr);
        assert_eq!(error["code"], "AIW_WSB_SESSION_STATUS_INVALID");
        assert_eq!(error["stage"], "wsbSessionStatus");
        assert_eq!(error["runId"], "run-one");
        assert_eq!(error["retryable"], false);
        assert!(error["detail"].as_str().unwrap().chars().count() <= 512);
    }
}

#[test]
fn clean_wsb_transaction_without_terminal_result_fails_closed() {
    let temp = TempDir::new();
    let root = temp.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let project = repo_path("examples/minimal.aiw.yaml");
    let plan_path = temp.path().join("wsb-plan.json");
    let plan = write_wsb_plan(&plan_path, &project);
    let layout = persist_test_wsb_import(&root, &plan);
    layout
        .write_approval(&ApprovalRecord::for_plan(&plan, "admin", "now").unwrap())
        .unwrap();
    write_clean_wsb_transaction(&layout.run_dir(), &plan);
    let journal = layout.journal_path();
    let before = fs::read(&journal).unwrap();

    let status = Command::new(aiw())
        .args(["run", "status", "--root"])
        .arg(&root)
        .args(["--run-id", "run-one"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let status_json = parse_one_json(&status.stdout);
    assert_eq!(status_json["core"]["status"], "ready");
    assert_eq!(status_json["windowsSandbox"]["status"], "clean");
    assert_eq!(fs::read(&journal).unwrap(), before);

    let recovery = Command::new(aiw())
        .args(["run", "recover", "--root"])
        .arg(&root)
        .args(["--run-id", "run-one"])
        .output()
        .unwrap();
    assert!(!recovery.status.success());
    assert!(recovery.stdout.is_empty());
    let error = parse_one_json(&recovery.stderr);
    assert_eq!(error["code"], "AIW_WSB_RECOVERY_FAILED");
    assert_eq!(error["stage"], "wsbRecovery");
    assert_eq!(error["runId"], "run-one");
    assert_eq!(fs::read(journal).unwrap(), before);

    layout
        .write_result(
            &RunResult::new(
                "run-one",
                RunOutcome::InsufficientEvidence,
                "now",
                None,
                true,
                "provider cleanup was previously verified",
            )
            .unwrap(),
        )
        .unwrap();
    let terminal = Command::new(aiw())
        .args(["run", "recover", "--root"])
        .arg(&root)
        .args(["--run-id", "run-one"])
        .output()
        .unwrap();
    assert!(!terminal.status.success());
    let terminal_error = parse_one_json(&terminal.stderr);
    assert_eq!(terminal_error["code"], "AIW_WSB_RECOVERY_FAILED");
    assert_eq!(terminal_error["runId"], "run-one");
}

#[test]
fn recover_repairs_interrupted_core_journal_before_provider_reconciliation() {
    let temp = TempDir::new();
    let root = temp.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let project = repo_path("examples/minimal.aiw.yaml");
    let plan_path = temp.path().join("wsb-plan.json");
    let plan = write_wsb_plan(&plan_path, &project);
    let layout = persist_test_wsb_import(&root, &plan);
    layout
        .write_approval(&ApprovalRecord::for_plan(&plan, "admin", "now").unwrap())
        .unwrap();
    write_clean_wsb_transaction(&layout.run_dir(), &plan);
    let mut journal = OpenOptions::new()
        .append(true)
        .open(layout.journal_path())
        .unwrap();
    journal.write_all(b"interrupted-tail").unwrap();
    journal.sync_all().unwrap();
    drop(journal);

    let recovery = Command::new(aiw())
        .args(["run", "recover", "--root"])
        .arg(&root)
        .args(["--run-id", "run-one"])
        .output()
        .unwrap();
    assert!(!recovery.status.success());
    let error = parse_one_json(&recovery.stderr);
    assert_eq!(error["code"], "AIW_WSB_RECOVERY_FAILED");
    assert_eq!(error["stage"], "wsbRecovery");
    assert_eq!(error["runId"], "run-one");
    assert!(
        layout.status().is_ok(),
        "core recovery did not repair the tail"
    );
}

#[test]
fn rejected_start_and_provider_recovery_preserve_run_identity() {
    let temp = TempDir::new();
    let root = temp.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let project = repo_path("examples/minimal.aiw.yaml");
    let start = Command::new(aiw())
        .args(["run", "start", "--root"])
        .arg(&root)
        .args(["--run-id", "exact-run-id", "--project"])
        .arg(&project)
        .args([
            "--guest-agent-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .output()
        .unwrap();
    assert!(!start.status.success());
    let start_error = parse_one_json(&start.stderr);
    assert_eq!(start_error["code"], "AIW_WSB_START_REJECTED");
    assert_eq!(start_error["runId"], "exact-run-id");

    let plan = temp.path().join("plan.json");
    write_plan(&plan, &project, None);
    let created = Command::new(aiw())
        .args(["run", "plan", "--root"])
        .arg(&root)
        .arg("--plan")
        .arg(&plan)
        .arg("--project")
        .arg(&project)
        .output()
        .unwrap();
    assert!(created.status.success());
    let run_dir = root.join("runs/run-one");
    let transaction_dir = run_dir.join("wsb-session-transaction");
    fs::create_dir(&transaction_dir).unwrap();
    let journal = run_dir.join("events.jsonl");
    let before = fs::read(&journal).unwrap();
    let recovery = Command::new(aiw())
        .args(["run", "recover", "--root"])
        .arg(&root)
        .args(["--run-id", "run-one"])
        .output()
        .unwrap();
    assert!(!recovery.status.success());
    let recovery_error = parse_one_json(&recovery.stderr);
    assert_eq!(recovery_error["code"], "AIW_WSB_RECOVERY_FAILED");
    assert_eq!(recovery_error["stage"], "wsbRecovery");
    assert_eq!(recovery_error["runId"], "run-one");
    assert_eq!(fs::read(journal).unwrap(), before);
    assert!(transaction_dir.is_dir());
}

#[test]
fn duplicate_project_keys_are_rejected_before_version_dispatch() {
    let temp = TempDir::new();
    let project = temp.path().join("duplicate.json");
    fs::write(
        &project,
        br#"{"schemaVersion":"aiw.dev/v0alpha1","schemaVersion":"aiw.dev/v0alpha2"}"#,
    )
    .unwrap();

    let output = Command::new(aiw())
        .args(["project", "validate", "--path"])
        .arg(project)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(parse_one_json(&output.stderr)["code"], "AIW_CLI_FAILED");
}

#[test]
fn versioned_project_and_orchestrator_schemas_are_public() {
    for (kind, expected_title) in [
        ("project-v0alpha1", "LegacyProjectV0Alpha1"),
        ("project-v0alpha2", "Project"),
        ("run-plan", "RunPlan"),
        ("run-plan-v0alpha1", "LegacyRunPlanV0Alpha1"),
        ("run-plan-v0alpha2", "LegacyRunPlanV0Alpha2"),
        ("run-plan-v0alpha3", "RunPlan"),
        ("approval-record", "ApprovalRecord"),
        ("run-event", "RunEvent"),
        ("run-result", "RunResult"),
        ("cancellation-request", "CancellationRequest"),
        ("recovery-status", "RecoveryStatus"),
        ("run-status", "RunStatusEnvelope"),
        ("wsb-session-transaction", "SessionTransaction"),
        ("wsb-session-status", "WsbSessionStatus"),
        ("wsb-preparation-receipt", "WsbPreparationReceipt"),
        ("wsb-preparation-result", "WsbPreparationResult"),
        ("wsb-planning-import-receipt", "WsbPlanningImportReceipt"),
        ("wsb-planning-import-result", "WsbPlanningImportResult"),
        ("wsb-revocation-record", "WsbRevocationRecord"),
        ("error-envelope", "AiwError"),
    ] {
        let output = Command::new(aiw()).args(["schema", kind]).output().unwrap();
        assert!(
            output.status.success(),
            "schema command failed for {kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(parse_one_json(&output.stdout)["title"], expected_title);
    }
}

#[cfg(windows)]
#[test]
fn preparation_rejects_pending_migration_before_creating_workspace() {
    let temp = TempDir::new();
    let run_id = "invalid-preparation";
    let workspace = temp.path().join(run_id);
    let output = Command::new(aiw())
        .args(["run", "prepare-wsb", "--run-id", run_id, "--project"])
        .arg(repo_path("examples/minimal-v0alpha1.aiw.yaml"))
        .args(["--guest-agent", "C:\\missing-agent.exe"])
        .args(["--guest-agent-sha256", &"0".repeat(64)])
        .arg("--workspace-parent")
        .arg(temp.path())
        .args(["--created-at", "2026-08-29T00:00:00Z"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = parse_one_json(&output.stderr);
    assert_eq!(error["code"], "AIW_WSB_PREPARATION_PROJECT_INVALID");
    assert_eq!(error["stage"], "wsbPreparationPreflight");
    assert_eq!(error["runId"], run_id);
    assert!(!workspace.exists());
}

#[cfg(windows)]
#[test]
fn powershell_preserves_structured_stderr_envelope() {
    let temp = TempDir::new();
    let script =
        repo_path("powershell/AppIsolationWorkbench/AppIsolationWorkbench.Integration.Tests.ps1");
    let module = repo_path("powershell/AppIsolationWorkbench/AppIsolationWorkbench.psd1");
    let output = Command::new("pwsh")
        .args(["-NoLogo", "-NoProfile", "-File"])
        .arg(script)
        .arg("-ModulePath")
        .arg(module)
        .arg("-CliPath")
        .arg(aiw())
        .arg("-RootPath")
        .arg(temp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "PowerShell integration failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
