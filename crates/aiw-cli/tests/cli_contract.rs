#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use aiw_orchestrator::{PlannedAction, RunLifecycleKind, RunPlan, project_revision_hash};
use aiw_schema::Project;
use serde_json::Value;

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
    assert_eq!(parse_one_json(&status.stdout)["status"], "pendingApproval");
    assert_eq!(fs::read(journal).unwrap(), before);
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
        ("run-plan-v0alpha2", "RunPlan"),
        ("approval-record", "ApprovalRecord"),
        ("run-event", "RunEvent"),
        ("run-result", "RunResult"),
        ("cancellation-request", "CancellationRequest"),
        ("recovery-status", "RecoveryStatus"),
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
