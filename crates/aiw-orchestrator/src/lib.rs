//! File-backed, non-executing orchestration primitives.
//!
//! This crate persists intent and receipts only. It cannot execute, elevate,
//! or start providers. Hashes provide local integrity and correlation, not
//! administrator-proof attestation. Callers must supply an ACL-restricted root.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use aiw_evidence::canonical_json_bytes;
use fs4::FileExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RUN_PLAN_SCHEMA: &str = "aiw.dev/run-plan/v0alpha1";
const APPROVAL_SCHEMA: &str = "aiw.dev/approval-record/v0alpha1";
const EVENT_SCHEMA: &str = "aiw.dev/run-event/v0alpha1";
const JOURNAL_SCHEMA: &str = "aiw.dev/run-journal/v0alpha1";
const HEAD_SCHEMA: &str = "aiw.dev/run-journal-head/v0alpha1";
const RESULT_SCHEMA: &str = "aiw.dev/run-result/v0alpha1";
const CANCELLATION_SCHEMA: &str = "aiw.dev/cancellation-request/v0alpha1";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_TEXT: usize = 4096;
const MAX_ARTIFACT: u64 = 1024 * 1024;
const MAX_JOURNAL: u64 = 64 * 1024 * 1024;
const MAX_LINE: usize = 16 * 1024;
const MAX_ITEMS: usize = 256;
const MAX_RECORDS: usize = 100_000;
static NEXT_STAGE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RunLifecycleKind {
    Assessment,
    Launch,
    Authoring,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PlannedAction {
    AssessHost,
    PrepareWorkspace,
    ExecuteScenario { scenario_id: String },
    CollectEvidence,
    LaunchValidatedProfile { profile_id: String },
    AuthorPackage,
    InspectPackage,
    SignPackage,
    ValidatePackage,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunPlan {
    pub schema: String,
    pub run_id: String,
    pub project_id: String,
    pub lifecycle: RunLifecycleKind,
    pub created_at: String,
    pub actions: Vec<PlannedAction>,
    #[serde(default)]
    pub trust_deltas: Vec<String>,
}

impl RunPlan {
    pub fn new(
        run_id: impl Into<String>,
        project_id: impl Into<String>,
        lifecycle: RunLifecycleKind,
        created_at: impl Into<String>,
        actions: Vec<PlannedAction>,
        trust_deltas: Vec<String>,
    ) -> Result<Self, AiwError> {
        let value = Self {
            schema: RUN_PLAN_SCHEMA.into(),
            run_id: run_id.into(),
            project_id: project_id.into(),
            lifecycle,
            created_at: created_at.into(),
            actions,
            trust_deltas,
        };
        validate_plan(&value)?;
        Ok(value)
    }

    pub fn hash(&self) -> Result<String, AiwError> {
        validate_plan(self)?;
        hash_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalRecord {
    pub schema: String,
    pub run_id: String,
    pub plan_hash: String,
    pub trust_deltas: Vec<String>,
    pub approved_by: String,
    pub approved_at: String,
}

impl ApprovalRecord {
    pub fn for_plan(
        plan: &RunPlan,
        approved_by: impl Into<String>,
        approved_at: impl Into<String>,
    ) -> Result<Self, AiwError> {
        let value = Self {
            schema: APPROVAL_SCHEMA.into(),
            run_id: plan.run_id.clone(),
            plan_hash: plan.hash()?,
            trust_deltas: plan.trust_deltas.clone(),
            approved_by: approved_by.into(),
            approved_at: approved_at.into(),
        };
        validate_approval(&value, plan)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RunEventKind {
    Created,
    ApprovalIntent,
    ApprovalRecorded,
    Progress,
    CancellationIntent,
    CancellationRequested,
    TerminalIntent,
    TerminalRecorded,
    MutationAborted,
    RecoveryObserved,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunEvent {
    pub schema: String,
    pub kind: RunEventKind,
    pub occurred_at: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_hash: Option<String>,
}

impl RunEvent {
    pub fn new(
        kind: RunEventKind,
        occurred_at: impl Into<String>,
        detail: impl Into<String>,
    ) -> Result<Self, AiwError> {
        let value = Self {
            schema: EVENT_SCHEMA.into(),
            kind,
            occurred_at: occurred_at.into(),
            detail: detail.into(),
            artifact_hash: None,
        };
        validate_event(&value)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JournalRecord {
    pub schema: String,
    pub run_id: String,
    pub plan_hash: String,
    pub sequence: u64,
    pub previous_hash: String,
    pub event: RunEvent,
    pub hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalHead {
    schema: String,
    run_id: String,
    plan_hash: String,
    sequence: u64,
    hash: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RunOutcome {
    Succeeded,
    Failed,
    Cancelled,
    InsufficientEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunResult {
    pub schema: String,
    pub run_id: String,
    pub outcome: RunOutcome,
    pub completed_at: String,
    pub evidence_root: Option<String>,
    pub cleanup_complete: bool,
    pub summary: String,
}

impl RunResult {
    pub fn new(
        run_id: impl Into<String>,
        outcome: RunOutcome,
        completed_at: impl Into<String>,
        evidence_root: Option<String>,
        cleanup_complete: bool,
        summary: impl Into<String>,
    ) -> Result<Self, AiwError> {
        let value = Self {
            schema: RESULT_SCHEMA.into(),
            run_id: run_id.into(),
            outcome,
            completed_at: completed_at.into(),
            evidence_root,
            cleanup_complete,
            summary: summary.into(),
        };
        validate_result(&value)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancellationRequest {
    pub schema: String,
    pub run_id: String,
    pub requested_at: String,
    pub requested_by: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiwError {
    pub code: Box<str>,
    pub summary: Box<str>,
    pub stage: Box<str>,
    pub run_id: Option<Box<str>>,
    pub retryable: bool,
    pub remediation: Box<str>,
    pub detail: Box<str>,
}

impl AiwError {
    fn new(
        code: &str,
        summary: &str,
        stage: &str,
        run_id: Option<&str>,
        retryable: bool,
        remediation: &str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            summary: summary.into(),
            stage: stage.into(),
            run_id: run_id.map(Into::into),
            retryable,
            remediation: remediation.into(),
            detail: limit_detail(detail.into()).into(),
        }
    }
}

impl fmt::Display for AiwError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.summary)
    }
}
impl std::error::Error for AiwError {}

#[derive(Clone, Debug)]
pub struct RunLayout {
    root: PathBuf,
    run_id: String,
}

struct RunLock {
    _file: File,
}

impl RunLayout {
    pub fn new(root: impl AsRef<Path>, run_id: impl Into<String>) -> Result<Self, AiwError> {
        let run_id = run_id.into();
        validate_id("runId", &run_id)?;
        let supplied = root.as_ref();
        if !supplied.is_absolute() || is_remote_path(supplied) {
            return Err(path_error(
                "workspace root must be an absolute local path",
                &run_id,
                supplied,
            ));
        }
        ensure_no_reparse_components(supplied, &run_id)?;
        let root =
            fs::canonicalize(supplied).map_err(|error| storage_error("layout", &run_id, error))?;
        if is_remote_path(&root) {
            return Err(path_error(
                "workspace resolved to a remote path",
                &run_id,
                &root,
            ));
        }
        ensure_directory(&root, &run_id, "layout")?;
        Ok(Self { root, run_id })
    }

    pub fn run_dir(&self) -> PathBuf {
        self.root.join("runs").join(&self.run_id)
    }
    pub fn plan_path(&self) -> PathBuf {
        self.run_dir().join("plan.json")
    }
    pub fn approval_path(&self) -> PathBuf {
        self.run_dir().join("approval.json")
    }
    pub fn journal_path(&self) -> PathBuf {
        self.run_dir().join("events.jsonl")
    }
    pub fn cancellation_path(&self) -> PathBuf {
        self.run_dir().join("cancellation.json")
    }
    pub fn result_path(&self) -> PathBuf {
        self.run_dir().join("result.json")
    }
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    fn heads_dir(&self) -> PathBuf {
        self.run_dir().join("journal-heads")
    }
    fn lock_path(&self) -> PathBuf {
        self.root
            .join("runs")
            .join(".locks")
            .join(format!("{}.lock", self.run_id))
    }
    fn pending_path(&self, target: &Path) -> PathBuf {
        target.with_extension(format!(
            "{}.pending",
            target
                .extension()
                .and_then(|v| v.to_str())
                .unwrap_or("json")
        ))
    }

    fn acquire_lock(&self) -> Result<RunLock, AiwError> {
        self.revalidate_root()?;
        let runs = self.root.join("runs");
        fs::create_dir_all(&runs).map_err(|error| storage_error("lock", &self.run_id, error))?;
        ensure_directory(&runs, &self.run_id, "lock")?;
        let locks = runs.join(".locks");
        fs::create_dir_all(&locks).map_err(|error| storage_error("lock", &self.run_id, error))?;
        ensure_directory(&locks, &self.run_id, "lock")?;
        let path = self.lock_path();
        if path.exists() {
            ensure_file(&path, &self.run_id, "lock")?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| storage_error("lock", &self.run_id, error))?;
        ensure_file(&path, &self.run_id, "lock")?;
        FileExt::lock(&file).map_err(|error| storage_error("lock", &self.run_id, error))?;
        self.revalidate_root()?;
        Ok(RunLock { _file: file })
    }

    fn revalidate_root(&self) -> Result<(), AiwError> {
        ensure_no_reparse_components(&self.root, &self.run_id)?;
        let current = fs::canonicalize(&self.root)
            .map_err(|error| storage_error("path", &self.run_id, error))?;
        if current != self.root {
            return Err(path_error(
                "workspace root identity changed",
                &self.run_id,
                &current,
            ));
        }
        Ok(())
    }

    fn validate_run_dir(&self) -> Result<(), AiwError> {
        self.revalidate_root()?;
        let runs = self.root.join("runs");
        ensure_directory(&runs, &self.run_id, "path")?;
        ensure_directory(&self.run_dir(), &self.run_id, "path")?;
        let current = fs::canonicalize(self.run_dir())
            .map_err(|error| storage_error("path", &self.run_id, error))?;
        if current.parent() != Some(runs.as_path()) {
            return Err(path_error(
                "run directory escaped the workspace",
                &self.run_id,
                &current,
            ));
        }
        Ok(())
    }

    pub fn create(&self, plan: &RunPlan) -> Result<(), AiwError> {
        validate_plan(plan)?;
        if plan.run_id != self.run_id {
            return Err(run_error(
                "AIW_RUN_ID_MISMATCH",
                "plan does not belong to this run",
                "create",
                &self.run_id,
            ));
        }
        let _lock = self.acquire_lock()?;
        if self.run_dir().exists() {
            return Err(run_error(
                "AIW_RUN_ALREADY_EXISTS",
                "run directory already exists",
                "create",
                &self.run_id,
            ));
        }
        let stage = self.root.join("runs").join(format!(
            ".create-{}-{}-{}",
            self.run_id,
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&stage).map_err(|error| storage_error("create", &self.run_id, error))?;
        fs::create_dir(stage.join("journal-heads"))
            .map_err(|error| storage_error("create", &self.run_id, error))?;
        write_complete_new(&stage.join("plan.json"), plan, &self.run_id, "create")?;
        write_empty_new(&stage.join("events.jsonl"), &self.run_id, "create")?;
        let plan_hash = plan.hash()?;
        let event = artifact_event(
            RunEventKind::Created,
            &plan.created_at,
            "run plan persisted",
            &plan_hash,
        )?;
        let record = build_record(&self.run_id, &plan_hash, 1, ZERO_HASH, event)?;
        append_raw(&stage.join("events.jsonl"), &record, &self.run_id)?;
        write_head(&stage.join("journal-heads"), &record, &self.run_id)?;
        fs::rename(&stage, self.run_dir())
            .map_err(|error| storage_error("create", &self.run_id, error))?;
        self.validate_run_dir()
    }

    pub fn read_plan(&self) -> Result<RunPlan, AiwError> {
        let _lock = self.acquire_lock()?;
        self.validate_run_dir()?;
        self.read_plan_locked()
    }

    fn read_plan_locked(&self) -> Result<RunPlan, AiwError> {
        let plan: RunPlan = read_json(&self.plan_path(), MAX_ARTIFACT, &self.run_id, "plan")?;
        validate_plan(&plan)?;
        if plan.run_id != self.run_id {
            return Err(run_error(
                "AIW_RUN_ID_MISMATCH",
                "persisted plan belongs to another run",
                "plan",
                &self.run_id,
            ));
        }
        Ok(plan)
    }

    pub fn write_approval(&self, approval: &ApprovalRecord) -> Result<(), AiwError> {
        let _lock = self.acquire_lock()?;
        self.validate_run_dir()?;
        self.recover_locked()?;
        let plan = self.read_plan_locked()?;
        validate_approval(approval, &plan)?;
        if self.approval_path().exists()
            || self.cancellation_path().exists()
            || self.result_path().exists()
        {
            return Err(run_error(
                "AIW_TRANSITION_INVALID",
                "approval requires a pending run",
                "approval",
                &self.run_id,
            ));
        }
        self.persist_mutation(
            RunEventKind::ApprovalIntent,
            RunEventKind::ApprovalRecorded,
            &self.approval_path(),
            approval,
            &approval.approved_at,
            "approval",
        )
    }

    pub fn read_approval(&self) -> Result<ApprovalRecord, AiwError> {
        let _lock = self.acquire_lock()?;
        self.validate_run_dir()?;
        self.recover_locked()?;
        self.read_approval_locked()
    }

    fn read_approval_locked(&self) -> Result<ApprovalRecord, AiwError> {
        let plan = self.read_plan_locked()?;
        let value: ApprovalRecord = read_json(
            &self.approval_path(),
            MAX_ARTIFACT,
            &self.run_id,
            "approval",
        )?;
        validate_approval(&value, &plan)?;
        Ok(value)
    }

    pub fn append_event(&self, event: RunEvent) -> Result<JournalRecord, AiwError> {
        validate_event(&event)?;
        if event.kind != RunEventKind::Progress || event.artifact_hash.is_some() {
            return Err(run_error(
                "AIW_EVENT_RESERVED",
                "only progress events may be appended by callers",
                "journal",
                &self.run_id,
            ));
        }
        let _lock = self.acquire_lock()?;
        self.validate_run_dir()?;
        self.recover_locked()?;
        if !self.approval_path().is_file()
            || self.cancellation_path().exists()
            || self.result_path().exists()
        {
            return Err(run_error(
                "AIW_TRANSITION_INVALID",
                "progress requires an approved active run",
                "journal",
                &self.run_id,
            ));
        }
        self.append_record(event)
    }

    pub fn replay_journal(&self) -> Result<Vec<JournalRecord>, AiwError> {
        let _lock = self.acquire_lock()?;
        self.validate_run_dir()?;
        self.recover_locked()?;
        self.load_records(true)
    }

    pub fn request_cancellation(
        &self,
        requested_by: impl Into<String>,
        requested_at: impl Into<String>,
    ) -> Result<CancellationRequest, AiwError> {
        let value = CancellationRequest {
            schema: CANCELLATION_SCHEMA.into(),
            run_id: self.run_id.clone(),
            requested_at: requested_at.into(),
            requested_by: requested_by.into(),
        };
        validate_cancellation(&value)?;
        let _lock = self.acquire_lock()?;
        self.validate_run_dir()?;
        self.recover_locked()?;
        if self.result_path().exists() {
            return Err(run_error(
                "AIW_RUN_TERMINAL",
                "cannot cancel a terminal run",
                "cancel",
                &self.run_id,
            ));
        }
        if self.cancellation_path().exists() {
            return Err(run_error(
                "AIW_WRITE_ONCE_CONFLICT",
                "cancellation already exists",
                "cancel",
                &self.run_id,
            ));
        }
        self.persist_mutation(
            RunEventKind::CancellationIntent,
            RunEventKind::CancellationRequested,
            &self.cancellation_path(),
            &value,
            &value.requested_at,
            "cancel",
        )?;
        Ok(value)
    }

    pub fn write_result(&self, result: &RunResult) -> Result<(), AiwError> {
        validate_result(result)?;
        if result.run_id != self.run_id {
            return Err(run_error(
                "AIW_RUN_ID_MISMATCH",
                "result belongs to another run",
                "result",
                &self.run_id,
            ));
        }
        let _lock = self.acquire_lock()?;
        self.validate_run_dir()?;
        self.recover_locked()?;
        if !self.approval_path().exists() {
            return Err(run_error(
                "AIW_TRANSITION_INVALID",
                "terminal result requires approval",
                "result",
                &self.run_id,
            ));
        }
        self.read_approval_locked()?;
        if self.result_path().exists() {
            return Err(run_error(
                "AIW_WRITE_ONCE_CONFLICT",
                "terminal result already exists",
                "result",
                &self.run_id,
            ));
        }
        if self.cancellation_path().exists() && result.outcome != RunOutcome::Cancelled {
            return Err(run_error(
                "AIW_CANCELLATION_WINS",
                "cancelled run requires a cancelled result",
                "result",
                &self.run_id,
            ));
        }
        self.persist_mutation(
            RunEventKind::TerminalIntent,
            RunEventKind::TerminalRecorded,
            &self.result_path(),
            result,
            &result.completed_at,
            "result",
        )
    }

    pub fn read_result(&self) -> Result<RunResult, AiwError> {
        let _lock = self.acquire_lock()?;
        self.validate_run_dir()?;
        self.recover_locked()?;
        self.read_result_locked()
    }

    fn read_result_locked(&self) -> Result<RunResult, AiwError> {
        let value: RunResult =
            read_json(&self.result_path(), MAX_ARTIFACT, &self.run_id, "result")?;
        validate_result(&value)?;
        if value.run_id != self.run_id {
            return Err(run_error(
                "AIW_RUN_ID_MISMATCH",
                "persisted result belongs to another run",
                "result",
                &self.run_id,
            ));
        }
        Ok(value)
    }

    fn read_cancellation_locked(&self) -> Result<CancellationRequest, AiwError> {
        let value: CancellationRequest = read_json(
            &self.cancellation_path(),
            MAX_ARTIFACT,
            &self.run_id,
            "cancel",
        )?;
        validate_cancellation(&value)?;
        if value.run_id != self.run_id {
            return Err(run_error(
                "AIW_RUN_ID_MISMATCH",
                "cancellation belongs to another run",
                "cancel",
                &self.run_id,
            ));
        }
        Ok(value)
    }

    pub fn recovery_status(&self) -> Result<RecoveryStatus, AiwError> {
        let _lock = self.acquire_lock()?;
        self.validate_run_dir()?;
        self.recover_locked()?;
        let plan = self.read_plan_locked()?;
        let records = self.load_records(true)?;
        let last_sequence = records.last().map_or(0, |record| record.sequence);
        if self.result_path().exists() {
            return Ok(RecoveryStatus::Terminal {
                result: self.read_result_locked()?,
                last_sequence,
            });
        }
        if self.cancellation_path().exists() {
            return Ok(RecoveryStatus::CancellationRequested {
                request: self.read_cancellation_locked()?,
                last_sequence,
            });
        }
        if self.approval_path().exists() {
            return Ok(RecoveryStatus::Ready {
                approval: self.read_approval_locked()?,
                last_sequence,
            });
        }
        Ok(RecoveryStatus::PendingApproval {
            plan_hash: plan.hash()?,
            last_sequence,
        })
    }

    fn persist_mutation<T: Serialize>(
        &self,
        intent: RunEventKind,
        committed: RunEventKind,
        target: &Path,
        value: &T,
        occurred_at: &str,
        stage: &str,
    ) -> Result<(), AiwError> {
        let hash = hash_value(value)?;
        self.append_record(artifact_event(
            intent,
            occurred_at,
            &format!("{stage} mutation prepared"),
            &hash,
        )?)?;
        let pending = self.pending_path(target);
        remove_pending(&pending, &self.run_id)?;
        write_complete_new(&pending, value, &self.run_id, stage)?;
        publish_new(&pending, target, &self.run_id, stage)?;
        self.append_record(artifact_event(
            committed,
            occurred_at,
            &format!("{stage} persisted"),
            &hash,
        )?)?;
        Ok(())
    }

    fn recover_locked(&self) -> Result<(), AiwError> {
        let records = self.load_records(true)?;
        self.verify_committed(&records)?;
        let last = records
            .last()
            .ok_or_else(|| journal_error(&self.run_id, "missing genesis"))?;
        if !is_intent(last.event.kind) {
            return Ok(());
        }
        let expected = last
            .event
            .artifact_hash
            .as_deref()
            .ok_or_else(|| journal_error(&self.run_id, "intent has no artifact hash"))?;
        let target = self.intent_target(last.event.kind);
        let pending = self.pending_path(&target);
        let recovered = if target.exists() {
            self.verify_artifact(last.event.kind, &target, expected)?;
            remove_pending(&pending, &self.run_id)?;
            remove_pending(&self.pending_path(&pending), &self.run_id)?;
            true
        } else if pending.exists() {
            self.verify_artifact(last.event.kind, &pending, expected)?;
            publish_new(&pending, &target, &self.run_id, "recovery")?;
            remove_pending(&self.pending_path(&pending), &self.run_id)?;
            true
        } else {
            remove_pending(&self.pending_path(&pending), &self.run_id)?;
            false
        };
        let kind = if recovered {
            commit_for(last.event.kind)
        } else {
            RunEventKind::MutationAborted
        };
        self.append_record(artifact_event(
            kind,
            &last.event.occurred_at,
            if recovered {
                "recovery committed durable mutation"
            } else {
                "recovery aborted unpublished mutation"
            },
            expected,
        )?)?;
        Ok(())
    }

    fn intent_target(&self, kind: RunEventKind) -> PathBuf {
        match kind {
            RunEventKind::ApprovalIntent => self.approval_path(),
            RunEventKind::CancellationIntent => self.cancellation_path(),
            RunEventKind::TerminalIntent => self.result_path(),
            _ => unreachable!("validated intent"),
        }
    }

    fn verify_artifact(
        &self,
        intent: RunEventKind,
        path: &Path,
        expected: &str,
    ) -> Result<(), AiwError> {
        let actual = match intent {
            RunEventKind::ApprovalIntent => {
                let value: ApprovalRecord =
                    read_json(path, MAX_ARTIFACT, &self.run_id, "recovery")?;
                validate_approval(&value, &self.read_plan_locked()?)?;
                hash_value(&value)?
            }
            RunEventKind::CancellationIntent => {
                let value: CancellationRequest =
                    read_json(path, MAX_ARTIFACT, &self.run_id, "recovery")?;
                validate_cancellation(&value)?;
                if value.run_id != self.run_id {
                    return Err(run_error(
                        "AIW_RUN_ID_MISMATCH",
                        "foreign cancellation",
                        "recovery",
                        &self.run_id,
                    ));
                }
                hash_value(&value)?
            }
            RunEventKind::TerminalIntent => {
                let value: RunResult = read_json(path, MAX_ARTIFACT, &self.run_id, "recovery")?;
                validate_result(&value)?;
                if value.run_id != self.run_id {
                    return Err(run_error(
                        "AIW_RUN_ID_MISMATCH",
                        "foreign result",
                        "recovery",
                        &self.run_id,
                    ));
                }
                if self.cancellation_path().exists() && value.outcome != RunOutcome::Cancelled {
                    return Err(run_error(
                        "AIW_CANCELLATION_WINS",
                        "recovered result conflicts with cancellation",
                        "recovery",
                        &self.run_id,
                    ));
                }
                hash_value(&value)?
            }
            _ => unreachable!("validated intent"),
        };
        if actual != expected {
            return Err(run_error(
                "AIW_ARTIFACT_TAMPERED",
                "artifact differs from journal intent",
                "recovery",
                &self.run_id,
            ));
        }
        Ok(())
    }

    fn verify_committed(&self, records: &[JournalRecord]) -> Result<(), AiwError> {
        let pending = records
            .last()
            .and_then(|record| is_intent(record.event.kind).then_some(record.event.kind));
        let mut approval_committed = false;
        let mut cancellation_committed = false;
        let mut terminal_committed = false;
        for record in records {
            let intent = match record.event.kind {
                RunEventKind::ApprovalRecorded => {
                    approval_committed = true;
                    Some(RunEventKind::ApprovalIntent)
                }
                RunEventKind::CancellationRequested => {
                    cancellation_committed = true;
                    Some(RunEventKind::CancellationIntent)
                }
                RunEventKind::TerminalRecorded => {
                    terminal_committed = true;
                    Some(RunEventKind::TerminalIntent)
                }
                _ => None,
            };
            if let Some(intent) = intent {
                let expected =
                    record.event.artifact_hash.as_deref().ok_or_else(|| {
                        journal_error(&self.run_id, "commit has no artifact hash")
                    })?;
                self.verify_artifact(intent, &self.intent_target(intent), expected)?;
            }
        }
        for (intent, path, committed) in [
            (
                RunEventKind::ApprovalIntent,
                self.approval_path(),
                approval_committed,
            ),
            (
                RunEventKind::CancellationIntent,
                self.cancellation_path(),
                cancellation_committed,
            ),
            (
                RunEventKind::TerminalIntent,
                self.result_path(),
                terminal_committed,
            ),
        ] {
            if path.exists() && !committed && pending != Some(intent) {
                return Err(run_error(
                    "AIW_ARTIFACT_UNJOURNALED",
                    "write-once artifact has no matching journal commit",
                    "recovery",
                    &self.run_id,
                ));
            }
        }
        if self.cancellation_path().exists()
            && self.result_path().exists()
            && self.read_result_locked()?.outcome != RunOutcome::Cancelled
        {
            return Err(run_error(
                "AIW_CANCELLATION_WINS",
                "result conflicts with cancellation",
                "recovery",
                &self.run_id,
            ));
        }
        Ok(())
    }

    fn append_record(&self, event: RunEvent) -> Result<JournalRecord, AiwError> {
        validate_event(&event)?;
        let mut records = self.load_records(true)?;
        if records.len() >= MAX_RECORDS {
            return Err(run_error(
                "AIW_JOURNAL_TOO_LARGE",
                "journal reached its record bound",
                "journal",
                &self.run_id,
            ));
        }
        let plan_hash = self.read_plan_locked()?.hash()?;
        let sequence = records.last().map_or(1, |record| record.sequence + 1);
        let previous = records
            .last()
            .map_or(ZERO_HASH, |record| record.hash.as_str());
        let record = build_record(&self.run_id, &plan_hash, sequence, previous, event)?;
        records.push(record.clone());
        validate_grammar(&records, &self.run_id, &plan_hash)?;
        append_raw(&self.journal_path(), &record, &self.run_id)?;
        write_head(&self.heads_dir(), &record, &self.run_id)?;
        Ok(record)
    }

    fn load_records(&self, repair_tail: bool) -> Result<Vec<JournalRecord>, AiwError> {
        let plan_hash = self.read_plan_locked()?.hash()?;
        let path = self.journal_path();
        let bytes = read_bounded(&path, MAX_JOURNAL, &self.run_id, "journal")?;
        let complete_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        if complete_len != bytes.len() && !repair_tail {
            return Err(journal_error(
                &self.run_id,
                "journal has an incomplete tail",
            ));
        }
        let mut records = Vec::new();
        if complete_len > 0 {
            for raw in bytes[..complete_len - 1].split(|byte| *byte == b'\n') {
                if raw.is_empty() {
                    return Err(journal_error(
                        &self.run_id,
                        "journal contains a blank record",
                    ));
                }
                if raw.len() > MAX_LINE || records.len() >= MAX_RECORDS {
                    return Err(run_error(
                        "AIW_JOURNAL_TOO_LARGE",
                        "journal input exceeds its bound",
                        "journal",
                        &self.run_id,
                    ));
                }
                let record: JournalRecord = serde_json::from_slice(raw)
                    .map_err(|error| journal_error(&self.run_id, error.to_string()))?;
                verify_record(&record, records.last(), &self.run_id, &plan_hash)?;
                records.push(record);
            }
        }
        self.verify_heads(&records)?;
        if records.is_empty() {
            return Err(journal_error(&self.run_id, "journal has no genesis record"));
        }
        validate_grammar(&records, &self.run_id, &plan_hash)?;
        if complete_len != bytes.len() {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|error| storage_error("journal", &self.run_id, error))?;
            file.set_len(complete_len as u64)
                .and_then(|_| file.sync_all())
                .map_err(|error| storage_error("journal", &self.run_id, error))?;
        }
        Ok(records)
    }

    fn verify_heads(&self, records: &[JournalRecord]) -> Result<(), AiwError> {
        ensure_directory(&self.heads_dir(), &self.run_id, "journal")?;
        let mut heads = BTreeMap::new();
        for entry in fs::read_dir(self.heads_dir())
            .map_err(|error| storage_error("journal", &self.run_id, error))?
        {
            let path = entry
                .map_err(|error| storage_error("journal", &self.run_id, error))?
                .path();
            if path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.ends_with(".pending"))
            {
                ensure_file(&path, &self.run_id, "journal")?;
                fs::remove_file(&path)
                    .map_err(|error| storage_error("journal", &self.run_id, error))?;
                continue;
            }
            if heads.len() >= MAX_RECORDS {
                return Err(journal_error(&self.run_id, "too many journal heads"));
            }
            let head: JournalHead = read_json(&path, MAX_ARTIFACT, &self.run_id, "journal")?;
            validate_head(&head, &self.run_id)?;
            if path.file_name().and_then(|value| value.to_str()) != Some(&head_name(head.sequence))
            {
                return Err(journal_error(&self.run_id, "journal head name is invalid"));
            }
            if heads.insert(head.sequence, head).is_some() {
                return Err(journal_error(&self.run_id, "duplicate journal head"));
            }
        }
        let highest = heads.keys().next_back().copied().unwrap_or(0);
        if highest as usize > records.len() {
            return Err(run_error(
                "AIW_JOURNAL_TRUNCATED",
                "journal is shorter than its durable head",
                "journal",
                &self.run_id,
            ));
        }
        for sequence in 1..=highest {
            let head = heads
                .get(&sequence)
                .ok_or_else(|| journal_error(&self.run_id, "journal head gap"))?;
            let record = &records[(sequence - 1) as usize];
            if head.run_id != record.run_id
                || head.plan_hash != record.plan_hash
                || head.hash != record.hash
            {
                return Err(run_error(
                    "AIW_JOURNAL_TAMPERED",
                    "journal head differs from its record",
                    "journal",
                    &self.run_id,
                ));
            }
        }
        for record in records.iter().skip(highest as usize) {
            write_head(&self.heads_dir(), record, &self.run_id)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RecoveryStatus {
    PendingApproval {
        plan_hash: String,
        last_sequence: u64,
    },
    Ready {
        approval: ApprovalRecord,
        last_sequence: u64,
    },
    CancellationRequested {
        request: CancellationRequest,
        last_sequence: u64,
    },
    Terminal {
        result: RunResult,
        last_sequence: u64,
    },
}

fn validate_plan(plan: &RunPlan) -> Result<(), AiwError> {
    if plan.schema != RUN_PLAN_SCHEMA {
        return Err(run_error(
            "AIW_PLAN_SCHEMA_UNSUPPORTED",
            "run plan schema is unsupported",
            "plan",
            &plan.run_id,
        ));
    }
    validate_id("runId", &plan.run_id)?;
    validate_id("projectId", &plan.project_id)?;
    validate_text("createdAt", &plan.created_at, &plan.run_id)?;
    if plan.actions.is_empty() || plan.actions.len() > MAX_ITEMS {
        return Err(run_error(
            "AIW_PLAN_ACTIONS_INVALID",
            "plan action count is outside its bound",
            "plan",
            &plan.run_id,
        ));
    }
    if plan.trust_deltas.len() > MAX_ITEMS {
        return Err(run_error(
            "AIW_PLAN_TRUST_DELTAS_INVALID",
            "trust delta count exceeds its bound",
            "plan",
            &plan.run_id,
        ));
    }
    for action in &plan.actions {
        match action {
            PlannedAction::ExecuteScenario { scenario_id } => {
                validate_id("scenarioId", scenario_id)?
            }
            PlannedAction::LaunchValidatedProfile { profile_id } => {
                validate_id("profileId", profile_id)?
            }
            _ => {}
        }
        if !action_allowed(plan.lifecycle, action) {
            return Err(run_error(
                "AIW_ACTION_LIFECYCLE_MISMATCH",
                "action is invalid for this lifecycle",
                "plan",
                &plan.run_id,
            ));
        }
    }
    for delta in &plan.trust_deltas {
        validate_text("trustDelta", delta, &plan.run_id)?;
    }
    Ok(())
}

fn action_allowed(lifecycle: RunLifecycleKind, action: &PlannedAction) -> bool {
    match lifecycle {
        RunLifecycleKind::Assessment => matches!(
            action,
            PlannedAction::AssessHost
                | PlannedAction::PrepareWorkspace
                | PlannedAction::ExecuteScenario { .. }
                | PlannedAction::CollectEvidence
        ),
        RunLifecycleKind::Launch => matches!(
            action,
            PlannedAction::AssessHost
                | PlannedAction::PrepareWorkspace
                | PlannedAction::LaunchValidatedProfile { .. }
                | PlannedAction::CollectEvidence
        ),
        RunLifecycleKind::Authoring => {
            !matches!(action, PlannedAction::LaunchValidatedProfile { .. })
        }
    }
}

fn validate_approval(value: &ApprovalRecord, plan: &RunPlan) -> Result<(), AiwError> {
    if value.schema != APPROVAL_SCHEMA
        || value.run_id != plan.run_id
        || value.plan_hash != plan.hash()?
        || value.trust_deltas != plan.trust_deltas
        || value.trust_deltas.len() > MAX_ITEMS
    {
        return Err(run_error(
            "AIW_APPROVAL_PLAN_MISMATCH",
            "approval is not bound to the current plan",
            "approval",
            &plan.run_id,
        ));
    }
    validate_text("approvedBy", &value.approved_by, &plan.run_id)?;
    validate_text("approvedAt", &value.approved_at, &plan.run_id)
}

fn validate_event(value: &RunEvent) -> Result<(), AiwError> {
    if value.schema != EVENT_SCHEMA {
        return Err(run_error(
            "AIW_EVENT_SCHEMA_UNSUPPORTED",
            "event schema is unsupported",
            "journal",
            "",
        ));
    }
    validate_text("occurredAt", &value.occurred_at, "")?;
    validate_text("detail", &value.detail, "")?;
    if let Some(hash) = &value.artifact_hash {
        validate_hash(hash, "artifactHash", "")?;
    }
    let requires_hash = matches!(
        value.kind,
        RunEventKind::Created
            | RunEventKind::ApprovalIntent
            | RunEventKind::ApprovalRecorded
            | RunEventKind::CancellationIntent
            | RunEventKind::CancellationRequested
            | RunEventKind::TerminalIntent
            | RunEventKind::TerminalRecorded
            | RunEventKind::MutationAborted
    );
    if requires_hash != value.artifact_hash.is_some() {
        return Err(run_error(
            "AIW_EVENT_BINDING_INVALID",
            "event artifact binding is invalid",
            "journal",
            "",
        ));
    }
    Ok(())
}

fn validate_result(value: &RunResult) -> Result<(), AiwError> {
    if value.schema != RESULT_SCHEMA {
        return Err(run_error(
            "AIW_RESULT_SCHEMA_UNSUPPORTED",
            "result schema is unsupported",
            "result",
            &value.run_id,
        ));
    }
    validate_id("runId", &value.run_id)?;
    validate_text("completedAt", &value.completed_at, &value.run_id)?;
    validate_text("summary", &value.summary, &value.run_id)?;
    if let Some(hash) = &value.evidence_root {
        validate_hash(hash, "evidenceRoot", &value.run_id)?;
    }
    if value.outcome == RunOutcome::Succeeded
        && (value.evidence_root.is_none() || !value.cleanup_complete)
    {
        return Err(run_error(
            "AIW_RESULT_INCOMPLETE",
            "successful result requires evidence and cleanup",
            "result",
            &value.run_id,
        ));
    }
    Ok(())
}

fn validate_cancellation(value: &CancellationRequest) -> Result<(), AiwError> {
    if value.schema != CANCELLATION_SCHEMA {
        return Err(run_error(
            "AIW_CANCELLATION_SCHEMA_UNSUPPORTED",
            "cancellation schema is unsupported",
            "cancel",
            &value.run_id,
        ));
    }
    validate_id("runId", &value.run_id)?;
    validate_text("requestedAt", &value.requested_at, &value.run_id)?;
    validate_text("requestedBy", &value.requested_by, &value.run_id)
}

fn validate_id(name: &str, value: &str) -> Result<(), AiwError> {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
    if value.is_empty()
        || value.len() > 128
        || matches!(value, "." | "..")
        || value.ends_with('.')
        || reserved
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(AiwError::new(
            "AIW_IDENTIFIER_INVALID",
            "identifier is unsafe or ambiguous",
            "validation",
            None,
            false,
            "Use lowercase ASCII letters, digits, hyphens, underscores, or interior dots; reserved names are forbidden.",
            format!("{name}: {value}"),
        ));
    }
    Ok(())
}

fn validate_text(name: &str, value: &str, run_id: &str) -> Result<(), AiwError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT || value.contains('\0') {
        return Err(AiwError::new(
            "AIW_TEXT_INVALID",
            "required text is empty, too long, or contains a NUL",
            "validation",
            (!run_id.is_empty()).then_some(run_id),
            false,
            "Provide bounded non-empty text without NUL characters.",
            name,
        ));
    }
    Ok(())
}

fn validate_hash(value: &str, name: &str, run_id: &str) -> Result<(), AiwError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(AiwError::new(
            "AIW_HASH_INVALID",
            "hash must be lowercase SHA-256 hexadecimal",
            "validation",
            (!run_id.is_empty()).then_some(run_id),
            false,
            "Use a lowercase 64-character SHA-256 hash.",
            name,
        ));
    }
    Ok(())
}

fn artifact_event(
    kind: RunEventKind,
    at: &str,
    detail: &str,
    hash: &str,
) -> Result<RunEvent, AiwError> {
    let value = RunEvent {
        schema: EVENT_SCHEMA.into(),
        kind,
        occurred_at: at.into(),
        detail: detail.into(),
        artifact_hash: Some(hash.into()),
    };
    validate_event(&value)?;
    Ok(value)
}

fn hash_value<T: Serialize>(value: &T) -> Result<String, AiwError> {
    let value =
        serde_json::to_value(value).map_err(|error| serialization_error("hash", "", error))?;
    let bytes = canonical_json_bytes(&value).map_err(|error| {
        AiwError::new(
            "AIW_CANONICALIZATION_FAILED",
            "could not canonicalize persisted data",
            "hash",
            None,
            false,
            "Use supported integer-only JSON values.",
            error.to_string(),
        )
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn build_record(
    run_id: &str,
    plan_hash: &str,
    sequence: u64,
    previous_hash: &str,
    event: RunEvent,
) -> Result<JournalRecord, AiwError> {
    let mut value = JournalRecord {
        schema: JOURNAL_SCHEMA.into(),
        run_id: run_id.into(),
        plan_hash: plan_hash.into(),
        sequence,
        previous_hash: previous_hash.into(),
        event,
        hash: String::new(),
    };
    value.hash = journal_hash(&value)?;
    Ok(value)
}

fn journal_hash(value: &JournalRecord) -> Result<String, AiwError> {
    hash_value(&serde_json::json!({
        "schema": value.schema,
        "runId": value.run_id,
        "planHash": value.plan_hash,
        "sequence": value.sequence,
        "previousHash": value.previous_hash,
        "event": value.event,
    }))
}

fn verify_record(
    value: &JournalRecord,
    previous: Option<&JournalRecord>,
    run_id: &str,
    plan_hash: &str,
) -> Result<(), AiwError> {
    if value.schema != JOURNAL_SCHEMA || value.run_id != run_id || value.plan_hash != plan_hash {
        return Err(run_error(
            "AIW_JOURNAL_BINDING_INVALID",
            "journal is bound to another run or plan",
            "journal",
            run_id,
        ));
    }
    validate_event(&value.event)?;
    let expected_sequence = previous.map_or(1, |record| record.sequence + 1);
    let expected_previous = previous.map_or(ZERO_HASH, |record| record.hash.as_str());
    if value.sequence != expected_sequence
        || value.previous_hash != expected_previous
        || journal_hash(value)? != value.hash
    {
        return Err(run_error(
            "AIW_JOURNAL_TAMPERED",
            "journal sequence or hash chain is invalid",
            "journal",
            run_id,
        ));
    }
    Ok(())
}

fn validate_grammar(
    records: &[JournalRecord],
    run_id: &str,
    plan_hash: &str,
) -> Result<(), AiwError> {
    let first = records
        .first()
        .ok_or_else(|| journal_error(run_id, "missing genesis"))?;
    if first.event.kind != RunEventKind::Created
        || first.event.artifact_hash.as_deref() != Some(plan_hash)
    {
        return Err(journal_error(run_id, "invalid genesis"));
    }
    let mut approved = false;
    let mut cancelled = false;
    let mut terminal = false;
    let mut pending: Option<(RunEventKind, &str)> = None;
    for (index, record) in records.iter().enumerate() {
        if index == 0 {
            continue;
        }
        if terminal {
            return Err(journal_error(run_id, "event follows terminal commit"));
        }
        match record.event.kind {
            RunEventKind::Created => return Err(journal_error(run_id, "duplicate genesis")),
            RunEventKind::ApprovalIntent => {
                if approved || cancelled || pending.is_some() {
                    return Err(journal_error(run_id, "approval intent out of order"));
                }
                pending = Some((
                    record.event.kind,
                    record.event.artifact_hash.as_deref().unwrap_or_default(),
                ));
            }
            RunEventKind::CancellationIntent => {
                if cancelled || pending.is_some() {
                    return Err(journal_error(run_id, "cancellation intent out of order"));
                }
                pending = Some((
                    record.event.kind,
                    record.event.artifact_hash.as_deref().unwrap_or_default(),
                ));
            }
            RunEventKind::TerminalIntent => {
                if !approved || pending.is_some() {
                    return Err(journal_error(run_id, "terminal intent out of order"));
                }
                pending = Some((
                    record.event.kind,
                    record.event.artifact_hash.as_deref().unwrap_or_default(),
                ));
            }
            RunEventKind::ApprovalRecorded => {
                match_intent(
                    &mut pending,
                    RunEventKind::ApprovalIntent,
                    &record.event,
                    run_id,
                )?;
                approved = true;
            }
            RunEventKind::CancellationRequested => {
                match_intent(
                    &mut pending,
                    RunEventKind::CancellationIntent,
                    &record.event,
                    run_id,
                )?;
                cancelled = true;
            }
            RunEventKind::TerminalRecorded => {
                match_intent(
                    &mut pending,
                    RunEventKind::TerminalIntent,
                    &record.event,
                    run_id,
                )?;
                terminal = true;
            }
            RunEventKind::MutationAborted => {
                let Some((_, expected)) = pending.take() else {
                    return Err(journal_error(run_id, "abort has no intent"));
                };
                if record.event.artifact_hash.as_deref() != Some(expected) {
                    return Err(journal_error(run_id, "abort differs from intent"));
                }
            }
            RunEventKind::Progress => {
                if !approved || cancelled || pending.is_some() {
                    return Err(journal_error(run_id, "progress out of order"));
                }
            }
            RunEventKind::RecoveryObserved => {
                if pending.is_some() {
                    return Err(journal_error(run_id, "recovery interrupts mutation"));
                }
            }
        }
    }
    Ok(())
}

fn match_intent<'a>(
    pending: &mut Option<(RunEventKind, &'a str)>,
    expected_kind: RunEventKind,
    event: &'a RunEvent,
    run_id: &str,
) -> Result<(), AiwError> {
    let Some((kind, hash)) = pending.take() else {
        return Err(journal_error(run_id, "commit has no intent"));
    };
    if kind != expected_kind || event.artifact_hash.as_deref() != Some(hash) {
        return Err(journal_error(run_id, "commit differs from intent"));
    }
    Ok(())
}

fn is_intent(kind: RunEventKind) -> bool {
    matches!(
        kind,
        RunEventKind::ApprovalIntent
            | RunEventKind::CancellationIntent
            | RunEventKind::TerminalIntent
    )
}

fn commit_for(kind: RunEventKind) -> RunEventKind {
    match kind {
        RunEventKind::ApprovalIntent => RunEventKind::ApprovalRecorded,
        RunEventKind::CancellationIntent => RunEventKind::CancellationRequested,
        RunEventKind::TerminalIntent => RunEventKind::TerminalRecorded,
        _ => unreachable!("validated intent"),
    }
}

fn append_raw(path: &Path, value: &JournalRecord, run_id: &str) -> Result<(), AiwError> {
    ensure_file(path, run_id, "journal")?;
    let mut bytes =
        serde_json::to_vec(value).map_err(|error| serialization_error("journal", run_id, error))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LINE {
        return Err(run_error(
            "AIW_JOURNAL_TOO_LARGE",
            "journal record exceeds bound",
            "journal",
            run_id,
        ));
    }
    let length = fs::metadata(path)
        .map_err(|error| storage_error("journal", run_id, error))?
        .len();
    if length.saturating_add(bytes.len() as u64) > MAX_JOURNAL {
        return Err(run_error(
            "AIW_JOURNAL_TOO_LARGE",
            "journal exceeds storage bound",
            "journal",
            run_id,
        ));
    }
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| storage_error("journal", run_id, error))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| storage_error("journal", run_id, error))
}

fn write_head(directory: &Path, record: &JournalRecord, run_id: &str) -> Result<(), AiwError> {
    let value = JournalHead {
        schema: HEAD_SCHEMA.into(),
        run_id: record.run_id.clone(),
        plan_hash: record.plan_hash.clone(),
        sequence: record.sequence,
        hash: record.hash.clone(),
    };
    write_complete_new(
        &directory.join(head_name(record.sequence)),
        &value,
        run_id,
        "journal",
    )
}

fn validate_head(value: &JournalHead, run_id: &str) -> Result<(), AiwError> {
    if value.schema != HEAD_SCHEMA || value.run_id != run_id || value.sequence == 0 {
        return Err(journal_error(run_id, "journal head binding is invalid"));
    }
    validate_hash(&value.plan_hash, "planHash", run_id)?;
    validate_hash(&value.hash, "hash", run_id)
}

fn head_name(sequence: u64) -> String {
    format!("{sequence:020}.json")
}

fn write_complete_new<T: Serialize>(
    path: &Path,
    value: &T,
    run_id: &str,
    stage: &str,
) -> Result<(), AiwError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| serialization_error(stage, run_id, error))?;
    if bytes.len() as u64 + 1 > MAX_ARTIFACT {
        return Err(run_error(
            "AIW_ARTIFACT_TOO_LARGE",
            "artifact exceeds storage bound",
            stage,
            run_id,
        ));
    }
    let pending = path.with_extension(format!(
        "{}.pending",
        path.extension().and_then(|v| v.to_str()).unwrap_or("tmp")
    ));
    remove_pending(&pending, run_id)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .map_err(|error| storage_error(stage, run_id, error))?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| storage_error(stage, run_id, error))?;
    publish_new(&pending, path, run_id, stage)
}

fn write_empty_new(path: &Path, run_id: &str, stage: &str) -> Result<(), AiwError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| storage_error(stage, run_id, error))
}

fn publish_new(pending: &Path, target: &Path, run_id: &str, stage: &str) -> Result<(), AiwError> {
    ensure_file(pending, run_id, stage)?;
    fs::hard_link(pending, target).map_err(|error| {
        io_error(
            "AIW_WRITE_ONCE_CONFLICT",
            "write-once artifact exists or cannot be published",
            stage,
            run_id,
            error,
        )
    })?;
    ensure_file(target, run_id, stage)?;
    fs::remove_file(pending).map_err(|error| storage_error(stage, run_id, error))
}

fn remove_pending(path: &Path, run_id: &str) -> Result<(), AiwError> {
    if path.exists() {
        ensure_file(path, run_id, "recovery")?;
        fs::remove_file(path).map_err(|error| storage_error("recovery", run_id, error))?;
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max: u64,
    run_id: &str,
    stage: &str,
) -> Result<T, AiwError> {
    let bytes = read_bounded(path, max, run_id, stage)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        AiwError::new(
            "AIW_STORAGE_INVALID",
            "artifact contains invalid or unsupported JSON",
            stage,
            Some(run_id),
            false,
            "Do not modify persisted artifacts; recover from an intact run.",
            error.to_string(),
        )
    })
}

fn read_bounded(path: &Path, max: u64, run_id: &str, stage: &str) -> Result<Vec<u8>, AiwError> {
    ensure_file(path, run_id, stage)?;
    let metadata = fs::metadata(path).map_err(|error| storage_error(stage, run_id, error))?;
    if metadata.len() > max {
        return Err(run_error(
            "AIW_ARTIFACT_TOO_LARGE",
            "artifact exceeds read bound",
            stage,
            run_id,
        ));
    }
    let file = File::open(path).map_err(|error| storage_error(stage, run_id, error))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| storage_error(stage, run_id, error))?;
    if bytes.len() as u64 > max {
        return Err(run_error(
            "AIW_ARTIFACT_TOO_LARGE",
            "artifact changed beyond read bound",
            stage,
            run_id,
        ));
    }
    ensure_file(path, run_id, stage)?;
    Ok(bytes)
}

fn ensure_no_reparse_components(path: &Path, run_id: &str) -> Result<(), AiwError> {
    for component in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if component.as_os_str().is_empty() || !component.exists() {
            continue;
        }
        let metadata = fs::symlink_metadata(component)
            .map_err(|error| storage_error("path", run_id, error))?;
        if metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
            return Err(path_error(
                "path contains a symbolic link or reparse point",
                run_id,
                component,
            ));
        }
    }
    Ok(())
}

fn ensure_directory(path: &Path, run_id: &str, stage: &str) -> Result<(), AiwError> {
    ensure_no_reparse_components(path, run_id)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| storage_error(stage, run_id, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
        return Err(path_error("expected a non-reparse directory", run_id, path));
    }
    Ok(())
}

fn ensure_file(path: &Path, run_id: &str, stage: &str) -> Result<(), AiwError> {
    ensure_no_reparse_components(path, run_id)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| storage_error(stage, run_id, error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
        return Err(path_error(
            "expected a non-reparse regular file",
            run_id,
            path,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn has_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn has_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn is_remote_path(path: &Path) -> bool {
    use std::path::{Component, Prefix};
    matches!(path.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::UNC(..) | Prefix::VerbatimUNC(..)))
}

#[cfg(not(windows))]
fn is_remote_path(_path: &Path) -> bool {
    false
}

fn path_error(summary: &str, run_id: &str, path: &Path) -> AiwError {
    AiwError::new(
        "AIW_PATH_UNSAFE",
        summary,
        "path",
        Some(run_id),
        false,
        "Use an absolute local ACL-restricted workspace without links or reparse points.",
        path.display().to_string(),
    )
}

fn journal_error(run_id: &str, detail: impl Into<String>) -> AiwError {
    AiwError::new(
        "AIW_JOURNAL_INVALID",
        "run journal grammar is invalid",
        "journal",
        Some(run_id),
        false,
        "Do not modify journals; recover from an intact run.",
        detail,
    )
}

fn storage_error(stage: &str, run_id: &str, error: io::Error) -> AiwError {
    io_error(
        "AIW_STORAGE_FAILED",
        "run storage operation failed",
        stage,
        run_id,
        error,
    )
}

fn io_error(code: &str, summary: &str, stage: &str, run_id: &str, error: io::Error) -> AiwError {
    AiwError::new(
        code,
        summary,
        stage,
        Some(run_id),
        matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ),
        "Inspect persisted state before retrying.",
        error.to_string(),
    )
}

fn serialization_error(stage: &str, run_id: &str, error: serde_json::Error) -> AiwError {
    AiwError::new(
        "AIW_SERIALIZATION_FAILED",
        "could not serialize persisted data",
        stage,
        (!run_id.is_empty()).then_some(run_id),
        false,
        "Use a supported persisted contract.",
        error.to_string(),
    )
}

fn run_error(code: &str, summary: &str, stage: &str, run_id: &str) -> AiwError {
    AiwError::new(
        code,
        summary,
        stage,
        (!run_id.is_empty()).then_some(run_id),
        false,
        "Inspect persisted state before retrying.",
        "",
    )
}

fn limit_detail(mut detail: String) -> String {
    if detail.len() <= MAX_TEXT {
        return detail;
    }
    let mut boundary = MAX_TEXT;
    while !detail.is_char_boundary(boundary) {
        boundary -= 1;
    }
    detail.truncate(boundary);
    detail
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{panic, sync::Arc, thread};

    fn root() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "aiw-orchestrator-test-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::canonicalize(path).unwrap()
    }

    fn plan(run_id: &str) -> RunPlan {
        RunPlan::new(
            run_id,
            "project.one",
            RunLifecycleKind::Assessment,
            "2026-08-27T00:00:00Z",
            vec![
                PlannedAction::AssessHost,
                PlannedAction::ExecuteScenario {
                    scenario_id: "install".into(),
                },
            ],
            vec!["provider starts a disposable environment".into()],
        )
        .unwrap()
    }

    fn layout(root: &Path, run_id: &str) -> RunLayout {
        RunLayout::new(root, run_id).unwrap()
    }
    fn approve(layout: &RunLayout, plan: &RunPlan) {
        layout
            .write_approval(
                &ApprovalRecord::for_plan(plan, "admin", "2026-08-27T00:01:00Z").unwrap(),
            )
            .unwrap();
    }
    fn success(run_id: &str) -> RunResult {
        RunResult::new(
            run_id,
            RunOutcome::Succeeded,
            "now",
            Some("a".repeat(64)),
            true,
            "done",
        )
        .unwrap()
    }

    #[test]
    fn golden_json_is_camel_case_and_hash_is_stable() {
        let value = serde_json::to_value(plan("run-one")).unwrap();
        assert_eq!(value["actions"][1]["kind"], "executeScenario");
        assert_eq!(value["actions"][1]["scenarioId"], "install");
        assert!(value["actions"][1].get("scenario_id").is_none());
        assert_eq!(
            plan("run-one").hash().unwrap(),
            "8042bf29b3d2a4e3390655fe37a29ced8a19eec2dffa9e070b31c35e48dcbccf"
        );
    }

    #[test]
    fn strict_json_rejects_unknown_fields() {
        let schema = schemars::schema_for!(RunPlan);
        assert!(serde_json::to_value(schema).unwrap().is_object());
        let mut value = serde_json::to_value(plan("run-one")).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("futureExecution".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<RunPlan>(value).is_err());
        assert!(
            serde_json::from_value::<PlannedAction>(serde_json::json!({
                "kind": "executeScenario", "scenarioId": "install", "command": "bad"
            }))
            .is_err()
        );
    }

    #[test]
    fn identifiers_roots_and_lifecycle_actions_fail_closed() {
        let root = root();
        for value in [".", "..", "con", "nul.txt", "run.", "Run"] {
            assert!(RunLayout::new(&root, value).is_err(), "{value}");
        }
        assert!(RunLayout::new("relative", "run-one").is_err());
        assert!(
            RunPlan::new(
                "run-one",
                "project",
                RunLifecycleKind::Assessment,
                "now",
                vec![PlannedAction::SignPackage],
                vec![]
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unicode_error_detail_is_infallible() {
        let run_id = format!("{}€", "a".repeat(4088));
        let result = panic::catch_unwind(|| {
            RunPlan::new(
                run_id,
                "project",
                RunLifecycleKind::Assessment,
                "now",
                vec![PlannedAction::AssessHost],
                vec![],
            )
        });
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn mutation_and_terminal_invariants_are_enforced() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = plan("run-one");
        layout.create(&plan).unwrap();
        assert!(matches!(
            layout.recovery_status().unwrap(),
            RecoveryStatus::PendingApproval {
                last_sequence: 1,
                ..
            }
        ));
        assert!(layout.write_result(&success("run-one")).is_err());
        approve(&layout, &plan);
        layout.write_result(&success("run-one")).unwrap();
        assert!(matches!(
            layout.recovery_status().unwrap(),
            RecoveryStatus::Terminal {
                last_sequence: 5,
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_wins_result_arbitration() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = plan("run-one");
        layout.create(&plan).unwrap();
        approve(&layout, &plan);
        layout.request_cancellation("admin", "now").unwrap();
        assert_eq!(
            layout
                .write_result(&success("run-one"))
                .unwrap_err()
                .code
                .as_ref(),
            "AIW_CANCELLATION_WINS"
        );
        let cancelled = RunResult::new(
            "run-one",
            RunOutcome::Cancelled,
            "later",
            None,
            true,
            "cancelled",
        )
        .unwrap();
        layout.write_result(&cancelled).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_append_has_monotonic_sequences() {
        let root = root();
        let layout = Arc::new(layout(&root, "run-one"));
        let plan = plan("run-one");
        layout.create(&plan).unwrap();
        approve(&layout, &plan);
        let handles: Vec<_> = (0..8)
            .map(|index| {
                let layout = Arc::clone(&layout);
                thread::spawn(move || {
                    layout
                        .append_event(
                            RunEvent::new(RunEventKind::Progress, "now", format!("event {index}"))
                                .unwrap(),
                        )
                        .unwrap();
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let records = layout.replay_journal().unwrap();
        assert_eq!(records.len(), 11);
        assert!(
            records
                .iter()
                .enumerate()
                .all(|(index, record)| record.sequence == index as u64 + 1)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_completes_published_intent_and_repairs_tail() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = plan("run-one");
        layout.create(&plan).unwrap();
        let approval = ApprovalRecord::for_plan(&plan, "admin", "now").unwrap();
        {
            let _lock = layout.acquire_lock().unwrap();
            let hash = hash_value(&approval).unwrap();
            layout
                .append_record(
                    artifact_event(RunEventKind::ApprovalIntent, "now", "intent", &hash).unwrap(),
                )
                .unwrap();
            write_complete_new(&layout.approval_path(), &approval, "run-one", "test").unwrap();
            let mut file = OpenOptions::new()
                .append(true)
                .open(layout.journal_path())
                .unwrap();
            file.write_all(b"partial").unwrap();
            file.sync_all().unwrap();
        }
        assert!(matches!(
            layout.recovery_status().unwrap(),
            RecoveryStatus::Ready {
                last_sequence: 3,
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_aborts_unpublished_intent_and_allows_a_clean_retry() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = plan("run-one");
        layout.create(&plan).unwrap();
        let approval = ApprovalRecord::for_plan(&plan, "admin", "now").unwrap();
        {
            let _lock = layout.acquire_lock().unwrap();
            let hash = hash_value(&approval).unwrap();
            layout
                .append_record(
                    artifact_event(RunEventKind::ApprovalIntent, "now", "intent", &hash).unwrap(),
                )
                .unwrap();
        }
        assert!(matches!(
            layout.recovery_status().unwrap(),
            RecoveryStatus::PendingApproval {
                last_sequence: 3,
                ..
            }
        ));
        approve(&layout, &plan);
        assert!(matches!(
            layout.recovery_status().unwrap(),
            RecoveryStatus::Ready {
                last_sequence: 5,
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn transplant_truncation_foreign_id_and_oversize_are_rejected() {
        let root = root();
        let left = layout(&root, "run-one");
        let right = layout(&root, "run-two");
        left.create(&plan("run-one")).unwrap();
        right.create(&plan("run-two")).unwrap();
        fs::copy(left.journal_path(), right.journal_path()).unwrap();
        assert_eq!(
            right.replay_journal().unwrap_err().code.as_ref(),
            "AIW_JOURNAL_BINDING_INVALID"
        );
        let bytes = fs::read(left.journal_path()).unwrap();
        fs::write(left.journal_path(), &bytes[..bytes.len() / 2]).unwrap();
        assert_eq!(
            left.replay_journal().unwrap_err().code.as_ref(),
            "AIW_JOURNAL_TRUNCATED"
        );

        let third = layout(&root, "run-three");
        third.create(&plan("run-three")).unwrap();
        let foreign = CancellationRequest {
            schema: CANCELLATION_SCHEMA.into(),
            run_id: "run-four".into(),
            requested_at: "now".into(),
            requested_by: "admin".into(),
        };
        fs::write(
            third.cancellation_path(),
            serde_json::to_vec(&foreign).unwrap(),
        )
        .unwrap();
        assert_eq!(
            third.recovery_status().unwrap_err().code.as_ref(),
            "AIW_ARTIFACT_UNJOURNALED"
        );
        let file = OpenOptions::new()
            .write(true)
            .open(third.plan_path())
            .unwrap();
        file.set_len(MAX_ARTIFACT + 1).unwrap();
        assert_eq!(
            third.read_plan().unwrap_err().code.as_ref(),
            "AIW_ARTIFACT_TOO_LARGE"
        );

        let fourth = layout(&root, "run-four");
        fourth.create(&plan("run-four")).unwrap();
        let foreign = CancellationRequest {
            schema: CANCELLATION_SCHEMA.into(),
            run_id: "run-five".into(),
            requested_at: "now".into(),
            requested_by: "admin".into(),
        };
        {
            let _lock = fourth.acquire_lock().unwrap();
            let hash = hash_value(&foreign).unwrap();
            fourth
                .append_record(
                    artifact_event(
                        RunEventKind::CancellationIntent,
                        "now",
                        "foreign intent",
                        &hash,
                    )
                    .unwrap(),
                )
                .unwrap();
            write_complete_new(&fourth.cancellation_path(), &foreign, "run-four", "test").unwrap();
        }
        assert_eq!(
            fourth.recovery_status().unwrap_err().code.as_ref(),
            "AIW_RUN_ID_MISMATCH"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn reparse_workspace_is_rejected_when_symlinks_are_available() {
        use std::os::windows::fs::symlink_dir;
        let root = root();
        let link = root.with_extension("link");
        if symlink_dir(&root, &link).is_ok() {
            assert!(RunLayout::new(&link, "run-one").is_err());
            fs::remove_dir(&link).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
}
