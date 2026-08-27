//! File-backed, non-executing orchestration primitives.
//!
//! This crate deliberately persists intent and receipts only. It cannot start
//! providers, elevate, or execute an application.

#![forbid(unsafe_code)]

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Component, Path, PathBuf},
};

use aiw_evidence::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RUN_PLAN_SCHEMA: &str = "aiw.dev/run-plan/v0alpha1";
const APPROVAL_SCHEMA: &str = "aiw.dev/approval-record/v0alpha1";
const EVENT_SCHEMA: &str = "aiw.dev/run-event/v0alpha1";
const JOURNAL_SCHEMA: &str = "aiw.dev/run-journal/v0alpha1";
const RESULT_SCHEMA: &str = "aiw.dev/run-result/v0alpha1";
const CANCELLATION_SCHEMA: &str = "aiw.dev/cancellation-request/v0alpha1";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_DETAIL_BYTES: usize = 4096;

/// The independent lifecycle a persisted run belongs to.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RunLifecycleKind {
    Assessment,
    Launch,
    Authoring,
}

/// A bounded, declarative action. It is deliberately not a command language.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
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

/// Immutable, hash-bound intent that must be approved before future runners act.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
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
        let plan = Self {
            schema: RUN_PLAN_SCHEMA.to_owned(),
            run_id: run_id.into(),
            project_id: project_id.into(),
            lifecycle,
            created_at: created_at.into(),
            actions,
            trust_deltas,
        };
        validate_plan(&plan)?;
        Ok(plan)
    }

    pub fn hash(&self) -> Result<String, AiwError> {
        validate_plan(self)?;
        hash_value(self)
    }
}

/// Approval is valid only for the exact immutable plan hash and displayed deltas.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
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
        let record = Self {
            schema: APPROVAL_SCHEMA.to_owned(),
            run_id: plan.run_id.clone(),
            plan_hash: plan.hash()?,
            trust_deltas: plan.trust_deltas.clone(),
            approved_by: approved_by.into(),
            approved_at: approved_at.into(),
        };
        validate_approval(&record, plan)?;
        Ok(record)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RunEventKind {
    Created,
    ApprovalRecorded,
    Progress,
    CancellationRequested,
    RecoveryObserved,
    TerminalRecorded,
}

/// Append-only event data. Detail is bounded, untrusted diagnostic text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunEvent {
    pub schema: String,
    pub kind: RunEventKind,
    pub occurred_at: String,
    pub detail: String,
}

impl RunEvent {
    pub fn new(
        kind: RunEventKind,
        occurred_at: impl Into<String>,
        detail: impl Into<String>,
    ) -> Result<Self, AiwError> {
        let event = Self {
            schema: EVENT_SCHEMA.to_owned(),
            kind,
            occurred_at: occurred_at.into(),
            detail: detail.into(),
        };
        validate_event(&event)?;
        Ok(event)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalRecord {
    pub schema: String,
    pub sequence: u64,
    pub previous_hash: String,
    pub event: RunEvent,
    pub hash: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RunOutcome {
    Succeeded,
    Failed,
    Cancelled,
    InsufficientEvidence,
}

/// A terminal receipt. It is write-once and does not imply execution provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
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
        let result = Self {
            schema: RESULT_SCHEMA.to_owned(),
            run_id: run_id.into(),
            outcome,
            completed_at: completed_at.into(),
            evidence_root,
            cleanup_complete,
            summary: summary.into(),
        };
        validate_result(&result)?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancellationRequest {
    pub schema: String,
    pub run_id: String,
    pub requested_at: String,
    pub requested_by: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
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

/// All paths for a run; identifiers are never accepted as paths.
#[derive(Clone, Debug)]
pub struct RunLayout {
    root: PathBuf,
    run_id: String,
}

impl RunLayout {
    pub fn new(root: impl AsRef<Path>, run_id: impl Into<String>) -> Result<Self, AiwError> {
        let run_id = run_id.into();
        validate_id("runId", &run_id)?;
        let root = root.as_ref().to_path_buf();
        if root.as_os_str().is_empty()
            || root
                .components()
                .any(|item| matches!(item, Component::ParentDir))
        {
            return Err(AiwError::new(
                "AIW_PATH_UNSAFE",
                "run root is not a safe path",
                "layout",
                Some(&run_id),
                false,
                "Use an absolute or workspace-relative root without parent traversal.",
                root.display().to_string(),
            ));
        }
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
    pub fn create(&self, plan: &RunPlan) -> Result<(), AiwError> {
        validate_plan(plan)?;
        if plan.run_id != self.run_id {
            return Err(run_error(
                "AIW_RUN_ID_MISMATCH",
                "plan does not belong to this run layout",
                "create",
                &self.run_id,
            ));
        }
        fs::create_dir_all(self.root.join("runs")).map_err(|error| {
            io_error(
                "AIW_STORAGE_CREATE_FAILED",
                "could not create runs root",
                "create",
                &self.run_id,
                error,
            )
        })?;
        fs::create_dir(self.run_dir()).map_err(|error| {
            io_error(
                "AIW_RUN_ALREADY_EXISTS",
                "run directory already exists or cannot be created",
                "create",
                &self.run_id,
                error,
            )
        })?;
        if let Err(error) = write_json_new(&self.plan_path(), plan, &self.run_id, "create") {
            let _ = fs::remove_dir(self.run_dir());
            return Err(error);
        }
        if let Err(error) = write_empty_new(&self.journal_path(), &self.run_id, "create") {
            let _ = fs::remove_dir_all(self.run_dir());
            return Err(error);
        }
        self.append_event(RunEvent::new(
            RunEventKind::Created,
            plan.created_at.clone(),
            "run plan persisted",
        )?)
        .map(|_| ())
    }
    pub fn read_plan(&self) -> Result<RunPlan, AiwError> {
        read_json(&self.plan_path(), &self.run_id, "plan").and_then(|plan: RunPlan| {
            validate_plan(&plan)?;
            if plan.run_id == self.run_id {
                Ok(plan)
            } else {
                Err(run_error(
                    "AIW_RUN_ID_MISMATCH",
                    "persisted plan belongs to another run",
                    "plan",
                    &self.run_id,
                ))
            }
        })
    }
    pub fn write_approval(&self, approval: &ApprovalRecord) -> Result<(), AiwError> {
        let plan = self.read_plan()?;
        validate_approval(approval, &plan)?;
        write_json_new(&self.approval_path(), approval, &self.run_id, "approval")?;
        self.append_event(RunEvent::new(
            RunEventKind::ApprovalRecorded,
            approval.approved_at.clone(),
            "approval persisted",
        )?)
        .map(|_| ())
    }
    pub fn read_approval(&self) -> Result<ApprovalRecord, AiwError> {
        let plan = self.read_plan()?;
        let approval = read_json(&self.approval_path(), &self.run_id, "approval")?;
        validate_approval(&approval, &plan)?;
        Ok(approval)
    }
    pub fn append_event(&self, event: RunEvent) -> Result<JournalRecord, AiwError> {
        validate_event(&event)?;
        if !self.journal_path().is_file() {
            return Err(run_error(
                "AIW_JOURNAL_MISSING",
                "run journal is missing or is not a regular file",
                "journal",
                &self.run_id,
            ));
        }
        let records = self.replay_journal()?;
        let sequence = records.last().map_or(1, |last| last.sequence + 1);
        let previous_hash = records
            .last()
            .map_or_else(|| ZERO_HASH.to_owned(), |last| last.hash.clone());
        let mut record = JournalRecord {
            schema: JOURNAL_SCHEMA.to_owned(),
            sequence,
            previous_hash,
            event,
            hash: String::new(),
        };
        record.hash = journal_hash(&record)?;
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| serialization_error("journal", &self.run_id, error))?;
        let mut file = OpenOptions::new()
            .append(true)
            .open(self.journal_path())
            .map_err(|error| {
                io_error(
                    "AIW_JOURNAL_APPEND_FAILED",
                    "could not append run journal",
                    "journal",
                    &self.run_id,
                    error,
                )
            })?;
        file.write_all(&bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_data())
            .map_err(|error| {
                io_error(
                    "AIW_JOURNAL_APPEND_FAILED",
                    "could not persist run journal",
                    "journal",
                    &self.run_id,
                    error,
                )
            })?;
        Ok(record)
    }
    pub fn replay_journal(&self) -> Result<Vec<JournalRecord>, AiwError> {
        let path = self.journal_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&path).map_err(|error| {
            io_error(
                "AIW_JOURNAL_READ_FAILED",
                "could not read run journal",
                "journal",
                &self.run_id,
                error,
            )
        })?;
        let mut records = Vec::new();
        for (line_number, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(|error| {
                io_error(
                    "AIW_JOURNAL_READ_FAILED",
                    "could not read run journal",
                    "journal",
                    &self.run_id,
                    error,
                )
            })?;
            if line.is_empty() {
                return Err(AiwError::new(
                    "AIW_JOURNAL_INVALID",
                    "run journal contains an unexpected blank record",
                    "journal",
                    Some(&self.run_id),
                    false,
                    "Do not modify run journal files; recover from an intact run.",
                    format!("line {}", line_number + 1),
                ));
            }
            let record: JournalRecord = serde_json::from_str(&line).map_err(|error| {
                AiwError::new(
                    "AIW_JOURNAL_INVALID",
                    "run journal contains invalid JSON",
                    "journal",
                    Some(&self.run_id),
                    false,
                    "Do not modify run journal files; recover from an intact run.",
                    format!("line {}: {error}", line_number + 1),
                )
            })?;
            verify_journal_record(&record, records.last(), &self.run_id)?;
            records.push(record);
        }
        Ok(records)
    }
    pub fn request_cancellation(
        &self,
        requested_by: impl Into<String>,
        requested_at: impl Into<String>,
    ) -> Result<CancellationRequest, AiwError> {
        if self.result_path().exists() {
            return Err(run_error(
                "AIW_RUN_TERMINAL",
                "cannot cancel a terminal run",
                "cancel",
                &self.run_id,
            ));
        }
        let request = CancellationRequest {
            schema: CANCELLATION_SCHEMA.to_owned(),
            run_id: self.run_id.clone(),
            requested_at: requested_at.into(),
            requested_by: requested_by.into(),
        };
        validate_cancellation(&request)?;
        write_json_new(&self.cancellation_path(), &request, &self.run_id, "cancel")?;
        self.append_event(RunEvent::new(
            RunEventKind::CancellationRequested,
            request.requested_at.clone(),
            "cancellation requested",
        )?)?;
        Ok(request)
    }
    pub fn write_result(&self, result: &RunResult) -> Result<(), AiwError> {
        validate_result(result)?;
        if result.run_id != self.run_id {
            return Err(run_error(
                "AIW_RUN_ID_MISMATCH",
                "result does not belong to this run layout",
                "result",
                &self.run_id,
            ));
        }
        write_json_new(&self.result_path(), result, &self.run_id, "result")?;
        self.append_event(RunEvent::new(
            RunEventKind::TerminalRecorded,
            result.completed_at.clone(),
            "terminal result persisted",
        )?)?;
        Ok(())
    }
    pub fn read_result(&self) -> Result<RunResult, AiwError> {
        let result = read_json(&self.result_path(), &self.run_id, "result")?;
        validate_result(&result)?;
        if result.run_id == self.run_id {
            Ok(result)
        } else {
            Err(run_error(
                "AIW_RUN_ID_MISMATCH",
                "persisted result belongs to another run",
                "result",
                &self.run_id,
            ))
        }
    }
    pub fn recovery_status(&self) -> Result<RecoveryStatus, AiwError> {
        let plan = self.read_plan()?;
        if !self.journal_path().is_file() {
            return Err(run_error(
                "AIW_JOURNAL_MISSING",
                "run journal is missing or is not a regular file",
                "recovery",
                &self.run_id,
            ));
        }
        let journal = self.replay_journal()?;
        if self.result_path().exists() {
            return Ok(RecoveryStatus::Terminal {
                result: self.read_result()?,
                last_sequence: journal.last().map(|record| record.sequence).unwrap_or(0),
            });
        }
        if self.cancellation_path().exists() {
            let request: CancellationRequest =
                read_json(&self.cancellation_path(), &self.run_id, "cancel")?;
            validate_cancellation(&request)?;
            return Ok(RecoveryStatus::CancellationRequested {
                request,
                last_sequence: journal.last().map(|record| record.sequence).unwrap_or(0),
            });
        }
        if self.approval_path().exists() {
            return Ok(RecoveryStatus::Ready {
                approval: self.read_approval()?,
                last_sequence: journal.last().map(|record| record.sequence).unwrap_or(0),
            });
        }
        Ok(RecoveryStatus::PendingApproval {
            plan_hash: plan.hash()?,
            last_sequence: journal.last().map(|record| record.sequence).unwrap_or(0),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    if plan.actions.is_empty() {
        return Err(run_error(
            "AIW_PLAN_EMPTY",
            "run plan must contain at least one typed action",
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
    }
    for delta in &plan.trust_deltas {
        validate_text("trustDelta", delta, &plan.run_id)?;
    }
    Ok(())
}
fn validate_approval(approval: &ApprovalRecord, plan: &RunPlan) -> Result<(), AiwError> {
    if approval.schema != APPROVAL_SCHEMA {
        return Err(run_error(
            "AIW_APPROVAL_SCHEMA_UNSUPPORTED",
            "approval schema is unsupported",
            "approval",
            &plan.run_id,
        ));
    }
    if approval.run_id != plan.run_id
        || approval.plan_hash != plan.hash()?
        || approval.trust_deltas != plan.trust_deltas
    {
        return Err(run_error(
            "AIW_APPROVAL_PLAN_MISMATCH",
            "approval is not bound to the current plan",
            "approval",
            &plan.run_id,
        ));
    }
    validate_text("approvedBy", &approval.approved_by, &plan.run_id)?;
    validate_text("approvedAt", &approval.approved_at, &plan.run_id)
}
fn validate_event(event: &RunEvent) -> Result<(), AiwError> {
    if event.schema != EVENT_SCHEMA {
        return Err(AiwError::new(
            "AIW_EVENT_SCHEMA_UNSUPPORTED",
            "run event schema is unsupported",
            "journal",
            None,
            false,
            "Use the current event schema.",
            event.schema.clone(),
        ));
    }
    validate_text("occurredAt", &event.occurred_at, "")?;
    validate_text("detail", &event.detail, "")?;
    if event.detail.len() > MAX_DETAIL_BYTES {
        return Err(AiwError::new(
            "AIW_EVENT_DETAIL_TOO_LARGE",
            "run event detail exceeds its bound",
            "journal",
            None,
            false,
            "Store large diagnostics as a separate artifact.",
            event.detail.len().to_string(),
        ));
    }
    Ok(())
}
fn validate_result(result: &RunResult) -> Result<(), AiwError> {
    if result.schema != RESULT_SCHEMA {
        return Err(run_error(
            "AIW_RESULT_SCHEMA_UNSUPPORTED",
            "run result schema is unsupported",
            "result",
            &result.run_id,
        ));
    }
    validate_id("runId", &result.run_id)?;
    validate_text("completedAt", &result.completed_at, &result.run_id)?;
    validate_text("summary", &result.summary, &result.run_id)?;
    if let Some(hash) = &result.evidence_root {
        validate_hash(hash, "evidenceRoot", &result.run_id)?;
    }
    Ok(())
}
fn validate_cancellation(request: &CancellationRequest) -> Result<(), AiwError> {
    if request.schema != CANCELLATION_SCHEMA {
        return Err(run_error(
            "AIW_CANCELLATION_SCHEMA_UNSUPPORTED",
            "cancellation schema is unsupported",
            "cancel",
            &request.run_id,
        ));
    }
    validate_id("runId", &request.run_id)?;
    validate_text("requestedAt", &request.requested_at, &request.run_id)?;
    validate_text("requestedBy", &request.requested_by, &request.run_id)
}
fn validate_id(name: &str, value: &str) -> Result<(), AiwError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AiwError::new(
            "AIW_IDENTIFIER_INVALID",
            "identifier contains unsupported characters",
            "validation",
            None,
            false,
            "Use 1-128 ASCII letters, digits, hyphens, underscores, or dots.",
            format!("{name}: {value}"),
        ));
    }
    Ok(())
}
fn validate_text(name: &str, value: &str, run_id: &str) -> Result<(), AiwError> {
    if value.trim().is_empty() || value.len() > MAX_DETAIL_BYTES || value.contains('\0') {
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
fn validate_hash(hash: &str, name: &str, run_id: &str) -> Result<(), AiwError> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(AiwError::new(
            "AIW_HASH_INVALID",
            "hash must be lowercase SHA-256 hexadecimal",
            "validation",
            Some(run_id),
            false,
            "Use a lowercase 64-character SHA-256 hash.",
            name,
        ));
    }
    Ok(())
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
fn journal_hash(record: &JournalRecord) -> Result<String, AiwError> {
    hash_value(
        &serde_json::json!({ "schema": record.schema, "sequence": record.sequence, "previousHash": record.previous_hash, "event": record.event }),
    )
}
fn verify_journal_record(
    record: &JournalRecord,
    previous: Option<&JournalRecord>,
    run_id: &str,
) -> Result<(), AiwError> {
    if record.schema != JOURNAL_SCHEMA {
        return Err(run_error(
            "AIW_JOURNAL_SCHEMA_UNSUPPORTED",
            "run journal schema is unsupported",
            "journal",
            run_id,
        ));
    }
    validate_event(&record.event)?;
    let sequence = previous.map_or(1, |entry| entry.sequence + 1);
    let previous_hash = previous.map_or(ZERO_HASH, |entry| entry.hash.as_str());
    if record.sequence != sequence
        || record.previous_hash != previous_hash
        || journal_hash(record)? != record.hash
    {
        return Err(run_error(
            "AIW_JOURNAL_TAMPERED",
            "run journal sequence or hash chain is invalid",
            "journal",
            run_id,
        ));
    }
    Ok(())
}
fn write_json_new<T: Serialize>(
    path: &Path,
    value: &T,
    run_id: &str,
    stage: &str,
) -> Result<(), AiwError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| serialization_error(stage, run_id, error))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            io_error(
                "AIW_WRITE_ONCE_CONFLICT",
                "write-once run artifact already exists or cannot be created",
                stage,
                run_id,
                error,
            )
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_data())
        .map_err(|error| {
            io_error(
                "AIW_STORAGE_WRITE_FAILED",
                "could not persist run artifact",
                stage,
                run_id,
                error,
            )
        })
}

fn write_empty_new(path: &Path, run_id: &str, stage: &str) -> Result<(), AiwError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|file| {
            file.sync_data()?;
            Ok(())
        })
        .map_err(|error| {
            io_error(
                "AIW_STORAGE_WRITE_FAILED",
                "could not create run journal",
                stage,
                run_id,
                error,
            )
        })
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    run_id: &str,
    stage: &str,
) -> Result<T, AiwError> {
    let bytes = fs::read(path).map_err(|error| {
        io_error(
            "AIW_STORAGE_READ_FAILED",
            "could not read run artifact",
            stage,
            run_id,
            error,
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        AiwError::new(
            "AIW_STORAGE_INVALID",
            "run artifact contains invalid JSON",
            stage,
            Some(run_id),
            false,
            "Do not modify persisted run artifacts; recover from an intact run.",
            error.to_string(),
        )
    })
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
        "Inspect the run directory and retry only when the condition is resolved.",
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
        Some(run_id),
        false,
        "Inspect the persisted run state before retrying.",
        "",
    )
}
fn limit_detail(mut detail: String) -> String {
    detail.truncate(MAX_DETAIL_BYTES);
    detail
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(1);
    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "aiw-orchestrator-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        root
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
                    scenario_id: "install".to_owned(),
                },
            ],
            vec!["provider starts a disposable environment".to_owned()],
        )
        .unwrap()
    }
    fn layout(root: &Path, run_id: &str) -> RunLayout {
        RunLayout::new(root, run_id).unwrap()
    }
    #[test]
    fn plan_hash_is_canonical_and_changes_on_content() {
        let left = plan("run-one");
        let mut right = left.clone();
        assert_eq!(left.hash().unwrap(), right.hash().unwrap());
        right.actions.push(PlannedAction::CollectEvidence);
        assert_ne!(left.hash().unwrap(), right.hash().unwrap());
    }
    #[test]
    fn create_approval_and_recovery_are_persisted() {
        let root = temp_root();
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
        let approval = ApprovalRecord::for_plan(&plan, "admin", "2026-08-27T00:01:00Z").unwrap();
        layout.write_approval(&approval).unwrap();
        assert!(matches!(
            layout.recovery_status().unwrap(),
            RecoveryStatus::Ready {
                last_sequence: 2,
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn tampered_plan_invalidates_approval() {
        let root = temp_root();
        let layout = layout(&root, "run-one");
        let plan = plan("run-one");
        layout.create(&plan).unwrap();
        layout
            .write_approval(&ApprovalRecord::for_plan(&plan, "admin", "now").unwrap())
            .unwrap();
        let mut changed = plan.clone();
        changed.actions.push(PlannedAction::CollectEvidence);
        fs::write(layout.plan_path(), serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_eq!(
            layout.read_approval().unwrap_err().code.as_ref(),
            "AIW_APPROVAL_PLAN_MISMATCH"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn journal_replay_rejects_gaps_and_tampering() {
        let root = temp_root();
        let layout = layout(&root, "run-one");
        layout.create(&plan("run-one")).unwrap();
        layout
            .append_event(RunEvent::new(RunEventKind::Progress, "now", "one").unwrap())
            .unwrap();
        let mut records = layout.replay_journal().unwrap();
        records[1].sequence = 3;
        fs::write(
            layout.journal_path(),
            records
                .into_iter()
                .map(|record| serde_json::to_string(&record).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        assert_eq!(
            layout.replay_journal().unwrap_err().code.as_ref(),
            "AIW_JOURNAL_TAMPERED"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn result_is_write_once() {
        let root = temp_root();
        let layout = layout(&root, "run-one");
        layout.create(&plan("run-one")).unwrap();
        let result = RunResult::new(
            "run-one",
            RunOutcome::Succeeded,
            "now",
            Some("a".repeat(64)),
            true,
            "done",
        )
        .unwrap();
        layout.write_result(&result).unwrap();
        assert_eq!(
            layout.write_result(&result).unwrap_err().code.as_ref(),
            "AIW_WRITE_ONCE_CONFLICT"
        );
        assert!(matches!(
            layout.recovery_status().unwrap(),
            RecoveryStatus::Terminal { .. }
        ));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn cancellation_is_write_once_and_terminal_runs_cannot_be_cancelled() {
        let root = temp_root();
        let layout = layout(&root, "run-one");
        layout.create(&plan("run-one")).unwrap();
        layout.request_cancellation("admin", "now").unwrap();
        assert_eq!(
            layout
                .request_cancellation("admin", "later")
                .unwrap_err()
                .code
                .as_ref(),
            "AIW_WRITE_ONCE_CONFLICT"
        );
        assert!(matches!(
            layout.recovery_status().unwrap(),
            RecoveryStatus::CancellationRequested { .. }
        ));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unsafe_run_ids_and_roots_are_rejected() {
        assert!(RunLayout::new("safe", "../escape").is_err());
        assert!(RunLayout::new("../unsafe", "run-one").is_err());
        assert!(
            RunPlan::new(
                "run-one",
                "project",
                RunLifecycleKind::Launch,
                "now",
                vec![PlannedAction::LaunchValidatedProfile {
                    profile_id: "../../bad".to_owned()
                }],
                vec![]
            )
            .is_err()
        );
    }
    #[test]
    fn invalid_or_forged_journal_hash_is_rejected() {
        let root = temp_root();
        let layout = layout(&root, "run-one");
        layout.create(&plan("run-one")).unwrap();
        let mut records = layout.replay_journal().unwrap();
        records[0].event.detail = "forged".to_owned();
        fs::write(
            layout.journal_path(),
            serde_json::to_vec(&records[0]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            layout.replay_journal().unwrap_err().code.as_ref(),
            "AIW_JOURNAL_TAMPERED"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_rejects_a_missing_or_blank_journal() {
        {
            let root = temp_root();
            let layout = layout(&root, "run-one");
            layout.create(&plan("run-one")).unwrap();
            fs::remove_file(layout.journal_path()).unwrap();
            assert_eq!(
                layout.recovery_status().unwrap_err().code.as_ref(),
                "AIW_JOURNAL_MISSING"
            );
            fs::remove_dir_all(root).unwrap();
        }

        let root = temp_root();
        let layout = layout(&root, "run-one");
        layout.create(&plan("run-one")).unwrap();
        fs::write(layout.journal_path(), b"\n").unwrap();
        assert_eq!(
            layout.replay_journal().unwrap_err().code.as_ref(),
            "AIW_JOURNAL_INVALID"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
