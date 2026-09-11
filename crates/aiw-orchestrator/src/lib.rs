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
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
#[cfg(windows)]
use std::{
    thread,
    time::{Duration, Instant},
};

use aiw_evidence::canonical_json_bytes;
use aiw_probe::{
    DISCARD_INTENT_BINDING_POLICY_VERSION, DISCARD_INTENT_BINDING_SCHEMA_VERSION,
    DiscardIntentBindingEvidence, DiscardIntentStableId, WSB_FIXED_TREE_CONTRACT_VERSION,
    WorkspaceBindingEvidence, WsbFixedTreeInventoryEvidence,
};
use aiw_schema::Project;
#[cfg(windows)]
use aiw_windows_platform::{
    BoundWorkspaceDirectory, HeldDiscardIntentPublication, HeldRunWorkspace, RunCoordinationError,
    RunCoordinationKey, RunCoordinationLease, RunCoordinationMode, WorkspaceAclPolicy,
    try_acquire_run_coordination,
};
use fs4::FileExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RUN_PLAN_SCHEMA_VERSION: &str = "aiw.dev/run-plan/v0alpha3";
pub const IMPORTED_MSI_RUN_PLAN_SCHEMA_VERSION: &str = "aiw.dev/run-plan/v0alpha4";
pub const IMPORTED_BAMBU_RUN_PLAN_SCHEMA_VERSION: &str = "aiw.dev/run-plan/v0alpha5";
pub const LEGACY_RUN_PLAN_SCHEMA_VERSION: &str = "aiw.dev/run-plan/v0alpha1";
const APPROVAL_SCHEMA: &str = "aiw.dev/approval-record/v0alpha1";
const EVENT_SCHEMA: &str = "aiw.dev/run-event/v0alpha1";
const JOURNAL_SCHEMA: &str = "aiw.dev/run-journal/v0alpha1";
const HEAD_SCHEMA: &str = "aiw.dev/run-journal-head/v0alpha1";
const RESULT_SCHEMA: &str = "aiw.dev/run-result/v0alpha1";
const CANCELLATION_SCHEMA: &str = "aiw.dev/cancellation-request/v0alpha1";
pub const WSB_REVOCATION_SCHEMA_VERSION: &str = "aiw.dev/wsb-revocation-record/v0alpha2";
pub const WSB_DISCARD_CHECKPOINT_SCHEMA_VERSION: &str = "aiw.dev/wsb-discard-checkpoint/v0alpha1";
pub const WSB_DISCARD_CHECKPOINT_POLICY_VERSION: &str = "owner-system-protected-checkpoint-v1";
const WSB_DISCARD_CURRENT_PREFIX: &str = ".aiw-discard-v1-";
const WSB_DISCARD_STAGE_PREFIX: &str = ".aiw-discard-stage-v1-";
const MAX_DISCARD_INTENT_BYTES: u64 = 1024 * 1024;
pub const WSB_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION: &str =
    "aiw.dev/wsb-planning-import-receipt/v0alpha1";
pub const WSB_MSI_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION: &str =
    "aiw.dev/wsb-planning-import-receipt/v0alpha2";
pub const WSB_BAMBU_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION: &str =
    "aiw.dev/wsb-planning-import-receipt/v0alpha3";
const WSB_PLANNING_IMPORT_FILE: &str = "wsb-planning-import.json";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_TEXT: usize = 4096;
const MAX_ARTIFACT: u64 = 1024 * 1024;
const MAX_JOURNAL: u64 = 64 * 1024 * 1024;
const MAX_LINE: usize = 16 * 1024;
const MAX_ITEMS: usize = 256;
const MAX_RECORDS: usize = 100_000;
const MAX_CREATE_STAGE_ATTEMPTS: usize = 32;
#[cfg(windows)]
const RUN_COORDINATION_DEADLINE: Duration = Duration::from_secs(30);
#[cfg(windows)]
const RUN_COORDINATION_POLL: Duration = Duration::from_millis(10);
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
    ExecuteScenario {
        scenario_id: String,
    },
    /// The only W1 mutating provider action. All executable and configuration
    /// identities are SHA-256 bound into the immutable, separately approved
    /// run plan; callers cannot attach arbitrary commands or policy text.
    ExecuteWindowsSandboxGoldenProbe {
        sandbox_plan_sha256: String,
        provider_sha256: String,
        guest_agent_sha256: String,
        workspace: Box<WorkspaceBindingEvidence>,
        workspace_identity_sha256: String,
    },
    ExecuteWindowsSandboxImportedMsiScenario {
        sandbox_plan_sha256: String,
        provider_sha256: String,
        guest_agent_sha256: String,
        workspace: Box<WorkspaceBindingEvidence>,
        workspace_identity_sha256: String,
        import_receipt_sha256: String,
        application_sha256: String,
        scenario_sha256: String,
    },
    ExecuteWindowsSandboxImportedBambuScenario {
        sandbox_plan_sha256: String,
        provider_sha256: String,
        guest_agent_sha256: String,
        workspace: Box<WorkspaceBindingEvidence>,
        workspace_identity_sha256: String,
        import_receipt_sha256: String,
        application_sha256: String,
        scenario_sha256: String,
    },
    CollectEvidence,
    LaunchValidatedProfile {
        profile_id: String,
    },
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
    pub project_revision_hash: String,
    pub lifecycle: RunLifecycleKind,
    pub created_at: String,
    pub actions: Vec<PlannedAction>,
    #[serde(default)]
    pub trust_deltas: Vec<String>,
}

/// The original unbound plan wire shape, retained for schema publication only.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyRunPlanV0Alpha1 {
    pub schema: String,
    pub run_id: String,
    pub project_id: String,
    pub lifecycle: RunLifecycleKind,
    pub created_at: String,
    pub actions: Vec<LegacyPlannedActionV0Alpha2>,
    pub trust_deltas: Vec<String>,
}

/// The first project-revision-bound plan contract. It remains available for
/// offline inspection, but provider mutation requires a newly approved v0alpha3
/// plan containing the complete workspace identity document.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyRunPlanV0Alpha2 {
    pub schema: String,
    pub run_id: String,
    pub project_id: String,
    pub project_revision_hash: String,
    pub lifecycle: RunLifecycleKind,
    pub created_at: String,
    pub actions: Vec<LegacyPlannedActionV0Alpha2>,
    #[serde(default)]
    pub trust_deltas: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum LegacyPlannedActionV0Alpha2 {
    AssessHost,
    PrepareWorkspace,
    ExecuteScenario {
        scenario_id: String,
    },
    ExecuteWindowsSandboxGoldenProbe {
        sandbox_plan_sha256: String,
        provider_sha256: String,
        guest_agent_sha256: String,
    },
    CollectEvidence,
    LaunchValidatedProfile {
        profile_id: String,
    },
    AuthorPackage,
    InspectPackage,
    SignPackage,
    ValidatePackage,
}

impl RunPlan {
    pub fn new(
        run_id: impl Into<String>,
        project_id: impl Into<String>,
        project_revision_hash: impl Into<String>,
        lifecycle: RunLifecycleKind,
        created_at: impl Into<String>,
        actions: Vec<PlannedAction>,
        trust_deltas: Vec<String>,
    ) -> Result<Self, AiwError> {
        let value = Self {
            schema: if actions.iter().any(|action| {
                matches!(
                    action,
                    PlannedAction::ExecuteWindowsSandboxImportedBambuScenario { .. }
                )
            }) {
                IMPORTED_BAMBU_RUN_PLAN_SCHEMA_VERSION.into()
            } else if actions.iter().any(|action| {
                matches!(
                    action,
                    PlannedAction::ExecuteWindowsSandboxImportedMsiScenario { .. }
                )
            }) {
                IMPORTED_MSI_RUN_PLAN_SCHEMA_VERSION.into()
            } else {
                RUN_PLAN_SCHEMA_VERSION.into()
            },
            run_id: run_id.into(),
            project_id: project_id.into(),
            project_revision_hash: project_revision_hash.into(),
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

    /// Parses only the current mutation-capable plan contract. Legacy plans
    /// remain separately readable for inspection and fail closed here.
    pub fn from_value(value: serde_json::Value) -> Result<Self, AiwError> {
        let schema = value.get("schema").and_then(serde_json::Value::as_str);
        if !matches!(
            schema,
            Some(RUN_PLAN_SCHEMA_VERSION)
                | Some(IMPORTED_MSI_RUN_PLAN_SCHEMA_VERSION)
                | Some(IMPORTED_BAMBU_RUN_PLAN_SCHEMA_VERSION)
        ) {
            return Err(run_error(
                "AIW_PLAN_SCHEMA_UNSUPPORTED",
                "run plan schema is unsupported for mutation and must be replanned",
                "plan",
                value
                    .get("runId")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
            ));
        }
        let plan: Self = serde_json::from_value(value)
            .map_err(|error| serialization_error("plan", "", error))?;
        validate_plan(&plan)?;
        Ok(plan)
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
    RevocationIntent,
    RevocationRecorded,
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
pub struct WsbRevocationRecord {
    pub schema_version: String,
    pub run_id: String,
    pub cleanup_id: String,
    pub discard_intent_sha256: String,
    pub discard_intent_binding: DiscardIntentBindingEvidence,
    pub plan_sha256: String,
    pub import_receipt_sha256: String,
    pub workspace_identity_sha256: String,
    pub requested_by: String,
    pub requested_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbDiscardCheckpointFileIdentity {
    pub parent_id: DiscardIntentStableId,
    pub file_id: DiscardIntentStableId,
}

/// Cycle-free external commit binding the immutable revocation record to one
/// exact portable observation of the pre-disposal 19-object tree.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbDiscardCheckpointV0Alpha1 {
    pub schema_version: String,
    pub policy_version: String,
    pub run_id: String,
    pub cleanup_id: String,
    pub fixed_tree_contract_version: String,
    pub revocation: WsbRevocationRecord,
    pub revocation_sha256: String,
    pub inventory: WsbFixedTreeInventoryEvidence,
    pub inventory_sha256: String,
    pub checkpoint_file: WsbDiscardCheckpointFileIdentity,
}

impl WsbDiscardCheckpointV0Alpha1 {
    pub fn validate(&self) -> Result<(), AiwError> {
        let revocation = &self.revocation;
        let inventory = &self.inventory;
        let binding = &revocation.discard_intent_binding;
        let valid_ids = [
            &self.checkpoint_file.parent_id,
            &self.checkpoint_file.file_id,
        ]
        .into_iter()
        .all(|id| {
            is_fixed_lower_hex(&id.volume_serial_number, 16) && is_fixed_lower_hex(&id.file_id, 32)
        });
        let checkpoint_leaf_matches = Path::new(&binding.final_path)
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .is_some_and(|leaf| {
                leaf == format!("{WSB_DISCARD_CURRENT_PREFIX}{}", binding.store_key)
            });
        let checkpoint_id_is_external = inventory.objects.iter().all(|object| {
            object.id != self.checkpoint_file.file_id && object.id != self.checkpoint_file.parent_id
        });
        let revocation_hashes_are_valid = [
            revocation.discard_intent_sha256.as_str(),
            revocation.plan_sha256.as_str(),
            revocation.import_receipt_sha256.as_str(),
            revocation.workspace_identity_sha256.as_str(),
            self.revocation_sha256.as_str(),
            self.inventory_sha256.as_str(),
        ]
        .into_iter()
        .all(|hash| is_fixed_lower_hex(hash, 64));
        let expected_control = Path::new(&inventory.workspace.parent.final_path)
            .join(format!("{WSB_DISCARD_CURRENT_PREFIX}{}", binding.store_key));
        validate_wsb_revocation_shape(revocation, &inventory.workspace, &expected_control)?;
        let valid = self.schema_version == WSB_DISCARD_CHECKPOINT_SCHEMA_VERSION
            && self.policy_version == WSB_DISCARD_CHECKPOINT_POLICY_VERSION
            && self.fixed_tree_contract_version == WSB_FIXED_TREE_CONTRACT_VERSION
            && revocation.schema_version == WSB_REVOCATION_SCHEMA_VERSION
            && inventory.validate().is_ok()
            && self.run_id == revocation.run_id
            && self.run_id == inventory.run_id
            && self.cleanup_id == revocation.cleanup_id
            && is_fixed_lower_hex(&self.cleanup_id, 64)
            && inventory.tombstone_leaf == format!(".aiw-discarded-v1-{}", self.cleanup_id)
            && self.revocation_sha256 == hash_value(revocation)?
            && self.inventory_sha256 == hash_value(inventory)?
            && revocation.discard_intent_sha256 == binding.intent_sha256
            && binding.schema_version == DISCARD_INTENT_BINDING_SCHEMA_VERSION
            && binding.policy_version == DISCARD_INTENT_BINDING_POLICY_VERSION
            && binding.run_id == self.run_id
            && binding.owner_sid == inventory.workspace.owner_sid
            && binding.store_key.len() == 64
            && is_fixed_lower_hex(&binding.store_key, 64)
            && checkpoint_leaf_matches
            && inventory.workspace.parent.volume_serial_number
                == self.checkpoint_file.parent_id.volume_serial_number
            && inventory.workspace.parent.file_id == self.checkpoint_file.parent_id.file_id
            && binding.parent_id == self.checkpoint_file.parent_id
            && self.checkpoint_file.file_id.volume_serial_number
                == self.checkpoint_file.parent_id.volume_serial_number
            && self.checkpoint_file.file_id != self.checkpoint_file.parent_id
            && checkpoint_id_is_external
            && revocation.workspace_identity_sha256 == hash_value(&inventory.workspace)?
            && revocation_hashes_are_valid
            && valid_ids;
        if !valid {
            return Err(run_error(
                "AIW_WSB_DISCARD_CHECKPOINT_INVALID",
                "protected discard checkpoint bindings are invalid",
                "checkpoint",
                &self.run_id,
            ));
        }
        Ok(())
    }
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
    #[cfg(windows)]
    coordination_key: RunCoordinationKey,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum PendingRunDisposition {
    Created,
    AlreadyPresent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum WsbPlanningImportStatus {
    PendingApproval,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbPlanningImportReceipt {
    pub schema_version: String,
    pub run_id: String,
    pub imported_at: String,
    pub status: WsbPlanningImportStatus,
    pub project_revision_sha256: String,
    pub workspace_root: String,
    pub workspace_identity_sha256: String,
    pub preparation_receipt_sha256: String,
    pub run_plan_sha256: String,
    pub windows_sandbox_plan_sha256: String,
    pub guest_agent_sha256: String,
    pub provider_sha256: String,
    pub run_root: String,
    pub journal_sequence: u64,
    pub approval_present: bool,
    pub provider_acquired: bool,
    pub provider_mutated: bool,
}

impl WsbPlanningImportReceipt {
    pub fn validate_for_plan(&self, plan: &RunPlan) -> Result<(), AiwError> {
        validate_wsb_import(self, plan)
    }
}

struct RunLock {
    #[cfg(windows)]
    _coordination: RunCoordinationLease,
    _inner_file: Option<File>,
}

#[derive(Clone, Copy)]
enum RunLockPurpose {
    Ordinary,
    InspectDiscardState,
}

/// Opaque authority that keeps the run lock held across external discard-
/// intent publication and internal revocation recording.
#[doc(hidden)]
pub struct WsbRevocationGuard<'a> {
    layout: &'a RunLayout,
    _lock: RunLock,
    plan: RunPlan,
    import: WsbPlanningImportReceipt,
    recoverable_revocation: Option<WsbRevocationRecord>,
    committed_revocation: Option<WsbRevocationRecord>,
}

/// Opaque two-phase revocation authority. It holds coordination and the run
/// lock while the runner reopens the independently receipt-bound workspace.
#[cfg(windows)]
#[doc(hidden)]
pub struct WsbRevocationLease<'a> {
    layout: &'a RunLayout,
    lock: RunLock,
}

#[cfg(windows)]
impl<'a> WsbRevocationLease<'a> {
    pub fn begin_bound(
        self,
        workspace: &HeldRunWorkspace,
    ) -> Result<WsbRevocationGuard<'a>, AiwError> {
        self.layout
            .revalidate_bound_workspace(workspace, "revocation")?;
        self.layout.begin_wsb_revocation_locked(
            self.lock,
            |layout| layout.repair_revocation_journal_bound_locked(workspace),
            |layout, revocation, hash| {
                layout.publish_wsb_revocation_artifact_bound_locked(workspace, revocation, hash)
            },
        )
    }
}

/// Opaque post-publication authority. It retains the owner-scoped outer
/// coordination lease and exact external intent handle; no descendant
/// workspace handle remains reachable.
#[cfg(windows)]
#[doc(hidden)]
pub struct WsbOuterDiscardAuthority<'a> {
    layout: &'a RunLayout,
    revocation: WsbRevocationRecord,
    publication: HeldDiscardIntentPublication,
    _coordination: RunCoordinationLease,
}

impl<'a> WsbRevocationGuard<'a> {
    pub fn control_path(&self) -> Result<PathBuf, AiwError> {
        self.layout.wsb_discard_control_path()
    }

    pub fn plan(&self) -> &RunPlan {
        &self.plan
    }

    pub fn import_receipt(&self) -> &WsbPlanningImportReceipt {
        &self.import
    }

    pub fn committed_revocation(&self) -> Option<&WsbRevocationRecord> {
        self.committed_revocation.as_ref()
    }

    /// Returns a strictly validated durable binding that can be resumed after
    /// a crash, even when its journal commit has not yet been recorded.
    pub fn recoverable_revocation(&self) -> Option<&WsbRevocationRecord> {
        self.recoverable_revocation.as_ref()
    }

    pub fn persist_staged_revocation(
        &mut self,
        revocation: &WsbRevocationRecord,
    ) -> Result<(), AiwError> {
        self.layout
            .write_wsb_revocation_locked(&self.plan, &self.import, revocation)?;
        self.recoverable_revocation = Some(revocation.clone());
        self.committed_revocation = Some(revocation.clone());
        Ok(())
    }

    /// Persist a Windows Sandbox revocation through the held preparation
    /// workspace.  The caller must supply the same live workspace authority
    /// that was used to import this run; a path-only reopening is never used
    /// for the revocation or its journal heads.
    #[cfg(windows)]
    pub fn persist_staged_revocation_bound(
        &mut self,
        workspace: &HeldRunWorkspace,
        revocation: &WsbRevocationRecord,
    ) -> Result<(), AiwError> {
        self.layout.write_wsb_revocation_artifact_bound_locked(
            workspace,
            &self.plan,
            &self.import,
            revocation,
        )?;
        self.recoverable_revocation = Some(revocation.clone());
        self.committed_revocation = Some(revocation.clone());
        Ok(())
    }

    #[cfg(windows)]
    pub fn into_outer_only(
        self,
        publication: HeldDiscardIntentPublication,
    ) -> Result<WsbOuterDiscardAuthority<'a>, AiwError> {
        let revocation = self.committed_revocation.ok_or_else(|| {
            run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "outer-only authority requires committed revocation",
                "revocation",
                &self.layout.run_id,
            )
        })?;
        if publication.evidence() != &revocation.discard_intent_binding
            || !same_path_text(
                publication.final_path(),
                &self.layout.wsb_discard_control_path()?.to_string_lossy(),
            )
            || !self.layout.current_discard_control_present()?
        {
            return Err(run_error(
                "AIW_WSB_DISCARD_AUTHORITY_MISSING",
                "published discard authority does not match committed revocation",
                "revocation",
                &self.layout.run_id,
            ));
        }
        let RunLock {
            _coordination,
            _inner_file,
        } = self._lock;
        drop(_inner_file);
        Ok(WsbOuterDiscardAuthority {
            layout: self.layout,
            revocation,
            publication,
            _coordination,
        })
    }

    #[cfg(all(test, windows))]
    fn release_inner_lock_for_test(&mut self) {
        self._lock._inner_file.take();
    }
}

#[cfg(windows)]
impl WsbOuterDiscardAuthority<'_> {
    pub fn run_id(&self) -> &str {
        self.layout.run_id()
    }

    pub fn revocation(&self) -> &WsbRevocationRecord {
        &self.revocation
    }

    pub fn revalidate_external_intent(&self) -> Result<(), AiwError> {
        self.publication.revalidate().map_err(|_error| {
            run_error(
                "AIW_WSB_DISCARD_AUTHORITY_MISSING",
                "published discard authority no longer matches committed revocation",
                "revocation",
                self.run_id(),
            )
        })
    }
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
        #[cfg(windows)]
        let coordination_key = RunCoordinationKey::from_existing_root(&root, &run_id)
            .map_err(|error| coordination_error("layout", &run_id, error))?;
        Ok(Self {
            root,
            run_id,
            #[cfg(windows)]
            coordination_key,
        })
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
    pub fn wsb_planning_import_path(&self) -> PathBuf {
        self.run_dir().join(WSB_PLANNING_IMPORT_FILE)
    }
    pub fn wsb_revocation_path(&self) -> PathBuf {
        self.run_dir().join("wsb-revocation.json")
    }
    /// Deterministic external cleanup-control location. Presence is a
    /// permanent fail-closed approval gate; content is validated by the WSB
    /// discard service rather than by ordinary run recovery.
    pub fn wsb_discard_control_path(&self) -> Result<PathBuf, AiwError> {
        let parent = self.root.parent().ok_or_else(|| {
            path_error(
                "workspace has no parent for external discard authority",
                &self.run_id,
                &self.root,
            )
        })?;
        #[cfg(windows)]
        return Ok(parent.join(format!(
            "{WSB_DISCARD_CURRENT_PREFIX}{}",
            self.coordination_key.binding_sha256()
        )));
        #[cfg(not(windows))]
        {
            let mut digest = Sha256::new();
            digest.update(self.root.to_string_lossy().to_ascii_lowercase().as_bytes());
            digest.update([0]);
            digest.update(self.run_id.as_bytes());
            return Ok(parent.join(format!(
                "{WSB_DISCARD_CURRENT_PREFIX}{}",
                hex::encode(digest.finalize())
            )));
        }
    }

    fn legacy_wsb_discard_control_path(&self) -> Result<PathBuf, AiwError> {
        let parent = self.root.parent().ok_or_else(|| {
            path_error(
                "workspace has no parent for legacy discard authority",
                &self.run_id,
                &self.root,
            )
        })?;
        let root_key = hex::encode(Sha256::digest(
            self.root.to_string_lossy().to_ascii_lowercase().as_bytes(),
        ));
        Ok(parent.join(format!(".aiw-discard-{}-{}", self.run_id, &root_key[..16])))
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

    fn acquire_lock(&self, stage: &'static str) -> Result<RunLock, AiwError> {
        self.acquire_lock_for(RunLockPurpose::Ordinary, stage)
    }

    fn acquire_discard_inspection_lock(&self, stage: &'static str) -> Result<RunLock, AiwError> {
        self.acquire_lock_for(RunLockPurpose::InspectDiscardState, stage)
    }

    fn acquire_lock_for(
        &self,
        purpose: RunLockPurpose,
        stage: &'static str,
    ) -> Result<RunLock, AiwError> {
        #[cfg(windows)]
        let coordination = self.acquire_outer_coordination(stage)?;
        if matches!(purpose, RunLockPurpose::Ordinary) {
            // This check is authoritative because the outer mutex is already
            // held. A waiter awakened after depublish must reject from the
            // external gate before it touches the now-missing workspace.
            self.reject_if_discard_control_present(stage)?;
        }
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
        if matches!(purpose, RunLockPurpose::Ordinary)
            && self.run_dir().is_dir()
            && self.has_internal_wsb_revocation_marker_locked()?
        {
            return Err(run_error(
                "AIW_WSB_REVOKED",
                "Windows Sandbox run is irrevocably reserved for discard",
                stage,
                &self.run_id,
            ));
        }
        Ok(RunLock {
            #[cfg(windows)]
            _coordination: coordination,
            _inner_file: Some(file),
        })
    }

    #[cfg(windows)]
    fn acquire_outer_coordination(
        &self,
        stage: &'static str,
    ) -> Result<RunCoordinationLease, AiwError> {
        let deadline = Instant::now() + RUN_COORDINATION_DEADLINE;
        loop {
            // No orchestrator path has durable abandoned-owner recovery
            // authority yet. InspectDiscardState only bypasses the external
            // control gate so it can report or complete logical revocation;
            // it must still fail closed if this wait observes abandonment.
            match try_acquire_run_coordination(&self.coordination_key, RunCoordinationMode::Normal)
            {
                Ok(lease) => return Ok(lease),
                Err(RunCoordinationError::LeaseUnavailable) if Instant::now() < deadline => {
                    thread::sleep(RUN_COORDINATION_POLL);
                }
                Err(error) => return Err(coordination_error(stage, &self.run_id, error)),
            }
        }
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
        if has_wsb_action(plan) {
            return Err(run_error(
                "AIW_WSB_IMPORT_REQUIRED",
                "Windows Sandbox plans require a verified preparation import",
                "create",
                &self.run_id,
            ));
        }
        let _lock = self.acquire_lock("create")?;
        if self.run_dir().exists() {
            return Err(run_error(
                "AIW_RUN_ALREADY_EXISTS",
                "run directory already exists",
                "create",
                &self.run_id,
            ));
        }
        self.create_locked(plan)?;
        self.validate_run_dir()
    }

    /// Atomically publishes a verified Windows Sandbox import or verifies an
    /// identical already-published import without advancing its lifecycle.
    pub fn create_or_verify_pending_wsb_import(
        &self,
        plan: &RunPlan,
        receipt: &WsbPlanningImportReceipt,
    ) -> Result<PendingRunDisposition, AiwError> {
        validate_plan(plan)?;
        if plan.run_id != self.run_id {
            return Err(run_error(
                "AIW_RUN_ID_MISMATCH",
                "plan does not belong to this run",
                "create",
                &self.run_id,
            ));
        }
        if !has_wsb_action(plan) {
            return Err(run_error(
                "AIW_WSB_IMPORT_INVALID",
                "verified import requires one Windows Sandbox action",
                "create",
                &self.run_id,
            ));
        }
        validate_wsb_import(receipt, plan)?;
        let _lock = self.acquire_lock("create")?;
        self.reject_if_wsb_discard_started_locked(plan, "create")?;
        let disposition =
            if optional_non_reparse_directory(&self.run_dir(), &self.run_id, "create")? {
                PendingRunDisposition::AlreadyPresent
            } else {
                self.create_or_resume_wsb_import_locked(plan, receipt)?;
                PendingRunDisposition::Created
            };
        self.verify_pristine_pending_wsb_import_locked(plan, receipt)?;
        Ok(disposition)
    }

    /// Windows-only WSB import path.  The caller retains the workspace
    /// authority created during preparation so every fixed-tree entry is
    /// created relative to a held parent and never adopted by path.
    #[cfg(windows)]
    pub fn create_or_verify_pending_wsb_import_bound(
        &self,
        workspace: &HeldRunWorkspace,
        plan: &RunPlan,
        receipt: &WsbPlanningImportReceipt,
    ) -> Result<PendingRunDisposition, AiwError> {
        validate_plan(plan)?;
        if plan.run_id != self.run_id || !has_wsb_action(plan) {
            return Err(run_error(
                "AIW_WSB_IMPORT_INVALID",
                "verified import requires the matching Windows Sandbox plan",
                "create",
                &self.run_id,
            ));
        }
        validate_wsb_import(receipt, plan)?;
        self.revalidate_bound_workspace(workspace, "create")?;
        let _lock = self.acquire_bound_wsb_import_lock(workspace, "create", false)?;
        self.reject_if_wsb_discard_started_locked(plan, "create")?;

        let disposition =
            if optional_non_reparse_directory(&self.run_dir(), &self.run_id, "create")? {
                PendingRunDisposition::AlreadyPresent
            } else {
                self.create_or_resume_wsb_import_bound_locked(workspace, plan, receipt)?;
                PendingRunDisposition::Created
            };
        self.verify_pristine_pending_wsb_import_locked(plan, receipt)?;
        Ok(disposition)
    }

    #[cfg(windows)]
    fn revalidate_bound_workspace(
        &self,
        workspace: &HeldRunWorkspace,
        stage: &'static str,
    ) -> Result<(), AiwError> {
        workspace
            .revalidate()
            .map_err(|error| workspace_storage_error(stage, &self.run_id, error))?;
        if !same_path_text(
            workspace.root_path().to_string_lossy().as_ref(),
            self.root.to_string_lossy().as_ref(),
        ) {
            return Err(path_error(
                "held workspace differs from run layout root",
                &self.run_id,
                workspace.root_path(),
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    fn acquire_bound_wsb_import_lock(
        &self,
        workspace: &HeldRunWorkspace,
        stage: &'static str,
        allow_existing_discard_authority: bool,
    ) -> Result<RunLock, AiwError> {
        let coordination = self.acquire_outer_coordination(stage)?;
        if !allow_existing_discard_authority {
            self.reject_if_discard_control_present(stage)?;
        }
        self.revalidate_bound_workspace(workspace, stage)?;
        let runs = bind_or_create_root_directory(workspace, "runs", &self.run_id, stage)?;
        let locks = bind_or_create_directory(&runs, ".locks", &self.run_id, stage)?;
        let leaf = format!("{}.lock", self.run_id);
        let file = match locks.create_file_new(&leaf) {
            Ok(created) => created.into_file(),
            Err(aiw_windows_platform::WorkspaceError::AlreadyExists) => locks
                .reopen_file(&leaf)
                .map_err(|error| workspace_storage_error(stage, &self.run_id, error))?
                .into_file(),
            Err(error) => return Err(workspace_storage_error(stage, &self.run_id, error)),
        };
        FileExt::lock(&file).map_err(|error| storage_error(stage, &self.run_id, error))?;
        self.revalidate_bound_workspace(workspace, stage)?;
        Ok(RunLock {
            _coordination: coordination,
            _inner_file: Some(file),
        })
    }

    #[cfg(windows)]
    fn create_or_resume_wsb_import_bound_locked(
        &self,
        workspace: &HeldRunWorkspace,
        plan: &RunPlan,
        receipt: &WsbPlanningImportReceipt,
    ) -> Result<(), AiwError> {
        let runs = bind_or_create_root_directory(workspace, "runs", &self.run_id, "create")?;
        let stage_leaf = self
            .wsb_import_stage_path(plan)?
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| journal_error(&self.run_id, "invalid WSB import stage leaf"))?
            .to_owned();
        let stage = bind_or_create_directory(&runs, &stage_leaf, &self.run_id, "create")?;
        validate_bound_wsb_stage_namespace(&stage, &self.run_id)?;
        let heads = bind_or_create_directory(&stage, "journal-heads", &self.run_id, "create")?;

        let plan_bytes = json_file_bytes(plan, &self.run_id)?;
        let receipt_bytes = json_file_bytes(receipt, &self.run_id)?;
        let plan_hash = plan.hash()?;
        let receipt_hash = hash_value(receipt)?;
        let event = artifact_event(
            RunEventKind::Created,
            &plan.created_at,
            "verified Windows Sandbox preparation imported",
            &receipt_hash,
        )?;
        let record = build_record(&self.run_id, &plan_hash, 1, ZERO_HASH, event)?;
        let mut journal_bytes = serde_json::to_vec(&record)
            .map_err(|error| serialization_error("create", &self.run_id, error))?;
        journal_bytes.push(b'\n');
        let head = JournalHead {
            schema: HEAD_SCHEMA.to_owned(),
            run_id: self.run_id.clone(),
            plan_hash,
            sequence: 1,
            hash: record.hash,
        };
        let head_bytes = json_file_bytes(&head, &self.run_id)?;

        reconcile_bound_wsb_file(&stage, "plan.json", &plan_bytes, &self.run_id)?;
        reconcile_bound_wsb_file(
            &stage,
            WSB_PLANNING_IMPORT_FILE,
            &receipt_bytes,
            &self.run_id,
        )?;
        reconcile_bound_wsb_file(&stage, "events.jsonl", &journal_bytes, &self.run_id)?;
        reconcile_bound_wsb_file(&heads, &head_name(1), &head_bytes, &self.run_id)?;
        self.verify_wsb_import_stage(stage.final_path(), plan, receipt)?;
        // `heads` retains a duplicate of the stage directory as its parent
        // authority. Release it before the stage is reopened with DELETE for
        // the one non-replacing publication rename.
        drop(heads);
        stage
            .publish_into_bound(&runs, &self.run_id)
            .map_err(|error| workspace_storage_error("create", &self.run_id, error))?;
        Ok(())
    }

    fn create_locked(&self, plan: &RunPlan) -> Result<(), AiwError> {
        let mut stage = None;
        for _ in 0..MAX_CREATE_STAGE_ATTEMPTS {
            let candidate = self.root.join("runs").join(format!(
                ".create-{}-{}-{}",
                self.run_id,
                std::process::id(),
                NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    stage = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(storage_error("create", &self.run_id, error)),
            }
        }
        let stage = stage.ok_or_else(|| {
            run_error(
                "AIW_CREATE_STAGE_EXHAUSTED",
                "could not reserve a fresh run staging directory",
                "create",
                &self.run_id,
            )
        })?;
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
        Ok(())
    }

    fn wsb_import_stage_path(&self, plan: &RunPlan) -> Result<PathBuf, AiwError> {
        Ok(self
            .root
            .join("runs")
            .join(format!(".import-{}-{}", self.run_id, plan.hash()?)))
    }

    fn create_or_resume_wsb_import_locked(
        &self,
        plan: &RunPlan,
        receipt: &WsbPlanningImportReceipt,
    ) -> Result<(), AiwError> {
        let stage = self.wsb_import_stage_path(plan)?;
        if !optional_non_reparse_directory(&stage, &self.run_id, "create")? {
            fs::create_dir(&stage).map_err(|error| storage_error("create", &self.run_id, error))?;
        }
        ensure_directory(&stage, &self.run_id, "create")?;
        let allowed = [
            "events.jsonl",
            "events.jsonl.pending",
            "journal-heads",
            "plan.json",
            "plan.json.pending",
            WSB_PLANNING_IMPORT_FILE,
            "wsb-planning-import.json.pending",
        ];
        for entry in
            fs::read_dir(&stage).map_err(|error| storage_error("create", &self.run_id, error))?
        {
            let name = entry
                .map_err(|error| storage_error("create", &self.run_id, error))?
                .file_name()
                .into_string()
                .map_err(|_| {
                    run_error(
                        "AIW_WSB_IMPORT_STAGE_INVALID",
                        "Windows Sandbox import stage contains a non-Unicode entry",
                        "create",
                        &self.run_id,
                    )
                })?;
            if !allowed.contains(&name.as_str()) {
                return Err(run_error(
                    "AIW_WSB_IMPORT_STAGE_INVALID",
                    "Windows Sandbox import stage differs from its exact allowlist",
                    "create",
                    &self.run_id,
                ));
            }
        }
        let plan_path = stage.join("plan.json");
        let receipt_path = stage.join(WSB_PLANNING_IMPORT_FILE);
        let journal_path = stage.join("events.jsonl");
        let plan_bytes = json_file_bytes(plan, &self.run_id)?;
        let receipt_bytes = json_file_bytes(receipt, &self.run_id)?;
        let plan_hash = plan.hash()?;
        let receipt_hash = hash_value(receipt)?;
        let event = artifact_event(
            RunEventKind::Created,
            &plan.created_at,
            "verified Windows Sandbox preparation imported",
            &receipt_hash,
        )?;
        let record = build_record(&self.run_id, &plan_hash, 1, ZERO_HASH, event)?;
        let mut expected_journal = serde_json::to_vec(&record)
            .map_err(|error| serialization_error("create", &self.run_id, error))?;
        expected_journal.push(b'\n');
        let heads = stage.join("journal-heads");
        let head_path = heads.join(head_name(1));
        let expected_head = JournalHead {
            schema: HEAD_SCHEMA.to_owned(),
            run_id: self.run_id.clone(),
            plan_hash: plan_hash.clone(),
            sequence: 1,
            hash: record.hash.clone(),
        };
        let head_bytes = json_file_bytes(&expected_head, &self.run_id)?;

        self.validate_wsb_import_stage_file_if_present(&plan_path, &plan_bytes)?;
        self.validate_wsb_import_stage_file_if_present(&receipt_path, &receipt_bytes)?;
        self.validate_wsb_import_stage_file_if_present(&journal_path, &expected_journal)?;
        if optional_non_reparse_directory(&heads, &self.run_id, "create")? {
            ensure_directory(&heads, &self.run_id, "create")?;
            let expected_head_name = head_name(1);
            let expected_pending_name = self
                .pending_path(&head_path)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_owned();
            for entry in fs::read_dir(&heads)
                .map_err(|error| storage_error("create", &self.run_id, error))?
            {
                let name = entry
                    .map_err(|error| storage_error("create", &self.run_id, error))?
                    .file_name()
                    .into_string()
                    .map_err(|_| {
                        run_error(
                            "AIW_WSB_IMPORT_STAGE_INVALID",
                            "Windows Sandbox import head stage contains a non-Unicode entry",
                            "create",
                            &self.run_id,
                        )
                    })?;
                if name != expected_head_name && name != expected_pending_name {
                    return Err(run_error(
                        "AIW_WSB_IMPORT_STAGE_INVALID",
                        "Windows Sandbox import head stage differs from its exact allowlist",
                        "create",
                        &self.run_id,
                    ));
                }
            }
            self.validate_wsb_import_stage_file_if_present(&head_path, &head_bytes)?;
        }

        if !optional_non_reparse_directory(&heads, &self.run_id, "create")? {
            fs::create_dir(&heads).map_err(|error| storage_error("create", &self.run_id, error))?;
        }
        self.reconcile_wsb_import_stage_file(&plan_path, &plan_bytes)?;
        self.reconcile_wsb_import_stage_file(&receipt_path, &receipt_bytes)?;
        self.reconcile_wsb_import_stage_file(&journal_path, &expected_journal)?;
        self.reconcile_wsb_import_stage_file(&head_path, &head_bytes)?;
        self.verify_wsb_import_stage(&stage, plan, receipt)?;
        fs::rename(&stage, self.run_dir())
            .map_err(|error| storage_error("create", &self.run_id, error))?;
        Ok(())
    }

    fn validate_wsb_import_stage_file_if_present(
        &self,
        target: &Path,
        expected: &[u8],
    ) -> Result<(), AiwError> {
        let pending = self.pending_path(target);
        let target_present = optional_non_reparse_file(target, &self.run_id, "create")?;
        let pending_present = optional_non_reparse_file(&pending, &self.run_id, "create")?;
        if target_present && read_bounded(target, MAX_JOURNAL, &self.run_id, "create")? != expected
        {
            return Err(run_error(
                "AIW_WSB_IMPORT_STAGE_INVALID",
                "Windows Sandbox import stage artifact differs from expected bytes",
                "create",
                &self.run_id,
            ));
        }
        if pending_present {
            let observed = read_bounded(&pending, MAX_JOURNAL, &self.run_id, "create")?;
            if !expected.starts_with(&observed) {
                return Err(run_error(
                    "AIW_WSB_IMPORT_STAGE_INVALID",
                    "Windows Sandbox import pending artifact is not an exact expected prefix",
                    "create",
                    &self.run_id,
                ));
            }
        }
        Ok(())
    }

    fn reconcile_wsb_import_stage_file(
        &self,
        target: &Path,
        expected: &[u8],
    ) -> Result<(), AiwError> {
        self.validate_wsb_import_stage_file_if_present(target, expected)?;
        let pending = self.pending_path(target);
        if optional_non_reparse_file(target, &self.run_id, "create")? {
            fs::remove_file(target)
                .map_err(|error| storage_error("create", &self.run_id, error))?;
        }
        if optional_non_reparse_file(&pending, &self.run_id, "create")? {
            fs::remove_file(&pending)
                .map_err(|error| storage_error("create", &self.run_id, error))?;
        }
        // Never append to or publish a recovered file directly. Regenerating
        // exact trusted bytes after unlinking the stage names prevents an
        // attacker-supplied hard link from becoming a write-through primitive
        // or remaining externally mutable after publication.
        write_bytes_complete_new(target, expected, &self.run_id, "create")?;
        Ok(())
    }

    fn verify_wsb_import_stage(
        &self,
        stage: &Path,
        plan: &RunPlan,
        receipt: &WsbPlanningImportReceipt,
    ) -> Result<(), AiwError> {
        ensure_directory(stage, &self.run_id, "create")?;
        let runs = self.root.join("runs");
        let canonical = fs::canonicalize(stage)
            .map_err(|error| storage_error("create", &self.run_id, error))?;
        if canonical.parent() != Some(runs.as_path())
            || canonical != self.wsb_import_stage_path(plan)?
        {
            return Err(path_error(
                "Windows Sandbox import staging escaped the workspace",
                &self.run_id,
                &canonical,
            ));
        }
        let mut entries = fs::read_dir(stage)
            .map_err(|error| storage_error("create", &self.run_id, error))?
            .map(|entry| {
                entry
                    .map_err(|error| storage_error("create", &self.run_id, error))?
                    .file_name()
                    .into_string()
                    .map_err(|_| {
                        run_error(
                            "AIW_WSB_IMPORT_STAGE_INVALID",
                            "Windows Sandbox import stage contains a non-Unicode entry",
                            "create",
                            &self.run_id,
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();
        if entries
            != [
                "events.jsonl",
                "journal-heads",
                "plan.json",
                WSB_PLANNING_IMPORT_FILE,
            ]
        {
            return Err(run_error(
                "AIW_WSB_IMPORT_STAGE_INVALID",
                "Windows Sandbox import stage differs from its exact allowlist",
                "create",
                &self.run_id,
            ));
        }
        let staged_plan: RunPlan = read_json(
            &stage.join("plan.json"),
            MAX_ARTIFACT,
            &self.run_id,
            "create",
        )?;
        let staged_receipt: WsbPlanningImportReceipt = read_json(
            &stage.join(WSB_PLANNING_IMPORT_FILE),
            MAX_ARTIFACT,
            &self.run_id,
            "create",
        )?;
        if &staged_plan != plan || &staged_receipt != receipt {
            return Err(run_error(
                "AIW_WSB_IMPORT_STAGE_INVALID",
                "Windows Sandbox import stage differs from the verified import",
                "create",
                &self.run_id,
            ));
        }
        validate_wsb_import(&staged_receipt, &staged_plan)?;
        let plan_hash = plan.hash()?;
        let receipt_hash = hash_value(&staged_receipt)?;
        let event = artifact_event(
            RunEventKind::Created,
            &plan.created_at,
            "verified Windows Sandbox preparation imported",
            &receipt_hash,
        )?;
        let expected_record = build_record(&self.run_id, &plan_hash, 1, ZERO_HASH, event)?;
        let journal = read_bounded(
            &stage.join("events.jsonl"),
            MAX_JOURNAL,
            &self.run_id,
            "create",
        )?;
        let mut expected_journal = serde_json::to_vec(&expected_record)
            .map_err(|error| serialization_error("create", &self.run_id, error))?;
        expected_journal.push(b'\n');
        if journal != expected_journal {
            return Err(run_error(
                "AIW_WSB_IMPORT_STAGE_INVALID",
                "Windows Sandbox import stage journal is not the exact genesis record",
                "create",
                &self.run_id,
            ));
        }
        let heads = stage.join("journal-heads");
        ensure_directory(&heads, &self.run_id, "create")?;
        let mut head_entries = fs::read_dir(&heads)
            .map_err(|error| storage_error("create", &self.run_id, error))?
            .map(|entry| entry.map_err(|error| storage_error("create", &self.run_id, error)))
            .collect::<Result<Vec<_>, _>>()?;
        if head_entries.len() != 1 {
            return Err(run_error(
                "AIW_WSB_IMPORT_STAGE_INVALID",
                "Windows Sandbox import stage must contain one genesis head",
                "create",
                &self.run_id,
            ));
        }
        let head_path = head_entries.pop().expect("length checked").path();
        if head_path.file_name().and_then(|value| value.to_str()) != Some(&head_name(1)) {
            return Err(run_error(
                "AIW_WSB_IMPORT_STAGE_INVALID",
                "Windows Sandbox import stage head name is invalid",
                "create",
                &self.run_id,
            ));
        }
        let head: JournalHead = read_json(&head_path, MAX_ARTIFACT, &self.run_id, "create")?;
        let expected_head = JournalHead {
            schema: HEAD_SCHEMA.to_owned(),
            run_id: self.run_id.clone(),
            plan_hash,
            sequence: 1,
            hash: expected_record.hash,
        };
        if head != expected_head {
            return Err(run_error(
                "AIW_WSB_IMPORT_STAGE_INVALID",
                "Windows Sandbox import stage head differs from its genesis record",
                "create",
                &self.run_id,
            ));
        }
        Ok(())
    }

    fn verify_pristine_pending_wsb_import_locked(
        &self,
        expected: &RunPlan,
        expected_receipt: &WsbPlanningImportReceipt,
    ) -> Result<(), AiwError> {
        self.validate_run_dir()?;
        let observed = self.read_plan_locked()?;
        if &observed != expected || observed.hash()? != expected.hash()? {
            return Err(run_error(
                "AIW_PENDING_RUN_CONFLICT",
                "existing run plan differs from the verified plan",
                "create",
                &self.run_id,
            ));
        }
        let observed_receipt: WsbPlanningImportReceipt = read_json(
            &self.wsb_planning_import_path(),
            MAX_ARTIFACT,
            &self.run_id,
            "create",
        )?;
        validate_wsb_import(&observed_receipt, &observed)?;
        if &observed_receipt != expected_receipt {
            return Err(run_error(
                "AIW_PENDING_RUN_CONFLICT",
                "existing Windows Sandbox import receipt differs from the verified import",
                "create",
                &self.run_id,
            ));
        }
        let records = self.load_records(false)?;
        self.verify_committed(&records)?;
        if records.len() != 1
            || records[0].sequence != 1
            || records[0].event.kind != RunEventKind::Created
            || self.approval_path().exists()
            || self.cancellation_path().exists()
            || self.result_path().exists()
        {
            return Err(run_error(
                "AIW_PENDING_RUN_CONFLICT",
                "existing run is not the pristine pending-approval state",
                "create",
                &self.run_id,
            ));
        }
        let mut observed_entries = fs::read_dir(self.run_dir())
            .map_err(|error| storage_error("create", &self.run_id, error))?
            .map(|entry| {
                entry
                    .map_err(|error| storage_error("create", &self.run_id, error))?
                    .file_name()
                    .into_string()
                    .map_err(|_| {
                        run_error(
                            "AIW_PENDING_RUN_CONFLICT",
                            "existing run contains a non-Unicode entry",
                            "create",
                            &self.run_id,
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        observed_entries.sort();
        if observed_entries
            != [
                "events.jsonl",
                "journal-heads",
                "plan.json",
                WSB_PLANNING_IMPORT_FILE,
            ]
        {
            return Err(run_error(
                "AIW_PENDING_RUN_CONFLICT",
                "existing run contains artifacts outside the pristine allowlist",
                "create",
                &self.run_id,
            ));
        }
        Ok(())
    }

    fn verify_revocation_run_allowlist_locked(&self) -> Result<(), AiwError> {
        self.validate_run_dir()?;
        let allowed = [
            "events.jsonl",
            "journal-heads",
            "plan.json",
            WSB_PLANNING_IMPORT_FILE,
            "wsb-revocation.json",
            "wsb-revocation.json.pending",
            "wsb-revocation.json.pending.pending",
        ];
        for entry in fs::read_dir(self.run_dir())
            .map_err(|error| storage_error("revocation", &self.run_id, error))?
        {
            let entry = entry.map_err(|error| storage_error("revocation", &self.run_id, error))?;
            let name = entry.file_name().into_string().map_err(|_| {
                run_error(
                    "AIW_WSB_DISCARD_STATE_INVALID",
                    "revoking run contains a non-Unicode entry",
                    "revocation",
                    &self.run_id,
                )
            })?;
            if !allowed.contains(&name.as_str()) {
                return Err(run_error(
                    "AIW_WSB_DISCARD_STATE_INVALID",
                    "revoking run contains an artifact outside its exact allowlist",
                    "revocation",
                    &self.run_id,
                ));
            }
        }
        for path in [
            self.plan_path(),
            self.journal_path(),
            self.wsb_planning_import_path(),
        ] {
            ensure_file(&path, &self.run_id, "revocation")?;
        }
        ensure_directory(&self.heads_dir(), &self.run_id, "revocation")?;
        for path in [
            self.wsb_revocation_path(),
            self.pending_path(&self.wsb_revocation_path()),
            self.pending_path(&self.pending_path(&self.wsb_revocation_path())),
        ] {
            optional_non_reparse_file(&path, &self.run_id, "revocation")?;
        }
        Ok(())
    }

    pub fn read_plan(&self) -> Result<RunPlan, AiwError> {
        let _lock = self.acquire_lock("plan")?;
        self.validate_run_dir()?;
        self.read_plan_locked()
    }

    fn read_plan_locked(&self) -> Result<RunPlan, AiwError> {
        let value: serde_json::Value =
            read_json(&self.plan_path(), MAX_ARTIFACT, &self.run_id, "plan")?;
        let plan = RunPlan::from_value(value)?;
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
        let _lock = self.acquire_lock("approval")?;
        self.validate_run_dir()?;
        let plan = self.read_plan_locked()?;
        self.validate_wsb_import_provenance_locked(&plan, "approval")?;
        self.reject_if_wsb_discard_started_locked(&plan, "approval")?;
        self.recover_locked()?;
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
        let _lock = self.acquire_lock("approval")?;
        self.validate_run_dir()?;
        let plan = self.read_plan_locked()?;
        self.reject_if_wsb_discard_started_locked(&plan, "approval")?;
        self.recover_locked()?;
        self.read_approval_locked()
    }

    fn read_approval_locked(&self) -> Result<ApprovalRecord, AiwError> {
        let plan = self.read_plan_locked()?;
        self.validate_wsb_import_provenance_locked(&plan, "approval")?;
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
        let _lock = self.acquire_lock("journal")?;
        self.validate_run_dir()?;
        let plan = self.read_plan_locked()?;
        self.reject_if_wsb_discard_started_locked(&plan, "journal")?;
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
        let _lock = self.acquire_lock("journal")?;
        self.validate_run_dir()?;
        let plan = self.read_plan_locked()?;
        self.reject_if_wsb_discard_started_locked(&plan, "journal")?;
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
        let _lock = self.acquire_lock("cancel")?;
        self.validate_run_dir()?;
        let plan = self.read_plan_locked()?;
        self.reject_if_wsb_discard_started_locked(&plan, "cancel")?;
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
        let _lock = self.acquire_lock("result")?;
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
        let _lock = self.acquire_lock("result")?;
        self.validate_run_dir()?;
        let plan = self.read_plan_locked()?;
        self.reject_if_wsb_discard_started_locked(&plan, "result")?;
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
        let _lock = self.acquire_discard_inspection_lock("recovery")?;
        self.validate_run_dir()?;
        let plan = self.read_plan_locked()?;
        if self.wsb_discard_started_locked(&plan)? {
            return self.revoked_status_locked(&plan);
        }
        self.recover_locked()?;
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

    /// Observes persisted state without taking a lock, repairing a journal, or creating files.
    pub fn status(&self) -> Result<RecoveryStatus, AiwError> {
        self.validate_run_dir()?;
        let plan = self.read_plan_locked()?;
        self.validate_wsb_import_provenance_locked(&plan, "status")?;
        if self.wsb_discard_started_locked(&plan)? {
            return self.revoked_status_locked(&plan);
        }
        self.reject_internal_revocation_without_authority_locked(&plan, "status")?;
        let records = self.load_records(false)?;
        self.verify_committed(&records)?;
        let last_sequence = records.last().map_or(0, |record| record.sequence);
        if let Some(last) = records.last().filter(|last| is_intent(last.event.kind)) {
            return Ok(RecoveryStatus::RecoveryRequired {
                pending_event: last.event.kind,
                last_sequence,
            });
        }
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

    /// Reads a terminal run without taking a lock, repairing a journal, or
    /// creating any missing storage.  The status is observed both before and
    /// after the artifact reads so a concurrent lifecycle change is reported
    /// instead of producing a mixed snapshot.
    pub fn completed_snapshot(&self) -> Result<CompletedRunSnapshot, AiwError> {
        let initial = self.status()?;
        let RecoveryStatus::Terminal {
            result: initial_result,
            ..
        } = initial
        else {
            return Err(run_error(
                "AIW_RUN_NOT_TERMINAL",
                "run has not reached a committed terminal state",
                "snapshot",
                &self.run_id,
            ));
        };

        let plan = self.read_plan_locked()?;
        let approval = self.read_approval_locked()?;
        let result = self.read_result_locked()?;
        if result != initial_result {
            return Err(run_error(
                "AIW_RUN_SNAPSHOT_CONFLICT",
                "terminal result changed while reading the snapshot",
                "snapshot",
                &self.run_id,
            ));
        }

        let confirmed = self.status()?;
        match confirmed {
            RecoveryStatus::Terminal {
                result: confirmed_result,
                ..
            } if confirmed_result == result => Ok(CompletedRunSnapshot {
                plan,
                approval,
                result,
            }),
            _ => Err(run_error(
                "AIW_RUN_SNAPSHOT_CONFLICT",
                "run lifecycle changed while reading the snapshot",
                "snapshot",
                &self.run_id,
            )),
        }
    }

    /// Holds the run lock across external intent publication and internal
    /// revocation. The returned guard exposes no ordinary lifecycle mutation.
    #[doc(hidden)]
    pub fn begin_wsb_revocation(&self) -> Result<WsbRevocationGuard<'_>, AiwError> {
        let lock = self.acquire_discard_inspection_lock("revocation")?;
        self.begin_wsb_revocation_locked(
            lock,
            |layout| layout.repair_revocation_journal_locked(),
            |layout, revocation, hash| {
                layout.publish_wsb_revocation_artifact_locked(revocation, hash)
            },
        )
    }

    #[cfg(windows)]
    #[doc(hidden)]
    pub fn acquire_wsb_revocation_lease(&self) -> Result<WsbRevocationLease<'_>, AiwError> {
        let lock = self.acquire_discard_inspection_lock("revocation")?;
        Ok(WsbRevocationLease { layout: self, lock })
    }

    fn begin_wsb_revocation_locked<R, F>(
        &self,
        lock: RunLock,
        repair_journal: R,
        publish_recorded: F,
    ) -> Result<WsbRevocationGuard<'_>, AiwError>
    where
        R: FnOnce(&RunLayout) -> Result<Vec<JournalRecord>, AiwError>,
        F: FnOnce(&RunLayout, &WsbRevocationRecord, &str) -> Result<(), AiwError>,
    {
        self.validate_run_dir()?;
        let plan = self.read_plan_locked()?;
        self.validate_wsb_import_provenance_locked(&plan, "revocation")?;
        if !has_wsb_action(&plan) {
            return Err(run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "revocation requires an imported Windows Sandbox run",
                "revocation",
                &self.run_id,
            ));
        }
        let import = self.read_wsb_import_receipt_locked(&plan, "revocation")?;
        if self.approval_path().exists()
            || self.cancellation_path().exists()
            || self.result_path().exists()
            || self.run_dir().join("wsb-session-transaction").exists()
        {
            return Err(run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "only a pristine never-approved WSB run can be revoked for discard",
                "revocation",
                &self.run_id,
            ));
        }
        let internal_started = self.has_internal_wsb_revocation_marker_locked()?;
        let discard_started = self.wsb_discard_started_locked(&plan)? || internal_started;
        if self.legacy_discard_control_present()? {
            return Err(run_error(
                "AIW_WSB_LEGACY_DISCARD_AUTHORITY",
                "legacy Windows Sandbox discard authority is fail-closed and cannot be adopted",
                "revocation",
                &self.run_id,
            ));
        }
        if self.current_discard_control_present()? && !internal_started {
            return Err(run_error(
                "AIW_WSB_DISCARD_AUTHORITY_MISSING",
                "external discard authority has no linked internal revocation",
                "revocation",
                &self.run_id,
            ));
        }
        let records = if discard_started {
            self.verify_revocation_run_allowlist_locked()?;
            repair_journal(self)?
        } else {
            self.verify_pristine_pending_wsb_import_locked(&plan, &import)?;
            self.load_records(false)?
        };
        self.verify_committed(&records)?;
        let lifecycle_is_revocation_only = records.len() == 1
            || (records.len() == 2 && records[1].event.kind == RunEventKind::RevocationIntent)
            || (records.len() == 3
                && records[1].event.kind == RunEventKind::RevocationIntent
                && records[2].event.kind == RunEventKind::RevocationRecorded);
        if !lifecycle_is_revocation_only {
            return Err(run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "only pristine or already-revoking WSB state can enter discard",
                "revocation",
                &self.run_id,
            ));
        }
        let revocation_recorded = records
            .iter()
            .any(|record| record.event.kind == RunEventKind::RevocationRecorded);
        let recoverable_revocation =
            self.read_recoverable_wsb_revocation_locked(&plan, &import, &records)?;
        if revocation_recorded {
            let revocation = recoverable_revocation.as_ref().ok_or_else(|| {
                run_error(
                    "AIW_WSB_DISCARD_STATE_INVALID",
                    "recorded revocation has no recoverable binding",
                    "revocation",
                    &self.run_id,
                )
            })?;
            publish_recorded(self, revocation, &hash_value(revocation)?)?;
        }
        let committed_revocation = revocation_recorded.then(|| {
            recoverable_revocation
                .as_ref()
                .expect("recorded revocation checked")
                .clone()
        });
        Ok(WsbRevocationGuard {
            layout: self,
            _lock: lock,
            plan,
            import,
            recoverable_revocation,
            committed_revocation,
        })
    }

    fn read_recoverable_wsb_revocation_locked(
        &self,
        plan: &RunPlan,
        import: &WsbPlanningImportReceipt,
        records: &[JournalRecord],
    ) -> Result<Option<WsbRevocationRecord>, AiwError> {
        let target = self.wsb_revocation_path();
        let pending = self.pending_path(&target);
        let pending_pending = self.pending_path(&pending);
        let expected_hash = records.iter().rev().find_map(|record| {
            matches!(
                record.event.kind,
                RunEventKind::RevocationIntent | RunEventKind::RevocationRecorded
            )
            .then(|| record.event.artifact_hash.clone())
            .flatten()
        });

        // A complete pending copy is authoritative for recovery. A malformed
        // target is deliberately ignored here and will be unlinked by publish.
        let source = if optional_non_reparse_file(&pending, &self.run_id, "revocation")? {
            Some(pending)
        } else if expected_hash.is_some()
            && optional_non_reparse_file(&target, &self.run_id, "revocation")?
        {
            // The target is data-only input. It is never adopted as authority;
            // publish first creates another complete copy and regenerates it.
            Some(target)
        } else {
            None
        };
        let Some(source) = source else {
            if optional_non_reparse_file(&pending_pending, &self.run_id, "revocation")? {
                return Err(run_error(
                    "AIW_WSB_DISCARD_STATE_INVALID",
                    "incomplete revocation binding blocks automatic recovery",
                    "revocation",
                    &self.run_id,
                ));
            }
            return Ok(None);
        };
        let revocation: WsbRevocationRecord =
            read_json(&source, MAX_ARTIFACT, &self.run_id, "revocation")?;
        validate_wsb_revocation(&revocation, plan, import, self)?;
        let observed_hash = hash_value(&revocation)?;
        if expected_hash
            .as_deref()
            .is_some_and(|hash| hash != observed_hash)
        {
            return Err(run_error(
                "AIW_WSB_REVOCATION_CONFLICT",
                "recoverable revocation does not match the journal intent",
                "revocation",
                &self.run_id,
            ));
        }
        Ok(Some(revocation))
    }

    fn write_wsb_revocation_locked(
        &self,
        plan: &RunPlan,
        import: &WsbPlanningImportReceipt,
        revocation: &WsbRevocationRecord,
    ) -> Result<(), AiwError> {
        validate_wsb_revocation(revocation, plan, import, self)?;
        let records = self.load_records(false)?;
        self.verify_committed(&records)?;
        let expected_hash = hash_value(revocation)?;
        if records
            .iter()
            .any(|record| record.event.kind == RunEventKind::RevocationRecorded)
        {
            let observed = self
                .read_recoverable_wsb_revocation_locked(plan, import, &records)?
                .ok_or_else(|| {
                    run_error(
                        "AIW_WSB_DISCARD_STATE_INVALID",
                        "recorded revocation has no recoverable binding",
                        "revocation",
                        &self.run_id,
                    )
                })?;
            if observed != *revocation {
                return Err(run_error(
                    "AIW_WSB_REVOCATION_CONFLICT",
                    "existing Windows Sandbox revocation differs from this request",
                    "revocation",
                    &self.run_id,
                ));
            }
            return self.publish_wsb_revocation_artifact_locked(revocation, &expected_hash);
        }
        if records.len() == 1 {
            let target = self.wsb_revocation_path();
            let pending = self.pending_path(&target);
            let pending_pending = self.pending_path(&pending);
            if target.exists() {
                return Err(run_error(
                    "AIW_ARTIFACT_UNJOURNALED",
                    "committed revocation artifact exists without a journal intent",
                    "revocation",
                    &self.run_id,
                ));
            }
            if pending.exists() {
                self.verify_revocation_file_locked(&pending, revocation, &expected_hash)?;
            } else {
                if pending_pending.exists() {
                    return Err(run_error(
                        "AIW_WSB_DISCARD_STATE_INVALID",
                        "incomplete revocation binding blocks automatic recovery",
                        "revocation",
                        &self.run_id,
                    ));
                }
                write_complete_new(&pending_pending, revocation, &self.run_id, "revocation")?;
                publish_new(&pending_pending, &pending, &self.run_id, "revocation")?;
            }
            self.append_record(artifact_event(
                RunEventKind::RevocationIntent,
                &revocation.requested_at,
                "revocation mutation prepared",
                &expected_hash,
            )?)?;
        }
        let records = self.load_records(false)?;
        self.verify_committed(&records)?;
        let last = records.last().expect("genesis checked");
        if last.event.kind != RunEventKind::RevocationIntent
            || last.event.artifact_hash.as_deref() != Some(expected_hash.as_str())
        {
            return Err(run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "run lifecycle changed before revocation completed",
                "revocation",
                &self.run_id,
            ));
        }
        self.publish_wsb_revocation_artifact_locked(revocation, &expected_hash)?;
        self.append_record(artifact_event(
            RunEventKind::RevocationRecorded,
            &revocation.requested_at,
            "revocation persisted",
            &expected_hash,
        )?)?;
        Ok(())
    }

    #[cfg(windows)]
    fn write_wsb_revocation_artifact_bound_locked(
        &self,
        workspace: &HeldRunWorkspace,
        plan: &RunPlan,
        import: &WsbPlanningImportReceipt,
        revocation: &WsbRevocationRecord,
    ) -> Result<(), AiwError> {
        self.revalidate_bound_workspace(workspace, "revocation")?;
        validate_wsb_revocation(revocation, plan, import, self)?;
        let (run, heads) = self.bind_wsb_revocation_run_directories(workspace)?;
        let records = self.load_records(false)?;
        self.verify_committed(&records)?;
        let expected_hash = hash_value(revocation)?;
        if records
            .iter()
            .any(|record| record.event.kind == RunEventKind::RevocationRecorded)
        {
            let observed = self
                .read_recoverable_wsb_revocation_locked(plan, import, &records)?
                .ok_or_else(|| {
                    run_error(
                        "AIW_WSB_DISCARD_STATE_INVALID",
                        "recorded revocation has no recoverable binding",
                        "revocation",
                        &self.run_id,
                    )
                })?;
            if observed != *revocation {
                return Err(run_error(
                    "AIW_WSB_REVOCATION_CONFLICT",
                    "existing Windows Sandbox revocation differs from this request",
                    "revocation",
                    &self.run_id,
                ));
            }
            return self.publish_wsb_revocation_artifact_bound_from_directories(
                &run,
                revocation,
                &expected_hash,
            );
        }
        if records.len() == 1 {
            let target = self.wsb_revocation_path();
            let pending = self.pending_path(&target);
            let pending_pending = self.pending_path(&pending);
            if target.exists() {
                return Err(run_error(
                    "AIW_ARTIFACT_UNJOURNALED",
                    "committed revocation artifact exists without a journal intent",
                    "revocation",
                    &self.run_id,
                ));
            }
            if pending.exists() {
                self.verify_revocation_file_locked(&pending, revocation, &expected_hash)?;
            } else {
                if pending_pending.exists() {
                    return Err(run_error(
                        "AIW_WSB_DISCARD_STATE_INVALID",
                        "incomplete revocation binding blocks automatic recovery",
                        "revocation",
                        &self.run_id,
                    ));
                }
                let bytes = json_file_bytes(revocation, &self.run_id)?;
                reconcile_bound_wsb_file(
                    &run,
                    "wsb-revocation.json.pending",
                    &bytes,
                    &self.run_id,
                )?;
            }
            self.append_record_bound(
                &run,
                &heads,
                artifact_event(
                    RunEventKind::RevocationIntent,
                    &revocation.requested_at,
                    "revocation mutation prepared",
                    &expected_hash,
                )?,
            )?;
        }
        let records = self.load_records(false)?;
        self.verify_committed(&records)?;
        let last = records.last().expect("genesis checked");
        if last.event.kind != RunEventKind::RevocationIntent
            || last.event.artifact_hash.as_deref() != Some(expected_hash.as_str())
        {
            return Err(run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "run lifecycle changed before revocation completed",
                "revocation",
                &self.run_id,
            ));
        }
        self.publish_wsb_revocation_artifact_bound_from_directories(
            &run,
            revocation,
            &expected_hash,
        )?;
        self.append_record_bound(
            &run,
            &heads,
            artifact_event(
                RunEventKind::RevocationRecorded,
                &revocation.requested_at,
                "revocation persisted",
                &expected_hash,
            )?,
        )?;
        Ok(())
    }

    #[cfg(windows)]
    fn bind_wsb_revocation_run_directories(
        &self,
        workspace: &HeldRunWorkspace,
    ) -> Result<(BoundWorkspaceDirectory, BoundWorkspaceDirectory), AiwError> {
        self.revalidate_bound_workspace(workspace, "revocation")?;
        let runs = workspace
            .reopen_root_directory("runs", WorkspaceAclPolicy::Inherited)
            .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
        let run = runs
            .reopen_directory(&self.run_id, WorkspaceAclPolicy::Inherited)
            .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
        let heads = run
            .reopen_directory("journal-heads", WorkspaceAclPolicy::Inherited)
            .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
        run.revalidate()
            .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
        heads
            .revalidate()
            .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
        Ok((run, heads))
    }

    #[cfg(windows)]
    fn publish_wsb_revocation_artifact_bound_locked(
        &self,
        workspace: &HeldRunWorkspace,
        revocation: &WsbRevocationRecord,
        expected_hash: &str,
    ) -> Result<(), AiwError> {
        let (run, _heads) = self.bind_wsb_revocation_run_directories(workspace)?;
        self.publish_wsb_revocation_artifact_bound_from_directories(&run, revocation, expected_hash)
    }

    #[cfg(windows)]
    fn publish_wsb_revocation_artifact_bound_from_directories(
        &self,
        run: &BoundWorkspaceDirectory,
        revocation: &WsbRevocationRecord,
        expected_hash: &str,
    ) -> Result<(), AiwError> {
        let target = self.wsb_revocation_path();
        let pending = self.pending_path(&target);
        let pending_pending = self.pending_path(&pending);
        let has_target = optional_non_reparse_file(&target, &self.run_id, "revocation")?;
        let has_pending = optional_non_reparse_file(&pending, &self.run_id, "revocation")?;
        let has_partial_pending =
            optional_non_reparse_file(&pending_pending, &self.run_id, "revocation")?;

        if has_pending {
            self.verify_revocation_file_locked(&pending, revocation, expected_hash)?;
            if has_partial_pending {
                remove_pending(&pending_pending, &self.run_id)?;
            }
        } else {
            if has_partial_pending {
                if !has_target {
                    return Err(run_error(
                        "AIW_WSB_DISCARD_STATE_INVALID",
                        "incomplete revocation binding blocks publication",
                        "revocation",
                        &self.run_id,
                    ));
                }
                self.verify_revocation_file_locked(&target, revocation, expected_hash)?;
                remove_pending(&pending_pending, &self.run_id)?;
            }
            let bytes = json_file_bytes(revocation, &self.run_id)?;
            reconcile_bound_wsb_file(run, "wsb-revocation.json.pending", &bytes, &self.run_id)?;
        }
        self.verify_revocation_file_locked(&pending, revocation, expected_hash)?;
        if has_target {
            fs::remove_file(&target)
                .map_err(|error| storage_error("revocation", &self.run_id, error))?;
        }
        // Keep the complete pending binding in place until a separately
        // created nested pending file has been published at the final name.
        // Unlike recreating `wsb-revocation.json.pending` in place, this
        // leaves a durable recovery source throughout the pending -> final
        // boundary.
        let bytes = json_file_bytes(revocation, &self.run_id)?;
        let nested_leaf = "wsb-revocation.json.pending.pending";
        if optional_non_reparse_file(
            &run.final_path().join(nested_leaf),
            &self.run_id,
            "revocation",
        )? {
            return Err(run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "incomplete nested revocation publication blocks recovery",
                "revocation",
                &self.run_id,
            ));
        }
        let mut created = run
            .create_file_new(nested_leaf)
            .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
        created
            .as_file_mut()
            .write_all(&bytes)
            .and_then(|_| created.as_file_mut().sync_all())
            .map_err(|error| storage_error("revocation", &self.run_id, error))?;
        created
            .publish_into_bound(run, "wsb-revocation.json")
            .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
        self.verify_revocation_file_locked(&target, revocation, expected_hash)?;
        let pending_file = run
            .reopen_file("wsb-revocation.json.pending")
            .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
        pending_file
            .revalidate()
            .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
        drop(pending_file);
        fs::remove_file(&pending).map_err(|error| storage_error("revocation", &self.run_id, error))
    }

    #[cfg(windows)]
    fn append_record_bound(
        &self,
        run: &BoundWorkspaceDirectory,
        heads: &BoundWorkspaceDirectory,
        event: RunEvent,
    ) -> Result<JournalRecord, AiwError> {
        validate_event(&event)?;
        let mut records = self.load_records(false)?;
        if records.len() >= MAX_RECORDS {
            return Err(run_error(
                "AIW_JOURNAL_TOO_LARGE",
                "journal reached its record bound",
                "journal",
                &self.run_id,
            ));
        }
        let plan = self.read_plan_locked()?;
        let plan_hash = plan.hash()?;
        let genesis_artifact_hash = self.expected_genesis_artifact_hash_locked(&plan)?;
        let sequence = records.last().map_or(1, |record| record.sequence + 1);
        let previous = records
            .last()
            .map_or(ZERO_HASH, |record| record.hash.as_str());
        let record = build_record(&self.run_id, &plan_hash, sequence, previous, event)?;
        records.push(record.clone());
        validate_grammar(&records, &self.run_id, &genesis_artifact_hash)?;

        let journal = run
            .reopen_file("events.jsonl")
            .map_err(|error| workspace_storage_error("journal", &self.run_id, error))?;
        journal
            .revalidate()
            .map_err(|error| workspace_storage_error("journal", &self.run_id, error))?;
        let mut bytes = serde_json::to_vec(&record)
            .map_err(|error| serialization_error("journal", &self.run_id, error))?;
        bytes.push(b'\n');
        let length = journal
            .as_file()
            .metadata()
            .map_err(|error| storage_error("journal", &self.run_id, error))?
            .len();
        if bytes.len() > MAX_LINE || length.saturating_add(bytes.len() as u64) > MAX_JOURNAL {
            return Err(run_error(
                "AIW_JOURNAL_TOO_LARGE",
                "journal exceeds storage bound",
                "journal",
                &self.run_id,
            ));
        }
        let mut file = journal
            .as_file()
            .try_clone()
            .map_err(|error| storage_error("journal", &self.run_id, error))?;
        file.seek(SeekFrom::End(0))
            .and_then(|_| file.write_all(&bytes))
            .and_then(|_| file.sync_all())
            .map_err(|error| storage_error("journal", &self.run_id, error))?;
        journal
            .revalidate()
            .map_err(|error| workspace_storage_error("journal", &self.run_id, error))?;

        let value = JournalHead {
            schema: HEAD_SCHEMA.into(),
            run_id: record.run_id.clone(),
            plan_hash: record.plan_hash.clone(),
            sequence: record.sequence,
            hash: record.hash.clone(),
        };
        let bytes = json_file_bytes(&value, &self.run_id)?;
        reconcile_bound_wsb_file(heads, &head_name(record.sequence), &bytes, &self.run_id)?;
        Ok(record)
    }

    fn verify_revocation_file_locked(
        &self,
        path: &Path,
        expected: &WsbRevocationRecord,
        expected_hash: &str,
    ) -> Result<(), AiwError> {
        let observed: WsbRevocationRecord =
            read_json(path, MAX_ARTIFACT, &self.run_id, "revocation")?;
        if &observed != expected || hash_value(&observed)? != expected_hash {
            return Err(run_error(
                "AIW_WSB_REVOCATION_CONFLICT",
                "persisted revocation binding differs from this request",
                "revocation",
                &self.run_id,
            ));
        }
        Ok(())
    }

    fn publish_wsb_revocation_artifact_locked(
        &self,
        revocation: &WsbRevocationRecord,
        expected_hash: &str,
    ) -> Result<(), AiwError> {
        let target = self.wsb_revocation_path();
        let pending = self.pending_path(&target);
        let pending_pending = self.pending_path(&pending);
        let has_target = optional_non_reparse_file(&target, &self.run_id, "revocation")?;
        let has_pending = optional_non_reparse_file(&pending, &self.run_id, "revocation")?;
        let has_partial_pending =
            optional_non_reparse_file(&pending_pending, &self.run_id, "revocation")?;

        if has_pending {
            self.verify_revocation_file_locked(&pending, revocation, expected_hash)?;
            if has_partial_pending {
                remove_pending(&pending_pending, &self.run_id)?;
            }
        } else {
            // Preserve a complete trusted copy before touching the target name.
            // This also makes target-only hard links data inputs rather than
            // adopted authority. A partial nested pending can be discarded only
            // while a complete validated target remains available.
            if has_partial_pending {
                if !has_target {
                    return Err(run_error(
                        "AIW_WSB_DISCARD_STATE_INVALID",
                        "incomplete revocation binding blocks publication",
                        "revocation",
                        &self.run_id,
                    ));
                }
                self.verify_revocation_file_locked(&target, revocation, expected_hash)?;
                remove_pending(&pending_pending, &self.run_id)?;
            }
            write_complete_new(&pending, revocation, &self.run_id, "revocation")?;
        }
        self.verify_revocation_file_locked(&pending, revocation, expected_hash)?;

        if has_target {
            // Never adopt a recovered target inode. Removing an exact hard-link
            // name does not mutate the externally linked file contents.
            fs::remove_file(&target)
                .map_err(|error| storage_error("revocation", &self.run_id, error))?;
        }
        write_complete_direct_new(&target, revocation, &self.run_id, "revocation")?;
        self.verify_revocation_file_locked(&target, revocation, expected_hash)?;
        remove_pending(&pending, &self.run_id)
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
        let plan = self.read_plan_locked()?;
        self.validate_wsb_import_provenance_locked(&plan, "recovery")?;
        self.reject_if_wsb_discard_started_locked(&plan, "recovery")?;
        self.reject_internal_revocation_without_authority_locked(&plan, "recovery")?;
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

    fn validate_wsb_import_provenance_locked(
        &self,
        plan: &RunPlan,
        stage: &str,
    ) -> Result<(), AiwError> {
        if has_wsb_action(plan) {
            self.read_wsb_import_receipt_locked(plan, stage)?;
        }
        Ok(())
    }

    fn wsb_discard_started_locked(&self, _plan: &RunPlan) -> Result<bool, AiwError> {
        Ok(self.discard_control_present()? || self.has_internal_wsb_revocation_marker_locked()?)
    }

    fn discard_control_present(&self) -> Result<bool, AiwError> {
        Ok(self.current_discard_control_present()? || self.legacy_discard_control_present()?)
    }

    fn current_discard_control_present(&self) -> Result<bool, AiwError> {
        self.control_path_present(&self.wsb_discard_control_path()?)
    }

    fn legacy_discard_control_present(&self) -> Result<bool, AiwError> {
        self.control_path_present(&self.legacy_wsb_discard_control_path()?)
    }

    fn control_path_present(&self, path: &Path) -> Result<bool, AiwError> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(storage_error("revocation", &self.run_id, error)),
        }
    }

    fn reject_if_discard_control_present(&self, stage: &str) -> Result<(), AiwError> {
        if self.discard_control_present()? {
            return Err(run_error(
                "AIW_WSB_REVOKED",
                "run ID is irrevocably reserved for Windows Sandbox discard",
                stage,
                &self.run_id,
            ));
        }
        Ok(())
    }

    fn reject_if_wsb_discard_started_locked(
        &self,
        plan: &RunPlan,
        stage: &str,
    ) -> Result<(), AiwError> {
        if self.wsb_discard_started_locked(plan)? {
            return Err(run_error(
                "AIW_WSB_REVOKED",
                "Windows Sandbox run is irrevocably reserved for discard",
                stage,
                &self.run_id,
            ));
        }
        Ok(())
    }

    fn reject_internal_revocation_without_authority_locked(
        &self,
        plan: &RunPlan,
        stage: &str,
    ) -> Result<(), AiwError> {
        if !has_wsb_action(plan) || !self.has_internal_wsb_revocation_marker_locked()? {
            return Ok(());
        }
        Err(run_error(
            "AIW_WSB_DISCARD_AUTHORITY_MISSING",
            "Windows Sandbox revocation state exists without external discard authority",
            stage,
            &self.run_id,
        ))
    }

    fn has_internal_wsb_revocation_marker_locked(&self) -> Result<bool, AiwError> {
        let target = self.wsb_revocation_path();
        let pending = self.pending_path(&target);
        if optional_non_reparse_file(&target, &self.run_id, "revocation")?
            || optional_non_reparse_file(&pending, &self.run_id, "revocation")?
            || optional_non_reparse_file(&self.pending_path(&pending), &self.run_id, "revocation")?
        {
            return Ok(true);
        }

        match fs::symlink_metadata(self.journal_path()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(storage_error("revocation", &self.run_id, error)),
            Ok(_) => ensure_file(&self.journal_path(), &self.run_id, "revocation")?,
        }

        // This read is deliberately non-repairing. It recognizes a durable
        // revocation event even when a later journal write was interrupted,
        // preventing ordinary recovery from converting it into an abort after
        // the external authority has disappeared.
        let bytes = read_bounded(
            &self.journal_path(),
            MAX_JOURNAL,
            &self.run_id,
            "revocation",
        )?;
        let complete_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        if complete_len == 0 {
            return Ok(false);
        }
        for raw in bytes[..complete_len - 1].split(|byte| *byte == b'\n') {
            if serde_json::from_slice::<JournalRecord>(raw).is_ok_and(|record| {
                matches!(
                    record.event.kind,
                    RunEventKind::RevocationIntent | RunEventKind::RevocationRecorded
                )
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn repair_revocation_journal_locked(&self) -> Result<Vec<JournalRecord>, AiwError> {
        let plan = self.read_plan_locked()?;
        let plan_hash = plan.hash()?;
        let genesis_artifact_hash = self.expected_genesis_artifact_hash_locked(&plan)?;
        let bytes = read_bounded(
            &self.journal_path(),
            MAX_JOURNAL,
            &self.run_id,
            "revocation",
        )?;
        let complete_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        let mut records = Vec::new();
        if complete_len > 0 {
            for raw in bytes[..complete_len - 1].split(|byte| *byte == b'\n') {
                if raw.is_empty() || raw.len() > MAX_LINE || records.len() >= MAX_RECORDS {
                    return Err(journal_error(
                        &self.run_id,
                        "revocation journal input is invalid or exceeds its bound",
                    ));
                }
                let record: JournalRecord = serde_json::from_slice(raw)
                    .map_err(|error| journal_error(&self.run_id, error.to_string()))?;
                verify_record(&record, records.last(), &self.run_id, &plan_hash)?;
                records.push(record);
            }
        }
        if records.is_empty() {
            return Err(journal_error(&self.run_id, "journal has no genesis record"));
        }
        validate_grammar(&records, &self.run_id, &genesis_artifact_hash)?;
        let lifecycle_is_revocation_only = records.len() == 1
            || (records.len() == 2 && records[1].event.kind == RunEventKind::RevocationIntent)
            || (records.len() == 3
                && records[1].event.kind == RunEventKind::RevocationIntent
                && records[2].event.kind == RunEventKind::RevocationRecorded);
        if !lifecycle_is_revocation_only {
            return Err(run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "external discard authority conflicts with the journal lifecycle",
                "revocation",
                &self.run_id,
            ));
        }
        self.preflight_revocation_head_repair_locked(&records)?;
        self.load_records(true)
    }

    /// Bound counterpart to revocation journal recovery.  It deliberately
    /// does not call the ordinary journal repair path because that path may
    /// create head files by pathname.  The run and heads handles have already
    /// been rebound from the live preparation workspace.
    #[cfg(windows)]
    fn repair_revocation_journal_bound_locked(
        &self,
        workspace: &HeldRunWorkspace,
    ) -> Result<Vec<JournalRecord>, AiwError> {
        let plan = self.read_plan_locked()?;
        let plan_hash = plan.hash()?;
        let genesis_artifact_hash = self.expected_genesis_artifact_hash_locked(&plan)?;
        let (run, heads) = self.bind_wsb_revocation_run_directories(workspace)?;
        let bytes = read_bounded(
            &self.journal_path(),
            MAX_JOURNAL,
            &self.run_id,
            "revocation",
        )?;
        let complete_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        let mut records = Vec::new();
        if complete_len > 0 {
            for raw in bytes[..complete_len - 1].split(|byte| *byte == b'\n') {
                if raw.is_empty() || raw.len() > MAX_LINE || records.len() >= MAX_RECORDS {
                    return Err(journal_error(
                        &self.run_id,
                        "revocation journal input is invalid or exceeds its bound",
                    ));
                }
                let record: JournalRecord = serde_json::from_slice(raw)
                    .map_err(|error| journal_error(&self.run_id, error.to_string()))?;
                verify_record(&record, records.last(), &self.run_id, &plan_hash)?;
                records.push(record);
            }
        }
        if records.is_empty() {
            return Err(journal_error(&self.run_id, "journal has no genesis record"));
        }
        validate_grammar(&records, &self.run_id, &genesis_artifact_hash)?;
        let lifecycle_is_revocation_only = records.len() == 1
            || (records.len() == 2 && records[1].event.kind == RunEventKind::RevocationIntent)
            || (records.len() == 3
                && records[1].event.kind == RunEventKind::RevocationIntent
                && records[2].event.kind == RunEventKind::RevocationRecorded);
        if !lifecycle_is_revocation_only {
            return Err(run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "external discard authority conflicts with the journal lifecycle",
                "revocation",
                &self.run_id,
            ));
        }
        self.preflight_revocation_head_repair_locked(&records)?;
        if complete_len != bytes.len() {
            let journal = run
                .reopen_file("events.jsonl")
                .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
            journal
                .revalidate()
                .map_err(|error| workspace_storage_error("revocation", &self.run_id, error))?;
            journal
                .as_file()
                .set_len(complete_len as u64)
                .and_then(|_| journal.as_file().sync_all())
                .map_err(|error| storage_error("revocation", &self.run_id, error))?;
        }
        for record in &records {
            let head = JournalHead {
                schema: HEAD_SCHEMA.into(),
                run_id: record.run_id.clone(),
                plan_hash: record.plan_hash.clone(),
                sequence: record.sequence,
                hash: record.hash.clone(),
            };
            let head_bytes = json_file_bytes(&head, &self.run_id)?;
            reconcile_bound_wsb_file(
                &heads,
                &head_name(record.sequence),
                &head_bytes,
                &self.run_id,
            )?;
        }
        Ok(records)
    }

    fn preflight_revocation_head_repair_locked(
        &self,
        records: &[JournalRecord],
    ) -> Result<(), AiwError> {
        ensure_directory(&self.heads_dir(), &self.run_id, "revocation")?;
        let expected = records
            .iter()
            .map(|record| (head_name(record.sequence), record))
            .collect::<BTreeMap<_, _>>();
        for entry in fs::read_dir(self.heads_dir())
            .map_err(|error| storage_error("revocation", &self.run_id, error))?
        {
            let path = entry
                .map_err(|error| storage_error("revocation", &self.run_id, error))?
                .path();
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| journal_error(&self.run_id, "journal head name is invalid"))?;
            let committed_name = name.strip_suffix(".pending").unwrap_or(name);
            let Some(record) = expected.get(committed_name) else {
                return Err(journal_error(
                    &self.run_id,
                    "unexpected journal head blocks revocation recovery",
                ));
            };
            ensure_file(&path, &self.run_id, "revocation")?;
            if name.ends_with(".pending") {
                continue;
            }
            let head: JournalHead = read_json(&path, MAX_ARTIFACT, &self.run_id, "revocation")?;
            validate_head(&head, &self.run_id)?;
            if head.sequence != record.sequence
                || head.run_id != record.run_id
                || head.plan_hash != record.plan_hash
                || head.hash != record.hash
            {
                return Err(run_error(
                    "AIW_JOURNAL_TAMPERED",
                    "journal head differs from its record",
                    "revocation",
                    &self.run_id,
                ));
            }
        }
        Ok(())
    }

    fn revoked_status_locked(&self, plan: &RunPlan) -> Result<RecoveryStatus, AiwError> {
        self.validate_wsb_import_provenance_locked(plan, "status")?;
        if self.approval_path().exists()
            || self.cancellation_path().exists()
            || self.result_path().exists()
        {
            return Err(run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "external discard authority conflicts with existing lifecycle state",
                "status",
                &self.run_id,
            ));
        }
        let records = self.load_records(false)?;
        self.verify_committed(&records)?;
        let lifecycle_is_revocation_only = records.len() == 1
            || (records.len() == 2 && records[1].event.kind == RunEventKind::RevocationIntent)
            || (records.len() == 3
                && records[1].event.kind == RunEventKind::RevocationIntent
                && records[2].event.kind == RunEventKind::RevocationRecorded);
        if !lifecycle_is_revocation_only {
            return Err(run_error(
                "AIW_WSB_DISCARD_STATE_INVALID",
                "external discard authority conflicts with the journal lifecycle",
                "status",
                &self.run_id,
            ));
        }
        let last_sequence = records.last().map_or(0, |record| record.sequence);
        let revocation = if !self.legacy_discard_control_present()?
            && records
                .iter()
                .any(|record| record.event.kind == RunEventKind::RevocationRecorded)
        {
            let import = self.read_wsb_import_receipt_locked(plan, "status")?;
            let value: WsbRevocationRecord = read_json(
                &self.wsb_revocation_path(),
                MAX_ARTIFACT,
                &self.run_id,
                "status",
            )?;
            validate_wsb_revocation(&value, plan, &import, self)?;
            Some(Box::new(value))
        } else {
            None
        };
        Ok(RecoveryStatus::RevokedPendingDiscard {
            revocation,
            last_sequence,
        })
    }

    fn read_wsb_import_receipt_locked(
        &self,
        plan: &RunPlan,
        stage: &str,
    ) -> Result<WsbPlanningImportReceipt, AiwError> {
        let receipt: WsbPlanningImportReceipt = read_json(
            &self.wsb_planning_import_path(),
            MAX_ARTIFACT,
            &self.run_id,
            stage,
        )?;
        validate_wsb_import(&receipt, plan)?;
        Ok(receipt)
    }

    fn expected_genesis_artifact_hash_locked(&self, plan: &RunPlan) -> Result<String, AiwError> {
        if has_wsb_action(plan) {
            hash_value(&self.read_wsb_import_receipt_locked(plan, "journal")?)
        } else {
            plan.hash()
        }
    }

    fn intent_target(&self, kind: RunEventKind) -> PathBuf {
        match kind {
            RunEventKind::RevocationIntent => self.wsb_revocation_path(),
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
            RunEventKind::RevocationIntent => {
                let plan = self.read_plan_locked()?;
                let import = self.read_wsb_import_receipt_locked(&plan, "recovery")?;
                let value: WsbRevocationRecord =
                    read_json(path, MAX_ARTIFACT, &self.run_id, "recovery")?;
                validate_wsb_revocation(&value, &plan, &import, self)?;
                hash_value(&value)?
            }
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
        let mut revocation_committed = false;
        let mut cancellation_committed = false;
        let mut terminal_committed = false;
        for record in records {
            let intent = match record.event.kind {
                RunEventKind::RevocationRecorded => {
                    revocation_committed = true;
                    Some(RunEventKind::RevocationIntent)
                }
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
                RunEventKind::RevocationIntent,
                self.wsb_revocation_path(),
                revocation_committed,
            ),
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
        let plan = self.read_plan_locked()?;
        let plan_hash = plan.hash()?;
        let genesis_artifact_hash = self.expected_genesis_artifact_hash_locked(&plan)?;
        let sequence = records.last().map_or(1, |record| record.sequence + 1);
        let previous = records
            .last()
            .map_or(ZERO_HASH, |record| record.hash.as_str());
        let record = build_record(&self.run_id, &plan_hash, sequence, previous, event)?;
        records.push(record.clone());
        validate_grammar(&records, &self.run_id, &genesis_artifact_hash)?;
        append_raw(&self.journal_path(), &record, &self.run_id)?;
        write_head(&self.heads_dir(), &record, &self.run_id)?;
        Ok(record)
    }

    fn load_records(&self, repair_tail: bool) -> Result<Vec<JournalRecord>, AiwError> {
        let plan = self.read_plan_locked()?;
        let plan_hash = plan.hash()?;
        let genesis_artifact_hash = self.expected_genesis_artifact_hash_locked(&plan)?;
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
        self.verify_heads(&records, repair_tail)?;
        if records.is_empty() {
            return Err(journal_error(&self.run_id, "journal has no genesis record"));
        }
        validate_grammar(&records, &self.run_id, &genesis_artifact_hash)?;
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

    fn verify_heads(&self, records: &[JournalRecord], repair: bool) -> Result<(), AiwError> {
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
                if repair {
                    fs::remove_file(&path)
                        .map_err(|error| storage_error("journal", &self.run_id, error))?;
                    continue;
                }
                return Err(journal_error(
                    &self.run_id,
                    "journal head recovery is required",
                ));
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
        if highest as usize != records.len() && !repair {
            return Err(journal_error(
                &self.run_id,
                "journal head recovery is required",
            ));
        }
        if repair {
            for record in records.iter().skip(highest as usize) {
                write_head(&self.heads_dir(), record, &self.run_id)?;
            }
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
    RecoveryRequired {
        pending_event: RunEventKind,
        last_sequence: u64,
    },
    PendingApproval {
        plan_hash: String,
        last_sequence: u64,
    },
    RevokedPendingDiscard {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revocation: Option<Box<WsbRevocationRecord>>,
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

/// The immutable lifecycle artifacts for a run whose terminal journal commit
/// is currently visible.  This is an in-process view only; callers that need
/// a wire representation should serialize the individual validated artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedRunSnapshot {
    pub plan: RunPlan,
    pub approval: ApprovalRecord,
    pub result: RunResult,
}

fn validate_plan(plan: &RunPlan) -> Result<(), AiwError> {
    let has_bambu_action = plan.actions.iter().any(|action| {
        matches!(
            action,
            PlannedAction::ExecuteWindowsSandboxImportedBambuScenario { .. }
        )
    });
    let has_msi_action = plan.actions.iter().any(|action| {
        matches!(
            action,
            PlannedAction::ExecuteWindowsSandboxImportedMsiScenario { .. }
        )
    });
    let expected_schema = if has_bambu_action {
        IMPORTED_BAMBU_RUN_PLAN_SCHEMA_VERSION
    } else if has_msi_action {
        IMPORTED_MSI_RUN_PLAN_SCHEMA_VERSION
    } else {
        RUN_PLAN_SCHEMA_VERSION
    };
    if plan.schema != expected_schema {
        return Err(run_error(
            "AIW_PLAN_SCHEMA_UNSUPPORTED",
            if has_bambu_action {
                "Bambu Windows Sandbox plans require the imported-scenario schema"
            } else if has_msi_action {
                "MSI Windows Sandbox plans require the imported-scenario schema"
            } else {
                "run plan schema is unsupported or does not match its action profile"
            },
            "plan",
            &plan.run_id,
        ));
    }
    validate_id("runId", &plan.run_id)?;
    validate_id("projectId", &plan.project_id)?;
    validate_hash(
        &plan.project_revision_hash,
        "projectRevisionHash",
        &plan.run_id,
    )?;
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
    let mut wsb_action_count = 0usize;
    for action in &plan.actions {
        if is_wsb_action(action) {
            wsb_action_count += 1;
        }
        match action {
            PlannedAction::ExecuteScenario { scenario_id } => {
                validate_id("scenarioId", scenario_id)?
            }
            PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
            } => {
                for (field, hash) in [
                    ("sandboxPlanSha256", sandbox_plan_sha256),
                    ("providerSha256", provider_sha256),
                    ("guestAgentSha256", guest_agent_sha256),
                    ("workspaceIdentitySha256", workspace_identity_sha256),
                ] {
                    if !is_hash(hash) {
                        return Err(run_error(
                            "AIW_PLAN_BINDING_INVALID",
                            "Windows Sandbox golden-probe binding is invalid",
                            field,
                            &plan.run_id,
                        ));
                    }
                }
                if workspace.validate().is_err()
                    || hash_value(workspace)? != *workspace_identity_sha256
                {
                    return Err(run_error(
                        "AIW_PLAN_BINDING_INVALID",
                        "Windows Sandbox workspace evidence is invalid or does not match its hash",
                        "workspace",
                        &plan.run_id,
                    ));
                }
            }
            PlannedAction::ExecuteWindowsSandboxImportedMsiScenario {
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
                import_receipt_sha256,
                application_sha256,
                scenario_sha256,
            } => {
                for (field, hash) in [
                    ("sandboxPlanSha256", sandbox_plan_sha256),
                    ("providerSha256", provider_sha256),
                    ("guestAgentSha256", guest_agent_sha256),
                    ("workspaceIdentitySha256", workspace_identity_sha256),
                    ("importReceiptSha256", import_receipt_sha256),
                    ("applicationSha256", application_sha256),
                    ("scenarioSha256", scenario_sha256),
                ] {
                    if !is_hash(hash) {
                        return Err(run_error(
                            "AIW_PLAN_BINDING_INVALID",
                            "Windows Sandbox MSI scenario binding is invalid",
                            field,
                            &plan.run_id,
                        ));
                    }
                }
                if workspace.validate().is_err()
                    || hash_value(workspace)? != *workspace_identity_sha256
                {
                    return Err(run_error(
                        "AIW_PLAN_BINDING_INVALID",
                        "Windows Sandbox workspace evidence is invalid or does not match its hash",
                        "workspace",
                        &plan.run_id,
                    ));
                }
            }
            PlannedAction::ExecuteWindowsSandboxImportedBambuScenario {
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
                import_receipt_sha256,
                application_sha256,
                scenario_sha256,
            } => {
                for (field, hash) in [
                    ("sandboxPlanSha256", sandbox_plan_sha256),
                    ("providerSha256", provider_sha256),
                    ("guestAgentSha256", guest_agent_sha256),
                    ("workspaceIdentitySha256", workspace_identity_sha256),
                    ("importReceiptSha256", import_receipt_sha256),
                    ("applicationSha256", application_sha256),
                    ("scenarioSha256", scenario_sha256),
                ] {
                    if !is_hash(hash) {
                        return Err(run_error(
                            "AIW_PLAN_BINDING_INVALID",
                            "Windows Sandbox Bambu scenario binding is invalid",
                            field,
                            &plan.run_id,
                        ));
                    }
                }
                if workspace.validate().is_err()
                    || hash_value(workspace)? != *workspace_identity_sha256
                {
                    return Err(run_error(
                        "AIW_PLAN_BINDING_INVALID",
                        "Windows Sandbox workspace evidence is invalid or does not match its hash",
                        "workspace",
                        &plan.run_id,
                    ));
                }
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
    if wsb_action_count > 1 {
        return Err(run_error(
            "AIW_PLAN_BINDING_INVALID",
            "a run plan may contain at most one Windows Sandbox profile action",
            "actions",
            &plan.run_id,
        ));
    }
    for delta in &plan.trust_deltas {
        validate_text("trustDelta", delta, &plan.run_id)?;
    }
    Ok(())
}

fn is_wsb_action(action: &PlannedAction) -> bool {
    matches!(
        action,
        PlannedAction::ExecuteWindowsSandboxGoldenProbe { .. }
            | PlannedAction::ExecuteWindowsSandboxImportedMsiScenario { .. }
            | PlannedAction::ExecuteWindowsSandboxImportedBambuScenario { .. }
    )
}

fn has_wsb_action(plan: &RunPlan) -> bool {
    plan.actions.iter().any(is_wsb_action)
}

fn wsb_action(plan: &RunPlan) -> Result<Option<&PlannedAction>, AiwError> {
    let mut found = None;
    for action in &plan.actions {
        if is_wsb_action(action) {
            if found.is_some() {
                return Err(run_error(
                    "AIW_WSB_IMPORT_INVALID",
                    "verified import requires exactly one Windows Sandbox profile action",
                    "create",
                    &plan.run_id,
                ));
            }
            found = Some(action);
        }
    }
    Ok(found)
}

fn wsb_workspace(plan: &RunPlan) -> Result<&WorkspaceBindingEvidence, AiwError> {
    let action = wsb_action(plan)?.ok_or_else(|| {
        run_error(
            "AIW_WSB_REVOCATION_INVALID",
            "Windows Sandbox revocation has no workspace binding",
            "revocation",
            &plan.run_id,
        )
    })?;
    match action {
        PlannedAction::ExecuteWindowsSandboxGoldenProbe { workspace, .. }
        | PlannedAction::ExecuteWindowsSandboxImportedMsiScenario { workspace, .. }
        | PlannedAction::ExecuteWindowsSandboxImportedBambuScenario { workspace, .. } => {
            Ok(workspace.as_ref())
        }
        _ => unreachable!("wsb_action only returns WSB profile actions"),
    }
}

fn validate_wsb_import(receipt: &WsbPlanningImportReceipt, plan: &RunPlan) -> Result<(), AiwError> {
    validate_plan(plan)?;
    let action = wsb_action(plan)?.ok_or_else(|| {
        run_error(
            "AIW_WSB_IMPORT_INVALID",
            "verified import requires exactly one Windows Sandbox action",
            "create",
            &plan.run_id,
        )
    })?;
    let (
        receipt_schema,
        sandbox_plan_sha256,
        provider_sha256,
        guest_agent_sha256,
        workspace,
        workspace_identity_sha256,
    ) = match action {
        PlannedAction::ExecuteWindowsSandboxGoldenProbe {
            sandbox_plan_sha256,
            provider_sha256,
            guest_agent_sha256,
            workspace,
            workspace_identity_sha256,
        } => (
            WSB_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION,
            sandbox_plan_sha256,
            provider_sha256,
            guest_agent_sha256,
            workspace,
            workspace_identity_sha256,
        ),
        PlannedAction::ExecuteWindowsSandboxImportedMsiScenario {
            sandbox_plan_sha256,
            provider_sha256,
            guest_agent_sha256,
            workspace,
            workspace_identity_sha256,
            ..
        } => (
            WSB_MSI_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION,
            sandbox_plan_sha256,
            provider_sha256,
            guest_agent_sha256,
            workspace,
            workspace_identity_sha256,
        ),
        PlannedAction::ExecuteWindowsSandboxImportedBambuScenario {
            sandbox_plan_sha256,
            provider_sha256,
            guest_agent_sha256,
            workspace,
            workspace_identity_sha256,
            ..
        } => (
            WSB_BAMBU_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION,
            sandbox_plan_sha256,
            provider_sha256,
            guest_agent_sha256,
            workspace,
            workspace_identity_sha256,
        ),
        _ => unreachable!("wsb_action only returns WSB profile actions"),
    };
    if receipt.schema_version != receipt_schema
        || receipt.run_id != plan.run_id
        || receipt.status != WsbPlanningImportStatus::PendingApproval
        || receipt.project_revision_sha256 != plan.project_revision_hash
        || receipt.workspace_root != workspace.root.final_path
        || receipt.run_root != receipt.workspace_root
        || receipt.workspace_identity_sha256 != *workspace_identity_sha256
        || receipt.run_plan_sha256 != plan.hash()?
        || receipt.windows_sandbox_plan_sha256 != *sandbox_plan_sha256
        || receipt.guest_agent_sha256 != *guest_agent_sha256
        || receipt.provider_sha256 != *provider_sha256
        || receipt.journal_sequence != 1
        || receipt.approval_present
        || receipt.provider_acquired
        || receipt.provider_mutated
    {
        return Err(run_error(
            "AIW_WSB_IMPORT_INVALID",
            "Windows Sandbox import receipt is not bound to the exact pending plan",
            "create",
            &plan.run_id,
        ));
    }
    validate_text("importedAt", &receipt.imported_at, &plan.run_id)?;
    for (field, value) in [
        (
            "preparationReceiptSha256",
            &receipt.preparation_receipt_sha256,
        ),
        ("runPlanSha256", &receipt.run_plan_sha256),
        (
            "windowsSandboxPlanSha256",
            &receipt.windows_sandbox_plan_sha256,
        ),
        (
            "workspaceIdentitySha256",
            &receipt.workspace_identity_sha256,
        ),
        ("guestAgentSha256", &receipt.guest_agent_sha256),
        ("providerSha256", &receipt.provider_sha256),
    ] {
        validate_hash(value, field, &plan.run_id)?;
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
                | PlannedAction::ExecuteWindowsSandboxGoldenProbe { .. }
                | PlannedAction::ExecuteWindowsSandboxImportedMsiScenario { .. }
                | PlannedAction::ExecuteWindowsSandboxImportedBambuScenario { .. }
                | PlannedAction::CollectEvidence
        ),
        RunLifecycleKind::Launch => matches!(
            action,
            PlannedAction::AssessHost
                | PlannedAction::PrepareWorkspace
                | PlannedAction::LaunchValidatedProfile { .. }
                | PlannedAction::ExecuteWindowsSandboxImportedMsiScenario { .. }
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

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
            | RunEventKind::RevocationIntent
            | RunEventKind::RevocationRecorded
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

fn validate_wsb_revocation(
    value: &WsbRevocationRecord,
    plan: &RunPlan,
    import: &WsbPlanningImportReceipt,
    layout: &RunLayout,
) -> Result<(), AiwError> {
    let workspace = wsb_workspace(plan)?;
    let expected_control = layout.wsb_discard_control_path()?;
    validate_wsb_revocation_shape(value, workspace, &expected_control)?;
    let binding = &value.discard_intent_binding;
    #[cfg(windows)]
    let valid_coordination = binding.store_key == layout.coordination_key.binding_sha256();
    #[cfg(not(windows))]
    let valid_coordination = layout
        .wsb_discard_control_path()?
        .file_name()
        .and_then(|value| value.to_str())
        .and_then(|value| value.strip_prefix(WSB_DISCARD_CURRENT_PREFIX))
        .is_some_and(|value| value == binding.store_key);
    if value.run_id != plan.run_id
        || value.plan_sha256 != plan.hash()?
        || value.import_receipt_sha256 != hash_value(import)?
        || value.workspace_identity_sha256 != import.workspace_identity_sha256
        || !valid_coordination
        || !same_path_text(
            &binding.final_path,
            &layout.wsb_discard_control_path()?.to_string_lossy(),
        )
    {
        return Err(run_error(
            "AIW_WSB_REVOCATION_INVALID",
            "Windows Sandbox revocation bindings are invalid",
            "revocation",
            &plan.run_id,
        ));
    }
    Ok(())
}

fn validate_wsb_revocation_shape(
    value: &WsbRevocationRecord,
    workspace: &WorkspaceBindingEvidence,
    expected_control: &Path,
) -> Result<(), AiwError> {
    let binding = &value.discard_intent_binding;
    let valid_stage_leaf = binding
        .staging_leaf
        .strip_prefix(&format!("{WSB_DISCARD_STAGE_PREFIX}{}-", binding.store_key))
        .is_some_and(|suffix| suffix.len() == 16 && is_hash_fragment(suffix));
    let valid_parent_id = binding.parent_id.volume_serial_number
        == workspace.parent.volume_serial_number
        && binding.parent_id.file_id == workspace.parent.file_id;
    let valid_intent_id = binding.intent_id.volume_serial_number.len() == 16
        && binding.intent_id.file_id.len() == 32
        && is_hash_fragment(&binding.intent_id.volume_serial_number)
        && is_hash_fragment(&binding.intent_id.file_id)
        && binding.intent_id.volume_serial_number == binding.parent_id.volume_serial_number
        && binding.intent_id.file_id != binding.parent_id.file_id;
    if value.schema_version != WSB_REVOCATION_SCHEMA_VERSION
        || workspace.validate().is_err()
        || value.run_id.is_empty()
        || binding.schema_version != DISCARD_INTENT_BINDING_SCHEMA_VERSION
        || binding.policy_version != DISCARD_INTENT_BINDING_POLICY_VERSION
        || binding.run_id != value.run_id
        || binding.owner_sid != workspace.owner_sid
        || binding.store_key.len() != 64
        || !is_hash_fragment(&binding.store_key)
        || binding.intent_sha256 != value.discard_intent_sha256
        || binding.intent_size == 0
        || binding.intent_size > MAX_DISCARD_INTENT_BYTES
        || !valid_stage_leaf
        || !valid_parent_id
        || !valid_intent_id
        || !validate_discard_intent_ea(&binding.intent_ea)
        || !same_path_text(&binding.final_path, &expected_control.to_string_lossy())
        || value.workspace_identity_sha256 != hash_value(workspace)?
    {
        return Err(run_error(
            "AIW_WSB_REVOCATION_INVALID",
            "Windows Sandbox revocation shape is invalid",
            "revocation",
            &value.run_id,
        ));
    }
    validate_hash(&value.cleanup_id, "cleanupId", &value.run_id)?;
    validate_hash(
        &value.discard_intent_sha256,
        "discardIntentSha256",
        &value.run_id,
    )?;
    validate_hash(&value.plan_sha256, "planSha256", &value.run_id)?;
    validate_hash(
        &value.import_receipt_sha256,
        "importReceiptSha256",
        &value.run_id,
    )?;
    validate_hash(
        &value.workspace_identity_sha256,
        "workspaceIdentitySha256",
        &value.run_id,
    )?;
    validate_text("requestedBy", &value.requested_by, &value.run_id)?;
    validate_text("requestedAt", &value.requested_at, &value.run_id)
}

fn validate_discard_intent_ea(ea: &aiw_probe::DiscardIntentEaBinding) -> bool {
    let valid_names = ea.entries.is_empty()
        || (ea.entries.len() == 2
            && ea.entries[0].name == "$KERNEL.PURGE.SMARTLOCKER.VALID"
            && ea.entries[1].name == "$KERNEL.SMARTLOCKER.ORIGINCLAIM");
    let valid_query = if ea.entries.is_empty() {
        ea.queried_bytes == 0
    } else {
        ea.queried_bytes > 0 && ea.queried_bytes <= 64 * 1024
    };
    if !valid_names || !valid_query {
        return false;
    }

    let mut canonical = Vec::new();
    for entry in &ea.entries {
        let Ok(name_len) = u16::try_from(entry.name.len()) else {
            return false;
        };
        let valid_length = if entry.name == "$KERNEL.PURGE.SMARTLOCKER.VALID" {
            entry.value_length == 4
        } else {
            entry.value_length > 0
        };
        if !is_fixed_lower_hex(&entry.value_sha256, 64) {
            return false;
        }
        let Ok(value_hash) = hex::decode(&entry.value_sha256) else {
            return false;
        };
        if entry.flags != 0 || !valid_length || value_hash.len() != 32 {
            return false;
        }
        canonical.extend_from_slice(&name_len.to_le_bytes());
        canonical.extend_from_slice(entry.name.as_bytes());
        canonical.push(entry.flags);
        canonical.extend_from_slice(&entry.value_length.to_le_bytes());
        canonical.extend_from_slice(&value_hash);
    }
    is_fixed_lower_hex(&ea.canonical_sha256, 64)
        && ea.canonical_sha256 == hex::encode(Sha256::digest(&canonical))
}

fn is_hash_fragment(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn same_path_text(left: &str, right: &str) -> bool {
    fn normalized(value: &str) -> String {
        let value = value.replace('/', "\\");
        value
            .strip_prefix(r"\\?\")
            .unwrap_or(&value)
            .trim_end_matches('\\')
            .to_owned()
    }
    normalized(left).eq_ignore_ascii_case(&normalized(right))
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

fn is_fixed_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Hashes the canonical, validated project wire representation bound into a run plan.
pub fn project_revision_hash(project: &Project) -> Result<String, AiwError> {
    hash_value(project)
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
    genesis_artifact_hash: &str,
) -> Result<(), AiwError> {
    let first = records
        .first()
        .ok_or_else(|| journal_error(run_id, "missing genesis"))?;
    if first.event.kind != RunEventKind::Created
        || first.event.artifact_hash.as_deref() != Some(genesis_artifact_hash)
    {
        return Err(journal_error(run_id, "invalid genesis"));
    }
    let mut approved = false;
    let mut revoked = false;
    let mut cancelled = false;
    let mut terminal = false;
    let mut pending: Option<(RunEventKind, &str)> = None;
    for (index, record) in records.iter().enumerate() {
        if index == 0 {
            continue;
        }
        if terminal || revoked {
            return Err(journal_error(
                run_id,
                "event follows terminal or revocation commit",
            ));
        }
        match record.event.kind {
            RunEventKind::Created => return Err(journal_error(run_id, "duplicate genesis")),
            RunEventKind::RevocationIntent => {
                if approved || cancelled || pending.is_some() {
                    return Err(journal_error(run_id, "revocation intent out of order"));
                }
                pending = Some((
                    record.event.kind,
                    record.event.artifact_hash.as_deref().unwrap_or_default(),
                ));
            }
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
            RunEventKind::RevocationRecorded => {
                match_intent(
                    &mut pending,
                    RunEventKind::RevocationIntent,
                    &record.event,
                    run_id,
                )?;
                revoked = true;
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
        RunEventKind::RevocationIntent
            | RunEventKind::ApprovalIntent
            | RunEventKind::CancellationIntent
            | RunEventKind::TerminalIntent
    )
}

fn commit_for(kind: RunEventKind) -> RunEventKind {
    match kind {
        RunEventKind::RevocationIntent => RunEventKind::RevocationRecorded,
        RunEventKind::ApprovalIntent => RunEventKind::ApprovalRecorded,
        RunEventKind::CancellationIntent => RunEventKind::CancellationRequested,
        RunEventKind::TerminalIntent => RunEventKind::TerminalRecorded,
        _ => unreachable!("validated intent"),
    }
}

#[cfg(windows)]
fn bind_or_create_root_directory(
    workspace: &HeldRunWorkspace,
    leaf: &str,
    run_id: &str,
    stage: &'static str,
) -> Result<BoundWorkspaceDirectory, AiwError> {
    match workspace.create_root_directory_new_with_policy(leaf, WorkspaceAclPolicy::Inherited) {
        Ok(created) => {
            let identity = created.identity().clone();
            drop(created);
            let bound = workspace
                .reopen_root_directory(leaf, WorkspaceAclPolicy::Inherited)
                .map_err(|error| workspace_storage_error(stage, run_id, error))?;
            if bound.identity() != &identity {
                return Err(path_error(
                    "created directory identity changed",
                    run_id,
                    bound.final_path(),
                ));
            }
            Ok(bound)
        }
        Err(aiw_windows_platform::WorkspaceError::AlreadyExists) => workspace
            .reopen_root_directory(leaf, WorkspaceAclPolicy::Inherited)
            .map_err(|error| workspace_storage_error(stage, run_id, error)),
        Err(error) => Err(workspace_storage_error(stage, run_id, error)),
    }
}

#[cfg(windows)]
fn bind_or_create_directory(
    parent: &BoundWorkspaceDirectory,
    leaf: &str,
    run_id: &str,
    stage: &'static str,
) -> Result<BoundWorkspaceDirectory, AiwError> {
    match parent.create_directory_new_with_policy(leaf, WorkspaceAclPolicy::Inherited) {
        Ok(created) => {
            let identity = created.identity().clone();
            drop(created);
            let bound = parent
                .reopen_directory(leaf, WorkspaceAclPolicy::Inherited)
                .map_err(|error| workspace_storage_error(stage, run_id, error))?;
            if bound.identity() != &identity {
                return Err(path_error(
                    "created directory identity changed",
                    run_id,
                    bound.final_path(),
                ));
            }
            Ok(bound)
        }
        Err(aiw_windows_platform::WorkspaceError::AlreadyExists) => parent
            .reopen_directory(leaf, WorkspaceAclPolicy::Inherited)
            .map_err(|error| workspace_storage_error(stage, run_id, error)),
        Err(error) => Err(workspace_storage_error(stage, run_id, error)),
    }
}

#[cfg(windows)]
fn reconcile_bound_wsb_file(
    parent: &BoundWorkspaceDirectory,
    leaf: &str,
    expected: &[u8],
    run_id: &str,
) -> Result<(), AiwError> {
    let target = parent.final_path().join(leaf);
    let pending_leaf = format!("{leaf}.pending");
    let pending = parent.final_path().join(&pending_leaf);
    for (name, path) in [(leaf, &target), (&pending_leaf, &pending)] {
        if path.exists() {
            let bound = parent
                .reopen_file(name)
                .map_err(|error| workspace_storage_error("create", run_id, error))?;
            let mut observed = Vec::new();
            bound
                .as_file()
                .try_clone()
                .and_then(|mut file| file.read_to_end(&mut observed))
                .map_err(|error| storage_error("create", run_id, error))?;
            let valid = if name == leaf {
                observed == expected
            } else {
                expected.starts_with(&observed)
            };
            if !valid {
                return Err(run_error(
                    "AIW_WSB_IMPORT_STAGE_INVALID",
                    "Windows Sandbox import stage artifact differs from its expected crash prefix",
                    "create",
                    run_id,
                ));
            }
            // Existing valid prefixes are recovery inputs, never adopted as
            // authority. Remove only after the strict held rebind above.
            // The bound handle deliberately has no delete sharing, so close
            // it only after all identity and content checks have completed.
            drop(bound);
            fs::remove_file(path).map_err(|error| storage_error("create", run_id, error))?;
        }
    }
    let mut created = parent
        .create_file_new(&pending_leaf)
        .map_err(|error| workspace_storage_error("create", run_id, error))?;
    created
        .as_file_mut()
        .write_all(expected)
        .and_then(|_| created.as_file_mut().sync_all())
        .map_err(|error| storage_error("create", run_id, error))?;
    created
        .publish_into_bound(parent, leaf)
        .map_err(|error| workspace_storage_error("create", run_id, error))?;
    Ok(())
}

#[cfg(windows)]
fn validate_bound_wsb_stage_namespace(
    stage: &BoundWorkspaceDirectory,
    run_id: &str,
) -> Result<(), AiwError> {
    const ALLOWED: [&str; 7] = [
        "events.jsonl",
        "events.jsonl.pending",
        "journal-heads",
        "plan.json",
        "plan.json.pending",
        WSB_PLANNING_IMPORT_FILE,
        "wsb-planning-import.json.pending",
    ];
    stage
        .revalidate()
        .map_err(|error| workspace_storage_error("create", run_id, error))?;
    for entry in
        fs::read_dir(stage.final_path()).map_err(|error| storage_error("create", run_id, error))?
    {
        let name = entry
            .map_err(|error| storage_error("create", run_id, error))?
            .file_name()
            .into_string()
            .map_err(|_| {
                run_error(
                    "AIW_WSB_IMPORT_STAGE_INVALID",
                    "Windows Sandbox import stage contains a non-Unicode entry",
                    "create",
                    run_id,
                )
            })?;
        if !ALLOWED.contains(&name.as_str()) {
            return Err(run_error(
                "AIW_WSB_IMPORT_STAGE_INVALID",
                "Windows Sandbox import stage differs from its exact allowlist",
                "create",
                run_id,
            ));
        }
        if name == "journal-heads" {
            stage
                .reopen_directory(&name, WorkspaceAclPolicy::Inherited)
                .map_err(|error| workspace_storage_error("create", run_id, error))?;
        } else {
            stage
                .reopen_file(&name)
                .map_err(|error| workspace_storage_error("create", run_id, error))?;
        }
    }
    Ok(())
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
    let bytes = json_file_bytes(value, run_id)?;
    write_bytes_complete_new(path, &bytes, run_id, stage)
}

fn json_file_bytes<T: Serialize>(value: &T, run_id: &str) -> Result<Vec<u8>, AiwError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| serialization_error("create", run_id, error))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_ARTIFACT {
        return Err(run_error(
            "AIW_ARTIFACT_TOO_LARGE",
            "artifact exceeds storage bound",
            "create",
            run_id,
        ));
    }
    Ok(bytes)
}

fn write_bytes_complete_new(
    path: &Path,
    bytes: &[u8],
    run_id: &str,
    stage: &str,
) -> Result<(), AiwError> {
    if bytes.len() as u64 > MAX_JOURNAL {
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
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| storage_error(stage, run_id, error))?;
    publish_new(&pending, path, run_id, stage)
}

fn write_complete_direct_new<T: Serialize>(
    path: &Path,
    value: &T,
    run_id: &str,
    stage: &str,
) -> Result<(), AiwError> {
    let bytes = json_file_bytes(value, run_id)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            io_error(
                "AIW_WRITE_ONCE_CONFLICT",
                "write-once artifact exists or cannot be published",
                stage,
                run_id,
                error,
            )
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| storage_error(stage, run_id, error))
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

fn optional_non_reparse_directory(
    path: &Path,
    run_id: &str,
    stage: &str,
) -> Result<bool, AiwError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && !has_reparse_point(&metadata) =>
        {
            Ok(true)
        }
        Ok(_) => Err(path_error(
            "expected an absent or non-reparse directory",
            run_id,
            path,
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(storage_error(stage, run_id, error)),
    }
}

fn optional_non_reparse_file(path: &Path, run_id: &str, stage: &str) -> Result<bool, AiwError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && !has_reparse_point(&metadata) =>
        {
            Ok(true)
        }
        Ok(_) => Err(path_error(
            "expected an absent or non-reparse file",
            run_id,
            path,
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(storage_error(stage, run_id, error)),
    }
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

#[cfg(windows)]
fn workspace_storage_error(
    stage: &str,
    run_id: &str,
    error: aiw_windows_platform::WorkspaceError,
) -> AiwError {
    AiwError::new(
        "AIW_WORKSPACE_BINDING_FAILED",
        "held Windows workspace could not be validated or extended",
        stage,
        Some(run_id),
        false,
        "Do not modify the workspace; inspect the exact workspace identity and recover from an intact prefix.",
        error.to_string(),
    )
}

#[cfg(windows)]
fn coordination_error(stage: &str, run_id: &str, error: RunCoordinationError) -> AiwError {
    match error {
        RunCoordinationError::LeaseUnavailable => AiwError::new(
            "AIW_RUN_COORDINATION_TIMEOUT",
            "timed out waiting for another run operation",
            stage,
            Some(run_id),
            true,
            "Wait for the active operation to finish, then retry.",
            error.to_string(),
        ),
        RunCoordinationError::RecoveryRequired => AiwError::new(
            "AIW_RUN_RECOVERY_REQUIRED",
            "an abandoned run operation requires durable recovery",
            stage,
            Some(run_id),
            false,
            "Inspect persisted state and use the bounded recovery workflow before retrying.",
            error.to_string(),
        ),
        RunCoordinationError::InvalidBinding(_) | RunCoordinationError::Authority(_) => {
            AiwError::new(
                "AIW_RUN_COORDINATION_FAILED",
                "run coordination authority could not be established",
                stage,
                Some(run_id),
                false,
                "Do not mutate the run; inspect the canonical workspace identity and mutex security.",
                error.to_string(),
            )
        }
    }
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

    #[test]
    fn windows_verbatim_prefix_is_path_identity_not_drift() {
        assert!(same_path_text(r"C:\AIW\run-one", r"\\?\C:\AIW\run-one"));
        assert!(!same_path_text(r"C:\AIW\run-one", r"\\?\C:\AIW\run-two"));
    }
    #[cfg(windows)]
    use std::sync::mpsc;
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

    fn checkpoint_fixture() -> WsbDiscardCheckpointV0Alpha1 {
        let owner = "S-1-5-21-1".to_owned();
        let identity = |path: &str, marker: u8| aiw_probe::WindowsFileIdentity {
            final_path: path.to_owned(),
            volume_serial_number: "1".repeat(16),
            file_id: format!("{marker:032x}"),
        };
        let workspace = WorkspaceBindingEvidence {
            schema_version: aiw_probe::WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
            policy: aiw_probe::WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
            security_policy_sha256: aiw_probe::workspace_policy_hash(&owner),
            owner_sid: owner.clone(),
            dacl_protected: true,
            allowed_sids: vec![aiw_probe::WINDOWS_SYSTEM_SID.to_owned(), owner.clone()],
            parent: identity(r"C:\AIW", 1),
            root: identity(r"C:\AIW\workspace", 2),
            tools: identity(r"C:\AIW\workspace\tools", 3),
            output: identity(r"C:\AIW\workspace\output", 4),
        };
        let kinds = [
            (
                "workspaceRoot",
                ".",
                true,
                "ownerSystemProtected",
                "noStreams",
            ),
            (
                "toolsDirectory",
                "tools",
                true,
                "ownerSystemProtected",
                "noStreams",
            ),
            (
                "outputDirectory",
                "output",
                true,
                "ownerSystemProtected",
                "noStreams",
            ),
            (
                "runsDirectory",
                "runs",
                true,
                "ownerSystemInherited",
                "noStreams",
            ),
            (
                "locksDirectory",
                "runs/.locks",
                true,
                "ownerSystemInherited",
                "noStreams",
            ),
            (
                "runDirectory",
                "runs/run-one",
                true,
                "ownerSystemInherited",
                "noStreams",
            ),
            (
                "journalHeadsDirectory",
                "runs/run-one/journal-heads",
                true,
                "ownerSystemInherited",
                "noStreams",
            ),
            (
                "guestAgent",
                "tools/aiw-guest-agent.exe",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "preparedPlan",
                "plan.json",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "windowsSandboxPlan",
                "wsb-plan.json",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "preparationReceipt",
                "preparation.json",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "runLock",
                "runs/.locks/run-one.lock",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "authoritativePlan",
                "runs/run-one/plan.json",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "planningImportReceipt",
                "runs/run-one/wsb-planning-import.json",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "eventsJournal",
                "runs/run-one/events.jsonl",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "revocationRecord",
                "runs/run-one/wsb-revocation.json",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "journalHead1",
                "runs/run-one/journal-heads/00000000000000000001.json",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "journalHead2",
                "runs/run-one/journal-heads/00000000000000000002.json",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
            (
                "journalHead3",
                "runs/run-one/journal-heads/00000000000000000003.json",
                false,
                "ownerSystemInherited",
                "unnamedDataOnly",
            ),
        ];
        let empty_ea = hex::encode(Sha256::digest([]));
        let objects = kinds
            .iter()
            .enumerate()
            .map(|(index, (kind, path, directory, acl, stream))| {
                let marker = match index {
                    0 => 2,
                    1 => 3,
                    2 => 4,
                    _ => index as u8 + 5,
                };
                let mut value = serde_json::json!({
                    "kind": kind,
                    "relativePath": path,
                    "id": {"volumeSerialNumber": "1".repeat(16), "fileId": format!("{marker:032x}")},
                    "isDirectory": directory,
                    "attributes": if *directory { 16 } else { 32 },
                    "linkCount": 1,
                    "aclPolicy": acl,
                    "streamPolicy": stream,
                    "ea": {"entries": [], "canonicalSha256": empty_ea}
                });
                if !directory {
                    value["sizeBytes"] = serde_json::json!(if *kind == "runLock" { 0 } else { 1 });
                    value["sha256"] = serde_json::json!("a".repeat(64));
                }
                serde_json::from_value(value).unwrap()
            })
            .collect();
        let inventory = WsbFixedTreeInventoryEvidence {
            schema_version: aiw_probe::WSB_FIXED_TREE_INVENTORY_SCHEMA_VERSION.to_owned(),
            contract_version: WSB_FIXED_TREE_CONTRACT_VERSION.to_owned(),
            run_id: "run-one".to_owned(),
            workspace: workspace.clone(),
            parent_id: DiscardIntentStableId {
                volume_serial_number: workspace.parent.volume_serial_number.clone(),
                file_id: workspace.parent.file_id.clone(),
            },
            original_root: workspace.root.final_path.clone(),
            tombstone_leaf: format!(".aiw-discarded-v1-{}", "d".repeat(64)),
            objects,
        };
        assert!(inventory.validate().is_ok());
        let binding = DiscardIntentBindingEvidence {
            schema_version: DISCARD_INTENT_BINDING_SCHEMA_VERSION.to_owned(),
            policy_version: DISCARD_INTENT_BINDING_POLICY_VERSION.to_owned(),
            run_id: "run-one".to_owned(),
            owner_sid: owner,
            store_key: "c".repeat(64),
            final_path: format!(r"C:\AIW\.aiw-discard-v1-{}", "c".repeat(64)),
            staging_leaf: format!(".aiw-discard-stage-v1-{}-1234567890abcdef", "c".repeat(64)),
            parent_id: inventory.parent_id.clone(),
            intent_id: DiscardIntentStableId {
                volume_serial_number: "1".repeat(16),
                file_id: "e".repeat(32),
            },
            intent_size: 1,
            intent_sha256: "b".repeat(64),
            intent_ea: aiw_probe::DiscardIntentEaBinding {
                queried_bytes: 0,
                entries: vec![],
                canonical_sha256: empty_ea,
            },
        };
        let revocation = WsbRevocationRecord {
            schema_version: WSB_REVOCATION_SCHEMA_VERSION.to_owned(),
            run_id: "run-one".to_owned(),
            cleanup_id: "d".repeat(64),
            discard_intent_sha256: "b".repeat(64),
            discard_intent_binding: binding,
            plan_sha256: "1".repeat(64),
            import_receipt_sha256: "2".repeat(64),
            workspace_identity_sha256: hash_value(&workspace).unwrap(),
            requested_by: "admin".to_owned(),
            requested_at: "now".to_owned(),
        };
        WsbDiscardCheckpointV0Alpha1 {
            schema_version: WSB_DISCARD_CHECKPOINT_SCHEMA_VERSION.to_owned(),
            policy_version: WSB_DISCARD_CHECKPOINT_POLICY_VERSION.to_owned(),
            run_id: "run-one".to_owned(),
            cleanup_id: "d".repeat(64),
            fixed_tree_contract_version: WSB_FIXED_TREE_CONTRACT_VERSION.to_owned(),
            revocation_sha256: hash_value(&revocation).unwrap(),
            inventory_sha256: hash_value(&inventory).unwrap(),
            revocation,
            inventory,
            checkpoint_file: WsbDiscardCheckpointFileIdentity {
                parent_id: DiscardIntentStableId {
                    volume_serial_number: "1".repeat(16),
                    file_id: format!("{:032x}", 1),
                },
                file_id: DiscardIntentStableId {
                    volume_serial_number: "1".repeat(16),
                    file_id: "f".repeat(32),
                },
            },
        }
    }

    #[test]
    fn discard_checkpoint_cross_bindings_fail_closed() {
        let checkpoint = checkpoint_fixture();
        checkpoint.validate().unwrap();
        let mut changed = checkpoint.clone();
        changed.cleanup_id = "0".repeat(64);
        assert!(changed.validate().is_err());
        let mut changed = checkpoint.clone();
        changed.inventory_sha256 = "0".repeat(64);
        assert!(changed.validate().is_err());
        let mut changed = checkpoint.clone();
        changed.revocation.plan_sha256 = "0".repeat(64);
        assert!(changed.validate().is_err());
        let mut changed = checkpoint.clone();
        changed.revocation.discard_intent_binding.staging_leaf = "foreign".to_owned();
        changed.revocation_sha256 = hash_value(&changed.revocation).unwrap();
        assert!(changed.validate().is_err());
        let mut changed = checkpoint.clone();
        changed.revocation.discard_intent_binding.intent_id =
            changed.revocation.discard_intent_binding.parent_id.clone();
        changed.revocation_sha256 = hash_value(&changed.revocation).unwrap();
        assert!(changed.validate().is_err());
        let mut changed = checkpoint.clone();
        changed.revocation.discard_intent_binding.intent_size = 0;
        changed.revocation_sha256 = hash_value(&changed.revocation).unwrap();
        assert!(changed.validate().is_err());
        let mut changed = checkpoint.clone();
        changed.revocation.discard_intent_binding.intent_ea = aiw_probe::DiscardIntentEaBinding {
            queried_bytes: 64,
            entries: vec![aiw_probe::DiscardIntentEaEntry {
                name: "$KERNEL.PURGE.SMARTLOCKER.VALID".to_owned(),
                flags: 1,
                value_length: 4,
                value_sha256: "a".repeat(64),
            }],
            canonical_sha256: "a".repeat(64),
        };
        changed.revocation_sha256 = hash_value(&changed.revocation).unwrap();
        assert!(changed.validate().is_err());
        let mut changed = checkpoint.clone();
        changed.checkpoint_file.file_id = changed.inventory.objects[0].id.clone();
        assert!(changed.validate().is_err());
        let mut changed = checkpoint;
        changed.inventory.tombstone_leaf = format!(".aiw-discarded-v1-{}", "0".repeat(64));
        assert!(changed.validate().is_err());
    }

    fn plan(run_id: &str) -> RunPlan {
        RunPlan::new(
            run_id,
            "project.one",
            "f".repeat(64),
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

    fn wsb_workspace(run_id: &str) -> WorkspaceBindingEvidence {
        let owner = "S-1-5-21-1";
        let identity = |path: &str, marker: char| aiw_probe::WindowsFileIdentity {
            final_path: path.to_owned(),
            volume_serial_number: "1".repeat(16),
            file_id: marker.to_string().repeat(32),
        };
        WorkspaceBindingEvidence {
            schema_version: aiw_probe::WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
            policy: aiw_probe::WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
            security_policy_sha256: aiw_probe::workspace_policy_hash(owner),
            owner_sid: owner.to_owned(),
            dacl_protected: true,
            allowed_sids: vec![aiw_probe::WINDOWS_SYSTEM_SID.to_owned(), owner.to_owned()],
            parent: identity(r"C:\AIW", '1'),
            root: identity(&format!(r"C:\AIW\{run_id}"), '2'),
            tools: identity(&format!(r"C:\AIW\{run_id}\tools"), '3'),
            output: identity(&format!(r"C:\AIW\{run_id}\output"), '4'),
        }
    }

    fn wsb_plan(run_id: &str) -> RunPlan {
        let workspace = wsb_workspace(run_id);
        let workspace_identity_sha256 = hash_value(&workspace).unwrap();
        RunPlan::new(
            run_id,
            "project.one",
            "f".repeat(64),
            RunLifecycleKind::Assessment,
            "2026-08-29T00:00:00Z",
            vec![PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                sandbox_plan_sha256: "a".repeat(64),
                provider_sha256: "b".repeat(64),
                guest_agent_sha256: "c".repeat(64),
                workspace: Box::new(workspace),
                workspace_identity_sha256,
            }],
            vec!["starts one exact Windows Sandbox session".into()],
        )
        .unwrap()
    }

    fn msi_wsb_plan(run_id: &str) -> RunPlan {
        let workspace = wsb_workspace(run_id);
        let workspace_identity_sha256 = hash_value(&workspace).unwrap();
        RunPlan::new(
            run_id,
            "project.one",
            "f".repeat(64),
            RunLifecycleKind::Assessment,
            "2026-08-29T00:00:00Z",
            vec![PlannedAction::ExecuteWindowsSandboxImportedMsiScenario {
                sandbox_plan_sha256: "a".repeat(64),
                provider_sha256: "b".repeat(64),
                guest_agent_sha256: "c".repeat(64),
                workspace: Box::new(workspace),
                workspace_identity_sha256,
                import_receipt_sha256: "d".repeat(64),
                application_sha256: "e".repeat(64),
                scenario_sha256: "f".repeat(64),
            }],
            vec!["starts one exact imported MSI Windows Sandbox session".into()],
        )
        .unwrap()
    }

    #[cfg(windows)]
    fn bound_wsb_plan(run_id: &str, workspace: WorkspaceBindingEvidence) -> RunPlan {
        let workspace_identity_sha256 = hash_value(&workspace).unwrap();
        RunPlan::new(
            run_id,
            "project.one",
            "f".repeat(64),
            RunLifecycleKind::Assessment,
            "2026-08-29T00:00:00Z",
            vec![PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                sandbox_plan_sha256: "a".repeat(64),
                provider_sha256: "b".repeat(64),
                guest_agent_sha256: "c".repeat(64),
                workspace: Box::new(workspace),
                workspace_identity_sha256,
            }],
            vec!["starts one exact Windows Sandbox session".into()],
        )
        .unwrap()
    }

    fn wsb_import(plan: &RunPlan) -> WsbPlanningImportReceipt {
        let (
            schema_version,
            sandbox_plan_sha256,
            provider_sha256,
            guest_agent_sha256,
            workspace,
            workspace_identity_sha256,
        ) = match &plan.actions[0] {
            PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
            } => (
                WSB_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION,
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
            ),
            PlannedAction::ExecuteWindowsSandboxImportedMsiScenario {
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
                ..
            } => (
                WSB_MSI_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION,
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace,
                workspace_identity_sha256,
            ),
            _ => unreachable!(),
        };
        WsbPlanningImportReceipt {
            schema_version: schema_version.to_owned(),
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
        }
    }

    fn wsb_revocation(
        layout: &RunLayout,
        plan: &RunPlan,
        import: &WsbPlanningImportReceipt,
    ) -> WsbRevocationRecord {
        let PlannedAction::ExecuteWindowsSandboxGoldenProbe { workspace, .. } = &plan.actions[0]
        else {
            unreachable!();
        };
        let control = layout.wsb_discard_control_path().unwrap();
        let store_key = control
            .file_name()
            .and_then(|value| value.to_str())
            .and_then(|value| value.strip_prefix(WSB_DISCARD_CURRENT_PREFIX))
            .unwrap()
            .to_owned();
        WsbRevocationRecord {
            schema_version: WSB_REVOCATION_SCHEMA_VERSION.to_owned(),
            run_id: plan.run_id.clone(),
            cleanup_id: "e".repeat(64),
            discard_intent_sha256: "f".repeat(64),
            discard_intent_binding: DiscardIntentBindingEvidence {
                schema_version: DISCARD_INTENT_BINDING_SCHEMA_VERSION.to_owned(),
                policy_version: DISCARD_INTENT_BINDING_POLICY_VERSION.to_owned(),
                run_id: plan.run_id.clone(),
                owner_sid: workspace.owner_sid.clone(),
                store_key: store_key.clone(),
                final_path: control.to_string_lossy().into_owned(),
                staging_leaf: format!("{WSB_DISCARD_STAGE_PREFIX}{store_key}-{}", "1".repeat(16)),
                parent_id: aiw_probe::DiscardIntentStableId {
                    volume_serial_number: workspace.parent.volume_serial_number.clone(),
                    file_id: workspace.parent.file_id.clone(),
                },
                intent_id: aiw_probe::DiscardIntentStableId {
                    volume_serial_number: workspace.root.volume_serial_number.clone(),
                    file_id: "9".repeat(32),
                },
                intent_size: 128,
                intent_sha256: "f".repeat(64),
                intent_ea: aiw_probe::DiscardIntentEaBinding {
                    queried_bytes: 0,
                    entries: Vec::new(),
                    canonical_sha256: hex::encode(Sha256::digest([])),
                },
            },
            plan_sha256: plan.hash().unwrap(),
            import_receipt_sha256: hash_value(import).unwrap(),
            workspace_identity_sha256: import.workspace_identity_sha256.clone(),
            requested_by: "admin".to_owned(),
            requested_at: "2026-08-29T00:02:00Z".to_owned(),
        }
    }

    fn stage_complete_wsb_import(
        layout: &RunLayout,
        plan: &RunPlan,
        receipt: &WsbPlanningImportReceipt,
    ) -> PathBuf {
        let _lock = layout.acquire_lock("test").unwrap();
        let stage = layout.wsb_import_stage_path(plan).unwrap();
        fs::create_dir(&stage).unwrap();
        fs::create_dir(stage.join("journal-heads")).unwrap();
        write_complete_new(&stage.join("plan.json"), plan, layout.run_id(), "test").unwrap();
        write_complete_new(
            &stage.join(WSB_PLANNING_IMPORT_FILE),
            receipt,
            layout.run_id(),
            "test",
        )
        .unwrap();
        write_empty_new(&stage.join("events.jsonl"), layout.run_id(), "test").unwrap();
        let plan_hash = plan.hash().unwrap();
        let receipt_hash = hash_value(receipt).unwrap();
        let event = artifact_event(
            RunEventKind::Created,
            &plan.created_at,
            "verified Windows Sandbox preparation imported",
            &receipt_hash,
        )
        .unwrap();
        let record = build_record(layout.run_id(), &plan_hash, 1, ZERO_HASH, event).unwrap();
        append_raw(&stage.join("events.jsonl"), &record, layout.run_id()).unwrap();
        write_head(&stage.join("journal-heads"), &record, layout.run_id()).unwrap();
        stage
    }

    fn layout(root: &Path, run_id: &str) -> RunLayout {
        RunLayout::new(root, run_id).unwrap()
    }

    fn tree_snapshot(path: &Path, root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        let mut snapshot = Vec::new();
        for entry in entries {
            let relative = entry
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if entry.is_dir() {
                snapshot.push((relative, None));
                snapshot.extend(tree_snapshot(&entry, root));
            } else {
                snapshot.push((relative, Some(fs::read(&entry).unwrap())));
            }
        }
        snapshot
    }

    fn approve(layout: &RunLayout, plan: &RunPlan) {
        layout
            .write_approval(
                &ApprovalRecord::for_plan(plan, "admin", "2026-08-27T00:01:00Z").unwrap(),
            )
            .unwrap();
    }

    fn append_unimported_wsb_test_event(layout: &RunLayout, plan: &RunPlan, event: RunEvent) {
        let bytes = fs::read(layout.journal_path()).unwrap();
        let complete = bytes.strip_suffix(b"\n").unwrap();
        let previous: JournalRecord =
            serde_json::from_slice(complete.rsplit(|byte| *byte == b'\n').next().unwrap()).unwrap();
        let record = build_record(
            layout.run_id(),
            &plan.hash().unwrap(),
            previous.sequence + 1,
            &previous.hash,
            event,
        )
        .unwrap();
        append_raw(&layout.journal_path(), &record, layout.run_id()).unwrap();
        write_head(&layout.heads_dir(), &record, layout.run_id()).unwrap();
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
        assert_eq!(value["projectRevisionHash"], "f".repeat(64));
        assert_eq!(value["actions"][1]["kind"], "executeScenario");
        assert_eq!(value["actions"][1]["scenarioId"], "install");
        assert!(value["actions"][1].get("scenario_id").is_none());
        assert_eq!(
            plan("run-one").hash().unwrap(),
            "f707923f123bf13e044e5ab10ceedb53e6ae65cf21c68391f620938bd355546d"
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

        let legacy = serde_json::json!({
            "schema": "aiw.dev/run-plan/v0alpha2",
            "runId": "old-wsb",
            "projectId": "project.one",
            "projectRevisionHash": "f".repeat(64),
            "lifecycle": "assessment",
            "createdAt": "2026-08-27T00:00:00Z",
            "actions": [{
                "kind": "executeWindowsSandboxGoldenProbe",
                "sandboxPlanSha256": "a".repeat(64),
                "providerSha256": "b".repeat(64),
                "guestAgentSha256": "c".repeat(64)
            }],
            "trustDeltas": []
        });
        assert!(
            serde_json::from_value::<LegacyRunPlanV0Alpha2>(legacy.clone()).is_ok(),
            "the exact legacy v0alpha2 plan remains readable for inspection"
        );
        assert!(RunPlan::from_value(legacy).is_err());
    }

    #[test]
    fn workspace_identity_is_approval_bound_and_malformed_hashes_fail_closed() {
        let workspace = WorkspaceBindingEvidence {
            schema_version: aiw_probe::WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
            policy: aiw_probe::WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
            security_policy_sha256: aiw_probe::workspace_policy_hash("S-1-5-21-1"),
            owner_sid: "S-1-5-21-1".to_owned(),
            dacl_protected: true,
            allowed_sids: vec!["S-1-5-18".to_owned(), "S-1-5-21-1".to_owned()],
            parent: aiw_probe::WindowsFileIdentity {
                final_path: r"C:\AIW".to_owned(),
                volume_serial_number: "1".repeat(16),
                file_id: "1".repeat(32),
            },
            root: aiw_probe::WindowsFileIdentity {
                final_path: r"C:\AIW\run".to_owned(),
                volume_serial_number: "1".repeat(16),
                file_id: "2".repeat(32),
            },
            tools: aiw_probe::WindowsFileIdentity {
                final_path: r"C:\AIW\run\tools".to_owned(),
                volume_serial_number: "1".repeat(16),
                file_id: "3".repeat(32),
            },
            output: aiw_probe::WindowsFileIdentity {
                final_path: r"C:\AIW\run\output".to_owned(),
                volume_serial_number: "1".repeat(16),
                file_id: "4".repeat(32),
            },
        };
        let action =
            |workspace_identity_sha256: String| PlannedAction::ExecuteWindowsSandboxGoldenProbe {
                sandbox_plan_sha256: "a".repeat(64),
                provider_sha256: "b".repeat(64),
                guest_agent_sha256: "c".repeat(64),
                workspace: Box::new(workspace.clone()),
                workspace_identity_sha256,
            };
        let build = |workspace_identity_sha256: String| {
            RunPlan::new(
                "run-wsb",
                "project.one",
                "f".repeat(64),
                RunLifecycleKind::Assessment,
                "2026-08-29T00:00:00Z",
                vec![action(workspace_identity_sha256)],
                vec!["starts one exact Windows Sandbox session".into()],
            )
        };

        assert!(build("not-a-sha256".into()).is_err());

        let original = build(hash_value(&workspace).unwrap()).unwrap();
        let mut replacement = original.clone();
        let PlannedAction::ExecuteWindowsSandboxGoldenProbe {
            workspace,
            workspace_identity_sha256,
            ..
        } = &mut replacement.actions[0]
        else {
            unreachable!();
        };
        workspace.output.file_id = "5".repeat(32);
        *workspace_identity_sha256 = hash_value(workspace).unwrap();
        assert_ne!(original.hash().unwrap(), replacement.hash().unwrap());

        let approval =
            ApprovalRecord::for_plan(&original, "admin", "2026-08-29T00:01:00Z").unwrap();
        assert!(validate_approval(&approval, &replacement).is_err());
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
                "f".repeat(64),
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
                "f".repeat(64),
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
    fn completed_snapshot_is_read_only_and_returns_terminal_artifacts() {
        let root = root();
        let layout = layout(&root, "run-one");
        let expected_plan = plan("run-one");
        let expected_result = success("run-one");
        layout.create(&expected_plan).unwrap();
        approve(&layout, &expected_plan);
        layout.write_result(&expected_result).unwrap();
        let before = tree_snapshot(&root, &root);

        let snapshot = layout.completed_snapshot().unwrap();

        assert_eq!(snapshot.plan, expected_plan);
        assert_eq!(
            snapshot.approval,
            ApprovalRecord::for_plan(&expected_plan, "admin", "2026-08-27T00:01:00Z").unwrap()
        );
        assert_eq!(snapshot.result, expected_result);
        assert_eq!(tree_snapshot(&root, &root), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completed_snapshot_requires_current_terminal_artifacts() {
        let root = root();
        let missing = layout(&root, "missing");
        assert!(missing.completed_snapshot().is_err());
        assert!(!root.join("runs").exists());

        let layout = layout(&root, "run-one");
        let expected_plan = plan("run-one");
        layout.create(&expected_plan).unwrap();
        let before = tree_snapshot(&root, &root);
        let error = layout.completed_snapshot().unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_RUN_NOT_TERMINAL");
        assert_eq!(tree_snapshot(&root, &root), before);

        let interrupted = RunLayout::new(&root, "run-two").unwrap();
        let interrupted_plan = plan("run-two");
        interrupted.create(&interrupted_plan).unwrap();
        let interrupted_approval =
            ApprovalRecord::for_plan(&interrupted_plan, "admin", "2026-08-27T00:01:00Z").unwrap();
        {
            let _lock = interrupted.acquire_lock("test").unwrap();
            let hash = hash_value(&interrupted_approval).unwrap();
            interrupted
                .append_record(
                    artifact_event(RunEventKind::ApprovalIntent, "now", "intent", &hash).unwrap(),
                )
                .unwrap();
        }
        let before_interrupted = tree_snapshot(&root, &root);
        let error = interrupted.completed_snapshot().unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_RUN_NOT_TERMINAL");
        assert_eq!(tree_snapshot(&root, &root), before_interrupted);

        approve(&layout, &expected_plan);
        let result = success("run-one");
        layout.write_result(&result).unwrap();
        let approval_bytes = fs::read(layout.approval_path()).unwrap();
        let mut changed_approval =
            ApprovalRecord::for_plan(&expected_plan, "different-admin", "2026-08-27T00:01:00Z")
                .unwrap();
        changed_approval.plan_hash = expected_plan.hash().unwrap();
        fs::write(
            layout.approval_path(),
            serde_json::to_vec(&changed_approval).unwrap(),
        )
        .unwrap();
        let error = layout.completed_snapshot().unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_ARTIFACT_TAMPERED");
        fs::write(layout.approval_path(), approval_bytes).unwrap();

        let mut changed = result.clone();
        changed.summary = "tampered".to_owned();
        fs::write(layout.result_path(), serde_json::to_vec(&changed).unwrap()).unwrap();
        let error = layout.completed_snapshot().unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_ARTIFACT_TAMPERED");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completed_snapshot_validates_current_windows_sandbox_import() {
        let root = root();
        let layout = layout(&root, "run-one");
        let expected_plan = wsb_plan("run-one");
        let receipt = wsb_import(&expected_plan);
        layout
            .create_or_verify_pending_wsb_import(&expected_plan, &receipt)
            .unwrap();
        approve(&layout, &expected_plan);
        let expected_result = success("run-one");
        layout.write_result(&expected_result).unwrap();
        let before = tree_snapshot(&root, &root);

        let snapshot = layout.completed_snapshot().unwrap();

        assert_eq!(snapshot.plan, expected_plan);
        assert_eq!(snapshot.result, expected_result);
        assert_eq!(snapshot.approval.plan_hash, expected_plan.hash().unwrap());
        assert_eq!(tree_snapshot(&root, &root), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn create_or_verify_pending_is_exact_and_idempotent() {
        let root = root();
        let layout = layout(&root, "run-one");
        let expected = wsb_plan("run-one");
        let receipt = wsb_import(&expected);
        assert_eq!(
            layout
                .create_or_verify_pending_wsb_import(&expected, &receipt)
                .unwrap(),
            PendingRunDisposition::Created
        );
        let plan_before = fs::read(layout.plan_path()).unwrap();
        let journal_before = fs::read(layout.journal_path()).unwrap();
        assert_eq!(
            layout
                .create_or_verify_pending_wsb_import(&expected, &receipt)
                .unwrap(),
            PendingRunDisposition::AlreadyPresent
        );
        assert_eq!(fs::read(layout.plan_path()).unwrap(), plan_before);
        assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_before);
        let mut changed_time = receipt.clone();
        changed_time.imported_at = "2026-08-29T00:02:00Z".to_owned();
        let error = layout
            .create_or_verify_pending_wsb_import(&expected, &changed_time)
            .unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_PENDING_RUN_CONFLICT");
        assert!(matches!(
            layout.status().unwrap(),
            RecoveryStatus::PendingApproval {
                last_sequence: 1,
                ..
            }
        ));

        let mut changed = expected.clone();
        changed.created_at = "later".to_owned();
        let changed_receipt = wsb_import(&changed);
        let error = layout
            .create_or_verify_pending_wsb_import(&changed, &changed_receipt)
            .unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_PENDING_RUN_CONFLICT");
        assert_eq!(fs::read(layout.plan_path()).unwrap(), plan_before);
        assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn create_or_verify_pending_rejects_lifecycle_progress_and_extra_artifacts() {
        let expected = wsb_plan("run-one");
        let receipt = wsb_import(&expected);
        {
            let root = root();
            let layout = layout(&root, "run-one");
            layout
                .create_or_verify_pending_wsb_import(&expected, &receipt)
                .unwrap();
            approve(&layout, &expected);
            let error = layout
                .create_or_verify_pending_wsb_import(&expected, &receipt)
                .unwrap_err();
            assert_eq!(error.code.as_ref(), "AIW_PENDING_RUN_CONFLICT");
            fs::remove_dir_all(&root).unwrap();
        }

        let root = root();
        let layout = layout(&root, "run-one");
        layout
            .create_or_verify_pending_wsb_import(&expected, &receipt)
            .unwrap();
        fs::write(layout.run_dir().join("unexpected.json"), b"{}").unwrap();
        let error = layout
            .create_or_verify_pending_wsb_import(&expected, &receipt)
            .unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_PENDING_RUN_CONFLICT");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn create_skips_colliding_staging_directory_without_adopting_it() {
        let root = root();
        let layout = layout(&root, "run-one");
        let expected = wsb_plan("run-one");
        let receipt = wsb_import(&expected);
        let runs = root.join("runs");
        fs::create_dir(&runs).unwrap();
        fs::create_dir(runs.join(".locks")).unwrap();
        let next = NEXT_STAGE.load(Ordering::Relaxed);
        let collision = runs.join(format!(".create-run-one-{}-{next}", std::process::id()));
        fs::create_dir(&collision).unwrap();
        fs::write(collision.join("preserve.txt"), b"preserve").unwrap();
        assert_eq!(
            layout
                .create_or_verify_pending_wsb_import(&expected, &receipt)
                .unwrap(),
            PendingRunDisposition::Created
        );
        assert_eq!(
            fs::read(collision.join("preserve.txt")).unwrap(),
            b"preserve"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_completed_wsb_import_stage_is_resumed_without_rewriting_it() {
        let root = root();
        let layout = layout(&root, "run-one");
        let expected = wsb_plan("run-one");
        let receipt = wsb_import(&expected);
        let stage = stage_complete_wsb_import(&layout, &expected, &receipt);
        let staged_journal = fs::read(stage.join("events.jsonl")).unwrap();
        assert_eq!(
            layout
                .create_or_verify_pending_wsb_import(&expected, &receipt)
                .unwrap(),
            PendingRunDisposition::Created
        );
        assert!(!stage.exists());
        assert_eq!(fs::read(layout.journal_path()).unwrap(), staged_journal);
        assert!(matches!(
            layout.status().unwrap(),
            RecoveryStatus::PendingApproval {
                last_sequence: 1,
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_partial_wsb_import_stages_resume_at_each_publication_boundary() {
        for step in [0, 1, 2, 3, 5] {
            let root = root();
            let layout = layout(&root, "run-one");
            let expected = wsb_plan("run-one");
            let receipt = wsb_import(&expected);
            {
                let _lock = layout.acquire_lock("test").unwrap();
                let stage = layout.wsb_import_stage_path(&expected).unwrap();
                fs::create_dir(&stage).unwrap();
                if step >= 1 {
                    fs::create_dir(stage.join("journal-heads")).unwrap();
                }
                if step >= 2 {
                    write_complete_new(
                        &stage.join("plan.json"),
                        &expected,
                        layout.run_id(),
                        "test",
                    )
                    .unwrap();
                }
                if step >= 3 {
                    write_complete_new(
                        &stage.join(WSB_PLANNING_IMPORT_FILE),
                        &receipt,
                        layout.run_id(),
                        "test",
                    )
                    .unwrap();
                }
                if step >= 4 {
                    write_empty_new(&stage.join("events.jsonl"), layout.run_id(), "test").unwrap();
                }
                if step >= 5 {
                    let plan_hash = expected.hash().unwrap();
                    let receipt_hash = hash_value(&receipt).unwrap();
                    let event = artifact_event(
                        RunEventKind::Created,
                        &expected.created_at,
                        "verified Windows Sandbox preparation imported",
                        &receipt_hash,
                    )
                    .unwrap();
                    let record =
                        build_record(layout.run_id(), &plan_hash, 1, ZERO_HASH, event).unwrap();
                    append_raw(&stage.join("events.jsonl"), &record, layout.run_id()).unwrap();
                }
            }
            assert_eq!(
                layout
                    .create_or_verify_pending_wsb_import(&expected, &receipt)
                    .unwrap(),
                PendingRunDisposition::Created,
                "stage step {step}"
            );
            assert!(matches!(
                layout.status().unwrap(),
                RecoveryStatus::PendingApproval {
                    last_sequence: 1,
                    ..
                }
            ));
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn wsb_import_resumes_pending_prefix_and_target_plus_pending_windows() {
        for case in 0..5 {
            let root = root();
            let layout = layout(&root, "run-one");
            let expected = wsb_plan("run-one");
            let receipt = wsb_import(&expected);
            let plan_bytes = json_file_bytes(&expected, layout.run_id()).unwrap();
            let receipt_bytes = json_file_bytes(&receipt, layout.run_id()).unwrap();
            let plan_hash = expected.hash().unwrap();
            let receipt_hash = hash_value(&receipt).unwrap();
            let event = artifact_event(
                RunEventKind::Created,
                &expected.created_at,
                "verified Windows Sandbox preparation imported",
                &receipt_hash,
            )
            .unwrap();
            let record = build_record(layout.run_id(), &plan_hash, 1, ZERO_HASH, event).unwrap();
            let mut journal_bytes = serde_json::to_vec(&record).unwrap();
            journal_bytes.push(b'\n');
            let head = JournalHead {
                schema: HEAD_SCHEMA.to_owned(),
                run_id: layout.run_id().to_owned(),
                plan_hash,
                sequence: 1,
                hash: record.hash,
            };
            let head_bytes = json_file_bytes(&head, layout.run_id()).unwrap();
            {
                let _lock = layout.acquire_lock("test").unwrap();
                let stage = layout.wsb_import_stage_path(&expected).unwrap();
                fs::create_dir(&stage).unwrap();
                let heads = stage.join("journal-heads");
                fs::create_dir(&heads).unwrap();
                let plan_path = stage.join("plan.json");
                let receipt_path = stage.join(WSB_PLANNING_IMPORT_FILE);
                let journal_path = stage.join("events.jsonl");
                let head_path = heads.join(head_name(1));
                match case {
                    0 => fs::write(
                        layout.pending_path(&plan_path),
                        &plan_bytes[..plan_bytes.len() / 2],
                    )
                    .unwrap(),
                    1 => {
                        fs::write(&plan_path, &plan_bytes).unwrap();
                        fs::hard_link(&plan_path, layout.pending_path(&plan_path)).unwrap();
                    }
                    2 => {
                        fs::write(&plan_path, &plan_bytes).unwrap();
                        fs::write(
                            layout.pending_path(&receipt_path),
                            &receipt_bytes[..receipt_bytes.len() / 2],
                        )
                        .unwrap();
                    }
                    3 => {
                        fs::write(&plan_path, &plan_bytes).unwrap();
                        fs::write(&receipt_path, &receipt_bytes).unwrap();
                        fs::write(
                            layout.pending_path(&journal_path),
                            &journal_bytes[..journal_bytes.len() / 2],
                        )
                        .unwrap();
                    }
                    4 => {
                        fs::write(&plan_path, &plan_bytes).unwrap();
                        fs::write(&receipt_path, &receipt_bytes).unwrap();
                        fs::write(&journal_path, &journal_bytes).unwrap();
                        fs::write(
                            layout.pending_path(&head_path),
                            &head_bytes[..head_bytes.len() / 2],
                        )
                        .unwrap();
                    }
                    _ => unreachable!(),
                }
            }
            assert_eq!(
                layout
                    .create_or_verify_pending_wsb_import(&expected, &receipt)
                    .unwrap(),
                PendingRunDisposition::Created,
                "pending case {case}"
            );
            assert!(!layout.pending_path(&layout.plan_path()).exists());
            assert!(
                !layout
                    .pending_path(&layout.wsb_planning_import_path())
                    .exists()
            );
            assert!(!layout.pending_path(&layout.journal_path()).exists());
            assert!(
                !layout
                    .pending_path(&layout.heads_dir().join(head_name(1)))
                    .exists()
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn malformed_wsb_import_stage_is_preserved_and_never_published() {
        {
            let root = root();
            let layout = layout(&root, "run-one");
            let expected = wsb_plan("run-one");
            let receipt = wsb_import(&expected);
            let _lock = layout.acquire_lock("test").unwrap();
            let stage = layout.wsb_import_stage_path(&expected).unwrap();
            fs::create_dir(&stage).unwrap();
            fs::write(stage.join("unexpected.txt"), b"preserve").unwrap();
            drop(_lock);
            let error = layout
                .create_or_verify_pending_wsb_import(&expected, &receipt)
                .unwrap_err();
            assert_eq!(error.code.as_ref(), "AIW_WSB_IMPORT_STAGE_INVALID");
            assert_eq!(fs::read(stage.join("unexpected.txt")).unwrap(), b"preserve");
            assert!(!layout.run_dir().exists());
            fs::remove_dir_all(root).unwrap();
        }

        let root = root();
        let layout = layout(&root, "run-one");
        let expected = wsb_plan("run-one");
        let receipt = wsb_import(&expected);
        let pending;
        {
            let _lock = layout.acquire_lock("test").unwrap();
            let stage = layout.wsb_import_stage_path(&expected).unwrap();
            fs::create_dir(&stage).unwrap();
            pending = layout.pending_path(&stage.join("plan.json"));
            fs::write(&pending, b"not-an-expected-prefix").unwrap();
        }
        let error = layout
            .create_or_verify_pending_wsb_import(&expected, &receipt)
            .unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_WSB_IMPORT_STAGE_INVALID");
        assert_eq!(fs::read(&pending).unwrap(), b"not-an-expected-prefix");
        assert!(!layout.run_dir().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generic_create_rejects_wsb_before_creating_run_storage() {
        for plan in [wsb_plan("run-one"), msi_wsb_plan("run-one")] {
            let root = root();
            let layout = layout(&root, "run-one");
            let error = layout.create(&plan).unwrap_err();
            assert_eq!(error.code.as_ref(), "AIW_WSB_IMPORT_REQUIRED");
            assert!(!root.join("runs").exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn imported_msi_plan_uses_distinct_schema_and_receipt_contract() {
        let plan = msi_wsb_plan("run-one");
        assert_eq!(plan.schema, IMPORTED_MSI_RUN_PLAN_SCHEMA_VERSION);
        assert_eq!(
            wsb_import(&plan).schema_version,
            WSB_MSI_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION
        );
        assert!(RunPlan::from_value(serde_json::to_value(&plan).unwrap()).is_ok());

        let golden = wsb_plan("run-two");
        assert_eq!(golden.schema, RUN_PLAN_SCHEMA_VERSION);
        assert_eq!(
            wsb_import(&golden).schema_version,
            WSB_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION
        );

        let mut msi_with_golden_schema = serde_json::to_value(&plan).unwrap();
        msi_with_golden_schema["schema"] = serde_json::json!(RUN_PLAN_SCHEMA_VERSION);
        assert!(RunPlan::from_value(msi_with_golden_schema).is_err());
        let mut golden_with_msi_schema = serde_json::to_value(&golden).unwrap();
        golden_with_msi_schema["schema"] = serde_json::json!(IMPORTED_MSI_RUN_PLAN_SCHEMA_VERSION);
        assert!(RunPlan::from_value(golden_with_msi_schema).is_err());

        let mut wrong_golden_receipt = wsb_import(&golden);
        wrong_golden_receipt.schema_version =
            WSB_MSI_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION.to_owned();
        assert!(validate_wsb_import(&wrong_golden_receipt, &golden).is_err());
        let mut wrong_msi_receipt = wsb_import(&plan);
        wrong_msi_receipt.schema_version = WSB_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION.to_owned();
        assert!(validate_wsb_import(&wrong_msi_receipt, &plan).is_err());
    }

    #[test]
    fn imported_msi_hash_change_invalidates_the_existing_receipt() {
        let root = root();
        let layout = layout(&root, "run-one");
        let expected = msi_wsb_plan("run-one");
        let receipt = wsb_import(&expected);
        let mut changed = expected.clone();
        let PlannedAction::ExecuteWindowsSandboxImportedMsiScenario {
            application_sha256, ..
        } = &mut changed.actions[0]
        else {
            unreachable!();
        };
        *application_sha256 = "0".repeat(64);
        let error = layout
            .create_or_verify_pending_wsb_import(&changed, &receipt)
            .unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_WSB_IMPORT_INVALID");
        assert!(!root.join("runs").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn imported_msi_launch_requires_fresh_lifecycle_approval() {
        let assessment = msi_wsb_plan("run-one");
        let approval = ApprovalRecord::for_plan(&assessment, "operator", "time").unwrap();
        let mut launch = assessment.clone();
        launch.lifecycle = RunLifecycleKind::Launch;
        launch.validate().unwrap();
        assert_ne!(launch.hash().unwrap(), assessment.hash().unwrap());
        assert!(validate_approval(&approval, &launch).is_err());
    }

    #[test]
    fn duplicate_windows_sandbox_profile_actions_are_rejected() {
        let plan = msi_wsb_plan("run-one");
        let mut actions = plan.actions.clone();
        let duplicate = actions[0].clone();
        actions.push(duplicate);
        let error = RunPlan::new(
            plan.run_id,
            plan.project_id,
            plan.project_revision_hash,
            plan.lifecycle,
            plan.created_at,
            actions,
            plan.trust_deltas,
        )
        .unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_PLAN_BINDING_INVALID");
    }

    #[test]
    fn wsb_approval_requires_the_atomically_published_import_receipt() {
        let root = root();
        let layout = layout(&root, "run-one");
        let expected = wsb_plan("run-one");
        {
            let _lock = layout.acquire_lock("test").unwrap();
            layout.create_locked(&expected).unwrap();
        }
        let approval = ApprovalRecord::for_plan(&expected, "admin", "now").unwrap();
        assert!(layout.write_approval(&approval).is_err());
        assert!(!layout.approval_path().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wsb_approval_recovery_never_mutates_without_import_provenance() {
        for target_published in [false, true] {
            let root = root();
            let layout = layout(&root, "run-one");
            let expected = wsb_plan("run-one");
            {
                let _lock = layout.acquire_lock("test").unwrap();
                layout.create_locked(&expected).unwrap();
            }
            let approval = ApprovalRecord::for_plan(&expected, "admin", "now").unwrap();
            {
                let _lock = layout.acquire_lock("test").unwrap();
                let hash = hash_value(&approval).unwrap();
                append_unimported_wsb_test_event(
                    &layout,
                    &expected,
                    artifact_event(
                        RunEventKind::ApprovalIntent,
                        "now",
                        "approval mutation prepared",
                        &hash,
                    )
                    .unwrap(),
                );
                let path = if target_published {
                    layout.approval_path()
                } else {
                    layout.pending_path(&layout.approval_path())
                };
                write_complete_new(&path, &approval, layout.run_id(), "test").unwrap();
            }
            let journal_before = fs::read(layout.journal_path()).unwrap();
            let target = if target_published {
                layout.approval_path()
            } else {
                layout.pending_path(&layout.approval_path())
            };
            let artifact_before = fs::read(&target).unwrap();
            assert!(layout.recovery_status().is_err());
            assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_before);
            assert_eq!(fs::read(&target).unwrap(), artifact_before);
            assert!(!layout.wsb_planning_import_path().exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn status_rejects_unimported_wsb_state_without_mutating_it() {
        for approved in [false, true] {
            let root = root();
            let layout = layout(&root, "run-one");
            let expected = wsb_plan("run-one");
            {
                let _lock = layout.acquire_lock("test").unwrap();
                layout.create_locked(&expected).unwrap();
                if approved {
                    let approval = ApprovalRecord::for_plan(&expected, "admin", "now").unwrap();
                    let hash = hash_value(&approval).unwrap();
                    append_unimported_wsb_test_event(
                        &layout,
                        &expected,
                        artifact_event(
                            RunEventKind::ApprovalIntent,
                            "now",
                            "approval mutation prepared",
                            &hash,
                        )
                        .unwrap(),
                    );
                    write_complete_new(&layout.approval_path(), &approval, layout.run_id(), "test")
                        .unwrap();
                    append_unimported_wsb_test_event(
                        &layout,
                        &expected,
                        artifact_event(
                            RunEventKind::ApprovalRecorded,
                            "now",
                            "approval persisted",
                            &hash,
                        )
                        .unwrap(),
                    );
                }
            }
            let journal_before = fs::read(layout.journal_path()).unwrap();
            let approval_before = approved.then(|| fs::read(layout.approval_path()).unwrap());
            assert!(layout.status().is_err());
            assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_before);
            if let Some(approval_before) = approval_before {
                assert_eq!(fs::read(layout.approval_path()).unwrap(), approval_before);
            }
            assert!(!layout.wsb_planning_import_path().exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn receipt_tampering_invalidates_wsb_status_recovery_and_approval() {
        for tamper_imported_at in [false, true] {
            for operation in 0..3 {
                let root = root();
                let layout = layout(&root, "run-one");
                let expected = wsb_plan("run-one");
                let receipt = wsb_import(&expected);
                layout
                    .create_or_verify_pending_wsb_import(&expected, &receipt)
                    .unwrap();
                let mut tampered = receipt.clone();
                if tamper_imported_at {
                    tampered.imported_at = "2026-08-29T00:02:00Z".to_owned();
                } else {
                    tampered.preparation_receipt_sha256 = "e".repeat(64);
                }
                fs::write(
                    layout.wsb_planning_import_path(),
                    json_file_bytes(&tampered, layout.run_id()).unwrap(),
                )
                .unwrap();
                let journal_before = fs::read(layout.journal_path()).unwrap();
                let receipt_before = fs::read(layout.wsb_planning_import_path()).unwrap();
                let result = match operation {
                    0 => layout.status().map(|_| ()),
                    1 => layout.recovery_status().map(|_| ()),
                    2 => layout.write_approval(
                        &ApprovalRecord::for_plan(&expected, "admin", "now").unwrap(),
                    ),
                    _ => unreachable!(),
                };
                assert!(result.is_err());
                assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_before);
                assert_eq!(
                    fs::read(layout.wsb_planning_import_path()).unwrap(),
                    receipt_before
                );
                assert!(!layout.approval_path().exists());
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[test]
    fn external_discard_authority_immediately_blocks_approval_and_recovery() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let journal_before = fs::read(layout.journal_path()).unwrap();
        let guard = layout.begin_wsb_revocation().unwrap();
        let control = guard.control_path().unwrap();
        fs::create_dir(&control).unwrap();
        drop(guard);

        assert!(matches!(
            layout.status().unwrap(),
            RecoveryStatus::RevokedPendingDiscard {
                revocation: None,
                last_sequence: 1
            }
        ));
        assert!(matches!(
            layout.recovery_status().unwrap(),
            RecoveryStatus::RevokedPendingDiscard {
                revocation: None,
                last_sequence: 1
            }
        ));
        assert_eq!(
            layout
                .write_approval(&ApprovalRecord::for_plan(&plan, "admin", "now").unwrap())
                .unwrap_err()
                .code
                .as_ref(),
            "AIW_WSB_REVOKED"
        );
        assert_eq!(
            layout
                .create_or_verify_pending_wsb_import(&plan, &import)
                .unwrap_err()
                .code
                .as_ref(),
            "AIW_WSB_REVOKED"
        );
        assert_eq!(
            layout
                .write_result(&success("run-one"))
                .unwrap_err()
                .code
                .as_ref(),
            "AIW_WSB_REVOKED"
        );
        assert!(layout.replay_journal().is_err());
        assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_before);
        assert!(!layout.approval_path().exists());
        fs::remove_dir_all(&control).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn external_discard_authority_blocks_generic_run_id_reuse_without_creating_lock_state() {
        let root = root();
        let layout = layout(&root, "run-one");
        let control = layout.wsb_discard_control_path().unwrap();
        fs::create_dir(&control).unwrap();

        assert_eq!(
            layout.create(&plan("run-one")).unwrap_err().code.as_ref(),
            "AIW_WSB_REVOKED"
        );
        assert!(!root.join("runs").exists());
        fs::remove_dir_all(&control).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_discard_sentinel_is_fail_closed_and_never_adopted() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let legacy = layout.legacy_wsb_discard_control_path().unwrap();
        fs::create_dir(&legacy).unwrap();

        assert_eq!(
            layout.begin_wsb_revocation().err().unwrap().code.as_ref(),
            "AIW_WSB_LEGACY_DISCARD_AUTHORITY"
        );
        assert_eq!(
            layout
                .write_approval(&ApprovalRecord::for_plan(&plan, "admin", "now").unwrap())
                .unwrap_err()
                .code
                .as_ref(),
            "AIW_WSB_REVOKED"
        );
        assert!(!layout.wsb_discard_control_path().unwrap().exists());
        fs::remove_dir_all(legacy).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revocation_entry_requires_the_exact_pristine_or_revocation_allowlist() {
        for unexpected in [
            "approval.json.pending",
            "wsb-session-transaction",
            "extra.bin",
        ] {
            let root = root();
            let layout = layout(&root, "run-one");
            let plan = wsb_plan("run-one");
            let import = wsb_import(&plan);
            layout
                .create_or_verify_pending_wsb_import(&plan, &import)
                .unwrap();
            let path = layout.run_dir().join(unexpected);
            if unexpected == "wsb-session-transaction" {
                fs::create_dir(&path).unwrap();
            } else {
                fs::write(&path, b"unexpected").unwrap();
            }

            assert!(layout.begin_wsb_revocation().is_err());
            assert!(!layout.wsb_discard_control_path().unwrap().exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn recorded_approval_prevents_later_revocation() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        layout
            .write_approval(&ApprovalRecord::for_plan(&plan, "admin", "now").unwrap())
            .unwrap();

        assert_eq!(
            layout.begin_wsb_revocation().err().unwrap().code.as_ref(),
            "AIW_WSB_DISCARD_STATE_INVALID"
        );
        assert!(!layout.wsb_discard_control_path().unwrap().exists());
        assert!(matches!(
            layout.status().unwrap(),
            RecoveryStatus::Ready {
                last_sequence: 3,
                ..
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn external_discard_authority_rejects_a_conflicting_journal_lifecycle() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let guard = layout.begin_wsb_revocation().unwrap();
        let control = guard.control_path().unwrap();
        let approval = ApprovalRecord::for_plan(&plan, "admin", "now").unwrap();
        let hash = hash_value(&approval).unwrap();
        layout
            .append_record(
                artifact_event(RunEventKind::ApprovalIntent, "now", "intent", &hash).unwrap(),
            )
            .unwrap();
        fs::create_dir(&control).unwrap();
        drop(guard);

        assert_eq!(
            layout.status().unwrap_err().code.as_ref(),
            "AIW_WSB_DISCARD_STATE_INVALID"
        );
        assert_eq!(
            layout.recovery_status().unwrap_err().code.as_ref(),
            "AIW_WSB_DISCARD_STATE_INVALID"
        );
        fs::remove_dir_all(&control).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn internal_revocation_without_external_authority_never_recovers_to_ordinary_state() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        let revocation = wsb_revocation(&layout, &plan, &import);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let guard = layout.begin_wsb_revocation().unwrap();
        let hash = hash_value(&revocation).unwrap();
        layout
            .append_record(
                artifact_event(
                    RunEventKind::RevocationIntent,
                    &revocation.requested_at,
                    "revocation mutation prepared",
                    &hash,
                )
                .unwrap(),
            )
            .unwrap();
        drop(guard);
        let journal_before = fs::read(layout.journal_path()).unwrap();

        for status in [layout.status().unwrap(), layout.recovery_status().unwrap()] {
            assert!(matches!(
                status,
                RecoveryStatus::RevokedPendingDiscard {
                    revocation: None,
                    last_sequence: 2
                }
            ));
        }
        assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_before);
        assert!(!layout.approval_path().exists());
        assert_eq!(
            layout
                .write_approval(&ApprovalRecord::for_plan(&plan, "admin", "later").unwrap())
                .unwrap_err()
                .code
                .as_ref(),
            "AIW_WSB_REVOKED"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revocation_is_hash_bound_idempotent_and_permanently_gated() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        let revocation = wsb_revocation(&layout, &plan, &import);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let mut guard = layout.begin_wsb_revocation().unwrap();
        let control = guard.control_path().unwrap();
        fs::create_dir(&control).unwrap();
        guard.persist_staged_revocation(&revocation).unwrap();
        assert_eq!(guard.committed_revocation(), Some(&revocation));
        drop(guard);

        assert!(matches!(
            layout.status().unwrap(),
            RecoveryStatus::RevokedPendingDiscard {
                revocation: Some(ref observed),
                last_sequence: 3
            } if observed.as_ref() == &revocation
        ));
        let mut retry = layout.begin_wsb_revocation().unwrap();
        assert_eq!(retry.committed_revocation(), Some(&revocation));
        retry.persist_staged_revocation(&revocation).unwrap();
        let mut conflict = revocation.clone();
        conflict.requested_at = "later".to_owned();
        assert_eq!(
            retry
                .persist_staged_revocation(&conflict)
                .unwrap_err()
                .code
                .as_ref(),
            "AIW_WSB_REVOCATION_CONFLICT"
        );
        drop(retry);
        assert!(layout.request_cancellation("admin", "now").is_err());
        assert!(
            layout
                .append_event(RunEvent::new(RunEventKind::Progress, "now", "blocked").unwrap())
                .is_err()
        );
        fs::remove_dir_all(&control).unwrap();
        assert!(matches!(
            layout.status().unwrap(),
            RecoveryStatus::RevokedPendingDiscard {
                revocation: Some(_),
                last_sequence: 3
            }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn bound_revocation_recovers_intent_only_and_recorded_prefixes() {
        for recorded in [false, true] {
            let base = root();
            let workspace = HeldRunWorkspace::create(&base, "authority").unwrap();
            let layout = layout(workspace.root_path(), "run-one");
            let plan = bound_wsb_plan("run-one", workspace.evidence().clone());
            let import = wsb_import(&plan);
            let revocation = wsb_revocation(&layout, &plan, &import);
            layout
                .create_or_verify_pending_wsb_import_bound(&workspace, &plan, &import)
                .unwrap();

            let lease = layout.acquire_wsb_revocation_lease().unwrap();
            let guard = lease.begin_bound(&workspace).unwrap();
            let (run, heads) = layout
                .bind_wsb_revocation_run_directories(&workspace)
                .unwrap();
            reconcile_bound_wsb_file(
                &run,
                "wsb-revocation.json.pending",
                &json_file_bytes(&revocation, layout.run_id()).unwrap(),
                layout.run_id(),
            )
            .unwrap();
            if recorded {
                let hash = hash_value(&revocation).unwrap();
                layout
                    .append_record_bound(
                        &run,
                        &heads,
                        artifact_event(
                            RunEventKind::RevocationIntent,
                            &revocation.requested_at,
                            "revocation mutation prepared",
                            &hash,
                        )
                        .unwrap(),
                    )
                    .unwrap();
            }
            drop(heads);
            drop(run);
            drop(guard);

            let lease = layout.acquire_wsb_revocation_lease().unwrap();
            let mut retry = lease.begin_bound(&workspace).unwrap();
            assert_eq!(retry.recoverable_revocation(), Some(&revocation));
            retry
                .persist_staged_revocation_bound(&workspace, &revocation)
                .unwrap();
            assert_eq!(retry.committed_revocation(), Some(&revocation));
            drop(retry);

            let records = layout.load_records(false).unwrap();
            assert_eq!(records.len(), 3);
            assert_eq!(records[1].event.kind, RunEventKind::RevocationIntent);
            assert_eq!(records[2].event.kind, RunEventKind::RevocationRecorded);
            drop(workspace);
            fs::remove_dir_all(base).unwrap();
        }
    }

    #[test]
    fn revocation_v2_rejects_binding_tamper_before_persistence() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        let mut revocation = wsb_revocation(&layout, &plan, &import);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let mut guard = layout.begin_wsb_revocation().unwrap();

        revocation.discard_intent_binding.intent_sha256 = "0".repeat(64);
        assert_eq!(
            guard
                .persist_staged_revocation(&revocation)
                .unwrap_err()
                .code
                .as_ref(),
            "AIW_WSB_REVOCATION_INVALID"
        );
        assert_eq!(layout.load_records(false).unwrap().len(), 1);
        assert!(!layout.wsb_revocation_path().exists());
        assert!(!layout.pending_path(&layout.wsb_revocation_path()).exists());
        drop(guard);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revocation_v2_rejects_noncanonical_ea_evidence() {
        for tamper in 0..3 {
            let root = root();
            let layout = layout(&root, "run-one");
            let plan = wsb_plan("run-one");
            let import = wsb_import(&plan);
            let mut revocation = wsb_revocation(&layout, &plan, &import);
            let value_hash = hex::encode(Sha256::digest([1_u8, 2, 3, 4]));
            revocation.discard_intent_binding.intent_ea = aiw_probe::DiscardIntentEaBinding {
                queried_bytes: 128,
                entries: vec![
                    aiw_probe::DiscardIntentEaEntry {
                        name: "$KERNEL.PURGE.SMARTLOCKER.VALID".to_owned(),
                        flags: u8::from(tamper == 0),
                        value_length: if tamper == 1 { 3 } else { 4 },
                        value_sha256: value_hash.clone(),
                    },
                    aiw_probe::DiscardIntentEaEntry {
                        name: "$KERNEL.SMARTLOCKER.ORIGINCLAIM".to_owned(),
                        flags: 0,
                        value_length: 16,
                        value_sha256: hex::encode(Sha256::digest([5_u8; 16])),
                    },
                ],
                canonical_sha256: if tamper == 2 {
                    "0".repeat(64)
                } else {
                    // Deliberately remains inconsistent after the flag or
                    // length mutation above.
                    "f".repeat(64)
                },
            };
            layout
                .create_or_verify_pending_wsb_import(&plan, &import)
                .unwrap();
            let mut guard = layout.begin_wsb_revocation().unwrap();
            assert_eq!(
                guard
                    .persist_staged_revocation(&revocation)
                    .unwrap_err()
                    .code
                    .as_ref(),
                "AIW_WSB_REVOCATION_INVALID"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn complete_prejournal_binding_is_exposed_only_as_recoverable() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        let revocation = wsb_revocation(&layout, &plan, &import);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let guard = layout.begin_wsb_revocation().unwrap();
        write_complete_new(
            &layout.pending_path(&layout.wsb_revocation_path()),
            &revocation,
            layout.run_id(),
            "test",
        )
        .unwrap();
        drop(guard);

        let mut retry = layout.begin_wsb_revocation().unwrap();
        assert_eq!(retry.recoverable_revocation(), Some(&revocation));
        assert_eq!(retry.committed_revocation(), None);
        retry.persist_staged_revocation(&revocation).unwrap();
        assert_eq!(retry.committed_revocation(), Some(&revocation));
        drop(retry);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partial_target_is_rebuilt_from_complete_pending_after_crash() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        let revocation = wsb_revocation(&layout, &plan, &import);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let guard = layout.begin_wsb_revocation().unwrap();
        let pending = layout.pending_path(&layout.wsb_revocation_path());
        write_complete_new(&pending, &revocation, layout.run_id(), "test").unwrap();
        let hash = hash_value(&revocation).unwrap();
        layout
            .append_record(
                artifact_event(
                    RunEventKind::RevocationIntent,
                    &revocation.requested_at,
                    "revocation mutation prepared",
                    &hash,
                )
                .unwrap(),
            )
            .unwrap();
        fs::write(layout.wsb_revocation_path(), b"{\"partial\":").unwrap();
        drop(guard);

        let mut retry = layout.begin_wsb_revocation().unwrap();
        assert_eq!(retry.recoverable_revocation(), Some(&revocation));
        retry.persist_staged_revocation(&revocation).unwrap();
        let observed: WsbRevocationRecord = read_json(
            &layout.wsb_revocation_path(),
            MAX_ARTIFACT,
            layout.run_id(),
            "test",
        )
        .unwrap();
        assert_eq!(observed, revocation);
        drop(retry);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revocation_resumes_each_internal_publication_boundary() {
        for stage in 0..3 {
            let root = root();
            let layout = layout(&root, "run-one");
            let plan = wsb_plan("run-one");
            let import = wsb_import(&plan);
            let revocation = wsb_revocation(&layout, &plan, &import);
            layout
                .create_or_verify_pending_wsb_import(&plan, &import)
                .unwrap();
            let mut guard = layout.begin_wsb_revocation().unwrap();
            let hash = hash_value(&revocation).unwrap();
            if stage <= 1 {
                write_complete_new(
                    &layout.pending_path(&layout.wsb_revocation_path()),
                    &revocation,
                    layout.run_id(),
                    "test",
                )
                .unwrap();
            } else {
                write_complete_new(
                    &layout.wsb_revocation_path(),
                    &revocation,
                    layout.run_id(),
                    "test",
                )
                .unwrap();
            }
            if stage >= 1 {
                layout
                    .append_record(
                        artifact_event(
                            RunEventKind::RevocationIntent,
                            &revocation.requested_at,
                            "revocation mutation prepared",
                            &hash,
                        )
                        .unwrap(),
                    )
                    .unwrap();
            }
            guard.persist_staged_revocation(&revocation).unwrap();
            drop(guard);
            assert!(matches!(
                layout.status().unwrap(),
                RecoveryStatus::RevokedPendingDiscard {
                    revocation: Some(_),
                    last_sequence: 3
                }
            ));
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn revocation_repairs_only_its_torn_journal_and_head_publication_boundaries() {
        for stage in 0..3 {
            let root = root();
            let layout = layout(&root, "run-one");
            let plan = wsb_plan("run-one");
            let import = wsb_import(&plan);
            let revocation = wsb_revocation(&layout, &plan, &import);
            layout
                .create_or_verify_pending_wsb_import(&plan, &import)
                .unwrap();
            let guard = layout.begin_wsb_revocation().unwrap();
            write_complete_new(
                &layout.pending_path(&layout.wsb_revocation_path()),
                &revocation,
                layout.run_id(),
                "test",
            )
            .unwrap();
            drop(guard);

            if stage == 0 {
                let mut journal = OpenOptions::new()
                    .append(true)
                    .open(layout.journal_path())
                    .unwrap();
                journal.write_all(b"{\"tornRevocationIntent\":").unwrap();
                journal.sync_all().unwrap();
            } else {
                let hash = hash_value(&revocation).unwrap();
                layout
                    .append_record(
                        artifact_event(
                            RunEventKind::RevocationIntent,
                            &revocation.requested_at,
                            "revocation mutation prepared",
                            &hash,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                let head = layout.heads_dir().join(head_name(2));
                if stage == 1 {
                    fs::remove_file(head).unwrap();
                } else {
                    fs::rename(&head, layout.pending_path(&head)).unwrap();
                }
            }

            let mut retry = layout.begin_wsb_revocation().unwrap();
            retry.persist_staged_revocation(&revocation).unwrap();
            drop(retry);
            assert!(matches!(
                layout.status().unwrap(),
                RecoveryStatus::RevokedPendingDiscard {
                    revocation: Some(_),
                    last_sequence: 3
                }
            ));
            assert_eq!(
                layout
                    .write_approval(&ApprovalRecord::for_plan(&plan, "admin", "later").unwrap())
                    .unwrap_err()
                    .code
                    .as_ref(),
                "AIW_WSB_REVOKED"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn recovered_revocation_target_is_regenerated_while_complete_pending_is_preserved() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        let revocation = wsb_revocation(&layout, &plan, &import);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let mut guard = layout.begin_wsb_revocation().unwrap();
        let control = guard.control_path().unwrap();
        fs::create_dir(&control).unwrap();
        let hash = hash_value(&revocation).unwrap();
        let pending = layout.pending_path(&layout.wsb_revocation_path());
        write_complete_new(&pending, &revocation, layout.run_id(), "test").unwrap();
        layout
            .append_record(
                artifact_event(
                    RunEventKind::RevocationIntent,
                    &revocation.requested_at,
                    "revocation mutation prepared",
                    &hash,
                )
                .unwrap(),
            )
            .unwrap();
        let outside = root.parent().unwrap().join(format!(
            "{}-external-revocation.json",
            root.file_name().unwrap().to_string_lossy()
        ));
        fs::write(
            &outside,
            json_file_bytes(&revocation, layout.run_id()).unwrap(),
        )
        .unwrap();
        fs::hard_link(&outside, layout.wsb_revocation_path()).unwrap();

        guard.persist_staged_revocation(&revocation).unwrap();
        drop(guard);
        fs::write(&outside, b"externally mutated").unwrap();
        let observed: WsbRevocationRecord = read_json(
            &layout.wsb_revocation_path(),
            MAX_ARTIFACT,
            layout.run_id(),
            "test",
        )
        .unwrap();
        assert_eq!(observed, revocation);
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(&control).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn target_only_hard_link_is_data_only_and_regenerated() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        let revocation = wsb_revocation(&layout, &plan, &import);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let guard = layout.begin_wsb_revocation().unwrap();
        let hash = hash_value(&revocation).unwrap();
        layout
            .append_record(
                artifact_event(
                    RunEventKind::RevocationIntent,
                    &revocation.requested_at,
                    "revocation mutation prepared",
                    &hash,
                )
                .unwrap(),
            )
            .unwrap();
        let outside = root.parent().unwrap().join(format!(
            "{}-target-only-revocation.json",
            root.file_name().unwrap().to_string_lossy()
        ));
        fs::write(
            &outside,
            json_file_bytes(&revocation, layout.run_id()).unwrap(),
        )
        .unwrap();
        fs::hard_link(&outside, layout.wsb_revocation_path()).unwrap();
        drop(guard);

        let mut retry = layout.begin_wsb_revocation().unwrap();
        assert_eq!(retry.recoverable_revocation(), Some(&revocation));
        retry.persist_staged_revocation(&revocation).unwrap();
        drop(retry);
        fs::write(&outside, b"externally mutated").unwrap();
        let observed: WsbRevocationRecord = read_json(
            &layout.wsb_revocation_path(),
            MAX_ARTIFACT,
            layout.run_id(),
            "test",
        )
        .unwrap();
        assert_eq!(observed, revocation);
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn outer_coordination_keeps_waiter_out_of_tree_during_revoke_and_rename() {
        let root = root();
        let layout = Arc::new(layout(&root, "run-one"));
        let plan = wsb_plan("run-one");
        let import = wsb_import(&plan);
        let revocation = wsb_revocation(&layout, &plan, &import);
        layout
            .create_or_verify_pending_wsb_import(&plan, &import)
            .unwrap();
        let mut guard = layout.begin_wsb_revocation().unwrap();
        let control = guard.control_path().unwrap();
        let approval_layout = Arc::clone(&layout);
        let approval_plan = plan.clone();
        let (busy_sender, busy_receiver) = mpsc::channel();
        let approval = thread::spawn(move || {
            assert!(matches!(
                try_acquire_run_coordination(
                    &approval_layout.coordination_key,
                    RunCoordinationMode::Normal,
                ),
                Err(RunCoordinationError::LeaseUnavailable)
            ));
            busy_sender.send(()).unwrap();
            approval_layout
                .write_approval(&ApprovalRecord::for_plan(&approval_plan, "admin", "now").unwrap())
        });
        busy_receiver.recv().unwrap();
        thread::sleep(Duration::from_millis(100));
        assert!(
            !approval.is_finished(),
            "approval must wait on outer coordination rather than returning busy"
        );
        fs::create_dir(&control).unwrap();
        guard.persist_staged_revocation(&revocation).unwrap();
        guard.release_inner_lock_for_test();

        let renamed = root.with_file_name(format!(
            "{}-renamed",
            root.file_name().unwrap().to_string_lossy()
        ));
        fs::rename(&root, &renamed).unwrap();
        assert!(!root.exists());
        assert!(renamed.is_dir());
        assert!(
            !approval.is_finished(),
            "waiter must not enter the workspace while outer coordination is held"
        );
        drop(guard);
        assert_eq!(
            approval.join().unwrap().unwrap_err().code.as_ref(),
            "AIW_WSB_REVOKED"
        );
        assert!(!layout.approval_path().exists());
        fs::remove_dir_all(&control).unwrap();
        fs::remove_dir_all(renamed).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn coordination_failures_have_stable_retry_semantics() {
        let timeout = coordination_error("lock", "run-one", RunCoordinationError::LeaseUnavailable);
        assert_eq!(timeout.code.as_ref(), "AIW_RUN_COORDINATION_TIMEOUT");
        assert!(timeout.retryable);

        let abandoned =
            coordination_error("lock", "run-one", RunCoordinationError::RecoveryRequired);
        assert_eq!(abandoned.code.as_ref(), "AIW_RUN_RECOVERY_REQUIRED");
        assert!(!abandoned.retryable);
    }

    #[test]
    fn status_is_read_only_and_reports_pending_recovery() {
        let root = root();
        let missing = layout(&root, "missing");
        assert!(missing.status().is_err());
        assert!(!root.join("runs").exists());

        let layout = layout(&root, "run-one");
        let plan = plan("run-one");
        layout.create(&plan).unwrap();
        let before = fs::read(layout.journal_path()).unwrap();
        assert!(matches!(
            layout.status().unwrap(),
            RecoveryStatus::PendingApproval { .. }
        ));
        assert_eq!(fs::read(layout.journal_path()).unwrap(), before);

        let approval = ApprovalRecord::for_plan(&plan, "admin", "now").unwrap();
        {
            let _lock = layout.acquire_lock("test").unwrap();
            let hash = hash_value(&approval).unwrap();
            layout
                .append_record(
                    artifact_event(RunEventKind::ApprovalIntent, "now", "intent", &hash).unwrap(),
                )
                .unwrap();
        }
        let pending = fs::read(layout.journal_path()).unwrap();
        assert!(matches!(
            layout.status().unwrap(),
            RecoveryStatus::RecoveryRequired {
                pending_event: RunEventKind::ApprovalIntent,
                ..
            }
        ));
        assert_eq!(fs::read(layout.journal_path()).unwrap(), pending);
        assert!(!layout.approval_path().exists());
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
            let _lock = layout.acquire_lock("test").unwrap();
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
    fn interrupted_terminal_publication_recovers_before_an_idempotent_retry() {
        for published in [false, true] {
            let root = root();
            let layout = layout(&root, "run-one");
            let plan = plan("run-one");
            layout.create(&plan).unwrap();
            approve(&layout, &plan);
            let result = RunResult::new(
                "run-one",
                RunOutcome::Failed,
                "recovery-time-not-trusted",
                None,
                true,
                "interrupted completion processing after verified cleanup",
            )
            .unwrap();
            {
                let _lock = layout.acquire_lock("test").unwrap();
                let hash = hash_value(&result).unwrap();
                layout
                    .append_record(
                        artifact_event(
                            RunEventKind::TerminalIntent,
                            &result.completed_at,
                            "result",
                            &hash,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                if published {
                    write_complete_new(&layout.result_path(), &result, "run-one", "test").unwrap();
                }
                let mut journal = OpenOptions::new()
                    .append(true)
                    .open(layout.journal_path())
                    .unwrap();
                journal.write_all(b"partial").unwrap();
                journal.sync_all().unwrap();
            }
            let status = layout.recovery_status().unwrap();
            if published {
                assert!(matches!(status, RecoveryStatus::Terminal { .. }));
            } else {
                assert!(matches!(status, RecoveryStatus::Ready { .. }));
                layout.write_result(&result).unwrap();
            }
            assert_eq!(layout.read_result().unwrap(), result);
            let journal_before = fs::read(layout.journal_path()).unwrap();
            let result_before = fs::read(layout.result_path()).unwrap();
            assert!(matches!(
                layout.recovery_status().unwrap(),
                RecoveryStatus::Terminal { .. }
            ));
            assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_before);
            assert_eq!(fs::read(layout.result_path()).unwrap(), result_before);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn recovery_aborts_unpublished_intent_and_allows_a_clean_retry() {
        let root = root();
        let layout = layout(&root, "run-one");
        let plan = plan("run-one");
        layout.create(&plan).unwrap();
        let approval = ApprovalRecord::for_plan(&plan, "admin", "now").unwrap();
        {
            let _lock = layout.acquire_lock("test").unwrap();
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
            let _lock = fourth.acquire_lock("test").unwrap();
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

    #[cfg(windows)]
    #[test]
    fn dangling_stage_artifact_link_is_rejected_and_preserved() {
        use std::os::windows::fs::symlink_file;
        let root = root();
        let layout = layout(&root, "run-one");
        let expected = wsb_plan("run-one");
        let receipt = wsb_import(&expected);
        let stage;
        let link;
        {
            let _lock = layout.acquire_lock("test").unwrap();
            stage = layout.wsb_import_stage_path(&expected).unwrap();
            fs::create_dir(&stage).unwrap();
            link = stage.join("plan.json");
            if symlink_file(stage.join("missing-plan.json"), &link).is_err() {
                drop(_lock);
                fs::remove_dir_all(root).unwrap();
                return;
            }
        }
        let error = layout
            .create_or_verify_pending_wsb_import(&expected, &receipt)
            .unwrap_err();
        assert_eq!(error.code.as_ref(), "AIW_PATH_UNSAFE");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(!layout.run_dir().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn external_hard_links_are_unlinked_before_wsb_import_publication() {
        for pending in [false, true] {
            let root = root();
            let layout = layout(&root, "run-one");
            let expected = wsb_plan("run-one");
            let receipt = wsb_import(&expected);
            let expected_bytes = json_file_bytes(&expected, layout.run_id()).unwrap();
            let external = root.join(if pending {
                "external-pending-plan.json"
            } else {
                "external-final-plan.json"
            });
            let external_bytes = if pending {
                expected_bytes[..expected_bytes.len() / 2].to_vec()
            } else {
                expected_bytes
            };
            fs::write(&external, &external_bytes).unwrap();
            let staged;
            {
                let _lock = layout.acquire_lock("test").unwrap();
                let stage = layout.wsb_import_stage_path(&expected).unwrap();
                fs::create_dir(&stage).unwrap();
                let target = stage.join("plan.json");
                staged = if pending {
                    layout.pending_path(&target)
                } else {
                    target
                };
                fs::hard_link(&external, &staged).unwrap();
            }
            assert_eq!(
                layout
                    .create_or_verify_pending_wsb_import(&expected, &receipt)
                    .unwrap(),
                PendingRunDisposition::Created
            );
            assert_eq!(fs::read(&external).unwrap(), external_bytes);
            assert!(!staged.exists());
            let published_before = fs::read(layout.plan_path()).unwrap();
            fs::write(&external, b"external mutation").unwrap();
            assert_eq!(fs::read(layout.plan_path()).unwrap(), published_before);
            fs::remove_dir_all(root).unwrap();
        }
    }
}
