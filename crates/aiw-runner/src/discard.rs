//! Private, checkpoint-bound Windows Sandbox depublish transaction.
//!
//! This workflow may publish only the protected external intent, the hash-bound
//! internal revocation record, and the protected external fixed-tree
//! checkpoint and depublish commit. After depublish, it may publish one
//! immutable, chain-bound authorization record before each exact child-first
//! disposition. It has no provider operation or cleanup-complete claim.

use std::path::Path;

use aiw_evidence::canonical_json_bytes;
use aiw_orchestrator::{
    RunLayout, WSB_DISCARD_CHECKPOINT_POLICY_VERSION, WSB_DISCARD_CHECKPOINT_SCHEMA_VERSION,
    WSB_REVOCATION_SCHEMA_VERSION, WsbDiscardCheckpointFileIdentity, WsbDiscardCheckpointV0Alpha1,
    WsbOuterDiscardAuthority, WsbRevocationRecord, project_revision_hash,
};
use aiw_probe::{
    WSB_FIXED_OBJECT_DELETE_ORDER, WSB_FIXED_TREE_CONTRACT_VERSION,
    WSB_FIXED_TREE_DELETE_ORDER_VERSION, WorkspaceBindingEvidence, WsbFixedObjectKind,
    WsbFixedTreeInventoryEvidence,
};
use aiw_schema::Project;
use aiw_windows_platform::{
    CleanupReceiptBindingEvidence, CleanupReceiptError, CleanupReceiptSlotState,
    DepublishCommitBindingEvidence, DepublishCommitError, DiscardCheckpointBindingEvidence,
    DiscardCheckpointError, DiscardIntentBindingEvidence, DiscardIntentError,
    DispositionProgressBindingEvidence, DispositionProgressError, DispositionProgressSlotState,
    ExactDisposeError, HeldCheckpointBoundWsbDisposition, HeldCleanupReceiptPublication,
    HeldDepublishCommitPublication, HeldDiscardCheckpointPublication, HeldDiscardIntentPublication,
    HeldDispositionProgressPublication, ReopenedCleanupReceipt, ReopenedDepublishCommit,
    ReopenedDiscardCheckpoint, ReopenedDiscardIntent, ReopenedDispositionProgress,
    RunCoordinationKey, RunCoordinationLease, RunCoordinationMode, WsbRootDepublishObservation,
    WsbRootNamespaceState, classify_checkpoint_bound_wsb_root, classify_cleanup_receipt_slot,
    classify_disposition_progress_slot, hold_fixed_wsb_tree_for_checkpoint,
    locate_depublish_commit_from_persisted_root, reopen_checkpoint_bound_wsb_disposition,
    reopen_checkpoint_bound_wsb_root, reopen_existing_cleanup_receipt,
    reopen_existing_depublish_commit, reopen_existing_discard_checkpoint,
    reopen_existing_disposition_progress, reopen_prepared_cleanup_receipt,
    reopen_prepared_depublish_commit, reopen_prepared_discard_checkpoint,
    reopen_prepared_discard_intent, reopen_prepared_disposition_progress,
    reopen_published_discard_intent, reserve_cleanup_receipt, reserve_depublish_commit,
    reserve_discard_checkpoint, reserve_disposition_progress, stage_discard_intent,
    try_acquire_run_coordination,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::preparation::{
    WsbPreparationError, open_verified_windows_sandbox_preparation,
    require_current_readiness_matches_receipt,
};

const DISCARD_INTENT_SCHEMA: &str = "aiw.dev/wsb-discard-intent/v0alpha1";
const FIXED_TREE_INVENTORY_RECEIPT_SCHEMA: &str =
    "aiw.dev/wsb-fixed-tree-inventory-receipt/v0alpha1";
const DISCARD_PHASE: &str = "revocationPending";
const CONTROL_PREFIX: &str = ".aiw-discard-v1-";
const TOMBSTONE_PREFIX: &str = ".aiw-discarded-v1-";
const DEPUBLISH_COMMIT_SCHEMA: &str = "aiw.dev/wsb-depublish-commit/v0alpha1";
const DEPUBLISH_COMMIT_POLICY: &str = "checkpoint-bound-original-to-tombstone-v1";
const DEPUBLISH_OPERATION: &str = "originalToCheckpointBoundTombstone";
const DISPOSITION_PROGRESS_SCHEMA: &str = "aiw.dev/wsb-disposition-progress/v0alpha1";
const DISPOSITION_PROGRESS_POLICY: &str = "immutable-pre-disposition-chain-v1";
const DISPOSITION_OPERATION: &str = "deleteExactCheckpointObject";
const TERMINAL_CLEANUP_SCHEMA: &str = "aiw.dev/wsb-terminal-cleanup-receipt/v0alpha1";
const TERMINAL_CLEANUP_POLICY: &str = "checkpoint-bound-full-disposition-v1";
const TERMINAL_CLEANUP_OPERATION: &str = "recordTerminalCleanup";

#[derive(Debug, Error)]
pub(crate) enum WsbDiscardPreparationError {
    #[error("discard preparation contract is invalid: {0}")]
    Contract(String),
    #[error("verified WSB preparation could not be reopened: {0}")]
    Preparation(#[from] WsbPreparationError),
    #[error("run revocation state is invalid: {0}")]
    Orchestrator(String),
    #[error("protected discard intent failed: {0}")]
    Platform(#[from] DiscardIntentError),
    #[error("read-only fixed-tree inventory failed: {0}")]
    Inventory(#[from] ExactDisposeError),
    #[error("protected discard checkpoint failed: {0}")]
    Checkpoint(#[from] DiscardCheckpointError),
    #[error("protected depublish commit failed: {0}")]
    DepublishCommit(#[from] DepublishCommitError),
    #[error("protected disposition progress failed: {0}")]
    DispositionProgress(#[from] DispositionProgressError),
    #[error("protected terminal cleanup receipt failed: {0}")]
    CleanupReceipt(#[from] CleanupReceiptError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WsbDiscardIntent {
    schema_version: String,
    run_id: String,
    cleanup_id: String,
    phase: String,
    fixed_tree_contract: String,
    requested_by: String,
    requested_at: String,
    tombstone_leaf: String,
    control_path: String,
    coordination_binding_sha256: String,
    plan_sha256: String,
    import_receipt_sha256: String,
    preparation_receipt_sha256: String,
    project_revision_sha256: String,
    guest_agent_sha256: String,
    provider_sha256: String,
    provider_package_sha256: String,
    provider_catalog_sha256: String,
    provider_file_identity_sha256: String,
    provider_protocol_sha256: String,
    windows_sandbox_plan_sha256: String,
    workspace: WorkspaceBindingEvidence,
    workspace_identity_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanupIdMaterial<'a> {
    schema_version: &'a str,
    run_id: &'a str,
    phase: &'a str,
    fixed_tree_contract: &'a str,
    requested_by: &'a str,
    requested_at: &'a str,
    control_path: &'a str,
    coordination_binding_sha256: &'a str,
    plan_sha256: &'a str,
    import_receipt_sha256: &'a str,
    preparation_receipt_sha256: &'a str,
    project_revision_sha256: &'a str,
    guest_agent_sha256: &'a str,
    provider_sha256: &'a str,
    provider_package_sha256: &'a str,
    provider_catalog_sha256: &'a str,
    provider_file_identity_sha256: &'a str,
    provider_protocol_sha256: &'a str,
    windows_sandbox_plan_sha256: &'a str,
    workspace_identity_sha256: &'a str,
}

pub(crate) struct PreparedWsbDiscard<'a> {
    authority: WsbOuterDiscardAuthority<'a>,
    intent: WsbDiscardIntent,
    inventory_receipt: WsbFixedTreeInventoryReceipt,
    checkpoint: WsbDiscardCheckpointV0Alpha1,
    checkpoint_binding: DiscardCheckpointBindingEvidence,
    checkpoint_publication: HeldDiscardCheckpointPublication,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WsbFixedTreeInventoryReceipt {
    pub(crate) schema_version: String,
    pub(crate) run_id: String,
    pub(crate) cleanup_id: String,
    pub(crate) discard_intent_sha256: String,
    pub(crate) revocation_sha256: String,
    pub(crate) workspace_identity_sha256: String,
    pub(crate) inventory_sha256: String,
    pub(crate) inventory: WsbFixedTreeInventoryEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WsbDepublishCommitV0Alpha1 {
    schema_version: String,
    policy_version: String,
    operation: String,
    run_id: String,
    cleanup_id: String,
    store_key: String,
    workspace: WorkspaceBindingEvidence,
    workspace_identity_sha256: String,
    revocation_sha256: String,
    discard_intent_sha256: String,
    discard_intent_binding: DiscardIntentBindingEvidence,
    checkpoint_sha256: String,
    checkpoint_binding: DiscardCheckpointBindingEvidence,
    fixed_tree_contract_version: String,
    inventory_sha256: String,
    original_root: String,
    root_id: aiw_probe::DiscardIntentStableId,
    tombstone_leaf: String,
    tombstone_path: String,
    commit_parent_id: aiw_probe::DiscardIntentStableId,
    commit_file_id: aiw_probe::DiscardIntentStableId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WsbDispositionObjectV0Alpha1 {
    kind: WsbFixedObjectKind,
    relative_path: String,
    id: aiw_probe::DiscardIntentStableId,
    parent_id: aiw_probe::DiscardIntentStableId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WsbDispositionRecordFileV0Alpha1 {
    ordinal: u8,
    parent_id: aiw_probe::DiscardIntentStableId,
    file_id: aiw_probe::DiscardIntentStableId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WsbDispositionProgressV0Alpha1 {
    schema_version: String,
    policy_version: String,
    operation: String,
    delete_order_version: String,
    run_id: String,
    cleanup_id: String,
    store_key: String,
    workspace: WorkspaceBindingEvidence,
    workspace_identity_sha256: String,
    discard_intent_sha256: String,
    discard_intent_binding: DiscardIntentBindingEvidence,
    checkpoint_sha256: String,
    checkpoint_binding: DiscardCheckpointBindingEvidence,
    depublish_commit_sha256: String,
    depublish_commit_binding: DepublishCommitBindingEvidence,
    fixed_tree_contract_version: String,
    inventory_sha256: String,
    tombstone_leaf: String,
    tombstone_path: String,
    tombstone_root_id: aiw_probe::DiscardIntentStableId,
    ordinal: u8,
    completed_before: u8,
    next_object: WsbDispositionObjectV0Alpha1,
    previous_progress_sha256: String,
    record_file: WsbDispositionRecordFileV0Alpha1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum WsbOriginalRootTerminalState {
    Absent,
    UnrelatedReplacement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum WsbTombstoneTerminalState {
    Absent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WsbOriginalRootTerminalObservation {
    path: String,
    state: WsbOriginalRootTerminalState,
    replacement_id: Option<aiw_probe::DiscardIntentStableId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WsbPhysicalDispositionV0Alpha1 {
    expected_object_count: u8,
    completed_object_count: u8,
    tombstone_path: String,
    tombstone_root_id: aiw_probe::DiscardIntentStableId,
    tombstone_state: WsbTombstoneTerminalState,
    original_root: WsbOriginalRootTerminalObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WsbTerminalReceiptFileV0Alpha1 {
    parent_id: aiw_probe::DiscardIntentStableId,
    file_id: aiw_probe::DiscardIntentStableId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WsbTerminalCleanupReceiptV0Alpha1 {
    schema_version: String,
    policy_version: String,
    operation: String,
    run_id: String,
    cleanup_id: String,
    store_key: String,
    completed_at: String,
    workspace: WorkspaceBindingEvidence,
    workspace_identity_sha256: String,
    workspace_parent_id: aiw_probe::DiscardIntentStableId,
    discard_intent_sha256: String,
    discard_intent_binding: DiscardIntentBindingEvidence,
    checkpoint_sha256: String,
    checkpoint_binding: DiscardCheckpointBindingEvidence,
    depublish_commit_sha256: String,
    depublish_commit_binding: DepublishCommitBindingEvidence,
    fixed_tree_contract_version: String,
    inventory_sha256: String,
    delete_order_version: String,
    disposed_object_count: u8,
    final_progress_sha256: String,
    final_progress_binding: DispositionProgressBindingEvidence,
    physical_disposition: WsbPhysicalDispositionV0Alpha1,
    receipt_file: WsbTerminalReceiptFileV0Alpha1,
}

pub(crate) struct DepublishedWsbTombstone<'a> {
    prepared: PreparedWsbDiscard<'a>,
    commit: WsbDepublishCommitV0Alpha1,
    commit_publication: HeldDepublishCommitPublication,
    observation: WsbRootDepublishObservation,
}

pub(crate) struct RecoveredDepublishedWsbTombstone {
    _coordination: RunCoordinationLease,
    _intent: HeldDiscardIntentPublication,
    _checkpoint: HeldDiscardCheckpointPublication,
    checkpoint: WsbDiscardCheckpointV0Alpha1,
    depublish_commit: WsbDepublishCommitV0Alpha1,
    commit_publication: HeldDepublishCommitPublication,
    observation: WsbRootDepublishObservation,
}

impl RecoveredDepublishedWsbTombstone {
    pub(crate) fn observation(&self) -> &WsbRootDepublishObservation {
        &self.observation
    }

    pub(crate) fn revalidate(&self) -> Result<(), WsbDiscardPreparationError> {
        self._intent.revalidate()?;
        self._checkpoint.revalidate()?;
        self.commit_publication.revalidate()?;
        validate_depublish_commit(
            &self.depublish_commit,
            &self.checkpoint,
            self.commit_publication.evidence(),
        )?;
        Ok(())
    }
}

impl DepublishedWsbTombstone<'_> {
    pub(crate) fn observation(&self) -> &WsbRootDepublishObservation {
        &self.observation
    }

    pub(crate) fn revalidate(&self) -> Result<(), WsbDiscardPreparationError> {
        self.prepared.revalidate_checkpoint()?;
        self.commit_publication.revalidate()?;
        validate_depublish_commit(
            &self.commit,
            self.prepared.checkpoint(),
            self.commit_publication.evidence(),
        )
    }
}

pub(crate) trait WsbTombstoneDispositionAuthority {
    fn checkpoint(&self) -> &WsbDiscardCheckpointV0Alpha1;
    fn depublish_commit(&self) -> &WsbDepublishCommitV0Alpha1;
    fn depublish_binding(&self) -> &DepublishCommitBindingEvidence;
    fn revalidate_tombstone_authority(&self) -> Result<(), WsbDiscardPreparationError>;
}

impl WsbTombstoneDispositionAuthority for DepublishedWsbTombstone<'_> {
    fn checkpoint(&self) -> &WsbDiscardCheckpointV0Alpha1 {
        self.prepared.checkpoint()
    }
    fn depublish_commit(&self) -> &WsbDepublishCommitV0Alpha1 {
        &self.commit
    }
    fn depublish_binding(&self) -> &DepublishCommitBindingEvidence {
        self.commit_publication.evidence()
    }
    fn revalidate_tombstone_authority(&self) -> Result<(), WsbDiscardPreparationError> {
        self.revalidate()
    }
}

impl WsbTombstoneDispositionAuthority for RecoveredDepublishedWsbTombstone {
    fn checkpoint(&self) -> &WsbDiscardCheckpointV0Alpha1 {
        &self.checkpoint
    }
    fn depublish_commit(&self) -> &WsbDepublishCommitV0Alpha1 {
        &self.depublish_commit
    }
    fn depublish_binding(&self) -> &DepublishCommitBindingEvidence {
        self.commit_publication.evidence()
    }
    fn revalidate_tombstone_authority(&self) -> Result<(), WsbDiscardPreparationError> {
        self.revalidate()
    }
}

pub(crate) struct HeldWsbDispositionPrefix<A> {
    authority: A,
    progress: Vec<HeldDispositionProgressPublication>,
    tree: HeldCheckpointBoundWsbDisposition,
    completed_count: u8,
}

impl<A: WsbTombstoneDispositionAuthority> HeldWsbDispositionPrefix<A> {
    pub(crate) fn completed_count(&self) -> u8 {
        self.completed_count
    }

    pub(crate) fn revalidate(&self) -> Result<(), WsbDiscardPreparationError> {
        self.authority.revalidate_tombstone_authority()?;
        for progress in &self.progress {
            progress.revalidate()?;
        }
        self.tree.revalidate()?;
        Ok(())
    }
}

enum LoadedDispositionProgress {
    Published(
        WsbDispositionProgressV0Alpha1,
        HeldDispositionProgressPublication,
    ),
    Pending(
        WsbDispositionProgressV0Alpha1,
        aiw_windows_platform::PublishableDispositionProgress,
    ),
}

pub(crate) fn dispose_checkpoint_bound_wsb_tombstone<A>(
    authority: A,
) -> Result<HeldWsbDispositionPrefix<A>, WsbDiscardPreparationError>
where
    A: WsbTombstoneDispositionAuthority,
{
    resume_checkpoint_bound_wsb_disposition(authority, true)
}

fn reopen_completed_checkpoint_bound_wsb_disposition<A>(
    authority: A,
) -> Result<HeldWsbDispositionPrefix<A>, WsbDiscardPreparationError>
where
    A: WsbTombstoneDispositionAuthority,
{
    resume_checkpoint_bound_wsb_disposition(authority, false)
}

fn resume_checkpoint_bound_wsb_disposition<A>(
    authority: A,
    allow_disposition: bool,
) -> Result<HeldWsbDispositionPrefix<A>, WsbDiscardPreparationError>
where
    A: WsbTombstoneDispositionAuthority,
{
    authority.revalidate_tombstone_authority()?;
    let checkpoint = authority.checkpoint();
    let initial_root_state = classify_checkpoint_bound_wsb_root(&checkpoint.inventory)?;
    let workspace = &checkpoint.inventory.workspace;
    let run_id = &checkpoint.run_id;
    let store_key = &checkpoint.revocation.discard_intent_binding.store_key;
    let mut loaded = Vec::new();
    let mut previous_sha256 = canonical_hash(authority.depublish_commit())?;
    let mut gap = false;
    let mut saw_pending = false;
    for ordinal in 0..WSB_FIXED_OBJECT_DELETE_ORDER.len() as u8 {
        match classify_disposition_progress_slot(workspace, run_id, store_key, ordinal)? {
            DispositionProgressSlotState::Absent => gap = true,
            DispositionProgressSlotState::Ambiguous => {
                return Err(WsbDiscardPreparationError::Contract(format!(
                    "disposition progress slot {ordinal} is ambiguous"
                )));
            }
            DispositionProgressSlotState::Pending | DispositionProgressSlotState::Published => {
                if gap || saw_pending {
                    return Err(WsbDiscardPreparationError::Contract(
                        "disposition progress records are not one contiguous prefix".to_owned(),
                    ));
                }
                let existing =
                    reopen_existing_disposition_progress(workspace, run_id, store_key, ordinal)?;
                let progress: WsbDispositionProgressV0Alpha1 =
                    serde_json::from_slice(existing.bytes()).map_err(|error| {
                        WsbDiscardPreparationError::Contract(format!(
                            "persisted disposition progress is not the strict schema: {error}"
                        ))
                    })?;
                if canonical_bytes(&progress)? != existing.bytes() {
                    return Err(WsbDiscardPreparationError::Contract(
                        "persisted disposition progress is not canonical JSON".to_owned(),
                    ));
                }
                validate_disposition_progress(
                    &progress,
                    existing.binding(),
                    &authority,
                    &previous_sha256,
                )?;
                previous_sha256 = hash_bytes(existing.bytes());
                match existing.into_reopened() {
                    ReopenedDispositionProgress::Published(value) => {
                        loaded.push(LoadedDispositionProgress::Published(progress, value));
                    }
                    ReopenedDispositionProgress::Publishable(value) => {
                        saw_pending = true;
                        loaded.push(LoadedDispositionProgress::Pending(progress, value));
                    }
                }
            }
        }
    }

    let final_count = loaded
        .iter()
        .take_while(|record| matches!(record, LoadedDispositionProgress::Published(..)))
        .count() as u8;
    let has_pending = matches!(loaded.last(), Some(LoadedDispositionProgress::Pending(..)));
    let (mut physical_count, mut tree) = reopen_disposition_physical_prefix(&checkpoint.inventory)?;
    let disposition_complete = physical_count == WSB_FIXED_OBJECT_DELETE_ORDER.len() as u8;
    if (!disposition_complete && initial_root_state != WsbRootNamespaceState::Tombstone)
        || (disposition_complete
            && !matches!(
                initial_root_state,
                WsbRootNamespaceState::Absent | WsbRootNamespaceState::Foreign
            ))
    {
        return Err(WsbDiscardPreparationError::Contract(
            "root namespace state differs from the exact physical disposition prefix".to_owned(),
        ));
    }
    let physical_is_valid = disposition_prefixes_align(final_count, has_pending, physical_count);
    if !physical_is_valid {
        return Err(WsbDiscardPreparationError::Contract(format!(
            "physical disposition prefix {physical_count} differs from receipt prefix {final_count}"
        )));
    }

    let mut publications: Vec<HeldDispositionProgressPublication> = Vec::new();
    let mut pending = None;
    let depublish_anchor = canonical_hash(authority.depublish_commit())?;
    for record in loaded {
        match record {
            LoadedDispositionProgress::Published(progress, publication) => {
                let previous = publications
                    .last()
                    .map(|value| value.evidence().record_sha256())
                    .unwrap_or(&depublish_anchor);
                validate_disposition_progress(
                    &progress,
                    publication.evidence(),
                    &authority,
                    previous,
                )?;
                publications.push(publication);
            }
            LoadedDispositionProgress::Pending(progress, publishable) => {
                pending = Some((progress, publishable));
            }
        }
    }

    if !allow_disposition
        && (physical_count != WSB_FIXED_OBJECT_DELETE_ORDER.len() as u8
            || final_count != WSB_FIXED_OBJECT_DELETE_ORDER.len() as u8
            || pending.is_some())
    {
        return Err(WsbDiscardPreparationError::Contract(
            "terminal receipt recovery requires 19 published records and a complete physical disposition"
                .to_owned(),
        ));
    }

    while physical_count < WSB_FIXED_OBJECT_DELETE_ORDER.len() as u8 {
        authority.revalidate_tombstone_authority()?;
        for publication in &publications {
            publication.revalidate()?;
        }
        tree.revalidate()?;

        let publication = if physical_count + 1 == final_count {
            publications
                .get(usize::from(physical_count))
                .ok_or_else(|| {
                    WsbDiscardPreparationError::Contract(
                        "authorized disposition receipt is missing".to_owned(),
                    )
                })?
        } else {
            let previous = publications
                .last()
                .map(|value| value.evidence().record_sha256().to_owned())
                .unwrap_or(canonical_hash(authority.depublish_commit())?);
            let publication = if let Some((progress, publishable)) = pending.take() {
                if progress.ordinal != physical_count {
                    return Err(WsbDiscardPreparationError::Contract(
                        "pending disposition ordinal differs from physical prefix".to_owned(),
                    ));
                }
                authority.revalidate_tombstone_authority()?;
                tree.revalidate()?;
                let publication = publishable.publish()?;
                publication.revalidate()?;
                validate_disposition_progress(
                    &progress,
                    publication.evidence(),
                    &authority,
                    &previous,
                )?;
                publication
            } else {
                materialize_disposition_progress(&authority, &tree, physical_count, &previous)?
            };
            publications.push(publication);
            publications.last().expect("just pushed")
        };
        publication.revalidate()?;
        authority.revalidate_tombstone_authority()?;
        tree.revalidate()?;
        let expected = tree.next_step()?.ok_or_else(|| {
            WsbDiscardPreparationError::Contract(
                "physical tree completed before all disposition receipts".to_owned(),
            )
        })?;
        if expected.sequence != physical_count {
            return Err(WsbDiscardPreparationError::Contract(
                "native disposition sequence differs from receipt prefix".to_owned(),
            ));
        }
        let observed = tree.dispose_next()?;
        if observed != expected {
            return Err(WsbDiscardPreparationError::Contract(
                "native disposition observation differs from authorized next object".to_owned(),
            ));
        }
        physical_count += 1;
        tree.revalidate()?;
    }
    Ok(HeldWsbDispositionPrefix {
        authority,
        progress: publications,
        tree,
        completed_count: physical_count,
    })
}

fn disposition_prefixes_align(final_count: u8, has_pending: bool, physical_count: u8) -> bool {
    if has_pending {
        physical_count == final_count
    } else if final_count == 0 {
        physical_count == 0
    } else {
        physical_count == final_count || physical_count + 1 == final_count
    }
}

pub(crate) struct HeldTerminalWsbCleanupReceipt<A> {
    completed: HeldWsbDispositionPrefix<A>,
    receipt: WsbTerminalCleanupReceiptV0Alpha1,
    publication: HeldCleanupReceiptPublication,
}

impl<A: WsbTombstoneDispositionAuthority> HeldTerminalWsbCleanupReceipt<A> {
    pub(crate) fn revalidate(&self) -> Result<(), WsbDiscardPreparationError> {
        self.completed.revalidate()?;
        self.publication.revalidate()?;
        validate_terminal_cleanup_receipt(
            &self.receipt,
            self.publication.evidence(),
            &self.completed,
            &self.receipt.completed_at,
        )
    }

    pub(crate) fn receipt_sha256(&self) -> &str {
        self.publication.evidence().receipt_sha256()
    }
}

pub(crate) fn publish_terminal_wsb_cleanup_receipt<A>(
    completed: HeldWsbDispositionPrefix<A>,
    completed_at: &str,
) -> Result<HeldTerminalWsbCleanupReceipt<A>, WsbDiscardPreparationError>
where
    A: WsbTombstoneDispositionAuthority,
{
    require_canonical_utc_timestamp("completedAt", completed_at)?;
    completed.revalidate()?;
    if completed.completed_count != WSB_FIXED_OBJECT_DELETE_ORDER.len() as u8
        || completed.progress.len() != WSB_FIXED_OBJECT_DELETE_ORDER.len()
    {
        return Err(WsbDiscardPreparationError::Contract(
            "terminal cleanup receipt requires the complete 19-record disposition".to_owned(),
        ));
    }
    let checkpoint = completed.authority.checkpoint();
    let workspace = &checkpoint.inventory.workspace;
    let run_id = &checkpoint.run_id;
    let store_key = &checkpoint.revocation.discard_intent_binding.store_key;

    let (receipt, publication) = match classify_cleanup_receipt_slot(workspace, run_id, store_key)?
    {
        CleanupReceiptSlotState::Ambiguous => {
            return Err(WsbDiscardPreparationError::Contract(
                "terminal cleanup receipt pending and final namespaces are both occupied"
                    .to_owned(),
            ));
        }
        CleanupReceiptSlotState::Absent => {
            let reserved = reserve_cleanup_receipt(workspace, run_id, store_key)?;
            let binding = reserved.evidence().clone();
            let receipt = build_terminal_cleanup_receipt(&completed, &binding, completed_at)?;
            let bytes = canonical_bytes(&receipt)?;
            let sha256 = hash_bytes(&bytes);
            let staged = reserved.persist(&bytes, &sha256)?;
            let persisted_binding = staged.evidence().clone();
            drop(staged);
            completed.revalidate()?;
            validate_terminal_cleanup_receipt(
                &receipt,
                &persisted_binding,
                &completed,
                completed_at,
            )?;
            let reopened = reopen_prepared_cleanup_receipt(
                &bytes,
                &sha256,
                workspace,
                run_id,
                &persisted_binding,
            )?;
            let publication = match reopened {
                ReopenedCleanupReceipt::Publishable(value) => {
                    completed.revalidate()?;
                    validate_terminal_cleanup_receipt(
                        &receipt,
                        value.evidence(),
                        &completed,
                        completed_at,
                    )?;
                    value.publish()?
                }
                ReopenedCleanupReceipt::Published(value) => value,
            };
            (receipt, publication)
        }
        CleanupReceiptSlotState::Pending | CleanupReceiptSlotState::Published => {
            let existing = reopen_existing_cleanup_receipt(workspace, run_id, store_key)?;
            let receipt: WsbTerminalCleanupReceiptV0Alpha1 =
                serde_json::from_slice(existing.bytes()).map_err(|error| {
                    WsbDiscardPreparationError::Contract(format!(
                        "persisted terminal cleanup receipt is not the strict schema: {error}"
                    ))
                })?;
            if canonical_bytes(&receipt)? != existing.bytes() {
                return Err(WsbDiscardPreparationError::Contract(
                    "persisted terminal cleanup receipt is not canonical JSON".to_owned(),
                ));
            }
            validate_terminal_cleanup_receipt(
                &receipt,
                existing.binding(),
                &completed,
                completed_at,
            )?;
            let publication = match existing.into_reopened() {
                ReopenedCleanupReceipt::Publishable(value) => {
                    completed.revalidate()?;
                    validate_terminal_cleanup_receipt(
                        &receipt,
                        value.evidence(),
                        &completed,
                        completed_at,
                    )?;
                    value.publish()?
                }
                ReopenedCleanupReceipt::Published(value) => value,
            };
            (receipt, publication)
        }
    };
    completed.revalidate()?;
    publication.revalidate()?;
    validate_terminal_cleanup_receipt(&receipt, publication.evidence(), &completed, completed_at)?;
    Ok(HeldTerminalWsbCleanupReceipt {
        completed,
        receipt,
        publication,
    })
}

fn build_terminal_cleanup_receipt<A: WsbTombstoneDispositionAuthority>(
    completed: &HeldWsbDispositionPrefix<A>,
    binding: &CleanupReceiptBindingEvidence,
    completed_at: &str,
) -> Result<WsbTerminalCleanupReceiptV0Alpha1, WsbDiscardPreparationError> {
    let checkpoint = completed.authority.checkpoint();
    let inventory = &checkpoint.inventory;
    let final_progress = completed.progress.last().ok_or_else(|| {
        WsbDiscardPreparationError::Contract(
            "terminal cleanup receipt has no final disposition progress".to_owned(),
        )
    })?;
    if final_progress.ordinal() != WSB_FIXED_OBJECT_DELETE_ORDER.len() as u8 - 1 {
        return Err(WsbDiscardPreparationError::Contract(
            "terminal cleanup receipt final progress is not ordinal 18".to_owned(),
        ));
    }
    let replacement_id = completed.tree.completed_original_replacement_id()?;
    let original_root = WsbOriginalRootTerminalObservation {
        path: inventory.original_root.clone(),
        state: if replacement_id.is_some() {
            WsbOriginalRootTerminalState::UnrelatedReplacement
        } else {
            WsbOriginalRootTerminalState::Absent
        },
        replacement_id,
    };
    Ok(WsbTerminalCleanupReceiptV0Alpha1 {
        schema_version: TERMINAL_CLEANUP_SCHEMA.to_owned(),
        policy_version: TERMINAL_CLEANUP_POLICY.to_owned(),
        operation: TERMINAL_CLEANUP_OPERATION.to_owned(),
        run_id: checkpoint.run_id.clone(),
        cleanup_id: checkpoint.cleanup_id.clone(),
        store_key: checkpoint
            .revocation
            .discard_intent_binding
            .store_key
            .clone(),
        completed_at: completed_at.to_owned(),
        workspace: inventory.workspace.clone(),
        workspace_identity_sha256: checkpoint.revocation.workspace_identity_sha256.clone(),
        workspace_parent_id: inventory.parent_id.clone(),
        discard_intent_sha256: checkpoint.revocation.discard_intent_sha256.clone(),
        discard_intent_binding: checkpoint.revocation.discard_intent_binding.clone(),
        checkpoint_sha256: canonical_hash(checkpoint)?,
        checkpoint_binding: completed
            .authority
            .depublish_commit()
            .checkpoint_binding
            .clone(),
        depublish_commit_sha256: canonical_hash(completed.authority.depublish_commit())?,
        depublish_commit_binding: completed.authority.depublish_binding().clone(),
        fixed_tree_contract_version: checkpoint.fixed_tree_contract_version.clone(),
        inventory_sha256: checkpoint.inventory_sha256.clone(),
        delete_order_version: WSB_FIXED_TREE_DELETE_ORDER_VERSION.to_owned(),
        disposed_object_count: completed.completed_count,
        final_progress_sha256: final_progress.evidence().record_sha256().to_owned(),
        final_progress_binding: final_progress.evidence().clone(),
        physical_disposition: WsbPhysicalDispositionV0Alpha1 {
            expected_object_count: WSB_FIXED_OBJECT_DELETE_ORDER.len() as u8,
            completed_object_count: completed.completed_count,
            tombstone_path: completed
                .authority
                .depublish_commit()
                .tombstone_path
                .clone(),
            tombstone_root_id: inventory.objects[0].id.clone(),
            tombstone_state: WsbTombstoneTerminalState::Absent,
            original_root,
        },
        receipt_file: WsbTerminalReceiptFileV0Alpha1 {
            parent_id: binding.parent_id().clone(),
            file_id: binding.receipt_id().clone(),
        },
    })
}

fn validate_terminal_cleanup_receipt<A: WsbTombstoneDispositionAuthority>(
    receipt: &WsbTerminalCleanupReceiptV0Alpha1,
    binding: &CleanupReceiptBindingEvidence,
    completed: &HeldWsbDispositionPrefix<A>,
    completed_at: &str,
) -> Result<(), WsbDiscardPreparationError> {
    let expected = build_terminal_cleanup_receipt(completed, binding, completed_at)?;
    let bytes = canonical_bytes(receipt)?;
    let valid = receipt == &expected
        && binding.run_id() == receipt.run_id
        && binding.store_key() == receipt.store_key
        && binding.owner_sid() == receipt.workspace.owner_sid
        && binding.parent_id() == &receipt.workspace_parent_id
        && binding.receipt_sha256() == hash_bytes(&bytes)
        && binding.receipt_size() == bytes.len() as u64;
    if !valid {
        return Err(WsbDiscardPreparationError::Contract(
            "terminal cleanup receipt differs from its exact authority or platform binding"
                .to_owned(),
        ));
    }
    Ok(())
}

fn reopen_disposition_physical_prefix(
    inventory: &WsbFixedTreeInventoryEvidence,
) -> Result<(u8, HeldCheckpointBoundWsbDisposition), WsbDiscardPreparationError> {
    for completed in 0..=WSB_FIXED_OBJECT_DELETE_ORDER.len() as u8 {
        if let Ok(tree) = reopen_checkpoint_bound_wsb_disposition(inventory, completed) {
            return Ok((completed, tree));
        }
    }
    Err(WsbDiscardPreparationError::Contract(
        "tombstone objects do not form one exact disposition prefix".to_owned(),
    ))
}

fn materialize_disposition_progress<A: WsbTombstoneDispositionAuthority>(
    authority: &A,
    tree: &HeldCheckpointBoundWsbDisposition,
    ordinal: u8,
    previous_progress_sha256: &str,
) -> Result<HeldDispositionProgressPublication, WsbDiscardPreparationError> {
    authority.revalidate_tombstone_authority()?;
    tree.revalidate()?;
    let checkpoint = authority.checkpoint();
    let workspace = &checkpoint.inventory.workspace;
    let store_key = &checkpoint.revocation.discard_intent_binding.store_key;
    let reserved = reserve_disposition_progress(workspace, &checkpoint.run_id, store_key, ordinal)?;
    let binding = reserved.evidence().clone();
    let progress = build_disposition_progress(authority, &binding, previous_progress_sha256)?;
    let bytes = canonical_bytes(&progress)?;
    let sha256 = hash_bytes(&bytes);
    let staged = reserved.persist(&bytes, &sha256)?;
    let persisted_binding = staged.evidence().clone();
    drop(staged);
    authority.revalidate_tombstone_authority()?;
    tree.revalidate()?;
    validate_disposition_progress(
        &progress,
        &persisted_binding,
        authority,
        previous_progress_sha256,
    )?;
    let reopened = reopen_prepared_disposition_progress(
        &bytes,
        &sha256,
        workspace,
        &checkpoint.run_id,
        &persisted_binding,
    )?;
    let publication = match reopened {
        ReopenedDispositionProgress::Publishable(value) => value.publish()?,
        ReopenedDispositionProgress::Published(value) => value,
    };
    publication.revalidate()?;
    authority.revalidate_tombstone_authority()?;
    tree.revalidate()?;
    validate_disposition_progress(
        &progress,
        publication.evidence(),
        authority,
        previous_progress_sha256,
    )?;
    Ok(publication)
}

fn build_disposition_progress<A: WsbTombstoneDispositionAuthority>(
    authority: &A,
    binding: &DispositionProgressBindingEvidence,
    previous_progress_sha256: &str,
) -> Result<WsbDispositionProgressV0Alpha1, WsbDiscardPreparationError> {
    let ordinal = binding.ordinal();
    let checkpoint = authority.checkpoint();
    let inventory = &checkpoint.inventory;
    let kind = *WSB_FIXED_OBJECT_DELETE_ORDER
        .get(usize::from(ordinal))
        .ok_or_else(|| {
            WsbDiscardPreparationError::Contract(
                "disposition ordinal exceeds fixed delete order".to_owned(),
            )
        })?;
    let object = inventory
        .objects
        .iter()
        .find(|object| object.kind == kind)
        .ok_or_else(|| {
            WsbDiscardPreparationError::Contract(
                "disposition object is absent from fixed inventory".to_owned(),
            )
        })?;
    let parent_id = match kind.parent() {
        None => inventory.parent_id.clone(),
        Some(parent) => inventory
            .objects
            .iter()
            .find(|object| object.kind == parent)
            .map(|object| object.id.clone())
            .ok_or_else(|| {
                WsbDiscardPreparationError::Contract(
                    "disposition parent is absent from fixed inventory".to_owned(),
                )
            })?,
    };
    let progress = WsbDispositionProgressV0Alpha1 {
        schema_version: DISPOSITION_PROGRESS_SCHEMA.to_owned(),
        policy_version: DISPOSITION_PROGRESS_POLICY.to_owned(),
        operation: DISPOSITION_OPERATION.to_owned(),
        delete_order_version: WSB_FIXED_TREE_DELETE_ORDER_VERSION.to_owned(),
        run_id: checkpoint.run_id.clone(),
        cleanup_id: checkpoint.cleanup_id.clone(),
        store_key: checkpoint
            .revocation
            .discard_intent_binding
            .store_key
            .clone(),
        workspace: inventory.workspace.clone(),
        workspace_identity_sha256: checkpoint.revocation.workspace_identity_sha256.clone(),
        discard_intent_sha256: checkpoint.revocation.discard_intent_sha256.clone(),
        discard_intent_binding: checkpoint.revocation.discard_intent_binding.clone(),
        checkpoint_sha256: canonical_hash(checkpoint)?,
        checkpoint_binding: authority.depublish_commit().checkpoint_binding.clone(),
        depublish_commit_sha256: canonical_hash(authority.depublish_commit())?,
        depublish_commit_binding: authority.depublish_binding().clone(),
        fixed_tree_contract_version: checkpoint.fixed_tree_contract_version.clone(),
        inventory_sha256: checkpoint.inventory_sha256.clone(),
        tombstone_leaf: inventory.tombstone_leaf.clone(),
        tombstone_path: authority.depublish_commit().tombstone_path.clone(),
        tombstone_root_id: inventory.objects[0].id.clone(),
        ordinal,
        completed_before: ordinal,
        next_object: WsbDispositionObjectV0Alpha1 {
            kind,
            relative_path: object.relative_path.clone(),
            id: object.id.clone(),
            parent_id,
        },
        previous_progress_sha256: previous_progress_sha256.to_owned(),
        record_file: WsbDispositionRecordFileV0Alpha1 {
            ordinal,
            parent_id: binding.parent_id().clone(),
            file_id: binding.record_id().clone(),
        },
    };
    Ok(progress)
}

fn validate_disposition_progress<A: WsbTombstoneDispositionAuthority>(
    progress: &WsbDispositionProgressV0Alpha1,
    binding: &DispositionProgressBindingEvidence,
    authority: &A,
    previous_progress_sha256: &str,
) -> Result<(), WsbDiscardPreparationError> {
    let expected = build_disposition_progress(authority, binding, previous_progress_sha256)?;
    let bytes = canonical_bytes(progress)?;
    let checks = [
        (progress == &expected, "authority"),
        (
            progress.ordinal == progress.completed_before,
            "completed-before",
        ),
        (binding.run_id() == progress.run_id, "run-id"),
        (binding.store_key() == progress.store_key, "store-key"),
        (binding.ordinal() == progress.ordinal, "ordinal"),
        (binding.owner_sid() == progress.workspace.owner_sid, "owner"),
        (
            binding.parent_id().volume_serial_number
                == progress.workspace.parent.volume_serial_number,
            "parent-volume",
        ),
        (
            binding.parent_id().file_id == progress.workspace.parent.file_id,
            "parent-id",
        ),
        (binding.record_sha256() == hash_bytes(&bytes), "record-hash"),
        (binding.record_size() == bytes.len() as u64, "record-size"),
    ];
    if let Some((_, failed)) = checks.into_iter().find(|(valid, _)| !valid) {
        return Err(WsbDiscardPreparationError::Contract(format!(
            "disposition progress differs from its exact authority or platform binding: {failed}"
        )));
    }
    Ok(())
}

impl PreparedWsbDiscard<'_> {
    pub(crate) fn run_id(&self) -> &str {
        self.authority.run_id()
    }

    pub(crate) fn cleanup_id(&self) -> &str {
        &self.intent.cleanup_id
    }

    pub(crate) fn revocation(&self) -> &WsbRevocationRecord {
        self.authority.revocation()
    }

    pub(crate) fn inventory(&self) -> &WsbFixedTreeInventoryEvidence {
        &self.inventory_receipt.inventory
    }

    pub(crate) fn inventory_receipt(&self) -> &WsbFixedTreeInventoryReceipt {
        &self.inventory_receipt
    }

    pub(crate) fn checkpoint(&self) -> &WsbDiscardCheckpointV0Alpha1 {
        &self.checkpoint
    }

    pub(crate) fn checkpoint_binding(&self) -> &DiscardCheckpointBindingEvidence {
        &self.checkpoint_binding
    }

    pub(crate) fn revalidate_checkpoint(&self) -> Result<(), WsbDiscardPreparationError> {
        self.authority
            .revalidate_external_intent()
            .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
        self.checkpoint_publication.revalidate()?;
        self.checkpoint
            .validate()
            .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))
    }
}

pub(crate) fn depublish_prepared_windows_sandbox<'a>(
    prepared: PreparedWsbDiscard<'a>,
) -> Result<DepublishedWsbTombstone<'a>, WsbDiscardPreparationError> {
    prepared.revalidate_checkpoint()?;
    let state = classify_checkpoint_bound_wsb_root(prepared.inventory())?;
    if state != WsbRootNamespaceState::Original {
        return Err(WsbDiscardPreparationError::Contract(format!(
            "fresh depublish requires exact original state, observed {state:?}"
        )));
    }
    let tree = reopen_checkpoint_bound_wsb_root(prepared.inventory(), state)?;
    tree.revalidate()?;
    prepared.revalidate_checkpoint()?;

    let (commit, commit_publication) = materialize_depublish_commit(&prepared, &tree)?;
    prepared.revalidate_checkpoint()?;
    commit_publication.revalidate()?;
    tree.revalidate()?;
    let observation = tree.depublish_and_release()?;
    if classify_checkpoint_bound_wsb_root(prepared.inventory())? != WsbRootNamespaceState::Tombstone
        || observation.root_id != prepared.inventory().objects[0].id
    {
        return Err(WsbDiscardPreparationError::Contract(
            "depublish postcondition is not the exact checkpoint-bound tombstone".to_owned(),
        ));
    }
    Ok(DepublishedWsbTombstone {
        prepared,
        commit,
        commit_publication,
        observation,
    })
}

pub(crate) fn recover_committed_windows_sandbox_depublish(
    original_root: &Path,
    run_id: &str,
) -> Result<RecoveredDepublishedWsbTombstone, WsbDiscardPreparationError> {
    recover_windows_sandbox_depublish_authority(
        original_root,
        run_id,
        DepublishRecoveryMode::CompleteDepublish,
    )
}

pub(crate) fn recover_checkpoint_bound_wsb_disposition(
    original_root: &Path,
    run_id: &str,
) -> Result<HeldWsbDispositionPrefix<RecoveredDepublishedWsbTombstone>, WsbDiscardPreparationError>
{
    let authority = recover_windows_sandbox_depublish_authority(
        original_root,
        run_id,
        DepublishRecoveryMode::DispositionOnly,
    )?;
    dispose_checkpoint_bound_wsb_tombstone(authority)
}

pub(crate) fn recover_terminal_wsb_cleanup_receipt(
    original_root: &Path,
    run_id: &str,
    completed_at: &str,
) -> Result<
    HeldTerminalWsbCleanupReceipt<RecoveredDepublishedWsbTombstone>,
    WsbDiscardPreparationError,
> {
    let authority = recover_windows_sandbox_depublish_authority(
        original_root,
        run_id,
        DepublishRecoveryMode::DispositionOnly,
    )?;
    let completed = reopen_completed_checkpoint_bound_wsb_disposition(authority)?;
    publish_terminal_wsb_cleanup_receipt(completed, completed_at)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DepublishRecoveryMode {
    CompleteDepublish,
    DispositionOnly,
}

fn recover_windows_sandbox_depublish_authority(
    original_root: &Path,
    run_id: &str,
    mode: DepublishRecoveryMode,
) -> Result<RecoveredDepublishedWsbTombstone, WsbDiscardPreparationError> {
    let located = locate_depublish_commit_from_persisted_root(original_root, run_id)?;
    let commit: WsbDepublishCommitV0Alpha1 =
        serde_json::from_slice(located.commit()).map_err(|error| {
            WsbDiscardPreparationError::Contract(format!(
                "persisted depublish commit is not the strict schema: {error}"
            ))
        })?;
    if canonical_bytes(&commit)? != located.commit()
        || !same_windows_path_text(&commit.original_root, &original_root.to_string_lossy())
    {
        return Err(WsbDiscardPreparationError::Contract(
            "located depublish commit is noncanonical or bound to another original root".to_owned(),
        ));
    }
    let workspace = &commit.workspace;
    let key = RunCoordinationKey::from_workspace(workspace, run_id)
        .map_err(|error| WsbDiscardPreparationError::Contract(error.to_string()))?;
    if key.binding_sha256() != located.store_key() {
        return Err(WsbDiscardPreparationError::Contract(
            "located depublish commit store key differs from embedded workspace".to_owned(),
        ));
    }
    let existing = reopen_existing_depublish_commit(workspace, run_id, key.binding_sha256())?;
    if existing.commit() != located.commit() {
        return Err(WsbDiscardPreparationError::Contract(
            "depublish commit changed between bootstrap and strict reopen".to_owned(),
        ));
    }
    validate_depublish_envelope(&commit, workspace, run_id, existing.binding())?;
    let commit_binding = existing.binding().clone();
    let commit_reopened = existing.into_reopened();
    let coordination = try_acquire_run_coordination(&key, RunCoordinationMode::Recovery)
        .map_err(|error| WsbDiscardPreparationError::Contract(error.to_string()))?;

    let existing_checkpoint =
        reopen_existing_discard_checkpoint(workspace, run_id, key.binding_sha256())?;
    let checkpoint: WsbDiscardCheckpointV0Alpha1 =
        serde_json::from_slice(existing_checkpoint.checkpoint()).map_err(|error| {
            WsbDiscardPreparationError::Contract(format!(
                "persisted discard checkpoint is not the strict schema: {error}"
            ))
        })?;
    if canonical_bytes(&checkpoint)? != existing_checkpoint.checkpoint() {
        return Err(WsbDiscardPreparationError::Contract(
            "persisted discard checkpoint is not canonical JSON".to_owned(),
        ));
    }
    checkpoint
        .validate()
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
    validate_depublish_commit(&commit, &checkpoint, &commit_binding)?;
    if existing_checkpoint.binding() != &commit.checkpoint_binding {
        return Err(WsbDiscardPreparationError::Contract(
            "current checkpoint file binding differs from depublish authority".to_owned(),
        ));
    }
    let checkpoint_publication = match existing_checkpoint.into_reopened() {
        ReopenedDiscardCheckpoint::Published(value) => value,
        ReopenedDiscardCheckpoint::Publishable(_) => {
            return Err(WsbDiscardPreparationError::Contract(
                "pending-only discard checkpoint cannot authorize recovery".to_owned(),
            ));
        }
    };
    let intent_publication =
        reopen_published_discard_intent(workspace, run_id, &commit.discard_intent_binding)?;
    intent_publication.revalidate()?;
    checkpoint_publication.revalidate()?;

    let state = classify_checkpoint_bound_wsb_root(&checkpoint.inventory)?;
    let (commit_publication, observation) = match commit_reopened {
        ReopenedDepublishCommit::Publishable(value) => {
            if mode == DepublishRecoveryMode::DispositionOnly {
                return Err(WsbDiscardPreparationError::Contract(
                    "disposition recovery requires an already-published depublish commit"
                        .to_owned(),
                ));
            }
            if located.is_published() || state != WsbRootNamespaceState::Original {
                return Err(WsbDiscardPreparationError::Contract(
                    "pending depublish commit is not paired with the exact original tree"
                        .to_owned(),
                ));
            }
            let tree = reopen_checkpoint_bound_wsb_root(&checkpoint.inventory, state)?;
            tree.revalidate()?;
            intent_publication.revalidate()?;
            checkpoint_publication.revalidate()?;
            let publication = value.publish()?;
            publication.revalidate()?;
            tree.revalidate()?;
            let observation = tree.depublish_and_release()?;
            (publication, observation)
        }
        ReopenedDepublishCommit::Published(publication) => {
            publication.revalidate()?;
            let observation = match state {
                WsbRootNamespaceState::Original
                    if mode == DepublishRecoveryMode::CompleteDepublish =>
                {
                    let tree = reopen_checkpoint_bound_wsb_root(&checkpoint.inventory, state)?;
                    tree.revalidate()?;
                    intent_publication.revalidate()?;
                    checkpoint_publication.revalidate()?;
                    publication.revalidate()?;
                    tree.depublish_and_release()?
                }
                WsbRootNamespaceState::Tombstone => WsbRootDepublishObservation {
                    root_id: checkpoint.inventory.objects[0].id.clone(),
                    tombstone_path: commit.tombstone_path.clone(),
                },
                WsbRootNamespaceState::Absent | WsbRootNamespaceState::Foreign
                    if mode == DepublishRecoveryMode::DispositionOnly =>
                {
                    WsbRootDepublishObservation {
                        root_id: checkpoint.inventory.objects[0].id.clone(),
                        tombstone_path: commit.tombstone_path.clone(),
                    }
                }
                _ => {
                    return Err(WsbDiscardPreparationError::Contract(format!(
                        "committed depublish namespace is ambiguous or foreign: {state:?}"
                    )));
                }
            };
            (publication, observation)
        }
    };
    let recovered_state = classify_checkpoint_bound_wsb_root(&checkpoint.inventory)?;
    let state_is_valid = match mode {
        DepublishRecoveryMode::CompleteDepublish => {
            recovered_state == WsbRootNamespaceState::Tombstone
        }
        DepublishRecoveryMode::DispositionOnly => matches!(
            recovered_state,
            WsbRootNamespaceState::Tombstone
                | WsbRootNamespaceState::Absent
                | WsbRootNamespaceState::Foreign
        ),
    };
    if !state_is_valid {
        return Err(WsbDiscardPreparationError::Contract(
            "recovered depublish authority is outside the requested recovery mode".to_owned(),
        ));
    }
    Ok(RecoveredDepublishedWsbTombstone {
        _coordination: coordination,
        _intent: intent_publication,
        _checkpoint: checkpoint_publication,
        checkpoint,
        depublish_commit: commit,
        commit_publication,
        observation,
    })
}

fn materialize_depublish_commit(
    prepared: &PreparedWsbDiscard<'_>,
    tree: &aiw_windows_platform::HeldCheckpointBoundWsbRoot,
) -> Result<(WsbDepublishCommitV0Alpha1, HeldDepublishCommitPublication), WsbDiscardPreparationError>
{
    tree.revalidate()?;
    prepared.revalidate_checkpoint()?;
    let workspace = &prepared.inventory().workspace;
    let run_id = prepared.run_id();
    let store_key = &prepared.revocation().discard_intent_binding.store_key;
    match reserve_depublish_commit(workspace, run_id, store_key) {
        Ok(reserved) => {
            let commit = build_depublish_commit(
                prepared,
                reserved.parent_id().clone(),
                reserved.commit_id().clone(),
            )?;
            let bytes = canonical_bytes(&commit)?;
            let sha256 = hash_bytes(&bytes);
            let staged = reserved.persist(&bytes, &sha256)?;
            let binding = staged.evidence().clone();
            drop(staged);
            tree.revalidate()?;
            prepared.revalidate_checkpoint()?;
            let reopened =
                reopen_prepared_depublish_commit(&bytes, &sha256, workspace, run_id, &binding)?;
            let publication = publish_depublish_commit(reopened)?;
            publication.revalidate()?;
            validate_depublish_commit(&commit, prepared.checkpoint(), publication.evidence())?;
            Ok((commit, publication))
        }
        Err(DepublishCommitError::FinalConflict | DepublishCommitError::PendingConflict) => {
            let existing = reopen_existing_depublish_commit(workspace, run_id, store_key)?;
            let commit: WsbDepublishCommitV0Alpha1 = serde_json::from_slice(existing.commit())
                .map_err(|error| {
                    WsbDiscardPreparationError::Contract(format!(
                        "persisted depublish commit is not the strict schema: {error}"
                    ))
                })?;
            if canonical_bytes(&commit)? != existing.commit() {
                return Err(WsbDiscardPreparationError::Contract(
                    "persisted depublish commit is not canonical JSON".to_owned(),
                ));
            }
            if commit.checkpoint_binding != *prepared.checkpoint_binding() {
                return Err(WsbDiscardPreparationError::Contract(
                    "persisted depublish commit checkpoint binding differs from current authority"
                        .to_owned(),
                ));
            }
            validate_depublish_commit(&commit, prepared.checkpoint(), existing.binding())?;
            tree.revalidate()?;
            prepared.revalidate_checkpoint()?;
            let publication = match existing.into_reopened() {
                ReopenedDepublishCommit::Published(value) => value,
                ReopenedDepublishCommit::Publishable(value) => value.publish()?,
            };
            publication.revalidate()?;
            Ok((commit, publication))
        }
        Err(error) => Err(error.into()),
    }
}

fn publish_depublish_commit(
    reopened: ReopenedDepublishCommit,
) -> Result<HeldDepublishCommitPublication, WsbDiscardPreparationError> {
    match reopened {
        ReopenedDepublishCommit::Publishable(value) => Ok(value.publish()?),
        ReopenedDepublishCommit::Published(value) => Ok(value),
    }
}

fn build_depublish_commit(
    prepared: &PreparedWsbDiscard<'_>,
    commit_parent_id: aiw_probe::DiscardIntentStableId,
    commit_file_id: aiw_probe::DiscardIntentStableId,
) -> Result<WsbDepublishCommitV0Alpha1, WsbDiscardPreparationError> {
    let checkpoint = prepared.checkpoint();
    let workspace = &checkpoint.inventory.workspace;
    let parent = Path::new(&workspace.parent.final_path);
    let commit = WsbDepublishCommitV0Alpha1 {
        schema_version: DEPUBLISH_COMMIT_SCHEMA.to_owned(),
        policy_version: DEPUBLISH_COMMIT_POLICY.to_owned(),
        operation: DEPUBLISH_OPERATION.to_owned(),
        run_id: checkpoint.run_id.clone(),
        cleanup_id: checkpoint.cleanup_id.clone(),
        store_key: checkpoint
            .revocation
            .discard_intent_binding
            .store_key
            .clone(),
        workspace: workspace.clone(),
        workspace_identity_sha256: checkpoint.revocation.workspace_identity_sha256.clone(),
        revocation_sha256: checkpoint.revocation_sha256.clone(),
        discard_intent_sha256: checkpoint.revocation.discard_intent_sha256.clone(),
        discard_intent_binding: checkpoint.revocation.discard_intent_binding.clone(),
        checkpoint_sha256: canonical_hash(checkpoint)?,
        checkpoint_binding: prepared.checkpoint_binding().clone(),
        fixed_tree_contract_version: checkpoint.fixed_tree_contract_version.clone(),
        inventory_sha256: checkpoint.inventory_sha256.clone(),
        original_root: checkpoint.inventory.original_root.clone(),
        root_id: checkpoint.inventory.objects[0].id.clone(),
        tombstone_leaf: checkpoint.inventory.tombstone_leaf.clone(),
        tombstone_path: parent
            .join(&checkpoint.inventory.tombstone_leaf)
            .to_string_lossy()
            .into_owned(),
        commit_parent_id,
        commit_file_id,
    };
    // The platform binding is not available until after persist; validate the
    // complete cross-binding at that boundary.
    if commit.schema_version != DEPUBLISH_COMMIT_SCHEMA
        || commit.policy_version != DEPUBLISH_COMMIT_POLICY
        || commit.operation != DEPUBLISH_OPERATION
        || commit.commit_parent_id != checkpoint.checkpoint_file.parent_id
        || commit.commit_file_id == commit.commit_parent_id
    {
        return Err(WsbDiscardPreparationError::Contract(
            "depublish commit reservation does not match the checkpoint parent".to_owned(),
        ));
    }
    Ok(commit)
}

fn validate_depublish_commit(
    commit: &WsbDepublishCommitV0Alpha1,
    checkpoint: &WsbDiscardCheckpointV0Alpha1,
    binding: &DepublishCommitBindingEvidence,
) -> Result<(), WsbDiscardPreparationError> {
    let expected_tombstone = Path::new(&checkpoint.inventory.workspace.parent.final_path)
        .join(&checkpoint.inventory.tombstone_leaf);
    let valid = commit.schema_version == DEPUBLISH_COMMIT_SCHEMA
        && commit.policy_version == DEPUBLISH_COMMIT_POLICY
        && commit.operation == DEPUBLISH_OPERATION
        && commit.run_id == checkpoint.run_id
        && commit.cleanup_id == checkpoint.cleanup_id
        && commit.store_key == checkpoint.revocation.discard_intent_binding.store_key
        && commit.workspace == checkpoint.inventory.workspace
        && commit.workspace_identity_sha256 == checkpoint.revocation.workspace_identity_sha256
        && commit.revocation_sha256 == checkpoint.revocation_sha256
        && commit.discard_intent_sha256 == checkpoint.revocation.discard_intent_sha256
        && commit.discard_intent_binding == checkpoint.revocation.discard_intent_binding
        && commit.checkpoint_sha256 == canonical_hash(checkpoint)?
        && commit.checkpoint_binding.parent_id == checkpoint.checkpoint_file.parent_id
        && commit.checkpoint_binding.checkpoint_id == checkpoint.checkpoint_file.file_id
        && commit.fixed_tree_contract_version == WSB_FIXED_TREE_CONTRACT_VERSION
        && commit.inventory_sha256 == checkpoint.inventory_sha256
        && commit.original_root == checkpoint.inventory.original_root
        && commit.root_id == checkpoint.inventory.objects[0].id
        && commit.tombstone_leaf == checkpoint.inventory.tombstone_leaf
        && commit.tombstone_path == expected_tombstone.to_string_lossy()
        && commit.commit_parent_id == binding.parent_id
        && commit.commit_file_id == binding.commit_id
        && binding.run_id == commit.run_id
        && binding.store_key == commit.store_key
        && binding.owner_sid == checkpoint.inventory.workspace.owner_sid
        && binding.commit_sha256 == hash_bytes(&canonical_bytes(commit)?)
        && binding.commit_size == canonical_bytes(commit)?.len() as u64;
    if !valid {
        return Err(WsbDiscardPreparationError::Contract(
            "depublish commit differs from its checkpoint or protected file binding".to_owned(),
        ));
    }
    Ok(())
}

fn validate_depublish_envelope(
    commit: &WsbDepublishCommitV0Alpha1,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    binding: &DepublishCommitBindingEvidence,
) -> Result<(), WsbDiscardPreparationError> {
    let expected_tombstone = Path::new(&workspace.parent.final_path).join(&commit.tombstone_leaf);
    let valid = commit.schema_version == DEPUBLISH_COMMIT_SCHEMA
        && commit.policy_version == DEPUBLISH_COMMIT_POLICY
        && commit.operation == DEPUBLISH_OPERATION
        && commit.run_id == run_id
        && commit.store_key == binding.store_key
        && commit.workspace == *workspace
        && commit.workspace_identity_sha256 == canonical_hash(&commit.workspace)?
        && commit.discard_intent_binding.run_id == run_id
        && commit.discard_intent_binding.store_key == commit.store_key
        && commit.discard_intent_binding.owner_sid == workspace.owner_sid
        && commit.discard_intent_sha256 == commit.discard_intent_binding.intent_sha256
        && commit.original_root == workspace.root.final_path
        && commit.root_id.volume_serial_number == workspace.root.volume_serial_number
        && commit.root_id.file_id == workspace.root.file_id
        && commit.tombstone_leaf == format!("{TOMBSTONE_PREFIX}{}", commit.cleanup_id)
        && commit.tombstone_path == expected_tombstone.to_string_lossy()
        && commit.commit_parent_id == binding.parent_id
        && commit.commit_file_id == binding.commit_id
        && binding.run_id == run_id
        && binding.owner_sid == workspace.owner_sid
        && binding.commit_sha256 == hash_bytes(&canonical_bytes(commit)?)
        && binding.commit_size == canonical_bytes(commit)?.len() as u64;
    if !valid {
        return Err(WsbDiscardPreparationError::Contract(
            "depublish recovery envelope is not bound to the supplied workspace and run".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn prepare_windows_sandbox_discard<'a>(
    layout: &'a RunLayout,
    workspace_root: &Path,
    project: &Project,
    expected_guest_agent_sha256: &str,
    requested_by: &str,
    requested_at: &str,
) -> Result<PreparedWsbDiscard<'a>, WsbDiscardPreparationError> {
    require_request_text("requestedBy", requested_by)?;
    require_request_text("requestedAt", requested_at)?;

    // The owner-scoped outer mutex and the inner run lock are acquired before
    // any descendant preparation handle is reopened.
    let lease = layout.acquire_wsb_revocation_lease().map_err(|error| {
        WsbDiscardPreparationError::Orchestrator(format!("{error}: {}", error.detail))
    })?;
    let mut held = open_verified_windows_sandbox_preparation(
        workspace_root,
        project,
        expected_guest_agent_sha256,
        true,
        true,
    )?;
    let mut guard = lease.begin_bound(held.workspace()).map_err(|error| {
        WsbDiscardPreparationError::Orchestrator(format!("{error}: {}", error.detail))
    })?;
    require_guard_bindings(&guard, &held.artifacts, project)?;

    let intent = build_intent(&guard, &held.artifacts.receipt, requested_by, requested_at)?;
    let intent_bytes = canonical_bytes(&intent)?;
    let intent_sha256 = hash_bytes(&intent_bytes);

    let prefix = classify_prefix(
        guard.recoverable_revocation(),
        &intent.cleanup_id,
        &intent_sha256,
    )?;
    let (revocation, binding, held_stage) = if let DiscardPrefix::Retry(revocation) = prefix {
        let binding = revocation.discard_intent_binding.clone();
        (*revocation, binding, None)
    } else {
        let staged = stage_discard_intent(
            &intent_bytes,
            &intent_sha256,
            &held.artifacts.receipt.workspace,
            layout.run_id(),
        )?;
        let revocation = WsbRevocationRecord {
            schema_version: WSB_REVOCATION_SCHEMA_VERSION.to_owned(),
            run_id: layout.run_id().to_owned(),
            cleanup_id: intent.cleanup_id.clone(),
            discard_intent_sha256: intent_sha256.clone(),
            discard_intent_binding: staged.evidence().clone(),
            plan_sha256: guard
                .plan()
                .hash()
                .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?,
            import_receipt_sha256: canonical_hash(guard.import_receipt())?,
            workspace_identity_sha256: held.artifacts.receipt.workspace_identity_sha256.clone(),
            requested_by: requested_by.to_owned(),
            requested_at: requested_at.to_owned(),
        };
        let binding = staged.evidence().clone();
        (revocation, binding, Some(staged))
    };

    // A restart may expose a strictly validated durable revocation before its
    // journal boundary is complete. This call is idempotent for both that
    // prefix and the already-recorded prefix.
    guard
        .persist_staged_revocation_bound(held.workspace(), &revocation)
        .map_err(|error| {
            WsbDiscardPreparationError::Orchestrator(format!("{error}: {}", error.detail))
        })?;
    // Keep the exact staged file and parent handles alive until its binding is
    // durably recorded. Reopen is intentionally a separate strict step.
    drop(held_stage);

    // Internal revocation is already fail-closed. Revalidate every read-only
    // observation before the first possible external publication.
    held.revalidate_revoking()?;
    require_current_readiness_matches_receipt(&held.artifacts.receipt)?;
    require_guard_bindings(&guard, &held.artifacts, project)?;
    let publication = reopen_and_publish(
        &intent_bytes,
        &intent_sha256,
        &held.artifacts.receipt.workspace,
        layout.run_id(),
        &binding,
    )?;

    // Re-read every held descendant artifact and provider observation after
    // publication. Then release all descendant handles before the guard is
    // consumed into outer-only authority.
    held.revalidate_revoking()?;
    require_current_readiness_matches_receipt(&held.artifacts.receipt)?;
    require_guard_bindings(&guard, &held.artifacts, project)?;
    let preparation_receipt = held.artifacts.receipt.clone();
    drop(held);
    let authority = guard
        .into_outer_only(publication)
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
    require_current_readiness_matches_receipt(&preparation_receipt)?;
    authority
        .revalidate_external_intent()
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
    let snapshot = hold_fixed_wsb_tree_for_checkpoint(
        &intent.workspace,
        layout.run_id(),
        &intent.tombstone_leaf,
    )?;
    snapshot.revalidate()?;
    require_current_readiness_matches_receipt(&preparation_receipt)?;
    let inventory_receipt = build_inventory_receipt(
        &intent,
        authority.revocation(),
        &preparation_receipt.workspace_identity_sha256,
        snapshot.evidence().clone(),
    )?;
    let (checkpoint, checkpoint_binding, checkpoint_publication) =
        materialize_discard_checkpoint(&authority, &inventory_receipt, &snapshot)?;
    snapshot.revalidate()?;
    authority
        .revalidate_external_intent()
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
    checkpoint_publication.revalidate()?;
    drop(snapshot);
    Ok(PreparedWsbDiscard {
        authority,
        intent,
        inventory_receipt,
        checkpoint,
        checkpoint_binding,
        checkpoint_publication,
    })
}

fn materialize_discard_checkpoint(
    authority: &WsbOuterDiscardAuthority<'_>,
    inventory_receipt: &WsbFixedTreeInventoryReceipt,
    snapshot: &aiw_windows_platform::HeldFixedWsbCheckpointSnapshot,
) -> Result<
    (
        WsbDiscardCheckpointV0Alpha1,
        DiscardCheckpointBindingEvidence,
        HeldDiscardCheckpointPublication,
    ),
    WsbDiscardPreparationError,
> {
    snapshot.revalidate()?;
    authority
        .revalidate_external_intent()
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
    let store_key = &authority.revocation().discard_intent_binding.store_key;
    match reserve_discard_checkpoint(
        &inventory_receipt.inventory.workspace,
        &inventory_receipt.run_id,
        store_key,
    ) {
        Ok(reserved) => {
            let checkpoint = build_checkpoint(
                authority.revocation(),
                &inventory_receipt.inventory,
                reserved.parent_id().clone(),
                reserved.checkpoint_id().clone(),
            )?;
            let bytes = canonical_bytes(&checkpoint)?;
            let sha256 = hash_bytes(&bytes);
            let staged = reserved.persist(&bytes, &sha256)?;
            let binding = staged.evidence().clone();
            // The checkpoint contract requires a close/reopen boundary before
            // publication. Retaining the staged DELETE-capable handle would
            // make the strict reopen fail with a sharing violation.
            drop(staged);
            snapshot.revalidate()?;
            authority
                .revalidate_external_intent()
                .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
            let reopened = reopen_prepared_discard_checkpoint(
                &bytes,
                &sha256,
                &inventory_receipt.inventory.workspace,
                &inventory_receipt.run_id,
                &binding,
            )?;
            let publication = publish_checkpoint(reopened)?;
            publication.revalidate()?;
            let published_binding = publication.evidence().clone();
            Ok((checkpoint, published_binding, publication))
        }
        Err(DiscardCheckpointError::FinalConflict | DiscardCheckpointError::PendingConflict) => {
            let existing = reopen_existing_discard_checkpoint(
                &inventory_receipt.inventory.workspace,
                &inventory_receipt.run_id,
                store_key,
            )?;
            let checkpoint: WsbDiscardCheckpointV0Alpha1 =
                serde_json::from_slice(existing.checkpoint()).map_err(|error| {
                    WsbDiscardPreparationError::Contract(format!(
                        "persisted discard checkpoint is not the strict schema: {error}"
                    ))
                })?;
            if canonical_bytes(&checkpoint)? != existing.checkpoint()
                || checkpoint.revocation != *authority.revocation()
                || checkpoint.inventory != inventory_receipt.inventory
                || checkpoint.checkpoint_file.parent_id != *existing.binding().parent_id()
                || checkpoint.checkpoint_file.file_id != *existing.binding().checkpoint_id()
            {
                return Err(WsbDiscardPreparationError::Contract(
                    "persisted discard checkpoint differs from fresh held authority".to_owned(),
                ));
            }
            checkpoint
                .validate()
                .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
            let binding = existing.binding().clone();
            snapshot.revalidate()?;
            authority
                .revalidate_external_intent()
                .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
            let publication = publish_checkpoint(existing.into_reopened())?;
            publication.revalidate()?;
            Ok((checkpoint, binding, publication))
        }
        Err(error) => Err(error.into()),
    }
}

fn build_checkpoint(
    revocation: &WsbRevocationRecord,
    inventory: &WsbFixedTreeInventoryEvidence,
    parent_id: aiw_probe::DiscardIntentStableId,
    file_id: aiw_probe::DiscardIntentStableId,
) -> Result<WsbDiscardCheckpointV0Alpha1, WsbDiscardPreparationError> {
    let checkpoint = WsbDiscardCheckpointV0Alpha1 {
        schema_version: WSB_DISCARD_CHECKPOINT_SCHEMA_VERSION.to_owned(),
        policy_version: WSB_DISCARD_CHECKPOINT_POLICY_VERSION.to_owned(),
        run_id: revocation.run_id.clone(),
        cleanup_id: revocation.cleanup_id.clone(),
        fixed_tree_contract_version: WSB_FIXED_TREE_CONTRACT_VERSION.to_owned(),
        revocation: revocation.clone(),
        revocation_sha256: canonical_hash(revocation)?,
        inventory: inventory.clone(),
        inventory_sha256: canonical_hash(inventory)?,
        checkpoint_file: WsbDiscardCheckpointFileIdentity { parent_id, file_id },
    };
    checkpoint
        .validate()
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
    Ok(checkpoint)
}

fn publish_checkpoint(
    reopened: ReopenedDiscardCheckpoint,
) -> Result<HeldDiscardCheckpointPublication, WsbDiscardPreparationError> {
    match reopened {
        ReopenedDiscardCheckpoint::Publishable(value) => Ok(value.publish()?),
        ReopenedDiscardCheckpoint::Published(value) => Ok(value),
    }
}

fn build_inventory_receipt(
    intent: &WsbDiscardIntent,
    revocation: &WsbRevocationRecord,
    workspace_identity_sha256: &str,
    inventory: WsbFixedTreeInventoryEvidence,
) -> Result<WsbFixedTreeInventoryReceipt, WsbDiscardPreparationError> {
    inventory
        .validate()
        .map_err(|error| WsbDiscardPreparationError::Contract(error.to_owned()))?;
    if inventory.run_id != intent.run_id
        || inventory.workspace != intent.workspace
        || inventory.original_root != intent.workspace.root.final_path
        || inventory.tombstone_leaf != intent.tombstone_leaf
        || revocation.run_id != intent.run_id
        || revocation.cleanup_id != intent.cleanup_id
        || !tombstone_matches_cleanup(intent)
        || revocation.discard_intent_sha256 != hash_bytes(&canonical_bytes(intent)?)
        || workspace_identity_sha256 != intent.workspace_identity_sha256
    {
        return Err(WsbDiscardPreparationError::Contract(
            "fixed-tree inventory bindings differ from discard authority".to_owned(),
        ));
    }
    let inventory_sha256 = canonical_hash(&inventory)?;
    let receipt = WsbFixedTreeInventoryReceipt {
        schema_version: FIXED_TREE_INVENTORY_RECEIPT_SCHEMA.to_owned(),
        run_id: intent.run_id.clone(),
        cleanup_id: intent.cleanup_id.clone(),
        discard_intent_sha256: revocation.discard_intent_sha256.clone(),
        revocation_sha256: canonical_hash(revocation)?,
        workspace_identity_sha256: workspace_identity_sha256.to_owned(),
        inventory_sha256,
        inventory,
    };
    validate_inventory_receipt(&receipt, intent, revocation)?;
    Ok(receipt)
}

fn validate_inventory_receipt(
    receipt: &WsbFixedTreeInventoryReceipt,
    intent: &WsbDiscardIntent,
    revocation: &WsbRevocationRecord,
) -> Result<(), WsbDiscardPreparationError> {
    if receipt.schema_version != FIXED_TREE_INVENTORY_RECEIPT_SCHEMA
        || receipt.run_id != intent.run_id
        || receipt.cleanup_id != intent.cleanup_id
        || receipt.discard_intent_sha256 != revocation.discard_intent_sha256
        || receipt.revocation_sha256 != canonical_hash(revocation)?
        || receipt.workspace_identity_sha256 != intent.workspace_identity_sha256
        || receipt.inventory_sha256 != canonical_hash(&receipt.inventory)?
        || receipt.inventory.run_id != receipt.run_id
        || receipt.inventory.workspace != intent.workspace
        || receipt.inventory.tombstone_leaf != intent.tombstone_leaf
        || !tombstone_matches_cleanup(intent)
        || receipt.inventory.validate().is_err()
    {
        return Err(WsbDiscardPreparationError::Contract(
            "fixed-tree inventory receipt is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn reopen_and_publish(
    intent_bytes: &[u8],
    intent_sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    binding: &DiscardIntentBindingEvidence,
) -> Result<HeldDiscardIntentPublication, WsbDiscardPreparationError> {
    match reopen_prepared_discard_intent(intent_bytes, intent_sha256, workspace, run_id, binding)? {
        ReopenedDiscardIntent::Publishable(value) => Ok(value.publish()?),
        ReopenedDiscardIntent::Published(value) => Ok(value),
    }
}

enum DiscardPrefix {
    Fresh,
    Retry(Box<WsbRevocationRecord>),
}

fn classify_prefix(
    committed: Option<&WsbRevocationRecord>,
    cleanup_id: &str,
    intent_sha256: &str,
) -> Result<DiscardPrefix, WsbDiscardPreparationError> {
    let Some(committed) = committed else {
        return Ok(DiscardPrefix::Fresh);
    };
    if committed.cleanup_id != cleanup_id || committed.discard_intent_sha256 != intent_sha256 {
        return Err(WsbDiscardPreparationError::Contract(
            "the exact retry request differs from committed revocation".to_owned(),
        ));
    }
    Ok(DiscardPrefix::Retry(Box::new(committed.clone())))
}

fn require_guard_bindings(
    guard: &aiw_orchestrator::WsbRevocationGuard<'_>,
    artifacts: &crate::PreparedWsbArtifacts,
    project: &Project,
) -> Result<(), WsbDiscardPreparationError> {
    let import = guard.import_receipt();
    let receipt = &artifacts.receipt;
    if guard.plan() != &artifacts.run_plan {
        return Err(WsbDiscardPreparationError::Contract(
            "authoritative run plan drifted from the held preparation".to_owned(),
        ));
    }
    let project_sha256 = project_revision_hash(project)
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
    let preparation_sha256 = canonical_hash(receipt)?;
    require_exact_bindings(&[
        ("run", guard.plan().run_id.as_str(), receipt.run_id.as_str()),
        (
            "import run",
            import.run_id.as_str(),
            receipt.run_id.as_str(),
        ),
        (
            "project",
            project_sha256.as_str(),
            receipt.project_revision_sha256.as_str(),
        ),
        (
            "run plan",
            import.run_plan_sha256.as_str(),
            receipt.run_plan_sha256.as_str(),
        ),
        (
            "WSB plan",
            import.windows_sandbox_plan_sha256.as_str(),
            receipt.wsb_plan_sha256.as_str(),
        ),
        (
            "guest agent",
            import.guest_agent_sha256.as_str(),
            receipt.guest_agent.sha256.as_str(),
        ),
        (
            "provider",
            import.provider_sha256.as_str(),
            receipt.provider.sha256.as_str(),
        ),
        (
            "workspace",
            import.workspace_identity_sha256.as_str(),
            receipt.workspace_identity_sha256.as_str(),
        ),
        (
            "preparation",
            import.preparation_receipt_sha256.as_str(),
            preparation_sha256.as_str(),
        ),
    ])
}

fn require_exact_bindings(
    bindings: &[(&str, &str, &str)],
) -> Result<(), WsbDiscardPreparationError> {
    if let Some((name, _, _)) = bindings
        .iter()
        .find(|(_, observed, expected)| observed != expected)
    {
        return Err(WsbDiscardPreparationError::Contract(format!(
            "{name} binding drifted before discard publication"
        )));
    }
    Ok(())
}

fn build_intent(
    guard: &aiw_orchestrator::WsbRevocationGuard<'_>,
    receipt: &crate::WsbPreparationReceipt,
    requested_by: &str,
    requested_at: &str,
) -> Result<WsbDiscardIntent, WsbDiscardPreparationError> {
    let control_path = guard
        .control_path()
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?
        .to_string_lossy()
        .into_owned();
    let coordination_binding_sha256 = Path::new(&control_path)
        .file_name()
        .and_then(|value| value.to_str())
        .and_then(|value| value.strip_prefix(CONTROL_PREFIX))
        .filter(|value| is_sha256(value))
        .ok_or_else(|| {
            WsbDiscardPreparationError::Contract(
                "discard control path does not contain the full coordination binding".to_owned(),
            )
        })?
        .to_owned();
    let plan_sha256 = guard
        .plan()
        .hash()
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
    let import_receipt_sha256 = canonical_hash(guard.import_receipt())?;
    let preparation_receipt_sha256 = canonical_hash(receipt)?;
    let provider_package_sha256 = canonical_hash(&receipt.provider_package)?;
    let provider_file_identity_sha256 = canonical_hash(&receipt.provider_file_identity)?;
    let provider_protocol_sha256 = canonical_hash(&receipt.provider_protocol)?;
    let material = CleanupIdMaterial {
        schema_version: DISCARD_INTENT_SCHEMA,
        run_id: guard.plan().run_id.as_str(),
        phase: DISCARD_PHASE,
        fixed_tree_contract: WSB_FIXED_TREE_CONTRACT_VERSION,
        requested_by,
        requested_at,
        control_path: &control_path,
        coordination_binding_sha256: &coordination_binding_sha256,
        plan_sha256: &plan_sha256,
        import_receipt_sha256: &import_receipt_sha256,
        preparation_receipt_sha256: &preparation_receipt_sha256,
        project_revision_sha256: &receipt.project_revision_sha256,
        guest_agent_sha256: &receipt.guest_agent.sha256,
        provider_sha256: &receipt.provider.sha256,
        provider_package_sha256: &provider_package_sha256,
        provider_catalog_sha256: &receipt.provider_catalog.catalog_sha256,
        provider_file_identity_sha256: &provider_file_identity_sha256,
        provider_protocol_sha256: &provider_protocol_sha256,
        windows_sandbox_plan_sha256: &receipt.wsb_plan_sha256,
        workspace_identity_sha256: &receipt.workspace_identity_sha256,
    };
    let cleanup_id = canonical_hash(&material)?;
    Ok(WsbDiscardIntent {
        schema_version: DISCARD_INTENT_SCHEMA.to_owned(),
        run_id: receipt.run_id.clone(),
        cleanup_id: cleanup_id.clone(),
        phase: DISCARD_PHASE.to_owned(),
        fixed_tree_contract: WSB_FIXED_TREE_CONTRACT_VERSION.to_owned(),
        requested_by: requested_by.to_owned(),
        requested_at: requested_at.to_owned(),
        tombstone_leaf: format!("{TOMBSTONE_PREFIX}{cleanup_id}"),
        control_path,
        coordination_binding_sha256,
        plan_sha256,
        import_receipt_sha256,
        preparation_receipt_sha256,
        project_revision_sha256: receipt.project_revision_sha256.clone(),
        guest_agent_sha256: receipt.guest_agent.sha256.clone(),
        provider_sha256: receipt.provider.sha256.clone(),
        provider_package_sha256,
        provider_catalog_sha256: receipt.provider_catalog.catalog_sha256.clone(),
        provider_file_identity_sha256,
        provider_protocol_sha256,
        windows_sandbox_plan_sha256: receipt.wsb_plan_sha256.clone(),
        workspace: receipt.workspace.clone(),
        workspace_identity_sha256: receipt.workspace_identity_sha256.clone(),
    })
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, WsbDiscardPreparationError> {
    let value = serde_json::to_value(value)
        .map_err(|error| WsbDiscardPreparationError::Contract(error.to_string()))?;
    canonical_json_bytes(&value)
        .map_err(|error| WsbDiscardPreparationError::Contract(error.to_string()))
}

fn canonical_hash(value: &impl Serialize) -> Result<String, WsbDiscardPreparationError> {
    Ok(hash_bytes(&canonical_bytes(value)?))
}

fn hash_bytes(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn same_windows_path_text(left: &str, right: &str) -> bool {
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

fn tombstone_matches_cleanup(intent: &WsbDiscardIntent) -> bool {
    intent.tombstone_leaf == format!("{TOMBSTONE_PREFIX}{}", intent.cleanup_id)
}

fn require_request_text(field: &str, value: &str) -> Result<(), WsbDiscardPreparationError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(WsbDiscardPreparationError::Contract(format!(
            "{field} is empty or outside its fixed text bound"
        )));
    }
    Ok(())
}

fn require_canonical_utc_timestamp(
    field: &str,
    value: &str,
) -> Result<(), WsbDiscardPreparationError> {
    let bytes = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .filter(|slice| slice.iter().all(u8::is_ascii_digit))
            .and_then(|slice| std::str::from_utf8(slice).ok())
            .and_then(|slice| slice.parse::<u32>().ok())
    };
    let year = digits(0..4);
    let month = digits(5..7);
    let day = digits(8..10);
    let hour = digits(11..13);
    let minute = digits(14..16);
    let second = digits(17..19);
    let shape = bytes.len() == 20
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes.get(19) == Some(&b'Z');
    let valid_date = match (year, month, day) {
        (Some(year @ 2000..=9999), Some(month @ 1..=12), Some(day)) => {
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            let max_day = match month {
                2 if leap => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            (1..=max_day).contains(&day)
        }
        _ => false,
    };
    if !shape
        || !valid_date
        || !matches!(hour, Some(0..=23))
        || !matches!(minute, Some(0..=59))
        || !matches!(second, Some(0..=59))
    {
        return Err(WsbDiscardPreparationError::Contract(format!(
            "{field} must be canonical UTC YYYY-MM-DDTHH:MM:SSZ"
        )));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiw_probe::{
        DiscardIntentEaBinding, DiscardIntentStableId, WINDOWS_SYSTEM_SID,
        WINDOWS_WORKSPACE_SCHEMA_VERSION, WINDOWS_WORKSPACE_SECURITY_POLICY, WindowsFileIdentity,
        workspace_policy_hash,
    };

    #[cfg(windows)]
    fn native_project() -> Project {
        serde_yaml::from_str(include_str!("../../../examples/minimal.aiw.yaml")).unwrap()
    }

    #[cfg(windows)]
    fn native_unique_parent(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "aiw-runner-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path.canonicalize().unwrap()
    }

    fn test_workspace() -> WorkspaceBindingEvidence {
        let owner = "S-1-5-21-1".to_owned();
        let identity = |path: &str, marker: u8| WindowsFileIdentity {
            final_path: path.to_owned(),
            volume_serial_number: "1".repeat(16),
            file_id: format!("{marker:032x}"),
        };
        WorkspaceBindingEvidence {
            schema_version: WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
            policy: WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
            security_policy_sha256: workspace_policy_hash(&owner),
            owner_sid: owner.clone(),
            dacl_protected: true,
            allowed_sids: vec![WINDOWS_SYSTEM_SID.to_owned(), owner],
            parent: identity("C:\\AIW", 1),
            root: identity("C:\\AIW\\run-one", 2),
            tools: identity("C:\\AIW\\run-one\\tools", 3),
            output: identity("C:\\AIW\\run-one\\output", 4),
        }
    }

    fn binding() -> DiscardIntentBindingEvidence {
        DiscardIntentBindingEvidence {
            schema_version: aiw_probe::DISCARD_INTENT_BINDING_SCHEMA_VERSION.to_owned(),
            policy_version: aiw_probe::DISCARD_INTENT_BINDING_POLICY_VERSION.to_owned(),
            run_id: "run-one".to_owned(),
            owner_sid: "S-1-5-21-1".to_owned(),
            store_key: "a".repeat(64),
            final_path: format!(r"C:\AIW\{}{}", CONTROL_PREFIX, "a".repeat(64)),
            staging_leaf: format!(".aiw-discard-stage-v1-{}-1234567890abcdef", "a".repeat(64)),
            parent_id: DiscardIntentStableId {
                volume_serial_number: "1".repeat(16),
                file_id: "2".repeat(32),
            },
            intent_id: DiscardIntentStableId {
                volume_serial_number: "1".repeat(16),
                file_id: "3".repeat(32),
            },
            intent_size: 100,
            intent_sha256: "b".repeat(64),
            intent_ea: DiscardIntentEaBinding {
                queried_bytes: 0,
                entries: vec![],
                canonical_sha256: "c".repeat(64),
            },
        }
    }

    fn revocation() -> WsbRevocationRecord {
        WsbRevocationRecord {
            schema_version: WSB_REVOCATION_SCHEMA_VERSION.to_owned(),
            run_id: "run-one".to_owned(),
            cleanup_id: "d".repeat(64),
            discard_intent_sha256: "b".repeat(64),
            discard_intent_binding: binding(),
            plan_sha256: "e".repeat(64),
            import_receipt_sha256: "f".repeat(64),
            workspace_identity_sha256: "1".repeat(64),
            requested_by: "admin".to_owned(),
            requested_at: "now".to_owned(),
        }
    }

    #[test]
    fn cleanup_material_is_canonical_and_has_no_hash_cycle_fields() {
        let source = include_str!("discard.rs");
        let material = source
            .split("struct CleanupIdMaterial")
            .nth(1)
            .unwrap()
            .split("pub(crate) struct PreparedWsbDiscard")
            .next()
            .unwrap();
        assert!(!material.contains("cleanup_id"));
        assert!(!material.contains("tombstone_leaf"));

        let left = serde_json::json!({"b": 2, "a": 1});
        let right = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(
            canonical_hash(&left).unwrap(),
            canonical_hash(&right).unwrap()
        );
    }

    #[test]
    fn request_and_hash_contracts_fail_closed() {
        assert!(require_request_text("actor", "admin").is_ok());
        assert!(require_request_text("actor", "").is_err());
        assert!(require_request_text("actor", "bad\nactor").is_err());
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"A".repeat(64)));
        assert!(!is_sha256(&"a".repeat(63)));
        assert!(require_canonical_utc_timestamp("completedAt", "2026-08-31T09:30:00Z").is_ok());
        for invalid in [
            "2026-02-29T09:30:00Z",
            "2024-02-30T09:30:00Z",
            "2024-02-29T24:00:00Z",
            "2024-02-29T09:60:00Z",
            "2024-02-29T09:30:00+00:00",
            "2024-02-29 09:30:00Z",
        ] {
            assert!(require_canonical_utc_timestamp("completedAt", invalid).is_err());
        }
    }

    #[test]
    fn fresh_and_retry_prefixes_are_exact_and_conflicts_fail_read_only() {
        assert!(matches!(
            classify_prefix(None, &"d".repeat(64), &"b".repeat(64)).unwrap(),
            DiscardPrefix::Fresh
        ));
        let committed = revocation();
        let DiscardPrefix::Retry(observed) = classify_prefix(
            Some(&committed),
            &committed.cleanup_id,
            &committed.discard_intent_sha256,
        )
        .unwrap() else {
            panic!("committed prefix must retry");
        };
        assert_eq!(*observed, committed);
        assert!(classify_prefix(Some(&committed), &"0".repeat(64), &"b".repeat(64)).is_err());
        assert!(classify_prefix(Some(&committed), &"d".repeat(64), &"0".repeat(64)).is_err());
    }

    #[test]
    fn every_imported_identity_pair_is_a_drift_gate() {
        let names = [
            "run",
            "import run",
            "project",
            "run plan",
            "WSB plan",
            "guest agent",
            "provider",
            "workspace",
            "preparation",
        ];
        for changed in 0..names.len() {
            let mut bindings = names
                .iter()
                .map(|name| (*name, "same", "same"))
                .collect::<Vec<_>>();
            bindings[changed].1 = "drifted";
            let error = require_exact_bindings(&bindings).unwrap_err().to_string();
            assert!(error.contains(names[changed]));
        }
        assert!(require_exact_bindings(&[("provider", "same", "same")]).is_ok());
    }

    #[test]
    fn production_surface_has_no_workspace_or_provider_mutation_verbs() {
        let production = include_str!("discard.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "remove_dir",
            "remove_file",
            "fs::rename",
            "SetFileInformationByHandle",
            "exact_dispose",
            "dispose_all",
            "acquire_windows_sandbox",
            "provider.start",
            "provider.stop",
            "std::process::Command",
            "RunResult",
        ] {
            assert!(
                !production.contains(forbidden),
                "found forbidden {forbidden}"
            );
        }
        assert!(production.contains("acquire_wsb_revocation_lease"));
        assert!(production.contains("lease.begin_bound(held.workspace())"));
        assert!(production.contains("into_outer_only"));
        assert!(production.contains("hold_fixed_wsb_tree_for_checkpoint"));
        assert!(production.contains("reserve_discard_checkpoint"));
        assert!(production.contains("reopen_existing_discard_checkpoint"));
        assert!(production.contains("reopen_prepared_discard_checkpoint"));
        assert!(production.contains("reserve_depublish_commit"));
        assert!(production.contains("reopen_existing_depublish_commit"));
        assert!(production.contains("depublish_and_release"));
        assert!(production.contains("reserve_disposition_progress"));
        assert!(production.contains("reopen_existing_disposition_progress"));
        assert!(production.contains("tree.dispose_next()"));
        assert!(production.contains("reserve_cleanup_receipt"));
        assert!(production.contains("reopen_existing_cleanup_receipt"));
        assert!(
            production.find("into_outer_only(publication)").unwrap()
                < production
                    .rfind("hold_fixed_wsb_tree_for_checkpoint")
                    .unwrap(),
            "checkpoint snapshot must occur only after outer-only handoff"
        );
        assert!(
            production
                .find("hold_fixed_wsb_tree_for_checkpoint")
                .unwrap()
                < production.find("reserve_discard_checkpoint").unwrap(),
            "write/delete-denying tree handles must precede checkpoint creation"
        );
        assert!(!production.contains("events.jsonl"));
        assert!(!production.contains("journal-heads"));
        assert!(
            production.find("persist_staged_revocation").unwrap()
                < production.find("drop(held_stage)").unwrap(),
            "the exact stage handles must survive until internal persistence"
        );
        assert!(
            production.find("materialize_depublish_commit").unwrap()
                < production.find("tree.depublish_and_release").unwrap(),
            "the immutable external commit must be published before root rename"
        );
        assert!(
            production.find("materialize_disposition_progress").unwrap()
                < production.find("tree.dispose_next()").unwrap(),
            "an immutable progress record must be published before exact disposition"
        );
        let recovery = production
            .split("fn recover_committed_windows_sandbox_depublish")
            .nth(1)
            .unwrap()
            .split("fn materialize_depublish_commit")
            .next()
            .unwrap();
        assert!(!recovery.contains("RunLayout::new"));
        assert!(recovery.contains("RunCoordinationMode::Recovery"));
        assert!(recovery.contains("ReopenedDepublishCommit::Publishable"));
        assert!(recovery.contains("value.publish()"));
        assert!(recovery.contains("WsbRootNamespaceState::Tombstone"));
        let disposition_recovery = production
            .split("fn recover_checkpoint_bound_wsb_disposition")
            .nth(1)
            .unwrap()
            .split("enum DepublishRecoveryMode")
            .next()
            .unwrap();
        assert!(disposition_recovery.contains("DepublishRecoveryMode::DispositionOnly"));
        assert!(disposition_recovery.contains("dispose_checkpoint_bound_wsb_tombstone"));
        assert!(!disposition_recovery.contains("depublish_and_release"));
        let terminal_recovery = production
            .split("fn recover_terminal_wsb_cleanup_receipt")
            .nth(1)
            .unwrap()
            .split("enum DepublishRecoveryMode")
            .next()
            .unwrap();
        assert!(terminal_recovery.contains("reopen_completed_checkpoint_bound_wsb_disposition"));
        assert!(!terminal_recovery.contains("dispose_checkpoint_bound_wsb_tombstone"));
        assert!(!terminal_recovery.contains("depublish_and_release"));
        let terminal_publication = production
            .split("fn publish_terminal_wsb_cleanup_receipt")
            .nth(1)
            .unwrap()
            .split("fn build_terminal_cleanup_receipt")
            .next()
            .unwrap();
        assert!(terminal_publication.contains("completed.revalidate()?"));
        assert!(terminal_publication.contains("reserve_cleanup_receipt"));
        assert!(terminal_publication.contains("value.publish()?"));
    }

    #[test]
    fn fixed_tree_and_phase_contracts_are_explicit() {
        assert_eq!(DISCARD_PHASE, "revocationPending");
        assert!(WSB_FIXED_TREE_CONTRACT_VERSION.ends_with("19-objects"));
        assert_eq!(CONTROL_PREFIX, ".aiw-discard-v1-");
        assert_eq!(TOMBSTONE_PREFIX, ".aiw-discarded-v1-");
        assert_eq!(
            TERMINAL_CLEANUP_SCHEMA,
            "aiw.dev/wsb-terminal-cleanup-receipt/v0alpha1"
        );
        assert_eq!(TERMINAL_CLEANUP_OPERATION, "recordTerminalCleanup");
    }

    #[test]
    fn disposition_recovery_accepts_only_the_exact_crash_window() {
        for final_count in 0..=19 {
            for physical_count in 0..=19 {
                assert_eq!(
                    disposition_prefixes_align(final_count, false, physical_count),
                    physical_count == final_count
                        || (final_count > 0 && physical_count + 1 == final_count)
                );
                assert_eq!(
                    disposition_prefixes_align(final_count, true, physical_count),
                    physical_count == final_count
                );
            }
        }
    }

    #[test]
    fn tombstone_is_bound_to_the_exact_cleanup_identity() {
        let mut intent = WsbDiscardIntent {
            schema_version: DISCARD_INTENT_SCHEMA.to_owned(),
            run_id: "run-one".to_owned(),
            cleanup_id: "a".repeat(64),
            phase: DISCARD_PHASE.to_owned(),
            fixed_tree_contract: WSB_FIXED_TREE_CONTRACT_VERSION.to_owned(),
            requested_by: "admin".to_owned(),
            requested_at: "now".to_owned(),
            tombstone_leaf: format!("{TOMBSTONE_PREFIX}{}", "a".repeat(64)),
            control_path: "control".to_owned(),
            coordination_binding_sha256: "b".repeat(64),
            plan_sha256: "c".repeat(64),
            import_receipt_sha256: "d".repeat(64),
            preparation_receipt_sha256: "e".repeat(64),
            project_revision_sha256: "f".repeat(64),
            guest_agent_sha256: "1".repeat(64),
            provider_sha256: "2".repeat(64),
            provider_package_sha256: "3".repeat(64),
            provider_catalog_sha256: "4".repeat(64),
            provider_file_identity_sha256: "5".repeat(64),
            provider_protocol_sha256: "6".repeat(64),
            windows_sandbox_plan_sha256: "7".repeat(64),
            workspace: test_workspace(),
            workspace_identity_sha256: "8".repeat(64),
        };
        assert!(tombstone_matches_cleanup(&intent));
        intent.tombstone_leaf = format!("{TOMBSTONE_PREFIX}{}", "9".repeat(64));
        assert!(!tombstone_matches_cleanup(&intent));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "native protected WSB workspace terminal-receipt proof; run explicitly on a supported host"]
    fn native_terminal_cleanup_receipt_fresh_recovery_and_replacement() {
        use crate::preparation::{
            import_windows_sandbox_preparation, prepare_windows_sandbox_bundle,
        };

        let base = native_unique_parent("terminal-receipt");
        let outer = aiw_windows_platform::HeldRunWorkspace::create(&base, "authority").unwrap();
        let parent = outer.root_path().to_owned();
        drop(outer);
        let run_id = format!("terminal-{}", std::process::id());
        let workspace_root = parent.join(&run_id);
        let project = native_project();
        let agent = std::env::current_exe().unwrap();
        let agent_sha256 = hash_bytes(&std::fs::read(&agent).unwrap());
        prepare_windows_sandbox_bundle(
            &run_id,
            &project,
            &agent,
            &agent_sha256,
            &parent,
            &run_id,
            "2026-08-31T09:00:00Z",
        )
        .unwrap();
        import_windows_sandbox_preparation(
            &workspace_root,
            &project,
            &agent_sha256,
            "2026-08-31T09:01:00Z",
        )
        .unwrap();
        let layout = RunLayout::new(&workspace_root, &run_id).unwrap();
        let prepared = prepare_windows_sandbox_discard(
            &layout,
            &workspace_root,
            &project,
            &agent_sha256,
            "native-test",
            "2026-08-31T09:02:00Z",
        )
        .unwrap();
        let depublished = depublish_prepared_windows_sandbox(prepared).unwrap();
        let completed = dispose_checkpoint_bound_wsb_tombstone(depublished).unwrap();
        assert_eq!(completed.completed_count(), 19);
        std::fs::create_dir(&workspace_root).unwrap();
        let replacement = workspace_root.join("replacement.txt");
        std::fs::write(&replacement, b"unrelated replacement").unwrap();
        let terminal =
            publish_terminal_wsb_cleanup_receipt(completed, "2026-08-31T09:03:00Z").unwrap();
        terminal.revalidate().unwrap();
        let receipt_sha256 = terminal.receipt_sha256().to_owned();
        drop(terminal);
        drop(layout);

        let recovered =
            recover_terminal_wsb_cleanup_receipt(&workspace_root, &run_id, "2026-08-31T09:03:00Z")
                .unwrap();
        assert_eq!(recovered.receipt_sha256(), receipt_sha256);
        recovered.revalidate().unwrap();
        assert_eq!(
            std::fs::read(&replacement).unwrap(),
            b"unrelated replacement"
        );
        drop(recovered);
        assert!(
            recover_terminal_wsb_cleanup_receipt(&workspace_root, &run_id, "2026-08-31T09:03:01Z",)
                .is_err()
        );

        std::fs::remove_dir_all(&base).unwrap();
    }
}
