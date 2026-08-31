//! Private, checkpoint-bound Windows Sandbox depublish transaction.
//!
//! This workflow may publish only the protected external intent, the hash-bound
//! internal revocation record, and the protected external fixed-tree
//! checkpoint and depublish commit. Its sole namespace mutation is the exact
//! checkpoint-bound root rename. It has no provider operation, child
//! disposition, deletion, or cleanup-complete claim.

use std::path::Path;

use aiw_evidence::canonical_json_bytes;
use aiw_orchestrator::{
    RunLayout, WSB_DISCARD_CHECKPOINT_POLICY_VERSION, WSB_DISCARD_CHECKPOINT_SCHEMA_VERSION,
    WSB_REVOCATION_SCHEMA_VERSION, WsbDiscardCheckpointFileIdentity, WsbDiscardCheckpointV0Alpha1,
    WsbOuterDiscardAuthority, WsbRevocationRecord, project_revision_hash,
};
use aiw_probe::{
    WSB_FIXED_TREE_CONTRACT_VERSION, WorkspaceBindingEvidence, WsbFixedTreeInventoryEvidence,
};
use aiw_schema::Project;
use aiw_windows_platform::{
    DepublishCommitBindingEvidence, DepublishCommitError, DiscardCheckpointBindingEvidence,
    DiscardCheckpointError, DiscardIntentBindingEvidence, DiscardIntentError, ExactDisposeError,
    HeldDepublishCommitPublication, HeldDiscardCheckpointPublication, HeldDiscardIntentPublication,
    ReopenedDepublishCommit, ReopenedDiscardCheckpoint, ReopenedDiscardIntent, RunCoordinationKey,
    RunCoordinationLease, RunCoordinationMode, WsbRootDepublishObservation, WsbRootNamespaceState,
    classify_checkpoint_bound_wsb_root, hold_fixed_wsb_tree_for_checkpoint,
    locate_depublish_commit_from_persisted_root, reopen_checkpoint_bound_wsb_root,
    reopen_existing_depublish_commit, reopen_existing_discard_checkpoint,
    reopen_prepared_depublish_commit, reopen_prepared_discard_checkpoint,
    reopen_prepared_discard_intent, reopen_published_discard_intent, reserve_depublish_commit,
    reserve_discard_checkpoint, stage_discard_intent, try_acquire_run_coordination,
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
struct WsbDepublishCommitV0Alpha1 {
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
    commit: HeldDepublishCommitPublication,
    observation: WsbRootDepublishObservation,
}

impl RecoveredDepublishedWsbTombstone {
    pub(crate) fn observation(&self) -> &WsbRootDepublishObservation {
        &self.observation
    }

    pub(crate) fn revalidate(&self) -> Result<(), WsbDiscardPreparationError> {
        self._intent.revalidate()?;
        self._checkpoint.revalidate()?;
        self.commit.revalidate()?;
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
    let located = locate_depublish_commit_from_persisted_root(original_root, run_id)?;
    let commit: WsbDepublishCommitV0Alpha1 =
        serde_json::from_slice(located.commit()).map_err(|error| {
            WsbDiscardPreparationError::Contract(format!(
                "persisted depublish commit is not the strict schema: {error}"
            ))
        })?;
    if canonical_bytes(&commit)? != located.commit()
        || Path::new(&commit.original_root) != original_root
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
                WsbRootNamespaceState::Original => {
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
                _ => {
                    return Err(WsbDiscardPreparationError::Contract(format!(
                        "committed depublish namespace is ambiguous or foreign: {state:?}"
                    )));
                }
            };
            (publication, observation)
        }
    };
    if classify_checkpoint_bound_wsb_root(&checkpoint.inventory)?
        != WsbRootNamespaceState::Tombstone
    {
        return Err(WsbDiscardPreparationError::Contract(
            "recovered depublish did not reach the exact tombstone".to_owned(),
        ));
    }
    Ok(RecoveredDepublishedWsbTombstone {
        _coordination: coordination,
        _intent: intent_publication,
        _checkpoint: checkpoint_publication,
        commit: commit_publication,
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
    let mut guard = layout
        .begin_wsb_revocation()
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
    let mut held = open_verified_windows_sandbox_preparation(
        workspace_root,
        project,
        expected_guest_agent_sha256,
        true,
        true,
    )?;
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
        .persist_staged_revocation(&revocation)
        .map_err(|error| WsbDiscardPreparationError::Orchestrator(error.to_string()))?;
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
            Ok((checkpoint, binding, publication))
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
            "dispose_next",
            "dispose_all",
            "acquire_windows_sandbox",
            "provider.start",
            "provider.stop",
            "std::process::Command",
        ] {
            assert!(
                !production.contains(forbidden),
                "found forbidden {forbidden}"
            );
        }
        assert!(production.contains("begin_wsb_revocation"));
        assert!(production.contains("into_outer_only"));
        assert!(production.contains("hold_fixed_wsb_tree_for_checkpoint"));
        assert!(production.contains("reserve_discard_checkpoint"));
        assert!(production.contains("reopen_existing_discard_checkpoint"));
        assert!(production.contains("reopen_prepared_discard_checkpoint"));
        assert!(production.contains("reserve_depublish_commit"));
        assert!(production.contains("reopen_existing_depublish_commit"));
        assert!(production.contains("depublish_and_release"));
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
    }

    #[test]
    fn fixed_tree_and_phase_contracts_are_explicit() {
        assert_eq!(DISCARD_PHASE, "revocationPending");
        assert!(WSB_FIXED_TREE_CONTRACT_VERSION.ends_with("19-objects"));
        assert_eq!(CONTROL_PREFIX, ".aiw-discard-v1-");
        assert_eq!(TOMBSTONE_PREFIX, ".aiw-discarded-v1-");
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
}
