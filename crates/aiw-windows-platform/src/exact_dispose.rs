//! Private native benchmark for exact cleanup of the fixed imported WSB tree.
//!
//! `observe_fixed_wsb_tree` is read-only evidence collection, not mutation
//! authority. This module deliberately does not publish external discard
//! intent, revoke a run, publish disposition authority, or expose a CLI. It can
//! reopen only an explicitly supplied child-first prefix and dispose its exact
//! next checkpoint-bound object. Authority and durable recovery remain with the
//! runner; callers must not infer permission to delete from inventory alone.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aiw_probe::{
    DiscardIntentEaEntry, DiscardIntentStableId, WSB_FIXED_OBJECT_DELETE_ORDER,
    WSB_FIXED_TREE_CONTRACT_VERSION, WSB_FIXED_TREE_INVENTORY_SCHEMA_VERSION,
    WorkspaceBindingEvidence, WsbFixedObjectEvidence, WsbFixedObjectKind, WsbFixedTreeAclPolicy,
    WsbFixedTreeEaBinding, WsbFixedTreeInventoryEvidence, WsbFixedTreeStreamPolicy,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::Wdk::Storage::FileSystem::{
    FILE_FULL_EA_INFORMATION, FileRenameInformation, NtQueryEaFile, NtSetInformationFile,
    RtlNtStatusToDosErrorNoTeb,
};
use windows::Win32::Foundation::{
    ERROR_HANDLE_EOF, ERROR_NO_MORE_FILES, STATUS_NO_EAS_ON_FILE, WIN32_ERROR,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DEVICE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_INTEGRITY_STREAM,
    FILE_ATTRIBUTE_NO_SCRUB_DATA, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_PINNED,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_SYSTEM,
    FILE_ATTRIBUTE_TEMPORARY, FILE_ATTRIBUTE_UNPINNED, FILE_ATTRIBUTE_VIRTUAL,
    FILE_CASE_SENSITIVE_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO, FILE_ID_EXTD_DIR_INFO, FILE_ID_INFO,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_STREAM_INFO,
    FILE_TRAVERSE, FileCaseSensitiveInfo, FileDispositionInfo, FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo, FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo,
    FileIdInfo, FileStandardInfo, FileStreamInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, READ_CONTROL, SYNCHRONIZE, SetFileInformationByHandle,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;

use crate::workspace::{OwnedSid, final_path, raw_handle, same_path, verify_owner_system_acl};

const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;
const EA_BUFFER_BYTES: usize = 64 * 1024;
pub(crate) const ALLOWED_KERNEL_EAS: [&str; 2] = [
    "$KERNEL.PURGE.SMARTLOCKER.VALID",
    "$KERNEL.SMARTLOCKER.ORIGINCLAIM",
];
const ALLOWED_KERNEL_EAS_WITH_FILE_HASH: [&str; 3] = [
    "$KERNEL.PURGE.SEC.FILEHASH",
    "$KERNEL.PURGE.SMARTLOCKER.VALID",
    "$KERNEL.SMARTLOCKER.ORIGINCLAIM",
];
// The workspace directories have tiny exact allowlists, but the held parent is
// shared with unrelated applications and may legitimately contain more names.
const MAX_DIRECTORY_ENTRIES: usize = 4096;
const MAX_STREAM_ENTRIES: usize = 64;
const MAX_EA_ENTRIES: usize = 16;
const MAX_SMALL_ARTIFACT: u64 = 1024 * 1024;
const MAX_JOURNAL: u64 = 64 * 1024 * 1024;
const MAX_GUEST_AGENT: u64 = 128 * 1024 * 1024;
const EA_STABILIZATION_ATTEMPTS: usize = 40;
const EA_NONEMPTY_STABLE_OBSERVATIONS: usize = 20;
pub(crate) const FORBIDDEN_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY.0
    | FILE_ATTRIBUTE_REPARSE_POINT.0
    | FILE_ATTRIBUTE_COMPRESSED.0
    | FILE_ATTRIBUTE_DEVICE.0
    | FILE_ATTRIBUTE_ENCRYPTED.0
    | FILE_ATTRIBUTE_INTEGRITY_STREAM.0
    | FILE_ATTRIBUTE_NO_SCRUB_DATA.0
    | FILE_ATTRIBUTE_OFFLINE.0
    | FILE_ATTRIBUTE_PINNED.0
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS.0
    | FILE_ATTRIBUTE_RECALL_ON_OPEN.0
    | FILE_ATTRIBUTE_SPARSE_FILE.0
    | FILE_ATTRIBUTE_SYSTEM.0
    | FILE_ATTRIBUTE_TEMPORARY.0
    | FILE_ATTRIBUTE_UNPINNED.0
    | FILE_ATTRIBUTE_VIRTUAL.0;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum FixedWsbObject {
    WorkspaceRoot,
    ToolsDirectory,
    OutputDirectory,
    RunsDirectory,
    LocksDirectory,
    RunDirectory,
    JournalHeadsDirectory,
    GuestAgent,
    PreparedPlan,
    WindowsSandboxPlan,
    PreparationReceipt,
    RunLock,
    AuthoritativePlan,
    PlanningImportReceipt,
    EventsJournal,
    RevocationRecord,
    JournalHead1,
    JournalHead2,
    JournalHead3,
}

const ACQUIRE_ORDER: [FixedWsbObject; 19] = [
    FixedWsbObject::WorkspaceRoot,
    FixedWsbObject::ToolsDirectory,
    FixedWsbObject::OutputDirectory,
    FixedWsbObject::RunsDirectory,
    FixedWsbObject::LocksDirectory,
    FixedWsbObject::RunDirectory,
    FixedWsbObject::JournalHeadsDirectory,
    FixedWsbObject::GuestAgent,
    FixedWsbObject::PreparedPlan,
    FixedWsbObject::WindowsSandboxPlan,
    FixedWsbObject::PreparationReceipt,
    FixedWsbObject::RunLock,
    FixedWsbObject::AuthoritativePlan,
    FixedWsbObject::PlanningImportReceipt,
    FixedWsbObject::EventsJournal,
    FixedWsbObject::RevocationRecord,
    FixedWsbObject::JournalHead1,
    FixedWsbObject::JournalHead2,
    FixedWsbObject::JournalHead3,
];

fn delete_order() -> [FixedWsbObject; 19] {
    WSB_FIXED_OBJECT_DELETE_ORDER.map(native_kind)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StableFileId {
    pub(crate) volume_serial_number: u64,
    pub(crate) file_id: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FixedObjectBinding {
    pub(crate) key: FixedWsbObject,
    pub(crate) id: StableFileId,
    pub(crate) attributes: u32,
    pub(crate) link_count: u32,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) sha256: Option<[u8; 32]>,
    pub(crate) ea: ExtendedAttributeBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExtendedAttributeEntryBinding {
    pub(crate) name: String,
    pub(crate) flags: u8,
    pub(crate) value_length: u16,
    pub(crate) value_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct ExtendedAttributeBinding {
    pub(crate) queried_bytes: u32,
    pub(crate) entries: Vec<ExtendedAttributeEntryBinding>,
    pub(crate) canonical_sha256: [u8; 32],
}

// `NtQueryEaFile` may report different trailing zero-padding lengths for the
// same EA records across exact close/reopen cycles. The parser validates every
// reported byte, while identity comparison is deliberately over the canonical
// names, flags, value lengths, and value hashes rather than that padding size.
impl PartialEq for ExtendedAttributeBinding {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries && self.canonical_sha256 == other.canonical_sha256
    }
}

impl Eq for ExtendedAttributeBinding {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FixedWsbTreeInventory {
    workspace: WorkspaceBindingEvidence,
    run_id: String,
    parent_id: StableFileId,
    original_root: PathBuf,
    tombstone_leaf: String,
    objects: Vec<FixedObjectBinding>,
}

impl FixedWsbTreeInventory {
    pub(crate) fn workspace(&self) -> &WorkspaceBindingEvidence {
        &self.workspace
    }

    pub(crate) fn run_id(&self) -> &str {
        &self.run_id
    }

    pub(crate) fn parent_id(&self) -> &StableFileId {
        &self.parent_id
    }

    pub(crate) fn original_root(&self) -> &Path {
        &self.original_root
    }

    pub(crate) fn tombstone_leaf(&self) -> &str {
        &self.tombstone_leaf
    }

    pub(crate) fn objects(&self) -> &[FixedObjectBinding] {
        &self.objects
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixedWsbTreeLocation {
    Original,
    Tombstone,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExactRenameObservation {
    pub(crate) root_id: StableFileId,
    pub(crate) tombstone_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExactDeleteObservation {
    pub(crate) key: FixedWsbObject,
    pub(crate) id: StableFileId,
}

#[derive(Debug, Error)]
#[doc(hidden)]
pub enum ExactDisposeError {
    #[error("fixed WSB tree contract is invalid: {0}")]
    Contract(String),
    #[error("fixed WSB tree identity, type, ACL, or content was rejected: {0}")]
    Rejected(String),
    #[error("fixed file SmartLocker EAs have not reached the exact pair")]
    TransientSmartLockerEa,
    #[error("fixed WSB tree native operation failed at {operation}: {detail}")]
    Native {
        operation: &'static str,
        detail: String,
    },
}

#[derive(Clone, Copy)]
enum OpenPurpose {
    Observe,
    CheckpointSnapshot,
    DisposeOriginal,
    DisposeTombstone,
}

struct HeldExactObject {
    key: FixedWsbObject,
    file: Option<File>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryEntry {
    pub(crate) name: String,
    pub(crate) file_id: [u8; 16],
    pub(crate) attributes: u32,
    pub(crate) ea_size: u32,
    pub(crate) reparse_tag: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryAliasEntry {
    name: String,
    short_name: Option<String>,
    ea_size: u32,
}

impl HeldExactObject {
    fn file(&self) -> Result<&File, ExactDisposeError> {
        self.file
            .as_ref()
            .ok_or_else(|| ExactDisposeError::Rejected("object handle was already consumed".into()))
    }
}

pub(crate) struct HeldFixedWsbTree {
    parent: File,
    inventory: FixedWsbTreeInventory,
    objects: Vec<HeldExactObject>,
    location: FixedWsbTreeLocation,
    next_delete: usize,
}

/// Read-only authority over the exact pre-disposal tree. The object handles
/// deliberately refuse write and delete sharing until checkpoint publication
/// has completed.
#[doc(hidden)]
pub struct HeldFixedWsbCheckpointSnapshot {
    parent: File,
    inventory: FixedWsbTreeInventory,
    evidence: WsbFixedTreeInventoryEvidence,
    objects: Vec<HeldExactObject>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum WsbRootNamespaceState {
    Original,
    Tombstone,
    Absent,
    Foreign,
    Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct WsbRootDepublishObservation {
    pub root_id: DiscardIntentStableId,
    pub tombstone_path: String,
}

#[doc(hidden)]
pub struct HeldCheckpointBoundWsbRoot {
    tree: HeldFixedWsbTree,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct WsbDispositionStep {
    pub sequence: u8,
    pub kind: WsbFixedObjectKind,
    pub id: DiscardIntentStableId,
}

#[doc(hidden)]
pub struct HeldCheckpointBoundWsbDisposition {
    tree: HeldFixedWsbTree,
}

impl HeldCheckpointBoundWsbDisposition {
    pub fn completed_count(&self) -> u8 {
        self.tree.next_delete as u8
    }

    pub fn next_step(&self) -> Result<Option<WsbDispositionStep>, ExactDisposeError> {
        let Some(key) = self.tree.next_object() else {
            return Ok(None);
        };
        let binding = self.tree.binding(key)?;
        Ok(Some(WsbDispositionStep {
            sequence: self.tree.next_delete as u8,
            kind: portable_kind(key),
            id: stable_id_evidence(&binding.id),
        }))
    }

    pub fn revalidate(&self) -> Result<(), ExactDisposeError> {
        self.tree.revalidate_remaining()
    }

    pub fn completed_original_replacement_id(
        &self,
    ) -> Result<Option<DiscardIntentStableId>, ExactDisposeError> {
        if self.tree.next_delete != delete_order().len() {
            return Err(ExactDisposeError::Contract(
                "original replacement observation requires a complete disposition".into(),
            ));
        }
        if stable_id(&self.tree.parent)? != self.tree.inventory.parent_id {
            return Err(ExactDisposeError::Rejected(
                "workspace parent identity changed after disposition".into(),
            ));
        }
        reject_case_sensitive_directory(&self.tree.parent)?;
        if path_identity_if_present(&self.tree.tombstone_root())?.is_some() {
            return Err(ExactDisposeError::Rejected(
                "completed disposition tombstone name is occupied".into(),
            ));
        }
        let observed = path_identity_if_present(&self.tree.inventory.original_root)?;
        if observed.as_ref() == Some(&self.tree.inventory.objects[0].id) {
            return Err(ExactDisposeError::Rejected(
                "disposed workspace identity reappeared at the original name".into(),
            ));
        }
        Ok(observed.map(|id| stable_id_evidence(&id)))
    }

    pub fn dispose_next(&mut self) -> Result<WsbDispositionStep, ExactDisposeError> {
        let sequence = self.tree.next_delete as u8;
        let observation = self.tree.dispose_next()?;
        Ok(WsbDispositionStep {
            sequence,
            kind: portable_kind(observation.key),
            id: stable_id_evidence(&observation.id),
        })
    }
}

impl HeldCheckpointBoundWsbRoot {
    pub fn revalidate(&self) -> Result<(), ExactDisposeError> {
        self.tree.revalidate_remaining()
    }

    pub fn depublish_and_release(
        mut self,
    ) -> Result<WsbRootDepublishObservation, ExactDisposeError> {
        let observation = self.tree.depublish()?;
        Ok(WsbRootDepublishObservation {
            root_id: stable_id_evidence(&observation.root_id),
            tombstone_path: observation.tombstone_path.to_string_lossy().into_owned(),
        })
    }
}

pub(crate) fn observe_fixed_wsb_tree(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    tombstone_leaf: &str,
) -> Result<FixedWsbTreeInventory, ExactDisposeError> {
    validate_inputs(workspace, run_id)?;
    validate_checkpoint_tombstone_leaf(tombstone_leaf)?;
    let original_root = PathBuf::from(&workspace.root.final_path);
    let parent_path = original_root.parent().ok_or_else(|| {
        ExactDisposeError::Contract("workspace root has no parent directory".into())
    })?;
    let parent = open_parent(parent_path)?;
    let parent_id = stable_id(&parent)?;
    require_evidence_id(&parent_id, &workspace.parent, "parent")?;
    reject_case_sensitive_directory(&parent)?;
    if path_identity_if_present(&parent_path.join(tombstone_leaf))?.is_some() {
        return Err(ExactDisposeError::Rejected(
            "checkpoint-bound tombstone name is already occupied".into(),
        ));
    }
    let owner = OwnedSid::from_string(&workspace.owner_sid).map_err(workspace_error)?;
    let held = open_objects(
        &original_root,
        run_id,
        OpenPurpose::Observe,
        &owner,
        workspace,
    )?;
    verify_allowlists(&held, run_id)?;
    let mut objects = Vec::with_capacity(ACQUIRE_ORDER.len());
    for object in &held {
        objects.push(observe_binding(object, &owner)?);
    }
    Ok(FixedWsbTreeInventory {
        workspace: workspace.clone(),
        run_id: run_id.to_owned(),
        parent_id,
        original_root,
        tombstone_leaf: tombstone_leaf.to_owned(),
        objects,
    })
}

#[doc(hidden)]
pub fn observe_fixed_wsb_tree_for_checkpoint(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    tombstone_leaf: &str,
) -> Result<WsbFixedTreeInventoryEvidence, ExactDisposeError> {
    inventory_evidence(observe_fixed_wsb_tree(workspace, run_id, tombstone_leaf)?)
}

#[doc(hidden)]
pub fn hold_fixed_wsb_tree_for_checkpoint(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    tombstone_leaf: &str,
) -> Result<HeldFixedWsbCheckpointSnapshot, ExactDisposeError> {
    validate_inputs(workspace, run_id)?;
    validate_checkpoint_tombstone_leaf(tombstone_leaf)?;
    let original_root = PathBuf::from(&workspace.root.final_path);
    let parent_path = original_root.parent().ok_or_else(|| {
        ExactDisposeError::Contract("workspace root has no parent directory".into())
    })?;
    let parent = open_parent(parent_path)?;
    let parent_id = stable_id(&parent)?;
    require_evidence_id(&parent_id, &workspace.parent, "parent")?;
    reject_case_sensitive_directory(&parent)?;
    if path_identity_if_present(&parent_path.join(tombstone_leaf))?.is_some() {
        return Err(ExactDisposeError::Rejected(
            "checkpoint-bound tombstone name is already occupied".into(),
        ));
    }
    let owner = OwnedSid::from_string(&workspace.owner_sid).map_err(workspace_error)?;
    let objects = open_objects(
        &original_root,
        run_id,
        OpenPurpose::CheckpointSnapshot,
        &owner,
        workspace,
    )?;
    verify_allowlists(&objects, run_id)?;
    let mut bindings = Vec::with_capacity(ACQUIRE_ORDER.len());
    for object in &objects {
        bindings.push(observe_binding(object, &owner)?);
    }
    let inventory = FixedWsbTreeInventory {
        workspace: workspace.clone(),
        run_id: run_id.to_owned(),
        parent_id,
        original_root,
        tombstone_leaf: tombstone_leaf.to_owned(),
        objects: bindings,
    };
    let evidence = inventory_evidence(inventory.clone())?;
    let held = HeldFixedWsbCheckpointSnapshot {
        parent,
        inventory,
        evidence,
        objects,
    };
    held.revalidate()?;
    Ok(held)
}

#[doc(hidden)]
pub fn classify_checkpoint_bound_wsb_root(
    expected: &WsbFixedTreeInventoryEvidence,
) -> Result<WsbRootNamespaceState, ExactDisposeError> {
    let inventory = portable_inventory(expected)?;
    let parent_path = inventory.original_root.parent().ok_or_else(|| {
        ExactDisposeError::Contract("workspace root has no parent directory".into())
    })?;
    let parent = open_parent(parent_path)?;
    if stable_id(&parent)? != inventory.parent_id {
        return Err(ExactDisposeError::Rejected(
            "workspace parent identity changed".into(),
        ));
    }
    reject_case_sensitive_directory(&parent)?;
    let expected_root = &inventory.objects[0].id;
    let original = path_identity_if_present(&inventory.original_root)?;
    let tombstone = path_identity_if_present(&parent_path.join(&inventory.tombstone_leaf))?;
    let state = match (&original, &tombstone) {
        (Some(original), None) if original == expected_root => WsbRootNamespaceState::Original,
        (original, Some(tombstone))
            if tombstone == expected_root && original.as_ref() != Some(expected_root) =>
        {
            // A replacement at the old name after a completed depublish is
            // unrelated. Exact tombstone recovery must neither open it nor let
            // it obscure the already-completed rename.
            WsbRootNamespaceState::Tombstone
        }
        (None, None) => WsbRootNamespaceState::Absent,
        (Some(_), Some(_)) => WsbRootNamespaceState::Ambiguous,
        _ => WsbRootNamespaceState::Foreign,
    };
    match state {
        WsbRootNamespaceState::Original => {
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original)?;
        }
        WsbRootNamespaceState::Tombstone => {
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Tombstone)?;
        }
        _ => {}
    }
    Ok(state)
}

#[doc(hidden)]
pub fn reopen_checkpoint_bound_wsb_root(
    expected: &WsbFixedTreeInventoryEvidence,
    state: WsbRootNamespaceState,
) -> Result<HeldCheckpointBoundWsbRoot, ExactDisposeError> {
    let inventory = portable_inventory(expected)?;
    let location = match state {
        WsbRootNamespaceState::Original => FixedWsbTreeLocation::Original,
        WsbRootNamespaceState::Tombstone => FixedWsbTreeLocation::Tombstone,
        _ => {
            return Err(ExactDisposeError::Contract(
                "only exact original or tombstone state can be reopened".into(),
            ));
        }
    };
    let tree = HeldFixedWsbTree::reopen_exact(&inventory, location)?;
    tree.revalidate_remaining()?;
    Ok(HeldCheckpointBoundWsbRoot { tree })
}

#[doc(hidden)]
pub fn reopen_checkpoint_bound_wsb_disposition(
    expected: &WsbFixedTreeInventoryEvidence,
    completed_count: u8,
) -> Result<HeldCheckpointBoundWsbDisposition, ExactDisposeError> {
    let inventory = portable_inventory(expected)?;
    let completed = usize::from(completed_count);
    if completed > delete_order().len() {
        return Err(ExactDisposeError::Contract(
            "disposition prefix exceeds the fixed object count".into(),
        ));
    }
    let tree = HeldFixedWsbTree::reopen_disposition_prefix(&inventory, completed)?;
    tree.revalidate_remaining()?;
    Ok(HeldCheckpointBoundWsbDisposition { tree })
}

impl HeldFixedWsbCheckpointSnapshot {
    #[must_use]
    pub fn evidence(&self) -> &WsbFixedTreeInventoryEvidence {
        &self.evidence
    }

    pub fn revalidate(&self) -> Result<(), ExactDisposeError> {
        self.evidence
            .validate()
            .map_err(|error| ExactDisposeError::Contract(error.into()))?;
        if stable_id(&self.parent)? != self.inventory.parent_id {
            return Err(ExactDisposeError::Rejected(
                "workspace parent identity changed during checkpoint capture".into(),
            ));
        }
        let parent_path = self.inventory.original_root.parent().ok_or_else(|| {
            ExactDisposeError::Contract("workspace root has no parent directory".into())
        })?;
        if path_identity_if_present(&parent_path.join(&self.inventory.tombstone_leaf))?.is_some() {
            return Err(ExactDisposeError::Rejected(
                "checkpoint-bound tombstone appeared during checkpoint capture".into(),
            ));
        }
        let owner =
            OwnedSid::from_string(&self.inventory.workspace.owner_sid).map_err(workspace_error)?;
        for (object, expected) in self.objects.iter().zip(&self.inventory.objects) {
            if object.key != expected.key {
                return Err(ExactDisposeError::Contract(
                    "fixed object ordering changed".into(),
                ));
            }
            verify_expected(
                object,
                expected,
                &owner,
                &self.inventory.original_root,
                &self.inventory.run_id,
            )?;
        }
        verify_allowlists(&self.objects, &self.inventory.run_id)
    }
}

#[doc(hidden)]
pub fn verify_fixed_wsb_tree_inventory(
    expected: &WsbFixedTreeInventoryEvidence,
) -> Result<(), ExactDisposeError> {
    expected
        .validate()
        .map_err(|error| ExactDisposeError::Contract(error.into()))?;
    let observed = observe_fixed_wsb_tree_for_checkpoint(
        &expected.workspace,
        &expected.run_id,
        &expected.tombstone_leaf,
    )?;
    if &observed != expected {
        return Err(ExactDisposeError::Rejected(
            "portable fixed-tree evidence changed during exact reopen".into(),
        ));
    }
    Ok(())
}

fn inventory_evidence(
    inventory: FixedWsbTreeInventory,
) -> Result<WsbFixedTreeInventoryEvidence, ExactDisposeError> {
    let root = inventory.original_root.clone();
    let run_id = inventory.run_id.clone();
    let objects = inventory
        .objects
        .iter()
        .map(|binding| object_evidence(binding, &root, &run_id))
        .collect::<Result<Vec<_>, _>>()?;
    let evidence = WsbFixedTreeInventoryEvidence {
        schema_version: WSB_FIXED_TREE_INVENTORY_SCHEMA_VERSION.to_owned(),
        contract_version: WSB_FIXED_TREE_CONTRACT_VERSION.to_owned(),
        run_id: inventory.run_id,
        workspace: inventory.workspace,
        parent_id: stable_id_evidence(&inventory.parent_id),
        original_root: inventory.original_root.to_string_lossy().into_owned(),
        tombstone_leaf: inventory.tombstone_leaf,
        objects,
    };
    evidence
        .validate()
        .map_err(|error| ExactDisposeError::Contract(error.into()))?;
    Ok(evidence)
}

fn portable_inventory(
    evidence: &WsbFixedTreeInventoryEvidence,
) -> Result<FixedWsbTreeInventory, ExactDisposeError> {
    evidence
        .validate()
        .map_err(|error| ExactDisposeError::Contract(error.into()))?;
    let parse_id = |value: &DiscardIntentStableId| -> Result<StableFileId, ExactDisposeError> {
        let volume_serial_number = u64::from_str_radix(&value.volume_serial_number, 16)
            .map_err(|_| ExactDisposeError::Contract("portable volume ID is invalid".into()))?;
        let file_id = hex::decode(&value.file_id)
            .map_err(|_| ExactDisposeError::Contract("portable file ID is invalid".into()))?
            .try_into()
            .map_err(|_| ExactDisposeError::Contract("portable file ID is invalid".into()))?;
        Ok(StableFileId {
            volume_serial_number,
            file_id,
        })
    };
    let objects = evidence
        .objects
        .iter()
        .map(|object| {
            let sha256 = object
                .sha256
                .as_ref()
                .map(|value| {
                    hex::decode(value)
                        .map_err(|_| {
                            ExactDisposeError::Contract("portable file hash is invalid".into())
                        })?
                        .try_into()
                        .map_err(|_| {
                            ExactDisposeError::Contract("portable file hash is invalid".into())
                        })
                })
                .transpose()?;
            let entries = object
                .ea
                .entries
                .iter()
                .map(|entry| {
                    Ok(ExtendedAttributeEntryBinding {
                        name: entry.name.clone(),
                        flags: entry.flags,
                        value_length: entry.value_length,
                        value_sha256: hex::decode(&entry.value_sha256)
                            .map_err(|_| {
                                ExactDisposeError::Contract(
                                    "portable EA value hash is invalid".into(),
                                )
                            })?
                            .try_into()
                            .map_err(|_| {
                                ExactDisposeError::Contract(
                                    "portable EA value hash is invalid".into(),
                                )
                            })?,
                    })
                })
                .collect::<Result<Vec<_>, ExactDisposeError>>()?;
            Ok(FixedObjectBinding {
                key: native_kind(object.kind),
                id: parse_id(&object.id)?,
                attributes: object.attributes,
                link_count: object.link_count,
                size_bytes: object.size_bytes,
                sha256,
                ea: ExtendedAttributeBinding {
                    queried_bytes: 0,
                    entries,
                    canonical_sha256: hex::decode(&object.ea.canonical_sha256)
                        .map_err(|_| {
                            ExactDisposeError::Contract("portable EA digest is invalid".into())
                        })?
                        .try_into()
                        .map_err(|_| {
                            ExactDisposeError::Contract("portable EA digest is invalid".into())
                        })?,
                },
            })
        })
        .collect::<Result<Vec<_>, ExactDisposeError>>()?;
    let inventory = FixedWsbTreeInventory {
        workspace: evidence.workspace.clone(),
        run_id: evidence.run_id.clone(),
        parent_id: parse_id(&evidence.parent_id)?,
        original_root: PathBuf::from(&evidence.original_root),
        tombstone_leaf: evidence.tombstone_leaf.clone(),
        objects,
    };
    validate_inventory(&inventory)?;
    Ok(inventory)
}

fn native_kind(kind: WsbFixedObjectKind) -> FixedWsbObject {
    match kind {
        WsbFixedObjectKind::WorkspaceRoot => FixedWsbObject::WorkspaceRoot,
        WsbFixedObjectKind::ToolsDirectory => FixedWsbObject::ToolsDirectory,
        WsbFixedObjectKind::OutputDirectory => FixedWsbObject::OutputDirectory,
        WsbFixedObjectKind::RunsDirectory => FixedWsbObject::RunsDirectory,
        WsbFixedObjectKind::LocksDirectory => FixedWsbObject::LocksDirectory,
        WsbFixedObjectKind::RunDirectory => FixedWsbObject::RunDirectory,
        WsbFixedObjectKind::JournalHeadsDirectory => FixedWsbObject::JournalHeadsDirectory,
        WsbFixedObjectKind::GuestAgent => FixedWsbObject::GuestAgent,
        WsbFixedObjectKind::PreparedPlan => FixedWsbObject::PreparedPlan,
        WsbFixedObjectKind::WindowsSandboxPlan => FixedWsbObject::WindowsSandboxPlan,
        WsbFixedObjectKind::PreparationReceipt => FixedWsbObject::PreparationReceipt,
        WsbFixedObjectKind::RunLock => FixedWsbObject::RunLock,
        WsbFixedObjectKind::AuthoritativePlan => FixedWsbObject::AuthoritativePlan,
        WsbFixedObjectKind::PlanningImportReceipt => FixedWsbObject::PlanningImportReceipt,
        WsbFixedObjectKind::EventsJournal => FixedWsbObject::EventsJournal,
        WsbFixedObjectKind::RevocationRecord => FixedWsbObject::RevocationRecord,
        WsbFixedObjectKind::JournalHead1 => FixedWsbObject::JournalHead1,
        WsbFixedObjectKind::JournalHead2 => FixedWsbObject::JournalHead2,
        WsbFixedObjectKind::JournalHead3 => FixedWsbObject::JournalHead3,
    }
}

fn object_evidence(
    binding: &FixedObjectBinding,
    root: &Path,
    run_id: &str,
) -> Result<WsbFixedObjectEvidence, ExactDisposeError> {
    let path = path_for(root, run_id, binding.key);
    let relative_path = if binding.key == FixedWsbObject::WorkspaceRoot {
        ".".to_owned()
    } else {
        path.strip_prefix(root)
            .map_err(|_| ExactDisposeError::Contract("fixed object escaped its root".into()))?
            .to_string_lossy()
            .replace('\\', "/")
    };
    Ok(WsbFixedObjectEvidence {
        kind: portable_kind(binding.key),
        relative_path,
        id: stable_id_evidence(&binding.id),
        is_directory: binding.key.is_directory(),
        attributes: binding.attributes,
        link_count: binding.link_count,
        acl_policy: if binding.key.require_protected_acl() {
            WsbFixedTreeAclPolicy::OwnerSystemProtected
        } else {
            WsbFixedTreeAclPolicy::OwnerSystemInherited
        },
        stream_policy: if binding.key.is_directory() {
            WsbFixedTreeStreamPolicy::NoStreams
        } else {
            WsbFixedTreeStreamPolicy::UnnamedDataOnly
        },
        size_bytes: binding.size_bytes,
        sha256: binding.sha256.map(hex::encode),
        ea: WsbFixedTreeEaBinding {
            entries: binding
                .ea
                .entries
                .iter()
                .map(|entry| DiscardIntentEaEntry {
                    name: entry.name.clone(),
                    flags: entry.flags,
                    value_length: entry.value_length,
                    value_sha256: hex::encode(entry.value_sha256),
                })
                .collect(),
            canonical_sha256: hex::encode(binding.ea.canonical_sha256),
        },
    })
}

fn stable_id_evidence(value: &StableFileId) -> DiscardIntentStableId {
    DiscardIntentStableId {
        volume_serial_number: format!("{:016x}", value.volume_serial_number),
        file_id: hex::encode(value.file_id),
    }
}

const fn portable_kind(value: FixedWsbObject) -> WsbFixedObjectKind {
    match value {
        FixedWsbObject::WorkspaceRoot => WsbFixedObjectKind::WorkspaceRoot,
        FixedWsbObject::ToolsDirectory => WsbFixedObjectKind::ToolsDirectory,
        FixedWsbObject::OutputDirectory => WsbFixedObjectKind::OutputDirectory,
        FixedWsbObject::RunsDirectory => WsbFixedObjectKind::RunsDirectory,
        FixedWsbObject::LocksDirectory => WsbFixedObjectKind::LocksDirectory,
        FixedWsbObject::RunDirectory => WsbFixedObjectKind::RunDirectory,
        FixedWsbObject::JournalHeadsDirectory => WsbFixedObjectKind::JournalHeadsDirectory,
        FixedWsbObject::GuestAgent => WsbFixedObjectKind::GuestAgent,
        FixedWsbObject::PreparedPlan => WsbFixedObjectKind::PreparedPlan,
        FixedWsbObject::WindowsSandboxPlan => WsbFixedObjectKind::WindowsSandboxPlan,
        FixedWsbObject::PreparationReceipt => WsbFixedObjectKind::PreparationReceipt,
        FixedWsbObject::RunLock => WsbFixedObjectKind::RunLock,
        FixedWsbObject::AuthoritativePlan => WsbFixedObjectKind::AuthoritativePlan,
        FixedWsbObject::PlanningImportReceipt => WsbFixedObjectKind::PlanningImportReceipt,
        FixedWsbObject::EventsJournal => WsbFixedObjectKind::EventsJournal,
        FixedWsbObject::RevocationRecord => WsbFixedObjectKind::RevocationRecord,
        FixedWsbObject::JournalHead1 => WsbFixedObjectKind::JournalHead1,
        FixedWsbObject::JournalHead2 => WsbFixedObjectKind::JournalHead2,
        FixedWsbObject::JournalHead3 => WsbFixedObjectKind::JournalHead3,
    }
}

impl HeldFixedWsbTree {
    pub(crate) fn reopen_exact(
        inventory: &FixedWsbTreeInventory,
        location: FixedWsbTreeLocation,
    ) -> Result<Self, ExactDisposeError> {
        validate_inventory(inventory)?;
        let parent_path = inventory.original_root.parent().ok_or_else(|| {
            ExactDisposeError::Contract("workspace root has no parent directory".into())
        })?;
        let parent = open_parent(parent_path)?;
        if stable_id(&parent)? != inventory.parent_id {
            return Err(ExactDisposeError::Rejected(
                "workspace parent identity changed".into(),
            ));
        }
        reject_case_sensitive_directory(&parent)?;
        let tombstone_path = parent_path.join(&inventory.tombstone_leaf);
        let root_id = &inventory.objects[0].id;
        match location {
            FixedWsbTreeLocation::Original => {
                let original_present = path_identity_if_present(&inventory.original_root)?;
                let tombstone_present = path_identity_if_present(&tombstone_path)?;
                if original_present.as_ref() != Some(root_id) || tombstone_present.is_some() {
                    return Err(ExactDisposeError::Rejected(
                        "original/tombstone name state is ambiguous or foreign".into(),
                    ));
                }
            }
            FixedWsbTreeLocation::Tombstone => {
                // Once the exact root was depublished, a new object published
                // at the old name is unrelated and must neither be opened nor
                // allowed to block exact tombstone recovery.
                if path_identity_if_present(&tombstone_path)?.as_ref() != Some(root_id) {
                    return Err(ExactDisposeError::Rejected(
                        "exact tombstone root is absent or foreign".into(),
                    ));
                }
            }
        }
        let root_path = match location {
            FixedWsbTreeLocation::Original => inventory.original_root.clone(),
            FixedWsbTreeLocation::Tombstone => tombstone_path,
        };
        let owner =
            OwnedSid::from_string(&inventory.workspace.owner_sid).map_err(workspace_error)?;
        let purpose = match location {
            FixedWsbTreeLocation::Original => OpenPurpose::DisposeOriginal,
            FixedWsbTreeLocation::Tombstone => OpenPurpose::DisposeTombstone,
        };
        let objects = open_objects(
            &root_path,
            &inventory.run_id,
            purpose,
            &owner,
            &inventory.workspace,
        )?;
        for (object, expected) in objects.iter().zip(&inventory.objects) {
            if object.key != expected.key {
                return Err(ExactDisposeError::Contract(
                    "fixed object ordering changed".into(),
                ));
            }
            verify_expected(object, expected, &owner, &root_path, &inventory.run_id)?;
        }
        verify_allowlists(&objects, &inventory.run_id)?;
        Ok(Self {
            parent,
            inventory: inventory.clone(),
            objects,
            location,
            next_delete: 0,
        })
    }

    fn reopen_disposition_prefix(
        inventory: &FixedWsbTreeInventory,
        completed: usize,
    ) -> Result<Self, ExactDisposeError> {
        validate_inventory(inventory)?;
        if completed > delete_order().len() {
            return Err(ExactDisposeError::Contract(
                "disposition prefix exceeds the fixed object count".into(),
            ));
        }
        let parent_path = inventory.original_root.parent().ok_or_else(|| {
            ExactDisposeError::Contract("workspace root has no parent directory".into())
        })?;
        let parent = open_parent(parent_path)?;
        if stable_id(&parent)? != inventory.parent_id {
            return Err(ExactDisposeError::Rejected(
                "workspace parent identity changed".into(),
            ));
        }
        reject_case_sensitive_directory(&parent)?;
        let tombstone_root = parent_path.join(&inventory.tombstone_leaf);
        let expected_root = &inventory.objects[0].id;
        let tombstone = path_identity_if_present(&tombstone_root)?;
        if completed == delete_order().len() {
            if tombstone.is_some() {
                return Err(ExactDisposeError::Rejected(
                    "completed disposition still has a tombstone name".into(),
                ));
            }
        } else if tombstone.as_ref() != Some(expected_root) {
            return Err(ExactDisposeError::Rejected(
                "partial disposition tombstone is absent or foreign".into(),
            ));
        }
        let owner =
            OwnedSid::from_string(&inventory.workspace.owner_sid).map_err(workspace_error)?;
        let deleted: BTreeSet<_> = delete_order().into_iter().take(completed).collect();
        let mut objects = Vec::with_capacity(ACQUIRE_ORDER.len());
        for key in ACQUIRE_ORDER {
            let path = path_for(&tombstone_root, &inventory.run_id, key);
            if deleted.contains(&key) {
                if path_identity_if_present(&path)?.is_some() {
                    return Err(ExactDisposeError::Rejected(format!(
                        "committed disposition object {key:?} is still present"
                    )));
                }
                objects.push(HeldExactObject { key, file: None });
                continue;
            }
            let file = open_object(&path, key, OpenPurpose::DisposeTombstone)?;
            objects.push(HeldExactObject {
                key,
                file: Some(file),
            });
        }
        for (object, expected) in objects.iter().zip(&inventory.objects) {
            if object.key != expected.key {
                return Err(ExactDisposeError::Contract(
                    "fixed object ordering changed".into(),
                ));
            }
            if object.file.is_some() {
                verify_expected(object, expected, &owner, &tombstone_root, &inventory.run_id)?;
            }
        }
        verify_allowlists(&objects, &inventory.run_id)?;
        Ok(Self {
            parent,
            inventory: inventory.clone(),
            objects,
            location: FixedWsbTreeLocation::Tombstone,
            next_delete: completed,
        })
    }

    pub(crate) fn inventory(&self) -> &FixedWsbTreeInventory {
        &self.inventory
    }

    pub(crate) fn next_object(&self) -> Option<FixedWsbObject> {
        delete_order().get(self.next_delete).copied()
    }

    pub(crate) fn depublish(&mut self) -> Result<ExactRenameObservation, ExactDisposeError> {
        if self.location != FixedWsbTreeLocation::Original || self.next_delete != 0 {
            return Err(ExactDisposeError::Contract(
                "only an untouched original tree can be depublished".into(),
            ));
        }
        self.revalidate_remaining()?;
        let parent_names = directory_namespace_names(&self.parent)?;
        let original_leaf = file_name_string(&self.inventory.original_root)?;
        if !contains_name(&parent_names, &original_leaf)
            || contains_name(&parent_names, &self.inventory.tombstone_leaf)
        {
            return Err(ExactDisposeError::Rejected(
                "original/tombstone parent state changed before rename".into(),
            ));
        }

        // NTFS refuses to rename a directory while descendants have open
        // handles, even when every handle shares delete access. Keep the exact
        // root handle continuously held, release only descendants for the
        // atomic namespace change, and reacquire/revalidate all descendants
        // under the tombstone before disposition can begin.
        for object in &mut self.objects {
            if object.key != FixedWsbObject::WorkspaceRoot {
                object.file.take();
            }
        }
        let root = self.object(FixedWsbObject::WorkspaceRoot)?.file()?;
        let rename_result = rename_relative(
            root,
            &self.parent,
            OsStr::new(&self.inventory.tombstone_leaf),
        );
        if let Err(rename_error) = rename_result {
            let parent_names = directory_namespace_names(&self.parent)?;
            if !contains_name(&parent_names, &original_leaf)
                || contains_name(&parent_names, &self.inventory.tombstone_leaf)
                || stable_id(root)? != self.inventory.objects[0].id
                || !same_path(
                    final_path(root).map_err(workspace_error)?,
                    &self.inventory.original_root,
                )
            {
                return Err(ExactDisposeError::Rejected(
                    "failed rename left an ambiguous original/tombstone state".into(),
                ));
            }
            // A live orchestrator RunLock is expected to make the ancestor
            // rename fail on NTFS even when it shares delete. Restore every
            // released descendant handle and prove the original tree stayed
            // exact so #28 may durably release that external authority and
            // retry this same held root/parent operation.
            let original_root = self.inventory.original_root.clone();
            self.reacquire_descendants(&original_root, OpenPurpose::DisposeOriginal)?;
            self.revalidate_remaining()?;
            return Err(rename_error);
        }
        let tombstone_root = self.tombstone_root();
        let parent_names = directory_namespace_names(&self.parent)?;
        if contains_name(&parent_names, &original_leaf)
            || !contains_name(&parent_names, &self.inventory.tombstone_leaf)
            || stable_id(root)? != self.inventory.objects[0].id
            || !same_path(final_path(root).map_err(workspace_error)?, &tombstone_root)
        {
            return Err(ExactDisposeError::Rejected(
                "rename postcondition is not original-absent/tombstone-same-ID".into(),
            ));
        }
        self.location = FixedWsbTreeLocation::Tombstone;
        self.reacquire_descendants(&tombstone_root, OpenPurpose::DisposeTombstone)?;
        self.revalidate_remaining()?;
        Ok(ExactRenameObservation {
            root_id: self.inventory.objects[0].id.clone(),
            tombstone_path: self.tombstone_root(),
        })
    }

    pub(crate) fn dispose_next(&mut self) -> Result<ExactDeleteObservation, ExactDisposeError> {
        if self.location != FixedWsbTreeLocation::Tombstone {
            return Err(ExactDisposeError::Contract(
                "tree must be depublished before disposition".into(),
            ));
        }
        self.revalidate_remaining()?;
        let key = self.next_object().ok_or_else(|| {
            ExactDisposeError::Contract("fixed tree is already fully disposed".into())
        })?;
        let expected = self.binding(key)?.clone();
        let root_path = self.tombstone_root();
        {
            let object = self.object(key)?;
            let owner = OwnedSid::from_string(&self.inventory.workspace.owner_sid)
                .map_err(workspace_error)?;
            verify_expected(
                object,
                &expected,
                &owner,
                &root_path,
                &self.inventory.run_id,
            )?;
            if key.is_directory() && !directory_entries(object.file()?)?.is_empty() {
                return Err(ExactDisposeError::Rejected(
                    "fixed child-first order reached a non-empty directory".into(),
                ));
            }
        }
        let index = self.object_index(key)?;
        let file = self.objects[index]
            .file
            .as_ref()
            .ok_or_else(|| ExactDisposeError::Rejected("object was already consumed".into()))?;
        mark_delete(file)?;
        if !standard_info(file)?.DeletePending {
            return Err(ExactDisposeError::Rejected(format!(
                "classic disposition did not mark {key:?} delete-pending"
            )));
        }
        let file = self.objects[index]
            .file
            .take()
            .expect("checked immediately above");
        drop(file);
        let leaf = file_name_string(&path_for(&root_path, &self.inventory.run_id, key))?;
        let remaining_names = if key == FixedWsbObject::WorkspaceRoot {
            directory_namespace_names(&self.parent)?
        } else {
            let parent_key = key.parent().ok_or_else(|| {
                ExactDisposeError::Contract("fixed object has no containing directory".into())
            })?;
            directory_entries(self.object(parent_key)?.file()?)?
                .into_iter()
                .map(|entry| entry.name)
                .collect()
        };
        if contains_name(&remaining_names, &leaf) {
            return Err(ExactDisposeError::Rejected(
                "marked object name remained present after handle close".into(),
            ));
        }
        self.next_delete += 1;
        Ok(ExactDeleteObservation {
            key,
            id: expected.id,
        })
    }

    pub(crate) fn dispose_all(&mut self) -> Result<Vec<ExactDeleteObservation>, ExactDisposeError> {
        let mut observations = Vec::with_capacity(delete_order().len() - self.next_delete);
        while self.next_object().is_some() {
            observations.push(self.dispose_next()?);
        }
        Ok(observations)
    }

    fn tombstone_root(&self) -> PathBuf {
        self.inventory
            .original_root
            .parent()
            .expect("validated parent")
            .join(&self.inventory.tombstone_leaf)
    }

    fn object_index(&self, key: FixedWsbObject) -> Result<usize, ExactDisposeError> {
        self.objects
            .iter()
            .position(|object| object.key == key)
            .ok_or_else(|| ExactDisposeError::Contract("fixed object is missing".into()))
    }

    fn object(&self, key: FixedWsbObject) -> Result<&HeldExactObject, ExactDisposeError> {
        Ok(&self.objects[self.object_index(key)?])
    }

    fn binding(&self, key: FixedWsbObject) -> Result<&FixedObjectBinding, ExactDisposeError> {
        self.inventory
            .objects
            .iter()
            .find(|binding| binding.key == key)
            .ok_or_else(|| ExactDisposeError::Contract("fixed binding is missing".into()))
    }

    fn revalidate_remaining(&self) -> Result<(), ExactDisposeError> {
        if self.location == FixedWsbTreeLocation::Tombstone
            && self.next_delete == delete_order().len()
            && path_identity_if_present(&self.tombstone_root())?.is_some()
        {
            return Err(ExactDisposeError::Rejected(
                "completed disposition tombstone name was recreated".into(),
            ));
        }
        let owner =
            OwnedSid::from_string(&self.inventory.workspace.owner_sid).map_err(workspace_error)?;
        let root = match self.location {
            FixedWsbTreeLocation::Original => self.inventory.original_root.clone(),
            FixedWsbTreeLocation::Tombstone => self.tombstone_root(),
        };
        for object in &self.objects {
            if object.file.is_some() {
                verify_expected(
                    object,
                    self.binding(object.key)?,
                    &owner,
                    &root,
                    &self.inventory.run_id,
                )?;
            }
        }
        verify_allowlists(&self.objects, &self.inventory.run_id)
    }

    fn reacquire_descendants(
        &mut self,
        root: &Path,
        purpose: OpenPurpose,
    ) -> Result<(), ExactDisposeError> {
        let owner =
            OwnedSid::from_string(&self.inventory.workspace.owner_sid).map_err(workspace_error)?;
        for key in ACQUIRE_ORDER.into_iter().skip(1) {
            let path = path_for(root, &self.inventory.run_id, key);
            let file = open_object(&path, key, purpose)?;
            let index = self.object_index(key)?;
            self.objects[index].file = Some(file);
        }
        for (object, expected) in self.objects.iter().zip(&self.inventory.objects) {
            verify_expected(object, expected, &owner, root, &self.inventory.run_id)?;
        }
        verify_allowlists(&self.objects, &self.inventory.run_id)
    }
}

impl FixedWsbObject {
    fn is_directory(self) -> bool {
        matches!(
            self,
            Self::WorkspaceRoot
                | Self::ToolsDirectory
                | Self::OutputDirectory
                | Self::RunsDirectory
                | Self::LocksDirectory
                | Self::RunDirectory
                | Self::JournalHeadsDirectory
        )
    }

    fn parent(self) -> Option<Self> {
        match self {
            Self::WorkspaceRoot => None,
            Self::ToolsDirectory
            | Self::OutputDirectory
            | Self::RunsDirectory
            | Self::PreparedPlan
            | Self::WindowsSandboxPlan
            | Self::PreparationReceipt => Some(Self::WorkspaceRoot),
            Self::LocksDirectory | Self::RunDirectory => Some(Self::RunsDirectory),
            Self::JournalHeadsDirectory
            | Self::AuthoritativePlan
            | Self::PlanningImportReceipt
            | Self::EventsJournal
            | Self::RevocationRecord => Some(Self::RunDirectory),
            Self::GuestAgent => Some(Self::ToolsDirectory),
            Self::RunLock => Some(Self::LocksDirectory),
            Self::JournalHead1 | Self::JournalHead2 | Self::JournalHead3 => {
                Some(Self::JournalHeadsDirectory)
            }
        }
    }

    fn size_limit(self) -> u64 {
        match self {
            Self::GuestAgent => MAX_GUEST_AGENT,
            Self::EventsJournal => MAX_JOURNAL,
            Self::RunLock => 0,
            _ => MAX_SMALL_ARTIFACT,
        }
    }

    fn require_protected_acl(self) -> bool {
        matches!(
            self,
            Self::WorkspaceRoot | Self::ToolsDirectory | Self::OutputDirectory
        )
    }
}

fn open_objects(
    root: &Path,
    run_id: &str,
    purpose: OpenPurpose,
    owner: &OwnedSid,
    workspace: &WorkspaceBindingEvidence,
) -> Result<Vec<HeldExactObject>, ExactDisposeError> {
    let mut objects = Vec::with_capacity(ACQUIRE_ORDER.len());
    for key in ACQUIRE_ORDER {
        let path = path_for(root, run_id, key);
        let file = open_object(&path, key, purpose)?;
        verify_object_shape(&file, key, owner)?;
        let id = stable_id(&file)?;
        match key {
            FixedWsbObject::WorkspaceRoot => require_evidence_id(&id, &workspace.root, "root")?,
            FixedWsbObject::ToolsDirectory => require_evidence_id(&id, &workspace.tools, "tools")?,
            FixedWsbObject::OutputDirectory => {
                require_evidence_id(&id, &workspace.output, "output")?
            }
            _ => {}
        }
        if !same_path(final_path(&file).map_err(workspace_error)?, &path) {
            return Err(ExactDisposeError::Rejected(format!(
                "held {:?} final path changed",
                key
            )));
        }
        objects.push(HeldExactObject {
            key,
            file: Some(file),
        });
    }
    Ok(objects)
}

fn open_parent(path: &Path) -> Result<File, ExactDisposeError> {
    let file = OpenOptions::new()
        .access_mode(
            FILE_READ_ATTRIBUTES.0
                | FILE_LIST_DIRECTORY.0
                | FILE_TRAVERSE.0
                | READ_CONTROL.0
                | SYNCHRONIZE.0,
        )
        // The held parent is the namespace authority for the relative rename.
        // Refusing delete sharing prevents parent replacement while it is used.
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| native_io("CreateFileW(parent)", error))?;
    let info = basic_info(&file)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(ExactDisposeError::Rejected(
            "workspace parent is not an ordinary directory".into(),
        ));
    }
    Ok(file)
}

fn open_object(
    path: &Path,
    key: FixedWsbObject,
    purpose: OpenPurpose,
) -> Result<File, ExactDisposeError> {
    let mut access = FILE_READ_ATTRIBUTES.0 | FILE_READ_EA.0 | READ_CONTROL.0 | SYNCHRONIZE.0;
    access |= if key.is_directory() {
        FILE_LIST_DIRECTORY.0
    } else {
        FILE_READ_DATA.0
    };
    if matches!(
        purpose,
        OpenPurpose::DisposeOriginal | OpenPurpose::DisposeTombstone
    ) {
        access |= DELETE.0;
    }
    let share = if matches!(purpose, OpenPurpose::DisposeOriginal) && key == FixedWsbObject::RunLock
    {
        // The orchestrator's live run-lock authority uses a read/write handle.
        // Its standard Windows share mode includes delete, so this exact
        // delete-capable observation must reciprocally share read and write.
        FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0
    } else if matches!(
        purpose,
        OpenPurpose::DisposeOriginal | OpenPurpose::DisposeTombstone
    ) {
        0
    } else if matches!(purpose, OpenPurpose::CheckpointSnapshot) {
        // This is the non-destructive commit barrier: cooperating or hostile
        // opens cannot acquire write/delete access while the exact snapshot is
        // being committed outside the tree.
        FILE_SHARE_READ.0
    } else {
        FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0
    };
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT.0;
    if key.is_directory() {
        flags |= FILE_FLAG_BACKUP_SEMANTICS.0;
    }
    OpenOptions::new()
        .access_mode(access)
        .share_mode(share)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| native_io("CreateFileW(fixed-object)", error))
}

fn observe_binding(
    object: &HeldExactObject,
    owner: &OwnedSid,
) -> Result<FixedObjectBinding, ExactDisposeError> {
    let file = object.file()?;
    verify_object_shape(file, object.key, owner)?;
    let basic = basic_info(file)?;
    let standard = standard_info(file)?;
    let ea = stabilized_extended_attributes(file, object.key.is_directory()).map_err(|error| {
        ExactDisposeError::Rejected(format!(
            "fixed {:?} extended attributes were rejected: {error}",
            object.key
        ))
    })?;
    if object.key.is_directory() {
        Ok(FixedObjectBinding {
            key: object.key,
            id: stable_id(file)?,
            attributes: basic.dwFileAttributes,
            link_count: standard.NumberOfLinks,
            size_bytes: None,
            sha256: None,
            ea,
        })
    } else {
        let size = file_size(file)?;
        if size > object.key.size_limit()
            || (object.key == FixedWsbObject::RunLock && size != 0)
            || (object.key == FixedWsbObject::GuestAgent && size == 0)
        {
            return Err(ExactDisposeError::Rejected(format!(
                "fixed {:?} size exceeds its policy",
                object.key
            )));
        }
        Ok(FixedObjectBinding {
            key: object.key,
            id: stable_id(file)?,
            attributes: basic.dwFileAttributes,
            link_count: standard.NumberOfLinks,
            size_bytes: Some(size),
            sha256: Some(hash_file(file, size)?),
            ea,
        })
    }
}

pub(crate) fn stabilized_extended_attributes(
    file: &File,
    directory: bool,
) -> Result<ExtendedAttributeBinding, ExactDisposeError> {
    let mut previous = None::<ExtendedAttributeBinding>;
    let mut matching_observations = 0usize;
    for attempt in 0..EA_STABILIZATION_ATTEMPTS {
        match query_extended_attributes(file, directory) {
            Ok(observed) => {
                matching_observations = if previous.as_ref().is_some_and(|prior| prior == &observed)
                {
                    matching_observations + 1
                } else {
                    1
                };
                if (!observed.entries.is_empty()
                    && matching_observations >= EA_NONEMPTY_STABLE_OBSERVATIONS)
                    || (observed.entries.is_empty() && attempt + 1 == EA_STABILIZATION_ATTEMPTS)
                {
                    return Ok(observed);
                }
                previous = Some(observed);
            }
            Err(ExactDisposeError::TransientSmartLockerEa) => {
                previous = None;
                matching_observations = 0;
            }
            Err(error) => return Err(error),
        }
        if attempt + 1 < EA_STABILIZATION_ATTEMPTS {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Err(ExactDisposeError::Rejected(
        "SmartLocker EA metadata did not stabilize to none or the exact kernel pair".into(),
    ))
}

fn verify_expected(
    object: &HeldExactObject,
    expected: &FixedObjectBinding,
    owner: &OwnedSid,
    root: &Path,
    run_id: &str,
) -> Result<(), ExactDisposeError> {
    let file = object.file()?;
    verify_object_shape(file, object.key, owner)?;
    if stable_id(file)? != expected.id {
        return Err(ExactDisposeError::Rejected(format!(
            "fixed {:?} identity changed",
            object.key
        )));
    }
    let basic = basic_info(file)?;
    let standard = standard_info(file)?;
    if basic.dwFileAttributes != expected.attributes
        || standard.NumberOfLinks != expected.link_count
    {
        return Err(ExactDisposeError::Rejected(format!(
            "fixed {:?} attributes or link count changed",
            object.key
        )));
    }
    if query_extended_attributes(file, object.key.is_directory()).map_err(|error| {
        ExactDisposeError::Rejected(format!(
            "fixed {:?} extended attributes were rejected: {error}",
            object.key
        ))
    })? != expected.ea
    {
        return Err(ExactDisposeError::Rejected(format!(
            "fixed {:?} extended attributes changed",
            object.key
        )));
    }
    let expected_path = path_for(root, run_id, object.key);
    if !same_path(final_path(file).map_err(workspace_error)?, expected_path) {
        return Err(ExactDisposeError::Rejected(format!(
            "fixed {:?} final path changed",
            object.key
        )));
    }
    if object.key.is_directory() {
        if expected.size_bytes.is_some() || expected.sha256.is_some() {
            return Err(ExactDisposeError::Contract(
                "directory binding contains file metadata".into(),
            ));
        }
    } else {
        let size = file_size(file)?;
        if expected.size_bytes != Some(size) || expected.sha256 != Some(hash_file(file, size)?) {
            return Err(ExactDisposeError::Rejected(format!(
                "fixed {:?} content changed",
                object.key
            )));
        }
    }
    Ok(())
}

fn verify_object_shape(
    file: &File,
    key: FixedWsbObject,
    owner: &OwnedSid,
) -> Result<(), ExactDisposeError> {
    let basic = basic_info(file)?;
    let is_directory = basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    if is_directory != key.is_directory() || basic.dwFileAttributes & FORBIDDEN_ATTRIBUTES != 0 {
        return Err(ExactDisposeError::Rejected(format!(
            "fixed {:?} type or attributes are not allowed",
            key
        )));
    }
    let standard = standard_info(file)?;
    if standard.Directory != key.is_directory() || standard.DeletePending {
        return Err(ExactDisposeError::Rejected(format!(
            "fixed {:?} is delete-pending or has the wrong type",
            key
        )));
    }
    if !key.is_directory() && standard.NumberOfLinks != 1 {
        return Err(ExactDisposeError::Rejected(format!(
            "fixed {:?} has more than one hard link",
            key
        )));
    }
    verify_owner_system_acl(file, owner, key.require_protected_acl(), key.is_directory())
        .map_err(workspace_error)?;
    if key.is_directory() {
        reject_case_sensitive_directory(file)?;
    }
    verify_stream_policy(file, key.is_directory(), standard.EndOfFile as u64)
}

fn verify_allowlists(objects: &[HeldExactObject], run_id: &str) -> Result<(), ExactDisposeError> {
    for key in ACQUIRE_ORDER.into_iter().filter(|key| key.is_directory()) {
        verify_directory_graph(objects, key, run_id)?;
    }
    Ok(())
}

fn verify_directory_graph(
    objects: &[HeldExactObject],
    directory: FixedWsbObject,
    run_id: &str,
) -> Result<(), ExactDisposeError> {
    let held_directory = objects
        .iter()
        .find(|object| object.key == directory)
        .ok_or_else(|| ExactDisposeError::Contract("fixed directory is missing".into()))?;
    if held_directory.file.is_none() {
        return Ok(());
    }
    let entries = directory_entries(held_directory.file()?)?;
    let expected: Vec<_> = ACQUIRE_ORDER
        .into_iter()
        .filter(|key| key.parent() == Some(directory))
        .filter_map(|key| {
            objects
                .iter()
                .find(|object| object.key == key && object.file.is_some())
                .map(|object| (key, object))
        })
        .collect();
    if entries.len() != expected.len() {
        return Err(ExactDisposeError::Rejected(format!(
            "fixed {directory:?} dynamic child count changed"
        )));
    }
    for (key, object) in expected {
        let expected_name = object_leaf(key, run_id)?;
        let entry = entries
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(&expected_name))
            .ok_or_else(|| {
                ExactDisposeError::Rejected(format!("fixed {directory:?} is missing child {key:?}"))
            })?;
        let file = object.file()?;
        let id = stable_id(file)?;
        let basic = basic_info(file)?;
        if entry.file_id != id.file_id
            || entry.attributes != basic.dwFileAttributes
            || (entry.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != key.is_directory()
            || (entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 && entry.reparse_tag == 0)
        {
            return Err(ExactDisposeError::Rejected(format!(
                "fixed {key:?} directory-entry identity, type, attributes, or EA changed"
            )));
        }
    }
    Ok(())
}

fn object_leaf(key: FixedWsbObject, run_id: &str) -> Result<String, ExactDisposeError> {
    file_name_string(&path_for(Path::new("C:\\aiw-fixed-root"), run_id, key))
}

fn path_for(root: &Path, run_id: &str, key: FixedWsbObject) -> PathBuf {
    match key {
        FixedWsbObject::WorkspaceRoot => root.to_owned(),
        FixedWsbObject::ToolsDirectory => root.join("tools"),
        FixedWsbObject::OutputDirectory => root.join("output"),
        FixedWsbObject::RunsDirectory => root.join("runs"),
        FixedWsbObject::LocksDirectory => root.join("runs").join(".locks"),
        FixedWsbObject::RunDirectory => root.join("runs").join(run_id),
        FixedWsbObject::JournalHeadsDirectory => {
            root.join("runs").join(run_id).join("journal-heads")
        }
        FixedWsbObject::GuestAgent => root.join("tools").join("aiw-guest-agent.exe"),
        FixedWsbObject::PreparedPlan => root.join("plan.json"),
        FixedWsbObject::WindowsSandboxPlan => root.join("wsb-plan.json"),
        FixedWsbObject::PreparationReceipt => root.join("preparation.json"),
        FixedWsbObject::RunLock => root
            .join("runs")
            .join(".locks")
            .join(format!("{run_id}.lock")),
        FixedWsbObject::AuthoritativePlan => root.join("runs").join(run_id).join("plan.json"),
        FixedWsbObject::PlanningImportReceipt => root
            .join("runs")
            .join(run_id)
            .join("wsb-planning-import.json"),
        FixedWsbObject::EventsJournal => root.join("runs").join(run_id).join("events.jsonl"),
        FixedWsbObject::RevocationRecord => {
            root.join("runs").join(run_id).join("wsb-revocation.json")
        }
        FixedWsbObject::JournalHead1 => root
            .join("runs")
            .join(run_id)
            .join("journal-heads")
            .join("00000000000000000001.json"),
        FixedWsbObject::JournalHead2 => root
            .join("runs")
            .join(run_id)
            .join("journal-heads")
            .join("00000000000000000002.json"),
        FixedWsbObject::JournalHead3 => root
            .join("runs")
            .join(run_id)
            .join("journal-heads")
            .join("00000000000000000003.json"),
    }
}

fn validate_inputs(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
) -> Result<(), ExactDisposeError> {
    workspace
        .validate()
        .map_err(|error| ExactDisposeError::Contract(error.to_string()))?;
    validate_run_id(run_id)?;
    let root = PathBuf::from(&workspace.root.final_path);
    if !root.is_absolute()
        || root
            .parent()
            .is_none_or(|parent| !same_path(parent, PathBuf::from(&workspace.parent.final_path)))
        || !same_path(root.join("tools"), &workspace.tools.final_path)
        || !same_path(root.join("output"), &workspace.output.final_path)
    {
        return Err(ExactDisposeError::Contract(
            "workspace binding paths do not describe the fixed tree".into(),
        ));
    }
    Ok(())
}

fn validate_inventory(inventory: &FixedWsbTreeInventory) -> Result<(), ExactDisposeError> {
    validate_inputs(&inventory.workspace, &inventory.run_id)?;
    if !same_path(
        &inventory.original_root,
        &inventory.workspace.root.final_path,
    ) || inventory.objects.len() != ACQUIRE_ORDER.len()
        || inventory
            .objects
            .iter()
            .zip(ACQUIRE_ORDER)
            .any(|(binding, key)| binding.key != key)
    {
        return Err(ExactDisposeError::Contract(
            "fixed inventory shape is invalid".into(),
        ));
    }
    validate_leaf(&inventory.tombstone_leaf)
}

fn validate_run_id(value: &str) -> Result<(), ExactDisposeError> {
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
        || value.ends_with('.')
        || reserved
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(ExactDisposeError::Contract("run ID is unsafe".into()));
    }
    Ok(())
}

fn validate_leaf(value: &str) -> Result<(), ExactDisposeError> {
    if value.is_empty()
        || value.len() > 240
        || value.ends_with('.')
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(ExactDisposeError::Contract(
            "tombstone leaf is unsafe".into(),
        ));
    }
    Ok(())
}

fn validate_checkpoint_tombstone_leaf(value: &str) -> Result<(), ExactDisposeError> {
    validate_leaf(value)?;
    if !value
        .strip_prefix(".aiw-discarded-v1-")
        .is_some_and(|suffix| {
            suffix.len() == 64
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    {
        return Err(ExactDisposeError::Contract(
            "tombstone leaf is not bound to the discard-intent convention".into(),
        ));
    }
    Ok(())
}

pub(crate) fn basic_info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, ExactDisposeError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) }
        .map_err(|error| native("GetFileInformationByHandle", error))?;
    Ok(info)
}

pub(crate) fn stable_id(file: &File) -> Result<StableFileId, ExactDisposeError> {
    let mut info = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            raw_handle(file),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(|error| native("GetFileInformationByHandleEx(FileIdInfo)", error))?;
    Ok(StableFileId {
        volume_serial_number: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

pub(crate) fn standard_info(file: &File) -> Result<FILE_STANDARD_INFO, ExactDisposeError> {
    let mut info = FILE_STANDARD_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            raw_handle(file),
            FileStandardInfo,
            (&mut info as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    }
    .map_err(|error| native("GetFileInformationByHandleEx(FileStandardInfo)", error))?;
    Ok(info)
}

pub(crate) fn file_size(file: &File) -> Result<u64, ExactDisposeError> {
    let size = standard_info(file)?.EndOfFile;
    u64::try_from(size).map_err(|_| ExactDisposeError::Rejected("negative file size".into()))
}

pub(crate) fn hash_file(file: &File, expected_size: u64) -> Result<[u8; 32], ExactDisposeError> {
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while offset < expected_size {
        let remaining = usize::try_from((expected_size - offset).min(buffer.len() as u64))
            .expect("bounded by buffer");
        let read = file
            .seek_read(&mut buffer[..remaining], offset)
            .map_err(|error| native_io("ReadFile(positional)", error))?;
        if read == 0 {
            return Err(ExactDisposeError::Rejected(
                "file ended before its held size".into(),
            ));
        }
        hasher.update(&buffer[..read]);
        offset += read as u64;
    }
    let mut trailing = [0_u8; 1];
    if file
        .seek_read(&mut trailing, expected_size)
        .map_err(|error| native_io("ReadFile(trailing)", error))?
        != 0
    {
        return Err(ExactDisposeError::Rejected(
            "file grew while it was hashed".into(),
        ));
    }
    Ok(hasher.finalize().into())
}

pub(crate) fn query_extended_attributes(
    file: &File,
    directory: bool,
) -> Result<ExtendedAttributeBinding, ExactDisposeError> {
    query_extended_attributes_with_policy(file, directory, true)
}

pub(crate) fn query_extended_attributes_for_import(
    file: &File,
    directory: bool,
) -> Result<ExtendedAttributeBinding, ExactDisposeError> {
    query_extended_attributes_with_policy(file, directory, false)
}

fn query_extended_attributes_with_policy(
    file: &File,
    directory: bool,
    reject_transient_origin_claim: bool,
) -> Result<ExtendedAttributeBinding, ExactDisposeError> {
    // u64 storage guarantees stronger alignment than FILE_FULL_EA_INFORMATION
    // requires. Zeroing also makes any tolerated final-record padding
    // deterministic and prevents stale process memory from entering evidence.
    let mut buffer = vec![0_u64; EA_BUFFER_BYTES / size_of::<u64>()];
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtQueryEaFile(
            raw_handle(file),
            &mut io_status,
            buffer.as_mut_ptr().cast(),
            EA_BUFFER_BYTES as u32,
            false,
            None,
            0,
            None,
            true,
        )
    };
    if status == STATUS_NO_EAS_ON_FILE {
        return empty_ea_binding();
    }
    if status.0 != 0 {
        return Err(ntstatus_io("NtQueryEaFile", status));
    }
    let completion_status = unsafe { io_status.Anonymous.Status };
    if completion_status.0 != 0 {
        return Err(ntstatus_io("NtQueryEaFile(completion)", completion_status));
    }
    let queried_bytes = u32::try_from(io_status.Information)
        .map_err(|_| ExactDisposeError::Rejected("EA result length overflowed u32".into()))?;
    if queried_bytes as usize > EA_BUFFER_BYTES {
        return Err(ExactDisposeError::Rejected(
            "EA result length exceeded its fixed buffer".into(),
        ));
    }
    let bytes = &as_bytes(&buffer)[..queried_bytes as usize];
    if bytes.is_empty() {
        return empty_ea_binding();
    }
    parse_extended_attributes(
        bytes,
        queried_bytes,
        directory,
        reject_transient_origin_claim,
    )
}

fn empty_ea_binding() -> Result<ExtendedAttributeBinding, ExactDisposeError> {
    Ok(ExtendedAttributeBinding {
        queried_bytes: 0,
        entries: Vec::new(),
        canonical_sha256: Sha256::digest([]).into(),
    })
}

fn parse_extended_attributes(
    bytes: &[u8],
    queried_bytes: u32,
    directory: bool,
    reject_transient_origin_claim: bool,
) -> Result<ExtendedAttributeBinding, ExactDisposeError> {
    if bytes.len() != queried_bytes as usize || bytes.len() > EA_BUFFER_BYTES {
        return Err(ExactDisposeError::Rejected(
            "EA parser input length differs from the kernel result".into(),
        ));
    }
    let header = offset_of!(FILE_FULL_EA_INFORMATION, EaName);
    let mut entries = Vec::new();
    let mut offset = 0_usize;
    loop {
        if offset % 4 != 0
            || offset
                .checked_add(size_of::<FILE_FULL_EA_INFORMATION>())
                .is_none_or(|end| end > bytes.len())
        {
            return Err(ExactDisposeError::Rejected(
                "EA information has an invalid header offset".into(),
            ));
        }
        let info: FILE_FULL_EA_INFORMATION = read_unaligned_struct(bytes, offset, "EA")?;
        let name_len = info.EaNameLength as usize;
        let value_len = info.EaValueLength as usize;
        if name_len == 0 {
            return Err(ExactDisposeError::Rejected("EA name is empty".into()));
        }
        let name_start = offset + header;
        let nul = name_start
            .checked_add(name_len)
            .ok_or_else(|| ExactDisposeError::Rejected("EA name length overflowed".into()))?;
        let value_start = nul
            .checked_add(1)
            .ok_or_else(|| ExactDisposeError::Rejected("EA value offset overflowed".into()))?;
        let value_end = value_start
            .checked_add(value_len)
            .ok_or_else(|| ExactDisposeError::Rejected("EA value length overflowed".into()))?;
        if value_end > bytes.len() || bytes[nul] != 0 {
            return Err(ExactDisposeError::Rejected(
                "EA name or value is truncated or lacks its NUL terminator".into(),
            ));
        }
        let name_bytes = &bytes[name_start..nul];
        if !name_bytes.is_ascii() {
            return Err(ExactDisposeError::Rejected("EA name is not ASCII".into()));
        }
        let name = std::str::from_utf8(name_bytes)
            .expect("ASCII was checked")
            .to_owned();
        entries.push(ExtendedAttributeEntryBinding {
            name,
            flags: info.Flags,
            value_length: info.EaValueLength,
            value_sha256: Sha256::digest(&bytes[value_start..value_end]).into(),
        });
        if entries.len() > MAX_EA_ENTRIES {
            return Err(ExactDisposeError::Rejected(
                "fixed object contains too many EAs".into(),
            ));
        }

        let next = info.NextEntryOffset as usize;
        if next == 0 {
            if bytes[value_end..].iter().any(|byte| *byte != 0) {
                return Err(ExactDisposeError::Rejected(
                    "EA result has nonzero trailing bytes".into(),
                ));
            }
            break;
        }
        let minimum_next = value_end
            .checked_sub(offset)
            .and_then(|length| length.checked_add(3))
            .map(|length| length & !3)
            .ok_or_else(|| ExactDisposeError::Rejected("EA next offset overflowed".into()))?;
        if next % 4 != 0
            || next < minimum_next
            || offset
                .checked_add(next)
                .is_none_or(|next_offset| next_offset >= bytes.len())
        {
            return Err(ExactDisposeError::Rejected(
                "EA information next offset is invalid".into(),
            ));
        }
        if bytes[value_end..offset + next]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ExactDisposeError::Rejected(
                "EA inter-record padding is nonzero".into(),
            ));
        }
        offset += next;
    }

    entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let mut folded_names = BTreeSet::new();
    for entry in &entries {
        if !folded_names.insert(entry.name.to_ascii_lowercase()) {
            return Err(ExactDisposeError::Rejected(
                "EA names are duplicated or differ only by case".into(),
            ));
        }
    }
    let file_origin_claim =
        !directory && entries.len() == 1 && entries[0].name == "$KERNEL.SMARTLOCKER.ORIGINCLAIM";
    if reject_transient_origin_claim && file_origin_claim {
        return Err(ExactDisposeError::TransientSmartLockerEa);
    }
    let stable_directory_origin_claim =
        directory && entries.len() == 1 && entries[0].name == "$KERNEL.SMARTLOCKER.ORIGINCLAIM";
    let exact_kernel_pair = !directory
        && entries.len() == ALLOWED_KERNEL_EAS.len()
        && entries
            .iter()
            .zip(ALLOWED_KERNEL_EAS)
            .all(|(entry, allowed)| entry.name == allowed);
    let exact_kernel_triple = !directory
        && entries.len() == ALLOWED_KERNEL_EAS_WITH_FILE_HASH.len()
        && entries
            .iter()
            .zip(ALLOWED_KERNEL_EAS_WITH_FILE_HASH)
            .all(|(entry, allowed)| entry.name == allowed);
    if !entries.is_empty()
        && !stable_directory_origin_claim
        && !(file_origin_claim && !reject_transient_origin_claim)
        && !exact_kernel_pair
        && !exact_kernel_triple
    {
        let names: Vec<_> = entries.iter().map(|entry| entry.name.as_str()).collect();
        return Err(ExactDisposeError::Rejected(format!(
            "fixed object EAs are outside the exact SmartLocker kernel sets: {names:?}"
        )));
    }

    let mut canonical = Vec::new();
    for entry in &entries {
        let name = entry.name.as_bytes();
        canonical.extend_from_slice(
            &u16::try_from(name.len())
                .expect("EA names are bounded by u8")
                .to_le_bytes(),
        );
        canonical.extend_from_slice(name);
        canonical.push(entry.flags);
        canonical.extend_from_slice(&entry.value_length.to_le_bytes());
        canonical.extend_from_slice(&entry.value_sha256);
    }
    Ok(ExtendedAttributeBinding {
        queried_bytes,
        entries,
        canonical_sha256: Sha256::digest(canonical).into(),
    })
}

fn ntstatus_io(
    operation: &'static str,
    status: windows::Win32::Foundation::NTSTATUS,
) -> ExactDisposeError {
    let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
    native_io(operation, std::io::Error::from_raw_os_error(code as i32))
}

fn read_unaligned_struct<T: Copy>(
    bytes: &[u8],
    offset: usize,
    kind: &str,
) -> Result<T, ExactDisposeError> {
    if offset
        .checked_add(size_of::<T>())
        .is_none_or(|end| end > bytes.len())
    {
        return Err(ExactDisposeError::Rejected(format!(
            "{kind} information is shorter than its fixed structure"
        )));
    }
    // SAFETY: the complete fixed-size T lies within `bytes`; read_unaligned
    // deliberately makes no alignment assumption about caller-controlled
    // safe byte slices.
    Ok(unsafe { bytes.as_ptr().add(offset).cast::<T>().read_unaligned() })
}

fn decode_utf16_bytes(bytes: &[u8], kind: &str) -> Result<String, ExactDisposeError> {
    if bytes.len() % size_of::<u16>() != 0 {
        return Err(ExactDisposeError::Rejected(format!(
            "{kind} has an odd UTF-16 byte length"
        )));
    }
    let units: Vec<_> = bytes
        .chunks_exact(size_of::<u16>())
        .map(|chunk| u16::from_ne_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&units)
        .map_err(|_| ExactDisposeError::Rejected(format!("{kind} is not UTF-16")))
}

fn require_evidence_id(
    actual: &StableFileId,
    expected: &aiw_probe::WindowsFileIdentity,
    name: &str,
) -> Result<(), ExactDisposeError> {
    let volume = u64::from_str_radix(&expected.volume_serial_number, 16)
        .map_err(|_| ExactDisposeError::Contract(format!("{name} volume ID is invalid")))?;
    let bytes = hex::decode(&expected.file_id)
        .map_err(|_| ExactDisposeError::Contract(format!("{name} file ID is invalid")))?;
    let file_id: [u8; 16] = bytes
        .try_into()
        .map_err(|_| ExactDisposeError::Contract(format!("{name} file ID length is invalid")))?;
    if actual.volume_serial_number != volume || actual.file_id != file_id {
        return Err(ExactDisposeError::Rejected(format!(
            "{name} identity differs from workspace evidence"
        )));
    }
    Ok(())
}

pub(crate) fn reject_case_sensitive_directory(file: &File) -> Result<(), ExactDisposeError> {
    let mut info = FILE_CASE_SENSITIVE_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            raw_handle(file),
            FileCaseSensitiveInfo,
            (&mut info as *mut FILE_CASE_SENSITIVE_INFO).cast(),
            size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    }
    .map_err(|error| native("GetFileInformationByHandleEx(FileCaseSensitiveInfo)", error))?;
    if info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
        return Err(ExactDisposeError::Rejected(
            "case-sensitive directory namespaces are unsupported".into(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_stream_policy(
    file: &File,
    directory: bool,
    expected_size: u64,
) -> Result<(), ExactDisposeError> {
    let mut buffer = vec![0_u64; STREAM_BUFFER_BYTES / size_of::<u64>()];
    let result = unsafe {
        GetFileInformationByHandleEx(
            raw_handle(file),
            FileStreamInfo,
            buffer.as_mut_ptr().cast(),
            STREAM_BUFFER_BYTES as u32,
        )
    };
    if let Err(error) = result {
        if WIN32_ERROR::from_error(&error) == Some(ERROR_HANDLE_EOF) && directory {
            return Ok(());
        }
        return Err(native(
            "GetFileInformationByHandleEx(FileStreamInfo)",
            error,
        ));
    }
    let streams = parse_streams(as_bytes(&buffer))?;
    if directory {
        if streams.is_empty() {
            Ok(())
        } else {
            Err(ExactDisposeError::Rejected(
                "directory has an alternate data stream".into(),
            ))
        }
    } else if streams.len() == 1 && streams[0].0 == "::$DATA" && streams[0].1 == expected_size {
        Ok(())
    } else {
        Err(ExactDisposeError::Rejected(
            "file stream policy requires only the unnamed data stream".into(),
        ))
    }
}

fn parse_streams(bytes: &[u8]) -> Result<Vec<(String, u64)>, ExactDisposeError> {
    let header = offset_of!(FILE_STREAM_INFO, StreamName);
    let mut streams = Vec::new();
    let mut offset = 0_usize;
    loop {
        if offset % 8 != 0
            || offset
                .checked_add(size_of::<FILE_STREAM_INFO>())
                .is_none_or(|end| end > bytes.len())
        {
            return Err(ExactDisposeError::Rejected(
                "stream information has an invalid header offset".into(),
            ));
        }
        let info: FILE_STREAM_INFO = read_unaligned_struct(bytes, offset, "stream")?;
        let name_len = info.StreamNameLength as usize;
        if name_len % 2 != 0
            || offset
                .checked_add(header)
                .and_then(|start| start.checked_add(name_len))
                .is_none_or(|end| end > bytes.len())
            || info.StreamSize < 0
        {
            return Err(ExactDisposeError::Rejected(
                "stream information is malformed".into(),
            ));
        }
        let name_start = offset + header;
        let name = decode_utf16_bytes(&bytes[name_start..name_start + name_len], "stream name")?;
        streams.push((name, info.StreamSize as u64));
        if streams.len() > MAX_STREAM_ENTRIES {
            return Err(ExactDisposeError::Rejected("too many streams".into()));
        }
        let next = info.NextEntryOffset as usize;
        if next == 0 {
            break;
        }
        if next % 8 != 0 || next < header + name_len {
            return Err(ExactDisposeError::Rejected(
                "stream information next offset is invalid".into(),
            ));
        }
        offset = offset
            .checked_add(next)
            .ok_or_else(|| ExactDisposeError::Rejected("stream offset overflow".into()))?;
    }
    Ok(streams)
}

pub(crate) fn directory_entries(file: &File) -> Result<Vec<DirectoryEntry>, ExactDisposeError> {
    let entries = source_directory_entries(file)?;
    reject_unsafe_directory_entries(&entries)?;
    Ok(entries)
}

pub(crate) fn source_directory_entries(
    file: &File,
) -> Result<Vec<DirectoryEntry>, ExactDisposeError> {
    let mut entries = extended_directory_entries(file)?;
    let aliases = directory_alias_entries(file)?;
    let entry_names = normalized_names(entries.iter().map(|entry| entry.name.clone()).collect())?;
    let alias_names = normalized_names(aliases.iter().map(|entry| entry.name.clone()).collect())?;
    let short_names: Vec<_> = aliases
        .iter()
        .filter_map(|entry| entry.short_name.as_deref())
        .collect();
    if entry_names != alias_names || !short_names.is_empty() {
        return Err(ExactDisposeError::Rejected(format!(
            "directory enumeration disagrees or exposes short-name aliases {short_names:?}: extended={entry_names:?}, aliases={alias_names:?}"
        )));
    }
    for entry in &mut entries {
        entry.ea_size = aliases
            .iter()
            .find(|alias| alias.name.eq_ignore_ascii_case(&entry.name))
            .expect("normalized name sets matched")
            .ea_size;
    }
    Ok(entries)
}

pub(crate) fn exact_directory_entry(
    file: &File,
    expected_name: &str,
) -> Result<DirectoryEntry, ExactDisposeError> {
    let mut entries = extended_directory_entries(file)?;
    let aliases = directory_alias_entries(file)?;
    let entry_names = normalized_names(entries.iter().map(|entry| entry.name.clone()).collect())?;
    let alias_names = normalized_names(aliases.iter().map(|entry| entry.name.clone()).collect())?;
    if entry_names != alias_names {
        return Err(ExactDisposeError::Rejected(
            "directory enumerations disagree or contain case collisions".into(),
        ));
    }
    let entry = entries
        .iter_mut()
        .find(|entry| entry.name.eq_ignore_ascii_case(expected_name))
        .ok_or_else(|| ExactDisposeError::Rejected("expected directory entry is absent".into()))?;
    let alias = aliases
        .iter()
        .find(|alias| alias.name.eq_ignore_ascii_case(expected_name))
        .expect("normalized name sets matched");
    if entry.name != expected_name || alias.name != expected_name || alias.short_name.is_some() {
        return Err(ExactDisposeError::Rejected(
            "expected directory entry has case drift or a short-name alias".into(),
        ));
    }
    entry.ea_size = alias.ea_size;
    let result = entry.clone();
    reject_unsafe_directory_entries(std::slice::from_ref(&result))?;
    Ok(result)
}

fn extended_directory_entries(file: &File) -> Result<Vec<DirectoryEntry>, ExactDisposeError> {
    let mut entries = Vec::new();
    let mut first = true;
    loop {
        let mut buffer = vec![0_u64; DIRECTORY_BUFFER_BYTES / size_of::<u64>()];
        let class = if first {
            FileIdExtdDirectoryRestartInfo
        } else {
            FileIdExtdDirectoryInfo
        };
        first = false;
        let result = unsafe {
            GetFileInformationByHandleEx(
                raw_handle(file),
                class,
                buffer.as_mut_ptr().cast(),
                DIRECTORY_BUFFER_BYTES as u32,
            )
        };
        if let Err(error) = result {
            if WIN32_ERROR::from_error(&error) == Some(ERROR_NO_MORE_FILES) {
                break;
            }
            return Err(native(
                "GetFileInformationByHandleEx(FileIdExtdDirectoryInfo)",
                error,
            ));
        }
        parse_extended_directory_buffer(as_bytes(&buffer), &mut entries)?;
        if entries.len() > MAX_DIRECTORY_ENTRIES {
            return Err(ExactDisposeError::Rejected(
                "directory contains too many entries".into(),
            ));
        }
    }

    Ok(entries)
}

fn reject_unsafe_directory_entries(entries: &[DirectoryEntry]) -> Result<(), ExactDisposeError> {
    let unsafe_entries: Vec<_> = entries
        .iter()
        .filter(|entry| entry.attributes & FORBIDDEN_ATTRIBUTES != 0)
        .map(|entry| {
            format!(
                "{}:attrs={:#x},ea={},tag={:#x}",
                entry.name, entry.attributes, entry.ea_size, entry.reparse_tag
            )
        })
        .collect();
    if !unsafe_entries.is_empty() {
        return Err(ExactDisposeError::Rejected(format!(
            "directory entry has forbidden attributes: {unsafe_entries:?}"
        )));
    }
    Ok(())
}

fn parse_extended_directory_buffer(
    bytes: &[u8],
    entries: &mut Vec<DirectoryEntry>,
) -> Result<(), ExactDisposeError> {
    let header = offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
    let mut offset = 0_usize;
    loop {
        if offset % 8 != 0
            || offset
                .checked_add(size_of::<FILE_ID_EXTD_DIR_INFO>())
                .is_none_or(|end| end > bytes.len())
        {
            return Err(ExactDisposeError::Rejected(
                "extended directory information has an invalid header offset".into(),
            ));
        }
        let info: FILE_ID_EXTD_DIR_INFO =
            read_unaligned_struct(bytes, offset, "extended directory")?;
        let name_len = info.FileNameLength as usize;
        if name_len % 2 != 0
            || offset
                .checked_add(header)
                .and_then(|start| start.checked_add(name_len))
                .is_none_or(|end| end > bytes.len())
        {
            return Err(ExactDisposeError::Rejected(
                "extended directory information is malformed".into(),
            ));
        }
        let name_start = offset + header;
        let name = decode_utf16_bytes(
            &bytes[name_start..name_start + name_len],
            "extended directory name",
        )?;
        if name != "." && name != ".." {
            entries.push(DirectoryEntry {
                name,
                file_id: info.FileId.Identifier,
                attributes: info.FileAttributes,
                ea_size: info.EaSize,
                reparse_tag: info.ReparsePointTag,
            });
        }
        let next = info.NextEntryOffset as usize;
        if next == 0 {
            break;
        }
        if next % 8 != 0 || next < header + name_len {
            return Err(ExactDisposeError::Rejected(
                "extended directory information next offset is invalid".into(),
            ));
        }
        offset = offset
            .checked_add(next)
            .ok_or_else(|| ExactDisposeError::Rejected("directory offset overflow".into()))?;
    }
    Ok(())
}

fn directory_alias_entries(file: &File) -> Result<Vec<DirectoryAliasEntry>, ExactDisposeError> {
    let mut entries = Vec::new();
    let mut first = true;
    loop {
        let mut buffer = vec![0_u64; DIRECTORY_BUFFER_BYTES / size_of::<u64>()];
        let class = if first {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        first = false;
        let result = unsafe {
            GetFileInformationByHandleEx(
                raw_handle(file),
                class,
                buffer.as_mut_ptr().cast(),
                DIRECTORY_BUFFER_BYTES as u32,
            )
        };
        if let Err(error) = result {
            if WIN32_ERROR::from_error(&error) == Some(ERROR_NO_MORE_FILES) {
                break;
            }
            return Err(native(
                "GetFileInformationByHandleEx(FileIdBothDirectoryInfo)",
                error,
            ));
        }
        parse_alias_directory_buffer(as_bytes(&buffer), &mut entries)?;
        if entries.len() > MAX_DIRECTORY_ENTRIES {
            return Err(ExactDisposeError::Rejected(
                "directory contains too many entries".into(),
            ));
        }
    }
    Ok(entries)
}

pub(crate) fn directory_namespace_names(file: &File) -> Result<Vec<String>, ExactDisposeError> {
    let mut names = Vec::new();
    for entry in directory_alias_entries(file)? {
        names.push(entry.name);
        if let Some(short_name) = entry.short_name {
            names.push(short_name);
        }
    }
    Ok(names)
}

fn parse_alias_directory_buffer(
    bytes: &[u8],
    entries: &mut Vec<DirectoryAliasEntry>,
) -> Result<(), ExactDisposeError> {
    let header = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
    let mut offset = 0_usize;
    loop {
        if offset % 8 != 0
            || offset
                .checked_add(size_of::<FILE_ID_BOTH_DIR_INFO>())
                .is_none_or(|end| end > bytes.len())
        {
            return Err(ExactDisposeError::Rejected(
                "directory information has an invalid header offset".into(),
            ));
        }
        let info: FILE_ID_BOTH_DIR_INFO = read_unaligned_struct(bytes, offset, "alias directory")?;
        let name_len = info.FileNameLength as usize;
        let short_len = usize::try_from(info.ShortNameLength).map_err(|_| {
            ExactDisposeError::Rejected("directory short-name length is negative".into())
        })?;
        if name_len % 2 != 0
            || short_len > size_of_val(&info.ShortName)
            || short_len % 2 != 0
            || offset
                .checked_add(header)
                .and_then(|start| start.checked_add(name_len))
                .is_none_or(|end| end > bytes.len())
        {
            return Err(ExactDisposeError::Rejected(
                "directory information is malformed".into(),
            ));
        }
        let name_start = offset + header;
        let name = decode_utf16_bytes(
            &bytes[name_start..name_start + name_len],
            "alias directory name",
        )?;
        if name != "." && name != ".." {
            let short_name = if short_len == 0 {
                None
            } else {
                Some(
                    String::from_utf16(&info.ShortName[..short_len / 2]).map_err(|_| {
                        ExactDisposeError::Rejected("directory short name is not UTF-16".into())
                    })?,
                )
            };
            entries.push(DirectoryAliasEntry {
                name,
                short_name,
                ea_size: info.EaSize,
            });
        }
        let next = info.NextEntryOffset as usize;
        if next == 0 {
            break;
        }
        if next % 8 != 0 || next < header + name_len {
            return Err(ExactDisposeError::Rejected(
                "directory information next offset is invalid".into(),
            ));
        }
        offset = offset
            .checked_add(next)
            .ok_or_else(|| ExactDisposeError::Rejected("directory offset overflow".into()))?;
    }
    Ok(())
}

fn normalized_names(values: Vec<String>) -> Result<Vec<String>, ExactDisposeError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !value.is_ascii() || value.contains(['\\', '/', ':', '\0']) {
            return Err(ExactDisposeError::Rejected(
                "directory entry name is outside the fixed ASCII namespace".into(),
            ));
        }
        let folded = value.to_ascii_lowercase();
        if !seen.insert(folded) {
            return Err(ExactDisposeError::Rejected(
                "directory contains case-colliding names".into(),
            ));
        }
    }
    Ok(seen.into_iter().collect())
}

pub(crate) fn contains_name(names: &[String], expected: &str) -> bool {
    names.iter().any(|name| name.eq_ignore_ascii_case(expected))
}

fn path_identity_if_present(path: &Path) -> Result<Option<StableFileId>, ExactDisposeError> {
    let file = match OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(native_io("CreateFileW(optional-name)", error)),
    };
    Ok(Some(stable_id(&file)?))
}

pub(crate) fn rename_relative(
    root: &File,
    parent: &File,
    leaf: &OsStr,
) -> Result<(), ExactDisposeError> {
    let mut buffer = build_relative_rename_info(parent, leaf)?;
    let info_length = buffer.information_length;
    let info = buffer.storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtSetInformationFile(
            raw_handle(root),
            &mut io_status,
            info.cast(),
            info_length,
            FileRenameInformation,
        )
    };
    let completion_status = unsafe { io_status.Anonymous.Status };
    if status.0 != 0 || completion_status.0 != 0 {
        let failed = if status.0 != 0 {
            status
        } else {
            completion_status
        };
        let code = unsafe { RtlNtStatusToDosErrorNoTeb(failed) };
        return Err(native_io(
            "NtSetInformationFile(FileRenameInformation)",
            std::io::Error::from_raw_os_error(code as i32),
        ));
    }
    Ok(())
}

struct RelativeRenameInfoBuffer {
    storage: Vec<usize>,
    information_length: u32,
}

fn build_relative_rename_info(
    parent: &File,
    leaf: &OsStr,
) -> Result<RelativeRenameInfoBuffer, ExactDisposeError> {
    let leaf = leaf
        .to_str()
        .ok_or_else(|| ExactDisposeError::Contract("tombstone leaf is not Unicode".into()))?;
    validate_leaf(leaf)?;
    let name: Vec<u16> = leaf.encode_utf16().collect();
    if name.is_empty() || name.contains(&0) {
        return Err(ExactDisposeError::Contract(
            "tombstone leaf is not valid UTF-16".into(),
        ));
    }
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| ExactDisposeError::Contract("tombstone length overflow".into()))?;
    let information_length = offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name_bytes)
        .ok_or_else(|| ExactDisposeError::Contract("rename buffer overflow".into()))?;
    let mut storage = vec![0_usize; information_length.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = raw_handle(parent);
        (*info).FileNameLength = u32::try_from(name_bytes)
            .map_err(|_| ExactDisposeError::Contract("tombstone is too long".into()))?;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
    }
    Ok(RelativeRenameInfoBuffer {
        storage,
        information_length: u32::try_from(information_length)
            .map_err(|_| ExactDisposeError::Contract("rename buffer is too large".into()))?,
    })
}

fn mark_delete(file: &File) -> Result<(), ExactDisposeError> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            raw_handle(file),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(|error| native("SetFileInformationByHandle(FileDispositionInfo)", error))
}

fn file_name_string(path: &Path) -> Result<String, ExactDisposeError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| ExactDisposeError::Contract("fixed path has no Unicode leaf".into()))
}

fn as_bytes(words: &[u64]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), size_of_val(words)) }
}

fn native(operation: &'static str, error: windows::core::Error) -> ExactDisposeError {
    ExactDisposeError::Native {
        operation,
        detail: error.to_string(),
    }
}

fn native_io(operation: &'static str, error: std::io::Error) -> ExactDisposeError {
    ExactDisposeError::Native {
        operation,
        detail: error.to_string(),
    }
}

fn workspace_error(error: crate::workspace::WorkspaceError) -> ExactDisposeError {
    ExactDisposeError::Rejected(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use super::*;
    use crate::HeldRunWorkspace;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);
    static CURRENT_DIRECTORY_LOCK: Mutex<()> = Mutex::new(());
    const RUN_ID: &str = "run-one";

    fn tombstone_leaf(workspace: &WorkspaceBindingEvidence) -> String {
        format!(
            ".aiw-discarded-v1-{}",
            hex::encode(Sha256::digest(workspace.root.final_path.as_bytes()))
        )
    }

    struct CurrentDirectoryGuard {
        original: PathBuf,
        _lock: MutexGuard<'static, ()>,
    }

    impl CurrentDirectoryGuard {
        fn enter(path: &Path) -> Self {
            let lock = CURRENT_DIRECTORY_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self {
                original,
                _lock: lock,
            }
        }
    }

    impl Drop for CurrentDirectoryGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.original)
                .expect("test process current directory must be restored");
        }
    }

    struct Fixture {
        parent: PathBuf,
        root: PathBuf,
        tombstone: PathBuf,
        sibling: PathBuf,
        workspace: WorkspaceBindingEvidence,
    }

    impl Fixture {
        fn new() -> Self {
            let parent = std::env::temp_dir().canonicalize().unwrap();
            let leaf = format!(
                "aiw-dispose-test-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            );
            let sibling = parent.join(format!("{leaf}-sibling"));
            let workspace = HeldRunWorkspace::create(&parent, &leaf).unwrap();
            let root = workspace.root_path().to_owned();
            fs::write(&sibling, b"unrelated").unwrap();
            write_file(&root.join("plan.json"), b"prepared-plan");
            write_file(&root.join("wsb-plan.json"), b"wsb-plan");
            write_file(&root.join("preparation.json"), b"preparation");
            write_file(&root.join("tools").join("aiw-guest-agent.exe"), b"agent");
            let run = root.join("runs").join(RUN_ID);
            fs::create_dir_all(run.join("journal-heads")).unwrap();
            fs::create_dir_all(root.join("runs").join(".locks")).unwrap();
            write_file(&root.join("runs").join(".locks").join("run-one.lock"), b"");
            write_file(&run.join("plan.json"), b"authoritative-plan");
            write_file(&run.join("wsb-planning-import.json"), b"planning-import");
            write_file(&run.join("events.jsonl"), b"events\n");
            write_file(&run.join("wsb-revocation.json"), b"revocation");
            for sequence in 1..=3 {
                write_file(
                    &run.join("journal-heads")
                        .join(format!("{sequence:020}.json")),
                    format!("head-{sequence}").as_bytes(),
                );
            }
            let evidence = workspace.evidence().clone();
            drop(workspace);
            for key in ACQUIRE_ORDER.into_iter().skip(1) {
                let path = path_for(&root, RUN_ID, key);
                clear_short_name(&path, key.is_directory());
            }
            let tombstone = parent.join(tombstone_leaf(&evidence));
            Self {
                parent,
                root,
                tombstone,
                sibling,
                workspace: evidence,
            }
        }

        fn inventory(&self) -> FixedWsbTreeInventory {
            observe_fixed_wsb_tree(&self.workspace, RUN_ID, &tombstone_leaf(&self.workspace))
                .unwrap()
        }

        fn cleanup(&self) {
            let _ = fs::remove_dir_all(&self.root);
            let _ = fs::remove_dir_all(&self.tombstone);
            let _ = fs::remove_file(&self.sibling);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.cleanup();
        }
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn clear_short_name(path: &Path, directory: bool) {
        use windows::core::PCWSTR;

        let mut flags = FILE_FLAG_OPEN_REPARSE_POINT.0;
        if directory {
            flags |= FILE_FLAG_BACKUP_SEMANTICS.0;
        }
        let file = OpenOptions::new()
            .access_mode(DELETE.0 | windows::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .custom_flags(flags)
            .open(path)
            .unwrap();
        let empty = [0_u16];
        for attempt in 0..40 {
            match unsafe {
                windows::Win32::Storage::FileSystem::SetFileShortNameW(
                    raw_handle(&file),
                    PCWSTR(empty.as_ptr()),
                )
            } {
                Ok(()) => return,
                Err(_) if attempt < 39 => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("failed to clear fixture short name for {path:?}: {error}"),
            }
        }
    }

    fn competing_delete_open(path: &Path, directory: bool) -> std::io::Result<File> {
        let mut flags = FILE_FLAG_OPEN_REPARSE_POINT.0;
        if directory {
            flags |= FILE_FLAG_BACKUP_SEMANTICS.0;
        }
        OpenOptions::new()
            .access_mode(DELETE.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .custom_flags(flags)
            .open(path)
    }

    #[test]
    fn exact_tree_is_depublished_and_disposed_without_touching_siblings() {
        let fixture = Fixture::new();
        let inventory = fixture.inventory();
        assert_eq!(inventory.objects().len(), 19);
        let tombstone = fixture.parent.join(inventory.tombstone_leaf());
        let mut held =
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).unwrap();
        held.depublish().unwrap();
        let deleted = held.dispose_all().unwrap();
        assert_eq!(deleted.len(), 19);
        assert!(!fixture.root.exists());
        assert!(!tombstone.exists());
        assert_eq!(fs::read(&fixture.sibling).unwrap(), b"unrelated");
    }

    #[test]
    fn portable_inventory_is_deterministic_strict_and_read_only() {
        let fixture = Fixture::new();
        let tombstone = tombstone_leaf(&fixture.workspace);
        let first =
            observe_fixed_wsb_tree_for_checkpoint(&fixture.workspace, RUN_ID, &tombstone).unwrap();
        let second =
            observe_fixed_wsb_tree_for_checkpoint(&fixture.workspace, RUN_ID, &tombstone).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.objects.len(), 19);
        assert!(first.objects.iter().all(|object| {
            object
                .ea
                .entries
                .iter()
                .all(|entry| entry.value_sha256.len() == 64)
        }));
        verify_fixed_wsb_tree_inventory(&first).unwrap();
        assert!(fixture.root.is_dir());
        assert!(!fixture.parent.join(tombstone).exists());

        let mut reordered = first.clone();
        reordered.objects.swap(0, 1);
        assert!(verify_fixed_wsb_tree_inventory(&reordered).is_err());
        let mut legacy = first;
        legacy.tombstone_leaf = ".aiw-wsb-tombstone-run-one-deadbeef".to_owned();
        assert!(verify_fixed_wsb_tree_inventory(&legacy).is_err());
    }

    #[test]
    fn checkpoint_bound_root_classifies_reopens_and_depublishes_exactly_once() {
        let fixture = Fixture::new();
        let tombstone = tombstone_leaf(&fixture.workspace);
        let inventory =
            observe_fixed_wsb_tree_for_checkpoint(&fixture.workspace, RUN_ID, &tombstone).unwrap();

        assert_eq!(
            classify_checkpoint_bound_wsb_root(&inventory).unwrap(),
            WsbRootNamespaceState::Original
        );
        let held =
            reopen_checkpoint_bound_wsb_root(&inventory, WsbRootNamespaceState::Original).unwrap();
        held.revalidate().unwrap();
        let observation = held.depublish_and_release().unwrap();

        assert_eq!(observation.root_id, inventory.objects[0].id);
        assert!(same_path(
            PathBuf::from(observation.tombstone_path),
            &fixture.tombstone
        ));
        assert!(!fixture.root.exists());
        assert!(fixture.tombstone.is_dir());
        assert_eq!(fs::read(&fixture.sibling).unwrap(), b"unrelated");
        assert_eq!(
            classify_checkpoint_bound_wsb_root(&inventory).unwrap(),
            WsbRootNamespaceState::Tombstone
        );
        reopen_checkpoint_bound_wsb_root(&inventory, WsbRootNamespaceState::Tombstone)
            .unwrap()
            .revalidate()
            .unwrap();
    }

    #[test]
    fn checkpoint_bound_classifier_fails_closed_on_ambiguous_foreign_and_absent_states() {
        let occupied = Fixture::new();
        let tombstone = tombstone_leaf(&occupied.workspace);
        let inventory =
            observe_fixed_wsb_tree_for_checkpoint(&occupied.workspace, RUN_ID, &tombstone).unwrap();
        fs::create_dir(&occupied.tombstone).unwrap();
        assert_eq!(
            classify_checkpoint_bound_wsb_root(&inventory).unwrap(),
            WsbRootNamespaceState::Ambiguous
        );
        assert!(
            reopen_checkpoint_bound_wsb_root(&inventory, WsbRootNamespaceState::Ambiguous).is_err()
        );
        fs::remove_dir(&occupied.tombstone).unwrap();

        let moved = Fixture::new();
        let tombstone = tombstone_leaf(&moved.workspace);
        let inventory =
            observe_fixed_wsb_tree_for_checkpoint(&moved.workspace, RUN_ID, &tombstone).unwrap();
        let displaced = moved.parent.join(format!(
            "{}-displaced",
            moved.root.file_name().unwrap().to_string_lossy()
        ));
        fs::rename(&moved.root, &displaced).unwrap();
        fs::create_dir(&moved.root).unwrap();
        assert_eq!(
            classify_checkpoint_bound_wsb_root(&inventory).unwrap(),
            WsbRootNamespaceState::Foreign
        );
        fs::remove_dir(&moved.root).unwrap();
        fs::rename(&displaced, &moved.root).unwrap();

        let absent = Fixture::new();
        let tombstone = tombstone_leaf(&absent.workspace);
        let inventory =
            observe_fixed_wsb_tree_for_checkpoint(&absent.workspace, RUN_ID, &tombstone).unwrap();
        let displaced = absent.parent.join(format!(
            "{}-displaced",
            absent.root.file_name().unwrap().to_string_lossy()
        ));
        fs::rename(&absent.root, &displaced).unwrap();
        assert_eq!(
            classify_checkpoint_bound_wsb_root(&inventory).unwrap(),
            WsbRootNamespaceState::Absent
        );
        fs::rename(&displaced, &absent.root).unwrap();
    }

    #[test]
    fn exact_tombstone_classification_ignores_but_never_touches_old_name_replacement() {
        let fixture = Fixture::new();
        let tombstone = tombstone_leaf(&fixture.workspace);
        let inventory =
            observe_fixed_wsb_tree_for_checkpoint(&fixture.workspace, RUN_ID, &tombstone).unwrap();
        reopen_checkpoint_bound_wsb_root(&inventory, WsbRootNamespaceState::Original)
            .unwrap()
            .depublish_and_release()
            .unwrap();
        fs::create_dir(&fixture.root).unwrap();
        write_file(&fixture.root.join("foreign"), b"replacement");

        assert_eq!(
            classify_checkpoint_bound_wsb_root(&inventory).unwrap(),
            WsbRootNamespaceState::Tombstone
        );
        assert_eq!(
            fs::read(fixture.root.join("foreign")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn checkpoint_snapshot_blocks_tree_write_and_rename_until_drop() {
        let fixture = Fixture::new();
        let tombstone = tombstone_leaf(&fixture.workspace);
        let held =
            hold_fixed_wsb_tree_for_checkpoint(&fixture.workspace, RUN_ID, &tombstone).unwrap();
        held.revalidate().unwrap();
        assert_eq!(held.evidence().objects.len(), ACQUIRE_ORDER.len());

        let plan = fixture.root.join("plan.json");
        assert!(OpenOptions::new().write(true).open(&plan).is_err());
        let renamed = fixture.parent.join(format!(
            "{}-blocked",
            fixture.root.file_name().unwrap().to_string_lossy()
        ));
        assert!(fs::rename(&fixture.root, &renamed).is_err());

        drop(held);
        OpenOptions::new()
            .write(true)
            .open(&plan)
            .expect("write sharing must be released with checkpoint snapshot");
    }

    #[test]
    fn portable_inventory_live_verifier_rejects_drift_and_occupied_tombstone() {
        let fixture = Fixture::new();
        let tombstone = tombstone_leaf(&fixture.workspace);
        let inventory =
            observe_fixed_wsb_tree_for_checkpoint(&fixture.workspace, RUN_ID, &tombstone).unwrap();
        fs::write(fixture.root.join("plan.json"), b"changed after inventory").unwrap();
        assert!(verify_fixed_wsb_tree_inventory(&inventory).is_err());

        let occupied = Fixture::new();
        let occupied_leaf = tombstone_leaf(&occupied.workspace);
        write_file(&occupied.parent.join(&occupied_leaf), b"foreign");
        assert!(
            observe_fixed_wsb_tree_for_checkpoint(&occupied.workspace, RUN_ID, &occupied_leaf,)
                .is_err()
        );
        assert!(occupied.root.is_dir());
        assert_eq!(
            fs::read(occupied.parent.join(occupied_leaf)).unwrap(),
            b"foreign"
        );
    }

    #[test]
    fn portable_inventory_converts_nonempty_semantic_eas_without_query_padding() {
        let fixture = Fixture::new();
        let mut inventory = fixture.inventory();
        let entries = vec![
            ExtendedAttributeEntryBinding {
                name: "$KERNEL.PURGE.SMARTLOCKER.VALID".to_owned(),
                flags: 0,
                value_length: 4,
                value_sha256: [1_u8; 32],
            },
            ExtendedAttributeEntryBinding {
                name: "$KERNEL.SMARTLOCKER.ORIGINCLAIM".to_owned(),
                flags: 0,
                value_length: 16,
                value_sha256: [2_u8; 32],
            },
        ];
        let mut canonical = Vec::new();
        for entry in &entries {
            canonical.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
            canonical.extend_from_slice(entry.name.as_bytes());
            canonical.push(entry.flags);
            canonical.extend_from_slice(&entry.value_length.to_le_bytes());
            canonical.extend_from_slice(&entry.value_sha256);
        }
        let guest = inventory
            .objects
            .iter_mut()
            .find(|object| object.key == FixedWsbObject::GuestAgent)
            .unwrap();
        guest.ea = ExtendedAttributeBinding {
            queried_bytes: 65_000,
            entries,
            canonical_sha256: Sha256::digest(canonical).into(),
        };
        let evidence = inventory_evidence(inventory).unwrap();
        let guest = evidence
            .objects
            .iter()
            .find(|object| object.kind == WsbFixedObjectKind::GuestAgent)
            .unwrap();
        assert_eq!(guest.ea.entries.len(), 2);
        assert_eq!(guest.ea.entries[0].value_sha256, hex::encode([1_u8; 32]));
        assert_eq!(guest.ea.entries[1].value_sha256, hex::encode([2_u8; 32]));
    }

    #[test]
    fn held_parent_relative_rename_ignores_hostile_process_current_directory() {
        let fixture = Fixture::new();
        let inventory = fixture.inventory();
        let hostile = fixture.parent.join(format!(
            "aiw-dispose-hostile-cwd-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&hostile).unwrap();
        let hostile_collision = hostile.join(inventory.tombstone_leaf());
        write_file(&hostile_collision, b"hostile-cwd-collision");

        let current_directory = CurrentDirectoryGuard::enter(&hostile);
        let mut held =
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).unwrap();
        held.depublish().unwrap();
        assert_eq!(
            fs::read(&hostile_collision).unwrap(),
            b"hostile-cwd-collision"
        );
        assert_eq!(held.dispose_all().unwrap().len(), 19);
        drop(current_directory);

        fs::remove_file(hostile_collision).unwrap();
        fs::remove_dir(hostile).unwrap();
    }

    #[test]
    fn occupied_tombstone_fails_without_replacing_either_tree() {
        let fixture = Fixture::new();
        let inventory = fixture.inventory();
        let tombstone = fixture.parent.join(inventory.tombstone_leaf());
        fs::create_dir(&tombstone).unwrap();
        assert!(
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).is_err()
        );
        assert!(fixture.root.is_dir());
        assert!(tombstone.is_dir());
        fs::remove_dir(&tombstone).unwrap();
    }

    #[test]
    fn dropping_held_tree_before_depublish_is_non_mutating() {
        let fixture = Fixture::new();
        let inventory = fixture.inventory();
        drop(HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).unwrap());
        assert!(fixture.root.is_dir());
        assert!(!fixture.parent.join(inventory.tombstone_leaf()).exists());
    }

    #[test]
    fn dispose_handles_exclude_competing_delete_opens() {
        let original_fixture = Fixture::new();
        let inventory = original_fixture.inventory();
        let original =
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).unwrap();
        assert!(competing_delete_open(&original_fixture.root, true).is_err());
        drop(original);

        let tombstone_fixture = Fixture::new();
        let inventory = tombstone_fixture.inventory();
        let tombstone = tombstone_fixture.parent.join(inventory.tombstone_leaf());
        let mut held =
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).unwrap();
        held.depublish().unwrap();
        let child = path_for(&tombstone, RUN_ID, FixedWsbObject::AuthoritativePlan);
        assert!(competing_delete_open(&child, false).is_err());
        held.dispose_all().unwrap();
    }

    #[test]
    fn dropping_after_depublish_preserves_exact_tombstone_for_recovery() {
        let fixture = Fixture::new();
        let inventory = fixture.inventory();
        let tombstone = fixture.parent.join(inventory.tombstone_leaf());
        let mut held =
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).unwrap();
        held.depublish().unwrap();
        drop(held);
        assert!(!fixture.root.exists());
        assert!(tombstone.is_dir());
        let mut resumed =
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Tombstone).unwrap();
        assert_eq!(resumed.dispose_all().unwrap().len(), 19);
    }

    #[test]
    fn every_partial_prefix_leaves_only_explicitly_deleted_objects_absent() {
        for stop_after in 0..delete_order().len() {
            let fixture = Fixture::new();
            let inventory = fixture.inventory();
            let tombstone = fixture.parent.join(inventory.tombstone_leaf());
            let mut held =
                HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).unwrap();
            held.depublish().unwrap();
            for expected in delete_order().into_iter().take(stop_after) {
                assert_eq!(held.dispose_next().unwrap().key, expected);
            }
            drop(held);

            for (index, key) in delete_order().into_iter().enumerate() {
                assert_eq!(
                    path_for(&tombstone, RUN_ID, key).exists(),
                    index >= stop_after,
                    "unexpected name state for {key:?} after prefix {stop_after}"
                );
            }
            assert_eq!(fs::read(&fixture.sibling).unwrap(), b"unrelated");
        }
    }

    #[test]
    fn every_checkpoint_bound_disposition_prefix_reopens_and_finishes_exactly() {
        for completed in 0..=delete_order().len() {
            let fixture = Fixture::new();
            let tombstone = tombstone_leaf(&fixture.workspace);
            let inventory =
                observe_fixed_wsb_tree_for_checkpoint(&fixture.workspace, RUN_ID, &tombstone)
                    .unwrap();
            reopen_checkpoint_bound_wsb_root(&inventory, WsbRootNamespaceState::Original)
                .unwrap()
                .depublish_and_release()
                .unwrap();
            fs::create_dir(&fixture.root).unwrap();
            let replacement = fixture.root.join("replacement.txt");
            fs::write(&replacement, b"unrelated replacement").unwrap();
            let internal = portable_inventory(&inventory).unwrap();
            let mut prefix = HeldFixedWsbTree::reopen_disposition_prefix(&internal, 0).unwrap();
            for sequence in 0..completed {
                let observation = prefix.dispose_next().unwrap();
                assert_eq!(observation.key, delete_order()[sequence]);
            }
            drop(prefix);

            let mut resumed =
                reopen_checkpoint_bound_wsb_disposition(&inventory, completed as u8).unwrap();
            assert_eq!(resumed.completed_count(), completed as u8);
            if completed < delete_order().len() {
                assert!(resumed.completed_original_replacement_id().is_err());
            }
            while let Some(expected) = resumed.next_step().unwrap() {
                let observed = resumed.dispose_next().unwrap();
                assert_eq!(observed, expected);
            }
            resumed.revalidate().unwrap();
            assert!(
                resumed
                    .completed_original_replacement_id()
                    .unwrap()
                    .is_some()
            );
            assert!(!fixture.tombstone.exists());
            assert_eq!(fs::read(replacement).unwrap(), b"unrelated replacement");
            assert_eq!(fs::read(&fixture.sibling).unwrap(), b"unrelated");
            if completed == delete_order().len() {
                fs::create_dir(&fixture.tombstone).unwrap();
                assert!(resumed.revalidate().is_err());
                fs::remove_dir(&fixture.tombstone).unwrap();
            }
        }
    }

    #[test]
    fn replacement_at_original_name_does_not_block_or_get_touched_by_tombstone_recovery() {
        let fixture = Fixture::new();
        let inventory = fixture.inventory();
        let mut held =
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).unwrap();
        held.depublish().unwrap();

        fs::create_dir(&fixture.root).unwrap();
        write_file(&fixture.root.join("foreign"), b"foreign");
        drop(held);

        let mut resumed =
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Tombstone).unwrap();
        assert_eq!(resumed.dispose_all().unwrap().len(), 19);
        assert_eq!(fs::read(fixture.root.join("foreign")).unwrap(), b"foreign");
    }

    #[test]
    fn unexpected_entry_and_nonempty_output_fail_before_mutation() {
        for relative in ["unexpected", "output/unexpected"] {
            let fixture = Fixture::new();
            write_file(&fixture.root.join(relative), b"unexpected");
            assert!(
                observe_fixed_wsb_tree(
                    &fixture.workspace,
                    RUN_ID,
                    &tombstone_leaf(&fixture.workspace),
                )
                .is_err()
            );
            assert!(fixture.root.is_dir());
        }
    }

    #[test]
    fn hardlink_and_alternate_stream_fail_before_mutation() {
        let hardlink_fixture = Fixture::new();
        let external = hardlink_fixture.parent.join(format!(
            "{}-external-link",
            hardlink_fixture.root.file_name().unwrap().to_string_lossy()
        ));
        fs::hard_link(hardlink_fixture.root.join("plan.json"), &external).unwrap();
        assert!(
            observe_fixed_wsb_tree(
                &hardlink_fixture.workspace,
                RUN_ID,
                &tombstone_leaf(&hardlink_fixture.workspace),
            )
            .is_err()
        );
        fs::remove_file(external).unwrap();

        let stream_fixture = Fixture::new();
        write_file(
            Path::new(&format!(
                "{}:unexpected",
                stream_fixture.root.join("plan.json").display()
            )),
            b"stream",
        );
        assert!(
            observe_fixed_wsb_tree(
                &stream_fixture.workspace,
                RUN_ID,
                &tombstone_leaf(&stream_fixture.workspace),
            )
            .is_err()
        );
    }

    #[test]
    fn content_and_identity_drift_are_rejected_on_delete_reopen() {
        let content_fixture = Fixture::new();
        let inventory = content_fixture.inventory();
        fs::write(content_fixture.root.join("plan.json"), b"changed").unwrap();
        assert!(
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).is_err()
        );

        let identity_fixture = Fixture::new();
        let inventory = identity_fixture.inventory();
        let plan = identity_fixture.root.join("plan.json");
        fs::remove_file(&plan).unwrap();
        fs::write(&plan, b"prepared-plan").unwrap();
        assert!(
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).is_err()
        );
    }

    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    // This crate and test are Windows-only; clearing FILE_ATTRIBUTE_READONLY
    // restores the fixture so its Drop cleanup can remove the exact test tree.
    fn readonly_file_is_rejected_before_mutation() {
        let fixture = Fixture::new();
        let path = fixture.root.join("plan.json");
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        assert!(
            observe_fixed_wsb_tree(
                &fixture.workspace,
                RUN_ID,
                &tombstone_leaf(&fixture.workspace),
            )
            .is_err()
        );
        assert!(fixture.root.is_dir());
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions).unwrap();
    }

    #[test]
    fn reparse_file_is_rejected_when_symlink_creation_is_available() {
        use std::os::windows::fs::symlink_file;

        let fixture = Fixture::new();
        let plan = fixture.root.join("plan.json");
        let target = fixture.root.join("target.json");
        fs::rename(&plan, &target).unwrap();
        if symlink_file(&target, &plan).is_err() {
            fs::rename(&target, &plan).unwrap();
            return;
        }
        assert!(
            observe_fixed_wsb_tree(
                &fixture.workspace,
                RUN_ID,
                &tombstone_leaf(&fixture.workspace),
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_variable_length_buffers_are_rejected() {
        let stream = FILE_STREAM_INFO {
            StreamNameLength: 3,
            ..Default::default()
        };
        let streams =
            fixed_record_with_tail(stream, offset_of!(FILE_STREAM_INFO, StreamName), &[0, 0, 0]);
        assert!(parse_streams(&streams).is_err());

        let entry = FILE_ID_BOTH_DIR_INFO {
            FileNameLength: 2,
            NextEntryOffset: 7,
            ..Default::default()
        };
        let directory = fixed_record_with_tail(
            entry,
            offset_of!(FILE_ID_BOTH_DIR_INFO, FileName),
            &1_u16.to_ne_bytes(),
        );
        assert!(parse_alias_directory_buffer(&directory, &mut Vec::new()).is_err());
    }

    #[test]
    fn safe_byte_parsers_accept_deliberately_misaligned_valid_records() {
        let ea = synthetic_ea_buffer(&[
            (ALLOWED_KERNEL_EAS[0], 0, b"one"),
            (ALLOWED_KERNEL_EAS[1], 0, b"two"),
        ]);
        let ea = misaligned(ea);
        assert_eq!(
            parse_extended_attributes(&ea[1..], (ea.len() - 1) as u32, false, true)
                .unwrap()
                .entries
                .len(),
            2
        );

        let stream_name = native_utf16_bytes("::$DATA");
        let stream = FILE_STREAM_INFO {
            StreamNameLength: stream_name.len() as u32,
            StreamSize: 3,
            ..Default::default()
        };
        let streams = misaligned(fixed_record_with_tail(
            stream,
            offset_of!(FILE_STREAM_INFO, StreamName),
            &stream_name,
        ));
        assert_eq!(
            parse_streams(&streams[1..]).unwrap(),
            vec![("::$DATA".into(), 3)]
        );

        let directory_name = native_utf16_bytes("plan.json");
        let extended = FILE_ID_EXTD_DIR_INFO {
            FileNameLength: directory_name.len() as u32,
            ..Default::default()
        };
        let extended = misaligned(fixed_record_with_tail(
            extended,
            offset_of!(FILE_ID_EXTD_DIR_INFO, FileName),
            &directory_name,
        ));
        let mut extended_entries = Vec::new();
        parse_extended_directory_buffer(&extended[1..], &mut extended_entries).unwrap();
        assert_eq!(extended_entries[0].name, "plan.json");

        let alias = FILE_ID_BOTH_DIR_INFO {
            FileNameLength: directory_name.len() as u32,
            ..Default::default()
        };
        let alias = misaligned(fixed_record_with_tail(
            alias,
            offset_of!(FILE_ID_BOTH_DIR_INFO, FileName),
            &directory_name,
        ));
        let mut alias_entries = Vec::new();
        parse_alias_directory_buffer(&alias[1..], &mut alias_entries).unwrap();
        assert_eq!(alias_entries[0].name, "plan.json");
    }

    #[test]
    fn safe_byte_parsers_reject_exactly_header_sized_inputs() {
        let ea = vec![0_u8; offset_of!(FILE_FULL_EA_INFORMATION, EaName)];
        assert!(parse_extended_attributes(&ea, ea.len() as u32, false, true).is_err());

        let streams = vec![0_u8; offset_of!(FILE_STREAM_INFO, StreamName)];
        assert!(parse_streams(&streams).is_err());

        let extended = vec![0_u8; offset_of!(FILE_ID_EXTD_DIR_INFO, FileName)];
        assert!(parse_extended_directory_buffer(&extended, &mut Vec::new()).is_err());

        let alias = vec![0_u8; offset_of!(FILE_ID_BOTH_DIR_INFO, FileName)];
        assert!(parse_alias_directory_buffer(&alias, &mut Vec::new()).is_err());
    }

    #[test]
    fn approved_ea_pair_is_canonicalized_without_retaining_values() {
        let first = synthetic_ea_buffer(&[
            (ALLOWED_KERNEL_EAS[1], 0, b"opaque-origin"),
            (ALLOWED_KERNEL_EAS[0], 0, b"SMV1"),
        ]);
        let second = synthetic_ea_buffer(&[
            (ALLOWED_KERNEL_EAS[0], 0, b"SMV1"),
            (ALLOWED_KERNEL_EAS[1], 0, b"opaque-origin"),
        ]);
        let first = parse_extended_attributes(&first, first.len() as u32, false, true).unwrap();
        let second = parse_extended_attributes(&second, second.len() as u32, false, true).unwrap();
        assert_eq!(first.entries, second.entries);
        assert_eq!(first.canonical_sha256, second.canonical_sha256);
        assert_eq!(first.entries[0].value_length, 4);
        assert_eq!(first.entries[1].value_length, 13);
    }

    #[test]
    fn approved_directory_origin_and_file_hash_triple_are_exact() {
        let directory =
            synthetic_ea_buffer(&[("$KERNEL.SMARTLOCKER.ORIGINCLAIM", 0, b"opaque-origin")]);
        let directory =
            parse_extended_attributes(&directory, directory.len() as u32, true, true).unwrap();
        assert_eq!(directory.entries.len(), 1);
        assert_eq!(directory.entries[0].name, "$KERNEL.SMARTLOCKER.ORIGINCLAIM");

        let file = synthetic_ea_buffer(&[
            (ALLOWED_KERNEL_EAS_WITH_FILE_HASH[0], 0, b"opaque-file-hash"),
            (ALLOWED_KERNEL_EAS_WITH_FILE_HASH[1], 0, b"SMV1"),
            (ALLOWED_KERNEL_EAS_WITH_FILE_HASH[2], 0, b"opaque-origin"),
        ]);
        let file = parse_extended_attributes(&file, file.len() as u32, false, true).unwrap();
        assert_eq!(file.entries.len(), 3);
        assert!(
            file.entries
                .iter()
                .zip(ALLOWED_KERNEL_EAS_WITH_FILE_HASH)
                .all(|(entry, expected)| entry.name == expected)
        );
    }

    #[test]
    fn ea_parser_rejects_unknown_partial_duplicate_and_case_colliding_sets() {
        for entries in [
            vec![(ALLOWED_KERNEL_EAS[0], 0, b"one".as_slice())],
            vec![
                (ALLOWED_KERNEL_EAS[0], 0, b"one".as_slice()),
                ("$KERNEL.UNKNOWN", 0, b"two".as_slice()),
            ],
            vec![
                (ALLOWED_KERNEL_EAS[0], 0, b"one".as_slice()),
                (ALLOWED_KERNEL_EAS[0], 0, b"two".as_slice()),
            ],
            vec![
                (ALLOWED_KERNEL_EAS[0], 0, b"one".as_slice()),
                ("$kernel.purge.smartlocker.valid", 0, b"two".as_slice()),
            ],
        ] {
            let bytes = synthetic_ea_buffer(&entries);
            assert!(parse_extended_attributes(&bytes, bytes.len() as u32, false, true).is_err());
        }
        let bytes = synthetic_ea_buffer(&[
            (ALLOWED_KERNEL_EAS[0], 0, b"one"),
            (ALLOWED_KERNEL_EAS[1], 0, b"two"),
        ]);
        assert!(parse_extended_attributes(&bytes, bytes.len() as u32, true, true).is_err());
    }

    #[test]
    fn ea_parser_rejects_malformed_lengths_offsets_and_padding() {
        let valid = synthetic_ea_buffer(&[
            (ALLOWED_KERNEL_EAS[0], 0, b"one"),
            (ALLOWED_KERNEL_EAS[1], 0, b"two"),
        ]);
        let mut missing_nul = valid.clone();
        let nul = offset_of!(FILE_FULL_EA_INFORMATION, EaName) + ALLOWED_KERNEL_EAS[0].len();
        missing_nul[nul] = 1;
        assert!(
            parse_extended_attributes(&missing_nul, missing_nul.len() as u32, false, true).is_err()
        );

        let mut bad_offset = valid.clone();
        bad_offset[..4].copy_from_slice(&3_u32.to_le_bytes());
        assert!(
            parse_extended_attributes(&bad_offset, bad_offset.len() as u32, false, true).is_err()
        );

        let mut nonzero_padding = valid.clone();
        let next = u32::from_le_bytes(nonzero_padding[..4].try_into().unwrap()) as usize;
        nonzero_padding[next - 1] = 1;
        assert!(
            parse_extended_attributes(&nonzero_padding, nonzero_padding.len() as u32, false, true)
                .is_err()
        );

        assert!(parse_extended_attributes(&valid[..7], 7, false, true).is_err());
        assert!(parse_extended_attributes(&valid, (valid.len() - 1) as u32, false, true).is_err());
    }

    #[test]
    fn persisted_ea_digest_drift_is_rejected_before_mutation() {
        let fixture = Fixture::new();
        let mut inventory = fixture.inventory();
        let binding = inventory
            .objects
            .iter_mut()
            .find(|binding| binding.key == FixedWsbObject::PreparedPlan)
            .unwrap();
        binding.ea.canonical_sha256[0] ^= 0xff;
        assert!(
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).is_err()
        );
        assert!(fixture.root.is_dir());
    }

    #[test]
    fn shared_run_lock_blocks_depublish_until_explicit_release() {
        let fixture = Fixture::new();
        let run_lock_path = path_for(&fixture.root, RUN_ID, FixedWsbObject::RunLock);
        let live_run_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .open(run_lock_path)
            .unwrap();
        let inventory = fixture.inventory();
        let mut held =
            HeldFixedWsbTree::reopen_exact(&inventory, FixedWsbTreeLocation::Original).unwrap();
        assert!(held.depublish().is_err());
        assert!(fixture.root.is_dir());
        assert!(!fixture.tombstone.exists());
        assert_eq!(held.next_object(), Some(FixedWsbObject::JournalHead3));
        drop(live_run_lock);
        held.depublish().unwrap();
        while held.next_object() != Some(FixedWsbObject::RunLock) {
            held.dispose_next().unwrap();
        }
        assert_eq!(held.dispose_next().unwrap().key, FixedWsbObject::RunLock);
        held.dispose_all().unwrap();
    }

    #[test]
    fn descendant_acl_drift_is_rejected_without_repair() {
        use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows::Win32::Storage::FileSystem::WRITE_DAC;

        let fixture = Fixture::new();
        let plan = fixture.root.join("plan.json");
        let handle = OpenOptions::new()
            .access_mode(READ_CONTROL.0 | WRITE_DAC.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .open(plan)
            .unwrap();
        let result = unsafe {
            SetSecurityInfo(
                raw_handle(&handle),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(std::ptr::null()),
                None,
            )
        };
        assert_eq!(result.0, 0);
        drop(handle);
        assert!(
            observe_fixed_wsb_tree(
                &fixture.workspace,
                RUN_ID,
                &tombstone_leaf(&fixture.workspace),
            )
            .is_err()
        );
        assert!(fixture.root.is_dir());
    }

    #[test]
    fn production_exact_cleanup_contains_no_path_delete_fallback() {
        let source = include_str!("exact_dispose.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "remove_dir_all(",
            "remove_dir(",
            "remove_file(",
            "std::fs::rename(",
            "fs::rename(",
        ] {
            assert!(
                !production.contains(forbidden),
                "production cleanup contains forbidden path mutation: {forbidden}"
            );
        }
    }

    #[test]
    fn relative_rename_buffer_has_exact_nonreplacing_root_bound_layout() {
        let fixture = Fixture::new();
        let parent = open_parent(&fixture.parent).unwrap();
        let leaf = tombstone_leaf(&fixture.workspace);
        let buffer = build_relative_rename_info(&parent, OsStr::new(&leaf)).unwrap();
        let name: Vec<u16> = leaf.encode_utf16().collect();
        assert_eq!(
            buffer.information_length as usize,
            offset_of!(FILE_RENAME_INFO, FileName) + name.len() * size_of::<u16>()
        );
        assert_eq!(
            buffer.storage.len() * size_of::<usize>(),
            (buffer.information_length as usize).next_multiple_of(size_of::<usize>())
        );
        let info = unsafe { &*buffer.storage.as_ptr().cast::<FILE_RENAME_INFO>() };
        assert!(!unsafe { info.Anonymous.ReplaceIfExists });
        assert_eq!(info.RootDirectory, raw_handle(&parent));
        assert_eq!(info.FileNameLength as usize, name.len() * size_of::<u16>());
        let actual_name = unsafe {
            std::slice::from_raw_parts(info.FileName.as_ptr(), info.FileNameLength as usize / 2)
        };
        assert_eq!(actual_name, name);
    }

    fn fixed_record_with_tail<T: Copy>(value: T, tail_offset: usize, tail: &[u8]) -> Vec<u8> {
        let length = size_of::<T>().max(tail_offset + tail.len());
        let mut bytes = vec![0_u8; length];
        // SAFETY: `value` is a fully initialized Copy value and `bytes` has
        // room for its complete object representation.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&value as *const T).cast::<u8>(),
                bytes.as_mut_ptr(),
                size_of::<T>(),
            );
        }
        bytes[tail_offset..tail_offset + tail.len()].copy_from_slice(tail);
        bytes
    }

    fn native_utf16_bytes(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_ne_bytes).collect()
    }

    fn misaligned(bytes: Vec<u8>) -> Vec<u8> {
        let mut result = Vec::with_capacity(bytes.len() + 1);
        result.push(0xa5);
        result.extend_from_slice(&bytes);
        result
    }

    fn synthetic_ea_buffer(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let header = offset_of!(FILE_FULL_EA_INFORMATION, EaName);
        let mut buffer = Vec::new();
        for (index, (name, flags, value)) in entries.iter().enumerate() {
            assert!(name.is_ascii());
            assert!(name.len() <= u8::MAX as usize);
            assert!(value.len() <= u16::MAX as usize);
            let record_len = header + name.len() + 1 + value.len();
            let allocated = if index + 1 == entries.len() {
                record_len
            } else {
                record_len.next_multiple_of(4)
            };
            let start = buffer.len();
            buffer.resize(start + allocated, 0);
            let next = if index + 1 == entries.len() {
                0
            } else {
                allocated as u32
            };
            buffer[start..start + 4].copy_from_slice(&next.to_le_bytes());
            buffer[start + 4] = *flags;
            buffer[start + 5] = name.len() as u8;
            buffer[start + 6..start + 8].copy_from_slice(&(value.len() as u16).to_le_bytes());
            let name_start = start + header;
            buffer[name_start..name_start + name.len()].copy_from_slice(name.as_bytes());
            let value_start = name_start + name.len() + 1;
            buffer[value_start..value_start + value.len()].copy_from_slice(value);
        }
        buffer
    }
}
