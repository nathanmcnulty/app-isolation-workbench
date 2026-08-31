//! Protected external publication of the fixed WSB discard checkpoint.
//!
//! A checkpoint is an immutable, portable fixed-tree inventory.  This module
//! owns only the publication boundary: it creates a protected pending file,
//! flushes it, closes and reopens it for strict verification, and publishes it
//! with one non-replacing handle-relative rename.  It has no delete operation
//! and never adopts or overwrites an existing namespace object.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aiw_probe::{
    DiscardIntentEaBinding, DiscardIntentEaEntry, DiscardIntentStableId, WorkspaceBindingEvidence,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_DATA, READ_CONTROL, SYNCHRONIZE, SetFileShortNameW,
};
use windows::core::PCWSTR;

use crate::coordination::{RunCoordinationError, RunCoordinationKey};
use crate::exact_dispose::{
    ALLOWED_KERNEL_EAS, FORBIDDEN_ATTRIBUTES, StableFileId, basic_info, exact_directory_entry,
    file_size, hash_file, query_extended_attributes, reject_case_sensitive_directory,
    rename_relative, stable_id, standard_info, verify_stream_policy,
};
use crate::workspace::{
    OwnedSid, create_owner_system_file, final_path, is_fixed_volume, raw_handle, same_path,
    verify_local_acl_volume, verify_owner_system_acl,
};

pub const DISCARD_CHECKPOINT_BINDING_SCHEMA_VERSION: &str =
    "aiw.dev/wsb-discard-checkpoint-binding/v0alpha1";
pub const DISCARD_CHECKPOINT_BINDING_POLICY_VERSION: &str =
    "owner-system-protected-checkpoint-file-v1";

const FINAL_PREFIX: &str = ".aiw-discard-checkpoint-v1-";
const PENDING_PREFIX: &str = ".aiw-discard-checkpoint-pending-v1-";
const MAX_CHECKPOINT_BYTES: usize = 1024 * 1024;
const EA_STABILIZATION_ATTEMPTS: usize = 40;

/// Portable evidence needed to reopen one exact pending or published file.
/// EA values are never retained, only bounded semantic metadata and hashes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardCheckpointBindingEvidence {
    pub schema_version: String,
    pub policy_version: String,
    pub run_id: String,
    pub owner_sid: String,
    pub store_key: String,
    pub final_path: String,
    pub pending_path: String,
    pub parent_id: DiscardIntentStableId,
    pub checkpoint_id: DiscardIntentStableId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_ea: Option<DiscardIntentEaBinding>,
}

impl DiscardCheckpointBindingEvidence {
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn owner_sid(&self) -> &str {
        &self.owner_sid
    }
    pub fn store_key(&self) -> &str {
        &self.store_key
    }
    pub fn final_path(&self) -> &str {
        &self.final_path
    }
    pub fn pending_path(&self) -> &str {
        &self.pending_path
    }
    pub fn parent_id(&self) -> &DiscardIntentStableId {
        &self.parent_id
    }
    pub fn checkpoint_id(&self) -> &DiscardIntentStableId {
        &self.checkpoint_id
    }
    pub fn checkpoint_file_id(&self) -> &DiscardIntentStableId {
        self.checkpoint_id()
    }
    pub fn checkpoint_size(&self) -> Option<u64> {
        self.checkpoint_size
    }
    pub fn checkpoint_sha256(&self) -> Option<&str> {
        self.checkpoint_sha256.as_deref()
    }
    pub fn checkpoint_ea(&self) -> Option<&DiscardIntentEaBinding> {
        self.checkpoint_ea.as_ref()
    }
}

#[derive(Debug, Error)]
pub enum DiscardCheckpointError {
    #[error("discard-checkpoint contract is invalid: {0}")]
    Contract(&'static str),
    #[error("discard-checkpoint authority or identity was rejected: {0}")]
    Rejected(String),
    #[error("discard-checkpoint native operation failed at {operation}: {detail}")]
    Native {
        operation: &'static str,
        detail: String,
    },
    #[error("discard-checkpoint final namespace conflicts with an existing object")]
    FinalConflict,
    #[error("discard-checkpoint pending namespace conflicts with an existing object")]
    PendingConflict,
}

/// Fresh exact pending state. It deliberately has no publication method.
#[must_use]
pub struct StagedDiscardCheckpoint {
    evidence: DiscardCheckpointBindingEvidence,
    _parent: File,
    _checkpoint: File,
}

/// Reserved deterministic pending namespace. The file identity is available
/// before any checkpoint bytes are supplied, allowing the caller to bind that
/// identity into the self-describing checkpoint envelope.
#[must_use]
pub struct ReservedDiscardCheckpoint {
    evidence: DiscardCheckpointBindingEvidence,
    parent: File,
    checkpoint: File,
}

impl ReservedDiscardCheckpoint {
    #[must_use]
    pub fn evidence(&self) -> &DiscardCheckpointBindingEvidence {
        &self.evidence
    }
    #[must_use]
    pub fn parent_id(&self) -> &DiscardIntentStableId {
        &self.evidence.parent_id
    }
    #[must_use]
    pub fn checkpoint_id(&self) -> &DiscardIntentStableId {
        &self.evidence.checkpoint_id
    }

    pub fn persist(
        self,
        checkpoint: &[u8],
        expected_sha256: &str,
    ) -> Result<StagedDiscardCheckpoint, DiscardCheckpointError> {
        persist_reserved(self, checkpoint, expected_sha256)
    }

    pub fn write(
        self,
        checkpoint: &[u8],
        expected_sha256: &str,
    ) -> Result<StagedDiscardCheckpoint, DiscardCheckpointError> {
        self.persist(checkpoint, expected_sha256)
    }
}

impl StagedDiscardCheckpoint {
    #[must_use]
    pub fn evidence(&self) -> &DiscardCheckpointBindingEvidence {
        &self.evidence
    }

    #[must_use]
    pub fn checkpoint_file_id(&self) -> &DiscardIntentStableId {
        self.evidence.checkpoint_file_id()
    }
    #[must_use]
    pub fn checkpoint_id(&self) -> &DiscardIntentStableId {
        self.evidence.checkpoint_id()
    }
}

/// Publication authority produced only by strict persisted-evidence reopen.
#[must_use]
pub struct PublishableDiscardCheckpoint {
    evidence: DiscardCheckpointBindingEvidence,
    parent: File,
    checkpoint: File,
}

impl PublishableDiscardCheckpoint {
    pub fn publish(self) -> Result<HeldDiscardCheckpointPublication, DiscardCheckpointError> {
        publish_reopened(self, PublishFailpoint::None)
    }
}

/// Held final checkpoint authority. The handle keeps competing writers from
/// changing the published bytes while an outer operation consumes the proof.
#[must_use]
pub struct HeldDiscardCheckpointPublication {
    evidence: DiscardCheckpointBindingEvidence,
    _parent: File,
    _checkpoint: File,
}

impl HeldDiscardCheckpointPublication {
    #[must_use]
    pub fn evidence(&self) -> &DiscardCheckpointBindingEvidence {
        &self.evidence
    }
    #[must_use]
    pub fn final_path(&self) -> &str {
        self.evidence.final_path()
    }
    #[must_use]
    pub fn pending_path(&self) -> &str {
        self.evidence.pending_path()
    }
    #[must_use]
    pub fn store_key(&self) -> &str {
        self.evidence.store_key()
    }
    #[must_use]
    pub fn parent_id(&self) -> &DiscardIntentStableId {
        self.evidence.parent_id()
    }
    #[must_use]
    pub fn checkpoint_file_id(&self) -> &DiscardIntentStableId {
        self.evidence.checkpoint_file_id()
    }
    #[must_use]
    pub fn checkpoint_size(&self) -> Option<u64> {
        self.evidence.checkpoint_size()
    }
    #[must_use]
    pub fn checkpoint_sha256(&self) -> Option<&str> {
        self.evidence.checkpoint_sha256()
    }
    #[must_use]
    pub fn checkpoint_ea(&self) -> Option<&DiscardIntentEaBinding> {
        self.evidence.checkpoint_ea()
    }

    pub fn revalidate(&self) -> Result<(), DiscardCheckpointError> {
        let context = Context::from_projection(&self.evidence)?;
        verify_parent(&self._parent, &context, &self.evidence.parent_id)?;
        verify_checkpoint(
            &self._checkpoint,
            &self._parent,
            &PathBuf::from(&self.evidence.final_path),
            &context,
            &self.evidence,
        )
    }
}

#[must_use]
pub enum ReopenedDiscardCheckpoint {
    Publishable(PublishableDiscardCheckpoint),
    Published(HeldDiscardCheckpointPublication),
}

#[must_use]
pub struct ExistingDiscardCheckpoint {
    checkpoint: Vec<u8>,
    binding: DiscardCheckpointBindingEvidence,
    reopened: ReopenedDiscardCheckpoint,
}

impl ExistingDiscardCheckpoint {
    pub fn checkpoint(&self) -> &[u8] {
        &self.checkpoint
    }

    pub fn binding(&self) -> &DiscardCheckpointBindingEvidence {
        &self.binding
    }

    pub fn into_reopened(self) -> ReopenedDiscardCheckpoint {
        self.reopened
    }
}

pub fn reserve_discard_checkpoint(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
) -> Result<ReservedDiscardCheckpoint, DiscardCheckpointError> {
    reserve_with_failpoint(workspace, run_id, store_key, StageFailpoint::None)
}

pub fn reopen_prepared_discard_checkpoint(
    checkpoint: &[u8],
    expected_sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    expected: &DiscardCheckpointBindingEvidence,
) -> Result<ReopenedDiscardCheckpoint, DiscardCheckpointError> {
    let context = Context::new(workspace, run_id, &expected.store_key)?;
    validate_checkpoint_bytes(
        checkpoint,
        expected_sha256,
        &expected.parent_id,
        &expected.checkpoint_id,
    )?;
    validate_projection(expected, &context, checkpoint.len() as u64, expected_sha256)?;
    let parent = open_parent(&context)?;
    match (
        namespace_present(&context.pending_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (true, false) => {
            let file = open_checkpoint(&context.pending_path, true)?;
            verify_checkpoint(&file, &parent, &context.pending_path, &context, expected)?;
            Ok(ReopenedDiscardCheckpoint::Publishable(
                PublishableDiscardCheckpoint {
                    evidence: expected.clone(),
                    parent,
                    checkpoint: file,
                },
            ))
        }
        (false, true) => {
            let file = open_checkpoint(&context.final_path, false)?;
            verify_checkpoint(&file, &parent, &context.final_path, &context, expected)?;
            Ok(ReopenedDiscardCheckpoint::Published(
                HeldDiscardCheckpointPublication {
                    evidence: expected.clone(),
                    _parent: parent,
                    _checkpoint: file,
                },
            ))
        }
        (true, true) => Err(DiscardCheckpointError::Rejected(
            "pending and final checkpoint namespace objects are both present".to_owned(),
        )),
        (false, false) => Err(DiscardCheckpointError::Rejected(
            "neither pending nor final checkpoint namespace object is present".to_owned(),
        )),
    }
}

/// Strictly discovers an exact deterministic pending or final checkpoint after
/// restart. The file's embedded stable identity is checked against the opened
/// object before any caller may validate its higher-level bindings.
pub fn reopen_existing_discard_checkpoint(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
) -> Result<ExistingDiscardCheckpoint, DiscardCheckpointError> {
    let context = Context::new(workspace, run_id, store_key)?;
    let parent = open_parent(&context)?;
    let (path, publishable) = match (
        namespace_present(&context.pending_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (true, false) => (&context.pending_path, true),
        (false, true) => (&context.final_path, false),
        (true, true) => {
            return Err(DiscardCheckpointError::Rejected(
                "pending and final checkpoint namespace objects are both present".to_owned(),
            ));
        }
        (false, false) => {
            return Err(DiscardCheckpointError::Rejected(
                "neither pending nor final checkpoint namespace object is present".to_owned(),
            ));
        }
    };
    let file = open_checkpoint(path, publishable)?;
    verify_checkpoint_shape(&file, &parent, path, &context)?;
    let size = map_exact(file_size(&file))?;
    if size == 0 || size > MAX_CHECKPOINT_BYTES as u64 {
        return Err(DiscardCheckpointError::Rejected(
            "existing checkpoint size is outside the fixed bound".to_owned(),
        ));
    }
    let mut checkpoint = Vec::with_capacity(size as usize);
    (&file)
        .take(MAX_CHECKPOINT_BYTES as u64 + 1)
        .read_to_end(&mut checkpoint)
        .map_err(|error| native_io("ReadFile(discard-checkpoint)", error))?;
    if checkpoint.len() as u64 != size {
        return Err(DiscardCheckpointError::Rejected(
            "existing checkpoint length changed while held".to_owned(),
        ));
    }
    let value: Value = serde_json::from_slice(&checkpoint)
        .map_err(|_| DiscardCheckpointError::Contract("checkpoint is not valid JSON"))?;
    let file_value = value
        .get("checkpointFile")
        .and_then(Value::as_object)
        .ok_or(DiscardCheckpointError::Contract(
            "checkpoint file identity is missing",
        ))?;
    let embedded_parent: DiscardIntentStableId =
        serde_json::from_value(file_value.get("parentId").cloned().ok_or(
            DiscardCheckpointError::Contract("checkpoint parent identity is missing"),
        )?)
        .map_err(|_| DiscardCheckpointError::Contract("checkpoint parent identity is invalid"))?;
    let embedded_file: DiscardIntentStableId =
        serde_json::from_value(file_value.get("fileId").cloned().ok_or(
            DiscardCheckpointError::Contract("checkpoint file identity is missing"),
        )?)
        .map_err(|_| DiscardCheckpointError::Contract("checkpoint file identity is invalid"))?;
    let sha256 = hex::encode(Sha256::digest(&checkpoint));
    validate_checkpoint_bytes(&checkpoint, &sha256, &embedded_parent, &embedded_file)?;
    let observed_id = id_evidence(map_exact(stable_id(&file))?);
    if embedded_parent != context.parent_expected || embedded_file != observed_id {
        return Err(DiscardCheckpointError::Rejected(
            "existing checkpoint self-identity differs from the held object".to_owned(),
        ));
    }
    let checkpoint_ea = ea_evidence(query_extended_attributes(&file, false).map_err(exact_error)?);
    if !valid_ea(&checkpoint_ea) {
        return Err(DiscardCheckpointError::Rejected(
            "existing checkpoint extended attributes are invalid".to_owned(),
        ));
    }
    let binding = DiscardCheckpointBindingEvidence {
        schema_version: DISCARD_CHECKPOINT_BINDING_SCHEMA_VERSION.to_owned(),
        policy_version: DISCARD_CHECKPOINT_BINDING_POLICY_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        owner_sid: workspace.owner_sid.clone(),
        store_key: store_key.to_owned(),
        final_path: context.final_path.to_string_lossy().into_owned(),
        pending_path: context.pending_path.to_string_lossy().into_owned(),
        parent_id: embedded_parent,
        checkpoint_id: embedded_file,
        checkpoint_size: Some(size),
        checkpoint_sha256: Some(sha256.clone()),
        checkpoint_ea: Some(checkpoint_ea),
    };
    validate_projection(&binding, &context, size, &sha256)?;
    verify_checkpoint(&file, &parent, path, &context, &binding)?;
    let reopened = if publishable {
        ReopenedDiscardCheckpoint::Publishable(PublishableDiscardCheckpoint {
            evidence: binding.clone(),
            parent,
            checkpoint: file,
        })
    } else {
        ReopenedDiscardCheckpoint::Published(HeldDiscardCheckpointPublication {
            evidence: binding.clone(),
            _parent: parent,
            _checkpoint: file,
        })
    };
    Ok(ExistingDiscardCheckpoint {
        checkpoint,
        binding,
        reopened,
    })
}

struct Context {
    parent_path: PathBuf,
    final_leaf: String,
    final_path: PathBuf,
    pending_path: PathBuf,
    store_key: String,
    owner: OwnedSid,
    owner_sid: String,
    parent_expected: DiscardIntentStableId,
}

impl Context {
    fn new(
        workspace: &WorkspaceBindingEvidence,
        run_id: &str,
        requested_store_key: &str,
    ) -> Result<Self, DiscardCheckpointError> {
        workspace
            .validate()
            .map_err(|_| DiscardCheckpointError::Contract("workspace binding is invalid"))?;
        let key =
            RunCoordinationKey::from_workspace(workspace, run_id).map_err(coordination_error)?;
        if requested_store_key != key.binding_sha256() {
            return Err(DiscardCheckpointError::Contract(
                "checkpoint store key is not derived from the workspace/run binding",
            ));
        }
        let store_key = requested_store_key.to_owned();
        let final_leaf = format!("{FINAL_PREFIX}{store_key}.json");
        let pending_leaf = format!("{PENDING_PREFIX}{store_key}.json");
        let parent_path = PathBuf::from(&workspace.parent.final_path);
        if Path::new(&workspace.root.final_path)
            .parent()
            .is_none_or(|path| !same_path(path, &parent_path))
        {
            return Err(DiscardCheckpointError::Contract(
                "workspace root slot does not belong to its persisted parent",
            ));
        }
        if !is_fixed_volume(&parent_path).map_err(workspace_error)? {
            return Err(DiscardCheckpointError::Rejected(
                "discard-checkpoint parent is not on a fixed local volume".to_owned(),
            ));
        }
        Ok(Self {
            final_path: parent_path.join(&final_leaf),
            pending_path: parent_path.join(&pending_leaf),
            final_leaf,
            parent_path,
            store_key,
            owner: OwnedSid::from_string(&workspace.owner_sid).map_err(workspace_error)?,
            owner_sid: workspace.owner_sid.clone(),
            parent_expected: DiscardIntentStableId {
                volume_serial_number: workspace.parent.volume_serial_number.clone(),
                file_id: workspace.parent.file_id.clone(),
            },
        })
    }

    fn from_projection(
        value: &DiscardCheckpointBindingEvidence,
    ) -> Result<Self, DiscardCheckpointError> {
        let final_path = PathBuf::from(&value.final_path);
        let pending_path = PathBuf::from(&value.pending_path);
        let parent_path = final_path.parent().ok_or(DiscardCheckpointError::Contract(
            "final checkpoint path has no parent",
        ))?;
        let final_leaf = final_path
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .ok_or(DiscardCheckpointError::Contract(
                "final checkpoint leaf is invalid",
            ))?
            .to_owned();
        let _pending_leaf = pending_path
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .ok_or(DiscardCheckpointError::Contract(
                "pending checkpoint leaf is invalid",
            ))?
            .to_owned();
        Ok(Self {
            parent_path: parent_path.to_owned(),
            final_leaf,
            final_path,
            pending_path,
            store_key: value.store_key.clone(),
            owner: OwnedSid::from_string(&value.owner_sid).map_err(workspace_error)?,
            owner_sid: value.owner_sid.clone(),
            parent_expected: value.parent_id.clone(),
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StageFailpoint {
    None,
    AfterCreate,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PublishFailpoint {
    None,
    AfterRename,
}

fn reserve_with_failpoint(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
    failpoint: StageFailpoint,
) -> Result<ReservedDiscardCheckpoint, DiscardCheckpointError> {
    let context = Context::new(workspace, run_id, store_key)?;
    let parent = open_parent(&context)?;
    if namespace_present(&context.final_path)? {
        return Err(DiscardCheckpointError::FinalConflict);
    }
    if namespace_present(&context.pending_path)? {
        return Err(DiscardCheckpointError::PendingConflict);
    }
    let file = create_owner_system_file(&context.pending_path, &context.owner_sid)
        .map_err(workspace_error)?;
    if failpoint == StageFailpoint::AfterCreate {
        return Err(injected("after pending file creation"));
    }
    clear_short_name(&file)?;
    let checkpoint_id = id_evidence(map_exact(stable_id(&file))?);
    let parent_id = id_evidence(map_exact(stable_id(&parent))?);
    let evidence = DiscardCheckpointBindingEvidence {
        schema_version: DISCARD_CHECKPOINT_BINDING_SCHEMA_VERSION.to_owned(),
        policy_version: DISCARD_CHECKPOINT_BINDING_POLICY_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        owner_sid: workspace.owner_sid.clone(),
        store_key: context.store_key.clone(),
        final_path: context.final_path.to_string_lossy().into_owned(),
        pending_path: context.pending_path.to_string_lossy().into_owned(),
        parent_id,
        checkpoint_id,
        checkpoint_size: None,
        checkpoint_sha256: None,
        checkpoint_ea: None,
    };
    verify_checkpoint_shape(&file, &parent, &context.pending_path, &context)?;
    Ok(ReservedDiscardCheckpoint {
        evidence,
        parent,
        checkpoint: file,
    })
}

fn persist_reserved(
    reserved: ReservedDiscardCheckpoint,
    checkpoint: &[u8],
    expected_sha256: &str,
) -> Result<StagedDiscardCheckpoint, DiscardCheckpointError> {
    validate_checkpoint_bytes(
        checkpoint,
        expected_sha256,
        &reserved.evidence.parent_id,
        &reserved.evidence.checkpoint_id,
    )?;
    let mut file = reserved.checkpoint;
    file.write_all(checkpoint)
        .map_err(|error| native_io("WriteFile(checkpoint)", error))?;
    file.sync_all()
        .map_err(|error| native_io("FlushFileBuffers(checkpoint)", error))?;
    let initial_id = map_exact(stable_id(&file))?;
    drop(file);
    let (file, checkpoint_ea) =
        reopen_stabilized_checkpoint(Path::new(&reserved.evidence.pending_path), &initial_id)?;
    let mut evidence = reserved.evidence;
    evidence.checkpoint_size = Some(checkpoint.len() as u64);
    evidence.checkpoint_sha256 = Some(expected_sha256.to_owned());
    evidence.checkpoint_ea = Some(checkpoint_ea);
    let context = Context::from_projection(&evidence)?;
    verify_checkpoint(
        &file,
        &reserved.parent,
        &context.pending_path,
        &context,
        &evidence,
    )?;
    Ok(StagedDiscardCheckpoint {
        evidence,
        _parent: reserved.parent,
        _checkpoint: file,
    })
}

fn publish_reopened(
    value: PublishableDiscardCheckpoint,
    failpoint: PublishFailpoint,
) -> Result<HeldDiscardCheckpointPublication, DiscardCheckpointError> {
    let context = Context::from_projection(&value.evidence)?;
    verify_parent(&value.parent, &context, &value.evidence.parent_id)?;
    verify_checkpoint(
        &value.checkpoint,
        &value.parent,
        &context.pending_path,
        &context,
        &value.evidence,
    )?;
    if namespace_present(&context.final_path)? {
        return Err(DiscardCheckpointError::FinalConflict);
    }
    rename_relative(
        &value.checkpoint,
        &value.parent,
        OsStr::new(&context.final_leaf),
    )
    .map_err(exact_error)?;
    if failpoint == PublishFailpoint::AfterRename {
        return Err(injected("after final rename before return"));
    }
    value
        .checkpoint
        .sync_all()
        .map_err(|error| native_io("FlushFileBuffers(checkpoint-after-rename)", error))?;
    let initial_id = map_exact(stable_id(&value.checkpoint))?;
    drop(value.checkpoint);
    let (checkpoint, final_ea) = reopen_stabilized_checkpoint(&context.final_path, &initial_id)?;
    let mut evidence = value.evidence;
    evidence.checkpoint_ea = Some(final_ea);
    verify_checkpoint(
        &checkpoint,
        &value.parent,
        &context.final_path,
        &context,
        &evidence,
    )?;
    Ok(HeldDiscardCheckpointPublication {
        evidence,
        _parent: value.parent,
        _checkpoint: checkpoint,
    })
}

fn open_parent(context: &Context) -> Result<File, DiscardCheckpointError> {
    let parent = OpenOptions::new()
        .access_mode(
            FILE_READ_ATTRIBUTES.0
                | FILE_LIST_DIRECTORY.0
                | FILE_TRAVERSE.0
                | FILE_ADD_FILE.0
                | READ_CONTROL.0
                | SYNCHRONIZE.0,
        )
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(&context.parent_path)
        .map_err(|error| native_io("CreateFileW(discard-checkpoint-parent)", error))?;
    verify_parent(&parent, context, &context.parent_expected)?;
    Ok(parent)
}

fn verify_parent(
    parent: &File,
    context: &Context,
    expected: &DiscardIntentStableId,
) -> Result<(), DiscardCheckpointError> {
    verify_local_acl_volume(parent).map_err(workspace_error)?;
    reject_case_sensitive_directory(parent).map_err(exact_error)?;
    verify_owner_system_acl(parent, &context.owner, true, true).map_err(|_| {
        DiscardCheckpointError::Rejected(
            "discard-checkpoint parent must be protected owner-and-SYSTEM-only".to_owned(),
        )
    })?;
    if id_evidence(map_exact(stable_id(parent))?) != *expected
        || !same_path(
            final_path(parent).map_err(workspace_error)?,
            &context.parent_path,
        )
    {
        return Err(DiscardCheckpointError::Rejected(
            "discard-checkpoint parent identity changed".to_owned(),
        ));
    }
    Ok(())
}

fn open_checkpoint(path: &Path, for_publish: bool) -> Result<File, DiscardCheckpointError> {
    let mut access =
        FILE_READ_ATTRIBUTES.0 | FILE_READ_EA.0 | FILE_READ_DATA.0 | READ_CONTROL.0 | SYNCHRONIZE.0;
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT.0;
    if for_publish {
        access |= DELETE.0 | FILE_WRITE_DATA.0;
        flags |= FILE_FLAG_WRITE_THROUGH.0;
    }
    OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| native_io("CreateFileW(discard-checkpoint)", error))
}

fn verify_checkpoint_shape(
    file: &File,
    parent: &File,
    expected_path: &Path,
    context: &Context,
) -> Result<(), DiscardCheckpointError> {
    verify_owner_system_acl(file, &context.owner, true, false).map_err(workspace_error)?;
    let basic = map_exact(basic_info(file))?;
    if basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        || basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || basic.dwFileAttributes & FORBIDDEN_ATTRIBUTES != 0
    {
        return Err(DiscardCheckpointError::Rejected(
            "discard-checkpoint is not an ordinary non-reparse file".to_owned(),
        ));
    }
    let standard = map_exact(standard_info(file))?;
    if standard.Directory || standard.DeletePending || standard.NumberOfLinks != 1 {
        return Err(DiscardCheckpointError::Rejected(
            "discard-checkpoint type, disposition, or link count changed".to_owned(),
        ));
    }
    let id = map_exact(stable_id(file))?;
    if id_evidence(id.clone()).volume_serial_number != context.parent_expected.volume_serial_number
    {
        return Err(DiscardCheckpointError::Rejected(
            "discard-checkpoint is on a different volume".to_owned(),
        ));
    }
    let leaf = expected_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(DiscardCheckpointError::Contract(
            "checkpoint leaf is invalid",
        ))?;
    let entry = map_exact(exact_directory_entry(parent, leaf))?;
    if entry.file_id != id.file_id || entry.attributes != basic.dwFileAttributes {
        return Err(DiscardCheckpointError::Rejected(
            "discard-checkpoint parent entry, exact case, attributes, identity, or short-name policy changed".to_owned(),
        ));
    }
    if !same_path(final_path(file).map_err(workspace_error)?, expected_path) {
        return Err(DiscardCheckpointError::Rejected(
            "discard-checkpoint final path changed".to_owned(),
        ));
    }
    Ok(())
}

fn verify_checkpoint(
    file: &File,
    parent: &File,
    expected_path: &Path,
    context: &Context,
    expected: &DiscardCheckpointBindingEvidence,
) -> Result<(), DiscardCheckpointError> {
    verify_checkpoint_shape(file, parent, expected_path, context)?;
    let basic = map_exact(basic_info(file))?;
    let id = map_exact(stable_id(file))?;
    let leaf = expected_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(DiscardCheckpointError::Contract(
            "checkpoint leaf is invalid",
        ))?;
    let entry = map_exact(exact_directory_entry(parent, leaf))?;
    if entry.file_id != id.file_id || entry.attributes != basic.dwFileAttributes {
        return Err(DiscardCheckpointError::Rejected("discard-checkpoint parent entry, exact case, attributes, identity, or short-name policy changed".to_owned()));
    }
    let id = id_evidence(id);
    let size = map_exact(file_size(file))?;
    let expected_size = expected
        .checkpoint_size
        .ok_or(DiscardCheckpointError::Contract(
            "checkpoint binding is not materialized",
        ))?;
    let expected_sha256 =
        expected
            .checkpoint_sha256
            .as_deref()
            .ok_or(DiscardCheckpointError::Contract(
                "checkpoint binding is not materialized",
            ))?;
    let expected_ea = expected
        .checkpoint_ea
        .as_ref()
        .ok_or(DiscardCheckpointError::Contract(
            "checkpoint binding is not materialized",
        ))?;
    if id != expected.checkpoint_id
        || size != expected_size
        || hex::encode(map_exact(hash_file(file, size))?) != expected_sha256
        || !same_path(final_path(file).map_err(workspace_error)?, expected_path)
    {
        return Err(DiscardCheckpointError::Rejected(
            "discard-checkpoint identity, path, or content changed".to_owned(),
        ));
    }
    let observed_ea = ea_evidence(query_extended_attributes(file, false).map_err(exact_error)?);
    if !same_ea_semantics(&observed_ea, expected_ea) {
        return Err(DiscardCheckpointError::Rejected(
            "discard-checkpoint extended attributes changed".to_owned(),
        ));
    }
    verify_stream_policy(file, false, size).map_err(exact_error)
}

fn reopen_stabilized_checkpoint(
    path: &Path,
    initial_id: &StableFileId,
) -> Result<(File, DiscardIntentEaBinding), DiscardCheckpointError> {
    let mut previous = None::<DiscardIntentEaBinding>;
    for attempt in 0..EA_STABILIZATION_ATTEMPTS {
        let file = open_checkpoint(path, false)?;
        if &map_exact(stable_id(&file))? != initial_id {
            return Err(DiscardCheckpointError::Rejected(
                "pending checkpoint identity changed during metadata stabilization".to_owned(),
            ));
        }
        match query_extended_attributes(&file, false) {
            Ok(binding) => {
                let observed = ea_evidence(binding);
                let stable = previous
                    .as_ref()
                    .is_some_and(|prior| same_ea_semantics(prior, &observed));
                previous = Some(observed.clone());
                if stable
                    && (!observed.entries.is_empty() || attempt + 1 == EA_STABILIZATION_ATTEMPTS)
                {
                    return Ok((file, observed));
                }
                drop(file);
                if attempt + 1 < EA_STABILIZATION_ATTEMPTS {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            Err(crate::exact_dispose::ExactDisposeError::TransientSmartLockerEa)
                if attempt + 1 < EA_STABILIZATION_ATTEMPTS =>
            {
                previous = None;
                drop(file);
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(exact_error(error)),
        }
    }
    Err(DiscardCheckpointError::Rejected(
        "checkpoint SmartLocker EA metadata did not stabilize".to_owned(),
    ))
}

fn validate_checkpoint_bytes(
    checkpoint: &[u8],
    expected_sha256: &str,
    parent_id: &DiscardIntentStableId,
    checkpoint_id: &DiscardIntentStableId,
) -> Result<(), DiscardCheckpointError> {
    if checkpoint.is_empty() || checkpoint.len() > MAX_CHECKPOINT_BYTES {
        return Err(DiscardCheckpointError::Contract(
            "checkpoint bytes are empty or exceed the fixed bound",
        ));
    }
    if expected_sha256.len() != 64
        || !is_lower_hex(expected_sha256)
        || hex::encode(Sha256::digest(checkpoint)) != expected_sha256
    {
        return Err(DiscardCheckpointError::Contract(
            "expected checkpoint SHA-256 is invalid or does not match",
        ));
    }
    let value: Value = serde_json::from_slice(checkpoint)
        .map_err(|_| DiscardCheckpointError::Contract("checkpoint is not valid JSON"))?;
    if serde_json::to_vec(&value)
        .map_err(|_| DiscardCheckpointError::Contract("checkpoint could not be canonicalized"))?
        != checkpoint
    {
        return Err(DiscardCheckpointError::Contract(
            "checkpoint is not canonical",
        ));
    }
    let file = value
        .get("checkpointFile")
        .and_then(Value::as_object)
        .ok_or(DiscardCheckpointError::Contract(
            "checkpoint file identity is missing",
        ))?;
    let parent: DiscardIntentStableId =
        serde_json::from_value(file.get("parentId").cloned().ok_or(
            DiscardCheckpointError::Contract("checkpoint parent identity is missing"),
        )?)
        .map_err(|_| DiscardCheckpointError::Contract("checkpoint parent identity is invalid"))?;
    let object: DiscardIntentStableId = serde_json::from_value(file.get("fileId").cloned().ok_or(
        DiscardCheckpointError::Contract("checkpoint file identity is missing"),
    )?)
    .map_err(|_| DiscardCheckpointError::Contract("checkpoint file identity is invalid"))?;
    if &parent != parent_id || &object != checkpoint_id {
        return Err(DiscardCheckpointError::Rejected(
            "checkpoint self-identity does not match the reserved file".to_owned(),
        ));
    }
    Ok(())
}

fn validate_projection(
    expected: &DiscardCheckpointBindingEvidence,
    context: &Context,
    size: u64,
    sha256: &str,
) -> Result<(), DiscardCheckpointError> {
    if expected.schema_version != DISCARD_CHECKPOINT_BINDING_SCHEMA_VERSION
        || expected.policy_version != DISCARD_CHECKPOINT_BINDING_POLICY_VERSION
        || expected.run_id.is_empty()
        || expected.run_id != expected.run_id.trim()
        || expected.owner_sid != context.owner_sid
        || expected.store_key != context.store_key
        || !same_path(&expected.final_path, &context.final_path)
        || !same_path(&expected.pending_path, &context.pending_path)
        || expected.parent_id != context.parent_expected
        || expected.checkpoint_size != Some(size)
        || expected.checkpoint_sha256.as_deref() != Some(sha256)
        || expected.checkpoint_id.volume_serial_number
            != context.parent_expected.volume_serial_number
        || !valid_id(&expected.parent_id)
        || !valid_id(&expected.checkpoint_id)
        || expected.checkpoint_id == expected.parent_id
        || !expected.checkpoint_ea.as_ref().is_some_and(valid_ea)
    {
        return Err(DiscardCheckpointError::Contract(
            "persisted discard-checkpoint binding is invalid",
        ));
    }
    Ok(())
}

fn clear_short_name(file: &File) -> Result<(), DiscardCheckpointError> {
    let empty = [0_u16];
    unsafe { SetFileShortNameW(raw_handle(file), PCWSTR(empty.as_ptr())) }.map_err(|error| {
        DiscardCheckpointError::Native {
            operation: "SetFileShortNameW(clear)",
            detail: error.to_string(),
        }
    })
}

fn namespace_present(path: &Path) -> Result<bool, DiscardCheckpointError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(native_io("GetFileAttributesW(namespace)", error)),
    }
}

fn same_ea_semantics(left: &DiscardIntentEaBinding, right: &DiscardIntentEaBinding) -> bool {
    left.entries == right.entries && left.canonical_sha256 == right.canonical_sha256
}

fn valid_ea(value: &DiscardIntentEaBinding) -> bool {
    let names_ok = value.entries.is_empty()
        || (value.entries.len() == ALLOWED_KERNEL_EAS.len()
            && value
                .entries
                .iter()
                .zip(ALLOWED_KERNEL_EAS)
                .all(|(entry, name)| entry.name == name));
    value.queried_bytes <= 64 * 1024
        && value.canonical_sha256.len() == 64
        && is_lower_hex(&value.canonical_sha256)
        && names_ok
        && value
            .entries
            .iter()
            .all(|entry| entry.value_sha256.len() == 64 && is_lower_hex(&entry.value_sha256))
}

fn valid_id(value: &DiscardIntentStableId) -> bool {
    value.volume_serial_number.len() == 16
        && value.file_id.len() == 32
        && is_lower_hex(&value.volume_serial_number)
        && is_lower_hex(&value.file_id)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn id_evidence(value: StableFileId) -> DiscardIntentStableId {
    DiscardIntentStableId {
        volume_serial_number: format!("{:016x}", value.volume_serial_number),
        file_id: hex::encode(value.file_id),
    }
}

fn ea_evidence(value: crate::exact_dispose::ExtendedAttributeBinding) -> DiscardIntentEaBinding {
    DiscardIntentEaBinding {
        queried_bytes: value.queried_bytes,
        entries: value
            .entries
            .into_iter()
            .map(|entry| DiscardIntentEaEntry {
                name: entry.name,
                flags: entry.flags,
                value_length: entry.value_length,
                value_sha256: hex::encode(entry.value_sha256),
            })
            .collect(),
        canonical_sha256: hex::encode(value.canonical_sha256),
    }
}

fn coordination_error(error: RunCoordinationError) -> DiscardCheckpointError {
    match error {
        RunCoordinationError::InvalidBinding(detail) => DiscardCheckpointError::Contract(detail),
        other => DiscardCheckpointError::Rejected(other.to_string()),
    }
}
fn workspace_error(error: crate::workspace::WorkspaceError) -> DiscardCheckpointError {
    DiscardCheckpointError::Rejected(error.to_string())
}
fn exact_error(error: crate::exact_dispose::ExactDisposeError) -> DiscardCheckpointError {
    DiscardCheckpointError::Rejected(error.to_string())
}
fn map_exact<T>(
    result: Result<T, crate::exact_dispose::ExactDisposeError>,
) -> Result<T, DiscardCheckpointError> {
    result.map_err(exact_error)
}
fn native_io(operation: &'static str, error: std::io::Error) -> DiscardCheckpointError {
    DiscardCheckpointError::Native {
        operation,
        detail: error.to_string(),
    }
}
fn injected(detail: &'static str) -> DiscardCheckpointError {
    DiscardCheckpointError::Native {
        operation: "crash-injection",
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::{HeldRunWorkspace, create_owner_system_directory};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    fn workspace_fixture() -> (PathBuf, PathBuf, WorkspaceBindingEvidence) {
        let outer = std::env::temp_dir().join(format!(
            "aiw-checkpoint-test-{}-{}",
            std::process::id(),
            NEXT_TEST.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&outer).unwrap();
        let outer = outer.canonicalize().unwrap();
        let seed = HeldRunWorkspace::create(&outer, "owner-seed").unwrap();
        let owner = seed.evidence().owner_sid.clone();
        let seed_root = seed.root_path().to_owned();
        drop(seed);
        fs::remove_dir_all(seed_root).unwrap();
        let parent = outer.join("protected-parent");
        create_owner_system_directory(&parent, &owner).unwrap();
        let parent = parent.canonicalize().unwrap();
        let workspace = HeldRunWorkspace::create(&parent, "workspace").unwrap();
        let root = workspace.root_path().to_owned();
        let evidence = workspace.evidence().clone();
        drop(workspace);
        (outer, root, evidence)
    }

    fn checkpoint_bytes(reserved: &ReservedDiscardCheckpoint) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "checkpointFile": {
                "fileId": reserved.checkpoint_id(),
                "parentId": reserved.parent_id(),
            },
            "schemaVersion": "aiw.dev/test-checkpoint/v1"
        }))
        .unwrap()
    }

    #[test]
    fn names_are_fixed_and_bound_to_store_key() {
        let key = "a".repeat(64);
        assert_eq!(
            format!("{FINAL_PREFIX}{key}.json"),
            format!(".aiw-discard-checkpoint-v1-{key}.json")
        );
        assert_eq!(
            format!("{PENDING_PREFIX}{key}.json"),
            format!(".aiw-discard-checkpoint-pending-v1-{key}.json")
        );
    }

    #[test]
    fn malformed_projection_is_rejected_without_namespace_mutation() {
        let evidence = DiscardCheckpointBindingEvidence {
            schema_version: "wrong".to_owned(),
            policy_version: "wrong".to_owned(),
            run_id: "run-one".to_owned(),
            owner_sid: "S-1-5-21-invalid".to_owned(),
            store_key: "x".to_owned(),
            final_path: "C:\\final".to_owned(),
            pending_path: "C:\\pending".to_owned(),
            parent_id: DiscardIntentStableId {
                volume_serial_number: "0".repeat(16),
                file_id: "0".repeat(32),
            },
            checkpoint_id: DiscardIntentStableId {
                volume_serial_number: "0".repeat(16),
                file_id: "1".repeat(32),
            },
            checkpoint_size: Some(1),
            checkpoint_sha256: Some("0".repeat(64)),
            checkpoint_ea: Some(DiscardIntentEaBinding {
                queried_bytes: 0,
                entries: Vec::new(),
                canonical_sha256: "0".repeat(64),
            }),
        };
        assert_eq!(
            serde_json::to_value(evidence).unwrap()["schemaVersion"],
            "wrong"
        );
    }

    #[test]
    fn complete_pending_resumes_and_publishes_exact_final() {
        let (outer, root, workspace) = workspace_fixture();
        let original_names = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        let key = RunCoordinationKey::from_workspace(&workspace, "run-one")
            .unwrap()
            .binding_sha256()
            .to_owned();
        let reserved = reserve_discard_checkpoint(&workspace, "run-one", &key).unwrap();
        let bytes = checkpoint_bytes(&reserved);
        let digest = hex::encode(Sha256::digest(&bytes));
        let staged = reserved.persist(&bytes, &digest).unwrap();
        let pending = PathBuf::from(staged.evidence().pending_path());
        let final_path = PathBuf::from(staged.evidence().final_path());
        assert!(pending.exists());
        assert!(!final_path.exists());
        drop(staged);

        let existing = reopen_existing_discard_checkpoint(&workspace, "run-one", &key).unwrap();
        assert_eq!(existing.checkpoint(), bytes);
        let ReopenedDiscardCheckpoint::Publishable(value) = existing.into_reopened() else {
            panic!("pending checkpoint must be publishable");
        };
        let published = value.publish().unwrap();
        published.revalidate().unwrap();
        assert!(!pending.exists());
        assert!(final_path.exists());
        assert!(OpenOptions::new().write(true).open(&final_path).is_err());
        let final_names = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(final_names, original_names);
        drop(published);

        let reopened = reopen_existing_discard_checkpoint(&workspace, "run-one", &key).unwrap();
        assert_eq!(reopened.checkpoint(), bytes);
        let ReopenedDiscardCheckpoint::Published(published) = reopened.into_reopened() else {
            panic!("final checkpoint must reopen as published");
        };
        published.revalidate().unwrap();
        drop(published);
        fs::remove_file(final_path).unwrap();
        fs::remove_dir_all(outer).unwrap();
    }

    #[test]
    fn recovered_hardlinked_final_is_rejected_and_preserved() {
        let (outer, root, workspace) = workspace_fixture();
        let key = RunCoordinationKey::from_workspace(&workspace, "run-one")
            .unwrap()
            .binding_sha256()
            .to_owned();
        let reserved = reserve_discard_checkpoint(&workspace, "run-one", &key).unwrap();
        let bytes = checkpoint_bytes(&reserved);
        let digest = hex::encode(Sha256::digest(&bytes));
        let staged = reserved.persist(&bytes, &digest).unwrap();
        let binding = staged.evidence().clone();
        drop(staged);
        let reopened =
            reopen_prepared_discard_checkpoint(&bytes, &digest, &workspace, "run-one", &binding)
                .unwrap();
        let ReopenedDiscardCheckpoint::Publishable(value) = reopened else {
            panic!("pending checkpoint must be publishable");
        };
        let published = value.publish().unwrap();
        let final_path = PathBuf::from(published.final_path());
        drop(published);
        let link = final_path.with_extension("hardlink");
        fs::hard_link(&final_path, &link).unwrap();
        assert!(reopen_existing_discard_checkpoint(&workspace, "run-one", &key).is_err());
        assert!(final_path.exists());
        assert!(link.exists());
        fs::remove_file(link).unwrap();
        fs::remove_file(final_path).unwrap();
        assert!(root.exists());
        fs::remove_dir_all(outer).unwrap();
    }

    #[test]
    fn incomplete_pending_prefixes_never_create_a_final_claim() {
        for flush_partial in [false, true] {
            let (outer, _root, workspace) = workspace_fixture();
            let key = RunCoordinationKey::from_workspace(&workspace, "run-one")
                .unwrap()
                .binding_sha256()
                .to_owned();
            let context = Context::new(&workspace, "run-one", &key).unwrap();
            let mut reserved = reserve_discard_checkpoint(&workspace, "run-one", &key).unwrap();
            reserved.checkpoint.write_all(b"partial").unwrap();
            if flush_partial {
                reserved.checkpoint.sync_all().unwrap();
            }
            drop(reserved);
            assert!(context.pending_path.exists());
            assert!(!context.final_path.exists());
            assert!(reopen_existing_discard_checkpoint(&workspace, "run-one", &key).is_err());
            assert!(context.pending_path.exists());
            assert!(!context.final_path.exists());
            fs::remove_file(context.pending_path).unwrap();
            fs::remove_dir_all(outer).unwrap();
        }
    }

    #[test]
    fn crash_after_atomic_rename_recovers_exact_final() {
        let (outer, _root, workspace) = workspace_fixture();
        let key = RunCoordinationKey::from_workspace(&workspace, "run-one")
            .unwrap()
            .binding_sha256()
            .to_owned();
        let reserved = reserve_discard_checkpoint(&workspace, "run-one", &key).unwrap();
        let bytes = checkpoint_bytes(&reserved);
        let digest = hex::encode(Sha256::digest(&bytes));
        let staged = reserved.persist(&bytes, &digest).unwrap();
        let binding = staged.evidence().clone();
        drop(staged);
        let ReopenedDiscardCheckpoint::Publishable(value) =
            reopen_prepared_discard_checkpoint(&bytes, &digest, &workspace, "run-one", &binding)
                .unwrap()
        else {
            panic!("pending checkpoint must be publishable");
        };
        assert!(matches!(
            publish_reopened(value, PublishFailpoint::AfterRename),
            Err(DiscardCheckpointError::Native { .. })
        ));
        let recovered = reopen_existing_discard_checkpoint(&workspace, "run-one", &key).unwrap();
        assert_eq!(recovered.checkpoint(), bytes);
        let ReopenedDiscardCheckpoint::Published(published) = recovered.into_reopened() else {
            panic!("post-rename state must recover as exact final");
        };
        let final_path = PathBuf::from(published.final_path());
        published.revalidate().unwrap();
        drop(published);
        fs::remove_file(final_path).unwrap();
        fs::remove_dir_all(outer).unwrap();
    }
}
