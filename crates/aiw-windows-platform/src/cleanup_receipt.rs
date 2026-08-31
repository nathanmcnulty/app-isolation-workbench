//! Protected external publication of the terminal discard cleanup receipt.
//!
//! This module owns only one deterministic, owner-and-SYSTEM-protected file
//! beside the workspace.  It is a write-once boundary: reserve a create-new
//! pending file, persist and reopen canonical self-bound bytes, publish with a
//! non-replacing handle-relative rename, and strictly reopen the final file.
//! It never deletes, overwrites, adopts, invokes a provider, or mutates a path
//! other than the one publication rename.

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

pub const CLEANUP_RECEIPT_BINDING_SCHEMA_VERSION: &str =
    "aiw.dev/wsb-discard-cleanup-receipt-binding/v1";
pub const CLEANUP_RECEIPT_BINDING_POLICY_VERSION: &str =
    "owner-system-protected-discard-cleanup-receipt-v1";
const FINAL_PREFIX: &str = ".aiw-discard-cleanup-receipt-v1-";
const PENDING_PREFIX: &str = ".aiw-discard-cleanup-receipt-pending-v1-";
const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
const EA_STABILIZATION_ATTEMPTS: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupReceiptSlotState {
    Absent,
    Pending,
    Published,
    Ambiguous,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleanupReceiptBindingEvidence {
    pub schema_version: String,
    pub policy_version: String,
    pub run_id: String,
    pub owner_sid: String,
    pub store_key: String,
    pub final_path: String,
    pub pending_path: String,
    pub parent_id: DiscardIntentStableId,
    pub receipt_id: DiscardIntentStableId,
    pub receipt_size: u64,
    pub receipt_sha256: String,
    pub receipt_ea: DiscardIntentEaBinding,
}

impl CleanupReceiptBindingEvidence {
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
    pub fn receipt_id(&self) -> &DiscardIntentStableId {
        &self.receipt_id
    }
    pub fn receipt_size(&self) -> u64 {
        self.receipt_size
    }
    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
    pub fn receipt_ea(&self) -> &DiscardIntentEaBinding {
        &self.receipt_ea
    }
}

#[derive(Debug, Error)]
pub enum CleanupReceiptError {
    #[error("cleanup-receipt contract is invalid: {0}")]
    Contract(&'static str),
    #[error("cleanup-receipt authority or identity was rejected: {0}")]
    Rejected(String),
    #[error("cleanup-receipt native operation failed at {operation}: {detail}")]
    Native {
        operation: &'static str,
        detail: String,
    },
    #[error("cleanup-receipt final namespace conflicts with an existing object")]
    FinalConflict,
    #[error("cleanup-receipt pending namespace conflicts with an existing object")]
    PendingConflict,
}

#[must_use]
pub struct ReservedCleanupReceipt {
    evidence: CleanupReceiptBindingEvidence,
    parent: File,
    receipt: File,
}

impl ReservedCleanupReceipt {
    pub fn evidence(&self) -> &CleanupReceiptBindingEvidence {
        &self.evidence
    }
    pub fn parent_id(&self) -> &DiscardIntentStableId {
        &self.evidence.parent_id
    }
    pub fn receipt_id(&self) -> &DiscardIntentStableId {
        &self.evidence.receipt_id
    }
    pub fn persist(
        self,
        bytes: &[u8],
        sha256: &str,
    ) -> Result<StagedCleanupReceipt, CleanupReceiptError> {
        validate_bytes(
            bytes,
            sha256,
            &self.evidence.parent_id,
            &self.evidence.receipt_id,
        )?;
        let mut receipt = self.receipt;
        receipt
            .write_all(bytes)
            .map_err(|error| native_io("WriteFile(cleanup-receipt)", error))?;
        receipt
            .sync_all()
            .map_err(|error| native_io("FlushFileBuffers(cleanup-receipt)", error))?;
        let initial = map_exact(stable_id(&receipt))?;
        if id_evidence(initial.clone()) != self.evidence.receipt_id {
            return Err(CleanupReceiptError::Rejected(
                "reserved receipt identity changed before persist".to_owned(),
            ));
        }
        drop(receipt);
        let (receipt, ea) = reopen_stabilized(Path::new(&self.evidence.pending_path), &initial)?;
        let mut evidence = self.evidence;
        evidence.receipt_size = bytes.len() as u64;
        evidence.receipt_sha256 = sha256.to_owned();
        evidence.receipt_ea = ea;
        let context = Context::from_projection(&evidence)?;
        verify_receipt(
            &receipt,
            &self.parent,
            &context.pending_path,
            &context,
            &evidence,
        )?;
        Ok(StagedCleanupReceipt {
            evidence,
            _parent: self.parent,
            _receipt: receipt,
            bytes: bytes.to_owned(),
        })
    }
}

#[must_use]
pub struct StagedCleanupReceipt {
    evidence: CleanupReceiptBindingEvidence,
    _parent: File,
    _receipt: File,
    bytes: Vec<u8>,
}

impl StagedCleanupReceipt {
    pub fn evidence(&self) -> &CleanupReceiptBindingEvidence {
        &self.evidence
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[must_use]
pub struct PublishableCleanupReceipt {
    evidence: CleanupReceiptBindingEvidence,
    parent: File,
    receipt: File,
    bytes: Vec<u8>,
}

impl PublishableCleanupReceipt {
    pub fn evidence(&self) -> &CleanupReceiptBindingEvidence {
        &self.evidence
    }

    pub fn publish(self) -> Result<HeldCleanupReceiptPublication, CleanupReceiptError> {
        let context = Context::from_projection(&self.evidence)?;
        if namespace_present(&context.final_path)? {
            return Err(CleanupReceiptError::FinalConflict);
        }
        verify_parent(&self.parent, &context, &self.evidence.parent_id)?;
        verify_receipt(
            &self.receipt,
            &self.parent,
            &context.pending_path,
            &context,
            &self.evidence,
        )?;
        rename_relative(&self.receipt, &self.parent, OsStr::new(&context.final_leaf))
            .map_err(exact_error)?;
        self.receipt
            .sync_all()
            .map_err(|error| native_io("FlushFileBuffers(cleanup-receipt-after-rename)", error))?;
        drop(self.receipt);
        let receipt = open_receipt(&context.final_path, false)?;
        verify_receipt(
            &receipt,
            &self.parent,
            &context.final_path,
            &context,
            &self.evidence,
        )?;
        Ok(HeldCleanupReceiptPublication {
            evidence: self.evidence,
            _parent: self.parent,
            _receipt: receipt,
            bytes: self.bytes,
        })
    }
}

#[must_use]
pub struct HeldCleanupReceiptPublication {
    evidence: CleanupReceiptBindingEvidence,
    _parent: File,
    _receipt: File,
    bytes: Vec<u8>,
}

impl HeldCleanupReceiptPublication {
    pub fn evidence(&self) -> &CleanupReceiptBindingEvidence {
        &self.evidence
    }
    pub fn binding(&self) -> &CleanupReceiptBindingEvidence {
        &self.evidence
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn final_path(&self) -> &str {
        self.evidence.final_path()
    }
    pub fn revalidate(&self) -> Result<(), CleanupReceiptError> {
        let context = Context::from_projection(&self.evidence)?;
        verify_parent(&self._parent, &context, &self.evidence.parent_id)?;
        verify_receipt(
            &self._receipt,
            &self._parent,
            &context.final_path,
            &context,
            &self.evidence,
        )
    }
}

#[must_use]
pub enum ReopenedCleanupReceipt {
    Publishable(PublishableCleanupReceipt),
    Published(HeldCleanupReceiptPublication),
}

#[must_use]
pub struct ExistingCleanupReceipt {
    receipt: Vec<u8>,
    binding: CleanupReceiptBindingEvidence,
    reopened: ReopenedCleanupReceipt,
}

impl ExistingCleanupReceipt {
    pub fn receipt(&self) -> &[u8] {
        &self.receipt
    }
    pub fn bytes(&self) -> &[u8] {
        &self.receipt
    }
    pub fn binding(&self) -> &CleanupReceiptBindingEvidence {
        &self.binding
    }
    pub fn into_reopened(self) -> ReopenedCleanupReceipt {
        self.reopened
    }
}

pub fn reserve_cleanup_receipt(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
) -> Result<ReservedCleanupReceipt, CleanupReceiptError> {
    let context = Context::new(workspace, run_id, store_key)?;
    let parent = open_parent(&context)?;
    if namespace_present(&context.final_path)? {
        return Err(CleanupReceiptError::FinalConflict);
    }
    if namespace_present(&context.pending_path)? {
        return Err(CleanupReceiptError::PendingConflict);
    }
    let receipt = create_owner_system_file(&context.pending_path, &context.owner_sid)
        .map_err(workspace_error)?;
    clear_short_name(&receipt)?;
    let evidence = CleanupReceiptBindingEvidence {
        schema_version: CLEANUP_RECEIPT_BINDING_SCHEMA_VERSION.to_owned(),
        policy_version: CLEANUP_RECEIPT_BINDING_POLICY_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        owner_sid: workspace.owner_sid.clone(),
        store_key: store_key.to_owned(),
        final_path: context.final_path.to_string_lossy().into_owned(),
        pending_path: context.pending_path.to_string_lossy().into_owned(),
        parent_id: id_evidence(map_exact(stable_id(&parent))?),
        receipt_id: id_evidence(map_exact(stable_id(&receipt))?),
        receipt_size: 0,
        receipt_sha256: String::new(),
        receipt_ea: DiscardIntentEaBinding {
            queried_bytes: 0,
            entries: Vec::new(),
            canonical_sha256: String::new(),
        },
    };
    verify_shape(&receipt, &parent, &context.pending_path, &context)?;
    Ok(ReservedCleanupReceipt {
        evidence,
        parent,
        receipt,
    })
}

pub fn stage_cleanup_receipt(
    bytes: &[u8],
    sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
) -> Result<StagedCleanupReceipt, CleanupReceiptError> {
    reserve_cleanup_receipt(workspace, run_id, store_key)?.persist(bytes, sha256)
}

pub fn classify_cleanup_receipt_slot(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
) -> Result<CleanupReceiptSlotState, CleanupReceiptError> {
    let context = Context::new(workspace, run_id, store_key)?;
    let _parent = open_parent(&context)?;
    match (
        namespace_present(&context.pending_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (false, false) => Ok(CleanupReceiptSlotState::Absent),
        (true, false) => Ok(CleanupReceiptSlotState::Pending),
        (false, true) => Ok(CleanupReceiptSlotState::Published),
        (true, true) => Ok(CleanupReceiptSlotState::Ambiguous),
    }
}

pub fn reopen_prepared_cleanup_receipt(
    bytes: &[u8],
    sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    expected: &CleanupReceiptBindingEvidence,
) -> Result<ReopenedCleanupReceipt, CleanupReceiptError> {
    let context = Context::new(workspace, run_id, &expected.store_key)?;
    validate_bytes(bytes, sha256, &expected.parent_id, &expected.receipt_id)?;
    validate_projection(expected, &context, bytes.len() as u64, sha256)?;
    let parent = open_parent(&context)?;
    match (
        namespace_present(&context.pending_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (true, false) => {
            let receipt = open_receipt(&context.pending_path, true)?;
            verify_receipt(&receipt, &parent, &context.pending_path, &context, expected)?;
            Ok(ReopenedCleanupReceipt::Publishable(
                PublishableCleanupReceipt {
                    evidence: expected.clone(),
                    parent,
                    receipt,
                    bytes: bytes.to_owned(),
                },
            ))
        }
        (false, true) => {
            let receipt = open_receipt(&context.final_path, false)?;
            verify_receipt(&receipt, &parent, &context.final_path, &context, expected)?;
            Ok(ReopenedCleanupReceipt::Published(
                HeldCleanupReceiptPublication {
                    evidence: expected.clone(),
                    _parent: parent,
                    _receipt: receipt,
                    bytes: bytes.to_owned(),
                },
            ))
        }
        (true, true) => Err(CleanupReceiptError::Rejected(
            "pending and final cleanup receipts are both present".to_owned(),
        )),
        (false, false) => Err(CleanupReceiptError::Rejected(
            "neither pending nor final cleanup receipt is present".to_owned(),
        )),
    }
}

pub fn reopen_existing_cleanup_receipt(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
) -> Result<ExistingCleanupReceipt, CleanupReceiptError> {
    let context = Context::new(workspace, run_id, store_key)?;
    let parent = open_parent(&context)?;
    let (path, publishable) = match (
        namespace_present(&context.pending_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (true, false) => (&context.pending_path, true),
        (false, true) => (&context.final_path, false),
        (true, true) => {
            return Err(CleanupReceiptError::Rejected(
                "pending and final cleanup receipts are both present".to_owned(),
            ));
        }
        (false, false) => {
            return Err(CleanupReceiptError::Rejected(
                "neither pending nor final cleanup receipt is present".to_owned(),
            ));
        }
    };
    let receipt = open_receipt(path, publishable)?;
    verify_shape(&receipt, &parent, path, &context)?;
    let size = map_exact(file_size(&receipt))?;
    if size == 0 || size > MAX_RECEIPT_BYTES as u64 {
        return Err(CleanupReceiptError::Rejected(
            "existing cleanup receipt size is outside fixed bound".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    (&receipt)
        .take(MAX_RECEIPT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| native_io("ReadFile(cleanup-receipt)", error))?;
    if bytes.len() as u64 != size {
        return Err(CleanupReceiptError::Rejected(
            "existing cleanup receipt length changed".to_owned(),
        ));
    }
    let file_id = id_evidence(map_exact(stable_id(&receipt))?);
    let parent_id = context.parent_expected.clone();
    let sha = hex::encode(Sha256::digest(&bytes));
    let ea = ea_evidence(query_extended_attributes(&receipt, false).map_err(exact_error)?);
    if !valid_ea(&ea) {
        return Err(CleanupReceiptError::Rejected(
            "existing cleanup receipt EAs are invalid".to_owned(),
        ));
    }
    validate_bytes(&bytes, &sha, &parent_id, &file_id)?;
    let binding = CleanupReceiptBindingEvidence {
        schema_version: CLEANUP_RECEIPT_BINDING_SCHEMA_VERSION.to_owned(),
        policy_version: CLEANUP_RECEIPT_BINDING_POLICY_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        owner_sid: workspace.owner_sid.clone(),
        store_key: store_key.to_owned(),
        final_path: context.final_path.to_string_lossy().into_owned(),
        pending_path: context.pending_path.to_string_lossy().into_owned(),
        parent_id,
        receipt_id: file_id,
        receipt_size: size,
        receipt_sha256: sha.clone(),
        receipt_ea: ea,
    };
    validate_projection(&binding, &context, size, &sha)?;
    verify_receipt(&receipt, &parent, path, &context, &binding)?;
    let reopened = if publishable {
        ReopenedCleanupReceipt::Publishable(PublishableCleanupReceipt {
            evidence: binding.clone(),
            parent,
            receipt,
            bytes: bytes.clone(),
        })
    } else {
        ReopenedCleanupReceipt::Published(HeldCleanupReceiptPublication {
            evidence: binding.clone(),
            _parent: parent,
            _receipt: receipt,
            bytes: bytes.clone(),
        })
    };
    Ok(ExistingCleanupReceipt {
        receipt: bytes,
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
        store_key: &str,
    ) -> Result<Self, CleanupReceiptError> {
        workspace
            .validate()
            .map_err(|_| CleanupReceiptError::Contract("workspace binding is invalid"))?;
        let key =
            RunCoordinationKey::from_workspace(workspace, run_id).map_err(coordination_error)?;
        if key.binding_sha256() != store_key {
            return Err(CleanupReceiptError::Contract(
                "cleanup receipt store key is not derived from workspace/run",
            ));
        }
        let parent_path = PathBuf::from(&workspace.parent.final_path);
        if Path::new(&workspace.root.final_path)
            .parent()
            .is_none_or(|path| !same_path(path, &parent_path))
        {
            return Err(CleanupReceiptError::Contract(
                "workspace root does not belong to its parent",
            ));
        }
        if !is_fixed_volume(&parent_path).map_err(workspace_error)? {
            return Err(CleanupReceiptError::Rejected(
                "cleanup receipt parent is not fixed local volume".to_owned(),
            ));
        }
        let final_leaf = format!("{FINAL_PREFIX}{store_key}.json");
        let pending_leaf = format!("{PENDING_PREFIX}{store_key}.json");
        Ok(Self {
            final_path: parent_path.join(&final_leaf),
            pending_path: parent_path.join(&pending_leaf),
            final_leaf,
            parent_path,
            store_key: store_key.to_owned(),
            owner: OwnedSid::from_string(&workspace.owner_sid).map_err(workspace_error)?,
            owner_sid: workspace.owner_sid.clone(),
            parent_expected: DiscardIntentStableId {
                volume_serial_number: workspace.parent.volume_serial_number.clone(),
                file_id: workspace.parent.file_id.clone(),
            },
        })
    }
    fn from_projection(value: &CleanupReceiptBindingEvidence) -> Result<Self, CleanupReceiptError> {
        let final_path = PathBuf::from(&value.final_path);
        let pending_path = PathBuf::from(&value.pending_path);
        let parent_path = final_path
            .parent()
            .ok_or(CleanupReceiptError::Contract(
                "cleanup receipt final path has no parent",
            ))?
            .to_owned();
        let final_leaf = final_path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(CleanupReceiptError::Contract(
                "cleanup receipt final leaf is invalid",
            ))?
            .to_owned();
        Ok(Self {
            parent_path,
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

fn open_parent(context: &Context) -> Result<File, CleanupReceiptError> {
    let file = OpenOptions::new()
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
        .map_err(|error| native_io("CreateFileW(cleanup-receipt-parent)", error))?;
    verify_parent(&file, context, &context.parent_expected)?;
    Ok(file)
}

fn verify_parent(
    parent: &File,
    context: &Context,
    expected: &DiscardIntentStableId,
) -> Result<(), CleanupReceiptError> {
    verify_local_acl_volume(parent).map_err(workspace_error)?;
    reject_case_sensitive_directory(parent).map_err(exact_error)?;
    verify_owner_system_acl(parent, &context.owner, true, true).map_err(|_| {
        CleanupReceiptError::Rejected(
            "cleanup receipt parent is not owner-and-SYSTEM protected".to_owned(),
        )
    })?;
    if id_evidence(map_exact(stable_id(parent))?) != *expected
        || !same_path(
            final_path(parent).map_err(workspace_error)?,
            &context.parent_path,
        )
    {
        return Err(CleanupReceiptError::Rejected(
            "cleanup receipt parent identity changed".to_owned(),
        ));
    }
    Ok(())
}

fn open_receipt(path: &Path, publishable: bool) -> Result<File, CleanupReceiptError> {
    let mut access =
        FILE_READ_ATTRIBUTES.0 | FILE_READ_EA.0 | FILE_READ_DATA.0 | READ_CONTROL.0 | SYNCHRONIZE.0;
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT.0;
    if publishable {
        access |= DELETE.0 | FILE_WRITE_DATA.0;
        flags |= FILE_FLAG_WRITE_THROUGH.0;
    }
    OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| native_io("CreateFileW(cleanup-receipt)", error))
}

fn verify_shape(
    file: &File,
    parent: &File,
    expected_path: &Path,
    context: &Context,
) -> Result<(), CleanupReceiptError> {
    verify_owner_system_acl(file, &context.owner, true, false).map_err(workspace_error)?;
    let basic = map_exact(basic_info(file))?;
    if basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        || basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || basic.dwFileAttributes & FORBIDDEN_ATTRIBUTES != 0
    {
        return Err(CleanupReceiptError::Rejected(
            "cleanup receipt is not ordinary non-reparse file".to_owned(),
        ));
    }
    let standard = map_exact(standard_info(file))?;
    if standard.Directory || standard.DeletePending || standard.NumberOfLinks != 1 {
        return Err(CleanupReceiptError::Rejected(
            "cleanup receipt type, disposition, or link count changed".to_owned(),
        ));
    }
    let id = map_exact(stable_id(file))?;
    if id_evidence(id.clone()).volume_serial_number != context.parent_expected.volume_serial_number
        || id_evidence(id.clone()) == context.parent_expected
    {
        return Err(CleanupReceiptError::Rejected(
            "cleanup receipt identity is invalid".to_owned(),
        ));
    }
    let leaf =
        expected_path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(CleanupReceiptError::Contract(
                "cleanup receipt leaf is invalid",
            ))?;
    let entry = map_exact(exact_directory_entry(parent, leaf))?;
    if entry.file_id != id.file_id || entry.attributes != basic.dwFileAttributes {
        return Err(CleanupReceiptError::Rejected(
            "cleanup receipt parent entry or alias policy changed".to_owned(),
        ));
    }
    if !same_path(final_path(file).map_err(workspace_error)?, expected_path) {
        return Err(CleanupReceiptError::Rejected(
            "cleanup receipt path changed".to_owned(),
        ));
    }
    Ok(())
}

fn verify_receipt(
    file: &File,
    parent: &File,
    expected_path: &Path,
    context: &Context,
    expected: &CleanupReceiptBindingEvidence,
) -> Result<(), CleanupReceiptError> {
    verify_shape(file, parent, expected_path, context)?;
    if id_evidence(map_exact(stable_id(file))?) != expected.receipt_id
        || map_exact(file_size(file))? != expected.receipt_size
        || hex::encode(map_exact(hash_file(file, expected.receipt_size))?)
            != expected.receipt_sha256
    {
        return Err(CleanupReceiptError::Rejected(
            "cleanup receipt identity, size, or content changed".to_owned(),
        ));
    }
    let ea = ea_evidence(query_extended_attributes(file, false).map_err(exact_error)?);
    if !same_ea(&ea, &expected.receipt_ea) {
        return Err(CleanupReceiptError::Rejected(
            "cleanup receipt extended attributes changed".to_owned(),
        ));
    }
    verify_stream_policy(file, false, expected.receipt_size).map_err(exact_error)
}

fn reopen_stabilized(
    path: &Path,
    initial: &StableFileId,
) -> Result<(File, DiscardIntentEaBinding), CleanupReceiptError> {
    let mut previous = None;
    for attempt in 0..EA_STABILIZATION_ATTEMPTS {
        let file = open_receipt(path, false)?;
        if &map_exact(stable_id(&file))? != initial {
            return Err(CleanupReceiptError::Rejected(
                "cleanup receipt identity changed during close/reopen".to_owned(),
            ));
        }
        match query_extended_attributes(&file, false) {
            Ok(value) => {
                let observed = ea_evidence(value);
                if previous
                    .as_ref()
                    .is_some_and(|prior| same_ea(prior, &observed))
                    && (!observed.entries.is_empty() || attempt + 1 == EA_STABILIZATION_ATTEMPTS)
                {
                    return Ok((file, observed));
                }
                previous = Some(observed);
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
    Err(CleanupReceiptError::Rejected(
        "cleanup receipt EAs did not stabilize".to_owned(),
    ))
}

fn validate_bytes(
    bytes: &[u8],
    sha: &str,
    parent: &DiscardIntentStableId,
    receipt: &DiscardIntentStableId,
) -> Result<(), CleanupReceiptError> {
    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
        return Err(CleanupReceiptError::Contract(
            "cleanup receipt bytes are empty or exceed fixed bound",
        ));
    }
    if sha.len() != 64 || !is_lower_hex(sha) || hex::encode(Sha256::digest(bytes)) != sha {
        return Err(CleanupReceiptError::Contract(
            "cleanup receipt SHA-256 is invalid or does not match",
        ));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| CleanupReceiptError::Contract("cleanup receipt is not valid JSON"))?;
    if serde_json::to_vec(&value)
        .map_err(|_| CleanupReceiptError::Contract("cleanup receipt could not be canonicalized"))?
        != bytes
    {
        return Err(CleanupReceiptError::Contract(
            "cleanup receipt is not canonical",
        ));
    }
    let object = value.get("receiptFile").and_then(Value::as_object).ok_or(
        CleanupReceiptError::Contract("cleanup receipt file identity is missing"),
    )?;
    let actual_parent: DiscardIntentStableId =
        serde_json::from_value(object.get("parentId").cloned().ok_or(
            CleanupReceiptError::Contract("cleanup receipt parent identity is missing"),
        )?)
        .map_err(|_| CleanupReceiptError::Contract("cleanup receipt parent identity is invalid"))?;
    let actual_receipt: DiscardIntentStableId =
        serde_json::from_value(object.get("fileId").cloned().ok_or(
            CleanupReceiptError::Contract("cleanup receipt file identity is missing"),
        )?)
        .map_err(|_| CleanupReceiptError::Contract("cleanup receipt file identity is invalid"))?;
    if &actual_parent != parent || &actual_receipt != receipt {
        return Err(CleanupReceiptError::Rejected(
            "cleanup receipt self-binding does not match reserved identity".to_owned(),
        ));
    }
    Ok(())
}

fn validate_projection(
    expected: &CleanupReceiptBindingEvidence,
    context: &Context,
    size: u64,
    sha: &str,
) -> Result<(), CleanupReceiptError> {
    if expected.schema_version != CLEANUP_RECEIPT_BINDING_SCHEMA_VERSION
        || expected.policy_version != CLEANUP_RECEIPT_BINDING_POLICY_VERSION
        || expected.run_id.is_empty()
        || expected.run_id != expected.run_id.trim()
        || expected.owner_sid != context.owner_sid
        || expected.store_key != context.store_key
        || !same_path(&expected.final_path, &context.final_path)
        || !same_path(&expected.pending_path, &context.pending_path)
        || expected.parent_id != context.parent_expected
        || expected.receipt_size != size
        || expected.receipt_sha256 != sha
        || !valid_id(&expected.parent_id)
        || !valid_id(&expected.receipt_id)
        || expected.receipt_id == expected.parent_id
        || expected.receipt_id.volume_serial_number != expected.parent_id.volume_serial_number
        || !valid_ea(&expected.receipt_ea)
    {
        return Err(CleanupReceiptError::Contract(
            "persisted cleanup receipt binding is invalid",
        ));
    }
    Ok(())
}

fn clear_short_name(file: &File) -> Result<(), CleanupReceiptError> {
    let empty = [0_u16];
    unsafe { SetFileShortNameW(raw_handle(file), PCWSTR(empty.as_ptr())) }.map_err(|error| {
        CleanupReceiptError::Native {
            operation: "SetFileShortNameW(clear)",
            detail: error.to_string(),
        }
    })
}
fn namespace_present(path: &Path) -> Result<bool, CleanupReceiptError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(native_io("GetFileAttributesW(namespace)", error)),
    }
}
fn same_ea(left: &DiscardIntentEaBinding, right: &DiscardIntentEaBinding) -> bool {
    left.entries == right.entries && left.canonical_sha256 == right.canonical_sha256
}
fn valid_ea(value: &DiscardIntentEaBinding) -> bool {
    let names = value.entries.is_empty()
        || (value.entries.len() == ALLOWED_KERNEL_EAS.len()
            && value
                .entries
                .iter()
                .zip(ALLOWED_KERNEL_EAS)
                .all(|(entry, allowed)| entry.name == allowed));
    value.queried_bytes <= 64 * 1024
        && value.canonical_sha256.len() == 64
        && is_lower_hex(&value.canonical_sha256)
        && names
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
fn coordination_error(error: RunCoordinationError) -> CleanupReceiptError {
    match error {
        RunCoordinationError::InvalidBinding(detail) => CleanupReceiptError::Contract(detail),
        other => CleanupReceiptError::Rejected(other.to_string()),
    }
}
fn workspace_error(error: crate::workspace::WorkspaceError) -> CleanupReceiptError {
    CleanupReceiptError::Rejected(error.to_string())
}
fn exact_error(error: crate::exact_dispose::ExactDisposeError) -> CleanupReceiptError {
    CleanupReceiptError::Rejected(error.to_string())
}
fn map_exact<T>(
    result: Result<T, crate::exact_dispose::ExactDisposeError>,
) -> Result<T, CleanupReceiptError> {
    result.map_err(exact_error)
}
fn native_io(operation: &'static str, error: std::io::Error) -> CleanupReceiptError {
    CleanupReceiptError::Native {
        operation,
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::{HeldRunWorkspace, create_owner_system_directory};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    const RUN_ID: &str = "run-one";
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        outer: PathBuf,
        parent: PathBuf,
        workspace: HeldRunWorkspace,
    }
    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let outer = std::env::temp_dir().join(format!(
                "aiw-cleanup-receipt-{}-{nonce}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&outer).unwrap();
            let outer = outer.canonicalize().unwrap();
            let seed = HeldRunWorkspace::create(&outer, "seed").unwrap();
            let owner = seed.evidence().owner_sid.clone();
            let seed_path = seed.root_path().to_owned();
            drop(seed);
            fs::remove_dir_all(seed_path).unwrap();
            let parent = outer.join("protected-parent");
            create_owner_system_directory(&parent, &owner).unwrap();
            let parent = parent.canonicalize().unwrap();
            let workspace = HeldRunWorkspace::create(&parent, "workspace").unwrap();
            Self {
                outer,
                parent,
                workspace,
            }
        }
        fn key(&self) -> String {
            RunCoordinationKey::from_workspace(self.workspace.evidence(), RUN_ID)
                .unwrap()
                .binding_sha256()
                .to_owned()
        }
        fn paths(&self) -> (PathBuf, PathBuf) {
            let key = self.key();
            (
                self.parent.join(format!("{PENDING_PREFIX}{key}.json")),
                self.parent.join(format!("{FINAL_PREFIX}{key}.json")),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.outer);
        }
    }
    fn bytes(receipt: &ReservedCleanupReceipt) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"receiptFile":{"parentId":receipt.parent_id(),"fileId":receipt.receipt_id()}})).unwrap()
    }

    #[test]
    fn native_roundtrip_classifier_and_write_exclusion() {
        let fixture = Fixture::new();
        let key = fixture.key();
        assert_eq!(
            classify_cleanup_receipt_slot(fixture.workspace.evidence(), RUN_ID, &key).unwrap(),
            CleanupReceiptSlotState::Absent
        );
        let reserved = reserve_cleanup_receipt(fixture.workspace.evidence(), RUN_ID, &key).unwrap();
        assert_eq!(
            classify_cleanup_receipt_slot(fixture.workspace.evidence(), RUN_ID, &key).unwrap(),
            CleanupReceiptSlotState::Pending
        );
        let body = bytes(&reserved);
        let sha = hex::encode(Sha256::digest(&body));
        let staged = reserved.persist(&body, &sha).unwrap();
        let evidence = staged.evidence().clone();
        drop(staged);
        let reopened = reopen_prepared_cleanup_receipt(
            &body,
            &sha,
            fixture.workspace.evidence(),
            RUN_ID,
            &evidence,
        )
        .unwrap();
        let held = match reopened {
            ReopenedCleanupReceipt::Publishable(value) => value.publish().unwrap(),
            ReopenedCleanupReceipt::Published(_) => panic!(),
        };
        let (_, final_path) = fixture.paths();
        assert!(final_path.is_file());
        assert_eq!(
            classify_cleanup_receipt_slot(fixture.workspace.evidence(), RUN_ID, &key).unwrap(),
            CleanupReceiptSlotState::Published
        );
        assert!(OpenOptions::new().write(true).open(final_path).is_err());
        held.revalidate().unwrap();
    }

    #[test]
    fn native_dual_hardlink_and_readonly_drift_fail_closed() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let reserved = reserve_cleanup_receipt(fixture.workspace.evidence(), RUN_ID, &key).unwrap();
        let body = bytes(&reserved);
        let sha = hex::encode(Sha256::digest(&body));
        let staged = reserved.persist(&body, &sha).unwrap();
        let evidence = staged.evidence().clone();
        let (pending, final_path) = fixture.paths();
        drop(staged);
        fs::write(&final_path, b"foreign").unwrap();
        assert_eq!(
            classify_cleanup_receipt_slot(fixture.workspace.evidence(), RUN_ID, &key).unwrap(),
            CleanupReceiptSlotState::Ambiguous
        );
        assert!(
            reopen_existing_cleanup_receipt(fixture.workspace.evidence(), RUN_ID, &key).is_err()
        );
        fs::remove_file(&final_path).unwrap();
        fs::hard_link(&pending, fixture.parent.join("foreign-hardlink")).unwrap();
        assert!(
            reopen_prepared_cleanup_receipt(
                &body,
                &sha,
                fixture.workspace.evidence(),
                RUN_ID,
                &evidence
            )
            .is_err()
        );
        let mut permissions = fs::metadata(&pending).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&pending, permissions).unwrap();
        assert!(
            reopen_prepared_cleanup_receipt(
                &body,
                &sha,
                fixture.workspace.evidence(),
                RUN_ID,
                &evidence
            )
            .is_err()
        );
    }

    #[test]
    fn native_acl_drift_and_partial_fail_closed() {
        use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows::Win32::Storage::FileSystem::WRITE_DAC;
        let fixture = Fixture::new();
        let key = fixture.key();
        let reserved = reserve_cleanup_receipt(fixture.workspace.evidence(), RUN_ID, &key).unwrap();
        let body = bytes(&reserved);
        let sha = hex::encode(Sha256::digest(&body));
        let staged = reserved.persist(&body, &sha).unwrap();
        let evidence = staged.evidence().clone();
        let (pending, _) = fixture.paths();
        drop(staged);
        let handle = OpenOptions::new()
            .access_mode(READ_CONTROL.0 | WRITE_DAC.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
            .open(&pending)
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
            reopen_prepared_cleanup_receipt(
                &body,
                &sha,
                fixture.workspace.evidence(),
                RUN_ID,
                &evidence
            )
            .is_err()
        );
        let fixture = Fixture::new();
        let key = fixture.key();
        let reserved = reserve_cleanup_receipt(fixture.workspace.evidence(), RUN_ID, &key).unwrap();
        drop(reserved);
        assert!(
            reopen_existing_cleanup_receipt(fixture.workspace.evidence(), RUN_ID, &key).is_err()
        );
    }

    #[test]
    fn production_has_no_destructive_or_provider_operation() {
        let production = include_str!("cleanup_receipt.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "remove_file",
            "remove_dir",
            "FileDispositionInfo",
            "acquire_windows_sandbox",
            "rename(",
        ] {
            assert!(!production.contains(forbidden), "found {forbidden}");
        }
        assert_eq!(production.matches("rename_relative(").count(), 1);
    }
}
