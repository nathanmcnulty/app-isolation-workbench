//! Protected external publication of one immutable disposition-progress record.
//!
//! Each of the nineteen records has an ordinal-bound deterministic pending and
//! final name. The boundary is deliberately write-once: it creates a new
//! protected pending file, persists and reopens it, then performs one
//! non-replacing handle-relative rename. It never deletes, overwrites, adopts,
//! or invokes a provider.

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

pub const DISPOSITION_PROGRESS_BINDING_SCHEMA_VERSION: &str =
    "aiw.dev/wsb-disposition-progress-binding/v1";
pub const DISPOSITION_PROGRESS_BINDING_POLICY_VERSION: &str =
    "owner-system-protected-disposition-progress-v1";
pub const DISPOSITION_PROGRESS_RECORD_COUNT: u8 = 19;
const FINAL_PREFIX: &str = ".aiw-discard-disposition-v1-";
const PENDING_PREFIX: &str = ".aiw-discard-disposition-pending-v1-";
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const EA_STABILIZATION_ATTEMPTS: usize = 40;

/// Namespace-only state for one deterministic disposition slot.
///
/// This deliberately reports occupancy without opening, adopting, repairing,
/// or deleting either object. Any occupied namespace, including a malformed
/// or foreign object, is therefore non-`Absent`; strict reopen remains the
/// authority for validating `Pending` and `Published` objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispositionProgressSlotState {
    Absent,
    Pending,
    Published,
    Ambiguous,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispositionProgressBindingEvidence {
    pub schema_version: String,
    pub policy_version: String,
    pub run_id: String,
    pub owner_sid: String,
    pub store_key: String,
    pub ordinal: u8,
    pub final_path: String,
    pub pending_path: String,
    pub parent_id: DiscardIntentStableId,
    pub record_id: DiscardIntentStableId,
    pub record_size: u64,
    pub record_sha256: String,
    pub record_ea: DiscardIntentEaBinding,
}

impl DispositionProgressBindingEvidence {
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
    pub fn ordinal(&self) -> u8 {
        self.ordinal
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
    pub fn record_id(&self) -> &DiscardIntentStableId {
        &self.record_id
    }
    pub fn record_size(&self) -> u64 {
        self.record_size
    }
    pub fn record_sha256(&self) -> &str {
        &self.record_sha256
    }
    pub fn record_ea(&self) -> &DiscardIntentEaBinding {
        &self.record_ea
    }
}

#[derive(Debug, Error)]
pub enum DispositionProgressError {
    #[error("disposition-progress contract is invalid: {0}")]
    Contract(&'static str),
    #[error("disposition-progress authority or identity was rejected: {0}")]
    Rejected(String),
    #[error("disposition-progress native operation failed at {operation}: {detail}")]
    Native {
        operation: &'static str,
        detail: String,
    },
    #[error("disposition-progress final namespace conflicts with an existing object")]
    FinalConflict,
    #[error("disposition-progress pending namespace conflicts with an existing object")]
    PendingConflict,
}

#[must_use]
pub struct ReservedDispositionProgress {
    evidence: DispositionProgressBindingEvidence,
    parent: File,
    record: File,
}

impl ReservedDispositionProgress {
    pub fn evidence(&self) -> &DispositionProgressBindingEvidence {
        &self.evidence
    }
    pub fn parent_id(&self) -> &DiscardIntentStableId {
        &self.evidence.parent_id
    }
    pub fn record_id(&self) -> &DiscardIntentStableId {
        &self.evidence.record_id
    }
    pub fn ordinal(&self) -> u8 {
        self.evidence.ordinal
    }
    pub fn persist(
        self,
        bytes: &[u8],
        sha256: &str,
    ) -> Result<StagedDispositionProgress, DispositionProgressError> {
        validate_bytes(
            bytes,
            sha256,
            &self.evidence.parent_id,
            &self.evidence.record_id,
            self.evidence.ordinal,
        )?;
        let mut record = self.record;
        record
            .write_all(bytes)
            .map_err(|error| native_io("WriteFile(disposition-progress)", error))?;
        record
            .sync_all()
            .map_err(|error| native_io("FlushFileBuffers(disposition-progress)", error))?;
        let initial = map_exact(stable_id(&record))?;
        if id_evidence(initial.clone()) != self.evidence.record_id {
            return Err(DispositionProgressError::Rejected(
                "reserved record identity changed before persist".to_owned(),
            ));
        }
        drop(record);
        let (record, ea) = reopen_stabilized(Path::new(&self.evidence.pending_path), &initial)?;
        let mut evidence = self.evidence;
        evidence.record_size = bytes.len() as u64;
        evidence.record_sha256 = sha256.to_owned();
        evidence.record_ea = ea;
        let context = Context::from_projection(&evidence)?;
        verify_record(
            &record,
            &self.parent,
            &context.pending_path,
            &context,
            &evidence,
        )?;
        Ok(StagedDispositionProgress {
            evidence,
            _parent: self.parent,
            _record: record,
            bytes: bytes.to_owned(),
        })
    }
}

#[must_use]
pub struct StagedDispositionProgress {
    evidence: DispositionProgressBindingEvidence,
    _parent: File,
    _record: File,
    bytes: Vec<u8>,
}
impl StagedDispositionProgress {
    pub fn evidence(&self) -> &DispositionProgressBindingEvidence {
        &self.evidence
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[must_use]
pub struct PublishableDispositionProgress {
    evidence: DispositionProgressBindingEvidence,
    parent: File,
    record: File,
    bytes: Vec<u8>,
}
impl PublishableDispositionProgress {
    pub fn publish(self) -> Result<HeldDispositionProgressPublication, DispositionProgressError> {
        let context = Context::from_projection(&self.evidence)?;
        if namespace_present(&context.final_path)? {
            return Err(DispositionProgressError::FinalConflict);
        }
        verify_parent(&self.parent, &context, &self.evidence.parent_id)?;
        verify_record(
            &self.record,
            &self.parent,
            &context.pending_path,
            &context,
            &self.evidence,
        )?;
        rename_relative(&self.record, &self.parent, OsStr::new(&context.final_leaf))
            .map_err(exact_error)?;
        self.record
            .sync_all()
            .map_err(|error| native_io("FlushFileBuffers(disposition-after-rename)", error))?;
        drop(self.record);
        let final_record = open_record(&context.final_path, false)?;
        verify_record(
            &final_record,
            &self.parent,
            &context.final_path,
            &context,
            &self.evidence,
        )?;
        Ok(HeldDispositionProgressPublication {
            evidence: self.evidence,
            _parent: self.parent,
            _record: final_record,
            bytes: self.bytes,
        })
    }
}

#[must_use]
pub struct HeldDispositionProgressPublication {
    evidence: DispositionProgressBindingEvidence,
    _parent: File,
    _record: File,
    bytes: Vec<u8>,
}
impl HeldDispositionProgressPublication {
    pub fn evidence(&self) -> &DispositionProgressBindingEvidence {
        &self.evidence
    }
    pub fn binding(&self) -> &DispositionProgressBindingEvidence {
        &self.evidence
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn ordinal(&self) -> u8 {
        self.evidence.ordinal
    }
    pub fn final_path(&self) -> &str {
        self.evidence.final_path()
    }
    pub fn revalidate(&self) -> Result<(), DispositionProgressError> {
        let context = Context::from_projection(&self.evidence)?;
        verify_parent(&self._parent, &context, &self.evidence.parent_id)?;
        verify_record(
            &self._record,
            &self._parent,
            &context.final_path,
            &context,
            &self.evidence,
        )
    }
}

#[must_use]
pub enum ReopenedDispositionProgress {
    Publishable(PublishableDispositionProgress),
    Published(HeldDispositionProgressPublication),
}

#[must_use]
pub struct ExistingDispositionProgress {
    bytes: Vec<u8>,
    binding: DispositionProgressBindingEvidence,
    reopened: ReopenedDispositionProgress,
}
impl ExistingDispositionProgress {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn binding(&self) -> &DispositionProgressBindingEvidence {
        &self.binding
    }
    pub fn into_reopened(self) -> ReopenedDispositionProgress {
        self.reopened
    }
}

pub fn reserve_disposition_progress(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
    ordinal: u8,
) -> Result<ReservedDispositionProgress, DispositionProgressError> {
    let context = Context::new(workspace, run_id, store_key, ordinal)?;
    let parent = open_parent(&context)?;
    if namespace_present(&context.final_path)? {
        return Err(DispositionProgressError::FinalConflict);
    }
    if namespace_present(&context.pending_path)? {
        return Err(DispositionProgressError::PendingConflict);
    }
    let record = create_owner_system_file(&context.pending_path, &context.owner_sid)
        .map_err(workspace_error)?;
    clear_short_name(&record)?;
    let evidence = DispositionProgressBindingEvidence {
        schema_version: DISPOSITION_PROGRESS_BINDING_SCHEMA_VERSION.to_owned(),
        policy_version: DISPOSITION_PROGRESS_BINDING_POLICY_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        owner_sid: workspace.owner_sid.clone(),
        store_key: store_key.to_owned(),
        ordinal,
        final_path: context.final_path.to_string_lossy().into_owned(),
        pending_path: context.pending_path.to_string_lossy().into_owned(),
        parent_id: id_evidence(map_exact(stable_id(&parent))?),
        record_id: id_evidence(map_exact(stable_id(&record))?),
        record_size: 0,
        record_sha256: String::new(),
        record_ea: DiscardIntentEaBinding {
            queried_bytes: 0,
            entries: Vec::new(),
            canonical_sha256: String::new(),
        },
    };
    verify_shape(&record, &parent, &context.pending_path, &context)?;
    Ok(ReservedDispositionProgress {
        evidence,
        parent,
        record,
    })
}

pub fn stage_disposition_progress(
    bytes: &[u8],
    sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
    ordinal: u8,
) -> Result<StagedDispositionProgress, DispositionProgressError> {
    reserve_disposition_progress(workspace, run_id, store_key, ordinal)?.persist(bytes, sha256)
}

/// Classify exact pending/final namespace occupancy for one disposition slot.
///
/// The classifier is intentionally narrower than strict reopen: it only
/// establishes whether either deterministic name is occupied. This lets the
/// runner prove the nineteen slots form a prefix without parsing error text;
/// malformed, foreign, hard-linked, or otherwise drifted objects remain
/// visibly occupied and are rejected by strict reopen.
pub fn classify_disposition_progress_slot(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
    ordinal: u8,
) -> Result<DispositionProgressSlotState, DispositionProgressError> {
    let context = Context::new(workspace, run_id, store_key, ordinal)?;
    let _parent = open_parent(&context)?;
    match (
        namespace_present(&context.pending_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (false, false) => Ok(DispositionProgressSlotState::Absent),
        (true, false) => Ok(DispositionProgressSlotState::Pending),
        (false, true) => Ok(DispositionProgressSlotState::Published),
        (true, true) => Ok(DispositionProgressSlotState::Ambiguous),
    }
}

pub fn reopen_prepared_disposition_progress(
    bytes: &[u8],
    sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    expected: &DispositionProgressBindingEvidence,
) -> Result<ReopenedDispositionProgress, DispositionProgressError> {
    let context = Context::new(workspace, run_id, &expected.store_key, expected.ordinal)?;
    validate_bytes(
        bytes,
        sha256,
        &expected.parent_id,
        &expected.record_id,
        expected.ordinal,
    )?;
    validate_projection(expected, &context, bytes.len() as u64, sha256)?;
    let parent = open_parent(&context)?;
    match (
        namespace_present(&context.pending_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (true, false) => {
            let record = open_record(&context.pending_path, true)?;
            verify_record(&record, &parent, &context.pending_path, &context, expected)?;
            Ok(ReopenedDispositionProgress::Publishable(
                PublishableDispositionProgress {
                    evidence: expected.clone(),
                    parent,
                    record,
                    bytes: bytes.to_owned(),
                },
            ))
        }
        (false, true) => {
            let record = open_record(&context.final_path, false)?;
            verify_record(&record, &parent, &context.final_path, &context, expected)?;
            Ok(ReopenedDispositionProgress::Published(
                HeldDispositionProgressPublication {
                    evidence: expected.clone(),
                    _parent: parent,
                    _record: record,
                    bytes: bytes.to_owned(),
                },
            ))
        }
        (true, true) => Err(DispositionProgressError::Rejected(
            "pending and final disposition records are both present".to_owned(),
        )),
        (false, false) => Err(DispositionProgressError::Rejected(
            "neither pending nor final disposition record is present".to_owned(),
        )),
    }
}

pub fn reopen_existing_disposition_progress(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
    ordinal: u8,
) -> Result<ExistingDispositionProgress, DispositionProgressError> {
    let context = Context::new(workspace, run_id, store_key, ordinal)?;
    let parent = open_parent(&context)?;
    let (path, publishable) = match (
        namespace_present(&context.pending_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (true, false) => (&context.pending_path, true),
        (false, true) => (&context.final_path, false),
        (true, true) => {
            return Err(DispositionProgressError::Rejected(
                "pending and final disposition records are both present".to_owned(),
            ));
        }
        (false, false) => {
            return Err(DispositionProgressError::Rejected(
                "neither pending nor final disposition record is present".to_owned(),
            ));
        }
    };
    let record = open_record(path, publishable)?;
    verify_shape(&record, &parent, path, &context)?;
    let size = map_exact(file_size(&record))?;
    if size == 0 || size > MAX_RECORD_BYTES as u64 {
        return Err(DispositionProgressError::Rejected(
            "existing disposition record size is outside fixed bound".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    (&record)
        .take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| native_io("ReadFile(disposition-progress)", error))?;
    if bytes.len() as u64 != size {
        return Err(DispositionProgressError::Rejected(
            "existing disposition record length changed".to_owned(),
        ));
    }
    let file_id = id_evidence(map_exact(stable_id(&record))?);
    let parent_id = context.parent_expected.clone();
    let sha = hex::encode(Sha256::digest(&bytes));
    let ea = ea_evidence(query_extended_attributes(&record, false).map_err(exact_error)?);
    if !valid_ea(&ea) {
        return Err(DispositionProgressError::Rejected(
            "existing disposition record EAs are invalid".to_owned(),
        ));
    }
    validate_bytes(&bytes, &sha, &parent_id, &file_id, ordinal)?;
    let binding = DispositionProgressBindingEvidence {
        schema_version: DISPOSITION_PROGRESS_BINDING_SCHEMA_VERSION.to_owned(),
        policy_version: DISPOSITION_PROGRESS_BINDING_POLICY_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        owner_sid: workspace.owner_sid.clone(),
        store_key: store_key.to_owned(),
        ordinal,
        final_path: context.final_path.to_string_lossy().into_owned(),
        pending_path: context.pending_path.to_string_lossy().into_owned(),
        parent_id,
        record_id: file_id,
        record_size: size,
        record_sha256: sha.clone(),
        record_ea: ea,
    };
    validate_projection(&binding, &context, size, &sha)?;
    verify_record(&record, &parent, path, &context, &binding)?;
    let reopened = if publishable {
        ReopenedDispositionProgress::Publishable(PublishableDispositionProgress {
            evidence: binding.clone(),
            parent,
            record,
            bytes: bytes.clone(),
        })
    } else {
        ReopenedDispositionProgress::Published(HeldDispositionProgressPublication {
            evidence: binding.clone(),
            _parent: parent,
            _record: record,
            bytes: bytes.clone(),
        })
    };
    Ok(ExistingDispositionProgress {
        bytes,
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
    ordinal: u8,
    owner: OwnedSid,
    owner_sid: String,
    parent_expected: DiscardIntentStableId,
}
impl Context {
    fn new(
        workspace: &WorkspaceBindingEvidence,
        run_id: &str,
        store_key: &str,
        ordinal: u8,
    ) -> Result<Self, DispositionProgressError> {
        if !valid_ordinal(ordinal) {
            return Err(DispositionProgressError::Contract(
                "disposition ordinal must be in 0..=18",
            ));
        }
        workspace
            .validate()
            .map_err(|_| DispositionProgressError::Contract("workspace binding is invalid"))?;
        let key =
            RunCoordinationKey::from_workspace(workspace, run_id).map_err(coordination_error)?;
        if key.binding_sha256() != store_key {
            return Err(DispositionProgressError::Contract(
                "disposition store key is not derived from workspace/run",
            ));
        }
        let parent_path = PathBuf::from(&workspace.parent.final_path);
        if Path::new(&workspace.root.final_path)
            .parent()
            .is_none_or(|path| !same_path(path, &parent_path))
        {
            return Err(DispositionProgressError::Contract(
                "workspace root does not belong to its parent",
            ));
        }
        if !is_fixed_volume(&parent_path).map_err(workspace_error)? {
            return Err(DispositionProgressError::Rejected(
                "disposition parent is not fixed local volume".to_owned(),
            ));
        }
        let final_leaf = format!("{FINAL_PREFIX}{store_key}-{ordinal:02}.json");
        let pending_leaf = format!("{PENDING_PREFIX}{store_key}-{ordinal:02}.json");
        Ok(Self {
            final_path: parent_path.join(&final_leaf),
            pending_path: parent_path.join(&pending_leaf),
            final_leaf,
            parent_path,
            store_key: store_key.to_owned(),
            ordinal,
            owner: OwnedSid::from_string(&workspace.owner_sid).map_err(workspace_error)?,
            owner_sid: workspace.owner_sid.clone(),
            parent_expected: DiscardIntentStableId {
                volume_serial_number: workspace.parent.volume_serial_number.clone(),
                file_id: workspace.parent.file_id.clone(),
            },
        })
    }
    fn from_projection(
        value: &DispositionProgressBindingEvidence,
    ) -> Result<Self, DispositionProgressError> {
        let final_path = PathBuf::from(&value.final_path);
        let pending_path = PathBuf::from(&value.pending_path);
        let parent_path = final_path
            .parent()
            .ok_or(DispositionProgressError::Contract(
                "disposition final path has no parent",
            ))?
            .to_owned();
        let final_leaf = final_path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(DispositionProgressError::Contract(
                "disposition final leaf is invalid",
            ))?
            .to_owned();
        Ok(Self {
            parent_path,
            final_leaf,
            final_path,
            pending_path,
            store_key: value.store_key.clone(),
            ordinal: value.ordinal,
            owner: OwnedSid::from_string(&value.owner_sid).map_err(workspace_error)?,
            owner_sid: value.owner_sid.clone(),
            parent_expected: value.parent_id.clone(),
        })
    }
}

fn open_parent(context: &Context) -> Result<File, DispositionProgressError> {
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
        .map_err(|error| native_io("CreateFileW(disposition-parent)", error))?;
    verify_parent(&file, context, &context.parent_expected)?;
    Ok(file)
}
fn verify_parent(
    parent: &File,
    context: &Context,
    expected: &DiscardIntentStableId,
) -> Result<(), DispositionProgressError> {
    verify_local_acl_volume(parent).map_err(workspace_error)?;
    reject_case_sensitive_directory(parent).map_err(exact_error)?;
    verify_owner_system_acl(parent, &context.owner, true, true).map_err(|_| {
        DispositionProgressError::Rejected(
            "disposition parent is not owner-and-SYSTEM protected".to_owned(),
        )
    })?;
    if id_evidence(map_exact(stable_id(parent))?) != *expected
        || !same_path(
            final_path(parent).map_err(workspace_error)?,
            &context.parent_path,
        )
    {
        return Err(DispositionProgressError::Rejected(
            "disposition parent identity changed".to_owned(),
        ));
    }
    Ok(())
}
fn open_record(path: &Path, publishable: bool) -> Result<File, DispositionProgressError> {
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
        .map_err(|error| native_io("CreateFileW(disposition-record)", error))
}
fn verify_shape(
    file: &File,
    parent: &File,
    expected_path: &Path,
    context: &Context,
) -> Result<(), DispositionProgressError> {
    verify_owner_system_acl(file, &context.owner, true, false).map_err(workspace_error)?;
    let basic = map_exact(basic_info(file))?;
    if basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        || basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || basic.dwFileAttributes & FORBIDDEN_ATTRIBUTES != 0
    {
        return Err(DispositionProgressError::Rejected(
            "disposition record is not ordinary non-reparse file".to_owned(),
        ));
    }
    let standard = map_exact(standard_info(file))?;
    if standard.Directory || standard.DeletePending || standard.NumberOfLinks != 1 {
        return Err(DispositionProgressError::Rejected(
            "disposition record type, disposition, or link count changed".to_owned(),
        ));
    }
    let id = map_exact(stable_id(file))?;
    if id_evidence(id.clone()).volume_serial_number != context.parent_expected.volume_serial_number
        || id_evidence(id.clone()) == context.parent_expected
    {
        return Err(DispositionProgressError::Rejected(
            "disposition record identity is invalid".to_owned(),
        ));
    }
    let leaf = expected_path.file_name().and_then(|v| v.to_str()).ok_or(
        DispositionProgressError::Contract("disposition leaf is invalid"),
    )?;
    let entry = map_exact(exact_directory_entry(parent, leaf))?;
    if entry.file_id != id.file_id || entry.attributes != basic.dwFileAttributes {
        return Err(DispositionProgressError::Rejected(
            "disposition parent entry or alias policy changed".to_owned(),
        ));
    }
    if !same_path(final_path(file).map_err(workspace_error)?, expected_path) {
        return Err(DispositionProgressError::Rejected(
            "disposition record path changed".to_owned(),
        ));
    }
    Ok(())
}
fn verify_record(
    file: &File,
    parent: &File,
    expected_path: &Path,
    context: &Context,
    expected: &DispositionProgressBindingEvidence,
) -> Result<(), DispositionProgressError> {
    verify_shape(file, parent, expected_path, context)?;
    let id = id_evidence(map_exact(stable_id(file))?);
    if id != expected.record_id
        || map_exact(file_size(file))? != expected.record_size
        || hex::encode(map_exact(hash_file(file, expected.record_size))?) != expected.record_sha256
    {
        return Err(DispositionProgressError::Rejected(
            "disposition record identity, size, or content changed".to_owned(),
        ));
    }
    let ea = ea_evidence(query_extended_attributes(file, false).map_err(exact_error)?);
    if !same_ea(&ea, &expected.record_ea) {
        return Err(DispositionProgressError::Rejected(
            "disposition record extended attributes changed".to_owned(),
        ));
    }
    verify_stream_policy(file, false, expected.record_size).map_err(exact_error)
}
fn reopen_stabilized(
    path: &Path,
    initial: &StableFileId,
) -> Result<(File, DiscardIntentEaBinding), DispositionProgressError> {
    let mut previous = None;
    for attempt in 0..EA_STABILIZATION_ATTEMPTS {
        let file = open_record(path, false)?;
        if &map_exact(stable_id(&file))? != initial {
            return Err(DispositionProgressError::Rejected(
                "disposition identity changed during close/reopen".to_owned(),
            ));
        }
        match query_extended_attributes(&file, false) {
            Ok(value) => {
                let observed = ea_evidence(value);
                if previous
                    .as_ref()
                    .is_some_and(|prior| same_ea(prior, &observed))
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
    Err(DispositionProgressError::Rejected(
        "disposition EAs did not stabilize".to_owned(),
    ))
}
fn validate_bytes(
    bytes: &[u8],
    sha: &str,
    parent: &DiscardIntentStableId,
    record: &DiscardIntentStableId,
    ordinal: u8,
) -> Result<(), DispositionProgressError> {
    if !valid_ordinal(ordinal) {
        return Err(DispositionProgressError::Contract(
            "disposition ordinal must be in 0..=18",
        ));
    }
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(DispositionProgressError::Contract(
            "disposition bytes are empty or exceed fixed bound",
        ));
    }
    if sha.len() != 64 || !is_lower_hex(sha) || hex::encode(Sha256::digest(bytes)) != sha {
        return Err(DispositionProgressError::Contract(
            "disposition SHA-256 is invalid or does not match",
        ));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| DispositionProgressError::Contract("disposition record is not valid JSON"))?;
    if serde_json::to_vec(&value).map_err(|_| {
        DispositionProgressError::Contract("disposition record could not be canonicalized")
    })? != bytes
    {
        return Err(DispositionProgressError::Contract(
            "disposition record is not canonical",
        ));
    }
    let object = value.get("recordFile").and_then(Value::as_object).ok_or(
        DispositionProgressError::Contract("disposition record file identity is missing"),
    )?;
    let actual_parent: DiscardIntentStableId =
        serde_json::from_value(object.get("parentId").cloned().ok_or(
            DispositionProgressError::Contract("disposition parent identity is missing"),
        )?)
        .map_err(|_| {
            DispositionProgressError::Contract("disposition parent identity is invalid")
        })?;
    let actual_record: DiscardIntentStableId =
        serde_json::from_value(object.get("fileId").cloned().ok_or(
            DispositionProgressError::Contract("disposition record identity is missing"),
        )?)
        .map_err(|_| {
            DispositionProgressError::Contract("disposition record identity is invalid")
        })?;
    let actual_ordinal = object
        .get("ordinal")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .ok_or(DispositionProgressError::Contract(
            "disposition ordinal is missing",
        ))?;
    if &actual_parent != parent || &actual_record != record || actual_ordinal != ordinal {
        return Err(DispositionProgressError::Rejected(
            "disposition record self-binding does not match reserved identity".to_owned(),
        ));
    }
    Ok(())
}
fn valid_ordinal(ordinal: u8) -> bool {
    ordinal < DISPOSITION_PROGRESS_RECORD_COUNT
}
fn validate_projection(
    expected: &DispositionProgressBindingEvidence,
    context: &Context,
    size: u64,
    sha: &str,
) -> Result<(), DispositionProgressError> {
    if expected.schema_version != DISPOSITION_PROGRESS_BINDING_SCHEMA_VERSION
        || expected.policy_version != DISPOSITION_PROGRESS_BINDING_POLICY_VERSION
        || expected.run_id.is_empty()
        || expected.run_id != expected.run_id.trim()
        || expected.owner_sid != context.owner_sid
        || expected.store_key != context.store_key
        || expected.ordinal != context.ordinal
        || !same_path(&expected.final_path, &context.final_path)
        || !same_path(&expected.pending_path, &context.pending_path)
        || expected.parent_id != context.parent_expected
        || expected.record_size != size
        || expected.record_sha256 != sha
        || !valid_id(&expected.parent_id)
        || !valid_id(&expected.record_id)
        || expected.record_id == expected.parent_id
        || expected.record_id.volume_serial_number != expected.parent_id.volume_serial_number
        || !valid_ea(&expected.record_ea)
    {
        return Err(DispositionProgressError::Contract(
            "persisted disposition binding is invalid",
        ));
    }
    Ok(())
}
fn clear_short_name(file: &File) -> Result<(), DispositionProgressError> {
    let empty = [0_u16];
    unsafe { SetFileShortNameW(raw_handle(file), PCWSTR(empty.as_ptr())) }.map_err(|error| {
        DispositionProgressError::Native {
            operation: "SetFileShortNameW(clear)",
            detail: error.to_string(),
        }
    })
}
fn namespace_present(path: &Path) -> Result<bool, DispositionProgressError> {
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
fn coordination_error(error: RunCoordinationError) -> DispositionProgressError {
    match error {
        RunCoordinationError::InvalidBinding(detail) => DispositionProgressError::Contract(detail),
        other => DispositionProgressError::Rejected(other.to_string()),
    }
}
fn workspace_error(error: crate::workspace::WorkspaceError) -> DispositionProgressError {
    DispositionProgressError::Rejected(error.to_string())
}
fn exact_error(error: crate::exact_dispose::ExactDisposeError) -> DispositionProgressError {
    DispositionProgressError::Rejected(error.to_string())
}
fn map_exact<T>(
    result: Result<T, crate::exact_dispose::ExactDisposeError>,
) -> Result<T, DispositionProgressError> {
    result.map_err(exact_error)
}
fn native_io(operation: &'static str, error: std::io::Error) -> DispositionProgressError {
    DispositionProgressError::Native {
        operation,
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::{HeldRunWorkspace, create_owner_system_directory};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    const RUN_ID: &str = "run-one";
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
            let outer = std::env::temp_dir().join(format!("aiw-disposition-{nonce}"));
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
        fn paths(&self, ordinal: u8) -> (PathBuf, PathBuf) {
            let key = self.key();
            (
                self.parent
                    .join(format!("{PENDING_PREFIX}{key}-{ordinal:02}.json")),
                self.parent
                    .join(format!("{FINAL_PREFIX}{key}-{ordinal:02}.json")),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.outer);
        }
    }
    fn bytes(reserved: &ReservedDispositionProgress) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"recordFile":{"ordinal":reserved.ordinal(),"parentId":reserved.parent_id(),"fileId":reserved.record_id()}})).unwrap()
    }
    #[test]
    fn ordinals_and_names_are_fixed() {
        let key = "a".repeat(64);
        for ordinal in 0..DISPOSITION_PROGRESS_RECORD_COUNT {
            assert!(
                format!("{FINAL_PREFIX}{key}-{ordinal:02}.json")
                    .ends_with(&format!("-{ordinal:02}.json"))
            );
            assert!(
                format!("{PENDING_PREFIX}{key}-{ordinal:02}.json")
                    .ends_with(&format!("-{ordinal:02}.json"))
            );
        }
        assert!(!valid_ordinal(DISPOSITION_PROGRESS_RECORD_COUNT));
    }
    #[test]
    fn native_roundtrip_and_write_exclusion() {
        let fixture = Fixture::new();
        let key = fixture.key();
        assert_eq!(
            classify_disposition_progress_slot(fixture.workspace.evidence(), RUN_ID, &key, 3)
                .unwrap(),
            DispositionProgressSlotState::Absent
        );
        let reserved =
            reserve_disposition_progress(fixture.workspace.evidence(), RUN_ID, &key, 3).unwrap();
        assert_eq!(
            classify_disposition_progress_slot(fixture.workspace.evidence(), RUN_ID, &key, 3)
                .unwrap(),
            DispositionProgressSlotState::Pending
        );
        let body = bytes(&reserved);
        let sha = hex::encode(Sha256::digest(&body));
        let staged = reserved.persist(&body, &sha).unwrap();
        let evidence = staged.evidence().clone();
        let (_, final_path) = fixture.paths(3);
        drop(staged);
        let reopened = reopen_prepared_disposition_progress(
            &body,
            &sha,
            fixture.workspace.evidence(),
            RUN_ID,
            &evidence,
        )
        .unwrap();
        let held = match reopened {
            ReopenedDispositionProgress::Publishable(value) => value.publish().unwrap(),
            ReopenedDispositionProgress::Published(_) => panic!(),
        };
        assert!(final_path.is_file());
        assert_eq!(
            classify_disposition_progress_slot(fixture.workspace.evidence(), RUN_ID, &key, 3)
                .unwrap(),
            DispositionProgressSlotState::Published
        );
        assert!(OpenOptions::new().write(true).open(&final_path).is_err());
        held.revalidate().unwrap();
    }
    #[test]
    fn native_dual_hardlink_and_content_drift_fail_closed() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let reserved =
            reserve_disposition_progress(fixture.workspace.evidence(), RUN_ID, &key, 0).unwrap();
        let body = bytes(&reserved);
        let sha = hex::encode(Sha256::digest(&body));
        let staged = reserved.persist(&body, &sha).unwrap();
        let evidence = staged.evidence().clone();
        let (pending, final_path) = fixture.paths(0);
        drop(staged);
        fs::write(&final_path, b"foreign").unwrap();
        assert_eq!(
            classify_disposition_progress_slot(fixture.workspace.evidence(), RUN_ID, &key, 0)
                .unwrap(),
            DispositionProgressSlotState::Ambiguous
        );
        assert!(
            reopen_existing_disposition_progress(fixture.workspace.evidence(), RUN_ID, &key, 0)
                .is_err()
        );
        fs::remove_file(&final_path).unwrap();
        fs::hard_link(&pending, fixture.parent.join("foreign-hardlink")).unwrap();
        assert_eq!(
            classify_disposition_progress_slot(fixture.workspace.evidence(), RUN_ID, &key, 0)
                .unwrap(),
            DispositionProgressSlotState::Pending
        );
        assert!(
            reopen_prepared_disposition_progress(
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
    fn native_partial_and_readonly_fail_closed() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let reserved =
            reserve_disposition_progress(fixture.workspace.evidence(), RUN_ID, &key, 1).unwrap();
        let (_pending, _) = fixture.paths(1);
        drop(reserved);
        assert!(
            reopen_existing_disposition_progress(fixture.workspace.evidence(), RUN_ID, &key, 1)
                .is_err()
        );
        let fixture = Fixture::new();
        let key = fixture.key();
        let reserved =
            reserve_disposition_progress(fixture.workspace.evidence(), RUN_ID, &key, 2).unwrap();
        let body = bytes(&reserved);
        let sha = hex::encode(Sha256::digest(&body));
        let staged = reserved.persist(&body, &sha).unwrap();
        let evidence = staged.evidence().clone();
        let (pending, _) = fixture.paths(2);
        drop(staged);
        let mut permissions = fs::metadata(&pending).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&pending, permissions).unwrap();
        assert!(
            reopen_prepared_disposition_progress(
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
    fn native_acl_drift_fail_closed_without_repair() {
        use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows::Win32::Storage::FileSystem::WRITE_DAC;

        let fixture = Fixture::new();
        let key = fixture.key();
        let reserved =
            reserve_disposition_progress(fixture.workspace.evidence(), RUN_ID, &key, 4).unwrap();
        let body = bytes(&reserved);
        let sha = hex::encode(Sha256::digest(&body));
        let staged = reserved.persist(&body, &sha).unwrap();
        let evidence = staged.evidence().clone();
        let (pending, _) = fixture.paths(4);
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
            reopen_prepared_disposition_progress(
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
    fn production_has_no_destructive_or_provider_operation() {
        let production = include_str!("disposition_progress.rs")
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
