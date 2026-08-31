//! Protected external publication boundary for the exact depublish commit.
//!
//! This is deliberately a small storage primitive. It accepts bounded opaque
//! bytes, binds their digest and file identity, and exposes only typed stages
//! around a create-new pending file and one non-replacing rename. It has no
//! delete, overwrite, adoption, or provider operation.

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

pub const DEPUBLISH_COMMIT_BINDING_SCHEMA_VERSION: &str = "aiw.dev/wsb-depublish-commit-binding/v1";
pub const DEPUBLISH_COMMIT_BINDING_POLICY_VERSION: &str =
    "owner-system-protected-depublish-commit-v1";
const FINAL_PREFIX: &str = ".aiw-discard-depublish-v1-";
const PENDING_PREFIX: &str = ".aiw-discard-depublish-pending-v1-";
const MAX_COMMIT_BYTES: usize = 1024 * 1024;
const EA_STABILIZATION_ATTEMPTS: usize = 40;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DepublishCommitBindingEvidence {
    pub schema_version: String,
    pub policy_version: String,
    pub run_id: String,
    pub owner_sid: String,
    pub store_key: String,
    pub final_path: String,
    pub pending_path: String,
    pub parent_id: DiscardIntentStableId,
    pub commit_id: DiscardIntentStableId,
    pub commit_size: u64,
    pub commit_sha256: String,
    pub commit_ea: DiscardIntentEaBinding,
}

impl DepublishCommitBindingEvidence {
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
    pub fn commit_id(&self) -> &DiscardIntentStableId {
        &self.commit_id
    }
    pub fn commit_size(&self) -> u64 {
        self.commit_size
    }
    pub fn commit_sha256(&self) -> &str {
        &self.commit_sha256
    }
    pub fn commit_ea(&self) -> &DiscardIntentEaBinding {
        &self.commit_ea
    }
}

#[derive(Debug, Error)]
pub enum DepublishCommitError {
    #[error("depublish-commit contract is invalid: {0}")]
    Contract(&'static str),
    #[error("depublish-commit authority or identity was rejected: {0}")]
    Rejected(String),
    #[error("depublish-commit native operation failed at {operation}: {detail}")]
    Native {
        operation: &'static str,
        detail: String,
    },
    #[error("depublish-commit final namespace conflicts with an existing object")]
    FinalConflict,
    #[error("depublish-commit pending namespace conflicts with an existing object")]
    PendingConflict,
}

#[must_use]
pub struct ReservedDepublishCommit {
    evidence: DepublishCommitBindingEvidence,
    parent: File,
    commit: File,
}

impl ReservedDepublishCommit {
    pub fn evidence(&self) -> &DepublishCommitBindingEvidence {
        &self.evidence
    }
    pub fn parent_id(&self) -> &DiscardIntentStableId {
        &self.evidence.parent_id
    }
    pub fn commit_id(&self) -> &DiscardIntentStableId {
        &self.evidence.commit_id
    }
    pub fn persist(
        self,
        commit: &[u8],
        expected_sha256: &str,
    ) -> Result<StagedDepublishCommit, DepublishCommitError> {
        validate_bytes(commit, expected_sha256)?;
        let mut file = self.commit;
        file.write_all(commit)
            .map_err(|error| native_io("WriteFile(depublish-commit)", error))?;
        file.sync_all()
            .map_err(|error| native_io("FlushFileBuffers(depublish-commit)", error))?;
        let initial_id = map_exact(stable_id(&file))?;
        if id_evidence(initial_id.clone()) != self.evidence.commit_id {
            return Err(DepublishCommitError::Rejected(
                "reserved depublish-commit identity changed before persist".to_owned(),
            ));
        }
        drop(file);
        let (file, commit_ea) =
            reopen_stabilized(Path::new(&self.evidence.pending_path), &initial_id)?;
        let mut evidence = self.evidence;
        evidence.commit_size = commit.len() as u64;
        evidence.commit_sha256 = expected_sha256.to_owned();
        evidence.commit_ea = commit_ea;
        let context = Context::from_projection(&evidence)?;
        verify_commit(
            &file,
            &self.parent,
            &context.pending_path,
            &context,
            &evidence,
        )?;
        Ok(StagedDepublishCommit {
            evidence,
            _parent: self.parent,
            _commit: file,
            commit_bytes: commit.to_owned(),
        })
    }
}

#[must_use]
pub struct StagedDepublishCommit {
    evidence: DepublishCommitBindingEvidence,
    _parent: File,
    _commit: File,
    commit_bytes: Vec<u8>,
}

impl StagedDepublishCommit {
    pub fn evidence(&self) -> &DepublishCommitBindingEvidence {
        &self.evidence
    }
    pub fn commit(&self) -> &[u8] {
        &self.commit_bytes
    }
}

#[must_use]
pub struct PublishableDepublishCommit {
    evidence: DepublishCommitBindingEvidence,
    parent: File,
    commit: File,
    commit_bytes: Vec<u8>,
}

impl PublishableDepublishCommit {
    pub fn publish(self) -> Result<HeldDepublishCommitPublication, DepublishCommitError> {
        if namespace_present(Path::new(&self.evidence.final_path))? {
            return Err(DepublishCommitError::FinalConflict);
        }
        let context = Context::from_projection(&self.evidence)?;
        verify_parent(&self.parent, &context, &self.evidence.parent_id)?;
        verify_commit(
            &self.commit,
            &self.parent,
            &context.pending_path,
            &context,
            &self.evidence,
        )?;
        rename_relative(&self.commit, &self.parent, OsStr::new(&context.final_leaf))
            .map_err(exact_error)?;
        self.commit
            .sync_all()
            .map_err(|error| native_io("FlushFileBuffers(commit-after-rename)", error))?;
        let initial_id = map_exact(stable_id(&self.commit))?;
        drop(self.commit);
        let (final_file, final_ea) = reopen_stabilized(&context.final_path, &initial_id)?;
        let mut evidence = self.evidence;
        evidence.commit_ea = final_ea;
        verify_commit(
            &final_file,
            &self.parent,
            &context.final_path,
            &context,
            &evidence,
        )?;
        Ok(HeldDepublishCommitPublication {
            evidence,
            _parent: self.parent,
            _commit: final_file,
            commit_bytes: self.commit_bytes,
        })
    }
}

#[must_use]
pub struct HeldDepublishCommitPublication {
    evidence: DepublishCommitBindingEvidence,
    _parent: File,
    _commit: File,
    commit_bytes: Vec<u8>,
}

impl HeldDepublishCommitPublication {
    pub fn evidence(&self) -> &DepublishCommitBindingEvidence {
        &self.evidence
    }
    pub fn binding(&self) -> &DepublishCommitBindingEvidence {
        &self.evidence
    }
    pub fn commit(&self) -> &[u8] {
        &self.commit_bytes
    }
    pub fn final_path(&self) -> &str {
        self.evidence.final_path()
    }
    pub fn revalidate(&self) -> Result<(), DepublishCommitError> {
        let context = Context::from_projection(&self.evidence)?;
        verify_parent(&self._parent, &context, &self.evidence.parent_id)?;
        verify_commit(
            &self._commit,
            &self._parent,
            &context.final_path,
            &context,
            &self.evidence,
        )
    }
}

#[must_use]
pub enum ReopenedDepublishCommit {
    Publishable(PublishableDepublishCommit),
    Published(HeldDepublishCommitPublication),
}

#[must_use]
pub struct ExistingDepublishCommit {
    commit: Vec<u8>,
    binding: DepublishCommitBindingEvidence,
    reopened: ReopenedDepublishCommit,
}

/// Bounded, non-authoritative bootstrap observation from the deterministic
/// external name. Callers must parse it as untrusted data and then use the
/// embedded workspace binding with `reopen_existing_depublish_commit` before
/// acquiring recovery authority or mutating anything.
pub struct LocatedDepublishCommit {
    commit: Vec<u8>,
    store_key: String,
    published: bool,
}

impl LocatedDepublishCommit {
    pub fn commit(&self) -> &[u8] {
        &self.commit
    }
    pub fn store_key(&self) -> &str {
        &self.store_key
    }
    pub fn is_published(&self) -> bool {
        self.published
    }
}

impl ExistingDepublishCommit {
    pub fn commit(&self) -> &[u8] {
        &self.commit
    }
    pub fn binding(&self) -> &DepublishCommitBindingEvidence {
        &self.binding
    }
    pub fn into_reopened(self) -> ReopenedDepublishCommit {
        self.reopened
    }
}

pub fn stage_depublish_commit(
    commit: &[u8],
    expected_sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
) -> Result<StagedDepublishCommit, DepublishCommitError> {
    reserve_depublish_commit(workspace, run_id, store_key)?.persist(commit, expected_sha256)
}

pub fn reserve_depublish_commit(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
) -> Result<ReservedDepublishCommit, DepublishCommitError> {
    let context = Context::new(workspace, run_id, store_key)?;
    let parent = open_parent(&context)?;
    if namespace_present(&context.final_path)? {
        return Err(DepublishCommitError::FinalConflict);
    }
    if namespace_present(&context.pending_path)? {
        return Err(DepublishCommitError::PendingConflict);
    }
    let file = create_owner_system_file(&context.pending_path, &context.owner_sid)
        .map_err(workspace_error)?;
    clear_short_name(&file)?;
    let evidence = DepublishCommitBindingEvidence {
        schema_version: DEPUBLISH_COMMIT_BINDING_SCHEMA_VERSION.to_owned(),
        policy_version: DEPUBLISH_COMMIT_BINDING_POLICY_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        owner_sid: workspace.owner_sid.clone(),
        store_key: store_key.to_owned(),
        final_path: context.final_path.to_string_lossy().into_owned(),
        pending_path: context.pending_path.to_string_lossy().into_owned(),
        parent_id: id_evidence(map_exact(stable_id(&parent))?),
        commit_id: id_evidence(map_exact(stable_id(&file))?),
        commit_size: 0,
        commit_sha256: String::new(),
        commit_ea: DiscardIntentEaBinding {
            queried_bytes: 0,
            entries: Vec::new(),
            canonical_sha256: String::new(),
        },
    };
    verify_shape(&file, &parent, &context.pending_path, &context)?;
    Ok(ReservedDepublishCommit {
        evidence,
        parent,
        commit: file,
    })
}

pub fn reopen_prepared_depublish_commit(
    commit: &[u8],
    expected_sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    expected: &DepublishCommitBindingEvidence,
) -> Result<ReopenedDepublishCommit, DepublishCommitError> {
    validate_bytes(commit, expected_sha256)?;
    let context = Context::new(workspace, run_id, &expected.store_key)?;
    validate_projection(expected, &context, commit.len() as u64, expected_sha256)?;
    let parent = open_parent(&context)?;
    match (
        namespace_present(&context.pending_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (true, false) => {
            let file = open_commit(&context.pending_path, true)?;
            verify_commit(&file, &parent, &context.pending_path, &context, expected)?;
            Ok(ReopenedDepublishCommit::Publishable(
                PublishableDepublishCommit {
                    evidence: expected.clone(),
                    parent,
                    commit: file,
                    commit_bytes: commit.to_owned(),
                },
            ))
        }
        (false, true) => {
            let file = open_commit(&context.final_path, false)?;
            verify_commit(&file, &parent, &context.final_path, &context, expected)?;
            Ok(ReopenedDepublishCommit::Published(
                HeldDepublishCommitPublication {
                    evidence: expected.clone(),
                    _parent: parent,
                    _commit: file,
                    commit_bytes: commit.to_owned(),
                },
            ))
        }
        (true, true) => Err(DepublishCommitError::Rejected(
            "pending and final depublish-commit objects are both present".to_owned(),
        )),
        (false, false) => Err(DepublishCommitError::Rejected(
            "neither pending nor final depublish-commit object is present".to_owned(),
        )),
    }
}

pub fn reopen_existing_depublish_commit(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    store_key: &str,
) -> Result<ExistingDepublishCommit, DepublishCommitError> {
    let context = Context::new(workspace, run_id, store_key)?;
    let parent = open_parent(&context)?;
    let (path, publishable) = match (
        namespace_present(&context.pending_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (true, false) => (&context.pending_path, true),
        (false, true) => (&context.final_path, false),
        (true, true) => {
            return Err(DepublishCommitError::Rejected(
                "pending and final depublish-commit objects are both present".to_owned(),
            ));
        }
        (false, false) => {
            return Err(DepublishCommitError::Rejected(
                "neither pending nor final depublish-commit object is present".to_owned(),
            ));
        }
    };
    let file = open_commit(path, publishable)?;
    verify_shape(&file, &parent, path, &context)?;
    let size = map_exact(file_size(&file))?;
    if size == 0 || size > MAX_COMMIT_BYTES as u64 {
        return Err(DepublishCommitError::Rejected(
            "existing depublish-commit size is outside fixed bound".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    (&file)
        .take(MAX_COMMIT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| native_io("ReadFile(depublish-commit)", error))?;
    if bytes.len() as u64 != size {
        return Err(DepublishCommitError::Rejected(
            "existing depublish-commit length changed while held".to_owned(),
        ));
    }
    let sha = hex::encode(Sha256::digest(&bytes));
    let commit_ea = ea_evidence(query_extended_attributes(&file, false).map_err(exact_error)?);
    if !valid_ea(&commit_ea) {
        return Err(DepublishCommitError::Rejected(
            "existing depublish-commit extended attributes are invalid".to_owned(),
        ));
    }
    let binding = DepublishCommitBindingEvidence {
        schema_version: DEPUBLISH_COMMIT_BINDING_SCHEMA_VERSION.to_owned(),
        policy_version: DEPUBLISH_COMMIT_BINDING_POLICY_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        owner_sid: workspace.owner_sid.clone(),
        store_key: store_key.to_owned(),
        final_path: context.final_path.to_string_lossy().into_owned(),
        pending_path: context.pending_path.to_string_lossy().into_owned(),
        parent_id: context.parent_expected.clone(),
        commit_id: id_evidence(map_exact(stable_id(&file))?),
        commit_size: size,
        commit_sha256: sha.clone(),
        commit_ea,
    };
    validate_projection(&binding, &context, size, &sha)?;
    verify_commit(&file, &parent, path, &context, &binding)?;
    let reopened = if publishable {
        ReopenedDepublishCommit::Publishable(PublishableDepublishCommit {
            evidence: binding.clone(),
            parent,
            commit: file,
            commit_bytes: bytes.clone(),
        })
    } else {
        ReopenedDepublishCommit::Published(HeldDepublishCommitPublication {
            evidence: binding.clone(),
            _parent: parent,
            _commit: file,
            commit_bytes: bytes.clone(),
        })
    };
    Ok(ExistingDepublishCommit {
        commit: bytes,
        binding,
        reopened,
    })
}

pub fn locate_depublish_commit_from_persisted_root(
    original_root: &Path,
    run_id: &str,
) -> Result<LocatedDepublishCommit, DepublishCommitError> {
    let store_key = RunCoordinationKey::binding_from_persisted_root(original_root, run_id)
        .map_err(coordination_error)?;
    let parent = original_root
        .parent()
        .ok_or(DepublishCommitError::Contract(
            "persisted original root has no parent",
        ))?;
    if !is_fixed_volume(parent).map_err(workspace_error)? {
        return Err(DepublishCommitError::Rejected(
            "depublish-commit locator parent is not a fixed local volume".to_owned(),
        ));
    }
    let final_path = parent.join(format!("{FINAL_PREFIX}{store_key}.json"));
    let pending_path = parent.join(format!("{PENDING_PREFIX}{store_key}.json"));
    let (path, published) = match (
        namespace_present(&pending_path)?,
        namespace_present(&final_path)?,
    ) {
        (false, true) => (final_path, true),
        (true, false) => (pending_path, false),
        (true, true) => {
            return Err(DepublishCommitError::Rejected(
                "pending and final depublish-commit objects are both present".to_owned(),
            ));
        }
        (false, false) => {
            return Err(DepublishCommitError::Rejected(
                "neither pending nor final depublish-commit object is present".to_owned(),
            ));
        }
    };
    let file = open_commit(&path, false)?;
    let basic = map_exact(basic_info(&file))?;
    let standard = map_exact(standard_info(&file))?;
    if basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        || basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || basic.dwFileAttributes & FORBIDDEN_ATTRIBUTES != 0
        || standard.Directory
        || standard.DeletePending
        || standard.NumberOfLinks != 1
    {
        return Err(DepublishCommitError::Rejected(
            "located depublish-commit is not one ordinary single-link file".to_owned(),
        ));
    }
    let size = map_exact(file_size(&file))?;
    if size == 0 || size > MAX_COMMIT_BYTES as u64 {
        return Err(DepublishCommitError::Rejected(
            "located depublish-commit size is outside fixed bound".to_owned(),
        ));
    }
    verify_stream_policy(&file, false, size).map_err(exact_error)?;
    let mut commit = Vec::with_capacity(size as usize);
    (&file)
        .take(MAX_COMMIT_BYTES as u64 + 1)
        .read_to_end(&mut commit)
        .map_err(|error| native_io("ReadFile(depublish-commit-locator)", error))?;
    if commit.len() as u64 != size {
        return Err(DepublishCommitError::Rejected(
            "located depublish-commit length changed while held".to_owned(),
        ));
    }
    Ok(LocatedDepublishCommit {
        commit,
        store_key,
        published,
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
    ) -> Result<Self, DepublishCommitError> {
        workspace
            .validate()
            .map_err(|_| DepublishCommitError::Contract("workspace binding is invalid"))?;
        let key =
            RunCoordinationKey::from_workspace(workspace, run_id).map_err(coordination_error)?;
        if key.binding_sha256() != store_key {
            return Err(DepublishCommitError::Contract(
                "depublish-commit store key is not derived from workspace/run",
            ));
        }
        let parent_path = PathBuf::from(&workspace.parent.final_path);
        if Path::new(&workspace.root.final_path)
            .parent()
            .is_none_or(|path| !same_path(path, &parent_path))
        {
            return Err(DepublishCommitError::Contract(
                "workspace root does not belong to its parent",
            ));
        }
        if !is_fixed_volume(&parent_path).map_err(workspace_error)? {
            return Err(DepublishCommitError::Rejected(
                "depublish-commit parent is not fixed local volume".to_owned(),
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
    fn from_projection(
        value: &DepublishCommitBindingEvidence,
    ) -> Result<Self, DepublishCommitError> {
        let final_path = PathBuf::from(&value.final_path);
        let pending_path = PathBuf::from(&value.pending_path);
        let parent_path = final_path
            .parent()
            .ok_or(DepublishCommitError::Contract(
                "depublish-commit final path has no parent",
            ))?
            .to_owned();
        let final_leaf = final_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(DepublishCommitError::Contract(
                "depublish-commit final leaf is invalid",
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

fn open_parent(context: &Context) -> Result<File, DepublishCommitError> {
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
        .map_err(|error| native_io("CreateFileW(depublish-commit-parent)", error))?;
    verify_parent(&file, context, &context.parent_expected)?;
    Ok(file)
}

fn verify_parent(
    parent: &File,
    context: &Context,
    expected: &DiscardIntentStableId,
) -> Result<(), DepublishCommitError> {
    verify_local_acl_volume(parent).map_err(workspace_error)?;
    reject_case_sensitive_directory(parent).map_err(exact_error)?;
    verify_owner_system_acl(parent, &context.owner, true, true).map_err(|_| {
        DepublishCommitError::Rejected(
            "depublish-commit parent is not owner-and-SYSTEM protected".to_owned(),
        )
    })?;
    if id_evidence(map_exact(stable_id(parent))?) != *expected
        || !same_path(
            final_path(parent).map_err(workspace_error)?,
            &context.parent_path,
        )
    {
        return Err(DepublishCommitError::Rejected(
            "depublish-commit parent identity changed".to_owned(),
        ));
    }
    Ok(())
}

fn open_commit(path: &Path, for_publish: bool) -> Result<File, DepublishCommitError> {
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
        .map_err(|error| native_io("CreateFileW(depublish-commit)", error))
}

fn verify_shape(
    file: &File,
    parent: &File,
    expected_path: &Path,
    context: &Context,
) -> Result<(), DepublishCommitError> {
    verify_owner_system_acl(file, &context.owner, true, false).map_err(workspace_error)?;
    let basic = map_exact(basic_info(file))?;
    if basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        || basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || basic.dwFileAttributes & FORBIDDEN_ATTRIBUTES != 0
    {
        return Err(DepublishCommitError::Rejected(
            "depublish-commit is not ordinary non-reparse file".to_owned(),
        ));
    }
    let standard = map_exact(standard_info(file))?;
    if standard.Directory || standard.DeletePending || standard.NumberOfLinks != 1 {
        return Err(DepublishCommitError::Rejected(
            "depublish-commit type, disposition, or link count changed".to_owned(),
        ));
    }
    let id = map_exact(stable_id(file))?;
    if id_evidence(id.clone()).volume_serial_number != context.parent_expected.volume_serial_number
        || id_evidence(id.clone()) == context.parent_expected
    {
        return Err(DepublishCommitError::Rejected(
            "depublish-commit identity is invalid".to_owned(),
        ));
    }
    let leaf = expected_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(DepublishCommitError::Contract(
            "depublish-commit leaf is invalid",
        ))?;
    let entry = map_exact(exact_directory_entry(parent, leaf))?;
    if entry.file_id != id.file_id || entry.attributes != basic.dwFileAttributes {
        return Err(DepublishCommitError::Rejected(
            "depublish-commit parent entry or alias policy changed".to_owned(),
        ));
    }
    if !same_path(final_path(file).map_err(workspace_error)?, expected_path) {
        return Err(DepublishCommitError::Rejected(
            "depublish-commit path changed".to_owned(),
        ));
    }
    Ok(())
}

fn verify_commit(
    file: &File,
    parent: &File,
    expected_path: &Path,
    context: &Context,
    expected: &DepublishCommitBindingEvidence,
) -> Result<(), DepublishCommitError> {
    verify_shape(file, parent, expected_path, context)?;
    let basic = map_exact(basic_info(file))?;
    let id = map_exact(stable_id(file))?;
    let leaf = expected_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(DepublishCommitError::Contract(
            "depublish-commit leaf is invalid",
        ))?;
    let entry = map_exact(exact_directory_entry(parent, leaf))?;
    if entry.file_id != id.file_id || entry.attributes != basic.dwFileAttributes {
        return Err(DepublishCommitError::Rejected(
            "depublish-commit parent entry or alias policy changed".to_owned(),
        ));
    }
    let evidence_id = id_evidence(id);
    let size = map_exact(file_size(file))?;
    if evidence_id != expected.commit_id
        || evidence_id.volume_serial_number != context.parent_expected.volume_serial_number
        || size != expected.commit_size
        || hex::encode(map_exact(hash_file(file, size))?) != expected.commit_sha256
        || !same_path(final_path(file).map_err(workspace_error)?, expected_path)
    {
        return Err(DepublishCommitError::Rejected(
            "depublish-commit identity, path, or content changed".to_owned(),
        ));
    }
    let observed_ea = ea_evidence(query_extended_attributes(file, false).map_err(exact_error)?);
    if !same_ea_semantics(&observed_ea, &expected.commit_ea) {
        return Err(DepublishCommitError::Rejected(
            "depublish-commit extended attributes changed".to_owned(),
        ));
    }
    verify_stream_policy(file, false, size).map_err(exact_error)
}

fn reopen_stabilized(
    path: &Path,
    initial_id: &StableFileId,
) -> Result<(File, DiscardIntentEaBinding), DepublishCommitError> {
    let mut previous = None;
    for attempt in 0..EA_STABILIZATION_ATTEMPTS {
        let file = open_commit(path, false)?;
        if &map_exact(stable_id(&file))? != initial_id {
            return Err(DepublishCommitError::Rejected(
                "depublish-commit identity changed during close/reopen".to_owned(),
            ));
        }
        match query_extended_attributes(&file, false) {
            Ok(value) => {
                let observed = ea_evidence(value);
                if previous
                    .as_ref()
                    .is_some_and(|prior| same_ea_semantics(prior, &observed))
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
    Err(DepublishCommitError::Rejected(
        "depublish-commit EAs did not stabilize".to_owned(),
    ))
}

fn validate_bytes(bytes: &[u8], expected: &str) -> Result<(), DepublishCommitError> {
    if bytes.is_empty() || bytes.len() > MAX_COMMIT_BYTES {
        return Err(DepublishCommitError::Contract(
            "depublish-commit bytes are empty or exceed fixed bound",
        ));
    }
    if expected.len() != 64
        || !is_lower_hex(expected)
        || hex::encode(Sha256::digest(bytes)) != expected
    {
        return Err(DepublishCommitError::Contract(
            "depublish-commit SHA-256 is invalid or does not match",
        ));
    }
    Ok(())
}

fn validate_projection(
    expected: &DepublishCommitBindingEvidence,
    context: &Context,
    size: u64,
    sha: &str,
) -> Result<(), DepublishCommitError> {
    if expected.schema_version != DEPUBLISH_COMMIT_BINDING_SCHEMA_VERSION
        || expected.policy_version != DEPUBLISH_COMMIT_BINDING_POLICY_VERSION
        || expected.run_id.is_empty()
        || expected.run_id != expected.run_id.trim()
        || expected.owner_sid != context.owner_sid
        || expected.store_key != context.store_key
        || !same_path(&expected.final_path, &context.final_path)
        || !same_path(&expected.pending_path, &context.pending_path)
        || expected.parent_id != context.parent_expected
        || expected.commit_size != size
        || expected.commit_sha256 != sha
        || !valid_id(&expected.parent_id)
        || !valid_id(&expected.commit_id)
        || expected.commit_id == expected.parent_id
        || expected.commit_id.volume_serial_number != expected.parent_id.volume_serial_number
        || !valid_ea(&expected.commit_ea)
    {
        return Err(DepublishCommitError::Contract(
            "persisted depublish-commit binding is invalid",
        ));
    }
    Ok(())
}

fn clear_short_name(file: &File) -> Result<(), DepublishCommitError> {
    let empty = [0_u16];
    unsafe { SetFileShortNameW(raw_handle(file), PCWSTR(empty.as_ptr())) }.map_err(|error| {
        DepublishCommitError::Native {
            operation: "SetFileShortNameW(clear)",
            detail: error.to_string(),
        }
    })
}
fn namespace_present(path: &Path) -> Result<bool, DepublishCommitError> {
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
fn coordination_error(error: RunCoordinationError) -> DepublishCommitError {
    match error {
        RunCoordinationError::InvalidBinding(detail) => DepublishCommitError::Contract(detail),
        other => DepublishCommitError::Rejected(other.to_string()),
    }
}
fn workspace_error(error: crate::workspace::WorkspaceError) -> DepublishCommitError {
    DepublishCommitError::Rejected(error.to_string())
}
fn exact_error(error: crate::exact_dispose::ExactDisposeError) -> DepublishCommitError {
    DepublishCommitError::Rejected(error.to_string())
}
fn map_exact<T>(
    result: Result<T, crate::exact_dispose::ExactDisposeError>,
) -> Result<T, DepublishCommitError> {
    result.map_err(exact_error)
}
fn native_io(operation: &'static str, error: std::io::Error) -> DepublishCommitError {
    DepublishCommitError::Native {
        operation,
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::workspace::{HeldRunWorkspace, create_owner_system_directory};

    const RUN_ID: &str = "run-one";
    const COMMIT: &[u8] = br#"{"schemaVersion":"aiw.dev/wsb-depublish-commit/v1"}"#;

    #[test]
    fn production_surface_has_no_delete_overwrite_or_provider_verbs() {
        let production = include_str!("depublish_commit.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "remove_file(",
            "remove_dir(",
            "remove_dir_all(",
            "std::fs::rename(",
            "fs::rename(",
            "std::process::Command",
            "acquire_windows_sandbox",
        ] {
            assert!(
                !production.contains(forbidden),
                "depublish commit contains forbidden operation {forbidden}"
            );
        }
        assert!(production.contains("create_owner_system_file"));
        assert!(production.contains("rename_relative"));
    }

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
            let outer = std::env::temp_dir().join(format!("aiw-depublish-{}", nonce));
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
        fn store_key(&self) -> String {
            RunCoordinationKey::from_workspace(self.workspace.evidence(), RUN_ID)
                .unwrap()
                .binding_sha256()
                .to_owned()
        }
        fn paths(&self) -> (PathBuf, PathBuf) {
            let key = self.store_key();
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

    fn hash() -> String {
        hex::encode(Sha256::digest(COMMIT))
    }

    #[test]
    fn namespace_names_are_deterministic_and_distinct() {
        let key = "a".repeat(64);
        assert_eq!(
            format!("{FINAL_PREFIX}{key}.json"),
            format!(".aiw-discard-depublish-v1-{key}.json")
        );
        assert_ne!(
            format!("{FINAL_PREFIX}{key}.json"),
            format!("{PENDING_PREFIX}{key}.json")
        );
    }

    #[test]
    fn byte_bound_and_hash_are_fail_closed() {
        let bytes = b"commit";
        let hash = hex::encode(Sha256::digest(bytes));
        assert!(validate_bytes(bytes, &hash).is_ok());
        assert!(validate_bytes(bytes, &"0".repeat(64)).is_err());
        assert!(validate_bytes(&[], &hash).is_err());
    }

    #[test]
    fn native_round_trip_publishes_and_reopens_exact_final() {
        let fixture = Fixture::new();
        let key = fixture.store_key();
        let staged =
            stage_depublish_commit(COMMIT, &hash(), fixture.workspace.evidence(), RUN_ID, &key)
                .unwrap();
        let evidence = staged.evidence().clone();
        let (pending, final_path) = fixture.paths();
        assert!(pending.is_file());
        drop(staged);
        let reopened = reopen_prepared_depublish_commit(
            COMMIT,
            &hash(),
            fixture.workspace.evidence(),
            RUN_ID,
            &evidence,
        )
        .unwrap();
        let held = match reopened {
            ReopenedDepublishCommit::Publishable(value) => value.publish().unwrap(),
            ReopenedDepublishCommit::Published(_) => panic!("pending unexpectedly published"),
        };
        assert!(final_path.is_file());
        assert_eq!(held.commit(), COMMIT);
        assert!(OpenOptions::new().write(true).open(&final_path).is_err());
        held.revalidate().unwrap();
        let located = locate_depublish_commit_from_persisted_root(
            Path::new(&fixture.workspace.evidence().root.final_path),
            RUN_ID,
        )
        .unwrap();
        assert!(located.is_published());
        assert_eq!(located.store_key(), key);
        assert_eq!(located.commit(), COMMIT);
        let existing =
            reopen_existing_depublish_commit(fixture.workspace.evidence(), RUN_ID, &key).unwrap();
        assert_eq!(existing.commit(), COMMIT);
        assert!(matches!(
            existing.into_reopened(),
            ReopenedDepublishCommit::Published(_)
        ));
    }

    #[test]
    fn native_pending_final_dual_and_hardlink_states_fail_closed() {
        let fixture = Fixture::new();
        let key = fixture.store_key();
        let staged =
            stage_depublish_commit(COMMIT, &hash(), fixture.workspace.evidence(), RUN_ID, &key)
                .unwrap();
        let evidence = staged.evidence().clone();
        let (pending, final_path) = fixture.paths();
        drop(staged);
        fs::write(&final_path, b"foreign").unwrap();
        assert!(matches!(
            reopen_existing_depublish_commit(fixture.workspace.evidence(), RUN_ID, &key),
            Err(DepublishCommitError::Rejected(_))
        ));
        fs::remove_file(&final_path).unwrap();
        fs::hard_link(&pending, fixture.parent.join("foreign-hardlink")).unwrap();
        assert!(
            reopen_prepared_depublish_commit(
                COMMIT,
                &hash(),
                fixture.workspace.evidence(),
                RUN_ID,
                &evidence
            )
            .is_err()
        );
    }

    #[test]
    fn native_reserved_crash_prefix_is_preserved_and_rejected() {
        let fixture = Fixture::new();
        let key = fixture.store_key();
        let reserved =
            reserve_depublish_commit(fixture.workspace.evidence(), RUN_ID, &key).unwrap();
        let (pending, final_path) = fixture.paths();
        drop(reserved);
        assert!(pending.is_file());
        assert!(!final_path.exists());
        assert!(
            reopen_existing_depublish_commit(fixture.workspace.evidence(), RUN_ID, &key).is_err()
        );
    }

    #[test]
    fn native_content_and_readonly_drift_are_rejected_without_repair() {
        let fixture = Fixture::new();
        let key = fixture.store_key();
        let staged =
            stage_depublish_commit(COMMIT, &hash(), fixture.workspace.evidence(), RUN_ID, &key)
                .unwrap();
        let evidence = staged.evidence().clone();
        let (pending, _) = fixture.paths();
        drop(staged);
        fs::write(&pending, b"changed").unwrap();
        assert!(
            reopen_prepared_depublish_commit(
                COMMIT,
                &hash(),
                fixture.workspace.evidence(),
                RUN_ID,
                &evidence
            )
            .is_err()
        );

        let fixture = Fixture::new();
        let key = fixture.store_key();
        let staged =
            stage_depublish_commit(COMMIT, &hash(), fixture.workspace.evidence(), RUN_ID, &key)
                .unwrap();
        let evidence = staged.evidence().clone();
        let (pending, _) = fixture.paths();
        drop(staged);
        let mut permissions = fs::metadata(&pending).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&pending, permissions).unwrap();
        assert!(
            reopen_prepared_depublish_commit(
                COMMIT,
                &hash(),
                fixture.workspace.evidence(),
                RUN_ID,
                &evidence
            )
            .is_err()
        );
    }
}
