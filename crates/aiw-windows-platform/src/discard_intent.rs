//! Protected external Windows Sandbox discard-intent publication.
//!
//! This boundary creates one internally named protected sibling file. Freshly
//! staged state must be persisted and strictly reopened before it can publish.
//! Publication is one non-replacing handle-relative rename. The workspace is
//! never opened for mutation and this module has no delete or provider verb.
//!
//! The file uses write-through and is flushed after all content/ACL/short-name
//! metadata changes and after rename. Windows does not offer a portable parent-
//! directory flush contract; persisted exact binding evidence plus reopen is
//! the recovery contract. The protected DACL excludes other principals but
//! cannot defend against a process already running as the same owner.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aiw_probe::WorkspaceBindingEvidence;
pub use aiw_probe::{
    DISCARD_INTENT_BINDING_POLICY_VERSION, DISCARD_INTENT_BINDING_SCHEMA_VERSION,
    DiscardIntentBindingEvidence, DiscardIntentEaBinding, DiscardIntentEaEntry,
    DiscardIntentStableId,
};
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

const FINAL_PREFIX: &str = ".aiw-discard-v1-";
const STAGE_PREFIX: &str = ".aiw-discard-stage-v1-";
const MAX_INTENT_BYTES: usize = 1024 * 1024;
const MAX_STAGE_ATTEMPTS: usize = 8;
const EA_STABILIZATION_ATTEMPTS: usize = 40;
static STAGE_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum DiscardIntentError {
    #[error("discard-intent contract is invalid: {0}")]
    Contract(&'static str),
    #[error("discard-intent authority or identity was rejected: {0}")]
    Rejected(String),
    #[error("discard-intent native operation failed at {operation}: {detail}")]
    Native {
        operation: &'static str,
        detail: String,
    },
    #[error("discard-intent publication conflicts with an existing final authority")]
    FinalConflict,
}

/// Fresh exact staged state. It deliberately has no publication method.
#[must_use]
pub struct StagedDiscardIntent {
    evidence: DiscardIntentBindingEvidence,
    _parent: File,
    _intent: File,
}

impl StagedDiscardIntent {
    #[must_use]
    pub fn evidence(&self) -> &DiscardIntentBindingEvidence {
        &self.evidence
    }
}

/// Publication authority produced only by strict persisted-evidence reopen.
#[must_use]
pub struct PublishableDiscardIntent {
    evidence: DiscardIntentBindingEvidence,
    parent: File,
    intent: File,
}

impl PublishableDiscardIntent {
    pub fn publish(self) -> Result<HeldDiscardIntentPublication, DiscardIntentError> {
        publish_reopened(self, PublishFailpoint::None)
    }
}

#[must_use]
pub struct HeldDiscardIntentPublication {
    evidence: DiscardIntentBindingEvidence,
    _parent: File,
    _intent: File,
}

impl HeldDiscardIntentPublication {
    #[must_use]
    pub fn evidence(&self) -> &DiscardIntentBindingEvidence {
        &self.evidence
    }
    #[must_use]
    pub fn final_path(&self) -> &str {
        self.evidence.final_path()
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
    pub fn intent_id(&self) -> &DiscardIntentStableId {
        self.evidence.intent_id()
    }
    #[must_use]
    pub fn intent_size(&self) -> u64 {
        self.evidence.intent_size()
    }
    #[must_use]
    pub fn intent_sha256(&self) -> &str {
        self.evidence.intent_sha256()
    }
    #[must_use]
    pub fn owner_sid(&self) -> &str {
        self.evidence.owner_sid()
    }
    #[must_use]
    pub fn intent_ea(&self) -> &DiscardIntentEaBinding {
        self.evidence.intent_ea()
    }

    /// Revalidates the exact held external authority without reopening by a
    /// caller-controlled path.
    #[doc(hidden)]
    pub fn revalidate(&self) -> Result<(), DiscardIntentError> {
        let context = Context::from_projection(&self.evidence)?;
        verify_parent(&self._parent, &context, &self.evidence.parent_id)?;
        verify_intent(
            &self._intent,
            &self._parent,
            &context.final_path,
            &context,
            &self.evidence,
        )
    }
}

#[must_use]
pub enum ReopenedDiscardIntent {
    Publishable(PublishableDiscardIntent),
    Published(HeldDiscardIntentPublication),
}

pub fn stage_discard_intent(
    intent: &[u8],
    expected_sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
) -> Result<StagedDiscardIntent, DiscardIntentError> {
    stage_with_failpoint(
        intent,
        expected_sha256,
        workspace,
        run_id,
        StageFailpoint::None,
    )
}

pub fn reopen_prepared_discard_intent(
    intent: &[u8],
    expected_sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    expected: &DiscardIntentBindingEvidence,
) -> Result<ReopenedDiscardIntent, DiscardIntentError> {
    validate_intent(intent, expected_sha256)?;
    let context = Context::new(workspace, run_id)?;
    validate_projection(expected, &context, run_id, intent, expected_sha256)?;
    let parent = open_parent(&context)?;
    let stage_path = context.parent_path.join(&expected.staging_leaf);
    match (
        namespace_present(&stage_path)?,
        namespace_present(&context.final_path)?,
    ) {
        (true, false) => {
            let file = open_intent(&stage_path, true)?;
            verify_intent(&file, &parent, &stage_path, &context, expected)?;
            Ok(ReopenedDiscardIntent::Publishable(
                PublishableDiscardIntent {
                    evidence: expected.clone(),
                    parent,
                    intent: file,
                },
            ))
        }
        (false, true) => {
            open_published(parent, &context, expected).map(ReopenedDiscardIntent::Published)
        }
        _ => Err(DiscardIntentError::Rejected(
            "expected staging/final namespace state is absent or ambiguous".to_owned(),
        )),
    }
}

/// Reopen an already-published exact intent using only its persisted binding.
/// This is the narrow recovery path used after the workspace name is gone; it
/// can neither publish a staged object nor mutate the namespace.
pub fn reopen_published_discard_intent(
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    expected: &DiscardIntentBindingEvidence,
) -> Result<HeldDiscardIntentPublication, DiscardIntentError> {
    let context = Context::new(workspace, run_id)?;
    validate_persisted_projection(expected, &context, run_id)?;
    let parent = open_parent(&context)?;
    if !namespace_present(&context.final_path)? {
        return Err(DiscardIntentError::Rejected(
            "published discard-intent is absent".to_owned(),
        ));
    }
    open_published(parent, &context, expected)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StageFailpoint {
    None,
    AfterCreate,
    AfterWrite,
    AfterFlush,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PublishFailpoint {
    None,
    AfterRename,
}

fn stage_with_failpoint(
    intent: &[u8],
    expected_sha256: &str,
    workspace: &WorkspaceBindingEvidence,
    run_id: &str,
    failpoint: StageFailpoint,
) -> Result<StagedDiscardIntent, DiscardIntentError> {
    validate_intent(intent, expected_sha256)?;
    let context = Context::new(workspace, run_id)?;
    let parent = open_parent(&context)?;
    reject_final_name(&context.final_path)?;
    let (staging_leaf, staging_path, mut file) = create_unique_stage(&context)?;
    if failpoint == StageFailpoint::AfterCreate {
        return Err(injected("after staging file creation"));
    }
    clear_short_name(&file)?;
    file.write_all(intent)
        .map_err(|error| native_io("WriteFile(intent)", error))?;
    if failpoint == StageFailpoint::AfterWrite {
        return Err(injected("after intent write before flush"));
    }
    file.sync_all()
        .map_err(|error| native_io("FlushFileBuffers(intent)", error))?;
    if failpoint == StageFailpoint::AfterFlush {
        return Err(injected("after intent flush"));
    }
    let initial_id = map_exact(stable_id(&file))?;
    drop(file);
    // SmartLocker adds the second kernel EA only after the creating writer is
    // closed on this host. Reopen is therefore mandatory; the held parent and
    // exact initial stable ID make substitution fail closed.
    let (file, intent_ea) = reopen_stabilized_stage(&staging_path, &initial_id)?;
    let evidence = DiscardIntentBindingEvidence {
        schema_version: DISCARD_INTENT_BINDING_SCHEMA_VERSION.to_owned(),
        policy_version: DISCARD_INTENT_BINDING_POLICY_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        owner_sid: workspace.owner_sid.clone(),
        store_key: context.store_key.clone(),
        final_path: context.final_path.to_string_lossy().into_owned(),
        staging_leaf,
        parent_id: id_evidence(map_exact(stable_id(&parent))?),
        intent_id: id_evidence(initial_id),
        intent_size: intent.len() as u64,
        intent_sha256: expected_sha256.to_owned(),
        intent_ea,
    };
    verify_intent(&file, &parent, &staging_path, &context, &evidence)?;
    Ok(StagedDiscardIntent {
        evidence,
        _parent: parent,
        _intent: file,
    })
}

fn publish_reopened(
    value: PublishableDiscardIntent,
    failpoint: PublishFailpoint,
) -> Result<HeldDiscardIntentPublication, DiscardIntentError> {
    let context = Context::from_projection(&value.evidence)?;
    verify_parent(&value.parent, &context, &value.evidence.parent_id)?;
    let stage_path = context.parent_path.join(&value.evidence.staging_leaf);
    verify_intent(
        &value.intent,
        &value.parent,
        &stage_path,
        &context,
        &value.evidence,
    )?;
    reject_final_name(&context.final_path)?;
    rename_relative(
        &value.intent,
        &value.parent,
        OsStr::new(&context.final_leaf),
    )
    .map_err(exact_error)?;
    if failpoint == PublishFailpoint::AfterRename {
        return Err(injected("after final rename before return"));
    }
    value
        .intent
        .sync_all()
        .map_err(|error| native_io("FlushFileBuffers(intent-after-rename)", error))?;
    verify_intent(
        &value.intent,
        &value.parent,
        &context.final_path,
        &context,
        &value.evidence,
    )?;
    drop(value.intent);
    let intent = open_intent(&context.final_path, false)?;
    verify_intent(
        &intent,
        &value.parent,
        &context.final_path,
        &context,
        &value.evidence,
    )?;
    Ok(HeldDiscardIntentPublication {
        evidence: value.evidence,
        _parent: value.parent,
        _intent: intent,
    })
}

fn open_published(
    parent: File,
    context: &Context,
    expected: &DiscardIntentBindingEvidence,
) -> Result<HeldDiscardIntentPublication, DiscardIntentError> {
    let file = open_intent(&context.final_path, false)?;
    verify_intent(&file, &parent, &context.final_path, context, expected)?;
    Ok(HeldDiscardIntentPublication {
        evidence: expected.clone(),
        _parent: parent,
        _intent: file,
    })
}

struct Context {
    parent_path: PathBuf,
    final_leaf: String,
    final_path: PathBuf,
    store_key: String,
    owner: OwnedSid,
    owner_sid: String,
    parent_expected: DiscardIntentStableId,
}

impl Context {
    fn new(workspace: &WorkspaceBindingEvidence, run_id: &str) -> Result<Self, DiscardIntentError> {
        workspace
            .validate()
            .map_err(|_| DiscardIntentError::Contract("workspace binding is invalid"))?;
        let key =
            RunCoordinationKey::from_workspace(workspace, run_id).map_err(coordination_error)?;
        let store_key = key.binding_sha256().to_owned();
        let final_leaf = format!("{FINAL_PREFIX}{store_key}");
        let parent_path = PathBuf::from(&workspace.parent.final_path);
        if Path::new(&workspace.root.final_path)
            .parent()
            .is_none_or(|path| !same_path(path, &parent_path))
        {
            return Err(DiscardIntentError::Contract(
                "workspace root slot does not belong to its persisted parent",
            ));
        }
        if !is_fixed_volume(&parent_path).map_err(workspace_error)? {
            return Err(DiscardIntentError::Rejected(
                "discard-intent parent is not on a fixed local volume".to_owned(),
            ));
        }
        Ok(Self {
            final_path: parent_path.join(&final_leaf),
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

    fn from_projection(value: &DiscardIntentBindingEvidence) -> Result<Self, DiscardIntentError> {
        let final_path = PathBuf::from(&value.final_path);
        let parent_path = final_path.parent().ok_or(DiscardIntentError::Contract(
            "final discard-intent path has no parent",
        ))?;
        let final_leaf = final_path
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .ok_or(DiscardIntentError::Contract(
                "final discard-intent leaf is invalid",
            ))?
            .to_owned();
        Ok(Self {
            parent_path: parent_path.to_owned(),
            final_leaf,
            final_path,
            store_key: value.store_key.clone(),
            owner: OwnedSid::from_string(&value.owner_sid).map_err(workspace_error)?,
            owner_sid: value.owner_sid.clone(),
            parent_expected: value.parent_id.clone(),
        })
    }
}

fn open_parent(context: &Context) -> Result<File, DiscardIntentError> {
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
        .map_err(|error| native_io("CreateFileW(discard-parent)", error))?;
    verify_parent(&parent, context, &context.parent_expected)?;
    Ok(parent)
}

fn verify_parent(
    parent: &File,
    context: &Context,
    expected: &DiscardIntentStableId,
) -> Result<(), DiscardIntentError> {
    verify_local_acl_volume(parent).map_err(workspace_error)?;
    reject_case_sensitive_directory(parent).map_err(exact_error)?;
    verify_owner_system_acl(parent, &context.owner, true, true).map_err(|_| {
        DiscardIntentError::Rejected(
            "discard-intent parent must be protected owner-and-SYSTEM-only; untrusted FILE_DELETE_CHILD is not allowed"
                .to_owned(),
        )
    })?;
    if id_evidence(map_exact(stable_id(parent))?) != *expected
        || !same_path(
            final_path(parent).map_err(workspace_error)?,
            &context.parent_path,
        )
    {
        return Err(DiscardIntentError::Rejected(
            "discard-intent parent identity changed".to_owned(),
        ));
    }
    Ok(())
}

fn create_unique_stage(context: &Context) -> Result<(String, PathBuf, File), DiscardIntentError> {
    for attempt in 0..MAX_STAGE_ATTEMPTS {
        let leaf = stage_leaf(&context.store_key, attempt as u64);
        let path = context.parent_path.join(&leaf);
        match create_owner_system_file(&path, &context.owner_sid) {
            Ok(file) => return Ok((leaf, path, file)),
            Err(crate::workspace::WorkspaceError::AlreadyExists) => continue,
            Err(error) => return Err(workspace_error(error)),
        }
    }
    Err(DiscardIntentError::Rejected(
        "bounded staging namespace attempts were exhausted".to_owned(),
    ))
}

fn stage_leaf(store_key: &str, attempt: u64) -> String {
    let tick = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = STAGE_NONCE.fetch_add(1, Ordering::Relaxed);
    let suffix = Sha256::digest(
        [
            tick.to_le_bytes().as_slice(),
            u128::from(std::process::id()).to_le_bytes().as_slice(),
            u128::from(sequence).to_le_bytes().as_slice(),
            u128::from(attempt).to_le_bytes().as_slice(),
        ]
        .concat(),
    );
    format!("{STAGE_PREFIX}{store_key}-{}", &hex::encode(suffix)[..16])
}

fn open_intent(path: &Path, for_publish: bool) -> Result<File, DiscardIntentError> {
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
        .map_err(|error| native_io("CreateFileW(discard-intent)", error))
}

fn verify_intent(
    file: &File,
    parent: &File,
    expected_path: &Path,
    context: &Context,
    expected: &DiscardIntentBindingEvidence,
) -> Result<(), DiscardIntentError> {
    verify_owner_system_acl(file, &context.owner, true, false).map_err(workspace_error)?;
    let basic = basic_info(file).map_err(exact_error)?;
    if basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        || basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || basic.dwFileAttributes & FORBIDDEN_ATTRIBUTES != 0
    {
        return Err(DiscardIntentError::Rejected(
            "discard-intent is not an ordinary non-reparse file".to_owned(),
        ));
    }
    let standard = standard_info(file).map_err(exact_error)?;
    if standard.Directory || standard.DeletePending || standard.NumberOfLinks != 1 {
        return Err(DiscardIntentError::Rejected(
            "discard-intent type, disposition, or link count changed".to_owned(),
        ));
    }
    let id = map_exact(stable_id(file))?;
    let leaf = expected_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(DiscardIntentError::Contract("intent leaf is invalid"))?;
    let entry = map_exact(exact_directory_entry(parent, leaf))?;
    if entry.file_id != id.file_id || entry.attributes != basic.dwFileAttributes {
        return Err(DiscardIntentError::Rejected(
            "discard-intent parent entry, exact case, attributes, identity, or short-name policy changed"
                .to_owned(),
        ));
    }
    let id = id_evidence(id);
    let size = file_size(file).map_err(exact_error)?;
    if id != expected.intent_id
        || id.volume_serial_number != context.parent_expected.volume_serial_number
        || size != expected.intent_size
        || hex::encode(hash_file(file, size).map_err(exact_error)?) != expected.intent_sha256
        || !same_path(final_path(file).map_err(workspace_error)?, expected_path)
    {
        return Err(DiscardIntentError::Rejected(
            "discard-intent identity, path, content, or volume changed".to_owned(),
        ));
    }
    let observed_ea = ea_evidence(query_extended_attributes(file, false).map_err(exact_error)?);
    if !same_ea_semantics(&observed_ea, &expected.intent_ea) {
        return Err(DiscardIntentError::Rejected(format!(
            "discard-intent extended attributes changed: expected {}; observed {}",
            expected.intent_ea.canonical_sha256, observed_ea.canonical_sha256
        )));
    }
    verify_stream_policy(file, false, size).map_err(exact_error)
}

fn reject_final_name(path: &Path) -> Result<(), DiscardIntentError> {
    if namespace_present(path)? {
        return Err(DiscardIntentError::FinalConflict);
    }
    Ok(())
}

fn namespace_present(path: &Path) -> Result<bool, DiscardIntentError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(native_io("GetFileAttributesW(namespace)", error)),
    }
}

fn clear_short_name(file: &File) -> Result<(), DiscardIntentError> {
    let empty = [0_u16];
    unsafe { SetFileShortNameW(raw_handle(file), PCWSTR(empty.as_ptr())) }.map_err(|error| {
        DiscardIntentError::Native {
            operation: "SetFileShortNameW(clear)",
            detail: error.to_string(),
        }
    })
}

fn reopen_stabilized_stage(
    path: &Path,
    initial_id: &StableFileId,
) -> Result<(File, DiscardIntentEaBinding), DiscardIntentError> {
    let mut previous = None::<DiscardIntentEaBinding>;
    for attempt in 0..EA_STABILIZATION_ATTEMPTS {
        let file = open_intent(path, false)?;
        if &map_exact(stable_id(&file))? != initial_id {
            return Err(DiscardIntentError::Rejected(
                "staging identity changed during required metadata stabilization".to_owned(),
            ));
        }
        match query_extended_attributes(&file, false) {
            Ok(binding) => {
                let observed = ea_evidence(binding);
                if observe_ea_stability(&mut previous, &observed) {
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
    Err(DiscardIntentError::Rejected(
        "SmartLocker EA metadata did not stabilize to none or the exact pair".to_owned(),
    ))
}

fn same_ea_semantics(left: &DiscardIntentEaBinding, right: &DiscardIntentEaBinding) -> bool {
    left.entries == right.entries && left.canonical_sha256 == right.canonical_sha256
}

fn observe_ea_stability(
    previous: &mut Option<DiscardIntentEaBinding>,
    observed: &DiscardIntentEaBinding,
) -> bool {
    let stable = previous
        .as_ref()
        .is_some_and(|prior| same_ea_semantics(prior, observed));
    *previous = Some(observed.clone());
    stable
}

fn validate_intent(intent: &[u8], expected_sha256: &str) -> Result<(), DiscardIntentError> {
    if intent.is_empty() || intent.len() > MAX_INTENT_BYTES {
        return Err(DiscardIntentError::Contract(
            "intent bytes are empty or exceed the fixed bound",
        ));
    }
    if expected_sha256.len() != 64
        || !is_lower_hex(expected_sha256)
        || hex::encode(Sha256::digest(intent)) != expected_sha256
    {
        return Err(DiscardIntentError::Contract(
            "expected intent SHA-256 is invalid or does not match",
        ));
    }
    Ok(())
}

fn validate_projection(
    expected: &DiscardIntentBindingEvidence,
    context: &Context,
    run_id: &str,
    intent: &[u8],
    expected_sha256: &str,
) -> Result<(), DiscardIntentError> {
    validate_persisted_projection(expected, context, run_id)?;
    if expected.intent_size != intent.len() as u64 || expected.intent_sha256 != expected_sha256 {
        return Err(DiscardIntentError::Contract(
            "persisted discard-intent binding differs from supplied bytes",
        ));
    }
    Ok(())
}

fn validate_persisted_projection(
    expected: &DiscardIntentBindingEvidence,
    context: &Context,
    run_id: &str,
) -> Result<(), DiscardIntentError> {
    if expected.schema_version != DISCARD_INTENT_BINDING_SCHEMA_VERSION
        || expected.policy_version != DISCARD_INTENT_BINDING_POLICY_VERSION
        || expected.run_id != run_id
        || expected.run_id.is_empty()
        || expected.run_id != expected.run_id.trim()
        || expected.owner_sid != context.owner_sid
        || expected.store_key != context.store_key
        || !same_path(&expected.final_path, &context.final_path)
        || expected.parent_id != context.parent_expected
        || expected.intent_size == 0
        || expected.intent_size > MAX_INTENT_BYTES as u64
        || expected.intent_sha256.len() != 64
        || !is_lower_hex(&expected.intent_sha256)
        || !valid_stage_leaf(&expected.staging_leaf, &context.store_key)
        || !valid_id(&expected.intent_id)
        || !valid_ea(&expected.intent_ea)
    {
        return Err(DiscardIntentError::Contract(
            "persisted discard-intent binding is invalid",
        ));
    }
    Ok(())
}

fn valid_stage_leaf(value: &str, store_key: &str) -> bool {
    value
        .strip_prefix(&format!("{STAGE_PREFIX}{store_key}-"))
        .is_some_and(|suffix| suffix.len() == 16 && is_lower_hex(suffix))
}

fn valid_id(value: &DiscardIntentStableId) -> bool {
    value.volume_serial_number.len() == 16
        && value.file_id.len() == 32
        && is_lower_hex(&value.volume_serial_number)
        && is_lower_hex(&value.file_id)
}

fn valid_ea(value: &DiscardIntentEaBinding) -> bool {
    let allowed_names = value.entries.is_empty()
        || (value.entries.len() == ALLOWED_KERNEL_EAS.len()
            && value
                .entries
                .iter()
                .zip(ALLOWED_KERNEL_EAS)
                .all(|(entry, allowed)| entry.name == allowed));
    let queried_bytes_are_bounded = if value.entries.is_empty() {
        value.queried_bytes == 0
    } else {
        value.queried_bytes > 0 && value.queried_bytes <= 64 * 1024
    };
    queried_bytes_are_bounded
        && value.canonical_sha256.len() == 64
        && is_lower_hex(&value.canonical_sha256)
        && allowed_names
        && value
            .entries
            .iter()
            .all(|entry| entry.value_sha256.len() == 64 && is_lower_hex(&entry.value_sha256))
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

fn coordination_error(error: RunCoordinationError) -> DiscardIntentError {
    match error {
        RunCoordinationError::InvalidBinding(detail) => DiscardIntentError::Contract(detail),
        other => DiscardIntentError::Rejected(other.to_string()),
    }
}

fn workspace_error(error: crate::workspace::WorkspaceError) -> DiscardIntentError {
    DiscardIntentError::Rejected(error.to_string())
}

fn exact_error(error: crate::exact_dispose::ExactDisposeError) -> DiscardIntentError {
    DiscardIntentError::Rejected(error.to_string())
}

fn map_exact<T>(
    result: Result<T, crate::exact_dispose::ExactDisposeError>,
) -> Result<T, DiscardIntentError> {
    result.map_err(exact_error)
}

fn native_io(operation: &'static str, error: std::io::Error) -> DiscardIntentError {
    DiscardIntentError::Native {
        operation,
        detail: error.to_string(),
    }
}

fn injected(detail: &'static str) -> DiscardIntentError {
    DiscardIntentError::Native {
        operation: "crash-injection",
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::workspace::{HeldRunWorkspace, create_owner_system_directory};

    use super::*;

    const RUN_ID: &str = "run-one";
    const INTENT: &[u8] =
        br#"{"schemaVersion":"aiw.dev/test-discard-intent/v1","runId":"run-one"}"#;

    fn nonce() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    struct Fixture {
        outer: PathBuf,
        parent: PathBuf,
        workspace: Option<HeldRunWorkspace>,
    }

    impl Fixture {
        fn new() -> Self {
            let outer = std::env::temp_dir().join(format!("aiw-discard-intent-{}", nonce()));
            fs::create_dir(&outer).unwrap();
            let outer = outer.canonicalize().unwrap();
            let seed = HeldRunWorkspace::create(&outer, "owner-seed").unwrap();
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
                workspace: Some(workspace),
            }
        }

        fn evidence(&self) -> WorkspaceBindingEvidence {
            self.workspace.as_ref().unwrap().evidence().clone()
        }

        fn final_path(&self) -> PathBuf {
            let evidence = self.evidence();
            let key = RunCoordinationKey::from_workspace(&evidence, RUN_ID).unwrap();
            self.parent
                .join(format!("{FINAL_PREFIX}{}", key.binding_sha256()))
        }

        fn stage_path(&self, evidence: &DiscardIntentBindingEvidence) -> PathBuf {
            self.parent.join(&evidence.staging_leaf)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.workspace.take();
            let _ = fs::remove_dir_all(&self.outer);
        }
    }

    fn digest() -> String {
        hex::encode(Sha256::digest(INTENT))
    }

    fn synthetic_ea(tag: &str) -> DiscardIntentEaBinding {
        let entries = if tag == "none" {
            Vec::new()
        } else {
            vec![DiscardIntentEaEntry {
                name: tag.to_owned(),
                flags: 0,
                value_length: 4,
                value_sha256: "1".repeat(64),
            }]
        };
        DiscardIntentEaBinding {
            queried_bytes: if entries.is_empty() { 0 } else { 64 },
            entries,
            canonical_sha256: hex::encode(Sha256::digest(tag.as_bytes())),
        }
    }

    #[test]
    fn ea_stabilization_requires_two_consecutive_semantic_observations() {
        let none = synthetic_ea("none");
        let pair = synthetic_ea("pair");
        let mut previous = None;
        assert!(!observe_ea_stability(&mut previous, &none));
        assert!(!observe_ea_stability(&mut previous, &pair));
        assert!(observe_ea_stability(&mut previous, &pair));

        // A transient single OriginClaim resets the sequence. Neither a later
        // empty observation nor a following pair is accepted without its own
        // second identical close/reopen observation.
        previous = None;
        assert!(!observe_ea_stability(&mut previous, &none));
        previous = None;
        assert!(!observe_ea_stability(&mut previous, &none));
        assert!(!observe_ea_stability(&mut previous, &pair));
        assert!(observe_ea_stability(&mut previous, &pair));

        previous = None;
        assert!(!observe_ea_stability(&mut previous, &none));
        assert!(observe_ea_stability(&mut previous, &none));
    }

    #[test]
    fn stage_must_be_persisted_and_reopened_before_publish() {
        let fixture = Fixture::new();
        let workspace = fixture.evidence();
        let staged = stage_discard_intent(INTENT, &digest(), &workspace, RUN_ID).unwrap();
        let projection = staged.evidence().clone();
        assert_eq!(
            projection.policy_version,
            DISCARD_INTENT_BINDING_POLICY_VERSION
        );
        assert!(!fixture.final_path().exists());
        assert!(fixture.stage_path(&projection).is_file());
        assert!(
            fs::OpenOptions::new()
                .write(true)
                .open(fixture.stage_path(&projection))
                .is_err(),
            "held staged evidence must exclude competing writers"
        );
        assert_eq!(
            serde_json::from_slice::<DiscardIntentBindingEvidence>(
                &serde_json::to_vec(&projection).unwrap()
            )
            .unwrap(),
            projection
        );
        drop(staged);

        let publishable = match reopen_prepared_discard_intent(
            INTENT,
            &digest(),
            &workspace,
            RUN_ID,
            &projection,
        )
        .unwrap()
        {
            ReopenedDiscardIntent::Publishable(value) => value,
            ReopenedDiscardIntent::Published(_) => panic!("staging unexpectedly published"),
        };
        let held = publishable.publish().unwrap();
        assert!(same_path(held.final_path(), fixture.final_path()));
        assert_eq!(held.intent_id(), projection.intent_id());
        assert_eq!(fs::read(fixture.final_path()).unwrap(), INTENT);
        assert!(
            fs::OpenOptions::new()
                .write(true)
                .open(fixture.final_path())
                .is_err(),
            "held final authority must exclude competing writers"
        );
        drop(held);
        reopen_published_discard_intent(&workspace, RUN_ID, &projection)
            .unwrap()
            .revalidate()
            .unwrap();
        assert!(matches!(
            reopen_prepared_discard_intent(INTENT, &digest(), &workspace, RUN_ID, &projection)
                .unwrap(),
            ReopenedDiscardIntent::Published(_)
        ));
    }

    #[test]
    fn rename_before_return_recovers_exact_final() {
        let fixture = Fixture::new();
        let workspace = fixture.evidence();
        let staged = stage_discard_intent(INTENT, &digest(), &workspace, RUN_ID).unwrap();
        let projection = staged.evidence().clone();
        drop(staged);
        let publishable = match reopen_prepared_discard_intent(
            INTENT,
            &digest(),
            &workspace,
            RUN_ID,
            &projection,
        )
        .unwrap()
        {
            ReopenedDiscardIntent::Publishable(value) => value,
            ReopenedDiscardIntent::Published(_) => unreachable!(),
        };
        assert!(matches!(
            publish_reopened(publishable, PublishFailpoint::AfterRename),
            Err(DiscardIntentError::Native {
                operation: "crash-injection",
                ..
            })
        ));
        assert!(fixture.final_path().is_file());
        assert!(matches!(
            reopen_prepared_discard_intent(INTENT, &digest(), &workspace, RUN_ID, &projection)
                .unwrap(),
            ReopenedDiscardIntent::Published(_)
        ));
    }

    #[test]
    fn incomplete_stage_never_exposes_final_and_retry_succeeds() {
        for failpoint in [
            StageFailpoint::AfterCreate,
            StageFailpoint::AfterWrite,
            StageFailpoint::AfterFlush,
        ] {
            let fixture = Fixture::new();
            let workspace = fixture.evidence();
            assert!(
                stage_with_failpoint(INTENT, &digest(), &workspace, RUN_ID, failpoint).is_err()
            );
            assert!(!fixture.final_path().exists());
            assert!(stage_discard_intent(INTENT, &digest(), &workspace, RUN_ID).is_ok());
        }
    }

    #[test]
    fn permissive_parent_and_existing_final_are_preserved_and_rejected() {
        let outer = std::env::temp_dir().join(format!("aiw-discard-permissive-{}", nonce()));
        fs::create_dir(&outer).unwrap();
        let outer = outer.canonicalize().unwrap();
        let workspace = HeldRunWorkspace::create(&outer, "workspace").unwrap();
        assert!(matches!(
            stage_discard_intent(INTENT, &digest(), workspace.evidence(), RUN_ID),
            Err(DiscardIntentError::Rejected(_))
        ));
        let workspace_path = workspace.root_path().to_owned();
        drop(workspace);
        fs::remove_dir_all(workspace_path).unwrap();
        fs::remove_dir(&outer).unwrap();

        let fixture = Fixture::new();
        fs::write(fixture.final_path(), b"foreign").unwrap();
        assert!(matches!(
            stage_discard_intent(INTENT, &digest(), &fixture.evidence(), RUN_ID),
            Err(DiscardIntentError::FinalConflict)
        ));
        assert_eq!(fs::read(fixture.final_path()).unwrap(), b"foreign");
    }

    #[test]
    fn content_links_streams_attributes_and_binding_drift_fail_closed() {
        let fixture = Fixture::new();
        let workspace = fixture.evidence();
        let staged = stage_discard_intent(INTENT, &digest(), &workspace, RUN_ID).unwrap();
        let projection = staged.evidence().clone();
        let stage = fixture.stage_path(&projection);
        drop(staged);
        fs::write(&stage, b"changed").unwrap();
        assert!(
            reopen_prepared_discard_intent(INTENT, &digest(), &workspace, RUN_ID, &projection,)
                .is_err()
        );

        let fixture = Fixture::new();
        let workspace = fixture.evidence();
        let staged = stage_discard_intent(INTENT, &digest(), &workspace, RUN_ID).unwrap();
        let projection = staged.evidence().clone();
        let stage = fixture.stage_path(&projection);
        drop(staged);
        fs::hard_link(&stage, fixture.parent.join("foreign-hardlink")).unwrap();
        assert!(
            reopen_prepared_discard_intent(INTENT, &digest(), &workspace, RUN_ID, &projection,)
                .is_err()
        );

        let fixture = Fixture::new();
        let workspace = fixture.evidence();
        let staged = stage_discard_intent(INTENT, &digest(), &workspace, RUN_ID).unwrap();
        let projection = staged.evidence().clone();
        let stage = fixture.stage_path(&projection);
        drop(staged);
        fs::write(format!("{}:foreign", stage.display()), b"ads").unwrap();
        assert!(
            reopen_prepared_discard_intent(INTENT, &digest(), &workspace, RUN_ID, &projection,)
                .is_err()
        );

        let fixture = Fixture::new();
        let workspace = fixture.evidence();
        let staged = stage_discard_intent(INTENT, &digest(), &workspace, RUN_ID).unwrap();
        let mut projection = staged.evidence().clone();
        drop(staged);
        projection.run_id = "run-two".to_owned();
        assert!(matches!(
            reopen_prepared_discard_intent(INTENT, &digest(), &workspace, RUN_ID, &projection),
            Err(DiscardIntentError::Contract(_))
        ));
    }

    #[test]
    fn readonly_and_invalid_input_and_production_surface_fail_closed() {
        let fixture = Fixture::new();
        let workspace = fixture.evidence();
        let staged = stage_discard_intent(INTENT, &digest(), &workspace, RUN_ID).unwrap();
        let projection = staged.evidence().clone();
        let stage = fixture.stage_path(&projection);
        drop(staged);
        let mut permissions = fs::metadata(&stage).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&stage, permissions).unwrap();
        assert!(
            reopen_prepared_discard_intent(INTENT, &digest(), &workspace, RUN_ID, &projection,)
                .is_err()
        );

        assert!(stage_discard_intent(&[], &digest(), &workspace, RUN_ID).is_err());
        assert!(
            stage_discard_intent(
                &vec![0_u8; MAX_INTENT_BYTES + 1],
                &"0".repeat(64),
                &workspace,
                RUN_ID,
            )
            .is_err()
        );
        assert!(stage_discard_intent(INTENT, &"0".repeat(64), &workspace, RUN_ID).is_err());

        let production = include_str!("discard_intent.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "remove_dir",
            "remove_file",
            "FileDispositionInfo",
            "acquire_windows_sandbox",
            "WindowsSandboxExecutionLease",
            "pub fn rename",
            "pub fn delete",
            "impl StagedDiscardIntent {\n    pub fn publish",
        ] {
            assert!(!production.contains(forbidden), "found {forbidden}");
        }
        assert_eq!(production.matches("rename_relative(").count(), 1);
        assert!(production.contains("&value.intent"));
    }
}
