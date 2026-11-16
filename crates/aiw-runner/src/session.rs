use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use aiw_evidence::canonical_json_bytes;
use aiw_orchestrator::RunLayout;
use aiw_probe::{WindowsSandboxCliProtocol, WorkspaceBindingEvidence};
use aiw_schema::is_safe_relative_path;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::{RunnerError, valid_uuid};

pub const SESSION_TRANSACTION_SCHEMA_VERSION: &str = "aiw.dev/wsb-session-transaction/v0alpha3";
pub const AUTHENTICATED_SESSION_TRANSACTION_SCHEMA: &str =
    "aiw.dev/wsb-session-transaction/v0alpha4";
const LEGACY_SESSION_TRANSACTION_SCHEMA_VERSION: &str = "aiw.dev/wsb-session-transaction/v0alpha2";
const MAX_TRANSACTION_BYTES: u64 = 64 * 1024;
const MAX_TRANSITIONS: usize = 16;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SessionTransactionState {
    StartIntent,
    Active,
    Unknown,
    CleanupIntent,
    CleanupVerified,
    RecoveryRequired,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionTransition {
    pub sequence: u32,
    pub state: SessionTransactionState,
    pub reason_code: String,
    pub previous_hash: String,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_latch_sha256: Option<String>,
}

#[derive(Default)]
struct HashPresence {
    present: bool,
    value: Option<String>,
}
impl<'de> Deserialize<'de> for HashPresence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self {
            present: true,
            value: Option::<String>::deserialize(deserializer)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransitionWire {
    sequence: u32,
    state: SessionTransactionState,
    reason_code: String,
    previous_hash: String,
    hash: String,
    #[serde(default)]
    channel_latch_sha256: HashPresence,
}
impl<'de> Deserialize<'de> for SessionTransition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let w = TransitionWire::deserialize(deserializer)?;
        if w.channel_latch_sha256.present && w.channel_latch_sha256.value.is_none() {
            return Err(serde::de::Error::custom(
                "channel latch null is not a historical field",
            ));
        }
        Ok(Self {
            sequence: w.sequence,
            state: w.state,
            reason_code: w.reason_code,
            previous_hash: w.previous_hash,
            hash: w.hash,
            channel_latch_sha256: w.channel_latch_sha256.value,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionRecoveryBinding {
    pub workspace: WorkspaceBindingEvidence,
    pub request_relative_path: String,
    pub provider_protocol: WindowsSandboxCliProtocol,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionTransaction {
    pub schema_version: String,
    pub run_id: String,
    pub plan_hash: String,
    pub project_revision_hash: String,
    pub provider_sha256: String,
    pub config_sha256: String,
    pub session_id: String,
    pub request_sha256: String,
    pub workspace_identity_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<SessionRecoveryBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor_sha256: Option<String>,
    pub transitions: Vec<SessionTransition>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionTransactionWire {
    schema_version: String,
    run_id: String,
    plan_hash: String,
    project_revision_hash: String,
    provider_sha256: String,
    config_sha256: String,
    session_id: String,
    request_sha256: String,
    workspace_identity_sha256: String,
    #[serde(default)]
    recovery: Option<SessionRecoveryBinding>,
    #[serde(default)]
    descriptor_sha256: HashPresence,
    transitions: Vec<SessionTransition>,
}

impl<'de> Deserialize<'de> for SessionTransaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SessionTransactionWire::deserialize(deserializer)?;
        if wire.descriptor_sha256.present && wire.descriptor_sha256.value.is_none() {
            return Err(serde::de::Error::custom(
                "channel descriptor null is not a historical field",
            ));
        }
        let transaction = Self {
            schema_version: wire.schema_version,
            run_id: wire.run_id,
            plan_hash: wire.plan_hash,
            project_revision_hash: wire.project_revision_hash,
            provider_sha256: wire.provider_sha256,
            config_sha256: wire.config_sha256,
            session_id: wire.session_id,
            request_sha256: wire.request_sha256,
            workspace_identity_sha256: wire.workspace_identity_sha256,
            recovery: wire.recovery,
            descriptor_sha256: wire.descriptor_sha256.value,
            transitions: wire.transitions,
        };
        validate_transaction(&transaction).map_err(serde::de::Error::custom)?;
        Ok(transaction)
    }
}

pub(crate) struct TransactionObservation {
    pub directory_present: bool,
    pub pending_present: bool,
    pub transaction: Option<SessionTransaction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingPublication {
    file_name: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionRecoveryInspection {
    pub transaction: Option<SessionTransaction>,
    pending: Vec<PendingPublication>,
}

impl SessionRecoveryInspection {
    pub(crate) fn pending_present(&self) -> bool {
        !self.pending.is_empty()
    }
}

#[derive(Debug)]
struct TransactionHistory {
    transaction: Option<SessionTransaction>,
    pending: Vec<PendingPublication>,
}

pub(crate) fn observe_transaction(
    layout: &RunLayout,
) -> Result<TransactionObservation, RunnerError> {
    let directory = layout.run_dir().join("wsb-session-transaction");
    if !directory.exists() {
        return Ok(TransactionObservation {
            directory_present: false,
            pending_present: false,
            transaction: None,
        });
    }
    let history = read_history(&directory)?;
    Ok(TransactionObservation {
        directory_present: true,
        pending_present: !history.pending.is_empty(),
        transaction: history.transaction,
    })
}

/// Reads the authoritative committed recovery point without requiring callers
/// to reconstruct any execution binding. This is read-only and grants no
/// provider or filesystem mutation authority.
pub(crate) fn inspect_for_recovery(
    layout: &RunLayout,
) -> Result<SessionRecoveryInspection, RunnerError> {
    let directory = layout.run_dir().join("wsb-session-transaction");
    if !directory.exists() {
        return Ok(SessionRecoveryInspection {
            transaction: None,
            pending: Vec::new(),
        });
    }
    let history = read_history(&directory)?;
    Ok(SessionRecoveryInspection {
        transaction: history.transaction,
        pending: history.pending,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct SessionBinding {
    pub run_id: String,
    pub plan_hash: String,
    pub project_revision_hash: String,
    pub provider_sha256: String,
    pub config_sha256: String,
    pub session_id: String,
    pub request_sha256: String,
    pub workspace_identity_sha256: String,
    pub recovery: Option<SessionRecoveryBinding>,
    pub descriptor_sha256: Option<String>,
}

impl SessionBinding {
    fn transaction(&self, reason_code: &str) -> Result<SessionTransaction, RunnerError> {
        let mut transaction = SessionTransaction {
            schema_version: if self.descriptor_sha256.is_some() {
                AUTHENTICATED_SESSION_TRANSACTION_SCHEMA
            } else {
                SESSION_TRANSACTION_SCHEMA_VERSION
            }
            .to_owned(),
            run_id: self.run_id.clone(),
            plan_hash: self.plan_hash.clone(),
            project_revision_hash: self.project_revision_hash.clone(),
            provider_sha256: self.provider_sha256.clone(),
            config_sha256: self.config_sha256.clone(),
            session_id: self.session_id.clone(),
            request_sha256: self.request_sha256.clone(),
            workspace_identity_sha256: self.workspace_identity_sha256.clone(),
            recovery: Some(self.recovery.clone().ok_or_else(|| {
                RunnerError::Transaction(
                    "new session transaction lacks its recovery binding".to_owned(),
                )
            })?),
            descriptor_sha256: self.descriptor_sha256.clone(),
            transitions: Vec::new(),
        };
        transaction.push(SessionTransactionState::StartIntent, reason_code)?;
        Ok(transaction)
    }

    fn matches(&self, transaction: &SessionTransaction) -> bool {
        transaction.run_id == self.run_id
            && transaction.plan_hash == self.plan_hash
            && transaction.project_revision_hash == self.project_revision_hash
            && transaction.provider_sha256 == self.provider_sha256
            && transaction.config_sha256 == self.config_sha256
            && transaction.session_id == self.session_id
            && transaction.request_sha256 == self.request_sha256
            && transaction.workspace_identity_sha256 == self.workspace_identity_sha256
            && transaction.descriptor_sha256 == self.descriptor_sha256
            && match transaction.schema_version.as_str() {
                AUTHENTICATED_SESSION_TRANSACTION_SCHEMA => {
                    self.descriptor_sha256.is_some()
                        && self.recovery.is_some()
                        && transaction.recovery == self.recovery
                }
                SESSION_TRANSACTION_SCHEMA_VERSION => {
                    self.recovery.is_some() && transaction.recovery == self.recovery
                }
                LEGACY_SESSION_TRANSACTION_SCHEMA_VERSION => {
                    self.recovery.is_none() && transaction.recovery.is_none()
                }
                _ => false,
            }
    }
}

impl SessionTransaction {
    fn push(
        &mut self,
        state: SessionTransactionState,
        reason_code: &str,
    ) -> Result<(), RunnerError> {
        let latch = self
            .transitions
            .last()
            .and_then(|t| t.channel_latch_sha256.clone());
        self.push_with_latch(state, reason_code, latch)
    }
    fn push_with_latch(
        &mut self,
        state: SessionTransactionState,
        reason_code: &str,
        latch: Option<String>,
    ) -> Result<(), RunnerError> {
        validate_reason(reason_code)?;
        let sequence = u32::try_from(self.transitions.len() + 1)
            .map_err(|_| RunnerError::Transaction("transition sequence overflow".to_owned()))?;
        let previous_hash = self
            .transitions
            .last()
            .map_or(ZERO_HASH, |transition| transition.hash.as_str())
            .to_owned();
        let hash = transition_hash(
            self,
            sequence,
            state,
            reason_code,
            &previous_hash,
            latch.as_deref(),
        )?;
        self.transitions.push(SessionTransition {
            sequence,
            state,
            reason_code: reason_code.to_owned(),
            previous_hash,
            hash,
            channel_latch_sha256: latch,
        });
        if let Err(error) = validate_transaction(self) {
            self.transitions.pop();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn current_state(&self) -> SessionTransactionState {
        self.transitions
            .last()
            .expect("validated transactions contain a transition")
            .state
    }
}

pub(crate) struct TransactionStore<'a> {
    layout: &'a RunLayout,
    binding: SessionBinding,
}

impl<'a> TransactionStore<'a> {
    pub(crate) fn new(layout: &'a RunLayout, binding: SessionBinding) -> Self {
        Self { layout, binding }
    }

    #[cfg(test)]
    pub(crate) fn seed_legacy_for_test(&self) -> Result<(), RunnerError> {
        let mut transaction = SessionTransaction {
            schema_version: LEGACY_SESSION_TRANSACTION_SCHEMA_VERSION.to_owned(),
            run_id: self.binding.run_id.clone(),
            plan_hash: self.binding.plan_hash.clone(),
            project_revision_hash: self.binding.project_revision_hash.clone(),
            provider_sha256: self.binding.provider_sha256.clone(),
            config_sha256: self.binding.config_sha256.clone(),
            session_id: self.binding.session_id.clone(),
            request_sha256: self.binding.request_sha256.clone(),
            workspace_identity_sha256: self.binding.workspace_identity_sha256.clone(),
            recovery: None,
            descriptor_sha256: None,
            transitions: Vec::new(),
        };
        transaction.push(SessionTransactionState::StartIntent, "approved-start")?;
        self.publish(&transaction)
    }

    pub(crate) fn create(&self, reason_code: &str) -> Result<SessionTransaction, RunnerError> {
        if self.load()?.is_some() {
            return Err(RunnerError::RecoveryRequired(
                "a provider session transaction already exists".to_owned(),
            ));
        }
        let transaction = self.binding.transaction(reason_code)?;
        self.publish(&transaction)?;
        Ok(transaction)
    }

    pub(crate) fn transition(
        &self,
        state: SessionTransactionState,
        reason_code: &str,
    ) -> Result<SessionTransaction, RunnerError> {
        let mut transaction = self.load()?.ok_or_else(|| {
            RunnerError::Transaction("session transaction does not exist".to_owned())
        })?;
        transaction.push(state, reason_code)?;
        self.publish(&transaction)?;
        Ok(transaction)
    }

    /// The immutable public latch is committed before any ACK transport write.
    pub(crate) fn commit_channel_latch(
        &self,
        digest: &str,
    ) -> Result<SessionTransaction, RunnerError> {
        validate_hash(digest)?;
        let mut transaction = self
            .load()?
            .ok_or_else(|| RunnerError::Transaction("channel transaction is absent".into()))?;
        if transaction.schema_version != AUTHENTICATED_SESSION_TRANSACTION_SCHEMA
            || transaction.current_state() != SessionTransactionState::Active
            || transaction
                .transitions
                .iter()
                .any(|t| t.channel_latch_sha256.is_some())
        {
            return Err(RunnerError::Transaction(
                "channel latch intent already consumed or unavailable".into(),
            ));
        }
        transaction.push_with_latch(
            SessionTransactionState::Active,
            "channel-ack-latched",
            Some(digest.into()),
        )?;
        self.publish(&transaction)?;
        Ok(transaction)
    }

    pub(crate) fn load_for_recovery(&self) -> Result<Option<SessionTransaction>, RunnerError> {
        Ok(self.inspect_for_recovery()?.transaction)
    }

    pub(crate) fn load_current(&self) -> Result<Option<SessionTransaction>, RunnerError> {
        self.load()
    }

    /// Reads committed snapshots and fingerprints staging artifacts without
    /// creating, deleting, repairing, or otherwise mutating transaction state.
    pub(crate) fn inspect_for_recovery(&self) -> Result<SessionRecoveryInspection, RunnerError> {
        let inspection = inspect_for_recovery(self.layout)?;
        if inspection
            .transaction
            .as_ref()
            .is_some_and(|transaction| !self.binding.matches(transaction))
        {
            return Err(RunnerError::Transaction(
                "session transaction belongs to different approved inputs".to_owned(),
            ));
        }
        Ok(inspection)
    }

    /// Rechecks that the read-only inspection is still current and returns the
    /// committed recovery point. It intentionally leaves every staging file in
    /// place; native provider and workspace authority are established outside
    /// this persistence boundary.
    pub(crate) fn resume_from(
        layout: &'a RunLayout,
        transaction: &SessionTransaction,
    ) -> Result<Self, RunnerError> {
        let current = inspect_for_recovery(layout)?;
        if current.transaction.as_ref() != Some(transaction) {
            return Err(RunnerError::RecoveryRequired(
                "session recovery transaction changed before resume".to_owned(),
            ));
        }
        Ok(Self {
            layout,
            binding: SessionBinding {
                run_id: transaction.run_id.clone(),
                plan_hash: transaction.plan_hash.clone(),
                project_revision_hash: transaction.project_revision_hash.clone(),
                provider_sha256: transaction.provider_sha256.clone(),
                config_sha256: transaction.config_sha256.clone(),
                session_id: transaction.session_id.clone(),
                request_sha256: transaction.request_sha256.clone(),
                workspace_identity_sha256: transaction.workspace_identity_sha256.clone(),
                descriptor_sha256: transaction.descriptor_sha256.clone(),
                recovery: transaction.recovery.clone(),
            },
        })
    }

    pub(crate) fn verify_inspection(
        &self,
        inspection: &SessionRecoveryInspection,
    ) -> Result<SessionTransaction, RunnerError> {
        let current = self.inspect_for_recovery()?;
        if &current != inspection {
            return Err(RunnerError::RecoveryRequired(
                "session recovery inspection changed before resume".to_owned(),
            ));
        }
        current.transaction.ok_or_else(|| {
            RunnerError::Transaction("session recovery transaction disappeared".to_owned())
        })
    }

    /// Deletes only the exact staging artifacts captured by a still-current
    /// inspection. The caller must invoke this only after independently
    /// establishing persisted workspace and exact-session provider authority.
    pub(crate) fn discard_pending_after_authority(
        &self,
        inspection: &SessionRecoveryInspection,
    ) -> Result<(), RunnerError> {
        let current = inspect_for_recovery(self.layout)?;
        if &current != inspection {
            return Err(RunnerError::RecoveryRequired(
                "session recovery inspection changed before staging discard".to_owned(),
            ));
        }
        let directory = self.directory();
        for pending in &inspection.pending {
            let path = directory.join(&pending.file_name);
            if pending_publication(&path)? != *pending {
                return Err(RunnerError::RecoveryRequired(
                    "session transaction staging changed before discard".to_owned(),
                ));
            }
        }
        for pending in &inspection.pending {
            let path = directory.join(&pending.file_name);
            fs::remove_file(path).map_err(transaction_io)?;
        }
        Ok(())
    }

    fn directory(&self) -> PathBuf {
        self.layout.run_dir().join("wsb-session-transaction")
    }

    fn ensure_directory(&self) -> Result<PathBuf, RunnerError> {
        let directory = self.directory();
        if !directory.exists() {
            fs::create_dir(&directory).map_err(transaction_io)?;
        }
        ensure_ordinary_directory(&directory)?;
        Ok(directory)
    }

    fn load(&self) -> Result<Option<SessionTransaction>, RunnerError> {
        let directory = self.directory();
        if !directory.exists() {
            return Ok(None);
        }
        let history = read_history(&directory)?;
        if !history.pending.is_empty() {
            return Err(RunnerError::RecoveryRequired(
                "session transaction staging requires recovery".to_owned(),
            ));
        }
        if history
            .transaction
            .as_ref()
            .is_some_and(|transaction| !self.binding.matches(transaction))
        {
            return Err(RunnerError::Transaction(
                "session transaction belongs to different approved inputs".to_owned(),
            ));
        }
        Ok(history.transaction)
    }

    fn publish(&self, transaction: &SessionTransaction) -> Result<(), RunnerError> {
        validate_transaction(transaction)?;
        if !self.binding.matches(transaction) {
            return Err(RunnerError::Transaction(
                "cannot publish a foreign session transaction".to_owned(),
            ));
        }
        let directory = self.ensure_directory()?;
        let sequence = transaction.transitions.len();
        let target = directory.join(format!("{sequence:020}.json"));
        let pending = directory.join(format!("{sequence:020}.json.pending"));
        if target.exists() || pending.exists() {
            return Err(RunnerError::RecoveryRequired(
                "session transaction publication conflicts with persisted state".to_owned(),
            ));
        }
        let mut bytes = serde_json::to_vec_pretty(transaction)
            .map_err(|error| RunnerError::Transaction(error.to_string()))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
            return Err(RunnerError::Transaction(
                "session transaction exceeds its fixed bound".to_owned(),
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
            .map_err(transaction_io)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(transaction_io)?;
        fs::hard_link(&pending, &target).map_err(transaction_io)?;
        ensure_ordinary_file(&target)?;
        fs::remove_file(&pending).map_err(transaction_io)
    }
}

fn read_history(directory: &Path) -> Result<TransactionHistory, RunnerError> {
    ensure_ordinary_directory(directory)?;
    let mut snapshots = Vec::new();
    let mut pending = Vec::new();
    for entry in fs::read_dir(directory).map_err(transaction_io)? {
        let path = entry.map_err(transaction_io)?.path();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| RunnerError::Transaction("non-Unicode transaction path".to_owned()))?;
        if name.ends_with(".pending") {
            parse_pending_name(name)?;
            pending.push(pending_publication(&path)?);
            if pending.len() > MAX_TRANSITIONS {
                return Err(RunnerError::Transaction(
                    "too many session transaction staging artifacts".to_owned(),
                ));
            }
            continue;
        }
        let sequence = parse_snapshot_name(name)?;
        snapshots.push((sequence, path));
        if snapshots.len() > MAX_TRANSITIONS {
            return Err(RunnerError::Transaction(
                "too many session transaction snapshots".to_owned(),
            ));
        }
    }
    snapshots.sort_by_key(|(sequence, _)| *sequence);
    let mut previous: Option<SessionTransaction> = None;
    for (index, (sequence, path)) in snapshots.into_iter().enumerate() {
        if usize::try_from(sequence).ok() != Some(index + 1) {
            return Err(RunnerError::Transaction(
                "session transaction sequence is not contiguous".to_owned(),
            ));
        }
        let transaction: SessionTransaction = read_bounded_json(&path)?;
        if transaction.transitions.len() != index + 1 {
            return Err(RunnerError::Transaction(
                "snapshot does not match its sequence".to_owned(),
            ));
        }
        if let Some(previous) = &previous {
            if transaction.schema_version != previous.schema_version {
                return Err(RunnerError::Transaction(
                    "session transaction history mixes schema versions".to_owned(),
                ));
            }
            if transaction.transitions[..index] != previous.transitions
                || !same_binding(previous, &transaction)
            {
                return Err(RunnerError::Transaction(
                    "session transaction history was rewritten".to_owned(),
                ));
            }
        }
        previous = Some(transaction);
    }
    pending.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    Ok(TransactionHistory {
        transaction: previous,
        pending,
    })
}

fn pending_publication(path: &Path) -> Result<PendingPublication, RunnerError> {
    ensure_ordinary_file(path)?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| RunnerError::Transaction("non-Unicode transaction path".to_owned()))?;
    parse_pending_name(file_name)?;
    let metadata = fs::metadata(path).map_err(transaction_io)?;
    if metadata.len() > MAX_TRANSACTION_BYTES {
        return Err(RunnerError::Transaction(
            "transaction staging exceeds its fixed bound".to_owned(),
        ));
    }
    let file = File::open(path).map_err(transaction_io)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_TRANSACTION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(transaction_io)?;
    if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
        return Err(RunnerError::Transaction(
            "transaction staging changed beyond its bound".to_owned(),
        ));
    }
    Ok(PendingPublication {
        file_name: file_name.to_owned(),
        size_bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

fn validate_transaction(transaction: &SessionTransaction) -> Result<(), RunnerError> {
    if !matches!(
        transaction.schema_version.as_str(),
        SESSION_TRANSACTION_SCHEMA_VERSION
            | LEGACY_SESSION_TRANSACTION_SCHEMA_VERSION
            | AUTHENTICATED_SESSION_TRANSACTION_SCHEMA
    ) || !valid_run_id(&transaction.run_id)
        || !valid_uuid(&transaction.session_id)
        || transaction
            .session_id
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
        || transaction.transitions.is_empty()
        || transaction.transitions.len() > MAX_TRANSITIONS
    {
        return Err(RunnerError::Transaction(
            "session transaction binding is invalid".to_owned(),
        ));
    }
    match transaction.schema_version.as_str() {
        SESSION_TRANSACTION_SCHEMA_VERSION | AUTHENTICATED_SESSION_TRANSACTION_SCHEMA => {
            let recovery = transaction.recovery.as_ref().ok_or_else(|| {
                RunnerError::Transaction(
                    "v0alpha3 session transaction lacks its recovery binding".to_owned(),
                )
            })?;
            validate_recovery_binding(recovery, &transaction.workspace_identity_sha256)?;
        }
        LEGACY_SESSION_TRANSACTION_SCHEMA_VERSION if transaction.recovery.is_none() => {}
        LEGACY_SESSION_TRANSACTION_SCHEMA_VERSION => {
            return Err(RunnerError::Transaction(
                "v0alpha2 session transaction contains a mixed-version recovery binding".to_owned(),
            ));
        }
        _ => unreachable!("schema version was bounded above"),
    }
    if transaction.schema_version == AUTHENTICATED_SESSION_TRANSACTION_SCHEMA {
        validate_hash(transaction.descriptor_sha256.as_deref().ok_or_else(|| {
            RunnerError::Transaction("authenticated transaction lacks descriptor".into())
        })?)?;
    } else if transaction.descriptor_sha256.is_some()
        || transaction
            .transitions
            .iter()
            .any(|t| t.channel_latch_sha256.is_some())
    {
        return Err(RunnerError::Transaction(
            "historical transaction cannot acquire channel fields".into(),
        ));
    }
    for value in [
        &transaction.plan_hash,
        &transaction.project_revision_hash,
        &transaction.provider_sha256,
        &transaction.config_sha256,
        &transaction.request_sha256,
        &transaction.workspace_identity_sha256,
    ] {
        validate_hash(value)?;
    }
    let mut previous_state = None;
    let mut previous_hash = ZERO_HASH.to_owned();
    let mut previous_latch: Option<&str> = None;
    let mut provider_start_intent = false;
    for (index, transition) in transaction.transitions.iter().enumerate() {
        if usize::try_from(transition.sequence).ok() != Some(index + 1)
            || transition.previous_hash != previous_hash
        {
            return Err(RunnerError::Transaction(
                "session transition sequence or chain is invalid".to_owned(),
            ));
        }
        validate_reason(&transition.reason_code)?;
        let latch_step = transaction.schema_version == AUTHENTICATED_SESSION_TRANSACTION_SCHEMA
            && previous_state == Some(SessionTransactionState::Active)
            && transition.state == SessionTransactionState::Active
            && transition.reason_code == "channel-ack-latched"
            && previous_latch.is_none()
            && transition.channel_latch_sha256.is_some();
        let provider_step = transaction.schema_version == AUTHENTICATED_SESSION_TRANSACTION_SCHEMA
            && previous_state == Some(SessionTransactionState::StartIntent)
            && transition.state == SessionTransactionState::StartIntent
            && transition.reason_code == "provider-start-intent"
            && !provider_start_intent
            && index == 1
            && previous_latch.is_none();
        let preflight_cleanup = transaction.schema_version
            == AUTHENTICATED_SESSION_TRANSACTION_SCHEMA
            && previous_state == Some(SessionTransactionState::StartIntent)
            && !provider_start_intent
            && transition.state == SessionTransactionState::CleanupIntent
            && transition.reason_code == "channel-preflight-cleanup";
        if transaction.schema_version == AUTHENTICATED_SESSION_TRANSACTION_SCHEMA
            && ((index == 0 && transition.reason_code != "channel-provider-preflight")
                || (transition.reason_code == "provider-start-intent" && !provider_step)
                || (transition.reason_code == "channel-preflight-cleanup" && !preflight_cleanup)
                || (matches!(
                    transition.state,
                    SessionTransactionState::Active | SessionTransactionState::Unknown
                ) && !provider_start_intent))
        {
            return Err(RunnerError::Transaction(
                "authenticated provider phase authority differs".into(),
            ));
        }
        if !valid_transition(previous_state, transition.state)
            && !latch_step
            && !provider_step
            && !preflight_cleanup
        {
            return Err(RunnerError::Transaction(
                "session transition grammar is invalid".to_owned(),
            ));
        }
        if let Some(latch) = transition.channel_latch_sha256.as_deref() {
            validate_hash(latch)?;
        }
        if (!latch_step && transition.channel_latch_sha256.as_deref() != previous_latch)
            || (transition.reason_code == "channel-ack-latched" && !latch_step)
        {
            return Err(RunnerError::Transaction(
                "channel latch changed, disappeared or lacks its unique intent transition".into(),
            ));
        }
        let expected = transition_hash(
            transaction,
            transition.sequence,
            transition.state,
            &transition.reason_code,
            &transition.previous_hash,
            transition.channel_latch_sha256.as_deref(),
        )?;
        if transition.hash != expected {
            return Err(RunnerError::Transaction(
                "session transition hash is invalid".to_owned(),
            ));
        }
        previous_state = Some(transition.state);
        previous_hash.clone_from(&transition.hash);
        previous_latch = transition.channel_latch_sha256.as_deref();
        provider_start_intent |= provider_step;
    }
    Ok(())
}

fn validate_recovery_binding(
    recovery: &SessionRecoveryBinding,
    workspace_identity_sha256: &str,
) -> Result<(), RunnerError> {
    recovery
        .workspace
        .validate()
        .map_err(|error| RunnerError::Transaction(error.to_owned()))?;
    if recovery.request_relative_path.len() > 512
        || !recovery.request_relative_path.is_ascii()
        || recovery.request_relative_path.contains('\\')
        || !is_safe_relative_path(&recovery.request_relative_path)
        || recovery.provider_protocol.adapter().is_err()
    {
        return Err(RunnerError::Transaction(
            "session recovery binding is invalid".to_owned(),
        ));
    }
    let value = serde_json::to_value(&recovery.workspace)
        .map_err(|error| RunnerError::Transaction(error.to_string()))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|error| RunnerError::Transaction(error.to_string()))?;
    if hex::encode(Sha256::digest(bytes)) != workspace_identity_sha256 {
        return Err(RunnerError::Transaction(
            "session recovery workspace does not match its identity hash".to_owned(),
        ));
    }
    Ok(())
}

fn valid_run_id(value: &str) -> bool {
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
    !value.is_empty()
        && value.len() <= 64
        && !matches!(value, "." | "..")
        && !value.ends_with('.')
        && !reserved
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_transition(
    previous: Option<SessionTransactionState>,
    next: SessionTransactionState,
) -> bool {
    use SessionTransactionState::{
        Active, CleanupIntent, CleanupVerified, RecoveryRequired, StartIntent, Unknown,
    };
    matches!(
        (previous, next),
        (None, StartIntent)
            | (Some(StartIntent), Active | Unknown)
            | (Some(Active | Unknown), CleanupIntent)
            | (Some(CleanupIntent), CleanupVerified | RecoveryRequired)
            | (Some(RecoveryRequired), CleanupIntent)
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransitionHashInputV2<'a> {
    schema_version: &'a str,
    run_id: &'a str,
    plan_hash: &'a str,
    project_revision_hash: &'a str,
    provider_sha256: &'a str,
    config_sha256: &'a str,
    session_id: &'a str,
    request_sha256: &'a str,
    workspace_identity_sha256: &'a str,
    sequence: u32,
    state: SessionTransactionState,
    reason_code: &'a str,
    previous_hash: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransitionHashInputV3<'a> {
    schema_version: &'a str,
    run_id: &'a str,
    plan_hash: &'a str,
    project_revision_hash: &'a str,
    provider_sha256: &'a str,
    config_sha256: &'a str,
    session_id: &'a str,
    request_sha256: &'a str,
    workspace_identity_sha256: &'a str,
    recovery: &'a SessionRecoveryBinding,
    sequence: u32,
    state: SessionTransactionState,
    reason_code: &'a str,
    previous_hash: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransitionHashInputV4<'a> {
    #[serde(flatten)]
    base: TransitionHashInputV3<'a>,
    descriptor_sha256: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_latch_sha256: Option<&'a str>,
}

fn transition_hash(
    transaction: &SessionTransaction,
    sequence: u32,
    state: SessionTransactionState,
    reason_code: &str,
    previous_hash: &str,
    channel_latch_sha256: Option<&str>,
) -> Result<String, RunnerError> {
    let value = match transaction.schema_version.as_str() {
        LEGACY_SESSION_TRANSACTION_SCHEMA_VERSION => serde_json::to_value(TransitionHashInputV2 {
            schema_version: &transaction.schema_version,
            run_id: &transaction.run_id,
            plan_hash: &transaction.plan_hash,
            project_revision_hash: &transaction.project_revision_hash,
            provider_sha256: &transaction.provider_sha256,
            config_sha256: &transaction.config_sha256,
            session_id: &transaction.session_id,
            request_sha256: &transaction.request_sha256,
            workspace_identity_sha256: &transaction.workspace_identity_sha256,
            sequence,
            state,
            reason_code,
            previous_hash,
        }),
        SESSION_TRANSACTION_SCHEMA_VERSION | AUTHENTICATED_SESSION_TRANSACTION_SCHEMA => {
            let recovery = transaction.recovery.as_ref().ok_or_else(|| {
                RunnerError::Transaction(
                    "v0alpha3 transition lacks its recovery binding".to_owned(),
                )
            })?;
            let base = TransitionHashInputV3 {
                schema_version: &transaction.schema_version,
                run_id: &transaction.run_id,
                plan_hash: &transaction.plan_hash,
                project_revision_hash: &transaction.project_revision_hash,
                provider_sha256: &transaction.provider_sha256,
                config_sha256: &transaction.config_sha256,
                session_id: &transaction.session_id,
                request_sha256: &transaction.request_sha256,
                workspace_identity_sha256: &transaction.workspace_identity_sha256,
                recovery,
                sequence,
                state,
                reason_code,
                previous_hash,
            };
            if transaction.schema_version == AUTHENTICATED_SESSION_TRANSACTION_SCHEMA {
                serde_json::to_value(TransitionHashInputV4 {
                    base,
                    descriptor_sha256: transaction.descriptor_sha256.as_deref().ok_or_else(
                        || RunnerError::Transaction("authenticated hash lacks descriptor".into()),
                    )?,
                    channel_latch_sha256,
                })
            } else {
                serde_json::to_value(base)
            }
        }
        _ => {
            return Err(RunnerError::Transaction(
                "unsupported session transaction schema version".to_owned(),
            ));
        }
    }
    .map_err(|error| RunnerError::Transaction(error.to_string()))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|error| RunnerError::Transaction(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_hash(value: &str) -> Result<(), RunnerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(RunnerError::Transaction(
            "session transaction contains a noncanonical hash".to_owned(),
        ));
    }
    Ok(())
}

fn validate_reason(value: &str) -> Result<(), RunnerError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(RunnerError::Transaction(
            "session transition reason code is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn same_binding(left: &SessionTransaction, right: &SessionTransaction) -> bool {
    left.schema_version == right.schema_version
        && left.run_id == right.run_id
        && left.plan_hash == right.plan_hash
        && left.project_revision_hash == right.project_revision_hash
        && left.provider_sha256 == right.provider_sha256
        && left.config_sha256 == right.config_sha256
        && left.session_id == right.session_id
        && left.request_sha256 == right.request_sha256
        && left.workspace_identity_sha256 == right.workspace_identity_sha256
        && left.recovery == right.recovery
        && left.descriptor_sha256 == right.descriptor_sha256
}

fn parse_snapshot_name(name: &str) -> Result<u32, RunnerError> {
    let value = name
        .strip_suffix(".json")
        .ok_or_else(|| RunnerError::Transaction("unexpected transaction entry".to_owned()))?;
    if value.len() != 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RunnerError::Transaction(
            "invalid transaction snapshot name".to_owned(),
        ));
    }
    value
        .parse()
        .map_err(|_| RunnerError::Transaction("invalid transaction sequence".to_owned()))
}

fn parse_pending_name(name: &str) -> Result<(), RunnerError> {
    let value = name
        .strip_suffix(".json.pending")
        .ok_or_else(|| RunnerError::Transaction("unexpected staging entry".to_owned()))?;
    if value.len() != 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RunnerError::Transaction(
            "invalid transaction staging name".to_owned(),
        ));
    }
    Ok(())
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, RunnerError> {
    ensure_ordinary_file(path)?;
    let metadata = fs::metadata(path).map_err(transaction_io)?;
    if metadata.len() > MAX_TRANSACTION_BYTES {
        return Err(RunnerError::Transaction(
            "session transaction exceeds its fixed bound".to_owned(),
        ));
    }
    let file = File::open(path).map_err(transaction_io)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_TRANSACTION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(transaction_io)?;
    if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
        return Err(RunnerError::Transaction(
            "session transaction changed beyond its bound".to_owned(),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| RunnerError::Transaction(error.to_string()))
}

fn ensure_ordinary_directory(path: &Path) -> Result<(), RunnerError> {
    ensure_no_reparse_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(transaction_io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
        return Err(RunnerError::Transaction(
            "transaction directory is not an ordinary local directory".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_ordinary_file(path: &Path) -> Result<(), RunnerError> {
    ensure_no_reparse_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(transaction_io)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
        return Err(RunnerError::Transaction(
            "transaction artifact is not an ordinary local file".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_no_reparse_components(path: &Path) -> Result<(), RunnerError> {
    for component in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if component.as_os_str().is_empty() || !component.exists() {
            continue;
        }
        let metadata = fs::symlink_metadata(component).map_err(transaction_io)?;
        if metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
            return Err(RunnerError::Transaction(
                "transaction path contains a link or reparse point".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn has_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn has_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn transaction_io(error: std::io::Error) -> RunnerError {
    RunnerError::Transaction(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "aiw-session-store-test-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn recovery_binding() -> SessionRecoveryBinding {
        let owner = "S-1-5-21-1".to_owned();
        let identity = |path: &str, marker: u8| aiw_probe::WindowsFileIdentity {
            final_path: path.to_owned(),
            volume_serial_number: "0".repeat(16),
            file_id: format!("{marker:032x}"),
        };
        SessionRecoveryBinding {
            workspace: WorkspaceBindingEvidence {
                schema_version: aiw_probe::WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
                policy: aiw_probe::WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
                security_policy_sha256: aiw_probe::workspace_policy_hash(&owner),
                owner_sid: owner.clone(),
                dacl_protected: true,
                allowed_sids: vec![aiw_probe::WINDOWS_SYSTEM_SID.to_owned(), owner],
                parent: identity("C:\\AIW", 1),
                root: identity("C:\\AIW\\run-one", 2),
                tools: identity("C:\\AIW\\run-one\\tools", 3),
                output: identity("C:\\AIW\\run-one\\output", 4),
            },
            request_relative_path: "request.json".to_owned(),
            provider_protocol: WindowsSandboxCliProtocol {
                cli_version: "0.8.107.0".to_owned(),
                protocol: "windowsSandboxCli/v0.8.107.0".to_owned(),
                list_schema: "WindowsSandboxEnvironments/Id".to_owned(),
            },
        }
    }

    fn workspace_hash(recovery: &SessionRecoveryBinding) -> String {
        let value = serde_json::to_value(&recovery.workspace).unwrap();
        let bytes = canonical_json_bytes(&value).unwrap();
        hex::encode(Sha256::digest(bytes))
    }

    fn binding() -> SessionBinding {
        let recovery = recovery_binding();
        SessionBinding {
            run_id: "run-one".to_owned(),
            plan_hash: "1".repeat(64),
            project_revision_hash: "2".repeat(64),
            provider_sha256: "3".repeat(64),
            config_sha256: "4".repeat(64),
            session_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            request_sha256: "5".repeat(64),
            workspace_identity_sha256: workspace_hash(&recovery),
            recovery: Some(recovery),
            descriptor_sha256: None,
        }
    }

    #[test]
    fn authenticated_descriptor_and_latch_are_bound_without_rewriting_prior_hashes() {
        let mut bound = binding();
        bound.descriptor_sha256 = Some("a".repeat(64));
        let mut tx = bound.transaction("channel-provider-preflight").unwrap();
        assert_eq!(tx.schema_version, AUTHENTICATED_SESSION_TRANSACTION_SCHEMA);
        tx.push(
            SessionTransactionState::StartIntent,
            "provider-start-intent",
        )
        .unwrap();
        tx.push(SessionTransactionState::Active, "start-confirmed")
            .unwrap();
        let prior = tx.transitions.clone();
        tx.push_with_latch(
            SessionTransactionState::Active,
            "channel-ack-latched",
            Some("b".repeat(64)),
        )
        .unwrap();
        assert_eq!(tx.transitions[..3], prior);
        let latched = tx.clone();
        assert!(
            tx.push_with_latch(
                SessionTransactionState::Active,
                "channel-ack-latched",
                Some("c".repeat(64))
            )
            .is_err()
        );
        assert_eq!(tx, latched);
        tx.push(SessionTransactionState::CleanupIntent, "cleanup")
            .unwrap();
        assert_eq!(
            tx.transitions
                .last()
                .unwrap()
                .channel_latch_sha256
                .as_deref(),
            Some("b".repeat(64).as_str())
        );
        tx.push(SessionTransactionState::CleanupVerified, "cleanup-verified")
            .unwrap();
        assert!(validate_transaction(&tx).is_ok());
        let mut changed = tx.clone();
        changed.descriptor_sha256 = Some("d".repeat(64));
        assert!(validate_transaction(&changed).is_err());
        let mut changed = tx.clone();
        changed.transitions.last_mut().unwrap().channel_latch_sha256 = None;
        assert!(validate_transaction(&changed).is_err());
        let mut mixed = tx;
        mixed.schema_version = SESSION_TRANSACTION_SCHEMA_VERSION.into();
        assert!(validate_transaction(&mixed).is_err());
    }

    #[test]
    fn historical_transactions_reject_channel_fields_even_null() {
        for mut tx in [
            binding().transaction("approved-start").unwrap(),
            legacy_transaction("approved-start"),
        ] {
            let before = serde_json::to_value(&tx).unwrap();
            assert!(before.get("descriptorSha256").is_none());
            assert!(before["transitions"][0].get("channelLatchSha256").is_none());
            for value in [serde_json::Value::Null, serde_json::json!("a".repeat(64))] {
                let mut wire = before.clone();
                wire["descriptorSha256"] = value.clone();
                assert!(serde_json::from_value::<SessionTransaction>(wire).is_err());
                let mut wire = before.clone();
                wire["transitions"][0]["channelLatchSha256"] = value;
                assert!(serde_json::from_value::<SessionTransaction>(wire).is_err());
            }
            assert_eq!(serde_json::to_value(&tx).unwrap(), before);
            tx.push(SessionTransactionState::Active, "start-confirmed")
                .unwrap();
            assert!(validate_transaction(&tx).is_ok());
        }
    }

    #[test]
    fn authenticated_provider_start_marker_is_single_and_preflight_never_grants_start() {
        let mut bound = binding();
        bound.descriptor_sha256 = Some("a".repeat(64));
        let mut tx = bound.transaction("channel-provider-preflight").unwrap();
        assert!(super::super::channel_start_not_attempted(&tx));
        let before = tx.clone();
        assert!(
            tx.push(SessionTransactionState::Active, "start-confirmed")
                .is_err()
        );
        assert!(
            tx.push(SessionTransactionState::Unknown, "start-outcome-unknown")
                .is_err()
        );
        assert_eq!(tx, before);
        let mut clean = tx.clone();
        clean
            .push(
                SessionTransactionState::CleanupIntent,
                "channel-preflight-cleanup",
            )
            .unwrap();
        clean
            .push(
                SessionTransactionState::CleanupVerified,
                "channel-preflight-cleanup-verified",
            )
            .unwrap();
        assert!(super::super::channel_start_not_attempted(&clean));
        assert!(super::super::start_settled(&clean));
        tx.push(
            SessionTransactionState::StartIntent,
            "provider-start-intent",
        )
        .unwrap();
        assert!(!super::super::channel_start_not_attempted(&tx));
        assert!(
            tx.push(
                SessionTransactionState::StartIntent,
                "provider-start-intent"
            )
            .is_err()
        );
        assert!(
            tx.push(
                SessionTransactionState::CleanupIntent,
                "channel-preflight-cleanup"
            )
            .is_err()
        );
        tx.push(SessionTransactionState::Unknown, "start-outcome-unknown")
            .unwrap();
        assert!(!super::super::start_settled(&tx));
        let legacy = binding().transaction("channel-provider-preflight").unwrap();
        assert!(!super::super::channel_start_not_attempted(&legacy));
    }

    #[test]
    fn public_latch_publication_is_bound_to_committed_active_history_once() {
        let root = TestRoot::new();
        let layout = layout(&root);
        let mut bound = binding();
        bound.descriptor_sha256 = Some("a".repeat(64));
        let store = TransactionStore::new(&layout, bound);
        store.create("channel-provider-preflight").unwrap();
        assert!(store.commit_channel_latch(&"b".repeat(64)).is_err());
        store
            .transition(
                SessionTransactionState::StartIntent,
                "provider-start-intent",
            )
            .unwrap();
        assert!(store.commit_channel_latch(&"b".repeat(64)).is_err());
        store
            .transition(SessionTransactionState::Active, "start-confirmed")
            .unwrap();
        let before = store.load_current().unwrap().unwrap();
        let latched = store.commit_channel_latch(&"b".repeat(64)).unwrap();
        assert_eq!(latched.transitions[..3], before.transitions);
        assert!(store.commit_channel_latch(&"c".repeat(64)).is_err());
        assert_eq!(store.load_current().unwrap().unwrap(), latched);
        store
            .transition(SessionTransactionState::CleanupIntent, "cleanup")
            .unwrap();
        let current = store.load_current().unwrap().unwrap();
        assert_eq!(
            current
                .transitions
                .last()
                .unwrap()
                .channel_latch_sha256
                .as_deref(),
            Some("b".repeat(64).as_str())
        );
    }

    fn legacy_transaction(reason_code: &str) -> SessionTransaction {
        let binding = binding();
        let mut transaction = SessionTransaction {
            schema_version: LEGACY_SESSION_TRANSACTION_SCHEMA_VERSION.to_owned(),
            run_id: binding.run_id,
            plan_hash: binding.plan_hash,
            project_revision_hash: binding.project_revision_hash,
            provider_sha256: binding.provider_sha256,
            config_sha256: binding.config_sha256,
            session_id: binding.session_id,
            request_sha256: binding.request_sha256,
            workspace_identity_sha256: binding.workspace_identity_sha256,
            recovery: None,
            descriptor_sha256: None,
            transitions: Vec::new(),
        };
        transaction
            .push(SessionTransactionState::StartIntent, reason_code)
            .unwrap();
        transaction
    }

    fn layout(root: &TestRoot) -> RunLayout {
        let layout = RunLayout::new(&root.0, "run-one").unwrap();
        fs::create_dir_all(layout.run_dir()).unwrap();
        layout
    }

    fn write_snapshot(layout: &RunLayout, transaction: &SessionTransaction) {
        let directory = layout.run_dir().join("wsb-session-transaction");
        fs::create_dir_all(&directory).unwrap();
        let sequence = transaction.transitions.len();
        let path = directory.join(format!("{sequence:020}.json"));
        fs::write(path, serde_json::to_vec_pretty(transaction).unwrap()).unwrap();
    }

    #[test]
    fn transition_grammar_is_monotonic_and_strict() {
        let binding = binding();
        let mut transaction = binding.transaction("approved-start").unwrap();
        transaction
            .push(SessionTransactionState::Active, "start-confirmed")
            .unwrap();
        assert!(
            transaction
                .push(SessionTransactionState::CleanupVerified, "invalid-skip")
                .is_err()
        );
        let mut value = serde_json::to_value(&transaction).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SessionTransaction>(value).is_err());
    }

    #[test]
    fn direct_deserialization_rejects_forged_or_corrupt_snapshots() {
        let binding = binding();
        let valid = binding.transaction("approved-start").unwrap();
        assert!(
            serde_json::from_value::<SessionTransaction>(serde_json::to_value(&valid).unwrap())
                .is_ok()
        );

        let mut forged_hash = serde_json::to_value(&valid).unwrap();
        forged_hash["transitions"][0]["hash"] = serde_json::json!("f".repeat(64));
        assert!(serde_json::from_value::<SessionTransaction>(forged_hash).is_err());

        let mut empty = serde_json::to_value(&valid).unwrap();
        empty["transitions"] = serde_json::json!([]);
        assert!(serde_json::from_value::<SessionTransaction>(empty).is_err());

        let mut legacy = serde_json::to_value(&valid).unwrap();
        legacy["schemaVersion"] = serde_json::json!("aiw.dev/wsb-session-transaction/v0alpha1");
        assert!(serde_json::from_value::<SessionTransaction>(legacy).is_err());

        let mut workspace_tamper = serde_json::to_value(&valid).unwrap();
        workspace_tamper["workspaceIdentitySha256"] = serde_json::json!("7".repeat(64));
        assert!(serde_json::from_value::<SessionTransaction>(workspace_tamper).is_err());

        let mut reserved = serde_json::to_value(&valid).unwrap();
        reserved["runId"] = serde_json::json!("con");
        assert!(serde_json::from_value::<SessionTransaction>(reserved).is_err());

        let mut invalid_grammar = valid.clone();
        invalid_grammar.transitions[0].state = SessionTransactionState::CleanupVerified;
        invalid_grammar.transitions[0].hash = transition_hash(
            &invalid_grammar,
            1,
            SessionTransactionState::CleanupVerified,
            "approved-start",
            ZERO_HASH,
            None,
        )
        .unwrap();
        assert!(
            serde_json::from_value::<SessionTransaction>(
                serde_json::to_value(invalid_grammar).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn v0alpha3_roundtrips_and_binds_recovery_fields_into_the_hash_chain() {
        let transaction = binding().transaction("approved-start").unwrap();
        assert_eq!(
            transaction.schema_version,
            SESSION_TRANSACTION_SCHEMA_VERSION
        );
        assert!(transaction.recovery.is_some());
        let roundtrip: SessionTransaction =
            serde_json::from_value(serde_json::to_value(&transaction).unwrap()).unwrap();
        assert_eq!(roundtrip, transaction);

        let mut request_tamper = serde_json::to_value(&transaction).unwrap();
        request_tamper["recovery"]["requestRelativePath"] = serde_json::json!("other.json");
        assert!(serde_json::from_value::<SessionTransaction>(request_tamper).is_err());

        let mut missing_recovery = serde_json::to_value(&transaction).unwrap();
        missing_recovery.as_object_mut().unwrap().remove("recovery");
        assert!(serde_json::from_value::<SessionTransaction>(missing_recovery).is_err());
    }

    #[test]
    fn v0alpha2_roundtrips_with_its_exact_legacy_hash_input() {
        let transaction = legacy_transaction("approved-start");
        let roundtrip: SessionTransaction =
            serde_json::from_value(serde_json::to_value(&transaction).unwrap()).unwrap();
        assert_eq!(roundtrip, transaction);

        let root = TestRoot::new();
        let layout = layout(&root);
        write_snapshot(&layout, &transaction);
        assert_eq!(
            inspect_for_recovery(&layout).unwrap().transaction,
            Some(transaction.clone())
        );

        let mut exact_fixture = transaction.clone();
        exact_fixture.workspace_identity_sha256 = "6".repeat(64);
        exact_fixture.transitions.clear();
        exact_fixture
            .push(SessionTransactionState::StartIntent, "approved-start")
            .unwrap();
        assert_eq!(
            exact_fixture.transitions[0].hash,
            "2c8bb65f414f9b25490f3cda713e36cd6b78bc94fa1a5d5316005881b0bb597e"
        );

        let mut mixed_fields = serde_json::to_value(&transaction).unwrap();
        mixed_fields["recovery"] = serde_json::to_value(recovery_binding()).unwrap();
        assert!(serde_json::from_value::<SessionTransaction>(mixed_fields).is_err());
    }

    #[test]
    fn history_rejects_mixed_v0alpha2_and_v0alpha3_snapshots() {
        let root = TestRoot::new();
        let layout = layout(&root);
        let legacy = legacy_transaction("approved-start");
        write_snapshot(&layout, &legacy);

        let mut current = binding().transaction("approved-start").unwrap();
        current
            .push(SessionTransactionState::Unknown, "start-outcome-unknown")
            .unwrap();
        write_snapshot(&layout, &current);

        let error = read_history(&layout.run_dir().join("wsb-session-transaction")).unwrap_err();
        assert!(
            error.to_string().contains("mixes schema versions"),
            "{error}"
        );
    }

    #[test]
    fn recovery_inspection_is_read_only_until_authorized_pending_discard() {
        let root = TestRoot::new();
        let layout = layout(&root);
        let store = TransactionStore::new(&layout, binding());
        let committed = store.create("approved-start").unwrap();
        let pending = layout
            .run_dir()
            .join("wsb-session-transaction")
            .join("00000000000000000002.json.pending");
        fs::write(&pending, b"interrupted-publication").unwrap();

        let inspection = store.inspect_for_recovery().unwrap();
        assert!(inspection.pending_present());
        assert_eq!(inspection.transaction.as_ref(), Some(&committed));
        assert_eq!(store.verify_inspection(&inspection).unwrap(), committed);
        assert!(pending.exists(), "read-only recovery removed staging");

        store.discard_pending_after_authority(&inspection).unwrap();
        assert!(!pending.exists());
        assert!(store.load_current().unwrap().is_some());
    }

    #[test]
    fn recovery_rejects_changed_pending_and_preserves_hardlinked_publication() {
        let root = TestRoot::new();
        let layout = layout(&root);
        let store = TransactionStore::new(&layout, binding());
        let mut transaction = store.create("approved-start").unwrap();
        transaction
            .push(SessionTransactionState::Unknown, "start-outcome-unknown")
            .unwrap();
        let directory = layout.run_dir().join("wsb-session-transaction");
        let pending = directory.join("00000000000000000002.json.pending");
        let target = directory.join("00000000000000000002.json");
        fs::write(&pending, serde_json::to_vec_pretty(&transaction).unwrap()).unwrap();
        fs::hard_link(&pending, &target).unwrap();

        let inspection = store.inspect_for_recovery().unwrap();
        assert_eq!(inspection.transaction.as_ref(), Some(&transaction));
        assert!(inspection.pending_present());
        assert!(pending.exists() && target.exists());

        fs::remove_file(&pending).unwrap();
        fs::write(&pending, b"changed-after-inspection").unwrap();
        assert!(matches!(
            store.verify_inspection(&inspection),
            Err(RunnerError::RecoveryRequired(_))
        ));
        assert!(matches!(
            store.discard_pending_after_authority(&inspection),
            Err(RunnerError::RecoveryRequired(_))
        ));
        assert!(pending.exists() && target.exists());

        fs::remove_file(&pending).unwrap();
        fs::hard_link(&target, &pending).unwrap();
        let current = store.inspect_for_recovery().unwrap();
        store.discard_pending_after_authority(&current).unwrap();
        assert!(!pending.exists());
        assert!(target.exists());
        assert_eq!(store.load_current().unwrap(), Some(transaction));
    }
}
