use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use aiw_evidence::canonical_json_bytes;
use aiw_orchestrator::RunLayout;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::{RunnerError, valid_uuid};

pub const SESSION_TRANSACTION_SCHEMA_VERSION: &str = "aiw.dev/wsb-session-transaction/v0alpha2";
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionTransition {
    pub sequence: u32,
    pub state: SessionTransactionState,
    pub reason_code: String,
    pub previous_hash: String,
    pub hash: String,
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
    transitions: Vec<SessionTransition>,
}

impl<'de> Deserialize<'de> for SessionTransaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SessionTransactionWire::deserialize(deserializer)?;
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
    let (transaction, pending_present) = read_history(&directory)?;
    Ok(TransactionObservation {
        directory_present: true,
        pending_present,
        transaction,
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
}

impl SessionBinding {
    fn transaction(&self, reason_code: &str) -> Result<SessionTransaction, RunnerError> {
        let mut transaction = SessionTransaction {
            schema_version: SESSION_TRANSACTION_SCHEMA_VERSION.to_owned(),
            run_id: self.run_id.clone(),
            plan_hash: self.plan_hash.clone(),
            project_revision_hash: self.project_revision_hash.clone(),
            provider_sha256: self.provider_sha256.clone(),
            config_sha256: self.config_sha256.clone(),
            session_id: self.session_id.clone(),
            request_sha256: self.request_sha256.clone(),
            workspace_identity_sha256: self.workspace_identity_sha256.clone(),
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
    }
}

impl SessionTransaction {
    fn push(
        &mut self,
        state: SessionTransactionState,
        reason_code: &str,
    ) -> Result<(), RunnerError> {
        validate_reason(reason_code)?;
        let sequence = u32::try_from(self.transitions.len() + 1)
            .map_err(|_| RunnerError::Transaction("transition sequence overflow".to_owned()))?;
        let previous_hash = self
            .transitions
            .last()
            .map_or(ZERO_HASH, |transition| transition.hash.as_str())
            .to_owned();
        let hash = transition_hash(self, sequence, state, reason_code, &previous_hash)?;
        self.transitions.push(SessionTransition {
            sequence,
            state,
            reason_code: reason_code.to_owned(),
            previous_hash,
            hash,
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

    pub(crate) fn load_for_recovery(&self) -> Result<Option<SessionTransaction>, RunnerError> {
        self.clean_pending()?;
        self.load()
    }

    pub(crate) fn load_current(&self) -> Result<Option<SessionTransaction>, RunnerError> {
        self.load()
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
        let (transaction, pending_present) = read_history(&directory)?;
        if pending_present {
            return Err(RunnerError::RecoveryRequired(
                "session transaction staging requires recovery".to_owned(),
            ));
        }
        if transaction
            .as_ref()
            .is_some_and(|transaction| !self.binding.matches(transaction))
        {
            return Err(RunnerError::Transaction(
                "session transaction belongs to different approved inputs".to_owned(),
            ));
        }
        Ok(transaction)
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

    fn clean_pending(&self) -> Result<(), RunnerError> {
        let directory = self.directory();
        if !directory.exists() {
            return Ok(());
        }
        ensure_ordinary_directory(&directory)?;
        for entry in fs::read_dir(&directory).map_err(transaction_io)? {
            let path = entry.map_err(transaction_io)?.path();
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    RunnerError::Transaction("non-Unicode transaction path".to_owned())
                })?;
            if name.ends_with(".pending") {
                parse_pending_name(name)?;
                ensure_ordinary_file(&path)?;
                let metadata = fs::metadata(&path).map_err(transaction_io)?;
                if metadata.len() > MAX_TRANSACTION_BYTES {
                    return Err(RunnerError::Transaction(
                        "transaction staging exceeds its fixed bound".to_owned(),
                    ));
                }
                fs::remove_file(path).map_err(transaction_io)?;
            }
        }
        Ok(())
    }
}

fn read_history(directory: &Path) -> Result<(Option<SessionTransaction>, bool), RunnerError> {
    ensure_ordinary_directory(directory)?;
    let mut snapshots = Vec::new();
    let mut pending_present = false;
    for entry in fs::read_dir(directory).map_err(transaction_io)? {
        let path = entry.map_err(transaction_io)?.path();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| RunnerError::Transaction("non-Unicode transaction path".to_owned()))?;
        if name.ends_with(".pending") {
            parse_pending_name(name)?;
            ensure_ordinary_file(&path)?;
            if fs::metadata(&path).map_err(transaction_io)?.len() > MAX_TRANSACTION_BYTES {
                return Err(RunnerError::Transaction(
                    "transaction staging exceeds its fixed bound".to_owned(),
                ));
            }
            pending_present = true;
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
    Ok((previous, pending_present))
}

fn validate_transaction(transaction: &SessionTransaction) -> Result<(), RunnerError> {
    if transaction.schema_version != SESSION_TRANSACTION_SCHEMA_VERSION
        || !valid_run_id(&transaction.run_id)
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
    for (index, transition) in transaction.transitions.iter().enumerate() {
        if usize::try_from(transition.sequence).ok() != Some(index + 1)
            || transition.previous_hash != previous_hash
        {
            return Err(RunnerError::Transaction(
                "session transition sequence or chain is invalid".to_owned(),
            ));
        }
        validate_reason(&transition.reason_code)?;
        if !valid_transition(previous_state, transition.state) {
            return Err(RunnerError::Transaction(
                "session transition grammar is invalid".to_owned(),
            ));
        }
        let expected = transition_hash(
            transaction,
            transition.sequence,
            transition.state,
            &transition.reason_code,
            &transition.previous_hash,
        )?;
        if transition.hash != expected {
            return Err(RunnerError::Transaction(
                "session transition hash is invalid".to_owned(),
            ));
        }
        previous_state = Some(transition.state);
        previous_hash.clone_from(&transition.hash);
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
struct TransitionHashInput<'a> {
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

fn transition_hash(
    transaction: &SessionTransaction,
    sequence: u32,
    state: SessionTransactionState,
    reason_code: &str,
    previous_hash: &str,
) -> Result<String, RunnerError> {
    let value = serde_json::to_value(TransitionHashInput {
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
    })
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

    #[test]
    fn transition_grammar_is_monotonic_and_strict() {
        let binding = SessionBinding {
            run_id: "run-one".to_owned(),
            plan_hash: "1".repeat(64),
            project_revision_hash: "2".repeat(64),
            provider_sha256: "3".repeat(64),
            config_sha256: "4".repeat(64),
            session_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            request_sha256: "5".repeat(64),
            workspace_identity_sha256: "6".repeat(64),
        };
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
        let binding = SessionBinding {
            run_id: "run-one".to_owned(),
            plan_hash: "1".repeat(64),
            project_revision_hash: "2".repeat(64),
            provider_sha256: "3".repeat(64),
            config_sha256: "4".repeat(64),
            session_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            request_sha256: "5".repeat(64),
            workspace_identity_sha256: "6".repeat(64),
        };
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
        )
        .unwrap();
        assert!(
            serde_json::from_value::<SessionTransaction>(
                serde_json::to_value(invalid_grammar).unwrap()
            )
            .is_err()
        );
    }
}
