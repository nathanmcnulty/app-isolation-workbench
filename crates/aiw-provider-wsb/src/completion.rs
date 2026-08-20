use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use aiw_evidence::{
    ArtifactRole, AssessmentBundleError, AssessmentBundleSpec, BundleArtifactSpec, BundlePurpose,
    CanonicalJsonError, ContentDeclaration, DataSensitivity, EvidenceError, EvidenceRecord,
    build_assessment_bundle, canonical_json_bytes, verify_records,
};
use aiw_schema::is_safe_relative_path;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::is_canonical_uuid;

pub const WINDOWS_SANDBOX_COMPLETION_EXPECTATION_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-completion-expectation/v0alpha1";
pub const WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-completion-receipt/v0alpha1";
pub const WINDOWS_SANDBOX_COMPLETION_VERIFICATION_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-completion-verification/v0alpha1";
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 256;
const MAX_OUTPUT_ENTRIES: usize = 512;
const MAX_OUTPUT_DEPTH: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionArtifactExpectation {
    pub path: String,
    pub role: ArtifactRole,
    pub sensitivity: DataSensitivity,
    pub media_type: String,
    pub maximum_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxCompletionExpectation {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub config_sha256: String,
    pub request_sha256: String,
    pub agent_sha256: String,
    pub receipt_path: String,
    pub evidence_log_path: String,
    pub content_declaration: ContentDeclaration,
    pub artifacts: Vec<CompletionArtifactExpectation>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CompletionStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionArtifact {
    pub path: String,
    pub role: ArtifactRole,
    pub media_type: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxCompletionReceipt {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub config_sha256: String,
    pub request_sha256: String,
    pub agent_sha256: String,
    pub status: CompletionStatus,
    pub exit_code: i32,
    pub evidence_root_hash: String,
    pub artifacts: Vec<CompletionArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxCompletionVerification {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub config_sha256: String,
    pub receipt_sha256: String,
    pub evidence_root_hash: String,
    pub artifact_count: u64,
    pub total_bytes: u64,
    pub status: CompletionStatus,
    pub exit_code: i32,
    pub run_binding_verified: bool,
    pub artifact_hashes_verified: bool,
    pub evidence_chain_verified: bool,
    pub receipt_verified: bool,
    pub successful: bool,
}

#[derive(Debug, Error)]
pub enum WindowsSandboxCompletionError {
    #[error("unsupported completion expectation schema version '{0}'")]
    UnsupportedExpectationSchema(String),
    #[error("unsupported completion receipt schema version '{0}'")]
    UnsupportedReceiptSchema(String),
    #[error("completion field '{0}' contains an invalid ID")]
    InvalidId(&'static str),
    #[error("completion field '{0}' must contain a lowercase SHA-256 value")]
    InvalidSha256(&'static str),
    #[error("sandboxId must be a lowercase canonical UUID without braces")]
    InvalidSandboxId,
    #[error("completion path is not portable and safe: {0}")]
    UnsafePath(String),
    #[error("completion output paths must be unique under Windows case rules: {0}")]
    DuplicatePath(String),
    #[error("completion expectation must contain exactly one declared evidence log")]
    InvalidEvidenceLogPolicy,
    #[error("completion expectation must contain 1-{MAX_ARTIFACTS} artifacts")]
    InvalidArtifactCount,
    #[error("artifact maximumBytes must be between 1 and 268435456: {0}")]
    InvalidArtifactLimit(String),
    #[error("receipt field '{0}' does not match the trusted expectation")]
    BindingMismatch(&'static str),
    #[error("receipt terminal status and exitCode are inconsistent")]
    InconsistentTerminalStatus,
    #[error("completion output root is not an ordinary directory: {0}")]
    InvalidOutputRoot(PathBuf),
    #[error("completion output contains a symbolic link or reparse point: {0}")]
    OutputLink(String),
    #[error("completion output contains an unexpected entry: {0}")]
    UnexpectedOutputEntry(String),
    #[error("completion output contains more than {MAX_OUTPUT_ENTRIES} entries")]
    TooManyOutputEntries,
    #[error("completion output exceeds the maximum directory depth of {MAX_OUTPUT_DEPTH}")]
    OutputTooDeep,
    #[error("could not inspect completion output {path}: {source}")]
    OutputIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("completion receipt is larger than {MAX_RECEIPT_BYTES} bytes")]
    ReceiptTooLarge,
    #[error("completion evidence log is larger than its approved bound")]
    EvidenceLogTooLarge,
    #[error("completion receipt is invalid JSON: {0}")]
    ReceiptJson(String),
    #[error("completion evidence log line {line} is invalid JSON: {message}")]
    EvidenceJson { line: usize, message: String },
    #[error("completion evidence log must contain at least one record")]
    EmptyEvidenceLog,
    #[error("completion receipt artifacts do not exactly match measured output")]
    ArtifactMismatch,
    #[error("completion evidence root does not match the verified evidence log")]
    EvidenceRootMismatch,
    #[error("completion output changed while it was being verified")]
    OutputChangedDuringVerification,
    #[error(transparent)]
    Bundle(#[from] AssessmentBundleError),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error(transparent)]
    CanonicalJson(#[from] CanonicalJsonError),
}

pub fn verify_completion_receipt(
    output_root: impl AsRef<Path>,
    expectation: &WindowsSandboxCompletionExpectation,
) -> Result<WindowsSandboxCompletionVerification, WindowsSandboxCompletionError> {
    validate_expectation(expectation)?;
    let output_root = output_root.as_ref();
    let mut allowed_paths: BTreeSet<String> = expectation
        .artifacts
        .iter()
        .map(|artifact| normalize_path(&artifact.path))
        .collect();
    allowed_paths.insert(normalize_path(&expectation.receipt_path));
    validate_output_tree(output_root, &allowed_paths)?;

    let receipt_bytes = read_bounded_file(
        output_root,
        &expectation.receipt_path,
        MAX_RECEIPT_BYTES,
        WindowsSandboxCompletionError::ReceiptTooLarge,
    )?;
    let receipt: WindowsSandboxCompletionReceipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|error| WindowsSandboxCompletionError::ReceiptJson(error.to_string()))?;
    validate_receipt(expectation, &receipt)?;

    let bundle_spec = AssessmentBundleSpec {
        schema_version: aiw_evidence::ASSESSMENT_BUNDLE_SPEC_SCHEMA_VERSION.to_owned(),
        bundle_id: expectation.run_id.clone(),
        purpose: BundlePurpose::InternalValidation,
        content_declaration: expectation.content_declaration,
        artifacts: expectation
            .artifacts
            .iter()
            .map(|artifact| BundleArtifactSpec {
                path: artifact.path.clone(),
                role: artifact.role,
                sensitivity: artifact.sensitivity,
                media_type: artifact.media_type.clone(),
            })
            .collect(),
    };
    let first_manifest = build_assessment_bundle(output_root, &bundle_spec)?;
    verify_reported_artifacts(expectation, &receipt, &first_manifest.artifacts)?;

    let evidence_limit = expectation
        .artifacts
        .iter()
        .find(|artifact| artifact.path == expectation.evidence_log_path)
        .expect("validate_expectation requires the declared evidence log")
        .maximum_bytes
        .min(MAX_EVIDENCE_LOG_BYTES);
    let evidence_bytes = read_bounded_file(
        output_root,
        &expectation.evidence_log_path,
        evidence_limit,
        WindowsSandboxCompletionError::EvidenceLogTooLarge,
    )?;
    let evidence_records = parse_evidence_records(&evidence_bytes)?;
    if evidence_records.is_empty() {
        return Err(WindowsSandboxCompletionError::EmptyEvidenceLog);
    }
    let evidence_manifest = verify_records(&evidence_records)?;
    if receipt.evidence_root_hash != evidence_manifest.root_hash {
        return Err(WindowsSandboxCompletionError::EvidenceRootMismatch);
    }

    let second_manifest = build_assessment_bundle(output_root, &bundle_spec)?;
    if first_manifest != second_manifest {
        return Err(WindowsSandboxCompletionError::OutputChangedDuringVerification);
    }
    validate_output_tree(output_root, &allowed_paths)?;
    let final_receipt_bytes = read_bounded_file(
        output_root,
        &expectation.receipt_path,
        MAX_RECEIPT_BYTES,
        WindowsSandboxCompletionError::ReceiptTooLarge,
    )?;
    if receipt_bytes != final_receipt_bytes {
        return Err(WindowsSandboxCompletionError::OutputChangedDuringVerification);
    }

    let receipt_value = serde_json::to_value(&receipt)
        .map_err(|error| WindowsSandboxCompletionError::ReceiptJson(error.to_string()))?;
    let receipt_sha256 = hex::encode(Sha256::digest(canonical_json_bytes(&receipt_value)?));
    Ok(WindowsSandboxCompletionVerification {
        schema_version: WINDOWS_SANDBOX_COMPLETION_VERIFICATION_SCHEMA_VERSION.to_owned(),
        run_id: receipt.run_id,
        sandbox_id: receipt.sandbox_id,
        config_sha256: receipt.config_sha256,
        receipt_sha256,
        evidence_root_hash: receipt.evidence_root_hash,
        artifact_count: first_manifest.artifact_count,
        total_bytes: first_manifest.total_bytes,
        status: receipt.status,
        exit_code: receipt.exit_code,
        run_binding_verified: true,
        artifact_hashes_verified: true,
        evidence_chain_verified: true,
        receipt_verified: true,
        successful: receipt.status == CompletionStatus::Succeeded,
    })
}

fn validate_expectation(
    expectation: &WindowsSandboxCompletionExpectation,
) -> Result<(), WindowsSandboxCompletionError> {
    if expectation.schema_version != WINDOWS_SANDBOX_COMPLETION_EXPECTATION_SCHEMA_VERSION {
        return Err(WindowsSandboxCompletionError::UnsupportedExpectationSchema(
            expectation.schema_version.clone(),
        ));
    }
    if !is_valid_id(&expectation.run_id) {
        return Err(WindowsSandboxCompletionError::InvalidId("runId"));
    }
    if !is_canonical_uuid(&expectation.sandbox_id)
        || expectation
            .sandbox_id
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
    {
        return Err(WindowsSandboxCompletionError::InvalidSandboxId);
    }
    for (field, value) in [
        ("configSha256", expectation.config_sha256.as_str()),
        ("requestSha256", expectation.request_sha256.as_str()),
        ("agentSha256", expectation.agent_sha256.as_str()),
    ] {
        validate_sha256(field, value)?;
    }
    validate_relative_path(&expectation.receipt_path)?;
    validate_relative_path(&expectation.evidence_log_path)?;
    if !expectation.receipt_path.ends_with(".json")
        || !expectation.evidence_log_path.ends_with(".jsonl")
    {
        return Err(WindowsSandboxCompletionError::InvalidEvidenceLogPolicy);
    }
    if expectation.artifacts.is_empty() || expectation.artifacts.len() > MAX_ARTIFACTS {
        return Err(WindowsSandboxCompletionError::InvalidArtifactCount);
    }

    let mut paths = BTreeSet::new();
    paths.insert(normalize_path(&expectation.receipt_path));
    let mut evidence_logs = 0;
    for artifact in &expectation.artifacts {
        validate_relative_path(&artifact.path)?;
        if !paths.insert(normalize_path(&artifact.path)) {
            return Err(WindowsSandboxCompletionError::DuplicatePath(
                artifact.path.clone(),
            ));
        }
        if artifact.maximum_bytes == 0 || artifact.maximum_bytes > MAX_ARTIFACT_BYTES {
            return Err(WindowsSandboxCompletionError::InvalidArtifactLimit(
                artifact.path.clone(),
            ));
        }
        if artifact.role == ArtifactRole::EvidenceLog {
            evidence_logs += 1;
            if artifact.path != expectation.evidence_log_path
                || artifact.maximum_bytes > MAX_EVIDENCE_LOG_BYTES
            {
                return Err(WindowsSandboxCompletionError::InvalidEvidenceLogPolicy);
            }
        }
    }
    if evidence_logs != 1 {
        return Err(WindowsSandboxCompletionError::InvalidEvidenceLogPolicy);
    }
    Ok(())
}

fn validate_receipt(
    expectation: &WindowsSandboxCompletionExpectation,
    receipt: &WindowsSandboxCompletionReceipt,
) -> Result<(), WindowsSandboxCompletionError> {
    if receipt.schema_version != WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION {
        return Err(WindowsSandboxCompletionError::UnsupportedReceiptSchema(
            receipt.schema_version.clone(),
        ));
    }
    for (field, actual, expected) in [
        (
            "runId",
            receipt.run_id.as_str(),
            expectation.run_id.as_str(),
        ),
        (
            "sandboxId",
            receipt.sandbox_id.as_str(),
            expectation.sandbox_id.as_str(),
        ),
        (
            "configSha256",
            receipt.config_sha256.as_str(),
            expectation.config_sha256.as_str(),
        ),
        (
            "requestSha256",
            receipt.request_sha256.as_str(),
            expectation.request_sha256.as_str(),
        ),
        (
            "agentSha256",
            receipt.agent_sha256.as_str(),
            expectation.agent_sha256.as_str(),
        ),
    ] {
        if actual != expected {
            return Err(WindowsSandboxCompletionError::BindingMismatch(field));
        }
    }
    validate_sha256("evidenceRootHash", &receipt.evidence_root_hash)?;
    if (receipt.status == CompletionStatus::Succeeded && receipt.exit_code != 0)
        || (receipt.status == CompletionStatus::Failed && receipt.exit_code == 0)
    {
        return Err(WindowsSandboxCompletionError::InconsistentTerminalStatus);
    }
    if receipt.artifacts.len() != expectation.artifacts.len() {
        return Err(WindowsSandboxCompletionError::ArtifactMismatch);
    }
    let mut paths = BTreeSet::new();
    for artifact in &receipt.artifacts {
        validate_relative_path(&artifact.path)?;
        validate_sha256("artifacts[].sha256", &artifact.sha256)?;
        if !paths.insert(normalize_path(&artifact.path)) {
            return Err(WindowsSandboxCompletionError::DuplicatePath(
                artifact.path.clone(),
            ));
        }
    }
    Ok(())
}

fn verify_reported_artifacts(
    expectation: &WindowsSandboxCompletionExpectation,
    receipt: &WindowsSandboxCompletionReceipt,
    measured: &[aiw_evidence::BundleArtifact],
) -> Result<(), WindowsSandboxCompletionError> {
    let mut reported = receipt.artifacts.iter().collect::<Vec<_>>();
    reported.sort_by_key(|artifact| normalize_path(&artifact.path));
    if reported.len() != measured.len() {
        return Err(WindowsSandboxCompletionError::ArtifactMismatch);
    }
    for (reported, measured) in reported.into_iter().zip(measured) {
        let policy = expectation
            .artifacts
            .iter()
            .find(|artifact| artifact.path == measured.path)
            .ok_or(WindowsSandboxCompletionError::ArtifactMismatch)?;
        if reported.path != measured.path
            || reported.role != measured.role
            || reported.media_type != measured.media_type
            || reported.size_bytes != measured.size_bytes
            || reported.sha256 != measured.sha256
            || measured.size_bytes > policy.maximum_bytes
        {
            return Err(WindowsSandboxCompletionError::ArtifactMismatch);
        }
    }
    Ok(())
}

fn validate_output_tree(
    root: &Path,
    allowed_paths: &BTreeSet<String>,
) -> Result<(), WindowsSandboxCompletionError> {
    let metadata =
        fs::symlink_metadata(root).map_err(|source| WindowsSandboxCompletionError::OutputIo {
            path: root.to_path_buf(),
            source,
        })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
        return Err(WindowsSandboxCompletionError::InvalidOutputRoot(
            root.to_path_buf(),
        ));
    }
    let mut seen_paths = BTreeSet::new();
    let mut entry_count = 0;
    visit_output_directory(
        root,
        "",
        0,
        allowed_paths,
        &mut seen_paths,
        &mut entry_count,
    )
}

fn visit_output_directory(
    directory: &Path,
    relative_directory: &str,
    depth: usize,
    allowed_paths: &BTreeSet<String>,
    seen_paths: &mut BTreeSet<String>,
    entry_count: &mut usize,
) -> Result<(), WindowsSandboxCompletionError> {
    if depth > MAX_OUTPUT_DEPTH {
        return Err(WindowsSandboxCompletionError::OutputTooDeep);
    }
    let entries =
        fs::read_dir(directory).map_err(|source| WindowsSandboxCompletionError::OutputIo {
            path: directory.to_path_buf(),
            source,
        })?;
    for entry in entries {
        let entry = entry.map_err(|source| WindowsSandboxCompletionError::OutputIo {
            path: directory.to_path_buf(),
            source,
        })?;
        *entry_count += 1;
        if *entry_count > MAX_OUTPUT_ENTRIES {
            return Err(WindowsSandboxCompletionError::TooManyOutputEntries);
        }
        let name = entry.file_name().into_string().map_err(|name| {
            WindowsSandboxCompletionError::UnexpectedOutputEntry(
                name.to_string_lossy().into_owned(),
            )
        })?;
        let relative = if relative_directory.is_empty() {
            name
        } else {
            format!("{relative_directory}/{name}")
        };
        validate_relative_path(&relative)?;
        let normalized = normalize_path(&relative);
        if !seen_paths.insert(normalized.clone()) {
            return Err(WindowsSandboxCompletionError::DuplicatePath(relative));
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| {
            WindowsSandboxCompletionError::OutputIo {
                path: path.clone(),
                source,
            }
        })?;
        if metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
            return Err(WindowsSandboxCompletionError::OutputLink(relative));
        }
        if metadata.is_dir() {
            let mut prefix = normalized;
            prefix.push('/');
            if !allowed_paths
                .iter()
                .any(|allowed| allowed.starts_with(&prefix))
            {
                return Err(WindowsSandboxCompletionError::UnexpectedOutputEntry(
                    relative,
                ));
            }
            visit_output_directory(
                &path,
                &relative,
                depth + 1,
                allowed_paths,
                seen_paths,
                entry_count,
            )?;
        } else if !metadata.is_file() || !allowed_paths.contains(&normalized) {
            return Err(WindowsSandboxCompletionError::UnexpectedOutputEntry(
                relative,
            ));
        }
    }
    Ok(())
}

fn read_bounded_file<E>(
    root: &Path,
    relative_path: &str,
    maximum_bytes: u64,
    too_large: E,
) -> Result<Vec<u8>, WindowsSandboxCompletionError>
where
    E: Into<WindowsSandboxCompletionError>,
{
    let path = relative_path
        .split('/')
        .fold(root.to_path_buf(), |path, segment| path.join(segment));
    let file = File::open(&path).map_err(|source| WindowsSandboxCompletionError::OutputIo {
        path: path.clone(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| WindowsSandboxCompletionError::OutputIo {
            path: path.clone(),
            source,
        })?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(too_large.into());
    }
    Ok(bytes)
}

fn parse_evidence_records(
    bytes: &[u8],
) -> Result<Vec<EvidenceRecord>, WindowsSandboxCompletionError> {
    let mut records = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let record = serde_json::from_slice(line).map_err(|error| {
            WindowsSandboxCompletionError::EvidenceJson {
                line: index + 1,
                message: error.to_string(),
            }
        })?;
        records.push(record);
    }
    Ok(records)
}

fn validate_relative_path(value: &str) -> Result<(), WindowsSandboxCompletionError> {
    if !value.is_ascii() || value.contains('\\') || !is_safe_relative_path(value) {
        return Err(WindowsSandboxCompletionError::UnsafePath(value.to_owned()));
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), WindowsSandboxCompletionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(WindowsSandboxCompletionError::InvalidSha256(field));
    }
    Ok(())
}

fn is_valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn normalize_path(value: &str) -> String {
    value.to_ascii_lowercase()
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use aiw_evidence::{EvidenceEvent, EvidenceLog};

    use super::*;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aiw-wsb-receipt-test-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
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

    fn fixture() -> (
        TestRoot,
        WindowsSandboxCompletionExpectation,
        WindowsSandboxCompletionReceipt,
    ) {
        let root = TestRoot::new();
        let mut log = EvidenceLog::new();
        log.append(EvidenceEvent {
            observed_utc: "2026-08-19T00:00:00Z".to_owned(),
            kind: "token".to_owned(),
            source: "fixture".to_owned(),
            payload: serde_json::json!({"appContainer": true}),
        })
        .unwrap();
        let mut evidence_bytes = Vec::new();
        for record in log.records() {
            serde_json::to_writer(&mut evidence_bytes, record).unwrap();
            evidence_bytes.push(b'\n');
        }
        fs::write(root.0.join("evidence.jsonl"), &evidence_bytes).unwrap();
        let evidence_sha256 = hex::encode(Sha256::digest(&evidence_bytes));
        let expectation = WindowsSandboxCompletionExpectation {
            schema_version: WINDOWS_SANDBOX_COMPLETION_EXPECTATION_SCHEMA_VERSION.to_owned(),
            run_id: "fixture-run".to_owned(),
            sandbox_id: "12345678-1234-abcd-9876-1234567890ab".to_owned(),
            config_sha256: "a".repeat(64),
            request_sha256: "b".repeat(64),
            agent_sha256: "c".repeat(64),
            receipt_path: "completion.json".to_owned(),
            evidence_log_path: "evidence.jsonl".to_owned(),
            content_declaration: ContentDeclaration::NoKnownSecrets,
            artifacts: vec![CompletionArtifactExpectation {
                path: "evidence.jsonl".to_owned(),
                role: ArtifactRole::EvidenceLog,
                sensitivity: DataSensitivity::Internal,
                media_type: "application/x-ndjson".to_owned(),
                maximum_bytes: 1024 * 1024,
            }],
        };
        let receipt = WindowsSandboxCompletionReceipt {
            schema_version: WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION.to_owned(),
            run_id: expectation.run_id.clone(),
            sandbox_id: expectation.sandbox_id.clone(),
            config_sha256: expectation.config_sha256.clone(),
            request_sha256: expectation.request_sha256.clone(),
            agent_sha256: expectation.agent_sha256.clone(),
            status: CompletionStatus::Succeeded,
            exit_code: 0,
            evidence_root_hash: log.manifest().unwrap().root_hash,
            artifacts: vec![CompletionArtifact {
                path: "evidence.jsonl".to_owned(),
                role: ArtifactRole::EvidenceLog,
                media_type: "application/x-ndjson".to_owned(),
                size_bytes: evidence_bytes.len() as u64,
                sha256: evidence_sha256,
            }],
        };
        fs::write(
            root.0.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        (root, expectation, receipt)
    }

    #[test]
    fn verifies_run_binding_artifacts_and_evidence_chain() {
        let (root, expectation, _) = fixture();
        let result = verify_completion_receipt(&root.0, &expectation).unwrap();
        assert!(result.receipt_verified);
        assert!(result.run_binding_verified);
        assert!(result.artifact_hashes_verified);
        assert!(result.evidence_chain_verified);
        assert!(result.successful);
        assert_eq!(result.artifact_count, 1);
        assert_eq!(result.receipt_sha256.len(), 64);
    }

    #[test]
    fn rejects_binding_mismatch_and_invented_artifact_hash() {
        let (root, expectation, mut receipt) = fixture();
        receipt.sandbox_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_owned();
        fs::write(
            root.0.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_completion_receipt(&root.0, &expectation),
            Err(WindowsSandboxCompletionError::BindingMismatch("sandboxId"))
        ));

        receipt.sandbox_id = expectation.sandbox_id.clone();
        receipt.artifacts[0].sha256 = "0".repeat(64);
        fs::write(
            root.0.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_completion_receipt(&root.0, &expectation),
            Err(WindowsSandboxCompletionError::ArtifactMismatch)
        ));
    }

    #[test]
    fn rejects_unexpected_output_and_inconsistent_status() {
        let (root, expectation, mut receipt) = fixture();
        fs::write(root.0.join("unexpected.txt"), b"untrusted").unwrap();
        assert!(matches!(
            verify_completion_receipt(&root.0, &expectation),
            Err(WindowsSandboxCompletionError::UnexpectedOutputEntry(_))
        ));
        fs::remove_file(root.0.join("unexpected.txt")).unwrap();

        receipt.status = CompletionStatus::Failed;
        fs::write(
            root.0.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_completion_receipt(&root.0, &expectation),
            Err(WindowsSandboxCompletionError::InconsistentTerminalStatus)
        ));
    }

    #[test]
    fn verified_failed_receipt_is_not_reported_as_successful() {
        let (root, expectation, mut receipt) = fixture();
        receipt.status = CompletionStatus::Failed;
        receipt.exit_code = 7;
        fs::write(
            root.0.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();

        let result = verify_completion_receipt(&root.0, &expectation).unwrap();
        assert!(result.receipt_verified);
        assert!(!result.successful);
        assert_eq!(result.exit_code, 7);
    }

    #[test]
    fn rejects_tampered_evidence_even_when_receipt_hash_matches_file() {
        let (root, expectation, mut receipt) = fixture();
        let evidence_path = root.0.join("evidence.jsonl");
        let original = fs::read_to_string(&evidence_path).unwrap();
        let tampered = original.replace("\"appContainer\":true", "\"appContainer\":false");
        fs::write(&evidence_path, tampered.as_bytes()).unwrap();
        receipt.artifacts[0].size_bytes = tampered.len() as u64;
        receipt.artifacts[0].sha256 = hex::encode(Sha256::digest(tampered.as_bytes()));
        fs::write(
            root.0.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            verify_completion_receipt(&root.0, &expectation),
            Err(WindowsSandboxCompletionError::Evidence(
                EvidenceError::HashMismatch { .. }
            ))
        ));
    }
}
