#![forbid(unsafe_code)]

//! The measured guest side of W1.  This binary intentionally has one job:
//! collect its own token evidence and produce a bound completion receipt.  It
//! never interprets a command, URL, script, policy fragment, or glob from its
//! request.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use aiw_evidence::{ArtifactRole, EvidenceEvent, EvidenceLog, canonical_json_bytes};
use aiw_provider_wsb::{
    CompletionArtifact, CompletionStatus, WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION,
    WindowsSandboxCompletionReceipt,
};
use aiw_token::collect_current_process_token;
use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REQUEST_SCHEMA: &str = "aiw.dev/wsb-golden-probe-request/v0alpha1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_OUTPUT_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "aiw-guest-agent", about = "Emit only W1 golden token evidence")]
struct Cli {
    /// Read a strict, immutable golden-probe request from the read-only tools mapping.
    #[arg(long)]
    request: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GoldenProbeRequest {
    schema_version: String,
    run_id: String,
    sandbox_id: String,
    config_sha256: String,
    request_sha256: String,
    agent_sha256: String,
    output_root: String,
    token_path: String,
    evidence_log_path: String,
    receipt_path: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("AIW_GUEST_AGENT_FAILED: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let request = read_request(&cli.request)?;
    validate_request(&request)?;
    if request.request_sha256 != request_hash(&request)? {
        bail!("guest request hash does not match its approved binding")
    }
    match execute_request(&request) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = write_failure_diagnostic(&request, &error);
            Err(error)
        }
    }
}

fn execute_request(request: &GoldenProbeRequest) -> Result<()> {
    let actual_agent_hash = hash_file(&std::env::current_exe().context("resolve agent identity")?)?;
    if actual_agent_hash != request.agent_sha256 {
        bail!("guest agent identity does not match the approved request")
    }
    let root = PathBuf::from(&request.output_root);
    ensure_output_root(&root)?;
    let token_path = output_path(&root, &request.token_path)?;
    let log_path = output_path(&root, &request.evidence_log_path)?;
    let receipt_path = output_path(&root, &request.receipt_path)?;
    let token = collect_current_process_token()?;
    write_new_json(&token_path, &token)?;

    let mut evidence = EvidenceLog::new();
    evidence.append(EvidenceEvent {
        observed_utc: "guest-agent-time-not-trusted".to_owned(),
        kind: "goldenTokenProbe".to_owned(),
        source: "aiw-guest-agent".to_owned(),
        payload: serde_json::to_value(&token)?,
    })?;
    let mut bytes = Vec::new();
    for record in evidence.records() {
        serde_json::to_writer(&mut bytes, record)?;
        bytes.push(b'\n');
    }
    write_new_bytes(&log_path, &bytes)?;

    // The receipt is always the last guest mutation.  All artifacts have been
    // closed and remeasured before it is create-new published.
    let receipt = WindowsSandboxCompletionReceipt {
        schema_version: WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION.to_owned(),
        run_id: request.run_id.clone(),
        sandbox_id: request.sandbox_id.clone(),
        config_sha256: request.config_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        agent_sha256: request.agent_sha256.clone(),
        status: CompletionStatus::Succeeded,
        exit_code: 0,
        evidence_root_hash: evidence.manifest()?.root_hash,
        artifacts: vec![
            completion_artifact(
                &token_path,
                &request.token_path,
                ArtifactRole::TokenEvidence,
                "application/json",
            )?,
            completion_artifact(
                &log_path,
                &request.evidence_log_path,
                ArtifactRole::EvidenceLog,
                "application/x-ndjson",
            )?,
        ],
    };
    write_receipt_last(&receipt_path, &receipt)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GuestFailureDiagnostic {
    schema_version: &'static str,
    code: &'static str,
    summary: String,
}

fn write_failure_diagnostic(request: &GoldenProbeRequest, error: &anyhow::Error) -> Result<()> {
    let root = PathBuf::from(&request.output_root);
    let summary: String = format!("{error:#}").chars().take(2048).collect();
    write_new_json(
        &root.join("guest-failure.json"),
        &GuestFailureDiagnostic {
            schema_version: "aiw.dev/wsb-guest-failure/v0alpha1",
            code: "AIW_GUEST_AGENT_FAILED",
            summary,
        },
    )
}

fn read_request(path: &Path) -> Result<GoldenProbeRequest> {
    let file = File::open(path).context("open guest request")?;
    let mut bytes = Vec::new();
    file.take(MAX_REQUEST_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        bail!("guest request exceeds its fixed size bound")
    }
    serde_json::from_slice(&bytes).context("parse strict guest request")
}

fn validate_request(request: &GoldenProbeRequest) -> Result<()> {
    if request.schema_version != REQUEST_SCHEMA {
        bail!("unsupported guest request schema")
    }
    for (name, value) in [
        ("runId", request.run_id.as_str()),
        ("sandboxId", request.sandbox_id.as_str()),
        ("configSha256", request.config_sha256.as_str()),
        ("requestSha256", request.request_sha256.as_str()),
        ("agentSha256", request.agent_sha256.as_str()),
    ] {
        if value.is_empty() || value.len() > 64 || value.contains(['/', '\\', '\r', '\n', '\0']) {
            bail!("invalid {name}")
        }
    }
    for (name, value) in [
        ("configSha256", request.config_sha256.as_str()),
        ("requestSha256", request.request_sha256.as_str()),
        ("agentSha256", request.agent_sha256.as_str()),
    ] {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            bail!("invalid {name}")
        }
    }
    for path in [
        &request.token_path,
        &request.evidence_log_path,
        &request.receipt_path,
    ] {
        if !safe_relative(path) {
            bail!("guest output path is not allowlisted")
        }
    }
    if request.token_path != "token.json"
        || request.evidence_log_path != "evidence.jsonl"
        || request.receipt_path != "completion.json"
    {
        bail!("only the fixed W1 golden-probe artifact names are accepted")
    }
    Ok(())
}

fn request_hash(request: &GoldenProbeRequest) -> Result<String> {
    let mut value = serde_json::to_value(request)?;
    value["requestSha256"] = serde_json::Value::String(String::new());
    Ok(hex::encode(Sha256::digest(canonical_json_bytes(&value)?)))
}

fn safe_relative(value: &str) -> bool {
    let path = Path::new(value);
    path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)))
        && value.is_ascii()
}

fn ensure_output_root(root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(root).context("inspect output root")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
        bail!("output root is not an ordinary directory")
    }
    if fs::read_dir(root)?.next().transpose()?.is_some() {
        bail!("output root is not empty")
    }
    Ok(())
}

fn output_path(root: &Path, relative: &str) -> Result<PathBuf> {
    if !safe_relative(relative) {
        bail!("unsafe output artifact path")
    }
    Ok(root.join(relative))
}

fn write_new_json(value: &Path, serializable: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(serializable)?;
    write_new_bytes(value, &bytes)
}

fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() >= MAX_OUTPUT_ARTIFACT_BYTES {
        bail!("guest output artifact exceeds its fixed size bound")
    }
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("guest output artifact already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect guest output artifact"),
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("guest output artifact has no portable file name")?;
    let staging = path.with_file_name(format!("{name}.pending"));
    clean_staging(&staging)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    match fs::hard_link(&staging, path) {
        Ok(()) => {
            fs::remove_file(staging)?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(staging);
            Err(error.into())
        }
    }
}

fn write_receipt_last(path: &Path, receipt: &WindowsSandboxCompletionReceipt) -> Result<()> {
    write_new_json(path, receipt)
}

fn clean_staging(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect guest output staging"),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || has_reparse_point(&metadata)
        || metadata.len() > MAX_OUTPUT_ARTIFACT_BYTES as u64
    {
        bail!("guest output staging is not a bounded ordinary file")
    }
    fs::remove_file(path).context("remove incomplete guest output staging")
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

fn completion_artifact(
    path: &Path,
    relative: &str,
    role: ArtifactRole,
    media_type: &str,
) -> Result<CompletionArtifact> {
    let bytes = fs::read(path)?;
    Ok(CompletionArtifact {
        path: relative.to_owned(),
        role,
        media_type: media_type.to_owned(),
        size_bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("aiw-guest-agent-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn request_never_allows_commands_or_nested_paths() {
        assert!(!safe_relative("../completion.json"));
        assert!(!safe_relative("nested/token.json"));
        assert!(safe_relative("token.json"));
    }

    #[test]
    fn publication_is_atomic_create_new_and_cleans_staging() {
        let root = test_root("atomic");
        let target = root.join("completion.json");
        let staging = root.join("completion.json.pending");
        fs::write(&staging, b"partial").unwrap();
        write_new_bytes(&target, b"complete").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"complete\n");
        assert!(!staging.exists());
        assert!(write_new_bytes(&target, b"replacement").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"complete\n");
        fs::remove_dir_all(root).unwrap();
    }
}
