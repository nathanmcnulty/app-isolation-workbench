#![forbid(unsafe_code)]

//! The measured guest side of W1.  This binary intentionally has one job:
//! collect its own token evidence and produce a bound completion receipt.  It
//! never interprets a command, URL, script, policy fragment, or glob from its
//! request.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use aiw_evidence::{ArtifactRole, EvidenceEvent, EvidenceLog, canonical_json_bytes};
use aiw_provider_wsb::{
    CompletionArtifact, CompletionStatus, IMPORTED_MSI_GUEST_REQUEST_SCHEMA_VERSION,
    ImportedMsiGuestRequest, ImportedMsiScenarioResult,
    WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION, WindowsSandboxCompletionReceipt,
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

enum GuestRequest {
    Golden(Box<GoldenProbeRequest>),
    ImportedMsi(Box<ImportedMsiGuestRequest>),
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
    match request {
        GuestRequest::Golden(request) => {
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
        GuestRequest::ImportedMsi(request) => {
            request
                .validate()
                .map_err(|error| anyhow::anyhow!("imported MSI request is invalid: {error}"))?;
            match execute_imported_msi_request(&request) {
                Ok(()) => Ok(()),
                Err(error) => {
                    if !error.is::<PublishedMsiFailure>() {
                        let _ = write_imported_msi_failure_diagnostic(&request, &error);
                    }
                    Err(error)
                }
            }
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

#[cfg(windows)]
fn execute_imported_msi_request(request: &ImportedMsiGuestRequest) -> Result<()> {
    let actual_agent_hash = hash_file(&std::env::current_exe().context("resolve agent identity")?)?;
    if actual_agent_hash != request.agent_sha256 {
        bail!("guest agent identity does not match the approved request")
    }

    // Hold the exact mapped installer handle before starting execution.  On
    // Windows the handle permits other readers (msiexec) but not replacement,
    // deletion, or writes while the scenario is in progress.
    let mut installer = HeldInstaller::open(
        Path::new(&request.installer_path),
        &request.installer_sha256,
        request.installer_size_bytes,
    )?;
    let root = PathBuf::from(&request.output_root);
    ensure_output_root(&root)?;
    installer.revalidate()?;

    let attempt =
        aiw_windows_platform::execute_fixed_notepad_plus_plus_msi_attempt(&request.scenario);
    installer.revalidate()?;
    let progress = if request.scenario.requires_application_exercise() {
        Some(
            aiw_provider_wsb::ImportedMsiStageProgress::new(
                request,
                stage_results(&attempt.stages),
            )
            .map_err(anyhow::Error::msg)?,
        )
    } else {
        None
    };
    let observation = match attempt.result {
        Ok(observation) => observation,
        Err(error) => {
            if let Some(progress) = progress {
                let diagnostic: String = error
                    .to_string()
                    .chars()
                    .take(2048)
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .collect();
                let failed =
                    aiw_provider_wsb::ImportedMsiFailedAttempt::from_progress(progress, diagnostic)
                        .map_err(anyhow::Error::msg)?;
                failed
                    .validate_for_request(request)
                    .map_err(anyhow::Error::msg)?;
                let mut evidence = EvidenceLog::new();
                append_stage_progress(&mut evidence, &failed.progress)?;
                if let Some(snapshots) = attempt.failed_snapshots {
                    let snapshots = aiw_provider_wsb::ImportedMsiFailedSnapshots {
                        schema_version:
                            aiw_provider_wsb::IMPORTED_MSI_FAILED_SNAPSHOTS_SCHEMA_VERSION
                                .to_owned(),
                        run_id: request.run_id.clone(),
                        sandbox_id: request.sandbox_id.clone(),
                        request_sha256: request.request_sha256.clone(),
                        scenario_sha256: request.scenario_sha256.clone(),
                        capture_context: snapshots.capture_context,
                        before_install: snapshots.before_install,
                        after_install: snapshots.after_install,
                        after_exercise: snapshots.after_exercise,
                    };
                    snapshots
                        .validate_for(request, &failed)
                        .map_err(anyhow::Error::msg)?;
                    evidence.append(EvidenceEvent {
                        observed_utc: "guest-agent-time-not-trusted".to_owned(),
                        kind: aiw_provider_wsb::IMPORTED_MSI_FAILED_SNAPSHOTS_EVENT.to_owned(),
                        source: "aiw-guest-agent".to_owned(),
                        payload: serde_json::to_value(&snapshots)?,
                    })?;
                }

                publish_msi_result(request, &failed, evidence, CompletionStatus::Failed)?;
                return Err(PublishedMsiFailure(error.to_string()).into());
            }
            bail!("fixed imported-MSI execution failed: {error}");
        }
    };
    let result = ImportedMsiScenarioResult::succeeded(
        request,
        observation.install_exit_code,
        observation.launch_process_id,
        observation.launch_exit_code,
    )?;
    result.validate_for_request(request).map_err(|error| {
        anyhow::anyhow!("guest produced an invalid imported-MSI result: {error}")
    })?;
    let mut evidence = EvidenceLog::new();
    evidence.append(EvidenceEvent {
        observed_utc: "guest-agent-time-not-trusted".to_owned(),
        kind: "importedMsiScenario".to_owned(),
        source: "aiw-guest-agent".to_owned(),
        payload: serde_json::to_value(&result)?,
    })?;
    let token = aiw_provider_wsb::ImportedMsiApplicationToken::new(
        request,
        &result,
        observation.application_token,
    )
    .map_err(anyhow::Error::msg)?;
    evidence.append(EvidenceEvent {
        observed_utc: "guest-agent-time-not-trusted".to_owned(),
        kind: aiw_provider_wsb::MSI_APPLICATION_TOKEN_EVENT.to_owned(),
        source: "aiw-guest-agent".to_owned(),
        payload: serde_json::to_value(&token)?,
    })?;
    let runtime = if let Some(context) = observation.standard_user_context {
        let runtime =
            aiw_provider_wsb::ImportedMsiRuntimeContext::new(request, &result, &token, context)
                .map_err(anyhow::Error::msg)?;
        evidence.append(EvidenceEvent {
            observed_utc: "guest-agent-time-not-trusted".to_owned(),
            kind: aiw_provider_wsb::IMPORTED_MSI_RUNTIME_CONTEXT_EVENT.to_owned(),
            source: "aiw-guest-agent".to_owned(),
            payload: serde_json::to_value(&runtime)?,
        })?;
        Some(runtime)
    } else if request.scenario.requires_standard_user() {
        bail!("guest did not produce the approved standard-user runtime context");
    } else {
        None
    };
    if let Some(registry) = observation.registry_observations {
        let runtime = runtime
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("registry capture requires runtime context"))?;
        let registry = aiw_provider_wsb::ImportedMsiRegistryEvidence {
            schema_version: aiw_provider_wsb::IMPORTED_MSI_REGISTRY_SCHEMA_VERSION.to_owned(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            user_sid: runtime.context.user_sid.clone(),
            before_install: registry.before_install,
            after_install: registry.after_install,
            after_exercise: registry.after_exercise,
        };
        registry
            .validate_for(request, &result, runtime)
            .map_err(anyhow::Error::msg)?;
        evidence.append(EvidenceEvent {
            observed_utc: "guest-agent-time-not-trusted".to_owned(),
            kind: aiw_provider_wsb::IMPORTED_MSI_REGISTRY_EVENT.to_owned(),
            source: "aiw-guest-agent".to_owned(),
            payload: serde_json::to_value(&registry)?,
        })?;
    } else if request.scenario.requires_registry_observations() {
        bail!("guest did not produce the approved registry observations");
    }
    match (
        observation.functional_exercise,
        observation.filesystem_observations,
    ) {
        (Some(functional_exercise), Some(files)) => {
            let behavior = aiw_provider_wsb::ImportedMsiBehaviorEvidence {
                schema_version: aiw_provider_wsb::IMPORTED_MSI_BEHAVIOR_SCHEMA.to_owned(),
                run_id: request.run_id.clone(),
                sandbox_id: request.sandbox_id.clone(),
                request_sha256: request.request_sha256.clone(),
                scenario_sha256: request.scenario_sha256.clone(),
                functional_exercise,
                before_install: files.before_install,
                after_install: files.after_install,
                after_exercise: files.after_exercise,
            };
            behavior
                .validate_for(request, &result)
                .map_err(anyhow::Error::msg)?;
            evidence.append(EvidenceEvent {
                observed_utc: "guest-agent-time-not-trusted".to_owned(),
                kind: aiw_provider_wsb::IMPORTED_MSI_BEHAVIOR_EVENT.to_owned(),
                source: "aiw-guest-agent".to_owned(),
                payload: serde_json::to_value(&behavior)?,
            })?;
        }
        (None, None) if !request.scenario.requires_application_exercise() => {}
        _ => bail!("guest did not produce all approved application observations"),
    }
    if let Some(progress) = &progress {
        if !progress.successful() {
            bail!("successful MSI result has incomplete stage progress");
        }
        append_stage_progress(&mut evidence, progress)?;
    }
    publish_msi_result(request, &result, evidence, CompletionStatus::Succeeded)
}

#[cfg(not(windows))]
fn execute_imported_msi_request(_request: &ImportedMsiGuestRequest) -> Result<()> {
    bail!("the imported-MSI guest profile only executes inside Windows Sandbox")
}

fn append_stage_progress(
    evidence: &mut EvidenceLog,
    progress: &aiw_provider_wsb::ImportedMsiStageProgress,
) -> Result<()> {
    evidence.append(EvidenceEvent {
        observed_utc: "guest-agent-time-not-trusted".to_owned(),
        kind: aiw_provider_wsb::IMPORTED_MSI_STAGE_PROGRESS_EVENT.to_owned(),
        source: "aiw-guest-agent".to_owned(),
        payload: serde_json::to_value(progress)?,
    })?;
    Ok(())
}

fn publish_msi_result(
    request: &ImportedMsiGuestRequest,
    result: &impl Serialize,
    evidence: EvidenceLog,
    status: CompletionStatus,
) -> Result<()> {
    let root = PathBuf::from(&request.output_root);
    let result_path = output_path(&root, &request.scenario_result_path)?;
    let evidence_path = output_path(&root, &request.evidence_log_path)?;
    let receipt_path = output_path(&root, &request.receipt_path)?;
    write_new_json(&result_path, result)?;
    let mut bytes = Vec::new();
    for record in evidence.records() {
        serde_json::to_writer(&mut bytes, record)?;
        bytes.push(b'\n');
    }
    if bytes.len() > aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES {
        bail!("guest application evidence exceeded its bound");
    }
    write_new_bytes(&evidence_path, &bytes)?;

    let receipt = WindowsSandboxCompletionReceipt {
        schema_version: WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION.to_owned(),
        run_id: request.run_id.clone(),
        sandbox_id: request.sandbox_id.clone(),
        config_sha256: request.config_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        agent_sha256: request.agent_sha256.clone(),
        status,
        exit_code: if status == CompletionStatus::Succeeded {
            0
        } else {
            1
        },
        evidence_root_hash: evidence.manifest()?.root_hash,
        artifacts: vec![
            completion_artifact(
                &result_path,
                &request.scenario_result_path,
                ArtifactRole::ScenarioResults,
                "application/json",
            )?,
            completion_artifact(
                &evidence_path,
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

fn write_imported_msi_failure_diagnostic(
    request: &ImportedMsiGuestRequest,
    error: &anyhow::Error,
) -> Result<()> {
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

struct HeldInstaller {
    path: PathBuf,
    file: File,
    sha256: String,
    size_bytes: u64,
}

impl HeldInstaller {
    fn open(path: &Path, sha256: &str, size_bytes: u64) -> Result<Self> {
        let metadata = ordinary_installer_metadata(path)?;
        if metadata.len() != size_bytes {
            bail!("held installer size does not match the approved request")
        }
        let file = open_installer_read_held(path)?;
        let mut value = Self {
            path: path.to_owned(),
            file,
            sha256: sha256.to_owned(),
            size_bytes,
        };
        value.revalidate()?;
        Ok(value)
    }

    fn revalidate(&mut self) -> Result<()> {
        let metadata = ordinary_installer_metadata(&self.path)?;
        let held_metadata = self.file.metadata()?;
        if metadata.len() != self.size_bytes || held_metadata.len() != self.size_bytes {
            bail!("held installer size changed from the approved request")
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = self.file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        if hex::encode(digest.finalize()) != self.sha256 {
            bail!("held installer hash does not match the approved request")
        }
        Ok(())
    }
}

fn ordinary_installer_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).context("inspect staged MSI")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
        bail!("staged MSI is not an ordinary file")
    }
    Ok(metadata)
}

#[cfg(windows)]
fn open_installer_read_held(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
        .context("open staged MSI with a held read handle")
}

#[cfg(not(windows))]
fn open_installer_read_held(path: &Path) -> Result<File> {
    File::open(path).context("open staged MSI")
}

fn read_request(path: &Path) -> Result<GuestRequest> {
    let file = File::open(path).context("open guest request")?;
    let mut bytes = Vec::new();
    file.take(MAX_REQUEST_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        bail!("guest request exceeds its fixed size bound")
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse strict guest request")?;
    match value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
    {
        Some(REQUEST_SCHEMA) => serde_json::from_value(value)
            .map(Box::new)
            .map(GuestRequest::Golden)
            .context("parse strict golden-probe request"),
        Some(IMPORTED_MSI_GUEST_REQUEST_SCHEMA_VERSION) => serde_json::from_value(value)
            .map(Box::new)
            .map(GuestRequest::ImportedMsi)
            .context("parse strict imported-MSI request"),
        _ => bail!("unsupported guest request schema"),
    }
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
    use aiw_provider_wsb::CompiledMsiScenario;

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

    #[test]
    fn imported_msi_request_dispatches_without_execution() {
        let root = test_root("imported-request");
        let request_path = root.join("request.json");
        let request = ImportedMsiGuestRequest::new(
            "run-1",
            "11111111-1111-1111-1111-111111111111",
            "b".repeat(64),
            "c".repeat(64),
            CompiledMsiScenario {
                schema_version: "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha1".to_owned(),
                profile: "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha1".to_owned(),
                scenario_id: "first-run".to_owned(),
                application_sha256: "a".repeat(64),
                installer_path: r"C:\AIW\Tools\application.msi".to_owned(),
                install_arguments: vec![
                    "/i".to_owned(),
                    r"C:\AIW\Tools\application.msi".to_owned(),
                    "/qn".to_owned(),
                    "/norestart".to_owned(),
                ],
                install_timeout_seconds: 120,
                launch_path: r"C:\Program Files\Notepad++\notepad++.exe".to_owned(),
                launch_arguments: Vec::new(),
                process_image: "notepad++.exe".to_owned(),
                process_wait_timeout_seconds: 30,
                graceful_close_timeout_seconds: 15,
                expected_exit_code: 0,
                document_exercise: None,
            },
            "a".repeat(64),
            1024,
            "d".repeat(64),
        )
        .unwrap();
        fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();

        assert!(matches!(
            read_request(&request_path).unwrap(),
            GuestRequest::ImportedMsi(request) if request.validate().is_ok()
        ));
        fs::remove_dir_all(root).unwrap();
    }
}

#[derive(Debug)]
struct PublishedMsiFailure(String);
impl std::fmt::Display for PublishedMsiFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "failed MSI attempt published: {}", self.0)
    }
}
impl std::error::Error for PublishedMsiFailure {}

#[cfg(windows)]
fn stage_results(
    stages: &[(
        aiw_windows_platform::GuestMsiStage,
        aiw_windows_platform::GuestMsiStageStatus,
    )],
) -> Vec<aiw_provider_wsb::MsiStageResult> {
    use aiw_provider_wsb::{MsiExecutionStage, MsiStageResult, MsiStageStatus};
    use aiw_windows_platform::{GuestMsiStage, GuestMsiStageStatus};
    stages
        .iter()
        .map(|(stage, status)| MsiStageResult {
            stage: match stage {
                GuestMsiStage::BeforeInstallCapture => MsiExecutionStage::BeforeInstallCapture,
                GuestMsiStage::Install => MsiExecutionStage::Install,
                GuestMsiStage::AfterInstallCapture => MsiExecutionStage::AfterInstallCapture,
                GuestMsiStage::PrepareDocument => MsiExecutionStage::PrepareDocument,
                GuestMsiStage::Launch => MsiExecutionStage::Launch,
                GuestMsiStage::OpenDocument => MsiExecutionStage::OpenDocument,
                GuestMsiStage::EditSaveDocument => MsiExecutionStage::EditSaveDocument,
                GuestMsiStage::Close => MsiExecutionStage::Close,
                GuestMsiStage::AfterExerciseCapture => MsiExecutionStage::AfterExerciseCapture,
            },
            status: match status {
                GuestMsiStageStatus::Passed => MsiStageStatus::Passed,
                GuestMsiStageStatus::Failed => MsiStageStatus::Failed,
                GuestMsiStageStatus::NotReached => MsiStageStatus::NotReached,
            },
        })
        .collect()
}
