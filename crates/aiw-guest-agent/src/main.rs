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
    BambuExecutionStage, BambuScenarioStatus, CompletionArtifact, CompletionStatus,
    IMPORTED_BAMBU_GUEST_REQUEST_SCHEMA_VERSION, IMPORTED_MSI_GUEST_REQUEST_SCHEMA_VERSION,
    ImportedBambuGuestRequest, ImportedBambuScenarioResult, ImportedMsiGuestRequest,
    ImportedMsiScenarioResult, WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION,
    WindowsSandboxCompletionReceipt,
};
use aiw_token::collect_current_process_token;
use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PAIRED_LAUNCHER_OBSERVATION_PATH: &str = r"C:\AIW\Control\paired-launcher.json";
const PAIRED_OUTPUT_ROOT: &str = r"C:\AIW\Output";
const REQUEST_SCHEMA: &str = "aiw.dev/wsb-golden-probe-request/v0alpha1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_OUTPUT_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
mod sevenzip;

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
    ImportedBambu(Box<ImportedBambuGuestRequest>),
    PairedControls(Box<aiw_provider_wsb::PairedControlsRequest>),
    SevenZip(Box<aiw_provider_wsb::sevenzip::SevenZipRequest>),
}

fn main() -> ExitCode {
    if let Some(result) = sevenzip::fixed_role() {
        return result;
    }
    if let Some(result) = fixed_control_role() {
        return result;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("AIW_GUEST_AGENT_FAILED: {error:#}");
            ExitCode::FAILURE
        }
    }
}

// The two staged roles are exact copies of this approved agent. A role is
// selected only by exact fixed arguments, current executable and native account
// identity. No arbitrary mode/path/script can enter the measured guest driver.
fn fixed_control_role() -> Option<ExitCode> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let role = classify_control_role(&args);
    let role = restrict_role_executable(std::env::current_exe().ok().as_deref(), role);
    match role {
        ControlRole::None => None,
        ControlRole::Rejected => Some(ExitCode::FAILURE),
        role => Some(match run_fixed_control_role(role) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("AIW_FIXED_CONTROL_ROLE_FAILED: {error:#}");
                ExitCode::FAILURE
            }
        }),
    }
}
#[derive(Debug, PartialEq, Eq)]
enum ControlRole {
    None,
    Rejected,
    Fixture(String),
    Launcher,
}
fn classify_control_role(args: &[std::ffi::OsString]) -> ControlRole {
    if args == [std::ffi::OsString::from("--paired-control-launcher")] {
        return ControlRole::Launcher;
    }
    if args.len() == 2 && args[0] == "--mode" {
        return match args[1].to_str() {
            Some(mode @ ("read-canary" | "read-registry" | "child" | "child-token")) => {
                ControlRole::Fixture(mode.into())
            }
            _ => ControlRole::Rejected,
        };
    }
    if args
        .iter()
        .any(|s| s == "--mode" || s == "--paired-control-launcher")
    {
        ControlRole::Rejected
    } else {
        ControlRole::None
    }
}
fn restrict_role_executable(path: Option<&Path>, role: ControlRole) -> ControlRole {
    let Some(path) = path.and_then(Path::to_str) else {
        return ControlRole::Rejected;
    };
    // GetModuleFileName may preserve case/verbatim spelling. No filesystem
    // canonicalization is required inside the low-integrity AppContainer.
    // Other spellings, including short paths, fail closed rather than falling
    // through to the normal request dispatcher.
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    let expected = match &role {
        ControlRole::None => r"C:\AIW\Tools\aiw-guest-agent.exe",
        ControlRole::Fixture(_) => r"C:\AIW\Control\aiw-control-fixture.exe",
        ControlRole::Launcher => r"C:\AIW\Control\aiw-control-appcontainer.exe",
        ControlRole::Rejected => return ControlRole::Rejected,
    };
    if path.eq_ignore_ascii_case(expected) {
        role
    } else {
        ControlRole::Rejected
    }
}
#[cfg(windows)]
fn run_fixed_control_role(role: ControlRole) -> Result<ExitCode> {
    match role {
        ControlRole::Fixture(mode) => {
            aiw_windows_platform::validate_fixed_paired_fixture_role(&mode)?;
            Ok(aiw_control_fixture::control_main())
        }
        ControlRole::Launcher => {
            let result = aiw_windows_platform::execute_fixed_paired_control_launcher()?;
            let path = Path::new(PAIRED_LAUNCHER_OBSERVATION_PATH);
            let bytes = serde_json::to_vec(&result)?;
            if bytes.len() > 64 * 1024 {
                bail!("fixed paired helper observation exceeded bound");
            }
            write_new_bytes(path, &bytes)?;
            Ok(ExitCode::SUCCESS)
        }
        _ => bail!("fixed role rejected"),
    }
}
#[cfg(not(windows))]
fn run_fixed_control_role(_role: ControlRole) -> Result<ExitCode> {
    bail!("fixed paired roles require the Windows guest")
}

#[cfg(windows)]
fn execute_paired_controls_request(
    request: &aiw_provider_wsb::PairedControlsRequest,
) -> Result<()> {
    request.validate().map_err(anyhow::Error::msg)?;
    request.profile.validate().map_err(anyhow::Error::msg)?;
    let root = Path::new(PAIRED_OUTPUT_ROOT);
    ensure_output_root(root)?;
    let (payload, kind, status) = match aiw_windows_platform::execute_fixed_paired_controls(request)
    {
        Ok(aiw_windows_platform::PairedGuestOutcome::Completed(result)) => {
            result.compare(request, None).map_err(anyhow::Error::msg)?;
            (
                serde_json::to_value(result)?,
                "pairedControls",
                CompletionStatus::Succeeded,
            )
        }
        Ok(aiw_windows_platform::PairedGuestOutcome::DriverIncomplete {
            progress,
            launcher_token,
        }) => {
            let mut result =
                aiw_provider_wsb::paired_controls::PairedControlDriverFailure::for_request(request)
                    .map_err(anyhow::Error::msg)?;
            result.progress = progress;
            result.launcher_token = Some(launcher_token);
            result.validate(request).map_err(anyhow::Error::msg)?;
            (
                serde_json::to_value(result)?,
                "pairedControlsDriverFailure",
                CompletionStatus::Failed,
            )
        }
        Err(error) => {
            // Logon-command stderr is not retained by every native provider.
            // Preserve bounded private diagnostics in the existing receipt-bound
            // artifact, never as a measurement or an allowlisted summary field.
            eprintln!("AIW_PAIRED_DRIVER_INCOMPLETE: {error}");
            let mut result =
                aiw_provider_wsb::paired_controls::PairedControlDriverFailure::for_request(request)
                    .map_err(anyhow::Error::msg)?;
            result.diagnostic = Some(bounded_diagnostic(&error));
            result.validate(request).map_err(anyhow::Error::msg)?;
            (
                serde_json::to_value(result)?,
                "pairedControlsDriverFailure",
                CompletionStatus::Failed,
            )
        }
    };
    publish_paired_controls(request, root, payload, kind, status)
}
#[cfg(not(windows))]
fn execute_paired_controls_request(
    _request: &aiw_provider_wsb::PairedControlsRequest,
) -> Result<()> {
    bail!("paired controls require the Windows guest")
}

fn publish_paired_controls(
    request: &aiw_provider_wsb::PairedControlsRequest,
    root: &Path,
    payload: serde_json::Value,
    kind: &str,
    status: CompletionStatus,
) -> Result<()> {
    let mut evidence = EvidenceLog::new();
    evidence.append(EvidenceEvent {
        observed_utc: "guest-agent-time-not-trusted".into(),
        kind: kind.into(),
        source: "aiw-guest-agent".into(),
        payload: payload.clone(),
    })?;
    let bytes = evidence_bytes(&evidence)?;
    let hash = evidence.manifest()?.root_hash;
    if status == CompletionStatus::Succeeded {
        let result = serde_json::from_value(payload.clone())?;
        aiw_provider_wsb::paired_controls::verify_paired_controls_evidence(
            &bytes, &hash, request, &result,
        )
        .map_err(anyhow::Error::msg)?;
    } else {
        let result = serde_json::from_value(payload.clone())?;
        aiw_provider_wsb::paired_controls::verify_paired_driver_failure_evidence(
            &bytes, &hash, request, &result,
        )
        .map_err(anyhow::Error::msg)?;
    }
    write_new_json(&root.join("scenario-result.json"), &payload)?;
    write_new_bytes(&root.join("evidence.jsonl"), &bytes)?;
    let receipt = WindowsSandboxCompletionReceipt {
        schema_version: WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION.into(),
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
        evidence_root_hash: hash,
        artifacts: vec![
            completion_artifact(
                &root.join("scenario-result.json"),
                "scenario-result.json",
                ArtifactRole::ScenarioResults,
                "application/json",
            )?,
            completion_artifact(
                &root.join("evidence.jsonl"),
                "evidence.jsonl",
                ArtifactRole::EvidenceLog,
                "application/x-ndjson",
            )?,
        ],
    };
    write_new_json(&root.join("completion.json"), &receipt)
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let request = read_request(&cli.request)?;
    match request {
        GuestRequest::SevenZip(request) => sevenzip::execute(&request),
        GuestRequest::PairedControls(request) => execute_paired_controls_request(&request),
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
        GuestRequest::ImportedBambu(request) => {
            request
                .validate()
                .map_err(|error| anyhow::anyhow!("imported Bambu request is invalid: {error}"))?;
            match execute_imported_bambu_request(&request) {
                Ok(()) => Ok(()),
                Err(error) => {
                    if !error.is::<PublishedBambuFailure>() {
                        let _ = write_imported_bambu_failure_diagnostic(&request, &error);
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
        aiw_windows_platform::execute_fixed_notepad_plus_plus_msi_attempt_with_observations(
            &request.scenario,
            request.required_observations,
        );
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

                publish_msi_result(request, &failed, evidence, CompletionStatus::Failed, None)?;
                return Err(PublishedMsiFailure(error.to_string()).into());
            }
            bail!("fixed imported-MSI execution failed: {error}");
        }
    };
    let document_transfer = observation.document_transfer.map(|transfer| {
        let output_sha256 = hex::encode(Sha256::digest(&transfer.output_bytes));
        (
            aiw_provider_wsb::ImportedMsiDocumentTransferResult {
                input_sha256: transfer.input_sha256,
                input_size_bytes: transfer.input_size_bytes,
                output_sha256,
                output_size_bytes: transfer.output_bytes.len() as u64,
            },
            transfer.output_bytes,
        )
    });
    let result = ImportedMsiScenarioResult::succeeded_with_document_transfer(
        request,
        observation.install_exit_code,
        observation.launch_process_id,
        observation.launch_exit_code,
        document_transfer.as_ref().map(|(result, _)| result.clone()),
    )?;
    result.validate_for_request(request).map_err(|error| {
        anyhow::anyhow!("guest produced an invalid imported-MSI result: {error}")
    })?;
    if let Some((transfer, output_bytes)) = document_transfer.as_ref()
        && (transfer.output_size_bytes != output_bytes.len() as u64
            || transfer.output_sha256 != hex::encode(Sha256::digest(output_bytes)))
    {
        bail!("guest document result does not match the output bytes")
    }
    let mut evidence = EvidenceLog::new();
    evidence.append(EvidenceEvent {
        observed_utc: "guest-agent-time-not-trusted".to_owned(),
        kind: "importedMsiScenario".to_owned(),
        source: "aiw-guest-agent".to_owned(),
        payload: serde_json::to_value(&result)?,
    })?;
    if let Some(product) = observation.product_registration {
        let product = aiw_provider_wsb::ImportedMsiProductRegistrationEvidence {
            schema_version: aiw_provider_wsb::IMPORTED_MSI_PRODUCT_REGISTRATION_SCHEMA_VERSION
                .to_owned(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            installer_sha256: request.installer_sha256.clone(),
            product_code: product.product_code,
            before_install: product.before_install,
            after_install: product.after_install,
        };
        product
            .validate_for(request, &result)
            .map_err(anyhow::Error::msg)?;
        evidence.append(EvidenceEvent {
            observed_utc: "guest-agent-time-not-trusted".to_owned(),
            kind: aiw_provider_wsb::IMPORTED_MSI_PRODUCT_REGISTRATION_EVENT.to_owned(),
            source: "aiw-guest-agent".to_owned(),
            payload: serde_json::to_value(&product)?,
        })?;
    } else if request.scenario.requires_product_registration() {
        bail!("guest did not produce the approved MSI product registration observations");
    }
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
        let runtime = aiw_provider_wsb::ImportedMsiRuntimeContext::new_observed(
            request,
            &result,
            &token,
            context,
            Some(aiw_windows_platform::observe_windows_version().map_err(anyhow::Error::msg)?),
            observation.standard_user_acl,
        )
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
    publish_msi_result(
        request,
        &result,
        evidence,
        CompletionStatus::Succeeded,
        document_transfer.map(|(_, bytes)| bytes),
    )
}

#[cfg(not(windows))]
fn execute_imported_msi_request(_request: &ImportedMsiGuestRequest) -> Result<()> {
    bail!("the imported-MSI guest profile only executes inside Windows Sandbox")
}

#[cfg(windows)]
fn execute_imported_bambu_request(request: &ImportedBambuGuestRequest) -> Result<()> {
    let root = PathBuf::from(&request.output_root);
    ensure_output_root(&root)?;
    let actual_agent_hash = hash_file(&std::env::current_exe().context("resolve agent identity")?)?;
    if actual_agent_hash != request.agent_sha256 {
        return publish_bambu_failure(
            request,
            Vec::new(),
            BambuExecutionStage::Install,
            "guest agent identity does not match the approved request",
        );
    }

    let mut installer = match HeldInstaller::open(
        Path::new(&request.installer_path),
        &request.installer_sha256,
        request.installer_size_bytes,
    ) {
        Ok(installer) => installer,
        Err(error) => {
            return publish_bambu_failure(
                request,
                Vec::new(),
                BambuExecutionStage::Install,
                &format!("held Bambu installer rejected: {error:#}"),
            );
        }
    };
    if let Err(error) = installer.revalidate() {
        return publish_bambu_failure(
            request,
            Vec::new(),
            BambuExecutionStage::Install,
            &format!("held Bambu installer failed pre-execution revalidation: {error:#}"),
        );
    }
    let attempt = aiw_windows_platform::execute_fixed_bambu_export_attempt(&request.scenario);
    if let Err(error) = installer.revalidate() {
        return publish_bambu_failure(
            request,
            Vec::new(),
            BambuExecutionStage::Install,
            &format!("held Bambu installer changed after execution: {error:#}"),
        );
    }

    let artifact_path = output_path(&root, aiw_provider_wsb::BAMBU_EXPORT_ARTIFACT_PATH)?;
    let (result, artifact_bytes, status) = match attempt.result {
        Ok(observation) => {
            let mut result = ImportedBambuScenarioResult::for_request(request);
            result.status = BambuScenarioStatus::Succeeded;
            result.completed_stages = attempt.completed_stages;
            result.failed_stage = None;
            result.diagnostic = None;
            result.install_exit_code = Some(observation.install_exit_code);
            result.launch_process_id = Some(observation.launch_process_id);
            result.launch_exit_code = Some(observation.launch_exit_code);
            result.application_token = Some(observation.application_token);
            result.standard_user_context = Some(observation.standard_user_context);
            result.artifact_sha256 = Some(hex::encode(Sha256::digest(&observation.artifact_bytes)));
            result.artifact_size_bytes = Some(observation.artifact_bytes.len() as u64);
            (
                result,
                observation.artifact_bytes,
                CompletionStatus::Succeeded,
            )
        }
        Err(error) => {
            let failed_stage = attempt.failed_stage.unwrap_or(BambuExecutionStage::Install);
            let result =
                failed_bambu_result(request, attempt.completed_stages, failed_stage, &error);
            (result, Vec::new(), CompletionStatus::Failed)
        }
    };
    result
        .validate_for_request(request)
        .map_err(|error| anyhow::anyhow!("guest produced an invalid Bambu result: {error}"))?;
    let mut evidence = EvidenceLog::new();
    evidence.append(EvidenceEvent {
        observed_utc: "guest-agent-time-not-trusted".to_owned(),
        kind: aiw_provider_wsb::BAMBU_SCENARIO_EVENT.to_owned(),
        source: "aiw-guest-agent".to_owned(),
        payload: serde_json::to_value(&result)?,
    })?;
    let evidence_bytes = evidence_bytes(&evidence)?;
    let root_hash = evidence.manifest()?.root_hash;
    aiw_provider_wsb::verify_bambu_scenario_evidence(&evidence_bytes, &root_hash, request, &result)
        .map_err(|error| {
            anyhow::anyhow!("guest Bambu evidence failed self-verification: {error}")
        })?;
    publish_bambu_result(
        request,
        &result,
        &evidence_bytes,
        &artifact_path,
        &artifact_bytes,
        evidence,
        status,
    )
    .map_err(|error| {
        if status == CompletionStatus::Failed {
            anyhow::anyhow!(PublishedBambuFailure(error.to_string()))
        } else {
            error
        }
    })
}

#[cfg(not(windows))]
fn execute_imported_bambu_request(_request: &ImportedBambuGuestRequest) -> Result<()> {
    bail!("the imported-Bambu guest profile only executes inside Windows Sandbox")
}

fn failed_bambu_result(
    request: &ImportedBambuGuestRequest,
    completed_stages: Vec<BambuExecutionStage>,
    failed_stage: BambuExecutionStage,
    diagnostic: &str,
) -> ImportedBambuScenarioResult {
    let mut result = ImportedBambuScenarioResult::for_request(request);
    result.completed_stages = completed_stages;
    result.failed_stage = Some(failed_stage);
    result.diagnostic = Some(bounded_diagnostic(diagnostic));
    result
}

fn bounded_diagnostic(value: &str) -> String {
    value
        .chars()
        .filter_map(|character| (!character.is_control()).then_some(character).or(Some(' ')))
        .take(2048)
        .collect()
}

fn evidence_bytes(evidence: &EvidenceLog) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for record in evidence.records() {
        serde_json::to_writer(&mut bytes, record)?;
        bytes.push(b'\n');
    }
    if bytes.len() > aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES {
        bail!("guest Bambu evidence exceeded its fixed bound")
    }
    Ok(bytes)
}

fn publish_bambu_failure(
    request: &ImportedBambuGuestRequest,
    completed_stages: Vec<BambuExecutionStage>,
    failed_stage: BambuExecutionStage,
    diagnostic: &str,
) -> Result<()> {
    let result = failed_bambu_result(request, completed_stages, failed_stage, diagnostic);
    result
        .validate_for_request(request)
        .map_err(|error| anyhow::anyhow!("guest produced an invalid Bambu failure: {error}"))?;
    let mut evidence = EvidenceLog::new();
    evidence.append(EvidenceEvent {
        observed_utc: "guest-agent-time-not-trusted".to_owned(),
        kind: aiw_provider_wsb::BAMBU_SCENARIO_EVENT.to_owned(),
        source: "aiw-guest-agent".to_owned(),
        payload: serde_json::to_value(&result)?,
    })?;
    let evidence_bytes = evidence_bytes(&evidence)?;
    let root_hash = evidence.manifest()?.root_hash;
    aiw_provider_wsb::verify_bambu_scenario_evidence(&evidence_bytes, &root_hash, request, &result)
        .map_err(|error| {
            anyhow::anyhow!("guest Bambu evidence failed self-verification: {error}")
        })?;
    let root = PathBuf::from(&request.output_root);
    let artifact_path = output_path(&root, aiw_provider_wsb::BAMBU_EXPORT_ARTIFACT_PATH)?;
    publish_bambu_result(
        request,
        &result,
        &evidence_bytes,
        &artifact_path,
        &[],
        evidence,
        CompletionStatus::Failed,
    )
    .map_err(|error| anyhow::anyhow!(PublishedBambuFailure(error.to_string())))
}

fn publish_bambu_result(
    request: &ImportedBambuGuestRequest,
    result: &ImportedBambuScenarioResult,
    evidence_bytes: &[u8],
    artifact_path: &Path,
    artifact_bytes: &[u8],
    evidence: EvidenceLog,
    status: CompletionStatus,
) -> Result<()> {
    let root = PathBuf::from(&request.output_root);
    let result_path = output_path(&root, &request.scenario_result_path)?;
    let evidence_path = output_path(&root, &request.evidence_log_path)?;
    let receipt_path = output_path(&root, &request.receipt_path)?;
    write_new_json(&result_path, result)?;
    write_new_bytes(&evidence_path, evidence_bytes)?;
    write_new_raw_bytes(artifact_path, artifact_bytes)?;
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
            completion_artifact(
                artifact_path,
                aiw_provider_wsb::BAMBU_EXPORT_ARTIFACT_PATH,
                ArtifactRole::ScenarioResults,
                "model/3mf",
            )?,
        ],
    };
    write_receipt_last(&receipt_path, &receipt)
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
    document_output: Option<Vec<u8>>,
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
    let document_path =
        if request.scenario.requires_document_transfer() && status == CompletionStatus::Succeeded {
            let bytes = document_output
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("interactive document output is missing"))?;
            let path = output_path(&root, "document-output.txt")?;
            write_new_raw_bytes(&path, bytes)?;
            Some(path)
        } else {
            if document_output.is_some() {
                bail!("non-transfer MSI profile produced document output")
            }
            None
        };

    let mut artifacts = vec![
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
    ];
    if let Some(path) = document_path {
        artifacts.push(completion_artifact(
            &path,
            "document-output.txt",
            ArtifactRole::ScenarioResults,
            "text/plain",
        )?);
    }
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
        artifacts,
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

fn write_imported_bambu_failure_diagnostic(
    request: &ImportedBambuGuestRequest,
    error: &anyhow::Error,
) -> Result<()> {
    let root = PathBuf::from(&request.output_root);
    let summary = bounded_diagnostic(&format!("{error:#}"));
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
        Some(aiw_provider_wsb::sevenzip::SEVENZIP_REQUEST_SCHEMA) => serde_json::from_value(value)
            .map(Box::new)
            .map(GuestRequest::SevenZip)
            .context("parse strict fixed 7-Zip request"),
        Some(aiw_provider_wsb::PAIRED_CONTROL_REQUEST_SCHEMA) => serde_json::from_value(value)
            .map(Box::new)
            .map(GuestRequest::PairedControls)
            .context("parse strict paired-controls request"),
        Some(REQUEST_SCHEMA) => serde_json::from_value(value)
            .map(Box::new)
            .map(GuestRequest::Golden)
            .context("parse strict golden-probe request"),
        Some(
            IMPORTED_MSI_GUEST_REQUEST_SCHEMA_VERSION
            | aiw_provider_wsb::IMPORTED_MSI_OBSERVATION_REQUEST_SCHEMA_VERSION,
        ) => serde_json::from_value(value)
            .map(Box::new)
            .map(GuestRequest::ImportedMsi)
            .context("parse strict imported-MSI request"),
        Some(IMPORTED_BAMBU_GUEST_REQUEST_SCHEMA_VERSION) => serde_json::from_value(value)
            .map(Box::new)
            .map(GuestRequest::ImportedBambu)
            .context("parse strict imported-Bambu request"),
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
    write_new_bytes_with_suffix(path, bytes, true)
}

fn write_new_raw_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    write_new_bytes_with_suffix(path, bytes, false)
}

fn write_new_bytes_with_suffix(path: &Path, bytes: &[u8], newline: bool) -> Result<()> {
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
    if newline {
        file.write_all(b"\n")?;
    }
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

    fn paired_request() -> (
        aiw_provider_wsb::PairedControlsRequest,
        aiw_provider_wsb::PairedControlResult,
    ) {
        use aiw_probe::paired_controls::{
            PAIRED_CONTROL_REVISION, PairedControlPolicy, paired_control_source_sha256,
        };
        let mut result: aiw_provider_wsb::PairedControlResult = serde_json::from_str(include_str!(
            "../../../fixtures/paired-controls/synthetic-result.json"
        ))
        .unwrap();
        let profile = aiw_probe::PairedControlProfile {
            revision: PAIRED_CONTROL_REVISION.into(),
            source_sha256: paired_control_source_sha256(),
            fixture_sha256: "a".repeat(64),
            fixture_size_bytes: 7,
            launcher_sha256: "a".repeat(64),
            launcher_size_bytes: 7,
            origin: aiw_probe::ControlEvidenceOrigin::SyntheticRehearsal,
            expected_windows: result.windows.clone(),
            expected_host_windows: Some(result.windows.clone()),
            policy: PairedControlPolicy::ClassicAppContainerNoCapabilitiesFixedChildOutputGrant,
        };
        let request = aiw_provider_wsb::PairedControlsRequest::new(
            "synthetic-agent-rehearsal",
            &result.sandbox_id,
            &"b".repeat(64),
            &"a".repeat(64),
            profile,
        )
        .unwrap();
        result.run_id = request.run_id.clone();
        result.request_sha256 = request.request_sha256.clone();
        result.profile_sha256 = request.profile.hash().unwrap();
        (request, result)
    }
    #[test]
    fn paired_role_arguments_and_fixed_paths_are_closed_without_native_calls() {
        let os = |args: &[&str]| {
            args.iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        };
        for mode in ["read-canary", "read-registry", "child", "child-token"] {
            assert_eq!(
                classify_control_role(&os(&["--mode", mode])),
                ControlRole::Fixture(mode.into())
            );
        }
        for args in [
            vec!["--mode", "round-trip"],
            vec!["--mode", "read-canary", "extra"],
            vec!["--paired-control-launcher", "--request", "x"],
            vec!["--mode"],
        ] {
            assert_eq!(classify_control_role(&os(&args)), ControlRole::Rejected);
        }
        assert_eq!(
            classify_control_role(&os(&["--paired-control-launcher"])),
            ControlRole::Launcher
        );
        assert_eq!(
            classify_control_role(&os(&["--request", "request.json"])),
            ControlRole::None
        );
        let fixture = Path::new(r"C:\AIW\Control\aiw-control-fixture.exe");
        let launcher = Path::new(r"C:\AIW\Control\aiw-control-appcontainer.exe");
        assert_eq!(
            restrict_role_executable(Some(fixture), ControlRole::None),
            ControlRole::Rejected
        );
        assert_eq!(
            restrict_role_executable(Some(launcher), ControlRole::None),
            ControlRole::Rejected
        );
        assert_eq!(
            restrict_role_executable(Some(fixture), ControlRole::Launcher),
            ControlRole::Rejected
        );
        assert_eq!(
            restrict_role_executable(Some(launcher), ControlRole::Fixture("child".into())),
            ControlRole::Rejected
        );

        assert_eq!(
            restrict_role_executable(None, ControlRole::None),
            ControlRole::Rejected
        );
        assert_eq!(
            restrict_role_executable(
                Some(Path::new(r"C:\AIW\Tools\aiw-guest-agent.exe")),
                ControlRole::None
            ),
            ControlRole::None
        );
        for path in [
            r"c:\aiw\control\aiw-control-fixture.exe",
            r"\\?\C:\AIW\Control\aiw-control-fixture.exe",
            r"C:\AIW\CONTRO~1\AIW-CO~1.EXE",
        ] {
            assert_eq!(
                restrict_role_executable(Some(Path::new(path)), ControlRole::None),
                ControlRole::Rejected
            );
        }
        let separator = char::from(92);
        assert_eq!(
            PAIRED_LAUNCHER_OBSERVATION_PATH,
            ["C:", "AIW", "Control", "paired-launcher.json"].join(&separator.to_string())
        );
        assert_eq!(
            PAIRED_OUTPUT_ROOT,
            ["C:", "AIW", "Output"].join(&separator.to_string())
        );
        #[cfg(windows)]
        {
            assert!(Path::new(PAIRED_OUTPUT_ROOT).is_absolute());
            assert!(Path::new(PAIRED_LAUNCHER_OBSERVATION_PATH).is_absolute());
        }
    }
    #[test]
    fn paired_request_dispatch_is_typed_and_does_not_execute() {
        let root = test_root("paired-dispatch");
        let (request, _) = paired_request();
        let path = root.join("request.json");
        fs::write(&path, serde_json::to_vec(&request).unwrap()).unwrap();
        assert!(matches!(
            read_request(&path).unwrap(),
            GuestRequest::PairedControls(_)
        ));
        let mut value = serde_json::to_value(request).unwrap();
        value["command"] = "hostile.exe".into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_request(&path).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn paired_publication_is_deterministic_and_receipt_last_without_execution() {
        use aiw_provider_wsb::{
            CompletionArtifactExpectation, WindowsSandboxCompletionExpectation,
        };
        let (request, result) = paired_request();
        let a = test_root("paired-publish-a");
        let b = test_root("paired-publish-b");
        let payload = serde_json::to_value(&result).unwrap();
        for root in [&a, &b] {
            publish_paired_controls(
                &request,
                root,
                payload.clone(),
                "pairedControls",
                CompletionStatus::Succeeded,
            )
            .unwrap();
        }
        let expectation = WindowsSandboxCompletionExpectation {
            schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_COMPLETION_EXPECTATION_SCHEMA_VERSION
                .into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            config_sha256: request.config_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            agent_sha256: request.agent_sha256.clone(),
            receipt_path: "completion.json".into(),
            evidence_log_path: "evidence.jsonl".into(),
            content_declaration: aiw_evidence::ContentDeclaration::NoKnownSecrets,
            artifacts: [
                (
                    "scenario-result.json",
                    ArtifactRole::ScenarioResults,
                    "application/json",
                ),
                (
                    "evidence.jsonl",
                    ArtifactRole::EvidenceLog,
                    "application/x-ndjson",
                ),
            ]
            .into_iter()
            .map(|(path, role, media_type)| CompletionArtifactExpectation {
                path: path.into(),
                role,
                media_type: media_type.into(),
                sensitivity: aiw_evidence::DataSensitivity::Internal,
                maximum_bytes: 64 * 1024,
            })
            .collect(),
        };
        assert!(
            aiw_provider_wsb::verify_completion_receipt(&a, &expectation)
                .unwrap()
                .successful
        );
        let receipt: WindowsSandboxCompletionReceipt =
            serde_json::from_slice(&fs::read(a.join("completion.json")).unwrap()).unwrap();
        aiw_provider_wsb::paired_controls::verify_paired_controls_evidence(
            &fs::read(a.join("evidence.jsonl")).unwrap(),
            &receipt.evidence_root_hash,
            &request,
            &result,
        )
        .unwrap();
        let before = ["scenario-result.json", "evidence.jsonl", "completion.json"]
            .map(|leaf| fs::read(a.join(leaf)).unwrap());
        assert!(
            publish_paired_controls(
                &request,
                &a,
                payload,
                "pairedControls",
                CompletionStatus::Succeeded
            )
            .is_err()
        );
        for (leaf, expected) in ["scenario-result.json", "evidence.jsonl", "completion.json"]
            .into_iter()
            .zip(before)
        {
            assert_eq!(fs::read(a.join(leaf)).unwrap(), expected);
            assert_eq!(fs::read(b.join(leaf)).unwrap(), expected);
        }
        fs::write(a.join("scenario-result.json"), b"tampered").unwrap();
        assert!(aiw_provider_wsb::verify_completion_receipt(&a, &expectation).is_err());
        fs::remove_dir_all(a).unwrap();
        fs::remove_dir_all(b).unwrap();
    }
    #[test]
    fn paired_partial_progress_is_ordered_bounded_and_receipt_bound() {
        use aiw_provider_wsb::paired_controls::{
            FixedControlCase, NormalizedCase, PairedCaseProgress, PairedControlDriverFailure,
            PairedVariantKind,
        };
        let (request, result) = paired_request();
        let prefix = PairedCaseProgress {
            variant: PairedVariantKind::Baseline,
            case: FixedControlCase::File,
            process: result.baseline.file_process.clone(),
            observation: NormalizedCase {
                read: Some(result.baseline.file.clone()),
                child_id: None,
                child_token: None,
                child_stdout_bytes: None,
                outcome: aiw_provider_wsb::ControlAccess::Success,
            },
        };
        let mut failure = PairedControlDriverFailure::for_request(&request).unwrap();
        failure.progress.push(prefix.clone());
        failure.launcher_token = Some(result.launcher_token.clone());
        failure.validate(&request).unwrap();
        let root = test_root("paired-partial");
        publish_paired_controls(
            &request,
            &root,
            serde_json::to_value(&failure).unwrap(),
            "pairedControlsDriverFailure",
            CompletionStatus::Failed,
        )
        .unwrap();
        let recorded: PairedControlDriverFailure =
            serde_json::from_slice(&fs::read(root.join("scenario-result.json")).unwrap()).unwrap();
        assert_eq!(recorded.progress, vec![prefix.clone()]);
        let mut duplicate = failure.clone();
        duplicate.progress.push(prefix.clone());
        assert!(duplicate.validate(&request).is_err());
        let mut skipped = failure.clone();
        skipped.progress[0].case = FixedControlCase::Registry;
        assert!(skipped.validate(&request).is_err());
        let mut excessive = failure.clone();
        excessive.progress = vec![prefix.clone(); 7];
        assert!(excessive.validate(&request).is_err());
        let mut token = failure.clone();
        token.progress[0]
            .process
            .held_token
            .as_mut()
            .unwrap()
            .is_elevated = true;
        assert!(token.validate(&request).is_err());
        let mut provenance = failure.clone();
        provenance.launcher_token.as_mut().unwrap().user_sid = "S-1-5-21-8-8-8-1001".into();
        assert!(provenance.validate(&request).is_err());
        let mut alias = failure.clone();
        alias.launcher_token.as_mut().unwrap().process_id = prefix.process.process_id;
        assert!(alias.validate(&request).is_err());
        let mut no_self = failure.clone();
        no_self.progress[0].process.self_token = None;
        assert!(no_self.validate(&request).is_err());
        let mut timed = failure.clone();
        timed.progress[0].process.timed_out = true;
        assert!(timed.validate(&request).is_err());
        let mut denial = failure;
        denial.progress[0]
            .observation
            .read
            .as_mut()
            .unwrap()
            .outcome = aiw_provider_wsb::ControlAccess::AccessDenied;
        assert!(denial.validate(&request).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn paired_driver_failure_is_bound_and_has_no_fabricated_observations() {
        let (request, _) = paired_request();
        let root = test_root("paired-driver-failure");
        let failure =
            aiw_provider_wsb::paired_controls::PairedControlDriverFailure::for_request(&request)
                .unwrap();
        publish_paired_controls(
            &request,
            &root,
            serde_json::to_value(&failure).unwrap(),
            "pairedControlsDriverFailure",
            CompletionStatus::Failed,
        )
        .unwrap();
        let receipt: WindowsSandboxCompletionReceipt =
            serde_json::from_slice(&fs::read(root.join("completion.json")).unwrap()).unwrap();
        assert_eq!(receipt.status, CompletionStatus::Failed);
        assert_eq!(receipt.exit_code, 1);
        aiw_provider_wsb::paired_controls::verify_paired_driver_failure_evidence(
            &fs::read(root.join("evidence.jsonl")).unwrap(),
            &receipt.evidence_root_hash,
            &request,
            &failure,
        )
        .unwrap();
        let mut other = request.clone();
        other.run_id.push('x');
        other.request_sha256 = other.hash().unwrap();
        assert!(failure.validate(&other).is_err());
        let value = serde_json::to_value(failure).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 9);
        assert!(value["launcherToken"].is_null());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn paired_private_diagnostic_is_bounded_and_published_under_the_failed_receipt() {
        let (request, _) = paired_request();
        let root = test_root("paired-private-diagnostic");
        let mut failure =
            aiw_provider_wsb::paired_controls::PairedControlDriverFailure::for_request(&request)
                .unwrap();
        failure.diagnostic = Some(bounded_diagnostic(&format!(
            "private-path-sentinel credential-sentinel\n{}",
            "🧪".repeat(4096)
        )));
        let diagnostic = failure.diagnostic.as_deref().unwrap();
        assert_eq!(
            diagnostic.chars().count(),
            aiw_provider_wsb::paired_controls::MAX_PAIRED_DRIVER_DIAGNOSTIC_CHARS
        );
        assert!(!diagnostic.chars().any(char::is_control));
        failure.validate(&request).unwrap();
        publish_paired_controls(
            &request,
            &root,
            serde_json::to_value(&failure).unwrap(),
            "pairedControlsDriverFailure",
            CompletionStatus::Failed,
        )
        .unwrap();
        let receipt: WindowsSandboxCompletionReceipt =
            serde_json::from_slice(&fs::read(root.join("completion.json")).unwrap()).unwrap();
        assert_eq!(receipt.status, CompletionStatus::Failed);
        assert_eq!(receipt.artifacts.len(), 2);
        let retained =
            serde_json::from_slice(&fs::read(root.join("scenario-result.json")).unwrap()).unwrap();
        aiw_provider_wsb::paired_controls::verify_paired_driver_failure_evidence(
            &fs::read(root.join("evidence.jsonl")).unwrap(),
            &receipt.evidence_root_hash,
            &request,
            &retained,
        )
        .unwrap();
        assert_eq!(failure, retained);
        assert!(retained.progress.is_empty());
        assert!(retained.launcher_token.is_none());
        fs::remove_dir_all(root).unwrap();
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

    fn msi_request() -> ImportedMsiGuestRequest {
        ImportedMsiGuestRequest::new(
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
                interactive_session_seconds: None,
                document_exercise: None,
                interactive_document: None,
            },
            "a".repeat(64),
            1024,
            "d".repeat(64),
        )
        .unwrap()
    }

    #[test]
    fn required_acl_request_dispatches_without_execution() {
        use aiw_provider_wsb::*;
        let root = test_root("required-acl-request");
        let path = root.join("request.json");
        let mut request = msi_request();
        request.scenario.schema_version = COMPILED_MSI_SCENARIO_SCHEMA_VERSION.into();
        request.scenario.profile = NOTEPAD_PLUS_PLUS_MSI_PROFILE.into();
        request.scenario.install_timeout_seconds = 300;
        request.scenario.document_exercise = Some(FixedDocumentExercise {
            document_path: STANDARD_USER_DOCUMENT_EXERCISE_PATH.into(),
            initial_sha256: hex::encode(Sha256::digest(DOCUMENT_INITIAL_TEXT.as_bytes())),
            expected_sha256: hex::encode(Sha256::digest(DOCUMENT_EXPECTED_TEXT.as_bytes())),
        });
        request.scenario_sha256 = request.scenario.canonical_sha256().unwrap();
        request.request_sha256 = request.request_sha256().unwrap();
        let request = request
            .with_required_observations(Some(MsiRequiredObservations::StandardUserAclV1))
            .unwrap();
        fs::write(&path, serde_json::to_vec(&request).unwrap()).unwrap();
        assert!(
            matches!(read_request(&path).unwrap(), GuestRequest::ImportedMsi(decoded) if *decoded == request)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn imported_msi_request_dispatches_without_execution() {
        let root = test_root("imported-request");
        let request_path = root.join("request.json");
        let request = msi_request();
        fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();

        assert!(matches!(
            read_request(&request_path).unwrap(),
            GuestRequest::ImportedMsi(request) if request.validate().is_ok()
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn published_transfer_is_accepted_by_the_host_receipt_contract() {
        use aiw_provider_wsb::{
            CompletionArtifactExpectation, WindowsSandboxCompletionExpectation,
        };
        let root = test_root("transfer-publication");
        let mut request = msi_request();
        request.scenario.schema_version =
            aiw_provider_wsb::COMPILED_MSI_INTERACTIVE_DOCUMENT_SCENARIO_SCHEMA_VERSION.into();
        request.scenario.profile =
            aiw_provider_wsb::NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE.into();
        request.scenario.interactive_session_seconds = Some(60);
        request.scenario.install_timeout_seconds = 300;
        request.scenario.install_arguments.extend([
            "/L*V".into(),
            aiw_provider_wsb::INTERACTIVE_MSI_INSTALL_LOG_PATH.into(),
        ]);
        request.scenario.interactive_document =
            Some(aiw_provider_wsb::InteractiveDocumentTransfer {
                input_sha256: "e".repeat(64),
                input_size_bytes: 7,
            });
        request.scenario_sha256 = request.scenario.canonical_sha256().unwrap();
        request.request_sha256 = request.request_sha256().unwrap();
        request.validate().unwrap();
        let bytes = "edited café".as_bytes();
        let result = ImportedMsiScenarioResult::succeeded_with_document_transfer(
            &request,
            0,
            42,
            0,
            Some(aiw_provider_wsb::ImportedMsiDocumentTransferResult {
                input_sha256: "e".repeat(64),
                input_size_bytes: 7,
                output_sha256: hex::encode(Sha256::digest(bytes)),
                output_size_bytes: bytes.len() as u64,
            }),
        )
        .unwrap();
        let mut log = EvidenceLog::new();
        log.append(aiw_evidence::EvidenceEvent {
            observed_utc: "fixture".into(),
            kind: "transfer-fixture".into(),
            source: "fixture".into(),
            payload: serde_json::json!({"completed": true}),
        })
        .unwrap();
        // Only redirect publication for this test; no guest execution occurs.
        request.output_root = root.to_string_lossy().into_owned();
        publish_msi_result(
            &request,
            &result,
            log,
            CompletionStatus::Succeeded,
            Some(bytes.to_vec()),
        )
        .unwrap();
        let expectation = WindowsSandboxCompletionExpectation {
            schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_COMPLETION_EXPECTATION_SCHEMA_VERSION
                .into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            config_sha256: request.config_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            agent_sha256: request.agent_sha256.clone(),
            receipt_path: "completion.json".into(),
            evidence_log_path: "evidence.jsonl".into(),
            content_declaration: aiw_evidence::ContentDeclaration::NoKnownSecrets,
            artifacts: [
                (
                    "scenario-result.json",
                    ArtifactRole::ScenarioResults,
                    "application/json",
                ),
                (
                    "evidence.jsonl",
                    ArtifactRole::EvidenceLog,
                    "application/x-ndjson",
                ),
                (
                    "document-output.txt",
                    ArtifactRole::ScenarioResults,
                    "text/plain",
                ),
            ]
            .into_iter()
            .map(|(path, role, media_type)| CompletionArtifactExpectation {
                path: path.into(),
                role,
                media_type: media_type.into(),
                sensitivity: aiw_evidence::DataSensitivity::Internal,
                maximum_bytes: 1024 * 1024,
            })
            .collect(),
        };
        assert!(
            aiw_provider_wsb::verify_completion_receipt(&root, &expectation)
                .unwrap()
                .successful
        );
        assert_eq!(fs::read(root.join("document-output.txt")).unwrap(), bytes);
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

#[derive(Debug)]
struct PublishedBambuFailure(String);
impl std::fmt::Display for PublishedBambuFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "failed Bambu attempt published: {}", self.0)
    }
}
impl std::error::Error for PublishedBambuFailure {}

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
