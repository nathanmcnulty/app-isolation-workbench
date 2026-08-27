#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aiw_core::{
    AnalystReport, AnalystReportValidation, CanaryObservationSet, CanaryPlan, CanaryReport,
    RunSummary, compare_runs, evaluate_canaries, validate_analyst_report,
};
use aiw_evidence::{
    AssessmentBundleManifest, AssessmentBundleSpec, BundleVerification, EvidenceRecord,
    build_assessment_bundle, verify_assessment_bundle, verify_records,
};
use aiw_orchestrator::{
    AiwError, ApprovalRecord, CancellationRequest, RecoveryStatus, RunLayout, RunPlan, RunResult,
};
use aiw_probe::probe_host;
use aiw_provider_mxc::{MxcGoldenProbePlan, plan_capability_probe, plan_golden_probe};
use aiw_provider_wsb::{
    WindowsSandboxCliLifecyclePlan, WindowsSandboxCompletionExpectation,
    WindowsSandboxCompletionReceipt, WindowsSandboxCompletionVerification, WindowsSandboxPlan,
    plan_cli_lifecycle, render_config, validate_host_mappings, verify_completion_receipt,
};
use aiw_schema::{
    LEGACY_PROJECT_SCHEMA_VERSION, LegacyProjectV0Alpha1, ModelPack, PROJECT_SCHEMA_VERSION,
    Project, ValidationIssue, migrate_v0alpha1, validate_model_pack, validate_project,
};
use aiw_token::{TokenEvidence, collect_current_process_token};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use schemars::schema_for;
use serde::Serialize;
use serde_json::Value;

const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "aiw", version, about = "App Isolation Workbench bootstrap CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Project(ProjectArgs),
    ModelPack(ModelPackArgs),
    Analyst(AnalystArgs),
    Evidence(EvidenceArgs),
    Bundle(BundleArgs),
    Canary(CanaryArgs),
    Host(HostArgs),
    Probe(ProbeArgs),
    Run(RunArgs),
    Provider(ProviderArgs),
    Schema(SchemaArgs),
    Compare(CompareArgs),
}

#[derive(Debug, Args)]
struct ProjectArgs {
    #[command(subcommand)]
    command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
    /// Convert a v0alpha1 project to v0alpha2 without overwriting either file.
    Migrate {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
struct ModelPackArgs {
    #[command(subcommand)]
    command: ModelPackCommand,
}

#[derive(Debug, Subcommand)]
enum ModelPackCommand {
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Debug, Args)]
struct AnalystArgs {
    #[command(subcommand)]
    command: AnalystCommand,
}

#[derive(Debug, Subcommand)]
enum AnalystCommand {
    /// Validate an advisory report against an evidence chain and model pack.
    Validate {
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        evidence_log: PathBuf,
        #[arg(long)]
        model_pack: PathBuf,
    },
}

#[derive(Debug, Args)]
struct EvidenceArgs {
    #[command(subcommand)]
    command: EvidenceCommand,
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    Verify {
        #[arg(long)]
        log: PathBuf,
    },
}

#[derive(Debug, Args)]
struct BundleArgs {
    #[command(subcommand)]
    command: BundleCommand,
}

#[derive(Debug, Subcommand)]
enum BundleCommand {
    /// Hash an explicit artifact set and emit a deterministic manifest without copying files.
    Build {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        spec: PathBuf,
    },
    /// Re-hash an explicit artifact set and verify it exactly matches its manifest.
    Verify {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
}

#[derive(Debug, Args)]
struct CanaryArgs {
    #[command(subcommand)]
    command: CanaryCommand,
}

#[derive(Debug, Subcommand)]
enum CanaryCommand {
    /// Evaluate baseline and isolated observations without executing any canary.
    Evaluate {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        observations: PathBuf,
        #[arg(long)]
        evidence_log: PathBuf,
    },
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[command(subcommand)]
    command: ProbeCommand,
}

#[derive(Debug, Subcommand)]
enum ProbeCommand {
    Host,
    Token,
}

#[derive(Debug, Args)]
struct HostArgs {
    #[command(subcommand)]
    command: HostCommand,
}

#[derive(Debug, Subcommand)]
enum HostCommand {
    /// Collect a non-mutating host readiness report.
    Assess,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(subcommand)]
    command: RunCommand,
}

#[derive(Debug, Subcommand)]
enum RunCommand {
    /// Persist a supplied immutable plan and create its run journal. This does not execute it.
    Plan {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        plan: PathBuf,
    },
    /// Persist a supplied approval for an existing plan. This does not execute it.
    Approve {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        approval: PathBuf,
    },
    /// Read the verified persisted state of a run without executing it.
    Status {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        run_id: String,
    },
    /// Reconcile and report persisted run state without starting a provider.
    Recover {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        run_id: String,
    },
    /// Persist a write-once cancellation request. This does not terminate a provider.
    Cancel {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        requested_by: String,
        #[arg(long)]
        requested_at: String,
    },
}

#[derive(Debug, Args)]
struct ProviderArgs {
    #[command(subcommand)]
    command: ProviderCommand,
}

#[derive(Debug, Subcommand)]
enum ProviderCommand {
    /// Render a hardened Windows Sandbox configuration after checking mapped folders.
    Wsb {
        #[arg(long)]
        plan: PathBuf,
    },
    /// Plan Windows Sandbox CLI start/list/stop calls without executing them.
    WsbCli {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        binary: String,
        #[arg(long)]
        sandbox_id: String,
    },
    /// Verify a run-bound Windows Sandbox receipt and its allowlisted output.
    WsbReceipt {
        #[arg(long)]
        output_root: PathBuf,
        #[arg(long)]
        expectation: PathBuf,
    },
    /// Render inspectable MXC dry-run and execution invocations without launching them.
    Mxc {
        #[arg(long)]
        plan: PathBuf,
    },
    /// Describe MXC's capability-probe invocation and its host-mutation caveat.
    MxcProbe {
        #[arg(long)]
        binary: String,
    },
}

#[derive(Debug, Args)]
struct SchemaArgs {
    #[arg(value_enum)]
    kind: SchemaKind,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SchemaKind {
    Project,
    ModelPack,
    EvidenceRecord,
    AssessmentBundleSpec,
    AssessmentBundleManifest,
    AssessmentBundleVerification,
    CanaryPlan,
    CanaryObservationSet,
    CanaryReport,
    AnalystReport,
    AnalystReportValidation,
    TokenEvidence,
    WindowsSandboxPlan,
    WindowsSandboxCliLifecyclePlan,
    WindowsSandboxCompletionExpectation,
    WindowsSandboxCompletionReceipt,
    WindowsSandboxCompletionVerification,
    MxcGoldenProbePlan,
}

#[derive(Debug, Args)]
struct CompareArgs {
    #[arg(long)]
    left: PathBuf,
    #[arg(long)]
    right: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidationResult {
    valid: bool,
    issues: Vec<ValidationIssue>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectMigrationResult {
    output: PathBuf,
    project: Project,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEnvelope<'a> {
    code: &'a str,
    summary: &'a str,
    stage: &'a str,
    run_id: Option<&'a str>,
    retryable: bool,
    remediation: &'a str,
    detail: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
enum RunStatusResult {
    PendingApproval {
        plan_hash: String,
        last_sequence: u64,
    },
    Ready {
        approval: ApprovalRecord,
        last_sequence: u64,
    },
    CancellationRequested {
        request: CancellationRequest,
        last_sequence: u64,
    },
    Terminal {
        result: RunResult,
        last_sequence: u64,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            emit_error(&error);
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Project(args) => match args.command {
            ProjectCommand::Validate { path } => {
                let project = read_project(&path)?;
                emit_validation(validate_project(&project))
            }
            ProjectCommand::Migrate { path, output } => {
                let legacy = read_legacy_project(&path)?;
                if output.exists() {
                    bail!("migration output already exists: {}", output.display());
                }
                let project = migrate_v0alpha1(&legacy);
                write_document_new(&output, &project)?;
                write_json(&ProjectMigrationResult { output, project })
            }
        },
        Command::ModelPack(args) => match args.command {
            ModelPackCommand::Validate { path } => {
                let pack: ModelPack = read_document(&path, MAX_CONFIG_BYTES)?;
                emit_validation(validate_model_pack(&pack))
            }
        },
        Command::Analyst(args) => match args.command {
            AnalystCommand::Validate {
                report,
                evidence_log,
                model_pack,
            } => {
                let report: AnalystReport = read_document(&report, MAX_CONFIG_BYTES)?;
                let records = read_evidence_log(&evidence_log)?;
                let model_pack: ModelPack = read_document(&model_pack, MAX_CONFIG_BYTES)?;
                write_json(&validate_analyst_report(&report, &records, &model_pack)?)
            }
        },
        Command::Evidence(args) => match args.command {
            EvidenceCommand::Verify { log } => {
                let records = read_evidence_log(&log)?;
                write_json(&verify_records(&records)?)
            }
        },
        Command::Bundle(args) => match args.command {
            BundleCommand::Build { root, spec } => {
                let spec: AssessmentBundleSpec = read_document(&spec, MAX_CONFIG_BYTES)?;
                write_json(&build_assessment_bundle(&root, &spec)?)
            }
            BundleCommand::Verify { root, manifest } => {
                let manifest: AssessmentBundleManifest =
                    read_document(&manifest, MAX_CONFIG_BYTES)?;
                write_json(&verify_assessment_bundle(&root, &manifest)?)
            }
        },
        Command::Canary(args) => match args.command {
            CanaryCommand::Evaluate {
                plan,
                observations,
                evidence_log,
            } => {
                let plan: CanaryPlan = read_document(&plan, MAX_CONFIG_BYTES)?;
                let observations: CanaryObservationSet =
                    read_document(&observations, MAX_CONFIG_BYTES)?;
                let evidence_records = read_evidence_log(&evidence_log)?;
                write_json(&evaluate_canaries(&plan, &observations, &evidence_records)?)
            }
        },
        Command::Probe(args) => match args.command {
            ProbeCommand::Host => write_json(&probe_host()),
            ProbeCommand::Token => write_json(&collect_current_process_token()?),
        },
        Command::Host(args) => match args.command {
            HostCommand::Assess => write_json(&probe_host()),
        },
        Command::Run(args) => match args.command {
            RunCommand::Plan { root, plan } => {
                let plan: RunPlan = read_document(&plan, MAX_CONFIG_BYTES)?;
                let layout = RunLayout::new(&root, &plan.run_id)?;
                layout.create(&plan)?;
                write_json(&plan)
            }
            RunCommand::Approve {
                root,
                run_id,
                approval,
            } => {
                let approval: ApprovalRecord = read_document(&approval, MAX_CONFIG_BYTES)?;
                let layout = RunLayout::new(&root, run_id)?;
                layout.write_approval(&approval)?;
                write_json(&approval)
            }
            RunCommand::Status { root, run_id } | RunCommand::Recover { root, run_id } => {
                let layout = RunLayout::new(&root, run_id)?;
                write_json(&serialize_recovery_status(layout.recovery_status()?))
            }
            RunCommand::Cancel {
                root,
                run_id,
                requested_by,
                requested_at,
            } => {
                let layout = RunLayout::new(&root, run_id)?;
                let cancellation = layout.request_cancellation(requested_by, requested_at)?;
                write_json(&cancellation)
            }
        },
        Command::Provider(args) => match args.command {
            ProviderCommand::Wsb { plan } => {
                let plan: WindowsSandboxPlan = read_document(&plan, MAX_CONFIG_BYTES)?;
                validate_host_mappings(&plan)?;
                write_json(&render_config(&plan)?)
            }
            ProviderCommand::WsbCli {
                plan,
                binary,
                sandbox_id,
            } => {
                let plan: WindowsSandboxPlan = read_document(&plan, MAX_CONFIG_BYTES)?;
                validate_host_mappings(&plan)?;
                write_json(&plan_cli_lifecycle(&binary, &sandbox_id, &plan)?)
            }
            ProviderCommand::WsbReceipt {
                output_root,
                expectation,
            } => {
                let expectation: WindowsSandboxCompletionExpectation =
                    read_document(&expectation, MAX_CONFIG_BYTES)?;
                write_json(&verify_completion_receipt(&output_root, &expectation)?)
            }
            ProviderCommand::Mxc { plan } => {
                let plan: MxcGoldenProbePlan = read_document(&plan, MAX_CONFIG_BYTES)?;
                write_json(&plan_golden_probe(&plan)?)
            }
            ProviderCommand::MxcProbe { binary } => write_json(&plan_capability_probe(&binary)?),
        },
        Command::Schema(args) => match args.kind {
            SchemaKind::Project => write_json(&schema_for!(Project)),
            SchemaKind::ModelPack => write_json(&schema_for!(ModelPack)),
            SchemaKind::EvidenceRecord => write_json(&schema_for!(EvidenceRecord)),
            SchemaKind::AssessmentBundleSpec => write_json(&schema_for!(AssessmentBundleSpec)),
            SchemaKind::AssessmentBundleManifest => {
                write_json(&schema_for!(AssessmentBundleManifest))
            }
            SchemaKind::AssessmentBundleVerification => {
                write_json(&schema_for!(BundleVerification))
            }
            SchemaKind::CanaryPlan => write_json(&schema_for!(CanaryPlan)),
            SchemaKind::CanaryObservationSet => write_json(&schema_for!(CanaryObservationSet)),
            SchemaKind::CanaryReport => write_json(&schema_for!(CanaryReport)),
            SchemaKind::AnalystReport => write_json(&schema_for!(AnalystReport)),
            SchemaKind::AnalystReportValidation => {
                write_json(&schema_for!(AnalystReportValidation))
            }
            SchemaKind::TokenEvidence => write_json(&schema_for!(TokenEvidence)),
            SchemaKind::WindowsSandboxPlan => write_json(&schema_for!(WindowsSandboxPlan)),
            SchemaKind::WindowsSandboxCliLifecyclePlan => {
                write_json(&schema_for!(WindowsSandboxCliLifecyclePlan))
            }
            SchemaKind::WindowsSandboxCompletionExpectation => {
                write_json(&schema_for!(WindowsSandboxCompletionExpectation))
            }
            SchemaKind::WindowsSandboxCompletionReceipt => {
                write_json(&schema_for!(WindowsSandboxCompletionReceipt))
            }
            SchemaKind::WindowsSandboxCompletionVerification => {
                write_json(&schema_for!(WindowsSandboxCompletionVerification))
            }
            SchemaKind::MxcGoldenProbePlan => write_json(&schema_for!(MxcGoldenProbePlan)),
        },
        Command::Compare(args) => {
            let left: RunSummary = read_document(&args.left, MAX_CONFIG_BYTES)?;
            let right: RunSummary = read_document(&args.right, MAX_CONFIG_BYTES)?;
            write_json(&compare_runs(&left, &right))
        }
    }
}

fn emit_validation(issues: Vec<ValidationIssue>) -> Result<()> {
    let valid = issues.is_empty();
    write_json(&ValidationResult { valid, issues })?;
    if valid {
        Ok(())
    } else {
        bail!("validation failed")
    }
}

fn serialize_recovery_status(status: RecoveryStatus) -> RunStatusResult {
    match status {
        RecoveryStatus::PendingApproval {
            plan_hash,
            last_sequence,
        } => RunStatusResult::PendingApproval {
            plan_hash,
            last_sequence,
        },
        RecoveryStatus::Ready {
            approval,
            last_sequence,
        } => RunStatusResult::Ready {
            approval,
            last_sequence,
        },
        RecoveryStatus::CancellationRequested {
            request,
            last_sequence,
        } => RunStatusResult::CancellationRequested {
            request,
            last_sequence,
        },
        RecoveryStatus::Terminal {
            result,
            last_sequence,
        } => RunStatusResult::Terminal {
            result,
            last_sequence,
        },
    }
}

fn read_project(path: &Path) -> Result<Project> {
    let value: Value = read_document(path, MAX_CONFIG_BYTES)?;
    match project_schema_version(&value)? {
        PROJECT_SCHEMA_VERSION => serde_json::from_value(value)
            .with_context(|| format!("invalid v0alpha2 project document: {}", path.display())),
        LEGACY_PROJECT_SCHEMA_VERSION => {
            let legacy: LegacyProjectV0Alpha1 =
                serde_json::from_value(value).with_context(|| {
                    format!("invalid v0alpha1 project document: {}", path.display())
                })?;
            Ok(migrate_v0alpha1(&legacy))
        }
        version => bail!("unsupported project schema version: {version}"),
    }
}

fn read_legacy_project(path: &Path) -> Result<LegacyProjectV0Alpha1> {
    let value: Value = read_document(path, MAX_CONFIG_BYTES)?;
    match project_schema_version(&value)? {
        LEGACY_PROJECT_SCHEMA_VERSION => serde_json::from_value(value)
            .with_context(|| format!("invalid v0alpha1 project document: {}", path.display())),
        PROJECT_SCHEMA_VERSION => bail!("project is already at {PROJECT_SCHEMA_VERSION}"),
        version => bail!("unsupported project schema version: {version}"),
    }
}

fn project_schema_version(value: &Value) -> Result<&str> {
    value
        .get("schemaVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("project document is missing string schemaVersion"))
}

fn read_evidence_log(path: &Path) -> Result<Vec<EvidenceRecord>> {
    enforce_size(path, MAX_EVIDENCE_BYTES)?;
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("could not read {} line {}", path.display(), index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str(&line).with_context(|| {
            format!(
                "invalid evidence JSON in {} line {}",
                path.display(),
                index + 1
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

fn read_document<T>(path: &Path, max_bytes: u64) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    enforce_size(path, max_bytes)?;
    let bytes = fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("yaml" | "yml") => serde_yaml::from_slice(&bytes)
            .with_context(|| format!("invalid YAML document: {}", path.display())),
        Some("json") => serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid JSON document: {}", path.display())),
        _ => Err(anyhow!(
            "unsupported document extension for {}; use .json, .yaml, or .yml",
            path.display()
        )),
    }
}

fn write_document_new<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    let bytes = match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("yaml" | "yml") => serde_yaml::to_string(value)
            .context("could not serialize migration output as YAML")?
            .into_bytes(),
        Some("json") => serde_json::to_vec_pretty(value)
            .context("could not serialize migration output as JSON")?,
        _ => bail!(
            "unsupported output document extension for {}; use .json, .yaml, or .yml",
            path.display()
        ),
    };
    let mut output = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("could not create migration output {}", path.display()))?;
    output
        .write_all(&bytes)
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.sync_all())
        .with_context(|| format!("could not write migration output {}", path.display()))
}

fn enforce_size(path: &Path, max_bytes: u64) -> Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("could not inspect {}", path.display()))?;
    if !metadata.is_file() {
        bail!("path is not a regular file: {}", path.display());
    }
    if metadata.len() > max_bytes {
        bail!(
            "{} is {} bytes; maximum accepted size is {} bytes",
            path.display(),
            metadata.len(),
            max_bytes
        );
    }
    Ok(())
}

fn write_json(value: &impl Serialize) -> Result<()> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, value)?;
    lock.write_all(b"\n")?;
    Ok(())
}

fn emit_error(error: &anyhow::Error) {
    let envelope = if let Some(error) = error.downcast_ref::<AiwError>() {
        ErrorEnvelope {
            code: &error.code,
            summary: &error.summary,
            stage: &error.stage,
            run_id: error.run_id.as_deref(),
            retryable: error.retryable,
            remediation: &error.remediation,
            detail: "See the persisted run state for bounded diagnostics.",
        }
    } else {
        ErrorEnvelope {
            code: "AIW_CLI_FAILED",
            summary: "command could not be completed",
            stage: "cli",
            run_id: None,
            retryable: false,
            remediation: "Correct the supplied input or persisted state and retry.",
            detail: "The command failed before completion; sensitive input is not included.",
        }
    };
    let stderr = io::stderr();
    let mut lock = stderr.lock();
    let _ = serde_json::to_writer(&mut lock, &envelope);
    let _ = lock.write_all(b"\n");
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    fn example_path(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("examples")
            .join(name)
    }

    fn temp_output(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "aiw-cli-test-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn current_example_validates() {
        let project = read_project(&example_path("minimal.aiw.yaml")).unwrap();
        assert!(validate_project(&project).is_empty());
    }

    #[test]
    fn legacy_example_is_migrated_in_memory() {
        let project = read_project(&example_path("minimal-v0alpha1.aiw.yaml")).unwrap();
        assert_eq!(project.schema_version, PROJECT_SCHEMA_VERSION);
    }

    #[test]
    fn migration_output_is_create_new_only() {
        let output = temp_output("project.yaml");
        let project = read_project(&example_path("minimal.aiw.yaml")).unwrap();
        write_document_new(&output, &project).unwrap();
        assert!(write_document_new(&output, &project).is_err());
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn recovery_status_is_serializable_without_orchestrator_schema_support() {
        let status = serialize_recovery_status(RecoveryStatus::PendingApproval {
            plan_hash: "a".repeat(64),
            last_sequence: 1,
        });
        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["status"], "pendingApproval");
    }
}
