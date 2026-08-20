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
use aiw_probe::probe_host;
use aiw_provider_mxc::{MxcGoldenProbePlan, plan_capability_probe, plan_golden_probe};
use aiw_provider_wsb::{
    WindowsSandboxCliLifecyclePlan, WindowsSandboxCompletionExpectation,
    WindowsSandboxCompletionReceipt, WindowsSandboxCompletionVerification, WindowsSandboxPlan,
    plan_cli_lifecycle, render_config, validate_host_mappings, verify_completion_receipt,
};
use aiw_schema::{ModelPack, Project, ValidationIssue, validate_model_pack, validate_project};
use aiw_token::{TokenEvidence, collect_current_process_token};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use schemars::schema_for;
use serde::Serialize;

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
    Probe(ProbeArgs),
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

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Project(args) => match args.command {
            ProjectCommand::Validate { path } => {
                let project: Project = read_document(&path, MAX_CONFIG_BYTES)?;
                emit_validation(validate_project(&project))
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
