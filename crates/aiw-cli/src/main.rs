#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

use aiw_core::{
    AnalystReport, AnalystReportValidation, CanaryObservationSet, CanaryPlan, CanaryReport,
    RunSummary, compare_runs, evaluate_canaries, validate_analyst_report,
};
use aiw_evidence::{
    AssessmentBundleManifest, AssessmentBundleSpec, BundleVerification, EvidenceRecord,
    build_assessment_bundle, verify_assessment_bundle, verify_records,
};
use aiw_orchestrator::{
    AiwError, ApprovalRecord, CancellationRequest, LegacyRunPlanV0Alpha1, LegacyRunPlanV0Alpha2,
    RecoveryStatus, RunEvent, RunLayout, RunPlan, RunResult, WsbRevocationRecord,
    project_revision_hash,
};
use aiw_probe::{WindowsSandboxReadiness, WorkspaceBindingEvidence, probe_host};
use aiw_provider_mxc::{MxcGoldenProbePlan, plan_capability_probe, plan_golden_probe};
use aiw_provider_wsb::{
    WindowsSandboxCliLifecyclePlan, WindowsSandboxCompletionExpectation,
    WindowsSandboxCompletionReceipt, WindowsSandboxCompletionVerification, WindowsSandboxPlan,
    plan_cli_lifecycle, render_config, validate_host_mappings, verify_completion_receipt,
};
use aiw_runner::{
    RunnerError, SessionTransaction, WsbGoldenProbeExecution, WsbGoldenProbeStart,
    WsbPlanningImportReceipt, WsbPlanningImportResult, WsbPreparationError, WsbPreparationReceipt,
    WsbRecoveryResult, WsbSessionDisposition, WsbSessionStatus, observe_wsb_session_status,
};
#[cfg(windows)]
use aiw_runner::{
    import_windows_sandbox_preparation, prepare_windows_sandbox_bundle, recover_windows_sandbox,
    verify_windows_sandbox_preparation,
};
use aiw_schema::{
    LEGACY_PROJECT_SCHEMA_VERSION, LegacyProjectV0Alpha1, ModelPack, PROJECT_SCHEMA_VERSION,
    Project, ValidationIssue, migrate_v0alpha1, project_requires_migration_review,
    validate_model_pack, validate_project_for_planning,
};
use aiw_token::{TokenEvidence, collect_current_process_token};
use aiw_windows_platform::assess_windows_sandbox;
use anyhow::{Context, Result, anyhow, bail};
use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand, ValueEnum};
use schemars::{JsonSchema, schema_for};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EVIDENCE_LINE_BYTES: usize = 4 * 1024 * 1024;
const MAX_STAGING_ATTEMPTS: u64 = 32;
static NEXT_STAGING_FILE: AtomicU64 = AtomicU64::new(1);

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
    /// Validate planning readiness. Findings are returned in one JSON result with valid=false.
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
    /// Validate a model pack. Findings are returned in one JSON result with valid=false.
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
    /// Create and verify a fresh Windows Sandbox workspace and approvable plan bundle.
    /// This does not approve, acquire, start, connect, stop, or recover a provider.
    PrepareWsb {
        #[arg(long)]
        run_id: String,
        /// Exact project revision from which the immutable plan is derived.
        #[arg(long)]
        project: PathBuf,
        /// Absolute canonical path to the fixed-function guest agent to stage.
        #[arg(long)]
        guest_agent: PathBuf,
        /// Independently obtained lowercase SHA-256 expected for the guest agent.
        #[arg(long)]
        guest_agent_sha256: String,
        /// Existing absolute canonical local directory that will hold the protected workspace.
        #[arg(long)]
        workspace_parent: PathBuf,
        #[arg(long)]
        created_at: String,
    },
    /// Reopen and verify a preparation after its creating process exited.
    /// This observes readiness but never acquires or mutates the provider.
    VerifyPreparedWsb {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        project: PathBuf,
        /// Independently obtained lowercase SHA-256 expected for the guest agent.
        #[arg(long)]
        guest_agent_sha256: String,
    },
    /// Atomically publish a verified preparation as an authoritative pending-approval run.
    /// This does not approve, acquire, start, connect, stop, or recover a provider.
    ImportPreparedWsb {
        /// Exact protected workspace returned by `run prepare-wsb`.
        #[arg(long)]
        workspace: PathBuf,
        /// Project revision used to create the preparation.
        #[arg(long)]
        project: PathBuf,
        /// Independently obtained lowercase SHA-256 expected for the guest agent.
        #[arg(long)]
        guest_agent_sha256: String,
        /// Operator-supplied import timestamp; reuse the exact value for an idempotent retry.
        #[arg(long)]
        imported_at: String,
    },
    /// Persist a supplied immutable plan and create its run journal. This does not execute it.
    Plan {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        /// Exact project revision the supplied plan is derived from.
        #[arg(long)]
        project: PathBuf,
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
    /// Start only an already-approved, hash-bound Windows Sandbox golden probe.
    /// No arbitrary command, script, policy fragment, or provider verb is accepted.
    Start {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        run_id: String,
        /// Exact validated project revision. It is rehashed immediately before start.
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        wsb_plan: PathBuf,
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
    /// Current project schema. Retained as the stable alias for project-v0alpha2.
    Project,
    #[value(name = "project-v0alpha1")]
    ProjectV0Alpha1,
    #[value(name = "project-v0alpha2")]
    ProjectV0Alpha2,
    RunPlan,
    #[value(name = "run-plan-v0alpha1")]
    RunPlanV0Alpha1,
    #[value(name = "run-plan-v0alpha2")]
    RunPlanV0Alpha2,
    #[value(name = "run-plan-v0alpha3")]
    RunPlanV0Alpha3,
    ApprovalRecord,
    RunEvent,
    RunResult,
    CancellationRequest,
    RecoveryStatus,
    RunStatus,
    ErrorEnvelope,
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
    WindowsSandboxReadiness,
    WorkspaceBindingEvidence,
    WsbGoldenProbeStart,
    WsbGoldenProbeExecution,
    WsbSessionTransaction,
    WsbSessionStatus,
    WsbPreparationReceipt,
    WsbPreparationResult,
    WsbPlanningImportReceipt,
    WsbPlanningImportResult,
    WsbRevocationRecord,
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
struct ProjectValidationResult {
    valid: bool,
    source_schema_version: String,
    effective_schema_version: &'static str,
    migration_review: MigrationReviewStatus,
    project_revision_hash: String,
    issues: Vec<ValidationIssue>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
enum MigrationReviewStatus {
    NotRequired,
    Pending,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectMigrationResult {
    output: PathBuf,
    source_schema_version: &'static str,
    target_schema_version: &'static str,
    migration_review: MigrationReviewStatus,
    project_revision_hash: String,
    planning_valid: bool,
    planning_issues: Vec<ValidationIssue>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEnvelope {
    code: String,
    summary: String,
    stage: String,
    run_id: Option<String>,
    retryable: bool,
    remediation: String,
    detail: String,
}

const RUN_STATUS_SCHEMA_VERSION: &str = "aiw.dev/run-status/v0alpha1";
const RUN_RECOVERY_SCHEMA_VERSION: &str = "aiw.dev/run-recovery/v0alpha1";
const WSB_PREPARATION_RESULT_SCHEMA_VERSION: &str = "aiw.dev/wsb-preparation-result/v0alpha1";

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WsbPreparationResult {
    schema_version: String,
    run_id: String,
    status: aiw_runner::WsbPreparationStatus,
    workspace_root: String,
    run_plan_path: String,
    windows_sandbox_plan_path: String,
    preparation_receipt_path: String,
    receipt: WsbPreparationReceipt,
}

fn preparation_result(prepared: aiw_runner::PreparedWsbArtifacts) -> WsbPreparationResult {
    let workspace_root = prepared.receipt.workspace.root.final_path.clone();
    WsbPreparationResult {
        schema_version: WSB_PREPARATION_RESULT_SCHEMA_VERSION.to_owned(),
        run_id: prepared.receipt.run_id.clone(),
        status: prepared.receipt.status,
        run_plan_path: format!(r"{}\plan.json", workspace_root),
        windows_sandbox_plan_path: format!(r"{}\wsb-plan.json", workspace_root),
        preparation_receipt_path: format!(r"{}\preparation.json", workspace_root),
        workspace_root,
        receipt: prepared.receipt,
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RunStatusEnvelope {
    schema_version: String,
    run_id: String,
    core: RecoveryStatus,
    windows_sandbox: WsbSessionStatus,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RunRecoveryEnvelope {
    schema_version: String,
    run_id: String,
    core: RecoveryStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    windows_sandbox: Option<WsbRecoveryResult>,
}

#[derive(Debug)]
struct RunOperationUnavailable {
    code: &'static str,
    summary: &'static str,
    stage: &'static str,
    remediation: &'static str,
    detail: &'static str,
    run_id: String,
}

impl std::fmt::Display for RunOperationUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.summary)
    }
}

impl std::error::Error for RunOperationUnavailable {}

#[derive(Debug)]
struct RunRecoveryFailed {
    run_id: String,
    source: RunnerError,
}

impl std::fmt::Display for RunRecoveryFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for RunRecoveryFailed {}

#[derive(Debug)]
struct RunPreparationFailed {
    run_id: String,
    source: WsbPreparationError,
}

impl std::fmt::Display for RunPreparationFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for RunPreparationFailed {}

#[derive(Debug)]
struct RunPreparationImportFailed {
    run_id: String,
    source: WsbPreparationError,
}

impl std::fmt::Display for RunPreparationImportFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for RunPreparationImportFailed {}

#[derive(Debug)]
struct WsbSessionStatusInvalid {
    run_id: String,
    detail: String,
}

impl std::fmt::Display for WsbSessionStatusInvalid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("persisted Windows Sandbox session status is invalid")
    }
}

impl std::error::Error for WsbSessionStatusInvalid {}

#[derive(Debug)]
struct LoadedProject {
    source_schema_version: String,
    project: Project,
}

fn main() -> ExitCode {
    let command = match Cli::try_parse() {
        Ok(cli) => cli.command,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            emit_error(&clap_error_envelope());
            return ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(1));
        }
    };

    match run(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            emit_anyhow_error(&error);
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Project(args) => match args.command {
            ProjectCommand::Validate { path } => {
                let loaded = read_project(&path)?;
                let issues = validate_project_for_planning(&loaded.project);
                write_json(&ProjectValidationResult {
                    valid: issues.is_empty(),
                    source_schema_version: loaded.source_schema_version,
                    effective_schema_version: PROJECT_SCHEMA_VERSION,
                    migration_review: migration_review_status(&loaded.project),
                    project_revision_hash: project_revision_hash(&loaded.project)?,
                    issues,
                })
            }
            ProjectCommand::Migrate { path, output } => {
                let legacy = read_legacy_project(&path)?;
                let project = migrate_v0alpha1(&legacy);
                write_document_new(&output, &project)?;
                let planning_issues = validate_project_for_planning(&project);
                write_json(&ProjectMigrationResult {
                    output,
                    source_schema_version: LEGACY_PROJECT_SCHEMA_VERSION,
                    target_schema_version: PROJECT_SCHEMA_VERSION,
                    migration_review: migration_review_status(&project),
                    project_revision_hash: project_revision_hash(&project)?,
                    planning_valid: planning_issues.is_empty(),
                    planning_issues,
                })
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
            HostCommand::Assess => write_json(&assess_windows_sandbox()),
        },
        Command::Run(args) => match args.command {
            RunCommand::PrepareWsb {
                run_id,
                project,
                guest_agent,
                guest_agent_sha256,
                workspace_parent,
                created_at,
            } => {
                let loaded = read_project(&project)?;
                #[cfg(windows)]
                {
                    let prepared = prepare_windows_sandbox_bundle(
                        &run_id,
                        &loaded.project,
                        &guest_agent,
                        &guest_agent_sha256,
                        &workspace_parent,
                        &run_id,
                        &created_at,
                    )
                    .map_err(|source| {
                        anyhow!(RunPreparationFailed {
                            run_id: run_id.clone(),
                            source,
                        })
                    })?;
                    write_json(&preparation_result(prepared))
                }
                #[cfg(not(windows))]
                {
                    let _ = (
                        loaded,
                        guest_agent,
                        guest_agent_sha256,
                        workspace_parent,
                        created_at,
                    );
                    Err(anyhow!(RunOperationUnavailable {
                        code: "AIW_WINDOWS_REQUIRED",
                        summary: "Windows Sandbox preparation requires Windows",
                        stage: "wsbPreparation",
                        remediation: "Run preparation on a supported Windows host after completing the non-mutating readiness assessment.",
                        detail: "No workspace was created and no provider was acquired.",
                        run_id,
                    }))
                }
            }
            RunCommand::VerifyPreparedWsb {
                workspace,
                project,
                guest_agent_sha256,
            } => {
                let loaded = read_project(&project)?;
                let fallback_run_id = workspace
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("unknown")
                    .to_owned();
                #[cfg(windows)]
                {
                    let prepared = verify_windows_sandbox_preparation(
                        &workspace,
                        &loaded.project,
                        &guest_agent_sha256,
                    )
                    .map_err(|source| {
                        anyhow!(RunPreparationFailed {
                            run_id: fallback_run_id,
                            source,
                        })
                    })?;
                    write_json(&preparation_result(prepared))
                }
                #[cfg(not(windows))]
                {
                    let _ = (loaded, guest_agent_sha256);
                    Err(anyhow!(RunOperationUnavailable {
                        code: "AIW_WINDOWS_REQUIRED",
                        summary: "Windows Sandbox preparation verification requires Windows",
                        stage: "wsbPreparation",
                        remediation: "Verify this workspace on its original supported Windows host.",
                        detail: "No provider was acquired and no workspace state was changed.",
                        run_id: fallback_run_id,
                    }))
                }
            }
            RunCommand::ImportPreparedWsb {
                workspace,
                project,
                guest_agent_sha256,
                imported_at,
            } => {
                let loaded = read_project(&project)?;
                let fallback_run_id = workspace
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("unknown")
                    .to_owned();
                #[cfg(windows)]
                {
                    let result = import_windows_sandbox_preparation(
                        &workspace,
                        &loaded.project,
                        &guest_agent_sha256,
                        &imported_at,
                    )
                    .map_err(|source| {
                        anyhow!(RunPreparationImportFailed {
                            run_id: fallback_run_id,
                            source,
                        })
                    })?;
                    write_json(&result)
                }
                #[cfg(not(windows))]
                {
                    let _ = (loaded, guest_agent_sha256, imported_at);
                    Err(anyhow!(RunOperationUnavailable {
                        code: "AIW_WINDOWS_REQUIRED",
                        summary: "Windows Sandbox preparation import requires Windows",
                        stage: "wsbPreparationImport",
                        remediation: "Import this verified workspace on its original supported Windows host.",
                        detail: "No run state was created and no provider was acquired.",
                        run_id: fallback_run_id,
                    }))
                }
            }
            RunCommand::Plan {
                root,
                plan,
                project,
            } => {
                let plan = RunPlan::from_value(read_document(&plan, MAX_CONFIG_BYTES)?)?;
                let loaded = read_project(&project)?;
                let issues = validate_project_for_planning(&loaded.project);
                if !issues.is_empty() {
                    bail!("project is not ready for planning");
                }
                let expected_id = &loaded.project.metadata.name;
                let expected_hash = project_revision_hash(&loaded.project)?;
                if plan.project_id != *expected_id || plan.project_revision_hash != expected_hash {
                    bail!("run plan does not match the validated project revision");
                }
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
            RunCommand::Status { root, run_id } => {
                let layout = RunLayout::new(&root, run_id)?;
                let core = layout.status()?;
                let windows_sandbox = observe_wsb_status(&layout)?;
                write_json(&RunStatusEnvelope {
                    schema_version: RUN_STATUS_SCHEMA_VERSION.to_owned(),
                    run_id: layout.run_id().to_owned(),
                    core,
                    windows_sandbox,
                })
            }
            RunCommand::Recover { root, run_id } => {
                let layout = RunLayout::new(&root, run_id)?;
                let core = layout.recovery_status()?;
                let provider_status = observe_wsb_status(&layout)?;
                if matches!(
                    provider_status.status,
                    WsbSessionDisposition::RecoveryRequired | WsbSessionDisposition::Clean
                ) {
                    #[cfg(windows)]
                    {
                        let windows_sandbox =
                            recover_windows_sandbox(&layout).map_err(|source| {
                                anyhow!(RunRecoveryFailed {
                                    run_id: layout.run_id().to_owned(),
                                    source,
                                })
                            })?;
                        return write_json(&RunRecoveryEnvelope {
                            schema_version: RUN_RECOVERY_SCHEMA_VERSION.to_owned(),
                            run_id: layout.run_id().to_owned(),
                            core,
                            windows_sandbox: Some(windows_sandbox),
                        });
                    }
                    #[cfg(not(windows))]
                    {
                        return Err(anyhow!(RunOperationUnavailable {
                            code: "AIW_WINDOWS_REQUIRED",
                            summary: "Windows Sandbox recovery requires Windows",
                            stage: "wsbRecovery",
                            remediation: "Recover this exact run on its original supported Windows host; do not modify provider or transaction state manually.",
                            detail: "The persisted run was not changed.",
                            run_id: layout.run_id().to_owned(),
                        }));
                    }
                }
                write_json(&RunRecoveryEnvelope {
                    schema_version: RUN_RECOVERY_SCHEMA_VERSION.to_owned(),
                    run_id: layout.run_id().to_owned(),
                    core,
                    windows_sandbox: None,
                })
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
            RunCommand::Start {
                root,
                run_id,
                project,
                wsb_plan,
            } => {
                let _ = (root, project, wsb_plan);
                Err(anyhow!(RunOperationUnavailable {
                    code: "AIW_WSB_EXECUTION_UNAVAILABLE",
                    summary: "trusted native Windows Sandbox verification and process execution are unavailable",
                    stage: "wsbRunner",
                    remediation: "Wait for the native Windows Sandbox execution boundary to be implemented; do not bypass provider cleanup state.",
                    detail: "Production Windows Sandbox execution remains fail-closed.",
                    run_id,
                }))
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
            SchemaKind::Project | SchemaKind::ProjectV0Alpha2 => write_json(&schema_for!(Project)),
            SchemaKind::ProjectV0Alpha1 => write_json(&schema_for!(LegacyProjectV0Alpha1)),
            SchemaKind::RunPlan | SchemaKind::RunPlanV0Alpha3 => write_json(&schema_for!(RunPlan)),
            SchemaKind::RunPlanV0Alpha1 => write_json(&schema_for!(LegacyRunPlanV0Alpha1)),
            SchemaKind::RunPlanV0Alpha2 => write_json(&schema_for!(LegacyRunPlanV0Alpha2)),
            SchemaKind::ApprovalRecord => write_json(&schema_for!(ApprovalRecord)),
            SchemaKind::RunEvent => write_json(&schema_for!(RunEvent)),
            SchemaKind::RunResult => write_json(&schema_for!(RunResult)),
            SchemaKind::CancellationRequest => write_json(&schema_for!(CancellationRequest)),
            SchemaKind::RecoveryStatus => write_json(&schema_for!(RecoveryStatus)),
            SchemaKind::RunStatus => write_json(&schema_for!(RunStatusEnvelope)),
            SchemaKind::ErrorEnvelope => write_json(&schema_for!(AiwError)),
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
            SchemaKind::WindowsSandboxReadiness => {
                write_json(&schema_for!(WindowsSandboxReadiness))
            }
            SchemaKind::WorkspaceBindingEvidence => {
                write_json(&schema_for!(WorkspaceBindingEvidence))
            }
            SchemaKind::WsbGoldenProbeStart => write_json(&schema_for!(WsbGoldenProbeStart)),
            SchemaKind::WsbGoldenProbeExecution => {
                write_json(&schema_for!(WsbGoldenProbeExecution))
            }
            SchemaKind::WsbSessionTransaction => write_json(&schema_for!(SessionTransaction)),
            SchemaKind::WsbSessionStatus => write_json(&schema_for!(WsbSessionStatus)),
            SchemaKind::WsbPreparationReceipt => write_json(&schema_for!(WsbPreparationReceipt)),
            SchemaKind::WsbPreparationResult => write_json(&schema_for!(WsbPreparationResult)),
            SchemaKind::WsbPlanningImportReceipt => {
                write_json(&schema_for!(WsbPlanningImportReceipt))
            }
            SchemaKind::WsbPlanningImportResult => {
                write_json(&schema_for!(WsbPlanningImportResult))
            }
            SchemaKind::WsbRevocationRecord => write_json(&schema_for!(WsbRevocationRecord)),
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
    write_json(&ValidationResult { valid, issues })
}

fn migration_review_status(project: &Project) -> MigrationReviewStatus {
    if project_requires_migration_review(project) {
        MigrationReviewStatus::Pending
    } else {
        MigrationReviewStatus::NotRequired
    }
}

fn read_project(path: &Path) -> Result<LoadedProject> {
    let value: Value = read_document(path, MAX_CONFIG_BYTES)?;
    let source_schema_version = project_schema_version(&value)?.to_owned();
    let project = match source_schema_version.as_str() {
        PROJECT_SCHEMA_VERSION => serde_json::from_value(value)
            .with_context(|| format!("invalid v0alpha2 project document: {}", path.display()))?,
        LEGACY_PROJECT_SCHEMA_VERSION => {
            let legacy: LegacyProjectV0Alpha1 =
                serde_json::from_value(value).with_context(|| {
                    format!("invalid v0alpha1 project document: {}", path.display())
                })?;
            migrate_v0alpha1(&legacy)
        }
        version => bail!("unsupported project schema version: {version}"),
    };
    Ok(LoadedProject {
        source_schema_version,
        project,
    })
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
    let bytes = read_file_bounded(path, MAX_EVIDENCE_BYTES)?;
    let mut records = Vec::new();
    for (index, raw_line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.len() > MAX_EVIDENCE_LINE_BYTES {
            bail!(
                "{} line {} is {} bytes; maximum accepted line size is {} bytes",
                path.display(),
                index + 1,
                line.len(),
                MAX_EVIDENCE_LINE_BYTES
            );
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value = parse_unique_value(line, DocumentFormat::Json).with_context(|| {
            format!(
                "invalid evidence JSON in {} line {}",
                path.display(),
                index + 1
            )
        })?;
        let record = serde_json::from_value(value).with_context(|| {
            format!(
                "invalid evidence record in {} line {}",
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
    let format = document_format(path)?;
    let bytes = read_file_bounded(path, max_bytes)?;
    let value = parse_unique_value(&bytes, format)
        .with_context(|| format!("invalid {} document: {}", format.name(), path.display()))?;
    serde_json::from_value(value)
        .with_context(|| format!("invalid {} document: {}", format.name(), path.display()))
}

#[derive(Clone, Copy, Debug)]
enum DocumentFormat {
    Json,
    Yaml,
}

impl DocumentFormat {
    fn name(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Yaml => "YAML",
        }
    }
}

fn document_format(path: &Path) -> Result<DocumentFormat> {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => Ok(DocumentFormat::Json),
        Some("yaml" | "yml") => Ok(DocumentFormat::Yaml),
        _ => bail!(
            "unsupported document extension for {}; use .json, .yaml, or .yml",
            path.display()
        ),
    }
}

fn parse_unique_value(bytes: &[u8], format: DocumentFormat) -> Result<Value> {
    match format {
        DocumentFormat::Json => {
            let mut deserializer = serde_json::Deserializer::from_slice(bytes);
            let value = UniqueValue::deserialize(&mut deserializer)?.0;
            deserializer.end()?;
            Ok(value)
        }
        DocumentFormat::Yaml => {
            let value: UniqueValue = serde_yaml::from_slice(bytes)?;
            Ok(value.0)
        }
    }
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON-compatible value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite numbers are not supported"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UniqueValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object key: {key}"
                )));
            }
            let value = object.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

fn write_document_new<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    let format = document_format(path)?;
    let mut bytes = match format {
        DocumentFormat::Yaml => serde_yaml::to_string(value)
            .context("could not serialize migration output as YAML")?
            .into_bytes(),
        DocumentFormat::Json => serde_json::to_vec_pretty(value)
            .context("could not serialize migration output as JSON")?,
    };
    bytes.push(b'\n');
    publish_bytes_new(path, &bytes)
}

fn publish_bytes_new(path: &Path, bytes: &[u8]) -> Result<()> {
    publish_bytes_new_with(path, bytes, |_| Ok(()))
}

fn publish_bytes_new_with(
    path: &Path,
    bytes: &[u8],
    before_publish: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    if path.exists() {
        bail!("migration output already exists: {}", path.display());
    }

    let (staging_path, mut output) = create_staging_file(path)?;
    let staging = StagingFile::new(staging_path);
    output
        .write_all(bytes)
        .and_then(|_| output.sync_all())
        .with_context(|| format!("could not stage migration output {}", path.display()))?;
    drop(output);

    before_publish(path)?;
    publish_staged_new(staging.path(), path)
        .with_context(|| format!("could not publish migration output {}", path.display()))?;
    Ok(())
}

fn create_staging_file(path: &Path) -> Result<(PathBuf, File)> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow!(
                "migration output must have a valid file name: {}",
                path.display()
            )
        })?;

    for _ in 0..MAX_STAGING_ATTEMPTS {
        let sequence = NEXT_STAGING_FILE.fetch_add(1, Ordering::Relaxed);
        let staging_path = parent.join(format!(
            ".{file_name}.aiw-stage-{}-{sequence}",
            std::process::id()
        ));
        match File::options()
            .write(true)
            .create_new(true)
            .open(&staging_path)
        {
            Ok(file) => return Ok((staging_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "could not create migration staging file in {}",
                        parent.display()
                    )
                });
            }
        }
    }
    bail!(
        "could not allocate a unique migration staging file in {}",
        parent.display()
    )
}

fn publish_staged_new(staging_path: &Path, output_path: &Path) -> io::Result<()> {
    fs::hard_link(staging_path, output_path)
}

struct StagingFile {
    path: PathBuf,
}

impl StagingFile {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn read_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    read_file_bounded_with(path, max_bytes, || Ok(()))
}

fn read_file_bounded_with(
    path: &Path,
    max_bytes: u64,
    after_open: impl FnOnce() -> Result<()>,
) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if !metadata.is_file() {
        bail!("path is not a regular file: {}", path.display());
    }
    after_open()?;
    read_bounded(file, max_bytes, path)
}

fn read_bounded(reader: impl Read, max_bytes: u64, path: &Path) -> Result<Vec<u8>> {
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow!("maximum input size is too large"))?;
    let initial_capacity = usize::try_from(max_bytes.min(1024 * 1024)).unwrap_or(1024 * 1024);
    let mut bytes = Vec::with_capacity(initial_capacity);
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        bail!(
            "{} exceeds the maximum accepted size of {} bytes",
            path.display(),
            max_bytes
        );
    }
    Ok(bytes)
}

fn write_json(value: &impl Serialize) -> Result<()> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, value)?;
    lock.write_all(b"\n")?;
    Ok(())
}

fn clap_error_envelope() -> ErrorEnvelope {
    ErrorEnvelope {
        code: "AIW_CLI_ARGUMENT_INVALID".to_owned(),
        summary: "command-line arguments are invalid".to_owned(),
        stage: "cliParse".to_owned(),
        run_id: None,
        retryable: false,
        remediation: "Use --help and provide the required supported arguments.".to_owned(),
        detail: "Argument values are omitted from diagnostics.".to_owned(),
    }
}

fn generic_error_envelope() -> ErrorEnvelope {
    ErrorEnvelope {
        code: "AIW_CLI_FAILED".to_owned(),
        summary: "command could not be completed".to_owned(),
        stage: "cli".to_owned(),
        run_id: None,
        retryable: false,
        remediation: "Correct the supplied input or persisted state and retry.".to_owned(),
        detail: "The command failed before completion; sensitive input is not included.".to_owned(),
    }
}

fn observe_wsb_status(layout: &RunLayout) -> Result<WsbSessionStatus> {
    observe_wsb_session_status(layout).map_err(|error| {
        anyhow!(WsbSessionStatusInvalid {
            run_id: layout.run_id().to_owned(),
            detail: error.to_string().chars().take(512).collect(),
        })
    })
}

fn preparation_error_envelope(error: &RunPreparationFailed) -> ErrorEnvelope {
    let (code, summary, stage, remediation) = match &error.source {
        WsbPreparationError::Project(_) => (
            "AIW_WSB_PREPARATION_PROJECT_INVALID",
            "project is not valid for Windows Sandbox preparation",
            "wsbPreparationPreflight",
            "Correct the project validation findings and retry before creating a workspace.",
        ),
        WsbPreparationError::Readiness(_) => (
            "AIW_WSB_PREPARATION_READINESS_BLOCKED",
            "Windows Sandbox readiness blocks preparation",
            "wsbPreparationPreflight",
            "Resolve the reported readiness or active-session blocker and rerun the non-mutating host assessment.",
        ),
        WsbPreparationError::Workspace(_) => (
            "AIW_WSB_PREPARATION_WORKSPACE_REJECTED",
            "protected Windows Sandbox workspace could not be created",
            "wsbWorkspace",
            "Use a canonical existing local fixed-volume parent and a fresh run ID; never adopt or repair an existing leaf.",
        ),
        WsbPreparationError::GuestAgent(_) => (
            "AIW_WSB_PREPARATION_GUEST_AGENT_REJECTED",
            "fixed-function guest agent could not be staged",
            "guestAgentStaging",
            "Supply the canonical ordinary file and its independently obtained lowercase SHA-256; use a fresh run ID if a workspace was created.",
        ),
        WsbPreparationError::Contract(_) => (
            "AIW_WSB_PREPARATION_CONTRACT_INVALID",
            "Windows Sandbox preparation contract is invalid",
            "wsbPreparationPlan",
            "Correct the bounded run metadata or contract drift before retrying.",
        ),
        WsbPreparationError::Persistence(_) => (
            "AIW_WSB_PREPARATION_PUBLISH_FAILED",
            "Windows Sandbox preparation artifacts could not be published",
            "wsbPreparationPublish",
            "Preserve the incomplete workspace for inspection; do not treat it as complete without a valid final receipt.",
        ),
        WsbPreparationError::WorkspacePreserved { .. } => (
            "AIW_WSB_PREPARATION_INCOMPLETE",
            "Windows Sandbox preparation stopped and preserved its fresh workspace",
            "wsbPreparation",
            "Preserve and inspect the exact reported workspace. Never adopt, repair, or blindly delete it; retry with a new run ID after correcting the cause.",
        ),
    };
    ErrorEnvelope {
        code: code.to_owned(),
        summary: summary.to_owned(),
        stage: stage.to_owned(),
        run_id: Some(error.run_id.clone()),
        retryable: false,
        remediation: remediation.to_owned(),
        detail: error.source.to_string().chars().take(512).collect(),
    }
}

fn preparation_import_error_envelope(error: &RunPreparationImportFailed) -> ErrorEnvelope {
    ErrorEnvelope {
        code: "AIW_WSB_PREPARATION_IMPORT_REJECTED".to_owned(),
        summary: "verified Windows Sandbox preparation could not be imported".to_owned(),
        stage: "wsbPreparationImport".to_owned(),
        run_id: Some(error.run_id.clone()),
        retryable: false,
        remediation: "Preserve the preparation and authoritative run artifacts; inspect the exact reported drift or conflict before retrying.".to_owned(),
        detail: error.source.to_string().chars().take(512).collect(),
    }
}

fn emit_anyhow_error(error: &anyhow::Error) {
    if let Some(error) = error.downcast_ref::<AiwError>() {
        emit_error(error);
    } else if let Some(error) = error.downcast_ref::<RunOperationUnavailable>() {
        emit_error(&ErrorEnvelope {
            code: error.code.to_owned(),
            summary: error.summary.to_owned(),
            stage: error.stage.to_owned(),
            run_id: Some(error.run_id.clone()),
            retryable: false,
            remediation: error.remediation.to_owned(),
            detail: error.detail.to_owned(),
        });
    } else if let Some(error) = error.downcast_ref::<WsbSessionStatusInvalid>() {
        emit_error(&ErrorEnvelope {
            code: "AIW_WSB_SESSION_STATUS_INVALID".to_owned(),
            summary: "persisted Windows Sandbox session status could not be validated".to_owned(),
            stage: "wsbSessionStatus".to_owned(),
            run_id: Some(error.run_id.clone()),
            retryable: false,
            remediation: "Do not start or recover the provider. Inspect or restore the run-bound session transaction from trusted evidence.".to_owned(),
            detail: error.detail.clone(),
        });
    } else if let Some(error) = error.downcast_ref::<RunRecoveryFailed>() {
        emit_error(&ErrorEnvelope {
            code: "AIW_WSB_RECOVERY_FAILED".to_owned(),
            summary: "Windows Sandbox recovery could not be safely completed".to_owned(),
            stage: "wsbRecovery".to_owned(),
            run_id: Some(error.run_id.clone()),
            retryable: matches!(
                error.source,
                RunnerError::LeaseUnavailable | RunnerError::RecoveryRequired(_)
            ),
            remediation: "Preserve the run directory and provider state, resolve the reported authority or drift condition, and retry the same run recovery command.".to_owned(),
            detail: error.source.to_string().chars().take(512).collect(),
        });
    } else if let Some(error) = error.downcast_ref::<RunPreparationFailed>() {
        emit_error(&preparation_error_envelope(error));
    } else if let Some(error) = error.downcast_ref::<RunPreparationImportFailed>() {
        emit_error(&preparation_import_error_envelope(error));
    } else if let Some(error) = error.downcast_ref::<RunnerError>() {
        emit_error(&ErrorEnvelope {
            code: "AIW_WSB_RUNNER_FAILED".to_owned(),
            summary: "Windows Sandbox golden-probe run was not completed".to_owned(),
            stage: "wsbRunner".to_owned(),
            run_id: None,
            retryable: false,
            remediation: "Inspect readiness, the approved plan, provider state, and run journal before retrying.".to_owned(),
            detail: error.to_string().chars().take(512).collect(),
        });
    } else {
        emit_error(&generic_error_envelope());
    }
}

fn emit_error(envelope: &impl Serialize) {
    let stderr = io::stderr();
    let mut lock = stderr.lock();
    let _ = serde_json::to_writer(&mut lock, envelope);
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
        let loaded = read_project(&example_path("minimal.aiw.yaml")).unwrap();
        assert_eq!(loaded.source_schema_version, PROJECT_SCHEMA_VERSION);
        assert!(validate_project_for_planning(&loaded.project).is_empty());
        assert!(!project_requires_migration_review(&loaded.project));
    }

    #[test]
    fn legacy_example_is_migrated_to_pending_review() {
        let loaded = read_project(&example_path("minimal-v0alpha1.aiw.yaml")).unwrap();
        assert_eq!(loaded.source_schema_version, LEGACY_PROJECT_SCHEMA_VERSION);
        assert_eq!(loaded.project.schema_version, PROJECT_SCHEMA_VERSION);
        assert!(project_requires_migration_review(&loaded.project));
        assert!(
            validate_project_for_planning(&loaded.project)
                .iter()
                .any(|issue| issue.code == "migrationReviewPending")
        );
    }

    #[test]
    fn migration_output_is_create_new_only() {
        let output = temp_output("project.yaml");
        let loaded = read_project(&example_path("minimal.aiw.yaml")).unwrap();
        write_document_new(&output, &loaded.project).unwrap();
        assert!(write_document_new(&output, &loaded.project).is_err());
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn failed_no_replace_publish_cleans_staging_file() {
        let output = temp_output("publish-race.yaml");
        let file_name = output.file_name().unwrap().to_string_lossy();
        let stage_prefix = format!(".{file_name}.aiw-stage-");
        let result = publish_bytes_new_with(&output, b"test\n", |path| {
            fs::write(path, b"competitor")?;
            Ok(())
        });
        assert!(result.is_err());
        let parent = output.parent().unwrap();
        let staging_files = fs::read_dir(parent)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&stage_prefix)
            })
            .count();
        assert_eq!(staging_files, 0);
        assert_eq!(fs::read(&output).unwrap(), b"competitor");
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn unique_json_loader_rejects_duplicate_keys() {
        let error = parse_unique_value(
            br#"{"schemaVersion":"aiw.dev/v0alpha1","schemaVersion":"aiw.dev/v0alpha2"}"#,
            DocumentFormat::Json,
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate object key"));
    }

    #[test]
    fn bounded_reader_checks_actual_bytes_read() {
        let input = io::Cursor::new(vec![0_u8; 9]);
        let error = read_bounded(input, 8, Path::new("growing.json")).unwrap_err();
        assert!(error.to_string().contains("maximum accepted size"));
    }

    #[test]
    fn bounded_file_reader_rejects_growth_after_open() {
        let path = temp_output("growing.json");
        fs::write(&path, vec![0_u8; 8]).unwrap();
        let error = read_file_bounded_with(&path, 8, || {
            let mut writer = File::options().append(true).open(&path)?;
            writer.write_all(&[0])?;
            writer.sync_all()?;
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("maximum accepted size"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn evidence_log_rejects_oversized_individual_line() {
        let path = temp_output("evidence.jsonl");
        fs::write(&path, vec![b'a'; MAX_EVIDENCE_LINE_BYTES + 1]).unwrap();
        let error = read_evidence_log(&path).unwrap_err();
        assert!(error.to_string().contains("maximum accepted line size"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn clap_argument_failure_maps_to_one_safe_envelope() {
        let error = Cli::try_parse_from(["aiw", "run", "status", "--root", "."]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        let envelope = clap_error_envelope();
        assert_eq!(envelope.code, "AIW_CLI_ARGUMENT_INVALID");
        assert!(!envelope.detail.contains("--root"));
    }

    #[test]
    fn orchestrator_recovery_status_is_serializable() {
        let status = RecoveryStatus::PendingApproval {
            plan_hash: "a".repeat(64),
            last_sequence: 1,
        };
        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["status"], "pendingApproval");
    }

    #[test]
    fn preparation_failures_have_stage_specific_stable_envelopes() {
        let cases = [
            (
                WsbPreparationError::Project("detail".to_owned()),
                "AIW_WSB_PREPARATION_PROJECT_INVALID",
                "wsbPreparationPreflight",
            ),
            (
                WsbPreparationError::Readiness("detail".to_owned()),
                "AIW_WSB_PREPARATION_READINESS_BLOCKED",
                "wsbPreparationPreflight",
            ),
            (
                WsbPreparationError::GuestAgent("detail".to_owned()),
                "AIW_WSB_PREPARATION_GUEST_AGENT_REJECTED",
                "guestAgentStaging",
            ),
            (
                WsbPreparationError::Persistence("detail".to_owned()),
                "AIW_WSB_PREPARATION_PUBLISH_FAILED",
                "wsbPreparationPublish",
            ),
            (
                WsbPreparationError::WorkspacePreserved {
                    workspace_path: "C:\\held".to_owned(),
                    detail: "detail".to_owned(),
                },
                "AIW_WSB_PREPARATION_INCOMPLETE",
                "wsbPreparation",
            ),
        ];
        for (source, code, stage) in cases {
            let envelope = preparation_error_envelope(&RunPreparationFailed {
                run_id: "run-one".to_owned(),
                source,
            });
            assert_eq!(envelope.code, code);
            assert_eq!(envelope.stage, stage);
            assert_eq!(envelope.run_id.as_deref(), Some("run-one"));
            assert!(envelope.detail.len() <= 512);
        }
    }
}
