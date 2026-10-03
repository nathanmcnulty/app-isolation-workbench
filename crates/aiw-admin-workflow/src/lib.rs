use std::io::{IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use aiw_orchestrator::{AiwError, ApprovalRecord, RunLayout};
use aiw_probe::{ApplicationInspectionKind, ReadinessState, inspect_application_source};
use aiw_schema::{ApplicationSource, Project, validate_project_for_planning};

mod admin_progress;
pub mod approval_review;

const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

fn read_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        bail!("{} is not a bounded regular file", path.display());
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(max_bytes.min(1024 * 1024)).unwrap_or(1024 * 1024));
    let file = std::fs::File::open(path)?;
    file.take(
        max_bytes
            .checked_add(1)
            .ok_or_else(|| anyhow!("maximum input size is too large"))?,
    )
    .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        bail!("{} exceeds the maximum accepted size", path.display());
    }
    Ok(bytes)
}

fn document_export_error(run_id: &str, source: aiw_runner::RunnerError) -> anyhow::Error {
    let destination = matches!(
        &source,
        aiw_runner::RunnerError::DocumentExportDestination(_)
    );
    anyhow!(AiwError {
        code: if destination { "AIW_WSB_EXPORT_DESTINATION_REJECTED" } else { "AIW_WSB_EXPORT_FAILED" }.into(),
        summary: if destination { "document export destination was refused" } else { "document export did not complete" }.into(),
        stage: "wsbDocumentExport".into(), run_id: Some(run_id.to_owned().into()), retryable: false,
        remediation: if destination { "Choose a new absolute file path in an existing ordinary folder outside the retained workspace. No existing file was overwritten." } else { "Preserve the run and any destination file. Inspect the retained report and exact run status before retrying; do not overwrite an existing export." }.into(),
        detail: source.to_string().chars().take(512).collect::<String>().into(),
    })
}

#[cfg(test)]
fn document_export_output_error(run_id: &str, error: anyhow::Error) -> anyhow::Error {
    anyhow!(AiwError { code: "AIW_WSB_EXPORT_OUTPUT_FAILED".into(), summary: "document exported, but console output failed".into(), stage: "wsbDocumentExport".into(), run_id: Some(run_id.to_owned().into()), retryable: false, remediation: "Preserve the exported file and verify it against the retained report. Do not repeat export because console output failed.".into(), detail: error.to_string().chars().take(512).collect::<String>().into() })
}

pub const MANIFEST_SCHEMA: &str = "aiw.dev/admin-product-assets/v0alpha1";
pub const PRODUCT_ID: &str = "notepad-plus-plus-local-settings";
pub const SCENARIO_ID: &str = "install-launch-close";
pub const INTERACTIVE_PRODUCT_ID: &str = "notepad-plus-plus-interactive";
pub const BAMBU_PRODUCT_ID: &str = "bambu-studio-export";
pub const BAMBU_SCENARIO_ID: &str = "local-file-export";

/// Complete, typed authority disclosure presented before approval or Start.
/// Presentation is advisory; `approve_review` re-reads the persisted plan under
/// the existing `RunLayout` lock before it records approval.
#[derive(Debug, Clone)]
pub struct ApprovalReview {
    pub run_id: String,
    pub workspace: PathBuf,
    pub evidence_root: PathBuf,
    pub recipe: serde_json::Value,
    pub plan: aiw_orchestrator::RunPlan,
    pub proposed_approval: ApprovalRecord,
}

pub trait ApprovalGate {
    /// Return the literal operator response. The service requires exactly
    /// `approve <displayed plan hash>`; `None` is cancellation.
    fn review(&self, review: &ApprovalReview) -> Result<Option<String>>;
    /// A distinct gate after durable approval and before provider acquisition.
    fn wait_for_start(&self, review: &ApprovalReview) -> Result<bool>;
    fn uses_terminal_progress(&self) -> bool {
        false
    }
}

pub struct TerminalApprovalGate;

impl ApprovalGate for TerminalApprovalGate {
    fn review(&self, review: &ApprovalReview) -> Result<Option<String>> {
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            bail!(
                "administrator workflow requires terminal input and visible approval review; no intake or run was created"
            );
        }
        let accepted = approval_review::confirm(
            &review.proposed_approval,
            &review.plan,
            std::io::stdin().lock(),
            std::io::stderr().lock(),
        )?;
        Ok(accepted.then(|| format!("approve {}", review.proposed_approval.plan_hash)))
    }
    fn wait_for_start(&self, _: &ApprovalReview) -> Result<bool> {
        Ok(true)
    }
    fn uses_terminal_progress(&self) -> bool {
        true
    }
}

pub fn approve_review(gate: &dyn ApprovalGate, review: &ApprovalReview) -> Result<bool> {
    let expected = format!("approve {}", review.proposed_approval.plan_hash);
    let Some(response) = gate.review(review)? else {
        return Ok(false);
    };
    if response != expected {
        return Ok(false);
    }
    let layout = RunLayout::new(&review.workspace, &review.run_id)?;
    let current = layout.read_plan()?;
    if current != review.plan {
        bail!("persisted plan changed after review")
    }
    layout.write_approval(&review.proposed_approval)?;
    Ok(true)
}

pub fn wait_for_start(gate: &dyn ApprovalGate, review: &ApprovalReview) -> Result<bool> {
    gate.wait_for_start(review)
}

pub fn public_error(error: anyhow::Error) -> anyhow::Error {
    if error.is::<AiwError>() {
        return error;
    }
    anyhow!(AiwError {
        code: "AIW_ADMIN_WORKFLOW_FAILED".into(),
        summary: "administrator workflow stopped safely".into(),
        stage: "adminWorkflow".into(),
        run_id: None,
        retryable: false,
        remediation: "Read the detail and retained stage files. Correct the package, input, or prerequisite; use a new evidence location unless an exact retained run status says otherwise.".into(),
        detail: error.to_string().into(),
    })
}

pub fn emit_summary_error(error: &anyhow::Error) {
    let mut terminal = std::io::stderr().lock();
    let _ = write_summary_error(&mut terminal, error);
}

#[derive(Debug)]
pub struct AdminOutputFailed {
    run_id: String,
    evidence_root: PathBuf,
    approval_recorded: bool,
    detail: String,
}

impl std::fmt::Display for AdminOutputFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "administrator result output failed: {}",
            self.detail
        )
    }
}

impl std::error::Error for AdminOutputFailed {}

impl AdminOutputFailed {
    pub fn from_result(result: &AdminAssessmentResult, error: anyhow::Error) -> anyhow::Error {
        anyhow!(Self {
            run_id: result.run_id.clone(),
            evidence_root: result.evidence_root.clone(),
            approval_recorded: result.approval_recorded,
            detail: error.to_string(),
        })
    }

    pub fn structured_error(&self) -> AiwError {
        AiwError {
            code: "AIW_ADMIN_OUTPUT_FAILED".into(),
            summary: if self.approval_recorded {
                "assessment result retained but console output failed"
            } else {
                "approval cancellation retained but console output failed"
            }
            .into(),
            stage: "adminOutput".into(),
            run_id: Some(self.run_id.clone().into()),
            retryable: false,
            remediation: if self.approval_recorded {
                format!(
                    "Read the retained report and exact run status under {}. Do not repeat the trial because console output failed.",
                    self.evidence_root.display()
                )
            } else {
                format!(
                    "Read approval-cancelled.json under {}. No Sandbox was started; use fresh evidence if you later choose to approve.",
                    self.evidence_root.display()
                )
            }
            .into(),
            detail: self.detail.clone().into(),
        }
    }
}

fn write_summary_error(output: &mut impl Write, error: &anyhow::Error) -> Result<()> {
    if let Some(failure) = error.downcast_ref::<AdminOutputFailed>() {
        writeln!(
            output,
            "{}",
            if failure.approval_recorded {
                "Assessment result retained, but console output failed."
            } else {
                "Approval cancellation retained, but console output failed. No Sandbox was started."
            }
        )?;
        writeln!(output, "Run: {}", failure.run_id)?;
        write!(output, "Evidence: ")?;
        approval_review::write_review_json(output, &failure.evidence_root.display().to_string())?;
        write!(output, "\nOutput error: ")?;
        approval_review::write_review_json(output, &failure.detail)?;
        writeln!(
            output,
            "\n{}",
            if failure.approval_recorded {
                "Read the retained report and exact run status. Do not repeat the trial because console output failed."
            } else {
                "Read approval-cancelled.json. Use fresh evidence if you later choose to approve."
            }
        )?;
        return Ok(());
    }
    let Some(error) = error.downcast_ref::<AiwError>() else {
        return writeln!(output, "Assessment stopped. Inspect the retained evidence and retry only after resolving the cause.").map_err(Into::into);
    };
    write!(
        output,
        "{}",
        if error.code.as_ref() == "AIW_WSB_EXPORT_OUTPUT_FAILED" {
            "Export completed, but console output failed: "
        } else if error.stage.as_ref() == "wsbDocumentExport" {
            "Export stopped: "
        } else {
            "Assessment stopped: "
        }
    )?;
    approval_review::write_review_json(output, &error.summary)?;
    write!(output, "\nCode: {}", error.code)?;
    if let Some(run_id) = &error.run_id {
        write!(output, "\nRun: ")?;
        approval_review::write_review_json(output, run_id)?;
    }
    write!(output, "\nNext: ")?;
    approval_review::write_review_json(output, &error.remediation)?;
    write!(output, "\nDetail: ")?;
    approval_review::write_review_json(output, &error.detail)?;
    writeln!(output)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductAssetManifest {
    schema_version: String,
    product_id: String,
    project_path: String,
    project_sha256: String,
    guest_agent_path: String,
    scenario_id: String,
    guest_agent_sha256: String,
    #[serde(default)]
    launch_profile_path: Option<String>,
    #[serde(default)]
    launch_profile_sha256: Option<String>,
}

struct ResolvedProductAssets {
    project: PathBuf,
    guest_agent: PathBuf,
    launch_profile: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAssessmentResult {
    pub schema_version: &'static str,
    pub product_id: &'static str,
    pub operator_identity: String,
    pub evidence_root: PathBuf,
    pub run_id: String,
    pub workspace: PathBuf,
    pub execution_mode: &'static str,
    pub approval_recorded: bool,
    pub execution_started: bool,
    pub next: &'static str,
    #[serde(skip)]
    summary: Option<String>,
}

impl AdminAssessmentResult {
    pub fn summary_text(&self) -> Option<&str> {
        self.summary.as_deref()
    }
    pub fn can_export_document(&self) -> bool {
        self.approval_recorded
            && self.execution_started
            && self.product_id == INTERACTIVE_PRODUCT_ID
    }
    pub fn write_summary(&self, output: &mut impl Write) -> Result<()> {
        if self.approval_recorded {
            writeln!(output, "Run: {}", self.run_id)?;
            if let Some(summary) = &self.summary {
                write!(output, "{summary}")?;
            } else {
                writeln!(output, "No completed assessment is available.")?;
            }
        } else {
            writeln!(output, "Approval cancelled. No Sandbox was started.")?;
            writeln!(output, "Run: {}", self.run_id)?;
        }
        write!(output, "Evidence: ")?;
        approval_review::write_review_json(output, &self.evidence_root.display().to_string())?;
        if self.approval_recorded && self.product_id == INTERACTIVE_PRODUCT_ID {
            write!(output, "\nExport workspace: ")?;
            approval_review::write_review_json(output, &self.workspace.display().to_string())?;
        }
        writeln!(output, "\nNext: {}", self.next)?;
        Ok(())
    }
}

fn report_summary(report: &aiw_runner::WsbMsiRunReport) -> (String, &'static str) {
    match report {
        aiw_runner::WsbMsiRunReport::CompletedAssessment(assessment) => {
            let mut summary = String::from("Fixed Notepad++ workflow (verified report):\n");
            for (name, result) in assessment.administrator_function_results() {
                let label = match result {
                    Some(true) => "passed",
                    Some(false) => "failed",
                    None => "not measured",
                };
                summary.push_str(&format!("  {name}: {label}\n"));
            }
            summary.push_str(&format!(
                "Recorded cleanup: {}\nBroader isolation: insufficient evidence; this fixed workflow is not a general compatibility verdict.\n",
                if assessment.recorded_cleanup_verified {
                    "verified"
                } else {
                    "not verified"
                }
            ));
            (
                summary,
                "Read report.md for the administrator overview; report.json and stage files retain the advanced evidence.",
            )
        }
        aiw_runner::WsbMsiRunReport::UnsuccessfulAttempt(attempt) => (
            format!(
                "No completed application assessment. Fixed workflow functions are not verified.\nRecorded cleanup: {}\n",
                if attempt.recorded_cleanup_verified {
                    "verified"
                } else {
                    "not verified"
                }
            ),
            "Read report.md and the exact run status before a new trial or any explicit recovery.",
        ),
        aiw_runner::WsbMsiRunReport::InteractiveSession(interactive) => {
            let transfer = interactive.document_transfer.as_ref();
            let cleanup = if interactive.recorded_cleanup_verified {
                "verified"
            } else {
                "not verified"
            };
            (
                match transfer {
                    Some(value) => format!(
                        "Fixed Notepad++ document session completed.\nVerified input: {} bytes.\nVerified retained output: {} bytes.\nRecorded cleanup: {cleanup}.\nBroader isolation: insufficient evidence.\n",
                        value.input_size_bytes, value.output_size_bytes,
                    ),
                    None => format!(
                        "Interactive session completed without a verified document transfer.\nRecorded cleanup: {cleanup}.\nBroader isolation: insufficient evidence.\n"
                    ),
                },
                if transfer.is_some() && interactive.recorded_cleanup_verified {
                    "Use admin export-document with the displayed export workspace, run ID, and a new destination. No host output file was created automatically. Read report.md for the overview and report.json for advanced evidence."
                } else {
                    "Read report.md and the exact retained run status before exporting or starting another trial."
                },
            )
        }
    }
}

fn bambu_report_summary(report: &aiw_runner::WsbBambuRunReport) -> (String, &'static str) {
    let mut summary = String::from("Fixed Bambu Studio export (retained report):\n");
    for (name, result) in report.administrator_function_results() {
        summary.push_str(&format!("  {name}: {result}\n"));
    }
    summary.push_str(&format!(
        "Recorded cleanup: {}\nBroader isolation: insufficient evidence; slicing, printing, cloud, and graphical workflows were not tested.\n",
        if report.recorded_cleanup_verified {
            "verified"
        } else {
            "not verified"
        }
    ));
    let next = if !report.recorded_cleanup_verified {
        "Read the exact retained run status before another attempt; recover only if that status requires it."
    } else if report.evidence_status != aiw_runner::BambuReportEvidenceStatus::Verified {
        "Read report.md and status. Missing or rejected evidence does not establish application incompatibility."
    } else if report
        .scenario
        .as_ref()
        .is_some_and(|scenario| scenario.successful())
        && report.artifact.is_some()
    {
        "Read report.md for the administrator overview; report.json and stage files retain the advanced evidence."
    } else {
        "Read the failed stage and diagnostics in report.md; correct that cause before approving a new disposable trial."
    };
    (summary, next)
}

impl ProductAssetManifest {
    fn resolve(&self, package_root: &Path) -> Result<ResolvedProductAssets> {
        self.resolve_fixed(package_root, PRODUCT_ID, SCENARIO_ID, ".yaml", true)
    }

    fn resolve_interactive(&self, package_root: &Path) -> Result<ResolvedProductAssets> {
        self.resolve_fixed(
            package_root,
            INTERACTIVE_PRODUCT_ID,
            SCENARIO_ID,
            ".yaml",
            false,
        )
    }

    fn resolve_bambu(&self, package_root: &Path) -> Result<ResolvedProductAssets> {
        self.resolve_fixed(
            package_root,
            BAMBU_PRODUCT_ID,
            BAMBU_SCENARIO_ID,
            ".json",
            false,
        )
    }

    fn resolve_fixed(
        &self,
        package_root: &Path,
        product_id: &str,
        scenario_id: &str,
        project_extension: &str,
        allow_profile: bool,
    ) -> Result<ResolvedProductAssets> {
        if self.schema_version != MANIFEST_SCHEMA
            || self.product_id != product_id
            || self.scenario_id != scenario_id
            || !valid_sha256(&self.project_sha256)
            || !valid_sha256(&self.guest_agent_sha256)
            || self
                .launch_profile_sha256
                .as_deref()
                .is_some_and(|value| !valid_sha256(value))
            || self.launch_profile_path.is_some() != self.launch_profile_sha256.is_some()
            || (!allow_profile && self.launch_profile_path.is_some())
        {
            bail!("packaged product manifest is not the selected fixed assessment contract");
        }
        let root = package_root
            .canonicalize()
            .map_err(|_| anyhow!("packaged product assets are missing"))?;
        let resolve = |value: &str, extension: &str| -> Result<PathBuf> {
            let relative = Path::new(value);
            if value.is_empty()
                || relative.is_absolute()
                || !value.ends_with(extension)
                || relative.components().any(|part| {
                    matches!(
                        part,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
            {
                bail!("packaged product asset path is invalid");
            }
            let path = root
                .join(relative)
                .canonicalize()
                .map_err(|_| anyhow!("packaged product asset is missing"))?;
            if !path.starts_with(&root) {
                bail!("packaged product asset resolves outside its package");
            }
            Ok(path)
        };
        Ok(ResolvedProductAssets {
            project: resolve(&self.project_path, project_extension)?,
            guest_agent: resolve(&self.guest_agent_path, ".exe")?,
            launch_profile: self
                .launch_profile_path
                .as_deref()
                .map(|path| resolve(path, ".json"))
                .transpose()?,
        })
    }
}

fn packaged_asset_root(product_directory: &str) -> Result<PathBuf> {
    let executable = std::env::current_exe()
        .map_err(|_| anyhow!("cannot resolve the installed AIW executable"))?;
    let parent = executable
        .parent()
        .ok_or_else(|| anyhow!("installed AIW executable has no package directory"))?;
    Ok(parent.join("product").join(product_directory))
}

#[cfg(any(windows, test))]
fn interactive_export_assets(
    assets_root: &Path,
) -> Result<(Project, ProductAssetManifest, ResolvedProductAssets)> {
    let manifest: ProductAssetManifest = serde_json::from_slice(&read_file_bounded(
        &assets_root.join("manifest.json"),
        1024 * 1024,
    )?)?;
    let assets = manifest.resolve_interactive(assets_root)?;
    let project_bytes = read_file_bounded(&assets.project, MAX_CONFIG_BYTES)?;
    if lowercase_sha256(&project_bytes) != manifest.project_sha256 {
        bail!("packaged project bytes do not match the product manifest");
    }
    let project: Project = serde_yaml::from_slice(&project_bytes)?;
    if !validate_project_for_planning(&project).is_empty()
        || project.metadata.name != INTERACTIVE_PRODUCT_ID
    {
        bail!("packaged project is not valid for the fixed interactive workflow");
    }
    Ok((project, manifest, assets))
}

#[cfg(windows)]
pub fn export_document(
    workspace: &Path,
    run_id: &str,
    destination: &Path,
) -> Result<aiw_runner::WsbMsiDocumentExport> {
    let result = (|| {
        let assets_root = packaged_asset_root(INTERACTIVE_PRODUCT_ID)?;
        let (project, manifest, assets) = interactive_export_assets(&assets_root)?;
        let agent = aiw_windows_platform::HeldApplicationFile::open(&assets.guest_agent)
            .map_err(|error| anyhow!("packaged guest agent is unsupported: {error}"))?;
        if agent.observation().sha256 != manifest.guest_agent_sha256 {
            bail!("packaged guest agent bytes do not match the product manifest");
        }
        agent
            .revalidate()
            .map_err(|error| anyhow!("packaged guest agent drifted: {error}"))?;
        aiw_runner::export_windows_sandbox_msi_document(
            workspace,
            run_id,
            &project,
            &manifest.guest_agent_sha256,
            destination,
        )
        .map_err(|source| document_export_error(run_id, source))
    })();
    result.map_err(|error: anyhow::Error| {
        if error.is::<AiwError>() {
            error
        } else {
            document_export_error(
                run_id,
                aiw_runner::RunnerError::Receipt(format!("export package rejected: {error}")),
            )
        }
    })
}

/// Reverify the retained interactive report using the package-bound project and guest identity.
#[cfg(windows)]
pub fn report_document(workspace: &Path, run_id: &str) -> Result<aiw_runner::WsbMsiRunReport> {
    let assets_root = packaged_asset_root(INTERACTIVE_PRODUCT_ID)?;
    let (project, manifest, assets) = interactive_export_assets(&assets_root)?;
    let agent = aiw_windows_platform::HeldApplicationFile::open(&assets.guest_agent)
        .map_err(|error| anyhow!("packaged guest agent is unsupported: {error}"))?;
    if agent.observation().sha256 != manifest.guest_agent_sha256 {
        bail!("packaged guest agent bytes do not match the product manifest");
    }
    agent
        .revalidate()
        .map_err(|error| anyhow!("packaged guest agent drifted: {error}"))?;
    aiw_runner::report_windows_sandbox_msi_run(
        workspace,
        run_id,
        &project,
        &manifest.guest_agent_sha256,
    )
    .map_err(|source| document_export_error(run_id, source))
}

/// Reverify a retained fixed Notepad++ assessment using package-bound assets.
#[cfg(windows)]
pub fn report_assessment(workspace: &Path, run_id: &str) -> Result<aiw_runner::WsbMsiRunReport> {
    let assets_root = packaged_asset_root("notepad-plus-plus")?;
    let manifest: ProductAssetManifest = serde_json::from_slice(&read_file_bounded(
        &assets_root.join("manifest.json"),
        1024 * 1024,
    )?)?;
    let assets = manifest.resolve(&assets_root)?;
    let project_bytes = read_file_bounded(&assets.project, MAX_CONFIG_BYTES)?;
    if lowercase_sha256(&project_bytes) != manifest.project_sha256 {
        bail!("packaged project bytes do not match the product manifest");
    }
    let project: Project = serde_yaml::from_slice(&project_bytes)?;
    if !validate_project_for_planning(&project).is_empty()
        || project.metadata.name != PRODUCT_ID
        || manifest.product_id != PRODUCT_ID
        || manifest.scenario_id != SCENARIO_ID
    {
        bail!("packaged project is not valid for the fixed assessment");
    }
    let agent = aiw_windows_platform::HeldApplicationFile::open(&assets.guest_agent)
        .map_err(|error| anyhow!("packaged guest agent is unsupported: {error}"))?;
    if agent.observation().sha256 != manifest.guest_agent_sha256 {
        bail!("packaged guest agent bytes do not match the product manifest");
    }
    agent
        .revalidate()
        .map_err(|error| anyhow!("packaged guest agent drifted: {error}"))?;
    aiw_runner::report_windows_sandbox_msi_run(
        workspace,
        run_id,
        &project,
        &manifest.guest_agent_sha256,
    )
    .map_err(|source| retained_result_error(workspace, run_id, "adminRetainedReport", source))
}

/// Reverify a retained fixed Bambu export using package-bound project and guest identities.
#[cfg(windows)]
pub fn report_bambu(workspace: &Path, run_id: &str) -> Result<aiw_runner::WsbBambuRunReport> {
    let assets_root = packaged_asset_root("bambu-studio")?;
    let manifest: ProductAssetManifest = serde_json::from_slice(&read_file_bounded(
        &assets_root.join("manifest.json"),
        1024 * 1024,
    )?)?;
    let assets = manifest.resolve_bambu(&assets_root)?;
    let project_bytes = read_file_bounded(&assets.project, MAX_CONFIG_BYTES)?;
    if lowercase_sha256(&project_bytes) != manifest.project_sha256 {
        bail!("packaged Bambu project bytes do not match the product manifest");
    }
    let project: Project = serde_json::from_slice(&project_bytes)?;
    if !validate_project_for_planning(&project).is_empty()
        || project.metadata.name != BAMBU_PRODUCT_ID
        || manifest.product_id != BAMBU_PRODUCT_ID
        || manifest.scenario_id != BAMBU_SCENARIO_ID
    {
        bail!("packaged Bambu project is not valid for the fixed assessment");
    }
    aiw_provider_wsb::compile_bambu_studio_export_scenario(&project, BAMBU_SCENARIO_ID)
        .map_err(|error| anyhow!("packaged Bambu export contract is invalid: {error}"))?;
    let agent = aiw_windows_platform::HeldApplicationFile::open(&assets.guest_agent)
        .map_err(|error| anyhow!("packaged guest agent is unsupported: {error}"))?;
    if agent.observation().sha256 != manifest.guest_agent_sha256 {
        bail!("packaged guest agent bytes do not match the product manifest");
    }
    agent
        .revalidate()
        .map_err(|error| anyhow!("packaged guest agent drifted: {error}"))?;
    aiw_runner::report_windows_sandbox_bambu_run(
        workspace,
        run_id,
        &project,
        &manifest.guest_agent_sha256,
    )
    .map_err(anyhow::Error::from)
}

#[cfg(not(windows))]
pub fn export_document(
    _: &Path,
    run_id: &str,
    _: &Path,
) -> Result<aiw_runner::WsbMsiDocumentExport> {
    Err(anyhow!(AiwError {
        code: "AIW_WINDOWS_REQUIRED".into(),
        summary: "interactive document export requires Windows".into(),
        stage: "wsbDocumentExport".into(),
        remediation:
            "Export this exact retained interactive run on its original supported Windows host."
                .into(),
        detail: "No files or provider state were changed.".into(),
        run_id: Some(run_id.into()),
        retryable: false,
    }))
}

fn unsupported_installer_error(
    evidence_root: &Path,
    run_id: &str,
    reason: impl Into<String>,
) -> anyhow::Error {
    unsupported_application_error(evidence_root, run_id, reason, "msi", "Notepad++ MSI")
}

fn unsupported_application_error(
    evidence_root: &Path,
    run_id: &str,
    reason: impl Into<String>,
    supported_kind: &'static str,
    profile: &'static str,
) -> anyhow::Error {
    let reason = reason.into();
    let diagnostic_path = evidence_root.join("installer-rejection.json");
    let diagnostic = serde_json::json!({
        "schemaVersion": "aiw.dev/admin-installer-rejection/v0alpha1",
        "runId": run_id,
        "supportedKind": supported_kind,
        "reason": reason,
        "intakeCreated": false,
        "providerAcquired": false
    });
    let diagnostic_status = save_stage(evidence_root, "installer-rejection", &diagnostic)
        .map(|_| format!("Inspect {}.", diagnostic_path.display()))
        .unwrap_or_else(|error| format!("Diagnostic publication failed safely: {error}."));
    anyhow!(AiwError {
        code: "AIW_ADMIN_UNSUPPORTED_INSTALLER".into(),
        summary: format!("installer is not supported by this {profile} profile").into(),
        stage: "adminInstallerInspection".into(),
        run_id: Some(run_id.into()),
        retryable: false,
        remediation: format!(
            "{diagnostic_status} Select the exact supported {profile} bytes; do not guess a recipe for another application type."
        )
        .into(),
        detail: "No protected intake was created and no Sandbox session was acquired.".into(),
    })
}

fn retained_result_error(
    evidence_root: &Path,
    run_id: &str,
    stage: &'static str,
    error: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow!(AiwError {
        code: "AIW_ADMIN_RESULT_PUBLICATION_FAILED".into(),
        summary: "approved execution returned but its administrator result could not be published"
            .into(),
        stage: stage.into(),
        run_id: Some(run_id.to_owned().into()),
        retryable: false,
        remediation: format!(
            "Inspect the exact retained run status and stage files under {}. Do not repeat the trial because report publication failed; use explicit recovery only if that status requires it.",
            evidence_root.display()
        )
        .into(),
        detail: error.to_string().into(),
    })
}

fn retained_execution_error(
    evidence_root: &Path,
    run_id: &str,
    error: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow!(AiwError {
        code: "AIW_ADMIN_EXECUTION_FAILED".into(),
        summary: "approved assessment did not complete".into(),
        stage: "adminExecution".into(),
        run_id: Some(run_id.to_owned().into()),
        retryable: false,
        remediation: format!(
            "Inspect failed-status.json and failed-report.md, when present, under {}. Do not repeat the trial or recover a session until the exact retained status and cause are understood.",
            evidence_root.display()
        )
        .into(),
        detail: error.to_string().into(),
    })
}

#[cfg(windows)]
pub fn assess(
    installer: &Path,
    evidence_parent: &Path,
    identity: &str,
    show_progress: bool,
) -> Result<AdminAssessmentResult> {
    require_terminal()?;
    assess_with_gate(
        installer,
        evidence_parent,
        identity,
        &TerminalApprovalGate,
        show_progress,
    )
}

#[cfg(windows)]
pub fn assess_with_gate(
    installer: &Path,
    evidence_parent: &Path,
    identity: &str,
    gate: &dyn ApprovalGate,
    show_progress: bool,
) -> Result<AdminAssessmentResult> {
    assess_notepad(
        installer,
        None,
        evidence_parent,
        identity,
        gate,
        show_progress,
    )
}

#[cfg(windows)]
pub fn launch_document(
    installer: &Path,
    document_input: &Path,
    evidence_parent: &Path,
    identity: &str,
    show_progress: bool,
) -> Result<AdminAssessmentResult> {
    require_terminal()?;
    launch_document_with_gate(
        installer,
        document_input,
        evidence_parent,
        identity,
        &TerminalApprovalGate,
        show_progress,
    )
}

#[cfg(windows)]
pub fn launch_document_with_gate(
    installer: &Path,
    document_input: &Path,
    evidence_parent: &Path,
    identity: &str,
    gate: &dyn ApprovalGate,
    show_progress: bool,
) -> Result<AdminAssessmentResult> {
    assess_notepad(
        installer,
        Some(document_input),
        evidence_parent,
        identity,
        gate,
        show_progress,
    )
}

#[cfg(windows)]
fn assess_notepad(
    installer: &Path,
    document_input: Option<&Path>,
    evidence_parent: &Path,
    identity: &str,
    gate: &dyn ApprovalGate,
    show_progress: bool,
) -> Result<AdminAssessmentResult> {
    let interactive = document_input.is_some();
    if identity.trim().is_empty() {
        bail!("operator identity is required");
    }
    let product_id = if interactive {
        INTERACTIVE_PRODUCT_ID
    } else {
        PRODUCT_ID
    };
    let assets_root = packaged_asset_root(if interactive {
        "notepad-plus-plus-interactive"
    } else {
        "notepad-plus-plus"
    })?;
    let manifest: ProductAssetManifest = serde_json::from_slice(
        &std::fs::read(assets_root.join("manifest.json"))
            .map_err(|_| anyhow!("packaged product manifest is missing"))?,
    )?;
    let assets = if interactive {
        manifest.resolve_interactive(&assets_root)?
    } else {
        manifest.resolve(&assets_root)?
    };
    let project_bytes = std::fs::read(&assets.project)?;
    if lowercase_sha256(&project_bytes) != manifest.project_sha256 {
        bail!("packaged project bytes do not match the product manifest");
    }
    let project: Project = serde_yaml::from_slice(&project_bytes)?;
    if !validate_project_for_planning(&project).is_empty() || project.metadata.name != product_id {
        bail!("packaged project is not valid for the selected fixed workflow");
    }
    let expected_msi = match &project.application {
        ApplicationSource::Msi(source) => &source.sha256,
        _ => bail!("packaged project is not an MSI assessment"),
    };
    let expected_agent = aiw_windows_platform::HeldApplicationFile::open(&assets.guest_agent)
        .map_err(|error| anyhow!("packaged guest agent is unsupported: {error}"))?;
    if expected_agent.observation().sha256 != manifest.guest_agent_sha256 {
        bail!("packaged guest agent bytes do not match the product manifest");
    }
    expected_agent
        .revalidate()
        .map_err(|error| anyhow!("packaged guest agent drifted: {error}"))?;
    let launch_profile: Option<aiw_runner::WsbLaunchProfileExport> = assets
        .launch_profile
        .as_ref()
        .map(|path| -> Result<_> {
            let profile: aiw_runner::WsbLaunchProfileExport =
                serde_json::from_slice(&std::fs::read(path)?)?;
            if Some(profile.profile_sha256.as_str()) != manifest.launch_profile_sha256.as_deref() {
                bail!("packaged launch profile identity differs from the product manifest");
            }
            Ok(profile)
        })
        .transpose()?;
    let execution_mode = if interactive {
        "interactiveDocumentTransfer"
    } else if launch_profile.is_some() {
        "approvedReplay"
    } else {
        "assessment"
    };
    let run_id = format!("admin-{}", nonce());
    let evidence_root = create_evidence_root(evidence_parent, &run_id)?;
    let readiness = aiw_windows_platform::assess_windows_sandbox();
    save_stage(&evidence_root, "host-readiness", &readiness)?;
    if !readiness.supported
        || readiness.current_sessions != ReadinessState::Available
        || !readiness.blockers.is_empty()
        || !readiness.current_session_ids.is_empty()
    {
        return Err(anyhow!(AiwError {
            code: "AIW_ADMIN_HOST_NOT_READY".into(),
            summary: "Windows Sandbox readiness blocks this workflow".into(),
            stage: "adminReadiness".into(),
            run_id: Some(run_id.clone().into()),
            retryable: false,
            remediation: format!(
                "Inspect {}. Resolve the listed prerequisite, or wait for the existing Sandbox session to finish. Do not stop an unrelated session.",
                evidence_root.join("host-readiness.json").display()
            ).into(),
            detail: "No protected intake was created and AIW did not acquire, recover, or stop a Sandbox session.".into(),
        }));
    }
    let held = aiw_windows_platform::HeldApplicationFile::open_with_download_metadata(installer)
        .map_err(|error| unsupported_installer_error(&evidence_root, &run_id, error.to_string()))?;
    let inspection = inspect_application_source(installer, ApplicationInspectionKind::Msi)
        .map_err(|error| unsupported_installer_error(&evidence_root, &run_id, error.to_string()))?;
    save_stage(&evidence_root, "installer-inspection", &inspection)?;
    if inspection.sha256.as_deref() != Some(&held.observation().sha256)
        || inspection.sha256.as_deref() != Some(expected_msi.as_str())
    {
        return Err(anyhow!(AiwError {
            code: "AIW_ADMIN_UNSUPPORTED_INSTALLER".into(),
            summary: "installer bytes are not supported by this Notepad++ profile".into(),
            stage: "adminInstallerInspection".into(),
            run_id: Some(run_id.clone().into()),
            retryable: false,
            remediation: format!(
                "Inspect {} and select the exact supported MSI bytes. Do not guess a recipe for changed bytes.",
                evidence_root.join("installer-inspection.json").display()
            ).into(),
            detail: "No protected intake was created and no Sandbox session was acquired.".into(),
        }));
    }
    held.revalidate()
        .map_err(|error| anyhow!("installer drifted before protected intake: {error}"))?;
    let intake_parent = evidence_root.join("intakes");
    std::fs::create_dir(&intake_parent)?;
    let receipt = aiw_windows_platform::import_application_file_with_metadata(&intake_parent, "notepad-plus-plus", ApplicationInspectionKind::Msi, &held, true)
        .map_err(|error| anyhow!("protected intake failed; preserve evidence and use a new evidence location to retry: {error}"))?;
    save_stage(&evidence_root, "intake-receipt", &receipt)?;
    let prepared = aiw_runner::prepare_windows_sandbox_msi_bundle(&run_id, &project, &assets.guest_agent, &manifest.guest_agent_sha256, &evidence_root, &now_rfc3339(), aiw_runner::WsbMsiPreparationInput { import_receipt: &receipt, scenario_id: SCENARIO_ID, document_input, launch_profile: launch_profile.as_ref().zip(manifest.launch_profile_sha256.as_deref()) })
        .map_err(|error| anyhow!("preparation failed; inspect retained stage output and do not retry this workspace: {error}"))?;
    save_stage(&evidence_root, "preparation", &prepared.receipt)?;
    let workspace = PathBuf::from(&prepared.receipt.workspace.root.final_path);
    let recipe = aiw_runner::inspect_windows_sandbox_msi_recipe(
        &workspace,
        &project,
        &manifest.guest_agent_sha256,
    )
    .map_err(|error| {
        anyhow!("recipe inspection failed; inspect retained preparation before retrying: {error}")
    })?;
    save_stage(&evidence_root, "recipe", &recipe)?;
    let imported = aiw_runner::import_windows_sandbox_preparation(
        &workspace,
        &project,
        &manifest.guest_agent_sha256,
        &now_rfc3339(),
    )
    .map_err(|error| {
        anyhow!("planning import failed; inspect retained preparation and status: {error}")
    })?;
    save_stage(&evidence_root, "planning-import", &imported)?;
    let layout = RunLayout::new(&workspace, &run_id)?;
    let plan = layout.read_plan()?;
    let approval = ApprovalRecord::for_plan(&plan, identity.trim(), now_rfc3339())?;
    let review = ApprovalReview {
        run_id: run_id.clone(),
        workspace: workspace.clone(),
        evidence_root: evidence_root.clone(),
        recipe: serde_json::to_value(&recipe)?,
        plan: plan.clone(),
        proposed_approval: approval.clone(),
    };
    if !approve_review(gate, &review)? {
        save_stage(
            &evidence_root,
            "approval-cancelled",
            &serde_json::json!({"runId": run_id, "approvalRecorded": false, "next": "Review the retained recipe, then rerun this command with a fresh evidence location when ready to approve."}),
        )?;
        return Ok(AdminAssessmentResult {
            schema_version: MANIFEST_SCHEMA,
            product_id,
            operator_identity: identity.trim().into(),
            evidence_root,
            run_id,
            workspace,
            execution_mode,
            approval_recorded: false,
            execution_started: false,
            next: "Approval was cancelled. The run remains pending approval; no Sandbox was started.",
            summary: None,
        });
    }
    save_stage(&evidence_root, "approval", &approval)?;
    if !wait_for_start(gate, &review)? {
        save_stage(
            &evidence_root,
            "execution-not-started",
            &serde_json::json!({"runId": run_id, "approvalRecorded": true, "providerAcquired": false, "next": "Approval is recorded. Explicitly request Start when ready; no Sandbox was started."}),
        )?;
        return Ok(AdminAssessmentResult {
            schema_version: MANIFEST_SCHEMA,
            product_id,
            operator_identity: identity.trim().into(),
            evidence_root,
            run_id,
            workspace,
            execution_mode,
            approval_recorded: true,
            execution_started: false,
            next: "Approval recorded; execution was not started. No Sandbox was started.",
            summary: None,
        });
    }
    let execution_result = {
        let _progress = admin_progress::RunProgress::start(
            show_progress && gate.uses_terminal_progress(),
            interactive,
        );
        aiw_runner::start_approved_windows_sandbox(
            &workspace,
            &assets.project,
            &project,
            &manifest.guest_agent_sha256,
            900,
        )
    };
    let execution = match execution_result {
        Ok(execution) => execution,
        Err(error) => {
            if let Ok(status) = layout.status() {
                let _ = save_stage(&evidence_root, "failed-status", &status);
            }
            if let Ok(report) = aiw_runner::report_windows_sandbox_msi_run(
                &workspace,
                &run_id,
                &project,
                &manifest.guest_agent_sha256,
            ) {
                let _ = save_stage(&evidence_root, "failed-report", &report);
                let _ =
                    std::fs::write(evidence_root.join("failed-report.md"), report.to_markdown());
            }
            return Err(retained_execution_error(&evidence_root, &run_id, error));
        }
    };
    save_stage(&evidence_root, "execution", &execution).map_err(|error| {
        retained_result_error(&evidence_root, &run_id, "adminExecutionRecord", error)
    })?;
    let report = aiw_runner::report_windows_sandbox_msi_run(
        &workspace,
        &run_id,
        &project,
        &manifest.guest_agent_sha256,
    )
    .map_err(|error| retained_result_error(&evidence_root, &run_id, "adminReport", error))?;
    save_stage(&evidence_root, "report", &report).map_err(|error| {
        retained_result_error(&evidence_root, &run_id, "adminReportRecord", error)
    })?;
    std::fs::write(evidence_root.join("report.md"), report.to_markdown()).map_err(|error| {
        retained_result_error(&evidence_root, &run_id, "adminReportMarkdown", error)
    })?;
    let (summary, next) = report_summary(&report);
    Ok(AdminAssessmentResult {
        schema_version: MANIFEST_SCHEMA,
        product_id,
        operator_identity: identity.trim().into(),
        evidence_root,
        run_id,
        workspace,
        execution_mode,
        approval_recorded: true,
        execution_started: true,
        next,
        summary: Some(summary),
    })
}

#[cfg(not(windows))]
pub fn assess(_: &Path, _: &Path, _: &str, _: bool) -> Result<AdminAssessmentResult> {
    bail!("admin assess requires Windows; no files or provider state were changed")
}

#[cfg(not(windows))]
pub fn launch_document(
    _: &Path,
    _: &Path,
    _: &Path,
    _: &str,
    _: bool,
) -> Result<AdminAssessmentResult> {
    bail!("admin launch-document requires Windows; no files or provider state were changed")
}

#[cfg(windows)]
pub fn assess_bambu(
    installer: &Path,
    evidence_parent: &Path,
    identity: &str,
    show_progress: bool,
) -> Result<AdminAssessmentResult> {
    require_terminal()?;
    assess_bambu_with_gate(
        installer,
        evidence_parent,
        identity,
        &TerminalApprovalGate,
        show_progress,
    )
}

fn require_terminal() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        bail!(
            "administrator workflow requires terminal input and visible approval review; no intake or run was created"
        );
    }
    Ok(())
}

#[cfg(windows)]
pub fn assess_bambu_with_gate(
    installer: &Path,
    evidence_parent: &Path,
    identity: &str,
    gate: &dyn ApprovalGate,
    show_progress: bool,
) -> Result<AdminAssessmentResult> {
    if identity.trim().is_empty() {
        bail!("operator identity is required");
    }
    let assets_root = packaged_asset_root("bambu-studio")?;
    let manifest: ProductAssetManifest = serde_json::from_slice(
        &std::fs::read(assets_root.join("manifest.json"))
            .map_err(|_| anyhow!("packaged Bambu product manifest is missing"))?,
    )?;
    let assets = manifest.resolve_bambu(&assets_root)?;
    let project_bytes = std::fs::read(&assets.project)?;
    if lowercase_sha256(&project_bytes) != manifest.project_sha256 {
        bail!("packaged Bambu project bytes do not match the product manifest");
    }
    let project: Project = serde_json::from_slice(&project_bytes)?;
    if !validate_project_for_planning(&project).is_empty()
        || project.metadata.name != BAMBU_PRODUCT_ID
    {
        bail!("packaged Bambu project is not valid for the fixed assessment");
    }
    let expected_exe = match &project.application {
        ApplicationSource::Exe(source) => &source.sha256,
        _ => bail!("packaged Bambu project is not an EXE assessment"),
    };
    aiw_provider_wsb::compile_bambu_studio_export_scenario(&project, BAMBU_SCENARIO_ID)
        .map_err(|error| anyhow!("packaged Bambu export contract is invalid: {error}"))?;
    let expected_agent = aiw_windows_platform::HeldApplicationFile::open(&assets.guest_agent)
        .map_err(|error| anyhow!("packaged guest agent is unsupported: {error}"))?;
    if expected_agent.observation().sha256 != manifest.guest_agent_sha256 {
        bail!("packaged guest agent bytes do not match the product manifest");
    }
    expected_agent
        .revalidate()
        .map_err(|error| anyhow!("packaged guest agent drifted: {error}"))?;

    let run_id = format!("admin-{}", nonce());
    let evidence_root = create_evidence_root(evidence_parent, &run_id)?;
    let readiness = aiw_windows_platform::assess_windows_sandbox();
    save_stage(&evidence_root, "host-readiness", &readiness)?;
    if !readiness.supported
        || readiness.current_sessions != ReadinessState::Available
        || !readiness.blockers.is_empty()
        || !readiness.current_session_ids.is_empty()
    {
        return Err(anyhow!(AiwError {
            code: "AIW_ADMIN_HOST_NOT_READY".into(),
            summary: "Windows Sandbox readiness blocks this assessment".into(),
            stage: "adminReadiness".into(),
            run_id: Some(run_id.clone().into()),
            retryable: false,
            remediation: format!(
                "Inspect {}. Resolve the listed prerequisite, or wait for the existing Sandbox session to finish. Do not stop an unrelated session.",
                evidence_root.join("host-readiness.json").display()
            ).into(),
            detail: "No protected intake was created and AIW did not acquire, recover, or stop a Sandbox session.".into(),
        }));
    }
    let held = aiw_windows_platform::HeldApplicationFile::open_with_download_metadata(installer)
        .map_err(|error| {
            unsupported_application_error(
                &evidence_root,
                &run_id,
                error.to_string(),
                "exe",
                "Bambu Studio EXE",
            )
        })?;
    let inspection = inspect_application_source(installer, ApplicationInspectionKind::Exe)
        .map_err(|error| {
            unsupported_application_error(
                &evidence_root,
                &run_id,
                error.to_string(),
                "exe",
                "Bambu Studio EXE",
            )
        })?;
    save_stage(&evidence_root, "installer-inspection", &inspection)?;
    if inspection.sha256.as_deref() != Some(&held.observation().sha256)
        || inspection.sha256.as_deref() != Some(expected_exe.as_str())
    {
        return Err(anyhow!(AiwError {
            code: "AIW_ADMIN_UNSUPPORTED_INSTALLER".into(),
            summary: "installer bytes are not supported by this Bambu Studio profile".into(),
            stage: "adminInstallerInspection".into(),
            run_id: Some(run_id.clone().into()),
            retryable: false,
            remediation: format!(
                "Inspect {} and select the exact supported EXE bytes. Do not guess a recipe for changed bytes.",
                evidence_root.join("installer-inspection.json").display()
            ).into(),
            detail: "No protected intake was created and no Sandbox session was acquired.".into(),
        }));
    }
    held.revalidate()
        .map_err(|error| anyhow!("installer drifted before protected intake: {error}"))?;
    let intake_parent = evidence_root.join("intakes");
    std::fs::create_dir(&intake_parent)?;
    let receipt = aiw_windows_platform::import_application_file_with_metadata(
        &intake_parent,
        "bambu-studio",
        ApplicationInspectionKind::Exe,
        &held,
        true,
    )
    .map_err(|error| {
        anyhow!("protected intake failed; preserve evidence and use a new evidence location to retry: {error}")
    })?;
    save_stage(&evidence_root, "intake-receipt", &receipt)?;
    let prepared = aiw_runner::prepare_windows_sandbox_bambu_bundle(
        &run_id,
        &project,
        &assets.guest_agent,
        &manifest.guest_agent_sha256,
        &evidence_root,
        &now_rfc3339(),
        aiw_runner::WsbBambuPreparationInput {
            import_receipt: &receipt,
            scenario_id: BAMBU_SCENARIO_ID,
        },
    )
    .map_err(|error| {
        anyhow!("preparation failed; inspect retained stage output and do not retry this workspace: {error}")
    })?;
    save_stage(&evidence_root, "preparation", &prepared.receipt)?;
    let workspace = PathBuf::from(&prepared.receipt.workspace.root.final_path);
    let scenario = prepared
        .receipt
        .bambu
        .as_ref()
        .ok_or_else(|| anyhow!("prepared Bambu scenario is missing"))?;
    let recipe = serde_json::json!({
        "schemaVersion": "aiw.dev/admin-bambu-recipe/v0alpha1",
        "productId": BAMBU_PRODUCT_ID,
        "runId": run_id,
        "scenario": scenario.scenario,
        "preparationReceipt": prepared.receipt,
        "sandboxPlan": prepared.wsb_plan,
        "runPlan": prepared.run_plan,
        "executionIdentity": "The Bambu Studio EXE installer runs with an elevated token inside Windows Sandbox. Bambu Studio, the fixed STL fixture, and local 3MF export run as AiwStandardUser.",
        "dataLifetime": "The fixed input and installed application are discarded with the worker. The receipt-bound 3MF and assessment evidence remain in the host run workspace; no automatic host export is performed.",
        "limits": "This is one fixed offline STL-to-3MF export. The installer wait is bounded at 900 seconds and the worker receipt wait at 1500 seconds. Slicing, printing, cloud, graphical editing, general EXE support, and effective application isolation are not tested."
    });
    save_stage(&evidence_root, "recipe", &recipe)?;
    let imported = aiw_runner::import_windows_sandbox_preparation(
        &workspace,
        &project,
        &manifest.guest_agent_sha256,
        &now_rfc3339(),
    )
    .map_err(|error| {
        anyhow!("planning import failed; inspect retained preparation and status: {error}")
    })?;
    save_stage(&evidence_root, "planning-import", &imported)?;
    let layout = RunLayout::new(&workspace, &run_id)?;
    let plan = layout.read_plan()?;
    let approval = ApprovalRecord::for_plan(&plan, identity.trim(), now_rfc3339())?;
    let review = ApprovalReview {
        run_id: run_id.clone(),
        workspace: workspace.clone(),
        evidence_root: evidence_root.clone(),
        recipe: recipe.clone(),
        plan: plan.clone(),
        proposed_approval: approval.clone(),
    };
    if !approve_review(gate, &review)? {
        save_stage(
            &evidence_root,
            "approval-cancelled",
            &serde_json::json!({"runId": run_id, "approvalRecorded": false, "next": "Review the retained recipe, then rerun this command with a fresh evidence location when ready to approve."}),
        )?;
        return Ok(AdminAssessmentResult {
            schema_version: MANIFEST_SCHEMA,
            product_id: BAMBU_PRODUCT_ID,
            operator_identity: identity.trim().into(),
            evidence_root,
            run_id,
            workspace,
            execution_mode: "assessment",
            approval_recorded: false,
            execution_started: false,
            next: "Approval was cancelled. The run remains pending approval; no Sandbox was started.",
            summary: None,
        });
    }
    save_stage(&evidence_root, "approval", &approval)?;
    if !wait_for_start(gate, &review)? {
        save_stage(
            &evidence_root,
            "execution-not-started",
            &serde_json::json!({"runId": run_id, "approvalRecorded": true, "providerAcquired": false}),
        )?;
        return Ok(AdminAssessmentResult {
            schema_version: MANIFEST_SCHEMA,
            product_id: BAMBU_PRODUCT_ID,
            operator_identity: identity.trim().into(),
            evidence_root,
            run_id,
            workspace,
            execution_mode: "assessment",
            approval_recorded: true,
            execution_started: false,
            next: "Approval recorded; execution was not started. No Sandbox was started.",
            summary: None,
        });
    }
    let execution_result = {
        let _progress = admin_progress::RunProgress::start(
            show_progress && gate.uses_terminal_progress(),
            false,
        );
        aiw_runner::start_approved_windows_sandbox(
            &workspace,
            &assets.project,
            &project,
            &manifest.guest_agent_sha256,
            1500,
        )
    };
    let execution = match execution_result {
        Ok(execution) => execution,
        Err(error) => {
            if let Ok(status) = layout.status() {
                let _ = save_stage(&evidence_root, "failed-status", &status);
            }
            if let Ok(report) = aiw_runner::report_windows_sandbox_bambu_run(
                &workspace,
                &run_id,
                &project,
                &manifest.guest_agent_sha256,
            ) {
                let _ = save_stage(&evidence_root, "failed-report", &report);
                let _ = std::fs::write(
                    evidence_root.join("failed-report.md"),
                    aiw_runner::render_bambu_run_report_markdown(&report),
                );
            }
            return Err(retained_execution_error(&evidence_root, &run_id, error));
        }
    };
    save_stage(&evidence_root, "execution", &execution).map_err(|error| {
        retained_result_error(&evidence_root, &run_id, "adminExecutionRecord", error)
    })?;
    let report = aiw_runner::report_windows_sandbox_bambu_run(
        &workspace,
        &run_id,
        &project,
        &manifest.guest_agent_sha256,
    )
    .map_err(|error| retained_result_error(&evidence_root, &run_id, "adminReport", error))?;
    save_stage(&evidence_root, "report", &report).map_err(|error| {
        retained_result_error(&evidence_root, &run_id, "adminReportRecord", error)
    })?;
    std::fs::write(
        evidence_root.join("report.md"),
        aiw_runner::render_bambu_run_report_markdown(&report),
    )
    .map_err(|error| {
        retained_result_error(&evidence_root, &run_id, "adminReportMarkdown", error)
    })?;
    let (summary, next) = bambu_report_summary(&report);
    Ok(AdminAssessmentResult {
        schema_version: MANIFEST_SCHEMA,
        product_id: BAMBU_PRODUCT_ID,
        operator_identity: identity.trim().into(),
        evidence_root,
        run_id,
        workspace,
        execution_mode: "assessment",
        approval_recorded: true,
        execution_started: true,
        next,
        summary: Some(summary),
    })
}

#[cfg(not(windows))]
pub fn assess_bambu(_: &Path, _: &Path, _: &str, _: bool) -> Result<AdminAssessmentResult> {
    bail!("admin assess Bambu requires Windows; no files or provider state were changed")
}

fn create_evidence_root(parent: &Path, run_id: &str) -> Result<PathBuf> {
    let parent = parent.canonicalize().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow!(AiwError {
                code: "AIW_ADMIN_EVIDENCE_NOT_READY".into(),
                summary: "evidence directory does not exist".into(),
                stage: "adminEvidenceRoot".into(),
                run_id: None,
                retryable: false,
                remediation: format!(
                    "Create {} as the current operator, then rerun this command. No intake or Sandbox session was created.",
                    parent.display()
                )
                .into(),
                detail: "The evidence parent must exist before assessment.".into(),
            })
        } else {
            anyhow!("evidence location could not be opened: {error}")
        }
    })?;
    if !parent.is_dir() {
        bail!("evidence location must be a directory");
    }
    let root = parent.join(run_id);
    std::fs::create_dir(&root).map_err(|_| {
        anyhow!("evidence location is occupied; choose a different evidence parent")
    })?;
    Ok(root)
}

fn save_stage(root: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    let path = root.join(format!("{name}.json"));
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(&bytes)?;
    Ok(())
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
fn now_rfc3339() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        day_seconds / 3_600,
        (day_seconds % 3_600) / 60,
        day_seconds % 60
    )
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value != "0".repeat(64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn lowercase_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    struct FixedGate {
        review_response: Option<String>,
        start: bool,
    }

    impl ApprovalGate for FixedGate {
        fn review(&self, _: &ApprovalReview) -> Result<Option<String>> {
            Ok(self.review_response.clone())
        }

        fn wait_for_start(&self, _: &ApprovalReview) -> Result<bool> {
            Ok(self.start)
        }
    }

    fn review_fixture() -> (PathBuf, ApprovalReview) {
        let root = std::env::temp_dir().join(format!(
            "aiw-admin-gate-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let plan = aiw_orchestrator::RunPlan::new(
            "gate-test",
            "project",
            "a".repeat(64),
            aiw_orchestrator::RunLifecycleKind::Assessment,
            "now",
            vec![aiw_orchestrator::PlannedAction::AssessHost],
            vec![],
        )
        .unwrap();
        let layout = RunLayout::new(&root, &plan.run_id).unwrap();
        layout.create(&plan).unwrap();
        let approval = ApprovalRecord::for_plan(&plan, "operator", "now").unwrap();
        (
            root.clone(),
            ApprovalReview {
                run_id: plan.run_id.clone(),
                workspace: root,
                evidence_root: PathBuf::from("evidence"),
                recipe: serde_json::json!({"fixed": true}),
                plan,
                proposed_approval: approval,
            },
        )
    }

    #[test]
    fn approval_gate_requires_the_exact_literal_and_cancellation_writes_nothing() {
        for response in [None, Some("approve wrong-hash".into())] {
            let (root, review) = review_fixture();
            let gate = FixedGate {
                review_response: response,
                start: true,
            };
            assert!(!approve_review(&gate, &review).unwrap());
            let layout = RunLayout::new(&root, &review.run_id).unwrap();
            assert!(layout.read_approval().is_err());
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn approval_gate_rejects_a_changed_persisted_plan() {
        let (root, review) = review_fixture();
        let gate = FixedGate {
            review_response: Some(format!("approve {}", review.proposed_approval.plan_hash)),
            start: true,
        };
        let changed = aiw_orchestrator::RunPlan::new(
            "gate-test",
            "changed-project",
            "b".repeat(64),
            aiw_orchestrator::RunLifecycleKind::Assessment,
            "now",
            vec![aiw_orchestrator::PlannedAction::AssessHost],
            vec![],
        )
        .unwrap();
        let layout = RunLayout::new(&root, &review.run_id).unwrap();
        std::fs::write(layout.plan_path(), serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(approve_review(&gate, &review).is_err());
        assert!(layout.read_approval().is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn approved_start_decline_leaves_a_durable_ready_run_without_acquisition() {
        let (root, review) = review_fixture();
        let gate = FixedGate {
            review_response: Some(format!("approve {}", review.proposed_approval.plan_hash)),
            start: false,
        };
        assert!(approve_review(&gate, &review).unwrap());
        assert!(!wait_for_start(&gate, &review).unwrap());
        let layout = RunLayout::new(&root, &review.run_id).unwrap();
        assert!(layout.read_approval().is_ok());
        assert!(matches!(
            layout.status().unwrap(),
            aiw_orchestrator::RecoveryStatus::Ready { .. }
        ));
        assert!(!layout.run_dir().join("receipt.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn export_failure_summary_preserves_completed_output_distinction() {
        let cases = [
            (
                document_export_error(
                    "run-one",
                    aiw_runner::RunnerError::Receipt("tampered".into()),
                ),
                "Export stopped:",
            ),
            (
                document_export_output_error("run-one", anyhow::anyhow!("broken pipe")),
                "Export completed, but console output failed:",
            ),
        ];
        for (error, prefix) in cases {
            let mut output = Vec::new();
            super::write_summary_error(&mut output, &error).unwrap();
            assert!(String::from_utf8(output).unwrap().starts_with(prefix));
        }
    }

    use super::*;
    #[test]
    fn missing_evidence_parent_gives_specific_safe_action() {
        let missing = std::env::temp_dir().join(format!(
            "aiw-admin-missing-evidence-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let error = public_error(create_evidence_root(&missing, "admin-test").unwrap_err());
        let structured = error.downcast_ref::<AiwError>().unwrap();
        assert_eq!(structured.code.as_ref(), "AIW_ADMIN_EVIDENCE_NOT_READY");
        assert!(structured.remediation.contains("Create"));
        assert!(
            structured
                .remediation
                .contains("No intake or Sandbox session was created")
        );
        assert!(!missing.exists());
    }

    #[test]
    fn approved_execution_error_preserves_run_and_retained_failure_paths() {
        let error = retained_execution_error(
            Path::new("evidence/admin-test"),
            "admin-test",
            "guest install timed out",
        );
        let structured = error.downcast_ref::<AiwError>().unwrap();
        assert_eq!(structured.code.as_ref(), "AIW_ADMIN_EXECUTION_FAILED");
        assert_eq!(structured.run_id.as_deref(), Some("admin-test"));
        assert!(structured.remediation.contains("failed-report.md"));
        assert!(structured.detail.contains("guest install timed out"));
    }

    #[test]
    fn summary_keeps_cancellation_distinct_and_escapes_evidence_path() {
        let result = AdminAssessmentResult {
            schema_version: MANIFEST_SCHEMA,
            product_id: PRODUCT_ID,
            operator_identity: "operator".into(),
            evidence_root: PathBuf::from("evidence-\u{1b}[2J"),
            run_id: "admin-test".into(),
            workspace: PathBuf::from("workspace"),
            execution_mode: "assessment",
            approval_recorded: false,
            execution_started: false,
            next: "Review the retained recipe.",
            summary: None,
        };
        let mut output = Vec::new();
        result.write_summary(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Approval cancelled. No Sandbox was started."));
        assert!(output.contains("evidence-\\u001b[2J"));
        assert!(!output.contains('\u{1b}'));
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("summary").is_none());
    }

    #[test]
    fn summary_error_preserves_action_without_terminal_controls() {
        let error = anyhow!(AiwError {
            code: "AIW_ADMIN_HOST_NOT_READY".into(),
            summary: "Sandbox busy".into(),
            stage: "adminReadiness".into(),
            run_id: Some("admin-test".into()),
            retryable: false,
            remediation: "Wait for the other session.\u{1b}[2J".into(),
            detail: "No worker acquired.".into(),
        });
        let mut output = Vec::new();
        write_summary_error(&mut output, &error).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("AIW_ADMIN_HOST_NOT_READY"));
        assert!(output.contains("Wait for the other session.\\u001b[2J"));
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn output_failure_does_not_claim_the_assessment_stopped() {
        let result = AdminAssessmentResult {
            schema_version: MANIFEST_SCHEMA,
            product_id: PRODUCT_ID,
            operator_identity: "operator".into(),
            evidence_root: PathBuf::from("evidence-\u{1b}[2J"),
            run_id: "admin-test".into(),
            workspace: PathBuf::from("workspace"),
            execution_mode: "assessment",
            approval_recorded: true,
            execution_started: true,
            next: "Read the report.",
            summary: Some("Fixed workflow results retained.\n".into()),
        };
        let error = AdminOutputFailed::from_result(&result, anyhow!("broken pipe"));
        let mut output = Vec::new();
        write_summary_error(&mut output, &error).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Assessment result retained, but console output failed."));
        assert!(output.contains("Do not repeat the trial"));
        assert!(output.contains("evidence-\\u001b[2J"));
        assert!(!output.contains("Assessment stopped"));
        assert!(!output.contains('\u{1b}'));
        let structured = error
            .downcast_ref::<AdminOutputFailed>()
            .unwrap()
            .structured_error();
        assert_eq!(structured.code.as_ref(), "AIW_ADMIN_OUTPUT_FAILED");
    }

    #[test]
    fn cancelled_output_failure_points_to_cancellation_record() {
        let result = AdminAssessmentResult {
            schema_version: MANIFEST_SCHEMA,
            product_id: PRODUCT_ID,
            operator_identity: "operator".into(),
            evidence_root: PathBuf::from("evidence"),
            run_id: "admin-cancelled".into(),
            workspace: PathBuf::from("workspace"),
            execution_mode: "assessment",
            approval_recorded: false,
            execution_started: false,
            next: "Use fresh evidence if later approved.",
            summary: None,
        };
        let error = AdminOutputFailed::from_result(&result, anyhow!("broken pipe"));
        let mut output = Vec::new();
        write_summary_error(&mut output, &error).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("No Sandbox was started"));
        assert!(output.contains("approval-cancelled.json"));
        assert!(!output.contains("retained report"));
        let structured = error
            .downcast_ref::<AdminOutputFailed>()
            .unwrap()
            .structured_error();
        assert!(structured.remediation.contains("approval-cancelled.json"));
        assert!(!structured.remediation.contains("retained report"));
    }

    #[test]
    fn manifest_paths_and_hash_are_fail_closed() {
        let manifest = ProductAssetManifest {
            schema_version: MANIFEST_SCHEMA.into(),
            product_id: PRODUCT_ID.into(),
            project_path: "../project.yaml".into(),
            project_sha256: "b".repeat(64),
            guest_agent_path: "tools/agent.exe".into(),
            scenario_id: SCENARIO_ID.into(),
            guest_agent_sha256: "a".repeat(64),
            launch_profile_path: None,
            launch_profile_sha256: None,
        };
        assert!(manifest.resolve(Path::new(".")).is_err());
    }
    #[test]
    fn manifest_rejects_placeholder_and_unpaired_profile_identity() {
        let manifest = ProductAssetManifest {
            schema_version: MANIFEST_SCHEMA.into(),
            product_id: PRODUCT_ID.into(),
            project_path: "project.yaml".into(),
            project_sha256: "b".repeat(64),
            guest_agent_path: "tools/agent.exe".into(),
            scenario_id: SCENARIO_ID.into(),
            guest_agent_sha256: "0".repeat(64),
            launch_profile_path: Some("profile.json".into()),
            launch_profile_sha256: None,
        };
        assert!(manifest.resolve(Path::new(".")).is_err());
    }
    #[test]
    fn bambu_manifest_rejects_profile_and_wrong_contract() {
        let mut manifest = ProductAssetManifest {
            schema_version: MANIFEST_SCHEMA.into(),
            product_id: BAMBU_PRODUCT_ID.into(),
            project_path: "project.json".into(),
            project_sha256: "a".repeat(64),
            guest_agent_path: "tools/agent.exe".into(),
            scenario_id: BAMBU_SCENARIO_ID.into(),
            guest_agent_sha256: "b".repeat(64),
            launch_profile_path: Some("profile.json".into()),
            launch_profile_sha256: Some("c".repeat(64)),
        };
        assert!(manifest.resolve_bambu(Path::new(".")).is_err());
        manifest.launch_profile_path = None;
        manifest.launch_profile_sha256 = None;
        manifest.scenario_id = SCENARIO_ID.into();
        assert!(manifest.resolve_bambu(Path::new(".")).is_err());
        manifest.scenario_id = BAMBU_SCENARIO_ID.into();
        manifest.project_path = "../project.json".into();
        assert!(manifest.resolve_bambu(Path::new(".")).is_err());
    }
    #[test]
    fn interactive_manifest_rejects_assessment_identity_and_launch_profile() {
        let root = std::env::temp_dir().join(format!("aiw-admin-interactive-{}", nonce()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("tools")).unwrap();
        std::fs::write(root.join("project.yaml"), b"project").unwrap();
        std::fs::write(root.join("tools/agent.exe"), b"agent").unwrap();
        let mut manifest = ProductAssetManifest {
            schema_version: MANIFEST_SCHEMA.into(),
            product_id: PRODUCT_ID.into(),
            project_path: "project.yaml".into(),
            project_sha256: "a".repeat(64),
            guest_agent_path: "tools/agent.exe".into(),
            scenario_id: SCENARIO_ID.into(),
            guest_agent_sha256: "b".repeat(64),
            launch_profile_path: None,
            launch_profile_sha256: None,
        };
        assert!(manifest.resolve_interactive(&root).is_err());
        manifest.product_id = INTERACTIVE_PRODUCT_ID.into();
        assert!(manifest.resolve_interactive(&root).is_ok());
        manifest.launch_profile_path = Some("launch-profile.json".into());
        manifest.launch_profile_sha256 = Some("c".repeat(64));
        assert!(manifest.resolve_interactive(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn export_package_rejects_project_drift_and_wrong_product() {
        let root = std::env::temp_dir().join(format!("aiw-export-assets-{}", nonce()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("tools")).unwrap();
        let project =
            include_bytes!("../../aiw-cli/product/notepad-plus-plus-interactive/project.yaml");
        std::fs::write(root.join("project.yaml"), project).unwrap();
        std::fs::write(root.join("tools/agent.exe"), b"agent").unwrap();
        let mut manifest = serde_json::json!({
            "schemaVersion": MANIFEST_SCHEMA,
            "productId": INTERACTIVE_PRODUCT_ID,
            "scenarioId": SCENARIO_ID,
            "projectPath": "project.yaml",
            "projectSha256": lowercase_sha256(project),
            "guestAgentPath": "tools/agent.exe",
            "guestAgentSha256": "a".repeat(64)
        });
        let save = |manifest: &serde_json::Value| {
            std::fs::write(
                root.join("manifest.json"),
                serde_json::to_vec(manifest).unwrap(),
            )
            .unwrap();
        };
        save(&manifest);
        assert!(interactive_export_assets(&root).is_ok());
        std::fs::write(root.join("project.yaml"), b"changed").unwrap();
        assert!(interactive_export_assets(&root).is_err());
        std::fs::write(root.join("project.yaml"), project).unwrap();
        manifest["productId"] = PRODUCT_ID.into();
        save(&manifest);
        assert!(interactive_export_assets(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn bambu_console_summary_does_not_promote_missing_evidence() {
        let project: Project =
            serde_json::from_str(include_str!("../../../examples/bambu-studio-export.json"))
                .unwrap();
        let report = aiw_runner::WsbBambuRunReport {
            schema_version: "aiw.dev/wsb-bambu-run-report/v0alpha1".into(),
            run_id: "admin-test".into(),
            project_revision_sha256: "a".repeat(64),
            request_sha256: "b".repeat(64),
            compiled_scenario: aiw_provider_wsb::compile_bambu_studio_export_scenario(
                &project,
                BAMBU_SCENARIO_ID,
            )
            .unwrap(),
            requested_assertions: project.assertions,
            outcome: aiw_orchestrator::RunOutcome::Failed,
            recorded_cleanup_verified: true,
            evidence_status: aiw_runner::BambuReportEvidenceStatus::Absent,
            receipt_sha256: None,
            evidence_root_hash: None,
            scenario: None,
            artifact: None,
            missing_evidence: vec!["ordinary baseline".into()],
        };
        let (summary, next) = bambu_report_summary(&report);
        assert!(summary.contains("Export 3MF: not measured"));
        assert!(summary.contains("Verify fixed 3MF geometry: not verified"));
        assert!(next.contains("does not establish application incompatibility"));
    }
    #[test]
    fn post_execution_publication_error_preserves_run_identity() {
        let error = retained_result_error(
            Path::new("retained-evidence"),
            "admin-test",
            "adminReport",
            "report drift",
        );
        let public = error.downcast_ref::<AiwError>().unwrap();
        assert_eq!(public.code.as_ref(), "AIW_ADMIN_RESULT_PUBLICATION_FAILED");
        assert_eq!(public.run_id.as_deref(), Some("admin-test"));
        assert!(public.remediation.contains("Do not repeat the trial"));
        assert!(public.detail.contains("report drift"));
    }
    #[test]
    fn unsupported_type_retains_a_specific_rejection_stage() {
        let root = std::env::temp_dir().join(format!("aiw-admin-rejection-{}", nonce()));
        std::fs::create_dir(&root).unwrap();
        let error = unsupported_installer_error(&root, "admin-test", "MSI extension required");
        let public = error.downcast_ref::<AiwError>().unwrap();
        assert_eq!(public.code.as_ref(), "AIW_ADMIN_UNSUPPORTED_INSTALLER");
        assert_eq!(public.run_id.as_deref(), Some("admin-test"));
        let retained: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("installer-rejection.json")).unwrap())
                .unwrap();
        assert_eq!(retained["supportedKind"], "msi");
        assert_eq!(retained["intakeCreated"], false);
        assert_eq!(retained["providerAcquired"], false);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn non_windows_route_cannot_start_provider() {
        #[cfg(not(windows))]
        assert!(
            assess(
                Path::new("installer.msi"),
                Path::new("."),
                "operator",
                false
            )
            .is_err()
        );
    }
}
