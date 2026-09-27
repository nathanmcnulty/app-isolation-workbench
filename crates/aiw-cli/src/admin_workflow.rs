use std::io::{IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use aiw_orchestrator::{AiwError, ApprovalRecord, RunLayout};
use aiw_probe::{ApplicationInspectionKind, ReadinessState, inspect_application_source};
use aiw_schema::{ApplicationSource, Project, validate_project_for_planning};

use crate::approval_review;

pub const MANIFEST_SCHEMA: &str = "aiw.dev/admin-product-assets/v0alpha1";
pub const PRODUCT_ID: &str = "notepad-plus-plus-local-settings";
pub const SCENARIO_ID: &str = "install-launch-close";

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
    write!(output, "Assessment stopped: ")?;
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
    pub next: &'static str,
    #[serde(skip)]
    summary: Option<String>,
}

impl AdminAssessmentResult {
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
        aiw_runner::WsbMsiRunReport::InteractiveSession(_) => (
            "No completed application assessment. This result needs detailed review.\n".into(),
            "Read report.md and the exact run status before a new trial.",
        ),
    }
}

impl ProductAssetManifest {
    fn resolve(&self, package_root: &Path) -> Result<ResolvedProductAssets> {
        if self.schema_version != MANIFEST_SCHEMA
            || self.product_id != PRODUCT_ID
            || self.scenario_id != SCENARIO_ID
            || !valid_sha256(&self.project_sha256)
            || !valid_sha256(&self.guest_agent_sha256)
            || self
                .launch_profile_sha256
                .as_deref()
                .is_some_and(|value| !valid_sha256(value))
            || self.launch_profile_path.is_some() != self.launch_profile_sha256.is_some()
        {
            bail!("packaged product manifest is not the fixed Notepad++ assessment contract");
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
            project: resolve(&self.project_path, ".yaml")?,
            guest_agent: resolve(&self.guest_agent_path, ".exe")?,
            launch_profile: self
                .launch_profile_path
                .as_deref()
                .map(|path| resolve(path, ".json"))
                .transpose()?,
        })
    }
}

fn packaged_asset_root() -> Result<PathBuf> {
    let executable = std::env::current_exe()
        .map_err(|_| anyhow!("cannot resolve the installed AIW executable"))?;
    let parent = executable
        .parent()
        .ok_or_else(|| anyhow!("installed AIW executable has no package directory"))?;
    Ok(parent.join("product").join("notepad-plus-plus"))
}

fn unsupported_installer_error(
    evidence_root: &Path,
    run_id: &str,
    reason: impl Into<String>,
) -> anyhow::Error {
    let reason = reason.into();
    let diagnostic_path = evidence_root.join("installer-rejection.json");
    let diagnostic = serde_json::json!({
        "schemaVersion": "aiw.dev/admin-installer-rejection/v0alpha1",
        "runId": run_id,
        "supportedKind": "msi",
        "reason": reason,
        "intakeCreated": false,
        "providerAcquired": false
    });
    let diagnostic_status = save_stage(evidence_root, "installer-rejection", &diagnostic)
        .map(|_| format!("Inspect {}.", diagnostic_path.display()))
        .unwrap_or_else(|error| format!("Diagnostic publication failed safely: {error}."));
    anyhow!(AiwError {
        code: "AIW_ADMIN_UNSUPPORTED_INSTALLER".into(),
        summary: "installer is not supported by this Notepad++ MSI profile".into(),
        stage: "adminInstallerInspection".into(),
        run_id: Some(run_id.into()),
        retryable: false,
        remediation: format!(
            "{diagnostic_status} Select the exact supported MSI bytes; do not guess a recipe for another application type."
        )
        .into(),
        detail: "No protected intake was created and no Sandbox session was acquired.".into(),
    })
}

#[cfg(windows)]
pub fn assess(
    installer: &Path,
    evidence_parent: &Path,
    identity: &str,
) -> Result<AdminAssessmentResult> {
    if identity.trim().is_empty() {
        bail!("operator identity is required");
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        bail!(
            "admin assess requires terminal input and visible approval review; no intake or run was created"
        );
    }
    let assets_root = packaged_asset_root()?;
    let manifest: ProductAssetManifest = serde_json::from_slice(
        &std::fs::read(assets_root.join("manifest.json"))
            .map_err(|_| anyhow!("packaged product manifest is missing"))?,
    )?;
    let assets = manifest.resolve(&assets_root)?;
    let project_bytes = std::fs::read(&assets.project)?;
    if lowercase_sha256(&project_bytes) != manifest.project_sha256 {
        bail!("packaged project bytes do not match the product manifest");
    }
    let project: Project = serde_yaml::from_slice(&project_bytes)?;
    if !validate_project_for_planning(&project).is_empty() || project.metadata.name != PRODUCT_ID {
        bail!("packaged project is not valid for the fixed assessment");
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
    let execution_mode = if launch_profile.is_some() {
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
    let prepared = aiw_runner::prepare_windows_sandbox_msi_bundle(&run_id, &project, &assets.guest_agent, &manifest.guest_agent_sha256, &evidence_root, &now_rfc3339(), aiw_runner::WsbMsiPreparationInput { import_receipt: &receipt, scenario_id: SCENARIO_ID, document_input: None, launch_profile: launch_profile.as_ref().zip(manifest.launch_profile_sha256.as_deref()) })
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
    {
        let mut terminal = std::io::stderr().lock();
        writeln!(
            terminal,
            "Review the complete verified recipe before approval (mode: {execution_mode}):\n"
        )?;
        approval_review::write_review_json(&mut terminal, &recipe)?;
        writeln!(terminal, "\n")?;
        terminal.flush()?;
    }
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
    if !approval_review::confirm(
        &approval,
        &plan,
        std::io::stdin().lock(),
        std::io::stderr().lock(),
    )? {
        save_stage(
            &evidence_root,
            "approval-cancelled",
            &serde_json::json!({"runId": run_id, "approvalRecorded": false, "next": "Review the retained recipe, then rerun this command with a fresh evidence location when ready to approve."}),
        )?;
        return Ok(AdminAssessmentResult {
            schema_version: MANIFEST_SCHEMA,
            product_id: PRODUCT_ID,
            operator_identity: identity.trim().into(),
            evidence_root,
            run_id,
            workspace,
            execution_mode,
            approval_recorded: false,
            next: "Approval was cancelled. The run remains pending approval; no Sandbox was started.",
            summary: None,
        });
    }
    layout.write_approval(&approval)?;
    save_stage(&evidence_root, "approval", &approval)?;
    let execution = match aiw_runner::start_approved_windows_sandbox(
        &workspace,
        &assets.project,
        &project,
        &manifest.guest_agent_sha256,
        900,
    ) {
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
            bail!(
                "execution failed; retained status/report diagnostics were attempted. Inspect this exact run and only run explicit recovery when status reports recovery required: {error}"
            );
        }
    };
    save_stage(&evidence_root, "execution", &execution)?;
    let report = aiw_runner::report_windows_sandbox_msi_run(
        &workspace,
        &run_id,
        &project,
        &manifest.guest_agent_sha256,
    )
    .map_err(|error| {
        anyhow!("run ended without a report; retain evidence and inspect status: {error}")
    })?;
    save_stage(&evidence_root, "report", &report)?;
    std::fs::write(evidence_root.join("report.md"), report.to_markdown())?;
    let (summary, next) = report_summary(&report);
    Ok(AdminAssessmentResult {
        schema_version: MANIFEST_SCHEMA,
        product_id: PRODUCT_ID,
        operator_identity: identity.trim().into(),
        evidence_root,
        run_id,
        workspace,
        execution_mode,
        approval_recorded: true,
        next,
        summary: Some(summary),
    })
}

#[cfg(not(windows))]
pub fn assess(_: &Path, _: &Path, _: &str) -> Result<AdminAssessmentResult> {
    bail!("admin assess requires Windows; no files or provider state were changed")
}

fn create_evidence_root(parent: &Path, run_id: &str) -> Result<PathBuf> {
    let parent = parent
        .canonicalize()
        .map_err(|_| anyhow!("evidence location must already exist"))?;
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
    use super::*;
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
        assert!(assess(Path::new("installer.msi"), Path::new("."), "operator").is_err());
    }
}
