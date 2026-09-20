use std::io::{IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use aiw_orchestrator::{ApprovalRecord, RunLayout};
use aiw_probe::{ApplicationInspectionKind, ReadinessState, inspect_application_source};
use aiw_schema::{ApplicationSource, Project, validate_project_for_planning};

use crate::approval_review;

pub const MANIFEST_SCHEMA: &str = "aiw.dev/admin-product-assets/v0alpha1";
pub const PRODUCT_ID: &str = "notepad-plus-plus-local-settings";
pub const SCENARIO_ID: &str = "install-launch-close";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductAssetManifest {
    schema_version: String,
    product_id: String,
    project_path: String,
    guest_agent_path: String,
    scenario_id: String,
    guest_agent_sha256: String,
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
    pub approval_recorded: bool,
    pub next: &'static str,
}

impl ProductAssetManifest {
    fn resolve(&self, package_root: &Path) -> Result<(PathBuf, PathBuf)> {
        if self.schema_version != MANIFEST_SCHEMA
            || self.product_id != PRODUCT_ID
            || self.scenario_id != SCENARIO_ID
            || !valid_sha256(&self.guest_agent_sha256)
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
        Ok((
            resolve(&self.project_path, ".yaml")?,
            resolve(&self.guest_agent_path, ".exe")?,
        ))
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
    let (project_path, guest_agent) = manifest.resolve(&assets_root)?;
    let project: Project = serde_yaml::from_slice(&std::fs::read(&project_path)?)?;
    if !validate_project_for_planning(&project).is_empty() || project.metadata.name != PRODUCT_ID {
        bail!("packaged project is not valid for the fixed assessment");
    }
    let expected_msi = match &project.application {
        ApplicationSource::Msi(source) => &source.sha256,
        _ => bail!("packaged project is not an MSI assessment"),
    };
    let expected_agent = aiw_windows_platform::HeldApplicationFile::open(&guest_agent)
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
        bail!(
            "host readiness blocks this assessment; inspect host-readiness.json. AIW did not create intake, acquire, recover, or stop a Sandbox session"
        );
    }
    let held = aiw_windows_platform::HeldApplicationFile::open_with_download_metadata(installer)
        .map_err(|error| anyhow!("installer is unsupported: {error}"))?;
    let inspection = inspect_application_source(installer, ApplicationInspectionKind::Msi)
        .map_err(|error| anyhow!("installer is unsupported: {error}"))?;
    if inspection.sha256.as_deref() != Some(&held.observation().sha256)
        || inspection.sha256.as_deref() != Some(expected_msi.as_str())
    {
        bail!(
            "installer bytes are unsupported for the packaged Notepad++ profile; no intake or Sandbox run was created"
        );
    }
    held.revalidate()
        .map_err(|error| anyhow!("installer drifted before protected intake: {error}"))?;
    save_stage(&evidence_root, "installer-inspection", &inspection)?;
    let intake_parent = evidence_root.join("intakes");
    std::fs::create_dir(&intake_parent)?;
    let receipt = aiw_windows_platform::import_application_file_with_metadata(&intake_parent, "notepad-plus-plus", ApplicationInspectionKind::Msi, &held, true)
        .map_err(|error| anyhow!("protected intake failed; preserve evidence and use a new evidence location to retry: {error}"))?;
    save_stage(&evidence_root, "intake-receipt", &receipt)?;
    let prepared = aiw_runner::prepare_windows_sandbox_msi_bundle(&run_id, &project, &guest_agent, &manifest.guest_agent_sha256, &evidence_root, &now_rfc3339(), aiw_runner::WsbMsiPreparationInput { import_receipt: &receipt, scenario_id: SCENARIO_ID, document_input: None, launch_profile: None })
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
    let approval = ApprovalRecord::for_plan(&plan, identity.trim(), &now_rfc3339())?;
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
            approval_recorded: false,
            next: "Approval was cancelled. The run remains pending approval; no Sandbox was started.",
        });
    }
    layout.write_approval(&approval)?;
    save_stage(&evidence_root, "approval", &approval)?;
    let execution = match aiw_runner::start_approved_windows_sandbox(
        &workspace,
        &project_path,
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
    Ok(AdminAssessmentResult {
        schema_version: MANIFEST_SCHEMA,
        product_id: PRODUCT_ID,
        operator_identity: identity.trim().into(),
        evidence_root,
        run_id,
        workspace,
        approval_recorded: true,
        next: "Assessment completed. Read report.md; use the retained run status for any later recovery decision.",
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_paths_and_hash_are_fail_closed() {
        let manifest = ProductAssetManifest {
            schema_version: MANIFEST_SCHEMA.into(),
            product_id: PRODUCT_ID.into(),
            project_path: "../project.yaml".into(),
            guest_agent_path: "tools/agent.exe".into(),
            scenario_id: SCENARIO_ID.into(),
            guest_agent_sha256: "a".repeat(64),
        };
        assert!(manifest.resolve(Path::new(".")).is_err());
    }
    #[test]
    fn non_windows_route_cannot_start_provider() {
        #[cfg(not(windows))]
        assert!(assess(Path::new("installer.msi"), Path::new("."), "operator").is_err());
    }
}
