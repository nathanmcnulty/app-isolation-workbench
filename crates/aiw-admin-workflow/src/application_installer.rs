//! Review a bounded Windows Installer operation against existing protected intake.
use aiw_probe::{ApplicationFileImportReceipt, ApplicationInspectionKind};
use aiw_provider_wsb::msi_diagnostics::{
    MAX_MSI_INSTALL_LOG_BYTES, MSI_INSTALL_LOG_ARGUMENT, MSI_INSTALL_LOG_PATH,
};
use aiw_schema::{
    ApplicationArchitecture, ApplicationSource, NetworkIntent, Project, ScenarioStep,
};
use anyhow::{Result, anyhow};
use serde::Serialize;

const MAX_MSI_BYTES: u64 = 128 * 1024 * 1024;
const MAX_INSTALL_SECONDS: u32 = 300;
const GUEST_MSI: &str = r"C:\AIW\Tools\application.msi";
const UNSUPPORTED: &str = "AIW_MSI_PREVIEW_UNSUPPORTED";
const INVALID_INPUT: &str = "AIW_MSI_PREVIEW_INPUT_REJECTED";
const INTAKE_DRIFT: &str = "AIW_MSI_PREVIEW_INTAKE_DRIFT";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MsiInstallPreview {
    schema_version: &'static str,
    project_revision_sha256: String,
    scenario_id: String,
    intake_receipt_sha256: String,
    installer_sha256: String,
    installer_size_bytes: u64,
    installation: WindowsInstallerOperation,
    provider_calls: u32,
    installer_executions: u32,
    limitations: &'static [&'static str],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WindowsInstallerOperation {
    worker: &'static str,
    network: NetworkIntent,
    privilege: &'static str,
    requested_scope: &'static str,
    executable: &'static str,
    arguments: [&'static str; 7],
    max_install_log_observation_bytes: usize,
    timeout_seconds: u32,
    expected_exit_code: u32,
    reboot_exit_codes: [u32; 2],
}

pub fn plan_msi_install(
    project: &Project,
    scenario_id: &str,
    receipt: &ApplicationFileImportReceipt,
    timeout_seconds: u32,
) -> Result<MsiInstallPreview> {
    let installation = compile_operation(
        project,
        scenario_id,
        receipt.source_kind,
        &receipt.sha256,
        receipt.size_bytes,
        timeout_seconds,
    )?;
    let held =
        aiw_windows_platform::open_verified_application_file_import(receipt).map_err(|_| {
            blocked(
                INTAKE_DRIFT,
                "Protected MSI intake did not match its receipt",
            )
        })?;
    let preview = MsiInstallPreview {
        schema_version: "aiw.dev/msi-install-preview/v0alpha2",
        project_revision_sha256: aiw_orchestrator::project_revision_hash(project)?,
        scenario_id: scenario_id.into(),
        intake_receipt_sha256: held.verification().receipt_sha256.clone(),
        installer_sha256: receipt.sha256.clone(),
        installer_size_bytes: receipt.size_bytes,
        installation,
        provider_calls: 0,
        installer_executions: 0,
        limitations: &[
            "Review only. This preview grants no execution authority and is not an importable run plan.",
            "Architecture and machine scope are requested. Package metadata, embedded media, dependencies, custom actions and actual registration are unmeasured.",
            "The planned worker keeps flushed Installer logging guest-local. The observation limit caps diagnostic reads.",
            "Application entry points, compatibility and effective isolation are unmeasured.",
        ],
    };
    held.revalidate()
        .map_err(|_| blocked(INTAKE_DRIFT, "Protected MSI intake changed during preview"))?;
    Ok(preview)
}

fn blocked(code: &str, summary: &str) -> anyhow::Error {
    anyhow!(aiw_orchestrator::AiwError {
        code: code.into(),
        summary: summary.into(),
        stage: "msiInstallPreview".into(),
        run_id: None,
        retryable: false,
        remediation: "Check the selected project scenario and verify the protected intake receipt before retrying.".into(),
        detail: "The preview produced no installation plan.".into(),
    })
}

fn compile_operation(
    project: &Project,
    scenario_id: &str,
    intake_kind: ApplicationInspectionKind,
    intake_sha256: &str,
    intake_size: u64,
    timeout_seconds: u32,
) -> Result<WindowsInstallerOperation> {
    if !aiw_schema::validate_project_for_planning(project).is_empty() {
        return Err(blocked(
            INVALID_INPUT,
            "Project validation refused MSI install planning",
        ));
    }
    let ApplicationSource::Msi(source) = &project.application else {
        return Err(blocked(
            UNSUPPORTED,
            "MSI install planning requires an MSI application source",
        ));
    };
    if source.architecture != ApplicationArchitecture::X64 {
        return Err(blocked(
            UNSUPPORTED,
            "MSI install planning requires a declared x64 package",
        ));
    }
    if source.may_reboot || source.update_uninstall.is_some() || source.expected_signer.is_some() {
        return Err(blocked(
            UNSUPPORTED,
            "Reboot, update, uninstall and signer requirements are outside this MSI preview",
        ));
    }
    if !source.silent_arguments.is_empty() {
        return Err(blocked(
            UNSUPPORTED,
            "Custom properties, transforms and arguments are outside the fixed Windows Installer operation",
        ));
    }
    if intake_kind != ApplicationInspectionKind::Msi || intake_sha256 != source.sha256 {
        return Err(blocked(
            INTAKE_DRIFT,
            "Protected intake MSI kind or SHA-256 differs from the project",
        ));
    }
    if !(1..=MAX_MSI_BYTES).contains(&intake_size) {
        return Err(blocked(
            INVALID_INPUT,
            "Protected MSI intake size must be between 1 byte and 128 MiB",
        ));
    }
    if !(1..=MAX_INSTALL_SECONDS).contains(&timeout_seconds) {
        return Err(blocked(
            INVALID_INPUT,
            "MSI install timeout must be between 1 and 300 seconds",
        ));
    }
    let intent = &project.isolation_intent;
    if intent.network != NetworkIntent::Blocked
        || intent.allow_clipboard
        || intent.allow_host_file_access
        || intent.allow_host_registry_access
    {
        return Err(blocked(
            UNSUPPORTED,
            "MSI install preview requires an offline disposable worker with no clipboard or host access",
        ));
    }
    if !project.extensions.is_empty()
        || !project.secrets.is_empty()
        || project.analyst.is_some()
        || project
            .candidates
            .iter()
            .any(|candidate| !candidate.extensions.is_empty())
    {
        return Err(blocked(
            UNSUPPORTED,
            "Extensions, secrets and analyst execution are outside this MSI preview",
        ));
    }
    let Some(scenario) = project
        .scenarios
        .iter()
        .find(|scenario| scenario.id == scenario_id)
    else {
        return Err(blocked(
            INVALID_INPUT,
            "Selected MSI install scenario does not exist",
        ));
    };
    if scenario.steps != [ScenarioStep::Install] {
        return Err(blocked(
            UNSUPPORTED,
            "MSI preview requires exactly one install step; application launch and later operations need a separate capability",
        ));
    }

    Ok(WindowsInstallerOperation {
        worker: "disposableWindowsSandbox",
        network: NetworkIntent::Blocked,
        privilege: "elevatedInsideWorker",
        requested_scope: "perMachine",
        executable: r"C:\Windows\System32\msiexec.exe",
        arguments: [
            "/i",
            GUEST_MSI,
            "/qn",
            "/norestart",
            "ALLUSERS=1",
            MSI_INSTALL_LOG_ARGUMENT,
            MSI_INSTALL_LOG_PATH,
        ],
        max_install_log_observation_bytes: MAX_MSI_INSTALL_LOG_BYTES,
        timeout_seconds,
        expected_exit_code: 0,
        reboot_exit_codes: [1641, 3010],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> Project {
        serde_json::from_value(serde_json::json!({
            "schemaVersion": aiw_schema::PROJECT_SCHEMA_VERSION,
            "kind": aiw_schema::PROJECT_KIND,
            "metadata": {"name":"unlisted-msi","displayName":"Unlisted installer","owner":"local"},
            "application": {"type":"msi","path":"input.msi","sha256":"a".repeat(64),"architecture":"x64"},
            "isolationIntent": {
                "runtimeBoundary":"windowsSandbox","network":"blocked","allowClipboard":false,
                "allowHostFileAccess":false,"allowHostRegistryAccess":false,"requireDescendantCoverage":false
            },
            "candidates": [{"id":"ordinary","type":"unpackagedBaseline","config":{"type":"baseline"}}],
            "scenarios": [{"id":"install","description":"Review install only","steps":[{"type":"install"}]}]
        }))
        .unwrap()
    }

    fn compile(project: &Project) -> Result<WindowsInstallerOperation> {
        compile_operation(
            project,
            "install",
            ApplicationInspectionKind::Msi,
            &"a".repeat(64),
            4096,
            300,
        )
    }

    #[test]
    fn machine_install_is_fixed_across_application_names() {
        let mut project = project();
        let first = compile(&project).unwrap();
        project.metadata.name = "different-installer".into();
        project.metadata.display_name = "Another title".into();
        let renamed = compile(&project).unwrap();
        assert_eq!(
            serde_json::to_value(&first).unwrap(),
            serde_json::to_value(&renamed).unwrap()
        );
        assert_eq!(
            first.arguments,
            [
                "/i",
                GUEST_MSI,
                "/qn",
                "/norestart",
                "ALLUSERS=1",
                MSI_INSTALL_LOG_ARGUMENT,
                MSI_INSTALL_LOG_PATH,
            ]
        );
        assert_eq!(
            first.max_install_log_observation_bytes,
            MAX_MSI_INSTALL_LOG_BYTES
        );
        assert_eq!(first.expected_exit_code, 0);
        assert_eq!(first.reboot_exit_codes, [1641, 3010]);
    }

    #[test]
    fn mismatched_intake_kind_hash_size_scenario_and_timeout_are_refused() {
        let project = project();
        for (scenario, kind, hash, size, timeout) in [
            ("install", ApplicationInspectionKind::Exe, "a", 4096, 30),
            ("install", ApplicationInspectionKind::Msi, "b", 4096, 30),
            ("install", ApplicationInspectionKind::Msi, "a", 0, 30),
            (
                "install",
                ApplicationInspectionKind::Msi,
                "a",
                MAX_MSI_BYTES + 1,
                30,
            ),
            ("install", ApplicationInspectionKind::Msi, "a", 4096, 0),
            (
                "install",
                ApplicationInspectionKind::Msi,
                "a",
                4096,
                MAX_INSTALL_SECONDS + 1,
            ),
            ("unknown", ApplicationInspectionKind::Msi, "a", 4096, 30),
        ] {
            assert!(
                compile_operation(&project, scenario, kind, &hash.repeat(64), size, timeout)
                    .is_err()
            );
        }
    }

    #[test]
    fn unsupported_install_controls_and_extra_steps_are_refused() {
        let mut custom = project();
        let ApplicationSource::Msi(source) = &mut custom.application else {
            unreachable!()
        };
        source
            .silent_arguments
            .push("TRANSFORMS=external.mst".into());
        assert!(
            compile(&custom)
                .unwrap_err()
                .to_string()
                .contains("transforms")
        );
        let mut reboot = project();
        let ApplicationSource::Msi(source) = &mut reboot.application else {
            unreachable!()
        };
        source.may_reboot = true;
        assert!(compile(&reboot).is_err());

        let mut network = project();
        network.isolation_intent.network = NetworkIntent::Allowed;
        assert!(compile(&network).is_err());

        let mut steps = project();
        steps.scenarios[0]
            .steps
            .push(ScenarioStep::ExpectExitCode { value: 0 });
        assert!(
            compile(&steps)
                .unwrap_err()
                .to_string()
                .contains("exactly one install step")
        );
    }
}
