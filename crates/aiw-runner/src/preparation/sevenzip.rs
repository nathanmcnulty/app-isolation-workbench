//! Non-executing, exact protected intake for the closed 7-Zip assessment.
use super::*;
pub const SEVENZIP_PREPARATION_SCHEMA: &str = "aiw.dev/wsb-preparation-receipt/v0alpha9";
pub const SEVENZIP_INSTALLER_FILE: &str = "7z2605-x64.exe";
pub const SEVENZIP_LAUNCHER_FILE: &str = "sevenzip_assessment.exe";
pub const SEVENZIP_TRUST_DELTA: &str = "installs the fixed approved 7-Zip 26.05 x64 installer with elevated guest authority inside one disposable offline Windows Sandbox; runs the same create/test/extract/verify archive workflow as a standard-user baseline and classic AppContainer with zero capabilities, read-only input and writable output grants; measures held target tokens and fixed file access controls; no automatic host export, general compatibility or effective-isolation verdict";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbSevenZipInstaller {
    pub import_receipt: aiw_probe::ApplicationFileImportReceipt,
    pub import_receipt_sha256: String,
    pub staged_payload: BinaryIdentity,
    pub staged_identity: WindowsFileIdentity,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbSevenZipAssessment {
    pub profile: aiw_probe::SevenZipProfile,
    pub installer: WsbSevenZipInstaller,
    pub launcher: WsbMsiDocument,
}
impl WsbSevenZipAssessment {
    pub(crate) fn validate(
        &self,
        workspace: &WorkspaceBindingEvidence,
        agent: &BinaryIdentity,
    ) -> Result<(), WsbPreparationError> {
        self.profile
            .validate()
            .map_err(WsbPreparationError::Contract)?;
        self.validate_historical(workspace, agent)
    }
    pub(crate) fn validate_historical(
        &self,
        workspace: &WorkspaceBindingEvidence,
        agent: &BinaryIdentity,
    ) -> Result<(), WsbPreparationError> {
        self.profile
            .validate_historical()
            .map_err(WsbPreparationError::Contract)?;
        let import = &self.installer.import_receipt;
        let bytes =
            serde_json::to_vec(import).map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
        if !matches!(
            import.schema_version.as_str(),
            aiw_probe::APPLICATION_FILE_IMPORT_RECEIPT_SCHEMA
                | aiw_probe::APPLICATION_DOWNLOAD_IMPORT_RECEIPT_SCHEMA
        ) || import.source_kind != aiw_probe::ApplicationInspectionKind::Exe
            || import.sha256 != self.profile.installer_sha256
            || import.size_bytes != self.profile.installer_size_bytes
            || hex::encode(Sha256::digest(bytes)) != self.installer.import_receipt_sha256
            || self.profile.agent_sha256 != agent.sha256
            || self.profile.agent_size_bytes != agent.size_bytes
        {
            return Err(WsbPreparationError::Contract(
                "7-Zip protected installer receipt or agent binding rejected".into(),
            ));
        }
        for (name, payload, identity, hash, size) in [
            (
                SEVENZIP_INSTALLER_FILE,
                &self.installer.staged_payload,
                &self.installer.staged_identity,
                &self.profile.installer_sha256,
                self.profile.installer_size_bytes,
            ),
            (
                SEVENZIP_LAUNCHER_FILE,
                &self.launcher.staged_payload,
                &self.launcher.staged_identity,
                &self.profile.launcher_sha256,
                self.profile.launcher_size_bytes,
            ),
        ] {
            if payload.sha256 != *hash
                || payload.size_bytes != size
                || payload.version.is_some()
                || payload.signature_status != ReadinessState::Unknown
                || normalized_windows_path(&payload.canonical_path)
                    != format!(
                        "{}\\{name}",
                        normalized_windows_path(&workspace.tools.final_path)
                    )
                || normalized_windows_path(&identity.final_path)
                    != normalized_windows_path(&payload.canonical_path)
                || identity.volume_serial_number != workspace.tools.volume_serial_number
            {
                return Err(WsbPreparationError::Contract(
                    "7-Zip staged fixed role identity rejected".into(),
                ));
            }
        }
        Ok(())
    }
}

pub fn build_wsb_sevenzip_preparation(
    base: PreparedWsbArtifacts,
    assessment: WsbSevenZipAssessment,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    // The static base is an intermediate identity observation; it deliberately
    // cannot validate as a complete golden/paired receipt. Validate the completed
    // exclusive 7-Zip artifacts, including every common identity, below.
    finish_sevenzip_preparation(base, assessment)
}
fn finish_sevenzip_preparation(
    mut base: PreparedWsbArtifacts,
    assessment: WsbSevenZipAssessment,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    assessment.validate(&base.receipt.workspace, &base.receipt.guest_agent)?;
    if base.receipt.msi.is_some()
        || base.receipt.bambu.is_some()
        || base.receipt.paired_controls.is_some()
        || base.receipt.seven_zip.is_some()
        || base.receipt.host_os_version.as_ref() != Some(assessment.profile.approved_host_windows())
        || base.receipt.provider_protocol_observation.is_none()
    {
        return Err(WsbPreparationError::Contract(
            "7-Zip preparation requires fresh exclusive profile and static exact host observation"
                .into(),
        ));
    }
    base.wsb_plan.probe.output = GUEST_MSI_RESULT.into();
    base.receipt.wsb_plan_sha256 = canonical_hash(&base.wsb_plan)?;
    base.run_plan = RunPlan::new(
        &base.receipt.run_id,
        &base.receipt.project_id,
        &base.receipt.project_revision_sha256,
        RunLifecycleKind::Assessment,
        &base.receipt.created_at,
        vec![
            PlannedAction::AssessHost,
            PlannedAction::PrepareWorkspace,
            PlannedAction::ExecuteWindowsSandboxSevenZipAssessment {
                sandbox_plan_sha256: base.receipt.wsb_plan_sha256.clone(),
                provider_sha256: base.receipt.provider.sha256.clone(),
                guest_agent_sha256: base.receipt.guest_agent.sha256.clone(),
                workspace: Box::new(base.receipt.workspace.clone()),
                workspace_identity_sha256: base.receipt.workspace_identity_sha256.clone(),
                import_receipt_sha256: assessment.installer.import_receipt_sha256.clone(),
                application_sha256: assessment.profile.installer_sha256.clone(),
                profile: Box::new(assessment.profile.clone()),
            },
            PlannedAction::CollectEvidence,
        ],
        vec![SEVENZIP_TRUST_DELTA.into(), TRUST_DELTA_MAPPINGS.into()],
    )
    .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
    base.receipt.run_plan_sha256 = base
        .run_plan
        .hash()
        .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
    base.receipt.schema_version = SEVENZIP_PREPARATION_SCHEMA.into();
    base.receipt.seven_zip = Some(assessment);
    base.validate()?;
    Ok(base)
}
#[allow(clippy::too_many_arguments)]
pub fn build_wsb_static_sevenzip_preparation(
    run_id: &str,
    project: &Project,
    identity: &aiw_probe::WindowsSandboxStaticIdentity,
    workspace: &WorkspaceBindingEvidence,
    agent: &BinaryIdentity,
    created_at: &str,
    assessment: WsbSevenZipAssessment,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    let trusted = require_static_identity(identity)?;
    let protocol = WindowsSandboxCliProtocol {
        cli_version: PINNED_CLI_VERSION.into(),
        protocol: PINNED_CLI_PROTOCOL.into(),
        list_schema: PINNED_LIST_SCHEMA.into(),
    };
    let base = build_preparation_identity(
        run_id,
        project,
        workspace,
        agent,
        created_at,
        trusted,
        &identity.schema_version,
        Some(&identity.os_version),
        &protocol,
        true,
    )?;
    finish_sevenzip_preparation(base, assessment)
}
#[cfg(windows)]
pub(crate) fn open_sevenzip_files(
    workspace: &aiw_windows_platform::HeldRunWorkspace,
    receipt: &WsbPreparationReceipt,
) -> Result<paired::HeldControlFiles, WsbPreparationError> {
    let Some(assessment) = &receipt.seven_zip else {
        return Ok(vec![]);
    };
    require_tools(&workspace.tools_path())?;
    let mut held = vec![];
    for (leaf, payload, identity) in [
        (
            SEVENZIP_LAUNCHER_FILE,
            &assessment.launcher.staged_payload,
            &assessment.launcher.staged_identity,
        ),
        (
            SEVENZIP_INSTALLER_FILE,
            &assessment.installer.staged_payload,
            &assessment.installer.staged_identity,
        ),
    ] {
        let file = workspace
            .reopen_tools_file_readonly(leaf)
            .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
        let observed = aiw_windows_platform::HeldApplicationFile::open(file.final_path())
            .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
        if file.identity() != identity
            || observed.observation().identity != *identity
            || observed.observation().sha256 != payload.sha256
            || observed.observation().size_bytes != payload.size_bytes
        {
            return Err(WsbPreparationError::Contract(
                "7-Zip retained role drifted".into(),
            ));
        }
        held.push((file, observed));
    }
    Ok(held)
}
#[cfg(windows)]
pub(crate) fn require_tools(path: &Path) -> Result<(), WsbPreparationError> {
    let mut observed = std::fs::read_dir(path)
        .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
    let mut expected = vec![
        GUEST_AGENT_FILE.to_owned(),
        SEVENZIP_INSTALLER_FILE.to_owned(),
        SEVENZIP_LAUNCHER_FILE.to_owned(),
    ];
    observed.sort();
    expected.sort();
    if observed != expected {
        return Err(WsbPreparationError::Contract(
            "7-Zip closed Tools inventory differs".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
pub fn prepare_windows_sandbox_sevenzip_assessment(
    workspace_parent: &Path,
    run_id: &str,
    project: &Project,
    agent_source: &Path,
    agent_sha256: &str,
    import_receipt: &aiw_probe::ApplicationFileImportReceipt,
    created_at: &str,
    expected_guest_windows: &aiw_probe::WindowsVersionObservation,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    prepare_sevenzip_with_inspector(
        workspace_parent,
        run_id,
        project,
        agent_source,
        agent_sha256,
        import_receipt,
        created_at,
        expected_guest_windows,
        &NativePreparationProviderInspector,
    )
}
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_sevenzip_with_inspector(
    workspace_parent: &Path,
    run_id: &str,
    project: &Project,
    agent_source: &Path,
    agent_sha256: &str,
    import_receipt: &aiw_probe::ApplicationFileImportReceipt,
    created_at: &str,
    expected_guest_windows: &aiw_probe::WindowsVersionObservation,
    inspector: &dyn PreparationProviderInspector,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    use aiw_probe::sevenzip::{SEVENZIP_INSTALLER_SHA256, SEVENZIP_INSTALLER_SIZE_BYTES};
    use aiw_windows_platform::{HeldApplicationFile, HeldRunWorkspace};
    validate_request_contract(run_id, project, created_at)?;
    expected_guest_windows
        .validate()
        .map_err(WsbPreparationError::Contract)?;
    if expected_guest_windows.observer_architecture != "x86_64"
        || import_receipt.source_kind != aiw_probe::ApplicationInspectionKind::Exe
        || import_receipt.sha256 != SEVENZIP_INSTALLER_SHA256
        || import_receipt.size_bytes != SEVENZIP_INSTALLER_SIZE_BYTES
    {
        return Err(WsbPreparationError::Contract(
            "7-Zip pinned intake/exact guest requirement rejected".into(),
        ));
    }
    let mut source = open_guest_agent_source(agent_source, agent_sha256)?;
    let mut intake = aiw_windows_platform::open_verified_application_file_import(import_receipt)
        .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
    let identity = inspector
        .static_identity()
        .map_err(WsbPreparationError::Readiness)?;
    require_static_identity(&identity)?;
    let workspace = HeldRunWorkspace::create(workspace_parent, run_id)
        .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
    let operation = (|| {
        let (writer, agent) = stage_guest_agent(&mut source, &workspace)?;
        drop(writer);
        let agent_file = workspace
            .reopen_tools_file_readonly(GUEST_AGENT_FILE)
            .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
        let held_agent = HeldApplicationFile::open(agent_file.final_path())
            .map_err(|e| WsbPreparationError::GuestAgent(e.to_string()))?;
        if held_agent.observation().sha256 != agent.sha256
            || held_agent.observation().size_bytes != agent.size_bytes
        {
            return Err(WsbPreparationError::GuestAgent(
                "Staged agent drifted before role copy".into(),
            ));
        }
        let launcher = paired::copy_agent_role(&workspace, SEVENZIP_LAUNCHER_FILE, &agent)?;
        let created = workspace
            .create_tools_file_new(SEVENZIP_INSTALLER_FILE)
            .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
        let copied = intake
            .copy_to(created)
            .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
        let copied_identity = copied.identity().clone();
        drop(copied);
        let file = workspace
            .reopen_tools_file_readonly(SEVENZIP_INSTALLER_FILE)
            .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
        let held = HeldApplicationFile::open(file.final_path())
            .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
        if file.identity() != &copied_identity
            || held.observation().identity != copied_identity
            || held.observation().sha256 != SEVENZIP_INSTALLER_SHA256
            || held.observation().size_bytes != SEVENZIP_INSTALLER_SIZE_BYTES
        {
            return Err(WsbPreparationError::Contract(
                "Staged 7-Zip installer identity drifted".into(),
            ));
        }
        let installer = WsbSevenZipInstaller {
            import_receipt: import_receipt.clone(),
            import_receipt_sha256: intake.verification().receipt_sha256.clone(),
            staged_payload: BinaryIdentity {
                canonical_path: provider_path(&file.final_path().to_string_lossy()),
                sha256: SEVENZIP_INSTALLER_SHA256.into(),
                size_bytes: SEVENZIP_INSTALLER_SIZE_BYTES,
                version: None,
                signature_status: ReadinessState::Unknown,
            },
            staged_identity: file.identity().clone(),
        };
        let profile = aiw_probe::SevenZipProfile {
            revision: aiw_probe::sevenzip::SEVENZIP_PROFILE_REVISION.into(),
            source_sha256: aiw_probe::seven_zip_source_sha256(),
            installer_sha256: SEVENZIP_INSTALLER_SHA256.into(),
            installer_size_bytes: SEVENZIP_INSTALLER_SIZE_BYTES,
            agent_sha256: agent.sha256.clone(),
            agent_size_bytes: agent.size_bytes,
            launcher_sha256: agent.sha256.clone(),
            launcher_size_bytes: agent.size_bytes,
            origin: aiw_probe::ControlEvidenceOrigin::NativeWorker,
            expected_windows: expected_guest_windows.clone(),
            expected_host_windows: identity.os_version.clone(),
            policy:
                aiw_probe::SevenZipPolicy::ClassicAppContainerNoCapabilitiesReadInputWriteOutput,
        };
        let artifacts = build_wsb_static_sevenzip_preparation(
            run_id,
            project,
            &identity,
            workspace.evidence(),
            &agent,
            created_at,
            WsbSevenZipAssessment {
                profile,
                installer,
                launcher,
            },
        )?;
        let roles = open_sevenzip_files(&workspace, &artifacts.receipt)?;
        workspace
            .revalidate()
            .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
        ensure_empty_directory(&workspace.output_path())?;
        require_tools(&workspace.tools_path())?;
        let staged = stage_bundle(&workspace, &artifacts)?;
        for (file, held) in roles {
            file.revalidate()
                .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
            held.revalidate()
                .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
        }
        held_agent
            .revalidate()
            .map_err(|e| WsbPreparationError::GuestAgent(e.to_string()))?;
        agent_file
            .revalidate()
            .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
        intake
            .revalidate()
            .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
        held.revalidate()
            .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
        file.revalidate()
            .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
        require_workspace_allowlist(workspace.root_path(), PreparationWorkspaceState::Building)?;
        complete_bundle(&workspace, &artifacts, staged)?;
        Ok(artifacts)
    })();
    operation.map_err(
        |e: WsbPreparationError| WsbPreparationError::WorkspacePreserved {
            workspace_path: workspace.root_path().to_string_lossy().into_owned(),
            detail: e.to_string(),
        },
    )
}
