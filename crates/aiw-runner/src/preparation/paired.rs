//! Fixed role copies of the approved agent; no caller-supplied executable intake.
use super::*;
pub const PAIRED_PREPARATION_SCHEMA: &str = "aiw.dev/wsb-preparation-receipt/v0alpha7";
pub const PAIRED_STATIC_PREPARATION_SCHEMA: &str = "aiw.dev/wsb-preparation-receipt/v0alpha8";
pub const CONTROL_FIXTURE_FILE: &str = "aiw-control-fixture.exe";
pub const CONTROL_LAUNCHER_FILE: &str = "aiw-control-appcontainer.exe";
pub const CONTROL_TRUST_DELTA: &str = "runs the fixed ordinary-user versus classic AppContainer file/registry/child controls inside one disposable offline Windows Sandbox; zero capability SIDs; only fixed fixture traversal and low-integrity child-output package grants; no general compatibility or isolation verdict";
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbPairedControls {
    pub profile: aiw_probe::PairedControlProfile,
    pub fixture: WsbMsiDocument,
    pub launcher: WsbMsiDocument,
}
impl WsbPairedControls {
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
        for (name, file, hash, size) in [
            (
                CONTROL_FIXTURE_FILE,
                &self.fixture,
                &self.profile.fixture_sha256,
                self.profile.fixture_size_bytes,
            ),
            (
                CONTROL_LAUNCHER_FILE,
                &self.launcher,
                &self.profile.launcher_sha256,
                self.profile.launcher_size_bytes,
            ),
        ] {
            if hash != &agent.sha256
                || size != agent.size_bytes
                || &file.staged_payload.sha256 != hash
                || file.staged_payload.size_bytes != size
                || file.staged_payload.version.is_some()
                || file.staged_payload.signature_status != ReadinessState::Unknown
                || normalized_windows_path(&file.staged_payload.canonical_path)
                    != format!(
                        "{}\\{name}",
                        normalized_windows_path(&workspace.tools.final_path)
                    )
                || normalized_windows_path(&file.staged_identity.final_path)
                    != normalized_windows_path(&file.staged_payload.canonical_path)
                || file.staged_identity.volume_serial_number != workspace.tools.volume_serial_number
            {
                return Err(WsbPreparationError::Contract("Fixed control roles must be exact protected copies of the approved guest agent".into()));
            }
        }
        Ok(())
    }
}
pub fn build_wsb_paired_controls_preparation(
    base: PreparedWsbArtifacts,
    controls: WsbPairedControls,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    base.validate()?;
    finish_paired_preparation(base, controls)
}
fn finish_paired_preparation(
    base: PreparedWsbArtifacts,
    controls: WsbPairedControls,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    controls.validate(&base.receipt.workspace, &base.receipt.guest_agent)?;
    if base.receipt.msi.is_some()
        || base.receipt.bambu.is_some()
        || base.receipt.paired_controls.is_some()
        || base.receipt.host_os_version.as_ref() != Some(controls.profile.approved_host_windows())
    {
        return Err(WsbPreparationError::Contract(
            "Paired controls require a fresh exclusive profile and exact recorded host environment"
                .into(),
        ));
    }
    let mut artifacts = base;
    artifacts.wsb_plan.probe.output = GUEST_MSI_RESULT.into();
    artifacts.receipt.wsb_plan_sha256 = canonical_hash(&artifacts.wsb_plan)?;
    artifacts.run_plan = RunPlan::new(
        &artifacts.receipt.run_id,
        &artifacts.receipt.project_id,
        &artifacts.receipt.project_revision_sha256,
        RunLifecycleKind::Assessment,
        &artifacts.receipt.created_at,
        vec![
            PlannedAction::AssessHost,
            PlannedAction::PrepareWorkspace,
            PlannedAction::ExecuteWindowsSandboxPairedControls {
                sandbox_plan_sha256: artifacts.receipt.wsb_plan_sha256.clone(),
                provider_sha256: artifacts.receipt.provider.sha256.clone(),
                guest_agent_sha256: artifacts.receipt.guest_agent.sha256.clone(),
                workspace: Box::new(artifacts.receipt.workspace.clone()),
                workspace_identity_sha256: artifacts.receipt.workspace_identity_sha256.clone(),
                profile: Box::new(controls.profile.clone()),
            },
            PlannedAction::CollectEvidence,
        ],
        vec![CONTROL_TRUST_DELTA.into(), TRUST_DELTA_MAPPINGS.into()],
    )
    .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
    artifacts.receipt.run_plan_sha256 = artifacts
        .run_plan
        .hash()
        .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
    artifacts.receipt.schema_version = if artifacts.receipt.provider_protocol_observation.is_some()
    {
        PAIRED_STATIC_PREPARATION_SCHEMA
    } else {
        PAIRED_PREPARATION_SCHEMA
    }
    .into();
    artifacts.receipt.paired_controls = Some(controls);
    artifacts.validate()?;
    Ok(artifacts)
}
#[cfg(windows)]
pub(crate) type HeldControlFiles = Vec<(
    aiw_windows_platform::BoundWorkspaceFile,
    aiw_windows_platform::HeldApplicationFile,
)>;
#[cfg(windows)]
pub(crate) fn open_control_files(
    workspace: &aiw_windows_platform::HeldRunWorkspace,
    receipt: &WsbPreparationReceipt,
) -> Result<HeldControlFiles, WsbPreparationError> {
    let mut held = vec![];
    if let Some(controls) = &receipt.paired_controls {
        for (name, expected) in [
            (CONTROL_FIXTURE_FILE, &controls.fixture),
            (CONTROL_LAUNCHER_FILE, &controls.launcher),
        ] {
            let file = workspace
                .reopen_tools_file_readonly(name)
                .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
            let observed = aiw_windows_platform::HeldApplicationFile::open(file.final_path())
                .map_err(|e| WsbPreparationError::Contract(e.to_string()))?;
            if file.identity() != &expected.staged_identity
                || observed.observation().identity != expected.staged_identity
                || observed.observation().sha256 != expected.staged_payload.sha256
                || observed.observation().size_bytes != expected.staged_payload.size_bytes
            {
                return Err(WsbPreparationError::Contract(
                    "Fixed control tool identity drifted".into(),
                ));
            }
            held.push((file, observed));
        }
    }
    Ok(held)
}
#[cfg(windows)]
pub(crate) fn require_receipt_tools(
    path: &Path,
    receipt: &WsbPreparationReceipt,
) -> Result<(), WsbPreparationError> {
    if receipt.paired_controls.is_none() {
        return require_profile_tools_allowlist(
            path,
            application_file_name(receipt),
            document_file_present(receipt),
        );
    }
    let mut observed = std::fs::read_dir(path)
        .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
    observed.sort();
    let mut expected = vec![
        GUEST_AGENT_FILE.to_string(),
        CONTROL_FIXTURE_FILE.to_string(),
        CONTROL_LAUNCHER_FILE.to_string(),
    ];
    expected.sort();
    if observed != expected {
        return Err(WsbPreparationError::Contract(
            "Paired tool allowlist differs".into(),
        ));
    }
    Ok(())
}
/// Non-executing preparation: copy only the held, expected-hash agent into its
/// fixed roles, publish immutable plans/receipt last, then require normal import.
#[allow(clippy::too_many_arguments)]
pub fn build_wsb_static_paired_preparation(
    run_id: &str,
    project: &Project,
    identity: &aiw_probe::WindowsSandboxStaticIdentity,
    workspace: &WorkspaceBindingEvidence,
    agent: &BinaryIdentity,
    created_at: &str,
    controls: WsbPairedControls,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    let trusted = require_static_identity(identity)?;
    let protocol = WindowsSandboxCliProtocol {
        cli_version: PINNED_CLI_VERSION.into(),
        protocol: "windowsSandboxCli/v0.8.107.0".into(),
        list_schema: "WindowsSandboxEnvironments/Id".into(),
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
    finish_paired_preparation(base, controls)
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
pub fn prepare_windows_sandbox_paired_controls(
    workspace_parent: &Path,
    run_id: &str,
    project: &Project,
    agent_source: &Path,
    agent_sha256: &str,
    created_at: &str,
    expected_guest_windows: Option<&aiw_probe::WindowsVersionObservation>,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    prepare_paired_with_inspector(
        workspace_parent,
        run_id,
        project,
        agent_source,
        agent_sha256,
        created_at,
        expected_guest_windows,
        &NativePreparationProviderInspector,
    )
}
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_paired_with_inspector(
    workspace_parent: &Path,
    run_id: &str,
    project: &Project,
    agent_source: &Path,
    agent_sha256: &str,
    created_at: &str,
    expected_guest_windows: Option<&aiw_probe::WindowsVersionObservation>,
    inspector: &dyn PreparationProviderInspector,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    use aiw_windows_platform::HeldRunWorkspace;
    validate_request_contract(run_id, project, created_at)?;
    let mut source = open_guest_agent_source(agent_source, agent_sha256)?;
    let static_identity = inspector
        .static_identity()
        .map_err(WsbPreparationError::Readiness)?;
    require_static_identity(&static_identity)?;
    if let Some(guest) = expected_guest_windows {
        guest.validate().map_err(WsbPreparationError::Contract)?;
        if guest.observer_architecture != "x86_64" {
            return Err(WsbPreparationError::Contract(
                "Fixed controls require an exact x64 guest version".into(),
            ));
        }
    }
    let workspace = HeldRunWorkspace::create(workspace_parent, run_id)
        .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
    let operation = (|| {
        let (agent_writer, identity) = stage_guest_agent(&mut source, &workspace)?;
        // Convert the staging writer to read-only custody before opening the
        // same agent for role copies. A live writer conflicts with read-only sharing.
        drop(agent_writer);
        let agent_file = workspace
            .reopen_tools_file_readonly(GUEST_AGENT_FILE)
            .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
        let agent_guard = aiw_windows_platform::HeldApplicationFile::open(agent_file.final_path())
            .map_err(|e| WsbPreparationError::GuestAgent(e.to_string()))?;
        if agent_guard.observation().sha256 != identity.sha256
            || agent_guard.observation().size_bytes != identity.size_bytes
        {
            return Err(WsbPreparationError::GuestAgent(
                "Staged agent changed before fixed role copies".into(),
            ));
        }
        let fixture = copy_agent_role(&workspace, CONTROL_FIXTURE_FILE, &identity)?;
        let launcher = copy_agent_role(&workspace, CONTROL_LAUNCHER_FILE, &identity)?;
        let profile = aiw_probe::PairedControlProfile {
            revision: aiw_probe::PAIRED_CONTROL_REVISION.into(),
            source_sha256: aiw_probe::paired_controls::paired_control_source_sha256(),
            fixture_sha256: identity.sha256.clone(),
            fixture_size_bytes: identity.size_bytes,
            launcher_sha256: identity.sha256.clone(),
            launcher_size_bytes: identity.size_bytes,
            origin: aiw_probe::ControlEvidenceOrigin::NativeWorker,
            expected_windows: expected_guest_windows.unwrap_or(&static_identity.os_version).clone(),
            expected_host_windows: Some(static_identity.os_version.clone()),
            policy: aiw_probe::paired_controls::PairedControlPolicy::ClassicAppContainerNoCapabilitiesFixedChildOutputGrant,
        };
        let artifacts = build_wsb_static_paired_preparation(
            run_id,
            project,
            &static_identity,
            workspace.evidence(),
            &identity,
            created_at,
            WsbPairedControls {
                profile,
                fixture,
                launcher,
            },
        )?;
        let _controls = open_control_files(&workspace, &artifacts.receipt)?;
        workspace
            .revalidate()
            .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
        ensure_empty_directory(&workspace.output_path())?;
        require_receipt_tools(&workspace.tools_path(), &artifacts.receipt)?;
        let staged = stage_bundle(&workspace, &artifacts)?;
        agent_guard
            .revalidate()
            .map_err(|e| WsbPreparationError::GuestAgent(e.to_string()))?;
        agent_file
            .revalidate()
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
#[cfg(windows)]
fn copy_agent_role(
    workspace: &aiw_windows_platform::HeldRunWorkspace,
    name: &str,
    agent: &BinaryIdentity,
) -> Result<WsbMsiDocument, WsbPreparationError> {
    let source = workspace
        .reopen_tools_file_readonly(GUEST_AGENT_FILE)
        .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
    let held = aiw_windows_platform::HeldApplicationFile::open(source.final_path())
        .map_err(|e| WsbPreparationError::GuestAgent(e.to_string()))?;
    let mut created = workspace
        .create_tools_file_new(name)
        .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?
        .into_file();
    held.copy_to(&mut created)
        .map_err(|e| WsbPreparationError::GuestAgent(e.to_string()))?;
    created
        .sync_all()
        .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
    drop(created);
    let copied = workspace
        .reopen_tools_file_readonly(name)
        .map_err(|e| WsbPreparationError::Workspace(e.to_string()))?;
    let observed = aiw_windows_platform::HeldApplicationFile::open(copied.final_path())
        .map_err(|e| WsbPreparationError::GuestAgent(e.to_string()))?;
    if observed.observation().sha256 != agent.sha256
        || observed.observation().size_bytes != agent.size_bytes
    {
        return Err(WsbPreparationError::GuestAgent(
            "Control role copy differs".into(),
        ));
    }
    Ok(WsbMsiDocument {
        staged_payload: BinaryIdentity {
            canonical_path: provider_path(&copied.final_path().to_string_lossy()),
            sha256: agent.sha256.clone(),
            size_bytes: agent.size_bytes,
            version: None,
            signature_status: ReadinessState::Unknown,
        },
        staged_identity: copied.identity().clone(),
    })
}
