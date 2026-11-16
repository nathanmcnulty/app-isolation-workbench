//! Generic assessment preparation on the existing protected WSB transaction.
use super::*;
use aiw_probe::{ApplicationInspectionKind, PortableDirectoryImportReceipt};
use aiw_provider_wsb::assessment::CompiledAssessment;
use aiw_provider_wsb::assessment_request::{
    APPLICATION_ASSESSMENT_AGENT_PATH, APPLICATION_ASSESSMENT_REQUEST_PATH,
    APPLICATION_ASSESSMENT_RESULT_PATH, assessment_value_sha256,
};

pub const APPLICATION_ASSESSMENT_PREPARATION_SCHEMA: &str =
    "aiw.dev/wsb-preparation/application-assessment/v0alpha4";
pub const HISTORICAL_APPLICATION_PREPARATION_V3: &str =
    "aiw.dev/wsb-preparation/application-assessment/v0alpha3";
pub const HISTORICAL_APPLICATION_PREPARATION_V2: &str =
    "aiw.dev/wsb-preparation/application-assessment/v0alpha2";
pub const HISTORICAL_APPLICATION_PREPARATION_V1: &str =
    "aiw.dev/wsb-preparation/application-assessment/v0alpha1";
pub const HISTORICAL_APPLICATION_TRUST_DELTA: &str = "stages only reviewed application and fixture content in a fresh offline Windows Sandbox; runs the declared bounded workflow as a fresh standard user under the selected ordinary or classic AppContainer policy; grants only owned guest application/work paths; retains bounded output and independent cleanup facts; no automatic host export, installation, fallback or general compatibility verdict";
pub const HISTORICAL_APPLICATION_V3_TRUST_DELTA: &str = "stages reviewed portable application and fixture inputs in one fresh offline Windows Sandbox; generates one ephemeral host collector-key acknowledgement key and nonce at separate Start and retains only public execution bindings; requires protected guest-local collection, authenticated signedCollector/p256-sha256/v1 transport and measured collector file/process/thread guards before any application creation as a fresh standard user under the selected ordinary or classic AppContainer policy; grants only owned guest application/work paths; sampled bounded output monitoring is not a disk quota; retains bounded facts and independent cleanup; no automatic host export, installation, fallback or general compatibility verdict";
pub const APPLICATION_ASSESSMENT_TRUST_DELTA: &str =
    aiw_orchestrator::APPLICATION_ASSESSMENT_TRUST_DELTA;
pub const APPLICATION_INTAKE_LEAF: &str = "application-intake";
pub const APPLICATION_FIXTURES_LEAF: &str = "fixtures";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbAssessmentInput {
    pub id: String,
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub source_identity: WindowsFileIdentity,
    pub staged_identity: WindowsFileIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbApplicationAssessment {
    pub compiled: CompiledAssessment,
    pub intake_receipt: PortableDirectoryImportReceipt,
    pub intake_receipt_sha256: String,
    pub fixtures_directory: WindowsFileIdentity,
    pub fixture_directories: Vec<WindowsFileIdentity>,
    pub inputs: Vec<WsbAssessmentInput>,
}

impl WsbApplicationAssessment {
    pub(crate) fn validate(
        &self,
        workspace: &WorkspaceBindingEvidence,
    ) -> Result<(), WsbPreparationError> {
        self.compiled
            .validate()
            .map_err(|error| WsbPreparationError::Contract(format!("{error:?}")))?;
        require_hash(&self.intake_receipt_sha256)?;
        let intake_bytes = serde_json::to_vec(&self.intake_receipt)
            .map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
        let intake = &self.intake_receipt;
        let root = normalized_windows_path(&workspace.root.final_path);
        let intake_root = format!(r"{root}\{APPLICATION_INTAKE_LEAF}");
        if intake.schema_version != aiw_probe::PORTABLE_DIRECTORY_IMPORT_RECEIPT_SCHEMA
            || intake.intake_id != APPLICATION_INTAKE_LEAF
            || intake.source_kind != ApplicationInspectionKind::PortableDirectory
            || hex::encode(Sha256::digest(intake_bytes)) != self.intake_receipt_sha256
            || intake.manifest_sha256 != self.compiled.portable_manifest_sha256
            || intake.source_manifest.manifest_sha256 != self.compiled.portable_manifest_sha256
            || intake.source_manifest.entries != self.compiled.portable_entries
            || intake.source_manifest.total_size_bytes != self.compiled.portable_total_size_bytes
            || intake.total_size_bytes != self.compiled.portable_total_size_bytes
            || intake.entries.len() != self.compiled.portable_entries.len()
            || intake.entry_count as usize != self.compiled.portable_entries.len()
            || normalized_windows_path(&intake.intake_root.final_path) != intake_root
            || normalized_windows_path(&intake.source_directory.final_path)
                != format!(r"{intake_root}\source")
            || normalized_windows_path(&intake.payload_directory.final_path)
                != format!(r"{intake_root}\source\payload")
            || normalized_windows_path(&intake.receipt.final_path)
                != format!(r"{intake_root}\intake.json")
            || normalized_windows_path(&self.fixtures_directory.final_path)
                != format!(r"{root}\{APPLICATION_FIXTURES_LEAF}")
            || self.fixtures_directory.volume_serial_number != workspace.root.volume_serial_number
            || self.inputs.len() != self.compiled.settings.inputs.len()
        {
            return Err(WsbPreparationError::Contract(
                "assessment protected intake or fixture root differs from its plan".into(),
            ));
        }
        for (actual, expected) in self.inputs.iter().zip(&self.compiled.settings.inputs) {
            if actual.id != expected.id
                || actual.path != expected.path
                || actual.sha256 != expected.sha256
                || actual.size_bytes != expected.size_bytes
                || normalized_windows_path(&actual.staged_identity.final_path)
                    != format!(
                        r"{root}\{APPLICATION_FIXTURES_LEAF}\{}",
                        expected.path.replace('/', "\\").to_ascii_lowercase()
                    )
                || actual.staged_identity.volume_serial_number
                    != self.fixtures_directory.volume_serial_number
            {
                return Err(WsbPreparationError::Contract(
                    "assessment fixture identity differs from its reviewed input".into(),
                ));
            }
        }
        let mut expected_directories = std::collections::BTreeSet::new();
        for input in &self.compiled.settings.inputs {
            let mut parent = input.path.as_str();
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                expected_directories.insert(format!(
                    r"{root}\{APPLICATION_FIXTURES_LEAF}\{}",
                    prefix.replace('/', "\\").to_ascii_lowercase()
                ));
                parent = prefix;
            }
        }
        let actual_directories: std::collections::BTreeSet<_> = self
            .fixture_directories
            .iter()
            .map(|identity| normalized_windows_path(&identity.final_path))
            .collect();
        if actual_directories != expected_directories
            || actual_directories.len() != self.fixture_directories.len()
            || self.fixture_directories.iter().any(|identity| {
                identity.volume_serial_number != self.fixtures_directory.volume_serial_number
            })
        {
            return Err(WsbPreparationError::Contract(
                "fixture directory ancestry does not match reviewed inputs".into(),
            ));
        }
        Ok(())
    }
    pub fn assessment_sha256(&self) -> Result<String, WsbPreparationError> {
        assessment_value_sha256(&self.compiled).map_err(WsbPreparationError::Contract)
    }
    pub(crate) fn validate_project(&self, project: &Project) -> Result<(), WsbPreparationError> {
        let expected = aiw_provider_wsb::assessment::compile_assessment(
            project,
            &self.compiled.settings,
            &self.intake_receipt.source_manifest,
        )
        .map_err(|blockers| WsbPreparationError::Contract(format!("{blockers:?}")))?;
        if expected != self.compiled {
            return Err(WsbPreparationError::Contract(
                "compiled assessment differs from protected project and intake".into(),
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_wsb_application_assessment_preparation(
    run_id: &str,
    project: &Project,
    identity: &aiw_probe::WindowsSandboxStaticIdentity,
    workspace: &WorkspaceBindingEvidence,
    agent: &BinaryIdentity,
    created_at: &str,
    assessment: WsbApplicationAssessment,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    let trusted = require_static_identity(identity)?;
    let protocol = aiw_probe::WindowsSandboxCliAdapter::from_version(&identity.package.version)
        .map_err(|e| WsbPreparationError::Readiness(e.into()))?
        .protocol();
    let mut artifacts = build_preparation_identity(
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
    assessment.validate(workspace)?;
    assessment.validate_project(project)?;
    artifacts.receipt.schema_version = APPLICATION_ASSESSMENT_PREPARATION_SCHEMA.into();
    artifacts.receipt.application_assessment = Some(assessment);
    artifacts.wsb_plan = fixed_assessment_wsb_plan(
        workspace,
        artifacts.receipt.application_assessment.as_ref().unwrap(),
    );
    artifacts.receipt.wsb_plan_sha256 = canonical_hash(&artifacts.wsb_plan)?;
    artifacts.run_plan = expected_application_run_plan(&artifacts.receipt)?;
    artifacts.receipt.run_plan_sha256 = artifacts
        .run_plan
        .hash()
        .map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    artifacts.validate()?;
    Ok(artifacts)
}

#[cfg(windows)]
pub struct ApplicationAssessmentPreparationInput<'a> {
    pub source: &'a Path,
    pub settings: &'a aiw_provider_wsb::assessment::AssessmentSettings,
    pub inputs: &'a std::collections::BTreeMap<String, std::path::PathBuf>,
}

#[cfg(windows)]
fn native_error(error: impl std::fmt::Display) -> WsbPreparationError {
    WsbPreparationError::Workspace(error.to_string())
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
pub fn prepare_windows_sandbox_application_assessment(
    workspace_parent: &Path,
    run_id: &str,
    project: &Project,
    agent_source: &Path,
    agent_sha256: &str,
    created_at: &str,
    input: ApplicationAssessmentPreparationInput<'_>,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    use aiw_windows_platform::{HeldApplicationFile, HeldPortableDirectory, HeldRunWorkspace};
    validate_request_contract(run_id, project, created_at)?;
    let source = HeldPortableDirectory::open(input.source).map_err(native_error)?;
    let compiled = aiw_provider_wsb::assessment::compile_assessment(
        project,
        input.settings,
        source.manifest(),
    )
    .map_err(|blockers| WsbPreparationError::Contract(format!("{blockers:?}")))?;
    if input.inputs.len() != compiled.settings.inputs.len() {
        return Err(WsbPreparationError::Contract(
            "input source roster does not match the reviewed input IDs".into(),
        ));
    }
    let mut held_inputs = std::collections::BTreeMap::new();
    for expected in &compiled.settings.inputs {
        let path = input.inputs.get(&expected.id).ok_or_else(|| {
            WsbPreparationError::Contract("reviewed input source is missing".into())
        })?;
        let held = HeldApplicationFile::open_bounded(path, compiled.settings.file_max_bytes)
            .map_err(native_error)?;
        if held.observation().sha256 != expected.sha256
            || held.observation().size_bytes != expected.size_bytes
        {
            return Err(WsbPreparationError::Contract(
                "input content differs from reviewed hash/size".into(),
            ));
        }
        held_inputs.insert(expected.id.clone(), held);
    }
    let mut agent = open_guest_agent_source(agent_source, agent_sha256)?;
    let identity = NativePreparationProviderInspector
        .static_identity()
        .map_err(WsbPreparationError::Readiness)?;
    require_static_identity(&identity)?;
    let workspace = HeldRunWorkspace::create(workspace_parent, run_id).map_err(native_error)?;
    let preserved = workspace.root_path().to_owned();
    let result = (|| {
        let (writer, agent_identity) = stage_guest_agent(&mut agent, &workspace)?;
        drop(writer);
        let intake_receipt = aiw_windows_platform::import_portable_directory(
            workspace.root_path(),
            APPLICATION_INTAKE_LEAF,
            &source,
        )
        .map_err(native_error)?;
        let intake = aiw_windows_platform::open_verified_portable_directory_import(&intake_receipt)
            .map_err(native_error)?;
        let fixtures = workspace
            .create_root_directory_new(APPLICATION_FIXTURES_LEAF)
            .map_err(native_error)?;
        let fixtures_directory = fixtures.identity().clone();
        let mut directories = std::collections::BTreeMap::from([(String::new(), fixtures)]);
        let mut staged_inputs = Vec::new();
        for expected in &compiled.settings.inputs {
            let (parent, leaf) = expected
                .path
                .rsplit_once('/')
                .unwrap_or(("", &expected.path));
            let mut prefix = String::new();
            if !parent.is_empty() {
                for component in parent.split('/') {
                    let next = if prefix.is_empty() {
                        component.into()
                    } else {
                        format!("{prefix}/{component}")
                    };
                    if !directories.contains_key(&next) {
                        let directory = directories[&prefix]
                            .create_directory_new(component)
                            .map_err(native_error)?;
                        directories.insert(next.clone(), directory);
                    }
                    prefix = next;
                }
            }
            let source = &held_inputs[&expected.id];
            let mut file = directories[parent]
                .create_file_new(leaf)
                .map_err(native_error)?;
            source.copy_to(file.as_file_mut()).map_err(native_error)?;
            file.as_file_mut().sync_all().map_err(native_error)?;
            let staged_identity = file.identity().clone();
            drop(file);
            let held = directories[parent]
                .reopen_file_readonly(leaf)
                .map_err(native_error)?;
            let observed = HeldApplicationFile::open_bounded(
                held.final_path(),
                compiled.settings.file_max_bytes,
            )
            .map_err(native_error)?;
            if held.identity() != &staged_identity
                || observed.observation().identity != staged_identity
                || observed.observation().sha256 != expected.sha256
                || observed.observation().size_bytes != expected.size_bytes
            {
                return Err(WsbPreparationError::Contract(
                    "staged input changed during protected copy".into(),
                ));
            }
            staged_inputs.push(WsbAssessmentInput {
                id: expected.id.clone(),
                path: expected.path.clone(),
                sha256: expected.sha256.clone(),
                size_bytes: expected.size_bytes,
                source_identity: source.observation().identity.clone(),
                staged_identity,
            });
        }
        let fixture_directories = directories
            .iter()
            .filter(|(path, _)| !path.is_empty())
            .map(|(_, directory)| directory.identity().clone())
            .collect();
        drop(directories);
        let assessment = WsbApplicationAssessment {
            intake_receipt_sha256: hex::encode(Sha256::digest(
                serde_json::to_vec(&intake_receipt).map_err(native_error)?,
            )),
            intake_receipt,
            compiled,
            fixtures_directory,
            fixture_directories,
            inputs: staged_inputs,
        };
        let artifacts = build_wsb_application_assessment_preparation(
            run_id,
            project,
            &identity,
            workspace.evidence(),
            &agent_identity,
            created_at,
            assessment,
        )?;
        let custody = open_application_files(&workspace, &artifacts.receipt)?;
        let staged = stage_bundle(&workspace, &artifacts)?;
        source.revalidate().map_err(native_error)?;
        for source in held_inputs.values() {
            source.revalidate().map_err(native_error)?;
        }
        intake.revalidate().map_err(native_error)?;
        custody.revalidate()?;
        complete_bundle(&workspace, &artifacts, staged)?;
        Ok(artifacts)
    })();
    result.map_err(
        |error: WsbPreparationError| WsbPreparationError::WorkspacePreserved {
            workspace_path: provider_path(&preserved.to_string_lossy()),
            detail: error.to_string(),
        },
    )
}

pub(crate) fn fixed_assessment_wsb_plan(
    workspace: &WorkspaceBindingEvidence,
    assessment: &WsbApplicationAssessment,
) -> WindowsSandboxPlan {
    WindowsSandboxPlan {
        schema_version: WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.into(),
        workspace_root: provider_path(&workspace.root.final_path),
        mappings: vec![
            MappedFolder {
                purpose: MappingPurpose::Tools,
                host_folder: provider_path(&workspace.tools.final_path),
                sandbox_folder: GUEST_TOOLS.into(),
            },
            MappedFolder {
                purpose: MappingPurpose::Input,
                host_folder: provider_path(&assessment.intake_receipt.payload_directory.final_path),
                sandbox_folder: r"C:\AIW\Input\App".into(),
            },
            MappedFolder {
                purpose: MappingPurpose::Input,
                host_folder: provider_path(&assessment.fixtures_directory.final_path),
                sandbox_folder: r"C:\AIW\Input\Fixtures".into(),
            },
            MappedFolder {
                purpose: MappingPurpose::Output,
                host_folder: provider_path(&workspace.output.final_path),
                sandbox_folder: GUEST_OUTPUT.into(),
            },
        ],
        probe: GoldenProbe {
            executable: APPLICATION_ASSESSMENT_AGENT_PATH.into(),
            request: Some(APPLICATION_ASSESSMENT_REQUEST_PATH.into()),
            output: APPLICATION_ASSESSMENT_RESULT_PATH.into(),
        },
        memory_mb: Some(2048),
    }
}

pub(crate) fn expected_application_run_plan(
    receipt: &WsbPreparationReceipt,
) -> Result<RunPlan, WsbPreparationError> {
    expected_application_run_plan_for_read(receipt, false)
}
pub(super) fn expected_application_run_plan_for_read(
    receipt: &WsbPreparationReceipt,
    historical: bool,
) -> Result<RunPlan, WsbPreparationError> {
    let assessment = receipt.application_assessment.as_ref().ok_or_else(|| {
        WsbPreparationError::Contract("generic assessment preparation is absent".into())
    })?;
    let mut plan = RunPlan::new(
        &receipt.run_id,
        &receipt.project_id,
        &receipt.project_revision_sha256,
        RunLifecycleKind::Assessment,
        &receipt.created_at,
        vec![
            PlannedAction::AssessHost,
            PlannedAction::PrepareWorkspace,
            PlannedAction::ExecuteWindowsSandboxApplicationAssessment {
                provider_protocol: Some(receipt.provider_protocol.clone()),
                evidence_channel: Some(aiw_probe::APPLICATION_ASSESSMENT_CHANNEL_PROTOCOL.into()),
                sandbox_plan_sha256: receipt.wsb_plan_sha256.clone(),
                provider_sha256: receipt.provider.sha256.clone(),
                guest_agent_sha256: receipt.guest_agent.sha256.clone(),
                workspace: Box::new(receipt.workspace.clone()),
                workspace_identity_sha256: receipt.workspace_identity_sha256.clone(),
                intake_receipt_sha256: assessment.intake_receipt_sha256.clone(),
                source_manifest_sha256: assessment.compiled.portable_manifest_sha256.clone(),
                assessment_sha256: assessment.assessment_sha256()?,
            },
            PlannedAction::CollectEvidence,
        ],
        vec![
            APPLICATION_ASSESSMENT_TRUST_DELTA.into(),
            TRUST_DELTA_MAPPINGS.into(),
        ],
    )
    .map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    if historical && receipt.schema_version == HISTORICAL_APPLICATION_PREPARATION_V3 {
        plan.schema = aiw_orchestrator::HISTORICAL_APPLICATION_ASSESSMENT_PLAN_V3.into();
        plan.trust_deltas[0] = HISTORICAL_APPLICATION_V3_TRUST_DELTA.into();
    }
    if historical
        && matches!(
            receipt.schema_version.as_str(),
            HISTORICAL_APPLICATION_PREPARATION_V1 | HISTORICAL_APPLICATION_PREPARATION_V2
        )
    {
        plan.schema = if receipt.schema_version == HISTORICAL_APPLICATION_PREPARATION_V1 {
            aiw_orchestrator::HISTORICAL_APPLICATION_ASSESSMENT_PLAN_V1
        } else {
            aiw_orchestrator::HISTORICAL_APPLICATION_ASSESSMENT_PLAN_V2
        }
        .into();
        plan.trust_deltas[0] = HISTORICAL_APPLICATION_TRUST_DELTA.into();
        if let PlannedAction::ExecuteWindowsSandboxApplicationAssessment {
            provider_protocol,
            evidence_channel,
            ..
        } = &mut plan.actions[2]
        {
            *evidence_channel = None;
            if receipt.schema_version == HISTORICAL_APPLICATION_PREPARATION_V1 {
                *provider_protocol = None;
            }
        }
    }
    Ok(plan)
}

pub(crate) fn validate_application_artifacts(
    artifacts: &PreparedWsbArtifacts,
    historical: bool,
) -> Result<(), WsbPreparationError> {
    let assessment = artifacts
        .receipt
        .application_assessment
        .as_ref()
        .ok_or_else(|| {
            WsbPreparationError::Contract("generic assessment preparation is absent".into())
        })?;
    assessment.validate(&artifacts.receipt.workspace)?;
    let expected = fixed_assessment_wsb_plan(&artifacts.receipt.workspace, assessment);
    validate_plan(&expected).map_err(|error| WsbPreparationError::Contract(error.to_string()))?;
    if artifacts.wsb_plan != expected
        || canonical_hash(&expected)? != artifacts.receipt.wsb_plan_sha256
        || expected_application_run_plan_for_read(&artifacts.receipt, historical)?
            != artifacts.run_plan
        || artifacts
            .run_plan
            .hash()
            .map_err(|error| WsbPreparationError::Contract(error.to_string()))?
            != artifacts.receipt.run_plan_sha256
    {
        return Err(WsbPreparationError::Contract(
            "generic assessment plans differ from protected preparation".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) struct HeldApplicationAssessmentFiles {
    intake: aiw_windows_platform::HeldVerifiedPortableDirectoryImport,
    directories: std::collections::BTreeMap<String, aiw_windows_platform::BoundWorkspaceDirectory>,
    files: Vec<(
        aiw_windows_platform::BoundWorkspaceFile,
        aiw_windows_platform::HeldApplicationFile,
    )>,
    expected: WsbApplicationAssessment,
}

#[cfg(windows)]
impl HeldApplicationAssessmentFiles {
    pub(crate) fn revalidate(&self) -> Result<(), WsbPreparationError> {
        self.intake.revalidate().map_err(native_error)?;
        for directory in self.directories.values() {
            directory.revalidate().map_err(native_error)?;
        }
        for (bound, observed) in &self.files {
            bound.revalidate().map_err(native_error)?;
            observed.revalidate().map_err(native_error)?;
        }
        require_fixture_inventory(&self.directories, &self.expected)
    }
}

#[cfg(windows)]
pub(crate) fn open_application_files(
    workspace: &aiw_windows_platform::HeldRunWorkspace,
    receipt: &WsbPreparationReceipt,
) -> Result<HeldApplicationAssessmentFiles, WsbPreparationError> {
    use aiw_windows_platform::{BoundWorkspaceDirectory, HeldApplicationFile, WorkspaceAclPolicy};
    let assessment = receipt.application_assessment.as_ref().ok_or_else(|| {
        WsbPreparationError::Contract("generic application custody is absent".into())
    })?;
    assessment.validate(workspace.evidence())?;
    let intake =
        aiw_windows_platform::open_verified_portable_directory_import(&assessment.intake_receipt)
            .map_err(native_error)?;
    let fixtures = BoundWorkspaceDirectory::reopen_protected(&assessment.fixtures_directory)
        .map_err(native_error)?;
    let mut directories = std::collections::BTreeMap::from([(String::new(), fixtures)]);
    let mut paths = std::collections::BTreeSet::new();
    for input in &assessment.compiled.settings.inputs {
        let mut path = input.path.as_str();
        while let Some((parent, _)) = path.rsplit_once('/') {
            paths.insert(parent.to_owned());
            path = parent;
        }
    }
    for path in paths {
        let (parent, leaf) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        let bound = directories[parent]
            .reopen_directory_readonly(leaf, WorkspaceAclPolicy::Protected)
            .map_err(native_error)?;
        let expected = assessment
            .fixture_directories
            .iter()
            .find(|identity| {
                normalized_windows_path(&identity.final_path)
                    == normalized_windows_path(&bound.identity().final_path)
            })
            .ok_or_else(|| {
                WsbPreparationError::Contract("fixture ancestor is not enrolled".into())
            })?;
        if bound.identity() != expected {
            return Err(WsbPreparationError::Contract(
                "fixture directory identity changed".into(),
            ));
        }
        directories.insert(path, bound);
    }
    let mut files = Vec::new();
    for input in &assessment.inputs {
        let (parent, leaf) = input.path.rsplit_once('/').unwrap_or(("", &input.path));
        let bound = directories[parent]
            .reopen_file_readonly(leaf)
            .map_err(native_error)?;
        let observed = HeldApplicationFile::open_bounded(
            bound.final_path(),
            assessment.compiled.settings.file_max_bytes,
        )
        .map_err(native_error)?;
        if bound.identity() != &input.staged_identity
            || observed.observation().identity != input.staged_identity
            || observed.observation().sha256 != input.sha256
            || observed.observation().size_bytes != input.size_bytes
        {
            return Err(WsbPreparationError::Contract(
                "fixture content or full identity changed".into(),
            ));
        }
        files.push((bound, observed));
    }
    let held = HeldApplicationAssessmentFiles {
        intake,
        directories,
        files,
        expected: assessment.clone(),
    };
    held.revalidate()?;
    Ok(held)
}

#[cfg(windows)]
fn require_fixture_inventory(
    directories: &std::collections::BTreeMap<String, aiw_windows_platform::BoundWorkspaceDirectory>,
    assessment: &WsbApplicationAssessment,
) -> Result<(), WsbPreparationError> {
    for (path, directory) in directories {
        let mut expected = Vec::new();
        for child in directories.keys().filter(|name| !name.is_empty()) {
            let (parent, leaf) = child.rsplit_once('/').unwrap_or(("", child.as_str()));
            if parent == path {
                expected.push(leaf.to_owned());
            }
        }
        for input in &assessment.inputs {
            let (parent, leaf) = input.path.rsplit_once('/').unwrap_or(("", &input.path));
            if parent == path {
                expected.push(leaf.to_owned());
            }
        }
        require_exact_names(directory.final_path(), expected)?;
    }
    Ok(())
}

#[cfg(windows)]
fn require_exact_names(path: &Path, mut expected: Vec<String>) -> Result<(), WsbPreparationError> {
    let mut names = std::fs::read_dir(path)
        .map_err(native_error)?
        .map(|entry| {
            entry
                .map_err(native_error)?
                .file_name()
                .into_string()
                .map_err(|_| {
                    WsbPreparationError::Contract("non-Unicode namespace entry refused".into())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    expected.sort();
    if names != expected {
        return Err(WsbPreparationError::Contract(
            "generic assessment namespace differs from closed inventory".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn require_application_workspace(
    root: &Path,
    state: PreparationWorkspaceState,
) -> Result<(), WsbPreparationError> {
    let mut expected = vec![
        "output",
        "plan.json",
        "tools",
        "wsb-plan.json",
        APPLICATION_INTAKE_LEAF,
        APPLICATION_FIXTURES_LEAF,
    ];
    if matches!(
        state,
        PreparationWorkspaceState::Prepared
            | PreparationWorkspaceState::Imported
            | PreparationWorkspaceState::Revoking
    ) {
        expected.push("preparation.json");
    }
    if matches!(
        state,
        PreparationWorkspaceState::Imported | PreparationWorkspaceState::Revoking
    ) {
        expected.push("runs");
    }
    require_exact_names(root, expected.into_iter().map(str::to_owned).collect())
}

#[cfg(windows)]
pub(super) fn require_application_tools(path: &Path) -> Result<(), WsbPreparationError> {
    require_exact_names(path, vec![GUEST_AGENT_FILE.into()])
}
