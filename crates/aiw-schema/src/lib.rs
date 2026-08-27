#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROJECT_SCHEMA_VERSION: &str = "aiw.dev/v0alpha2";
pub const LEGACY_PROJECT_SCHEMA_VERSION: &str = "aiw.dev/v0alpha1";
pub const PROJECT_KIND: &str = "AppIsolationProject";
pub const MODEL_PACK_SCHEMA_VERSION: &str = "aiw.dev/model-pack/v0alpha1";
pub const MODEL_PACK_KIND: &str = "AIWModelPack";
pub const MAX_SCENARIO_TIMEOUT_SECONDS: u32 = 3_600;

const FIRST_PARTY_EXTENSION_KEYS: &[&str] = &[
    "aiw.dev/legacy-v0alpha1-config",
    "aiw.dev/legacy-v0alpha1-input",
    "aiw.dev/legacy-v0alpha1-extensions",
];

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    pub schema_version: String,
    pub kind: String,
    pub metadata: ProjectMetadata,
    pub application: ApplicationSource,
    pub isolation_intent: IsolationIntent,
    #[serde(default)]
    pub execution_providers: Vec<ExecutionProvider>,
    #[serde(default)]
    pub secrets: Vec<SecretReference>,
    pub candidates: Vec<Candidate>,
    pub scenarios: Vec<Scenario>,
    #[serde(default)]
    pub assertions: Assertions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyst: Option<Analyst>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_review: Option<MigrationReview>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectV0Alpha2Wire {
    schema_version: String,
    kind: String,
    metadata: ProjectMetadata,
    application: ApplicationSource,
    isolation_intent: IsolationIntent,
    #[serde(default)]
    execution_providers: Vec<ExecutionProvider>,
    #[serde(default)]
    secrets: Vec<SecretReference>,
    candidates: Vec<Candidate>,
    scenarios: Vec<Scenario>,
    #[serde(default)]
    assertions: Assertions,
    #[serde(default)]
    analyst: Option<Analyst>,
    #[serde(default)]
    migration_review: Option<MigrationReview>,
    #[serde(default)]
    extensions: BTreeMap<String, Value>,
}

impl From<ProjectV0Alpha2Wire> for Project {
    fn from(wire: ProjectV0Alpha2Wire) -> Self {
        Self {
            schema_version: wire.schema_version,
            kind: wire.kind,
            metadata: wire.metadata,
            application: wire.application,
            isolation_intent: wire.isolation_intent,
            execution_providers: wire.execution_providers,
            secrets: wire.secrets,
            candidates: wire.candidates,
            scenarios: wire.scenarios,
            assertions: wire.assertions,
            analyst: wire.analyst,
            migration_review: wire.migration_review,
            extensions: wire.extensions,
        }
    }
}

impl<'de> Deserialize<'de> for Project {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let schema_version = value.get("schemaVersion").and_then(Value::as_str);
        if schema_version == Some(LEGACY_PROJECT_SCHEMA_VERSION) {
            let legacy: LegacyProjectV0Alpha1 =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            return Ok(migrate_v0alpha1(&legacy));
        }
        let wire: ProjectV0Alpha2Wire =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(wire.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectMetadata {
    pub name: String,
    pub display_name: String,
    pub owner: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyProjectInput {
    pub installer: LegacyInstaller,
    #[serde(default)]
    pub secrets: Vec<SecretReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyInstaller {
    pub path: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signer: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub arguments: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub may_reboot: bool,
}

#[deprecated(
    note = "v0alpha2 projects use ApplicationSource; parse v0alpha1 with LegacyProjectV0Alpha1"
)]
pub type ProjectInput = LegacyProjectInput;

#[deprecated(
    note = "v0alpha2 projects use ApplicationSource; parse v0alpha1 with LegacyProjectV0Alpha1"
)]
pub type Installer = LegacyInstaller;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub id: String,
    pub provider: String,
    pub reference: String,
}

/// A source application that can be assessed without accepting arbitrary commands.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ApplicationSource {
    Msi(FileApplicationSource),
    Exe(FileApplicationSource),
    PortableDirectory(PortableDirectoryApplicationSource),
    MigrationPending(MigrationPendingApplicationSource),
}

/// Non-executable source identity retained until a legacy migration is reviewed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigrationPendingApplicationSource {
    pub path: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signer: Option<String>,
    #[serde(default)]
    pub may_reboot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileApplicationSource {
    pub path: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signer: Option<String>,
    #[serde(default)]
    pub silent_arguments: Vec<String>,
    #[serde(default)]
    pub entry_points: Vec<EntryPoint>,
    #[serde(default)]
    pub architecture: ApplicationArchitecture,
    #[serde(default)]
    pub may_reboot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_uninstall: Option<UpdateUninstallMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableDirectoryApplicationSource {
    pub path: String,
    pub content_manifest_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signer: Option<String>,
    #[serde(default)]
    pub entry_points: Vec<EntryPoint>,
    #[serde(default)]
    pub architecture: ApplicationArchitecture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_uninstall: Option<UpdateUninstallMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntryPoint {
    pub id: String,
    pub path: String,
    #[serde(default)]
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum ApplicationArchitecture {
    X64,
    X86,
    Arm64,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateUninstallMetadata {
    #[serde(default)]
    pub supports_update: bool,
    #[serde(default)]
    pub supports_uninstall: bool,
    #[serde(default)]
    pub requires_reboot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct IsolationIntent {
    pub runtime_boundary: RuntimeBoundary,
    pub network: NetworkIntent,
    pub allow_clipboard: bool,
    pub allow_host_file_access: bool,
    pub allow_host_registry_access: bool,
    pub require_descendant_coverage: bool,
}

impl Default for IsolationIntent {
    fn default() -> Self {
        Self {
            runtime_boundary: RuntimeBoundary::AppContainer,
            network: NetworkIntent::Blocked,
            allow_clipboard: false,
            allow_host_file_access: false,
            allow_host_registry_access: false,
            require_descendant_coverage: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeBoundary {
    MediumIlFullTrust,
    AppContainer,
    AppSiloPreview,
    ProcessContainer,
    WindowsSandbox,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum NetworkIntent {
    Blocked,
    Restricted,
    Allowed,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ExecutionProvider {
    WindowsSandbox(WindowsSandboxProvider),
    MxcProcessContainer(MxcProcessContainerProvider),
    Other(OtherExecutionProvider),
}

impl ExecutionProvider {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::WindowsSandbox(provider) => &provider.id,
            Self::MxcProcessContainer(provider) => &provider.id,
            Self::Other(provider) => &provider.id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxProvider {
    pub id: String,
    pub version: String,
    pub executable_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MxcProcessContainerProvider {
    pub id: String,
    pub version: String,
    pub executable_sha256: String,
    #[serde(default)]
    pub experimental: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OtherExecutionProvider {
    pub id: String,
    pub version: String,
    pub executable_sha256: String,
    #[serde(default)]
    pub experimental: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    #[serde(rename = "type")]
    pub candidate_type: CandidateType,
    #[serde(default)]
    pub experimental: bool,
    pub config: CandidateConfiguration,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CandidateConfiguration {
    Baseline,
    WindowsSandbox {
        provider_id: String,
        network: NetworkIntent,
    },
    MxcProcessContainer {
        provider_id: String,
        requested_backend: ProcessContainerBackend,
        network: NetworkIntent,
    },
    Msix {
        delivery_model: DeliveryModel,
        runtime_boundary: RuntimeBoundary,
        #[serde(default)]
        capabilities: Vec<String>,
    },
    /// Preserves a legacy candidate without selecting a provider or executable policy.
    MigrationPending {
        legacy_candidate_type: CandidateType,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ProcessContainerBackend {
    AppContainer,
    BaseContainer,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DeliveryModel {
    ContainedMsix,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CandidateType {
    UnpackagedBaseline,
    FullMsix,
    AppSiloMsix,
    ProcessContainer,
    ClassicAppContainer,
    IsolationSession,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub description: String,
    #[serde(default = "default_true")]
    pub required: bool,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ScenarioStep {
    Install,
    Launch {
        entrypoint: String,
        #[serde(default)]
        arguments: Vec<String>,
    },
    WaitForProcess {
        image: String,
        #[serde(default = "default_wait_timeout_seconds")]
        timeout_seconds: u32,
    },
    WaitForWindow {
        title: String,
        #[serde(default = "default_wait_timeout_seconds")]
        timeout_seconds: u32,
    },
    ObserveFile {
        path: String,
    },
    ObserveRegistry {
        key: String,
    },
    OperatorCheckpoint {
        prompt: String,
    },
    GracefulClose,
    Update,
    Uninstall,
    RebootContinuation,
    ExpectExitCode {
        value: i32,
    },
}

/// The exact v0alpha1 wire contract. It is retained solely for read/migrate flows.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyProjectV0Alpha1 {
    pub schema_version: String,
    pub kind: String,
    pub metadata: ProjectMetadata,
    pub input: LegacyProjectInput,
    pub candidates: Vec<LegacyCandidateV0Alpha1>,
    pub scenarios: Vec<LegacyScenarioV0Alpha1>,
    #[serde(default)]
    pub assertions: Assertions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyst: Option<Analyst>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyCandidateV0Alpha1 {
    pub id: String,
    #[serde(rename = "type")]
    pub candidate_type: CandidateType,
    #[serde(default)]
    pub experimental: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyScenarioV0Alpha1 {
    pub id: String,
    pub description: String,
    #[serde(default = "default_true")]
    pub required: bool,
    pub steps: Vec<LegacyScenarioStepV0Alpha1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum LegacyScenarioStepV0Alpha1 {
    Launch {
        entrypoint: String,
        #[serde(default)]
        arguments: Vec<String>,
    },
    ManualCheckpoint {
        prompt: String,
    },
    ExpectProcess {
        image: String,
    },
    ExpectExitCode {
        value: i32,
    },
}

/// A fail-closed migration record. It must be removed after all legacy intent is reviewed and
/// represented by executable v0alpha2 fields.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum MigrationReview {
    Pending(PendingMigrationReview),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingMigrationReview {
    pub source_schema_version: String,
    pub installer: LegacyInstaller,
    #[serde(default)]
    pub candidates: Vec<LegacyCandidateV0Alpha1>,
    #[serde(default)]
    pub unresolved_entry_points: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub legacy_extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct Assertions {
    pub require_effective_backend_match: bool,
    pub require_target_token_evidence: bool,
    pub require_expected_child_coverage: bool,
    pub require_offline_canary_denied: bool,
    pub fail_on_evidence_truncation: bool,
}

impl Default for Assertions {
    fn default() -> Self {
        Self {
            require_effective_backend_match: true,
            require_target_token_evidence: true,
            require_expected_child_coverage: true,
            require_offline_canary_denied: true,
            fail_on_evidence_truncation: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Analyst {
    pub enabled: bool,
    pub authority: AnalystAuthority,
    pub execution_placement: AnalystExecutionPlacement,
    pub provider: AnalystProvider,
    #[serde(default)]
    pub permissions: AnalystPermissions,
    #[serde(default = "default_true")]
    pub require_evidence_citations: bool,
    #[serde(default = "default_true")]
    pub proposal_requires_human_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystAuthority {
    AdvisoryOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystExecutionPlacement {
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalystProvider {
    pub id: String,
    #[serde(default = "default_in_process")]
    pub mode: String,
    pub model_pack: String,
    #[serde(default = "default_true")]
    pub require_signed_pack: bool,
    #[serde(default)]
    pub allow_catalog_download: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct AnalystPermissions {
    pub filesystem: Permission,
    pub process_execution: Permission,
    pub network: Permission,
    pub package_mutation: Permission,
    pub signing: Permission,
    pub deployment: Permission,
}

impl Default for AnalystPermissions {
    fn default() -> Self {
        Self {
            filesystem: Permission::None,
            process_execution: Permission::None,
            network: Permission::None,
            package_mutation: Permission::None,
            signing: Permission::None,
            deployment: Permission::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Permission {
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelPack {
    pub schema_version: String,
    pub kind: String,
    pub metadata: ModelPackMetadata,
    pub model: ModelIdentity,
    pub runtime: ModelRuntime,
    pub license: ModelLicense,
    pub payload: ModelPayload,
    pub signature: ModelSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelPackMetadata {
    pub id: String,
    pub version: String,
    pub artifact_class: ArtifactClass,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ArtifactClass {
    Model,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelIdentity {
    pub family: String,
    pub source_revision: String,
    pub resolved_variant_id: String,
    pub format: String,
    pub quantization: String,
    pub tokenizer: String,
    pub tasks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelRuntime {
    pub provider: String,
    pub provider_version: String,
    pub minimum_aiw_core_api: String,
    pub architectures: Vec<String>,
    pub approved_execution_providers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelLicense {
    pub identifier: String,
    pub license_file: String,
    pub license_sha256: String,
    pub redistribution_decision: RedistributionDecision,
    #[serde(default)]
    pub required_notices: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RedistributionDecision {
    PendingReview,
    Approved,
    Prohibited,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelPayload {
    pub root_algorithm: String,
    pub root_hash: String,
    pub no_executable_content: bool,
    pub files: Vec<ModelFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelFile {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelSignature {
    pub canonicalization: String,
    pub detached_signature: String,
    pub required_trust_class: String,
    pub timestamp_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidationIssue {
    pub path: String,
    pub code: String,
    pub message: String,
}

/// Converts a parsed legacy project into the current schema without touching the source file.
///
/// Legacy executable intent is retained only inside a pending review record and is never
/// interpreted as executable or privileged v0alpha2 configuration.
#[must_use]
pub fn migrate_v0alpha1(legacy: &LegacyProjectV0Alpha1) -> Project {
    let mut extensions = BTreeMap::new();
    let legacy_extensions = legacy.extensions.clone();
    let legacy_input = serde_json::json!({
        "arguments": legacy.input.installer.arguments,
        "secrets": legacy.input.secrets,
    });
    extensions.insert("aiw.dev/legacy-v0alpha1-input".to_owned(), legacy_input);

    Project {
        schema_version: PROJECT_SCHEMA_VERSION.to_owned(),
        kind: legacy.kind.clone(),
        metadata: legacy.metadata.clone(),
        application: ApplicationSource::MigrationPending(MigrationPendingApplicationSource {
            path: legacy.input.installer.path.clone(),
            sha256: legacy.input.installer.sha256.clone(),
            expected_signer: legacy.input.installer.expected_signer.clone(),
            may_reboot: legacy.input.installer.may_reboot,
        }),
        isolation_intent: IsolationIntent::default(),
        execution_providers: Vec::new(),
        secrets: legacy.input.secrets.clone(),
        candidates: legacy
            .candidates
            .iter()
            .map(migrate_legacy_candidate)
            .collect(),
        scenarios: legacy
            .scenarios
            .iter()
            .map(migrate_legacy_scenario)
            .collect(),
        assertions: legacy.assertions.clone(),
        analyst: legacy.analyst.clone(),
        migration_review: Some(MigrationReview::Pending(PendingMigrationReview {
            source_schema_version: legacy.schema_version.clone(),
            installer: legacy.input.installer.clone(),
            candidates: legacy.candidates.clone(),
            unresolved_entry_points: legacy_entrypoint_references(legacy),
            legacy_extensions,
        })),
        extensions,
    }
}

fn migrate_legacy_candidate(candidate: &LegacyCandidateV0Alpha1) -> Candidate {
    let config = CandidateConfiguration::MigrationPending {
        legacy_candidate_type: candidate.candidate_type.clone(),
    };
    Candidate {
        id: candidate.id.clone(),
        candidate_type: candidate.candidate_type.clone(),
        experimental: candidate.experimental,
        config,
        extensions: BTreeMap::new(),
    }
}

fn legacy_entrypoint_references(legacy: &LegacyProjectV0Alpha1) -> Vec<String> {
    let mut references = BTreeSet::new();
    for scenario in &legacy.scenarios {
        for step in &scenario.steps {
            if let LegacyScenarioStepV0Alpha1::Launch { entrypoint, .. } = step {
                references.insert(entrypoint.clone());
            }
        }
    }
    references.into_iter().collect()
}

fn migrate_legacy_scenario(scenario: &LegacyScenarioV0Alpha1) -> Scenario {
    Scenario {
        id: scenario.id.clone(),
        description: scenario.description.clone(),
        required: scenario.required,
        steps: scenario
            .steps
            .iter()
            .map(|step| match step {
                LegacyScenarioStepV0Alpha1::Launch {
                    entrypoint,
                    arguments,
                } => ScenarioStep::Launch {
                    entrypoint: entrypoint.clone(),
                    arguments: arguments.clone(),
                },
                LegacyScenarioStepV0Alpha1::ManualCheckpoint { prompt } => {
                    ScenarioStep::OperatorCheckpoint {
                        prompt: prompt.clone(),
                    }
                }
                LegacyScenarioStepV0Alpha1::ExpectProcess { image } => {
                    ScenarioStep::WaitForProcess {
                        image: image.clone(),
                        timeout_seconds: default_wait_timeout_seconds(),
                    }
                }
                LegacyScenarioStepV0Alpha1::ExpectExitCode { value } => {
                    ScenarioStep::ExpectExitCode { value: *value }
                }
            })
            .collect(),
    }
}

pub fn validate_project(project: &Project) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    require_equal(
        &mut issues,
        "$.schemaVersion",
        "unsupportedSchemaVersion",
        &project.schema_version,
        PROJECT_SCHEMA_VERSION,
    );
    require_equal(
        &mut issues,
        "$.kind",
        "unexpectedKind",
        &project.kind,
        PROJECT_KIND,
    );
    validate_id(&mut issues, "$.metadata.name", &project.metadata.name);
    validate_application_source(&mut issues, &project.application);
    validate_migration_review(&mut issues, project);
    validate_extensions(&mut issues, "$.extensions", &project.extensions);
    validate_unique_ids(
        &mut issues,
        "$.executionProviders",
        project
            .execution_providers
            .iter()
            .map(|provider| provider.id()),
    );
    for (index, provider) in project.execution_providers.iter().enumerate() {
        validate_execution_provider(&mut issues, index, provider);
    }

    if project.candidates.is_empty() {
        issue(
            &mut issues,
            "$.candidates",
            "emptyCandidates",
            "at least one candidate is required",
        );
    }
    validate_unique_ids(
        &mut issues,
        "$.candidates",
        project
            .candidates
            .iter()
            .map(|candidate| candidate.id.as_str()),
    );
    for (index, candidate) in project.candidates.iter().enumerate() {
        validate_id(
            &mut issues,
            &format!("$.candidates[{index}].id"),
            &candidate.id,
        );
        validate_candidate(&mut issues, index, candidate, &project.execution_providers);
    }

    if project.scenarios.is_empty() {
        issue(
            &mut issues,
            "$.scenarios",
            "emptyScenarios",
            "at least one scenario is required",
        );
    }
    validate_unique_ids(
        &mut issues,
        "$.scenarios",
        project
            .scenarios
            .iter()
            .map(|scenario| scenario.id.as_str()),
    );
    for (index, scenario) in project.scenarios.iter().enumerate() {
        validate_id(
            &mut issues,
            &format!("$.scenarios[{index}].id"),
            &scenario.id,
        );
        if scenario.steps.is_empty() {
            issue(
                &mut issues,
                &format!("$.scenarios[{index}].steps"),
                "emptyScenario",
                "a scenario must contain at least one step",
            );
        }
        validate_scenario_steps(
            &mut issues,
            index,
            &scenario.steps,
            application_entry_point_ids(&project.application),
            project_requires_migration_review(project),
        );
    }

    if let Some(analyst) = &project.analyst
        && analyst.enabled
    {
        if !analyst.require_evidence_citations {
            issue(
                &mut issues,
                "$.analyst.requireEvidenceCitations",
                "unsafeAnalystConfiguration",
                "an enabled analyst must require evidence citations",
            );
        }
        if !analyst.proposal_requires_human_approval {
            issue(
                &mut issues,
                "$.analyst.proposalRequiresHumanApproval",
                "unsafeAnalystConfiguration",
                "an enabled analyst must require human approval",
            );
        }
        if analyst.provider.model_pack.trim().is_empty() {
            issue(
                &mut issues,
                "$.analyst.provider.modelPack",
                "missingModelPack",
                "an enabled analyst must name a signed model pack",
            );
        }
        if !analyst.provider.require_signed_pack {
            issue(
                &mut issues,
                "$.analyst.provider.requireSignedPack",
                "unsignedModelPack",
                "an enabled analyst must require a signed model pack",
            );
        }
    }

    issues
}

/// Returns structural issues plus a fail-closed blocker while migrated intent awaits review.
/// Future planners and runners must use this validator rather than structural validation alone.
#[must_use]
pub fn validate_project_for_planning(project: &Project) -> Vec<ValidationIssue> {
    let mut issues = validate_project(project);
    if project_requires_migration_review(project) {
        issue(
            &mut issues,
            "$.migrationReview",
            "migrationReviewPending",
            "legacy intent must be reviewed and replaced with executable v0alpha2 configuration",
        );
    }
    issues
}

/// Indicates that a project contains non-executable migration placeholders or a pending review.
#[must_use]
pub fn project_requires_migration_review(project: &Project) -> bool {
    project.migration_review.is_some()
        || matches!(&project.application, ApplicationSource::MigrationPending(_))
        || project.candidates.iter().any(|candidate| {
            matches!(
                &candidate.config,
                CandidateConfiguration::MigrationPending { .. }
            )
        })
}

pub fn validate_model_pack(pack: &ModelPack) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    require_equal(
        &mut issues,
        "$.schemaVersion",
        "unsupportedSchemaVersion",
        &pack.schema_version,
        MODEL_PACK_SCHEMA_VERSION,
    );
    require_equal(
        &mut issues,
        "$.kind",
        "unexpectedKind",
        &pack.kind,
        MODEL_PACK_KIND,
    );
    validate_id(&mut issues, "$.metadata.id", &pack.metadata.id);
    validate_sha256(
        &mut issues,
        "$.license.licenseSha256",
        &pack.license.license_sha256,
    );
    validate_sha256(&mut issues, "$.payload.rootHash", &pack.payload.root_hash);

    if pack.payload.root_algorithm != "sha256-merkle-v1" {
        issue(
            &mut issues,
            "$.payload.rootAlgorithm",
            "unsupportedRootAlgorithm",
            "model packs must use sha256-merkle-v1",
        );
    }
    if pack.signature.canonicalization != "jcs-rfc8785" {
        issue(
            &mut issues,
            "$.signature.canonicalization",
            "unsupportedCanonicalization",
            "model-pack manifests must use jcs-rfc8785 canonicalization",
        );
    }
    if pack.signature.required_trust_class != "model" {
        issue(
            &mut issues,
            "$.signature.requiredTrustClass",
            "invalidTrustClass",
            "a model pack must require the model trust class",
        );
    }
    if !pack.signature.timestamp_required {
        issue(
            &mut issues,
            "$.signature.timestampRequired",
            "timestampRequired",
            "production model packs must require a verifiable signing time",
        );
    }
    if pack.license.redistribution_decision != RedistributionDecision::Approved {
        issue(
            &mut issues,
            "$.license.redistributionDecision",
            "redistributionNotApproved",
            "a distributable model pack requires an explicit approved redistribution decision",
        );
    }

    if !pack.payload.no_executable_content {
        issue(
            &mut issues,
            "$.payload.noExecutableContent",
            "executableContentForbidden",
            "model packs must not contain executable content",
        );
    }
    if pack.payload.files.is_empty() {
        issue(
            &mut issues,
            "$.payload.files",
            "emptyPayload",
            "a model pack must contain at least one payload file",
        );
    }

    let mut paths = BTreeSet::new();
    for (index, file) in pack.payload.files.iter().enumerate() {
        let path = format!("$.payload.files[{index}].path");
        validate_safe_relative_path(&mut issues, &path, &file.path);
        validate_sha256(
            &mut issues,
            &format!("$.payload.files[{index}].sha256"),
            &file.sha256,
        );
        if !paths.insert(file.path.to_ascii_lowercase()) {
            issue(
                &mut issues,
                &path,
                "duplicatePath",
                "payload paths must be unique, ignoring Windows path case",
            );
        }
        if has_executable_extension(&file.path) {
            issue(
                &mut issues,
                &path,
                "executableContentForbidden",
                "executable or script-like file extensions are forbidden in model packs",
            );
        }
    }

    validate_safe_relative_path(
        &mut issues,
        "$.license.licenseFile",
        &pack.license.license_file,
    );
    for (index, notice) in pack.license.required_notices.iter().enumerate() {
        validate_safe_relative_path(
            &mut issues,
            &format!("$.license.requiredNotices[{index}]"),
            notice,
        );
    }
    validate_safe_relative_path(
        &mut issues,
        "$.signature.detachedSignature",
        &pack.signature.detached_signature,
    );
    issues
}

pub fn is_safe_relative_path(value: &str) -> bool {
    if value.trim().is_empty()
        || value.contains('\0')
        || value.starts_with(['/', '\\'])
        || value.as_bytes().get(1).is_some_and(|byte| *byte == b':')
    {
        return false;
    }

    let mut has_segment = false;
    for segment in value.split(['/', '\\']) {
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || segment.ends_with([' ', '.'])
            || segment
                .chars()
                .any(|character| matches!(character, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
            || is_reserved_windows_name(segment)
        {
            return false;
        }
        has_segment = true;
    }
    has_segment
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_application_source(issues: &mut Vec<ValidationIssue>, source: &ApplicationSource) {
    match source {
        ApplicationSource::Msi(source) => {
            validate_file_application_source(issues, "$.application", source);
            validate_source_extension(issues, "$.application.path", &source.path, "msi");
        }
        ApplicationSource::Exe(source) => {
            validate_file_application_source(issues, "$.application", source);
            validate_source_extension(issues, "$.application.path", &source.path, "exe");
        }
        ApplicationSource::PortableDirectory(source) => {
            validate_safe_relative_path(issues, "$.application.path", &source.path);
            validate_sha256(
                issues,
                "$.application.contentManifestSha256",
                &source.content_manifest_sha256,
            );
            validate_entry_points(issues, "$.application.entryPoints", &source.entry_points);
        }
        ApplicationSource::MigrationPending(source) => {
            validate_safe_relative_path(issues, "$.application.path", &source.path);
            validate_sha256(issues, "$.application.sha256", &source.sha256);
        }
    }
}

fn validate_source_extension(
    issues: &mut Vec<ValidationIssue>,
    path: &str,
    source_path: &str,
    expected_extension: &str,
) {
    let extension = source_path
        .rsplit(['/', '\\'])
        .next()
        .and_then(|file_name| file_name.rsplit_once('.'))
        .map_or("", |(_, extension)| extension);
    if !extension.eq_ignore_ascii_case(expected_extension) {
        issue(
            issues,
            path,
            "applicationTypeMismatch",
            &format!("application type requires a .{expected_extension} source"),
        );
    }
}

fn application_entry_point_ids(source: &ApplicationSource) -> &[EntryPoint] {
    match source {
        ApplicationSource::Msi(source) | ApplicationSource::Exe(source) => &source.entry_points,
        ApplicationSource::PortableDirectory(source) => &source.entry_points,
        ApplicationSource::MigrationPending(_) => &[],
    }
}

fn validate_migration_review(issues: &mut Vec<ValidationIssue>, project: &Project) {
    let has_pending_source = matches!(&project.application, ApplicationSource::MigrationPending(_));
    let has_pending_candidate = project.candidates.iter().any(|candidate| {
        matches!(
            &candidate.config,
            CandidateConfiguration::MigrationPending { .. }
        )
    });

    let Some(MigrationReview::Pending(review)) = &project.migration_review else {
        if has_pending_source || has_pending_candidate {
            issue(
                issues,
                "$.migrationReview",
                "missingMigrationReview",
                "migration placeholders require a pending migration review",
            );
        }
        return;
    };

    require_equal(
        issues,
        "$.migrationReview.sourceSchemaVersion",
        "unsupportedLegacySchemaVersion",
        &review.source_schema_version,
        LEGACY_PROJECT_SCHEMA_VERSION,
    );
    validate_safe_relative_path(
        issues,
        "$.migrationReview.installer.path",
        &review.installer.path,
    );
    validate_sha256(
        issues,
        "$.migrationReview.installer.sha256",
        &review.installer.sha256,
    );
    validate_unique_ids(
        issues,
        "$.migrationReview.candidates",
        review
            .candidates
            .iter()
            .map(|candidate| candidate.id.as_str()),
    );
    validate_unique_ids(
        issues,
        "$.migrationReview.unresolvedEntryPoints",
        review.unresolved_entry_points.iter().map(String::as_str),
    );
    for (index, entrypoint) in review.unresolved_entry_points.iter().enumerate() {
        validate_id(
            issues,
            &format!("$.migrationReview.unresolvedEntryPoints[{index}]"),
            entrypoint,
        );
    }
    if !has_pending_source && !has_pending_candidate {
        issue(
            issues,
            "$.migrationReview",
            "staleMigrationReview",
            "remove migrationReview after all executable fields have been resolved",
        );
    }
}

fn validate_file_application_source(
    issues: &mut Vec<ValidationIssue>,
    path: &str,
    source: &FileApplicationSource,
) {
    validate_safe_relative_path(issues, &format!("{path}.path"), &source.path);
    validate_sha256(issues, &format!("{path}.sha256"), &source.sha256);
    validate_entry_points(issues, &format!("{path}.entryPoints"), &source.entry_points);
}

fn validate_entry_points(
    issues: &mut Vec<ValidationIssue>,
    path: &str,
    entry_points: &[EntryPoint],
) {
    validate_unique_ids(
        issues,
        path,
        entry_points
            .iter()
            .map(|entry_point| entry_point.id.as_str()),
    );
    for (index, entry_point) in entry_points.iter().enumerate() {
        validate_id(issues, &format!("{path}[{index}].id"), &entry_point.id);
        validate_safe_relative_path(issues, &format!("{path}[{index}].path"), &entry_point.path);
    }
}

fn validate_execution_provider(
    issues: &mut Vec<ValidationIssue>,
    index: usize,
    provider: &ExecutionProvider,
) {
    let path = format!("$.executionProviders[{index}]");
    validate_id(issues, &format!("{path}.id"), provider.id());
    let (version, executable_sha256) = match provider {
        ExecutionProvider::WindowsSandbox(provider) => {
            (&provider.version, &provider.executable_sha256)
        }
        ExecutionProvider::MxcProcessContainer(provider) => {
            (&provider.version, &provider.executable_sha256)
        }
        ExecutionProvider::Other(provider) => (&provider.version, &provider.executable_sha256),
    };
    if version.trim().is_empty() {
        issue(
            issues,
            &format!("{path}.version"),
            "missingVersion",
            "providers must be version pinned",
        );
    }
    validate_sha256(
        issues,
        &format!("{path}.executableSha256"),
        executable_sha256,
    );
    if matches!(provider, ExecutionProvider::MxcProcessContainer(provider) if !provider.experimental)
    {
        issue(
            issues,
            &format!("{path}.experimental"),
            "experimentalProviderNotMarked",
            "MXC ProcessContainer providers must be marked experimental",
        );
    }
}

fn validate_candidate(
    issues: &mut Vec<ValidationIssue>,
    index: usize,
    candidate: &Candidate,
    providers: &[ExecutionProvider],
) {
    let path = format!("$.candidates[{index}]");
    validate_extensions(issues, &format!("{path}.extensions"), &candidate.extensions);
    match &candidate.config {
        CandidateConfiguration::Baseline => {
            if candidate.candidate_type != CandidateType::UnpackagedBaseline {
                issue(
                    issues,
                    &format!("{path}.config"),
                    "candidateConfigurationMismatch",
                    "baseline configuration requires the unpackagedBaseline candidate type",
                );
            }
        }
        CandidateConfiguration::WindowsSandbox { provider_id, .. } => {
            if candidate.candidate_type != CandidateType::IsolationSession {
                issue(
                    issues,
                    &format!("{path}.config"),
                    "candidateConfigurationMismatch",
                    "windowsSandbox configuration requires the isolationSession candidate type",
                );
            }
            validate_provider_reference(issues, &path, provider_id, providers, "windowsSandbox");
        }
        CandidateConfiguration::MxcProcessContainer { provider_id, .. } => {
            if candidate.candidate_type != CandidateType::ProcessContainer {
                issue(
                    issues,
                    &format!("{path}.config"),
                    "candidateConfigurationMismatch",
                    "mxcProcessContainer configuration requires the processContainer candidate type",
                );
            }
            validate_provider_reference(
                issues,
                &path,
                provider_id,
                providers,
                "mxcProcessContainer",
            );
            if !candidate.experimental {
                issue(
                    issues,
                    &format!("{path}.experimental"),
                    "experimentalCandidateNotMarked",
                    "MXC ProcessContainer candidates must be marked experimental",
                );
            }
        }
        CandidateConfiguration::Msix {
            runtime_boundary,
            capabilities,
            ..
        } => {
            let expected_type = match runtime_boundary {
                RuntimeBoundary::MediumIlFullTrust => CandidateType::FullMsix,
                RuntimeBoundary::AppContainer => CandidateType::ClassicAppContainer,
                RuntimeBoundary::AppSiloPreview => CandidateType::AppSiloMsix,
                RuntimeBoundary::ProcessContainer | RuntimeBoundary::WindowsSandbox => {
                    issue(
                        issues,
                        &format!("{path}.config.runtimeBoundary"),
                        "invalidMsixBoundary",
                        "MSIX candidates may only use full trust, AppContainer, or App Silo runtime boundaries",
                    );
                    return;
                }
            };
            if candidate.candidate_type != expected_type {
                issue(
                    issues,
                    &format!("{path}.config"),
                    "candidateConfigurationMismatch",
                    "MSIX configuration must match the declared candidate type",
                );
            }
            if matches!(runtime_boundary, RuntimeBoundary::AppSiloPreview)
                && !candidate.experimental
            {
                issue(
                    issues,
                    &format!("{path}.experimental"),
                    "experimentalCandidateNotMarked",
                    "App Silo candidates must be marked experimental",
                );
            }
            if capabilities
                .iter()
                .any(|capability| capability.trim().is_empty())
            {
                issue(
                    issues,
                    &format!("{path}.config.capabilities"),
                    "invalidCapability",
                    "capabilities must be non-empty identifiers",
                );
            }
        }
        CandidateConfiguration::MigrationPending {
            legacy_candidate_type,
        } => {
            if &candidate.candidate_type != legacy_candidate_type {
                issue(
                    issues,
                    &format!("{path}.config.legacyCandidateType"),
                    "candidateConfigurationMismatch",
                    "migration placeholder must preserve the legacy candidate type",
                );
            }
        }
    }
}

fn validate_provider_reference(
    issues: &mut Vec<ValidationIssue>,
    path: &str,
    provider_id: &str,
    providers: &[ExecutionProvider],
    expected_type: &str,
) {
    let matching = providers
        .iter()
        .find(|provider| provider.id() == provider_id);
    let valid = matches!(
        (matching, expected_type),
        (Some(ExecutionProvider::WindowsSandbox(_)), "windowsSandbox")
            | (
                Some(ExecutionProvider::MxcProcessContainer(_)),
                "mxcProcessContainer"
            )
    );
    if !valid {
        issue(
            issues,
            &format!("{path}.config.providerId"),
            "invalidProviderReference",
            "candidate configuration must reference a declared provider of the required type",
        );
    }
}

fn validate_scenario_steps(
    issues: &mut Vec<ValidationIssue>,
    index: usize,
    steps: &[ScenarioStep],
    entry_points: &[EntryPoint],
    migration_pending: bool,
) {
    for (step_index, step) in steps.iter().enumerate() {
        let path = format!("$.scenarios[{index}].steps[{step_index}]");
        match step {
            ScenarioStep::Launch { entrypoint, .. } => {
                validate_id(issues, &format!("{path}.entrypoint"), entrypoint);
                if !migration_pending
                    && !entry_points
                        .iter()
                        .any(|declared| declared.id.eq_ignore_ascii_case(entrypoint))
                {
                    issue(
                        issues,
                        &format!("{path}.entrypoint"),
                        "unknownEntryPoint",
                        "launch steps must reference a declared application entry point",
                    );
                }
            }
            ScenarioStep::WaitForProcess {
                image,
                timeout_seconds,
            } => {
                if image.trim().is_empty()
                    || *timeout_seconds == 0
                    || *timeout_seconds > MAX_SCENARIO_TIMEOUT_SECONDS
                {
                    issue(
                        issues,
                        &path,
                        "invalidWait",
                        "process waits require a non-empty image and bounded timeout",
                    );
                }
            }
            ScenarioStep::WaitForWindow {
                title,
                timeout_seconds,
            } => {
                if title.trim().is_empty()
                    || *timeout_seconds == 0
                    || *timeout_seconds > MAX_SCENARIO_TIMEOUT_SECONDS
                {
                    issue(
                        issues,
                        &path,
                        "invalidWait",
                        "window waits require a non-empty title and bounded timeout",
                    );
                }
            }
            ScenarioStep::ObserveFile { path: file_path } => {
                validate_safe_relative_path(issues, &format!("{path}.path"), file_path)
            }
            ScenarioStep::ObserveRegistry { key } => {
                if key.trim().is_empty() {
                    issue(
                        issues,
                        &format!("{path}.key"),
                        "invalidRegistryKey",
                        "registry observations require a non-empty key",
                    );
                }
            }
            ScenarioStep::OperatorCheckpoint { prompt } => {
                if prompt.trim().is_empty() {
                    issue(
                        issues,
                        &format!("{path}.prompt"),
                        "emptyPrompt",
                        "operator checkpoints require a prompt",
                    );
                }
            }
            ScenarioStep::Install
            | ScenarioStep::GracefulClose
            | ScenarioStep::Update
            | ScenarioStep::Uninstall
            | ScenarioStep::RebootContinuation
            | ScenarioStep::ExpectExitCode { .. } => {}
        }
    }
}

fn validate_extensions(
    issues: &mut Vec<ValidationIssue>,
    path: &str,
    extensions: &BTreeMap<String, Value>,
) {
    for key in extensions.keys() {
        if !is_allowed_extension_key(key) {
            issue(
                issues,
                path,
                "invalidExtensionNamespace",
                "extensions must use an allowlisted aiw.dev key or a third-party reverse-DNS namespace",
            );
        }
    }
}

fn is_allowed_extension_key(key: &str) -> bool {
    if key.starts_with("aiw.dev/") {
        return FIRST_PARTY_EXTENSION_KEYS.contains(&key);
    }
    let Some((namespace, name)) = key.split_once('/') else {
        return false;
    };
    !name.is_empty()
        && !name
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        && is_reverse_dns_namespace(namespace)
}

fn is_reverse_dns_namespace(namespace: &str) -> bool {
    let labels: Vec<_> = namespace.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn validate_unique_ids<'a>(
    issues: &mut Vec<ValidationIssue>,
    path: &str,
    values: impl Iterator<Item = &'a str>,
) {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.to_ascii_lowercase()) {
            issue(
                issues,
                path,
                "duplicateId",
                "IDs must be unique, ignoring Windows path case",
            );
        }
    }
}

fn validate_id(issues: &mut Vec<ValidationIssue>, path: &str, value: &str) {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid {
        issue(
            issues,
            path,
            "invalidId",
            "IDs must contain 1-64 lowercase ASCII letters, digits, or hyphens",
        );
    }
}

fn validate_safe_relative_path(issues: &mut Vec<ValidationIssue>, path: &str, value: &str) {
    if !is_safe_relative_path(value) {
        issue(
            issues,
            path,
            "unsafePath",
            "path must be non-empty, relative, and contain no parent traversal",
        );
    }
}

fn validate_sha256(issues: &mut Vec<ValidationIssue>, path: &str, value: &str) {
    if !is_sha256(value) {
        issue(
            issues,
            path,
            "invalidSha256",
            "SHA-256 values must contain exactly 64 hexadecimal characters",
        );
    }
}

fn has_executable_extension(path: &str) -> bool {
    let file_name = path.rsplit(['/', '\\']).next().unwrap_or_default();
    let extension = file_name
        .rsplit_once('.')
        .map_or("", |(_, extension)| extension)
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "exe"
            | "dll"
            | "sys"
            | "com"
            | "scr"
            | "cpl"
            | "ocx"
            | "msi"
            | "msp"
            | "ps1"
            | "psm1"
            | "psd1"
            | "bat"
            | "cmd"
            | "vbs"
            | "js"
            | "jse"
            | "wsf"
            | "hta"
            | "lnk"
    )
}

fn is_reserved_windows_name(segment: &str) -> bool {
    let base = segment
        .split_once('.')
        .map_or(segment, |(base, _)| base)
        .to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
}

fn require_equal(
    issues: &mut Vec<ValidationIssue>,
    path: &str,
    code: &str,
    actual: &str,
    expected: &str,
) {
    if actual != expected {
        issue(
            issues,
            path,
            code,
            &format!("expected '{expected}', found '{actual}'"),
        );
    }
}

fn issue(issues: &mut Vec<ValidationIssue>, path: &str, code: &str, message: &str) {
    issues.push(ValidationIssue {
        path: path.to_owned(),
        code: code.to_owned(),
        message: message.to_owned(),
    });
}

const fn default_true() -> bool {
    true
}

const fn default_wait_timeout_seconds() -> u32 {
    30
}

fn default_in_process() -> String {
    "inProcess".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_project() -> Project {
        Project {
            schema_version: PROJECT_SCHEMA_VERSION.to_owned(),
            kind: PROJECT_KIND.to_owned(),
            metadata: ProjectMetadata {
                name: "contoso-editor".to_owned(),
                display_name: "Contoso Editor".to_owned(),
                owner: "endpoint-engineering".to_owned(),
                labels: BTreeMap::new(),
            },
            application: ApplicationSource::Exe(FileApplicationSource {
                path: "inputs/setup.exe".to_owned(),
                sha256: "a".repeat(64),
                expected_signer: None,
                silent_arguments: Vec::new(),
                entry_points: vec![EntryPoint {
                    id: "main".to_owned(),
                    path: "app/editor.exe".to_owned(),
                    arguments: Vec::new(),
                }],
                architecture: ApplicationArchitecture::X64,
                may_reboot: false,
                update_uninstall: None,
            }),
            isolation_intent: IsolationIntent::default(),
            execution_providers: Vec::new(),
            secrets: Vec::new(),
            candidates: vec![Candidate {
                id: "baseline".to_owned(),
                candidate_type: CandidateType::UnpackagedBaseline,
                experimental: false,
                config: CandidateConfiguration::Baseline,
                extensions: BTreeMap::new(),
            }],
            scenarios: vec![Scenario {
                id: "first-run".to_owned(),
                description: "Launch the app".to_owned(),
                required: true,
                steps: vec![ScenarioStep::Launch {
                    entrypoint: "main".to_owned(),
                    arguments: Vec::new(),
                }],
            }],
            assertions: Assertions::default(),
            analyst: None,
            migration_review: None,
            extensions: BTreeMap::new(),
        }
    }

    fn minimal_model_pack() -> ModelPack {
        ModelPack {
            schema_version: MODEL_PACK_SCHEMA_VERSION.to_owned(),
            kind: MODEL_PACK_KIND.to_owned(),
            metadata: ModelPackMetadata {
                id: "aiw-analyst-small".to_owned(),
                version: "1.0.0".to_owned(),
                artifact_class: ArtifactClass::Model,
            },
            model: ModelIdentity {
                family: "example".to_owned(),
                source_revision: "immutable-revision".to_owned(),
                resolved_variant_id: "example-cpu".to_owned(),
                format: "onnx-genai".to_owned(),
                quantization: "int4".to_owned(),
                tokenizer: "example@immutable-revision".to_owned(),
                tasks: vec!["summarizeEvidence".to_owned()],
            },
            runtime: ModelRuntime {
                provider: "foundryLocal".to_owned(),
                provider_version: "1.0.0".to_owned(),
                minimum_aiw_core_api: "0.1.0".to_owned(),
                architectures: vec!["x64".to_owned()],
                approved_execution_providers: vec!["cpu".to_owned()],
            },
            license: ModelLicense {
                identifier: "Example-License".to_owned(),
                license_file: "licenses/model/LICENSE.txt".to_owned(),
                license_sha256: "b".repeat(64),
                redistribution_decision: RedistributionDecision::Approved,
                required_notices: vec!["licenses/model/NOTICE.txt".to_owned()],
            },
            payload: ModelPayload {
                root_algorithm: "sha256-merkle-v1".to_owned(),
                root_hash: "c".repeat(64),
                no_executable_content: true,
                files: vec![ModelFile {
                    path: "models/default/model.onnx".to_owned(),
                    size_bytes: 42,
                    sha256: "d".repeat(64),
                }],
            },
            signature: ModelSignature {
                canonicalization: "jcs-rfc8785".to_owned(),
                detached_signature: "signature/model-pack.p7s".to_owned(),
                required_trust_class: "model".to_owned(),
                timestamp_required: true,
            },
        }
    }

    #[test]
    fn minimal_project_is_valid() {
        assert!(validate_project(&minimal_project()).is_empty());
    }

    #[test]
    fn traversal_and_absolute_paths_are_rejected() {
        assert!(!is_safe_relative_path("../secret"));
        assert!(!is_safe_relative_path("C:\\Windows\\System32"));
        assert!(!is_safe_relative_path("\\\\server\\share"));
        assert!(!is_safe_relative_path("inputs/file.txt:stream"));
        assert!(!is_safe_relative_path("inputs/CON.txt"));
        assert!(!is_safe_relative_path("inputs/file.txt."));
        assert!(is_safe_relative_path("inputs/setup.exe"));
    }

    #[test]
    fn duplicate_candidate_ids_ignore_case() {
        let mut project = minimal_project();
        project.candidates.push(Candidate {
            id: "BASELINE".to_owned(),
            candidate_type: CandidateType::ProcessContainer,
            experimental: true,
            config: CandidateConfiguration::MxcProcessContainer {
                provider_id: "missing-provider".to_owned(),
                requested_backend: ProcessContainerBackend::AppContainer,
                network: NetworkIntent::Blocked,
            },
            extensions: BTreeMap::new(),
        });
        let issues = validate_project(&project);
        assert!(issues.iter().any(|issue| issue.code == "duplicateId"));
    }

    #[test]
    fn enabled_analyst_requires_signed_pack_and_approval() {
        let mut project = minimal_project();
        project.analyst = Some(Analyst {
            enabled: true,
            authority: AnalystAuthority::AdvisoryOnly,
            execution_placement: AnalystExecutionPlacement::Host,
            provider: AnalystProvider {
                id: "foundryLocal".to_owned(),
                mode: "inProcess".to_owned(),
                model_pack: String::new(),
                require_signed_pack: false,
                allow_catalog_download: false,
            },
            permissions: AnalystPermissions::default(),
            require_evidence_citations: false,
            proposal_requires_human_approval: false,
        });
        let issues = validate_project(&project);
        assert_eq!(issues.len(), 4);
    }

    #[test]
    fn migration_is_pure_preserves_intent_and_blocks_planning() {
        let legacy = LegacyProjectV0Alpha1 {
            schema_version: LEGACY_PROJECT_SCHEMA_VERSION.to_owned(),
            kind: PROJECT_KIND.to_owned(),
            metadata: minimal_project().metadata,
            input: LegacyProjectInput {
                installer: LegacyInstaller {
                    path: "inputs/setup.exe".to_owned(),
                    sha256: "a".repeat(64),
                    expected_signer: Some("Contoso".to_owned()),
                    arguments: BTreeMap::from([
                        ("install".to_owned(), vec!["/quiet".to_owned()]),
                        (
                            "uninstall".to_owned(),
                            vec!["/uninstall".to_owned(), "/quiet".to_owned()],
                        ),
                    ]),
                    may_reboot: false,
                },
                secrets: Vec::new(),
            },
            candidates: vec![LegacyCandidateV0Alpha1 {
                id: "baseline".to_owned(),
                candidate_type: CandidateType::ProcessContainer,
                experimental: true,
                config: BTreeMap::from([(
                    "policy".to_owned(),
                    Value::String("policies/minimal.json".to_owned()),
                )]),
            }],
            scenarios: vec![LegacyScenarioV0Alpha1 {
                id: "first-run".to_owned(),
                description: "Launch the app".to_owned(),
                required: true,
                steps: vec![
                    LegacyScenarioStepV0Alpha1::Launch {
                        entrypoint: "main".to_owned(),
                        arguments: vec!["--first-run".to_owned()],
                    },
                    LegacyScenarioStepV0Alpha1::ExpectProcess {
                        image: "editor.exe".to_owned(),
                    },
                ],
            }],
            assertions: Assertions::default(),
            analyst: None,
            extensions: BTreeMap::from([(
                "aiw.dev/custom".to_owned(),
                Value::String("kept".to_owned()),
            )]),
        };

        let migrated = migrate_v0alpha1(&legacy);
        assert_eq!(legacy.schema_version, LEGACY_PROJECT_SCHEMA_VERSION);
        assert_eq!(migrated.schema_version, PROJECT_SCHEMA_VERSION);
        assert!(!migrated.extensions.contains_key("aiw.dev/custom"));
        assert!(
            migrated
                .extensions
                .contains_key("aiw.dev/legacy-v0alpha1-input")
        );
        assert!(matches!(
            migrated.application,
            ApplicationSource::MigrationPending(_)
        ));
        assert!(matches!(
            migrated.candidates[0].config,
            CandidateConfiguration::MigrationPending {
                legacy_candidate_type: CandidateType::ProcessContainer
            }
        ));
        assert!(migrated.execution_providers.is_empty());
        assert!(matches!(
            migrated.scenarios[0].steps[1],
            ScenarioStep::WaitForProcess { .. }
        ));
        let Some(MigrationReview::Pending(review)) = &migrated.migration_review else {
            panic!("migration must create a pending review");
        };
        assert_eq!(review.installer.arguments, legacy.input.installer.arguments);
        assert_eq!(review.candidates, legacy.candidates);
        assert_eq!(review.unresolved_entry_points, vec!["main"]);
        assert_eq!(review.legacy_extensions, legacy.extensions);
        assert!(validate_project(&migrated).is_empty());
        assert!(
            validate_project_for_planning(&migrated)
                .iter()
                .any(|issue| issue.code == "migrationReviewPending")
        );
        let wire = serde_json::to_value(&migrated).unwrap();
        assert_eq!(wire["migrationReview"]["status"], "pending");
        assert_eq!(
            wire["migrationReview"]["sourceSchemaVersion"],
            LEGACY_PROJECT_SCHEMA_VERSION
        );
        assert_eq!(
            wire["candidates"][0]["config"]["legacyCandidateType"],
            "processContainer"
        );
        let round_trip: Project = serde_json::from_value(wire).unwrap();
        assert_eq!(round_trip, migrated);
        let legacy_wire = serde_json::to_value(&legacy).unwrap();
        let directly_read: Project = serde_json::from_value(legacy_wire).unwrap();
        assert_eq!(directly_read, migrated);
    }

    #[test]
    fn candidate_configuration_cannot_reference_an_undeclared_provider() {
        let mut project = minimal_project();
        project.candidates[0].config = CandidateConfiguration::WindowsSandbox {
            provider_id: "windows-sandbox".to_owned(),
            network: NetworkIntent::Blocked,
        };
        let issues = validate_project(&project);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "invalidProviderReference")
        );
    }

    #[test]
    fn extensions_require_allowlisted_or_third_party_namespaces() {
        let mut project = minimal_project();
        project.extensions.insert(
            "aiw.dev/exec".to_owned(),
            Value::String("not interpreted".to_owned()),
        );
        project
            .extensions
            .insert("com.contoso/assessment-data".to_owned(), Value::Bool(true));
        let issues = validate_project(&project);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "invalidExtensionNamespace")
        );
        project.extensions.remove("aiw.dev/exec");
        assert!(validate_project(&project).is_empty());
    }

    #[test]
    fn tagged_enum_fields_are_camel_case_in_serde_and_schema() {
        let config = CandidateConfiguration::MxcProcessContainer {
            provider_id: "mxc".to_owned(),
            requested_backend: ProcessContainerBackend::AppContainer,
            network: NetworkIntent::Blocked,
        };
        let value = serde_json::to_value(config).unwrap();
        assert_eq!(value["providerId"], "mxc");
        assert_eq!(value["requestedBackend"], "appContainer");
        assert!(value.get("provider_id").is_none());

        let step = serde_json::to_value(ScenarioStep::WaitForProcess {
            image: "editor.exe".to_owned(),
            timeout_seconds: 30,
        })
        .unwrap();
        assert_eq!(step["timeoutSeconds"], 30);
        assert!(step.get("timeout_seconds").is_none());

        let schema = serde_json::to_string(&schemars::schema_for!(Project)).unwrap();
        assert!(schema.contains("providerId"));
        assert!(schema.contains("requestedBackend"));
        assert!(schema.contains("runtimeBoundary"));
        assert!(schema.contains("timeoutSeconds"));
        assert!(!schema.contains("provider_id"));
        assert!(!schema.contains("timeout_seconds"));
    }

    #[test]
    fn launch_requires_declared_entrypoint_outside_migration() {
        let mut project = minimal_project();
        let ScenarioStep::Launch { entrypoint, .. } = &mut project.scenarios[0].steps[0] else {
            unreachable!();
        };
        *entrypoint = "missing".to_owned();
        assert!(
            validate_project(&project)
                .iter()
                .any(|issue| issue.code == "unknownEntryPoint")
        );
    }

    #[test]
    fn application_type_must_match_source_extension() {
        let mut project = minimal_project();
        {
            let ApplicationSource::Exe(source) = &mut project.application else {
                unreachable!();
            };
            source.path = "inputs/setup.msi".to_owned();
        }
        assert!(
            validate_project(&project)
                .iter()
                .any(|issue| issue.code == "applicationTypeMismatch")
        );
        let ApplicationSource::Exe(mut source) = project.application.clone() else {
            unreachable!();
        };
        source.path = "inputs/setup.exe".to_owned();
        project.application = ApplicationSource::Msi(source);
        assert!(
            validate_project(&project)
                .iter()
                .any(|issue| issue.code == "applicationTypeMismatch")
        );
    }

    #[test]
    fn scenario_waits_have_an_upper_bound() {
        let mut project = minimal_project();
        project.scenarios[0]
            .steps
            .push(ScenarioStep::WaitForWindow {
                title: "Editor".to_owned(),
                timeout_seconds: MAX_SCENARIO_TIMEOUT_SECONDS + 1,
            });
        project.scenarios[0]
            .steps
            .push(ScenarioStep::WaitForProcess {
                image: "editor.exe".to_owned(),
                timeout_seconds: MAX_SCENARIO_TIMEOUT_SECONDS + 1,
            });
        assert_eq!(
            validate_project(&project)
                .iter()
                .filter(|issue| issue.code == "invalidWait")
                .count(),
            2
        );
    }

    #[test]
    fn preview_candidates_and_mxc_provider_must_be_marked_experimental() {
        let mut project = minimal_project();
        project
            .execution_providers
            .push(ExecutionProvider::MxcProcessContainer(
                MxcProcessContainerProvider {
                    id: "mxc".to_owned(),
                    version: "1.0".to_owned(),
                    executable_sha256: "b".repeat(64),
                    experimental: false,
                },
            ));
        project.candidates.push(Candidate {
            id: "mxc".to_owned(),
            candidate_type: CandidateType::ProcessContainer,
            experimental: false,
            config: CandidateConfiguration::MxcProcessContainer {
                provider_id: "mxc".to_owned(),
                requested_backend: ProcessContainerBackend::AppContainer,
                network: NetworkIntent::Blocked,
            },
            extensions: BTreeMap::new(),
        });
        project.candidates.push(Candidate {
            id: "app-silo".to_owned(),
            candidate_type: CandidateType::AppSiloMsix,
            experimental: false,
            config: CandidateConfiguration::Msix {
                delivery_model: DeliveryModel::ContainedMsix,
                runtime_boundary: RuntimeBoundary::AppSiloPreview,
                capabilities: Vec::new(),
            },
            extensions: BTreeMap::new(),
        });
        assert_eq!(
            validate_project(&project)
                .iter()
                .filter(|issue| issue.code == "experimentalProviderNotMarked"
                    || issue.code == "experimentalCandidateNotMarked")
                .count(),
            3
        );
    }

    #[test]
    fn migration_placeholders_require_review_record() {
        let mut project = minimal_project();
        project.application =
            ApplicationSource::MigrationPending(MigrationPendingApplicationSource {
                path: "inputs/setup.exe".to_owned(),
                sha256: "a".repeat(64),
                expected_signer: None,
                may_reboot: false,
            });
        assert!(
            validate_project(&project)
                .iter()
                .any(|issue| issue.code == "missingMigrationReview")
        );
    }

    #[test]
    fn minimal_model_pack_is_valid() {
        assert!(validate_model_pack(&minimal_model_pack()).is_empty());
    }

    #[test]
    fn model_pack_rejects_code_duplicate_paths_and_unapproved_redistribution() {
        let mut pack = minimal_model_pack();
        pack.license.redistribution_decision = RedistributionDecision::PendingReview;
        pack.payload.files = vec![
            ModelFile {
                path: "models/native/helper.dll".to_owned(),
                size_bytes: 42,
                sha256: "d".repeat(64),
            },
            ModelFile {
                path: "MODELS/native/helper.dll".to_owned(),
                size_bytes: 42,
                sha256: "e".repeat(64),
            },
        ];
        let issues = validate_model_pack(&pack);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "redistributionNotApproved")
        );
        assert!(issues.iter().any(|issue| issue.code == "duplicatePath"));
        assert_eq!(
            issues
                .iter()
                .filter(|issue| issue.code == "executableContentForbidden")
                .count(),
            2
        );
    }
}
