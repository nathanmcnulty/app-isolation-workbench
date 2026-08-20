#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROJECT_SCHEMA_VERSION: &str = "aiw.dev/v0alpha1";
pub const PROJECT_KIND: &str = "AppIsolationProject";
pub const MODEL_PACK_SCHEMA_VERSION: &str = "aiw.dev/model-pack/v0alpha1";
pub const MODEL_PACK_KIND: &str = "AIWModelPack";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    pub schema_version: String,
    pub kind: String,
    pub metadata: ProjectMetadata,
    pub input: ProjectInput,
    pub candidates: Vec<Candidate>,
    pub scenarios: Vec<Scenario>,
    #[serde(default)]
    pub assertions: Assertions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyst: Option<Analyst>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
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
pub struct ProjectInput {
    pub installer: Installer,
    #[serde(default)]
    pub secrets: Vec<SecretReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Installer {
    pub path: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signer: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub arguments: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub may_reboot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub id: String,
    pub provider: String,
    pub reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    #[serde(rename = "type")]
    pub candidate_type: CandidateType,
    #[serde(default)]
    pub experimental: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, Value>,
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
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum ScenarioStep {
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
    validate_safe_relative_path(
        &mut issues,
        "$.input.installer.path",
        &project.input.installer.path,
    );
    validate_sha256(
        &mut issues,
        "$.input.installer.sha256",
        &project.input.installer.sha256,
    );

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
            input: ProjectInput {
                installer: Installer {
                    path: "inputs/setup.exe".to_owned(),
                    sha256: "a".repeat(64),
                    expected_signer: None,
                    arguments: BTreeMap::new(),
                    may_reboot: false,
                },
                secrets: Vec::new(),
            },
            candidates: vec![Candidate {
                id: "baseline".to_owned(),
                candidate_type: CandidateType::UnpackagedBaseline,
                experimental: false,
                config: BTreeMap::new(),
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
            config: BTreeMap::new(),
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
