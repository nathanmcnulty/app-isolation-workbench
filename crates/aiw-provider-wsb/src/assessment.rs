//! Pure portable/offline CLI assessment compiler. No filesystem or execution authority.
//!
//! Callers must separately bind these content facts to protected intake, current
//! worker/agent identities and a fresh approved run. A successful compilation is
//! neither execution, compatibility evidence nor effective-isolation proof.
use std::collections::{BTreeMap, BTreeSet};

use aiw_probe::{PortableContentEntry, PortableContentEntryKind, PortableContentManifest};
use aiw_schema::{ApplicationSource, CandidateConfiguration, NetworkIntent, Project, ScenarioStep};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ASSESSMENT_SETTINGS_SCHEMA: &str = "aiw.dev/assessment-settings/v0alpha1";
pub const COMPILED_ASSESSMENT_SCHEMA: &str = "aiw.dev/compiled-assessment/v0alpha1";
pub const ASSESSMENT_SCOPE: &str = "Portable offline CLI operations in a disposable Windows worker; standard-user roots, bounded captures, exit and declared work-file assertions. Descendant policy, DLL/memory, registry, network denial controls, brokers and all-host coverage are unmeasured.";
const MAX_ENTRIES: usize = 4096;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
const MAX_CAPTURE: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentSettings {
    pub schema_version: String,
    pub scenario_id: String,
    pub candidate_id: String,
    /// Relative to the mutable Work tree; "." means its root. Never a host path.
    pub working_directory: String,
    pub inputs: Vec<AssessmentInput>,
    pub assertions: Vec<AssessmentAssertion>,
    pub total_timeout_seconds: u32,
    pub process_timeout_seconds: u32,
    pub stdout_max_bytes: u64,
    pub stderr_max_bytes: u64,
    pub file_max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentInput {
    pub id: String,
    /// Destination relative to Work, copied from independently held input bytes.
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentAssertion {
    pub id: String,
    pub target: AssessmentAssertionTarget,
    pub expected_sha256: Option<String>,
    pub expected_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AssessmentAssertionTarget {
    Stdout { launch_step: usize },
    Stderr { launch_step: usize },
    WorkFile { path: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentMode {
    Ordinary,
    ClassicAppContainer,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentUserContext {
    StandardUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CompiledAssessmentStep {
    StagePortable,
    Launch {
        entrypoint: String,
        path: String,
        sha256: String,
        size_bytes: u64,
        arguments: Vec<String>,
    },
    ExpectExitCode {
        launch_step: usize,
        value: i32,
    },
    ObserveFile {
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledAssessment {
    pub schema_version: String,
    /// Canonical workflow content identity, excluding labels, host roots and
    /// selected policy/candidate. Pair admission must still verify environment,
    /// user, code custody and explicitly allowed policy differences separately.
    pub semantic_sha256: String,
    pub portable_manifest_sha256: String,
    pub portable_entries: Vec<PortableContentEntry>,
    pub portable_total_size_bytes: u64,
    pub settings: AssessmentSettings,
    pub mode: AssessmentMode,
    pub steps: Vec<CompiledAssessmentStep>,
    pub user_context: AssessmentUserContext,
    /// Requested outer-worker policy; not measured denial evidence.
    pub network_blocked: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AssessmentBlockerCode {
    InvalidProject,
    UnsupportedVersion,
    UnsupportedSource,
    UnsupportedCandidate,
    UnsupportedEvidence,
    UnsupportedStep,
    InvalidManifest,
    UnsafePath,
    InvalidSettings,
    InvalidInput,
    InvalidAssertion,
    MissingEntryPoint,
    InvalidArguments,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentBlocker {
    pub code: AssessmentBlockerCode,
    pub field: String,
    pub message: String,
}
type CompileResult<T> = Result<T, AssessmentBlocker>;
fn reject<T>(
    code: AssessmentBlockerCode,
    field: impl Into<String>,
    message: &str,
) -> CompileResult<T> {
    Err(AssessmentBlocker {
        code,
        field: field.into(),
        message: message.into(),
    })
}
fn hash_ok(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn id_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

/// Deliberately bounded Windows-relative domain. ASCII-only for this first
/// capability avoids pretending Unicode case folding is NTFS normalization.
/// Reparse/link/stream checks remain mandatory at intake and every native open.
pub fn safe_assessment_relative_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 180 || !path.is_ascii() {
        return false;
    }
    path.split('/').all(|part| {
        if part.is_empty()
            || part.len() > 80
            || part == "."
            || part == ".."
            || part.ends_with([' ', '.'])
            || part.starts_with(' ')
            || part
                .bytes()
                .any(|b| b < 32 || b == 127 || b"<>:\\|?*\"".contains(&b))
        {
            return false;
        }
        let stem = part
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end_matches(' ')
            .to_ascii_uppercase();
        !matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
            && !part.contains('~')
    })
}
fn require_path(path: &str, field: &str) -> CompileResult<()> {
    if !safe_assessment_relative_path(path) {
        return reject(
            AssessmentBlockerCode::UnsafePath,
            field,
            "requires a bounded unambiguous ASCII Windows-relative path using '/' separators",
        );
    }
    Ok(())
}

/// Exact existing portable-content framed digest; host root is excluded.
pub fn assessment_manifest_sha256(entries: &[PortableContentEntry]) -> String {
    let mut digest = Sha256::new();
    for entry in entries {
        digest.update((entry.relative_path.len() as u64).to_le_bytes());
        digest.update(entry.relative_path.as_bytes());
        digest.update([match entry.kind {
            PortableContentEntryKind::Directory => 0,
            PortableContentEntryKind::File => 1,
        }]);
        digest.update(entry.size_bytes.to_le_bytes());
        if let Some(hash) = &entry.sha256 {
            digest.update(hex::decode(hash).unwrap_or_default());
        }
    }
    hex::encode(digest.finalize())
}

fn validate_manifest(manifest: &PortableContentManifest) -> CompileResult<()> {
    if manifest.schema_version != aiw_probe::PORTABLE_MANIFEST_SCHEMA
        || manifest.entries.is_empty()
        || manifest.entries.len() > MAX_ENTRIES
        || !hash_ok(&manifest.manifest_sha256)
    {
        return reject(
            AssessmentBlockerCode::InvalidManifest,
            "manifest",
            "invalid version, count or digest",
        );
    }
    let mut names = BTreeMap::new();
    let mut previous: Option<&str> = None;
    let mut total = 0_u64;
    for entry in &manifest.entries {
        require_path(&entry.relative_path, "manifest.entries.path")?;
        if previous.is_some_and(|p| p >= entry.relative_path.as_str())
            || names
                .insert(entry.relative_path.to_ascii_lowercase(), entry.kind)
                .is_some()
        {
            return reject(
                AssessmentBlockerCode::InvalidManifest,
                "manifest.entries",
                "entries must be sorted, unique and free of case aliases",
            );
        }
        match entry.kind {
            PortableContentEntryKind::Directory
                if entry.size_bytes != 0 || entry.sha256.is_some() =>
            {
                return reject(
                    AssessmentBlockerCode::InvalidManifest,
                    "manifest.entries",
                    "directory must have zero size and no hash",
                );
            }
            PortableContentEntryKind::File
                if entry.sha256.as_deref().is_none_or(|h| !hash_ok(h)) =>
            {
                return reject(
                    AssessmentBlockerCode::InvalidManifest,
                    "manifest.entries",
                    "file requires lowercase SHA-256",
                );
            }
            _ => {}
        }
        total = total
            .checked_add(entry.size_bytes)
            .filter(|n| *n <= MAX_TOTAL)
            .ok_or_else(|| AssessmentBlocker {
                code: AssessmentBlockerCode::InvalidManifest,
                field: "manifest.totalSizeBytes".into(),
                message: "portable bytes exceed bound".into(),
            })?;
        previous = Some(&entry.relative_path);
    }
    for entry in &manifest.entries {
        let mut prefix = entry.relative_path.as_str();
        while let Some((parent, _)) = prefix.rsplit_once('/') {
            if !manifest.entries.iter().any(|entry| {
                entry.relative_path == parent && entry.kind == PortableContentEntryKind::Directory
            }) {
                return reject(
                    AssessmentBlockerCode::InvalidManifest,
                    "manifest.entries",
                    "every parent must be an explicit directory",
                );
            }
            prefix = parent;
        }
    }
    if total != manifest.total_size_bytes
        || assessment_manifest_sha256(&manifest.entries) != manifest.manifest_sha256
    {
        return reject(
            AssessmentBlockerCode::InvalidManifest,
            "manifest",
            "framed digest or total size differs",
        );
    }
    Ok(())
}

pub fn compile_assessment(
    project: &Project,
    settings: &AssessmentSettings,
    manifest: &PortableContentManifest,
) -> Result<CompiledAssessment, Vec<AssessmentBlocker>> {
    compile(project, settings, manifest).map_err(|error| vec![error])
}

fn compile(
    project: &Project,
    settings: &AssessmentSettings,
    manifest: &PortableContentManifest,
) -> CompileResult<CompiledAssessment> {
    use AssessmentBlockerCode as B;
    if settings.schema_version != ASSESSMENT_SETTINGS_SCHEMA {
        return reject(
            B::UnsupportedVersion,
            "settings.schemaVersion",
            "unsupported assessment settings version",
        );
    }
    if let Some(issue) = aiw_schema::validate_project_for_planning(project).first() {
        return reject(
            B::InvalidProject,
            "project",
            &format!("project validation failed: {issue:?}"),
        );
    }
    if !project.extensions.is_empty()
        || !project.secrets.is_empty()
        || project.analyst.is_some()
        || project.candidates.iter().any(|c| !c.extensions.is_empty())
    {
        return reject(
            B::InvalidProject,
            "project",
            "extensions, secret authority and analyst execution are unsupported",
        );
    }
    let ApplicationSource::PortableDirectory(source) = &project.application else {
        return reject(
            B::UnsupportedSource,
            "application",
            "first capability supports portable-directory staging only",
        );
    };
    if source.update_uninstall.is_some()
        || source.expected_signer.is_some()
        || source.architecture != aiw_schema::ApplicationArchitecture::X64
    {
        return reject(
            B::UnsupportedSource,
            "application",
            "requires reviewed x64 portable source without signer/update/uninstall claims",
        );
    }
    validate_manifest(manifest)?;
    if source.content_manifest_sha256 != manifest.manifest_sha256 {
        return reject(
            B::InvalidManifest,
            "application.contentManifestSha256",
            "source content differs from reviewed manifest",
        );
    }
    let Some(candidate) = project
        .candidates
        .iter()
        .find(|c| c.id == settings.candidate_id)
    else {
        return reject(
            B::UnsupportedCandidate,
            "settings.candidateId",
            "selected candidate does not exist",
        );
    };
    let mode = match &candidate.config {
        CandidateConfiguration::Baseline => AssessmentMode::Ordinary,
        CandidateConfiguration::ClassicAppContainer {
            network: NetworkIntent::Blocked,
        } => AssessmentMode::ClassicAppContainer,
        _ => {
            return reject(
                B::UnsupportedCandidate,
                "settings.candidateId",
                "supports ordinary standard-user or zero-capability classic AppContainer only",
            );
        }
    };
    let intent = &project.isolation_intent;
    if intent.network != NetworkIntent::Blocked
        || !matches!(
            intent.runtime_boundary,
            aiw_schema::RuntimeBoundary::MediumIlFullTrust
                | aiw_schema::RuntimeBoundary::AppContainer
                | aiw_schema::RuntimeBoundary::WindowsSandbox
        )
        || intent.allow_clipboard
        || intent.allow_host_file_access
        || intent.allow_host_registry_access
        || intent.require_descendant_coverage
        || project.assertions.require_expected_child_coverage
        || project.assertions.require_offline_canary_denied
    {
        return reject(
            B::UnsupportedEvidence,
            "isolationIntent/assertions",
            "host access, clipboard, descendant policy and denial canary requirements are not implemented; only blocked-network request and held root policy/capture are supported",
        );
    }
    if settings.total_timeout_seconds == 0
        || settings.total_timeout_seconds > 300
        || settings.process_timeout_seconds == 0
        || settings.process_timeout_seconds > settings.total_timeout_seconds
        || settings.stdout_max_bytes == 0
        || settings.stdout_max_bytes > MAX_CAPTURE
        || settings.stderr_max_bytes == 0
        || settings.stderr_max_bytes > MAX_CAPTURE
        || settings.file_max_bytes == 0
        || settings.file_max_bytes > 16 * MAX_CAPTURE
        || settings.inputs.len() > 64
        || settings.assertions.is_empty()
        || settings.assertions.len() > 128
    {
        return reject(
            B::InvalidSettings,
            "settings",
            "invalid deadline, capture, file, input or assertion bound",
        );
    }
    if settings.working_directory != "." {
        require_path(&settings.working_directory, "settings.workingDirectory")?;
    }
    let mut input_names = BTreeSet::new();
    let mut input_ids = BTreeSet::new();
    let mut input_total = 0_u64;
    for input in &settings.inputs {
        require_path(&input.path, "settings.inputs.path")?;
        if !id_ok(&input.id)
            || !input_ids.insert(&input.id)
            || !hash_ok(&input.sha256)
            || input.size_bytes > settings.file_max_bytes
            || !input_names.insert(input.path.to_ascii_lowercase())
        {
            return reject(
                B::InvalidInput,
                "settings.inputs",
                "invalid/duplicate input identity, alias or size",
            );
        }
        input_total = input_total
            .checked_add(input.size_bytes)
            .filter(|n| *n <= 64 * MAX_CAPTURE)
            .ok_or_else(|| AssessmentBlocker {
                code: B::InvalidInput,
                field: "settings.inputs".into(),
                message: "input total exceeds bound".into(),
            })?;
    }
    for name in &input_names {
        if input_names
            .iter()
            .any(|other| other != name && other.starts_with(&format!("{name}/")))
            || settings.working_directory.to_ascii_lowercase() == *name
            || settings
                .working_directory
                .to_ascii_lowercase()
                .starts_with(&format!("{name}/"))
        {
            return reject(
                B::InvalidInput,
                "settings.inputs",
                "input file overlaps another file or working directory",
            );
        }
    }
    let Some(scenario) = project
        .scenarios
        .iter()
        .find(|s| s.id == settings.scenario_id)
    else {
        return reject(
            B::InvalidSettings,
            "settings.scenarioId",
            "selected scenario does not exist",
        );
    };
    if scenario.steps.is_empty() || scenario.steps.len() > 64 {
        return reject(B::InvalidSettings, "scenario.steps", "requires 1..64 steps");
    }
    let mut steps = Vec::new();
    let mut last_launch = None;
    let mut staged = false;
    let mut observed = BTreeSet::new();
    for (index, step) in scenario.steps.iter().enumerate() {
        let field = format!("scenario.steps[{index}]");
        match step {
            ScenarioStep::Install if index == 0 && !staged => {
                staged = true;
                steps.push(CompiledAssessmentStep::StagePortable);
            }
            ScenarioStep::Launch {
                entrypoint,
                arguments,
            } if staged => {
                let Some(entry) = source.entry_points.iter().find(|e| e.id == *entrypoint) else {
                    return reject(
                        B::MissingEntryPoint,
                        field,
                        "launch entry point was not reviewed",
                    );
                };
                require_path(&entry.path, &field)?;
                let Some(file) = manifest.entries.iter().find(|f| {
                    f.relative_path == entry.path && f.kind == PortableContentEntryKind::File
                }) else {
                    return reject(
                        B::MissingEntryPoint,
                        field,
                        "entry point is not an exact manifest file",
                    );
                };
                if !entry.path.to_ascii_lowercase().ends_with(".exe") || file.size_bytes == 0 {
                    return reject(
                        B::MissingEntryPoint,
                        field,
                        "requires a nonempty reviewed .exe manifest entry",
                    );
                }
                let argv: Vec<_> = entry.arguments.iter().chain(arguments).cloned().collect();
                if argv.len() > 128
                    || argv.iter().any(|a| a.contains('\0') || a.len() > 4096)
                    || argv
                        .iter()
                        .map(|a| a.encode_utf16().count() + 3)
                        .sum::<usize>()
                        > 16000
                {
                    return reject(
                        B::InvalidArguments,
                        field,
                        "argument vector exceeds count/UTF16 bound or contains NUL",
                    );
                }
                last_launch = Some(index);
                steps.push(CompiledAssessmentStep::Launch {
                    entrypoint: entrypoint.clone(),
                    path: entry.path.clone(),
                    sha256: file.sha256.clone().unwrap_or_default(),
                    size_bytes: file.size_bytes,
                    arguments: argv,
                });
            }
            ScenarioStep::ExpectExitCode { value } if last_launch.is_some() => {
                steps.push(CompiledAssessmentStep::ExpectExitCode {
                    launch_step: last_launch.unwrap_or_default(),
                    value: *value,
                })
            }
            ScenarioStep::ObserveFile { path } if last_launch.is_some() => {
                require_path(path, &field)?;
                let folded = path.to_ascii_lowercase();
                if observed
                    .iter()
                    .any(|p: &String| p.to_ascii_lowercase() == folded)
                    || settings
                        .inputs
                        .iter()
                        .any(|i| i.path != *path && i.path.to_ascii_lowercase() == folded)
                    || folded == settings.working_directory.to_ascii_lowercase()
                    || settings
                        .working_directory
                        .to_ascii_lowercase()
                        .starts_with(&format!("{folded}/"))
                    || input_names.iter().any(|p| {
                        p != &folded
                            && (p.starts_with(&format!("{folded}/"))
                                || folded.starts_with(&format!("{p}/")))
                    })
                {
                    return reject(
                        B::UnsafePath,
                        field,
                        "work file overlaps another file/directory or aliases its spelling",
                    );
                }
                observed.insert(path.clone());
                steps.push(CompiledAssessmentStep::ObserveFile { path: path.clone() });
            }
            _ => {
                let operation = match step {
                    ScenarioStep::Install => "install",
                    ScenarioStep::Launch { .. } => "launch",
                    ScenarioStep::ExpectExitCode { .. } => "expectExitCode",
                    ScenarioStep::ObserveFile { .. } => "observeFile",
                    ScenarioStep::WaitForProcess { .. } => "waitForProcess",
                    ScenarioStep::WaitForWindow { .. } => "waitForWindow",
                    ScenarioStep::WaitForUserClose { .. } => "waitForUserClose",
                    ScenarioStep::ObserveRegistry { .. } => "observeRegistry",
                    ScenarioStep::OperatorCheckpoint { .. } => "operatorCheckpoint",
                    ScenarioStep::GracefulClose => "gracefulClose",
                    ScenarioStep::Update => "update",
                    ScenarioStep::Uninstall => "uninstall",
                    ScenarioStep::RebootContinuation => "rebootContinuation",
                };
                return reject(
                    B::UnsupportedStep,
                    field,
                    &format!(
                        "unsupported operation or ordering: {operation}; requires stage first, then bounded launch, exit expectation or work-file observation"
                    ),
                );
            }
        }
    }
    if last_launch.is_none() {
        return reject(
            B::InvalidSettings,
            "scenario.steps",
            "normal-use assessment requires at least one launch",
        );
    }
    // Match the native result envelope: each captured byte can require two hex
    // characters. Reserve 2 MiB for tokens, assertions and fixed result metadata.
    let launches = steps
        .iter()
        .filter(|step| matches!(step, CompiledAssessmentStep::Launch { .. }))
        .count() as u64;
    let captured_envelope = settings
        .stdout_max_bytes
        .checked_add(settings.stderr_max_bytes)
        .and_then(|bytes| bytes.checked_mul(launches))
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(2 * MAX_CAPTURE));
    if captured_envelope.is_none_or(|bytes| bytes > 16 * MAX_CAPTURE) {
        return reject(
            B::InvalidSettings,
            "settings.captureBudget",
            "aggregate launch captures plus fixed metadata exceed the 16 MiB native result bound",
        );
    }
    validate_work_namespace(settings, &observed)?;
    let mut assertion_ids = BTreeSet::new();
    for assertion in &settings.assertions {
        if !id_ok(&assertion.id)
            || !assertion_ids.insert(&assertion.id)
            || assertion
                .expected_sha256
                .as_deref()
                .is_some_and(|h| !hash_ok(h))
            || (assertion.expected_sha256.is_none() && assertion.expected_size_bytes.is_none())
        {
            return reject(
                B::InvalidAssertion,
                "settings.assertions",
                "assertion requires unique ID and declared exact hash and/or size",
            );
        }
        let bound = match &assertion.target {
            AssessmentAssertionTarget::Stdout { launch_step }
            | AssessmentAssertionTarget::Stderr { launch_step } => {
                if !matches!(
                    steps.get(*launch_step),
                    Some(CompiledAssessmentStep::Launch { .. })
                ) {
                    return reject(
                        B::InvalidAssertion,
                        "settings.assertions.target",
                        "capture must refer to an actual launch step",
                    );
                }
                if matches!(assertion.target, AssessmentAssertionTarget::Stdout { .. }) {
                    settings.stdout_max_bytes
                } else {
                    settings.stderr_max_bytes
                }
            }
            AssessmentAssertionTarget::WorkFile { path } => {
                require_path(path, "settings.assertions.target.path")?;
                if !observed.contains(path) {
                    return reject(
                        B::InvalidAssertion,
                        "settings.assertions.target",
                        "work-file assertion requires explicit ObserveFile step",
                    );
                }
                settings.file_max_bytes
            }
        };
        if assertion
            .expected_size_bytes
            .is_some_and(|size| size > bound)
        {
            return reject(
                B::InvalidAssertion,
                "settings.assertions.expectedSizeBytes",
                "expected bytes exceed capture bound",
            );
        }
    }
    // Selected IDs and descriptive project/scenario labels are deliberately not
    // semantic workflow identity. Actual resolved operations and all content are.
    let semantic = serde_json::json!({ "schemaVersion": COMPILED_ASSESSMENT_SCHEMA,
        "manifestSha256": manifest.manifest_sha256, "steps": steps,
        "workingDirectory": settings.working_directory, "inputs": settings.inputs,
        "assertions": settings.assertions, "totalTimeoutSeconds": settings.total_timeout_seconds,
        "processTimeoutSeconds": settings.process_timeout_seconds, "stdoutMaxBytes": settings.stdout_max_bytes,
        "stderrMaxBytes": settings.stderr_max_bytes, "fileMaxBytes": settings.file_max_bytes,
        "userContext": AssessmentUserContext::StandardUser });
    let semantic_bytes =
        aiw_evidence::canonical_json_bytes(&semantic).map_err(|_| AssessmentBlocker {
            code: B::InvalidSettings,
            field: "settings".into(),
            message: "canonical encoding failed".into(),
        })?;
    Ok(CompiledAssessment {
        schema_version: COMPILED_ASSESSMENT_SCHEMA.into(),
        semantic_sha256: hex::encode(Sha256::digest(semantic_bytes)),
        portable_manifest_sha256: manifest.manifest_sha256.clone(),
        portable_entries: manifest.entries.clone(),
        portable_total_size_bytes: manifest.total_size_bytes,
        settings: settings.clone(),
        mode,
        steps,
        user_context: AssessmentUserContext::StandardUser,
        network_blocked: true,
    })
}

fn validate_work_namespace(
    settings: &AssessmentSettings,
    observed: &BTreeSet<String>,
) -> CompileResult<()> {
    let mut names: BTreeMap<String, (String, bool)> = BTreeMap::new();
    let cwd =
        (settings.working_directory != ".").then_some((settings.working_directory.as_str(), false));
    for (path, is_file) in cwd
        .into_iter()
        .chain(
            settings
                .inputs
                .iter()
                .map(|input| (input.path.as_str(), true)),
        )
        .chain(observed.iter().map(|path| (path.as_str(), true)))
    {
        let parts: Vec<_> = path.split('/').collect();
        for index in 1..=parts.len() {
            let name = parts[..index].join("/");
            let file = is_file && index == parts.len();
            if let Some((original, original_file)) = names.get(&name.to_ascii_lowercase()) {
                if original != &name || *original_file != file {
                    return reject(
                        AssessmentBlockerCode::UnsafePath,
                        "settings.workNamespace",
                        "directory case alias or file/directory overlap",
                    );
                }
            } else {
                names.insert(name.to_ascii_lowercase(), (name, file));
            }
        }
    }
    Ok(())
}

impl CompiledAssessment {
    /// Independent worker-wire validation, sharing the compiler's full checks.
    /// The reconstructed project is a validation device, NOT original intake or
    /// operator authority. Host admission must additionally recompile and compare
    /// the independently protected original project/settings/source manifest.
    pub fn validate(&self) -> Result<(), AssessmentBlocker> {
        use AssessmentBlockerCode as B;
        if self.schema_version != COMPILED_ASSESSMENT_SCHEMA || !self.network_blocked {
            return reject(
                B::UnsupportedVersion,
                "compiled",
                "unsupported version or network policy",
            );
        }
        if self.steps.len() > 64
            || self.portable_entries.len() > MAX_ENTRIES
            || self.settings.inputs.len() > 64
            || self.settings.assertions.len() > 128
        {
            return reject(
                B::InvalidSettings,
                "compiled",
                "wire collection bounds exceeded",
            );
        }
        let mut entries = BTreeMap::new();
        let mut scenario = Vec::new();
        for step in &self.steps {
            scenario.push(match step {
                CompiledAssessmentStep::StagePortable => ScenarioStep::Install,
                CompiledAssessmentStep::Launch {
                    entrypoint,
                    path,
                    arguments,
                    ..
                } => {
                    if entries
                        .insert(entrypoint.clone(), path.clone())
                        .is_some_and(|old| old != *path)
                    {
                        return reject(
                            B::MissingEntryPoint,
                            "compiled.steps",
                            "entry ID resolves to different code paths",
                        );
                    }
                    ScenarioStep::Launch {
                        entrypoint: entrypoint.clone(),
                        arguments: arguments.clone(),
                    }
                }
                CompiledAssessmentStep::ExpectExitCode { value, .. } => {
                    ScenarioStep::ExpectExitCode { value: *value }
                }
                CompiledAssessmentStep::ObserveFile { path } => {
                    ScenarioStep::ObserveFile { path: path.clone() }
                }
            });
        }
        let (candidate_type, config) = match self.mode {
            AssessmentMode::Ordinary => {
                ("unpackagedBaseline", serde_json::json!({"type":"baseline"}))
            }
            AssessmentMode::ClassicAppContainer => (
                "classicAppContainer",
                serde_json::json!({"type":"classicAppContainer","network":"blocked"}),
            ),
        };
        let entry_points: Vec<_> = entries
            .into_iter()
            .map(|(id, path)| serde_json::json!({"id":id,"path":path,"arguments":[]}))
            .collect();
        let project: Project = serde_json::from_value(serde_json::json!({
            "schemaVersion": aiw_schema::PROJECT_SCHEMA_VERSION, "kind": aiw_schema::PROJECT_KIND,
            "metadata":{"name":"wire-validation","displayName":"Wire validation only","owner":"local"},
            "application":{"type":"portableDirectory","path":"source","contentManifestSha256":self.portable_manifest_sha256,"architecture":"x64","entryPoints":entry_points},
            "isolationIntent":{"runtimeBoundary":"windowsSandbox","network":"blocked","allowClipboard":false,"allowHostFileAccess":false,"allowHostRegistryAccess":false,"requireDescendantCoverage":false},
            "candidates":[{"id":self.settings.candidate_id,"type":candidate_type,"config":config}],
            "scenarios":[{"id":self.settings.scenario_id,"description":"Wire validation only","steps":scenario}],
            "assertions":{"requireEffectiveBackendMatch":true,"requireTargetTokenEvidence":true,"requireExpectedChildCoverage":false,"requireOfflineCanaryDenied":false,"failOnEvidenceTruncation":true}
        })).map_err(|_| AssessmentBlocker { code: B::InvalidSettings, field:"compiled".into(), message:"invalid reconstructed wire data".into() })?;
        let manifest = PortableContentManifest {
            schema_version: aiw_probe::PORTABLE_MANIFEST_SCHEMA.into(),
            root_path: String::new(),
            entries: self.portable_entries.clone(),
            total_size_bytes: self.portable_total_size_bytes,
            manifest_sha256: self.portable_manifest_sha256.clone(),
        };
        let expected = compile(&project, &self.settings, &manifest)?;
        if self != &expected {
            return reject(
                B::InvalidSettings,
                "compiled",
                "resolved operations, content or semantic commitment differ",
            );
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fixture() -> (Project, AssessmentSettings, PortableContentManifest) {
        let entries = vec![PortableContentEntry {
            relative_path: "tool.exe".into(),
            kind: PortableContentEntryKind::File,
            size_bytes: 3,
            sha256: Some(hex::encode(Sha256::digest(b"abc"))),
        }];
        let manifest = PortableContentManifest {
            schema_version: aiw_probe::PORTABLE_MANIFEST_SCHEMA.into(),
            root_path: "C:\\private\\unknown-app".into(),
            manifest_sha256: assessment_manifest_sha256(&entries),
            entries,
            total_size_bytes: 3,
        };
        let project: Project = serde_json::from_value(serde_json::json!({
            "schemaVersion": aiw_schema::PROJECT_SCHEMA_VERSION, "kind": aiw_schema::PROJECT_KIND,
            "metadata":{"name":"unlisted-tool","displayName":"Unknown tool","owner":"administrator"},
            "application":{"type":"portableDirectory","path":"private-input","contentManifestSha256":manifest.manifest_sha256,"architecture":"x64","entryPoints":[{"id":"main","path":"tool.exe"}]},
            "isolationIntent":{"runtimeBoundary":"windowsSandbox","network":"blocked","allowClipboard":false,"allowHostFileAccess":false,"allowHostRegistryAccess":false,"requireDescendantCoverage":false},
            "candidates":[{"id":"ordinary","type":"unpackagedBaseline","config":{"type":"baseline"}},{"id":"candidate","type":"classicAppContainer","config":{"type":"classicAppContainer","network":"blocked"}}],
            "scenarios":[{"id":"workflow","description":"Declared CLI work","steps":[{"type":"install"},{"type":"launch","entrypoint":"main","arguments":["--read","input.json"]},{"type":"expectExitCode","value":0}]}],
            "assertions":{"requireEffectiveBackendMatch":true,"requireTargetTokenEvidence":true,"requireExpectedChildCoverage":false,"requireOfflineCanaryDenied":false,"failOnEvidenceTruncation":true}
        })).unwrap();
        let settings = AssessmentSettings {
            schema_version: ASSESSMENT_SETTINGS_SCHEMA.into(),
            scenario_id: "workflow".into(),
            candidate_id: "ordinary".into(),
            working_directory: ".".into(),
            inputs: vec![AssessmentInput {
                id: "input".into(),
                path: "input.json".into(),
                sha256: hex::encode(Sha256::digest(b"{}")),
                size_bytes: 2,
            }],
            assertions: vec![AssessmentAssertion {
                id: "stdout".into(),
                target: AssessmentAssertionTarget::Stdout { launch_step: 1 },
                expected_sha256: None,
                expected_size_bytes: Some(3),
            }],
            total_timeout_seconds: 60,
            process_timeout_seconds: 20,
            stdout_max_bytes: 4096,
            stderr_max_bytes: 4096,
            file_max_bytes: 8192,
        };
        (project, settings, manifest)
    }

    #[test]
    fn unlisted_labels_and_host_roots_are_not_admission_or_semantic_identity() {
        let (mut project, mut settings, mut manifest) = fixture();
        let ordinary = compile_assessment(&project, &settings, &manifest).unwrap();
        ordinary.validate().unwrap();
        project.metadata.name = "another-unlisted-tool".into();
        project.metadata.display_name = "A different descriptive label".into();
        project.scenarios[0].description = "Renamed only".into();
        manifest.root_path = "D:\\different-private-source".into();
        let renamed = compile_assessment(&project, &settings, &manifest).unwrap();
        assert_eq!(ordinary, renamed);
        settings.candidate_id = "candidate".into();
        let candidate = compile_assessment(&project, &settings, &manifest).unwrap();
        candidate.validate().unwrap();
        assert_eq!(ordinary.semantic_sha256, candidate.semantic_sha256);
        assert_ne!(ordinary.mode, candidate.mode);
        assert!(
            !serde_json::to_string(&candidate)
                .unwrap()
                .contains("private-source")
        );
    }

    #[test]
    fn payload_and_input_changes_bind_semantics_and_original_manifest() {
        let (mut project, settings, mut manifest) = fixture();
        let original = compile_assessment(&project, &settings, &manifest).unwrap();
        manifest.entries[0].sha256 = Some("b".repeat(64));
        assert_eq!(
            compile_assessment(&project, &settings, &manifest).unwrap_err()[0].code,
            AssessmentBlockerCode::InvalidManifest
        );
        manifest.manifest_sha256 = assessment_manifest_sha256(&manifest.entries);
        assert!(compile_assessment(&project, &settings, &manifest).is_err());
        let ApplicationSource::PortableDirectory(source) = &mut project.application else {
            unreachable!()
        };
        source.content_manifest_sha256 = manifest.manifest_sha256.clone();
        let changed = compile_assessment(&project, &settings, &manifest).unwrap();
        assert_ne!(original.semantic_sha256, changed.semantic_sha256);
        assert_ne!(original.steps, changed.steps);
        let mut input_changed = settings;
        input_changed.inputs[0].sha256 = "e".repeat(64);
        assert_ne!(
            changed.semantic_sha256,
            compile_assessment(&project, &input_changed, &manifest)
                .unwrap()
                .semantic_sha256
        );
    }

    #[test]
    fn unsupported_operations_and_required_measurements_have_typed_blockers() {
        let (mut project, settings, manifest) = fixture();
        project.scenarios[0]
            .steps
            .push(ScenarioStep::ObserveRegistry {
                key: "HKCU/Software/Test".into(),
            });
        let error = compile_assessment(&project, &settings, &manifest).unwrap_err();
        assert_eq!(error[0].code, AssessmentBlockerCode::UnsupportedStep);
        assert_eq!(error[0].field, "scenario.steps[3]");
        project.scenarios[0].steps.pop();
        project.assertions.require_expected_child_coverage = true;
        assert_eq!(
            compile_assessment(&project, &settings, &manifest).unwrap_err()[0].code,
            AssessmentBlockerCode::UnsupportedEvidence
        );
    }

    #[test]
    fn windows_aliases_escape_and_unreviewed_launches_are_refused() {
        for path in [
            "../outside",
            "C:/absolute",
            "a\\b",
            "file:stream",
            "a//b",
            "./a",
            "CON.txt",
            "con .txt",
            "COM1",
            "x.",
            "x ",
            "a~1.exe",
            "\\\\server\\share",
            "unicode-\u{0130}",
            "a/../b",
        ] {
            assert!(!safe_assessment_relative_path(path), "{path}");
        }
        let (mut project, mut settings, manifest) = fixture();
        settings.inputs.push(AssessmentInput {
            id: "alias".into(),
            path: "INPUT.JSON".into(),
            sha256: "b".repeat(64),
            size_bytes: 1,
        });
        assert_eq!(
            compile_assessment(&project, &settings, &manifest).unwrap_err()[0].code,
            AssessmentBlockerCode::InvalidInput
        );
        settings.inputs.pop();
        settings.inputs[0].path = "directory".into();
        settings.working_directory = "directory/subdir".into();
        assert!(compile_assessment(&project, &settings, &manifest).is_err());
        settings.working_directory = ".".into();
        if let ScenarioStep::Launch { entrypoint, .. } = &mut project.scenarios[0].steps[1] {
            *entrypoint = "unreviewed".into();
        }
        assert!(compile_assessment(&project, &settings, &manifest).is_err());
    }

    #[test]
    fn manifest_requires_sorted_complete_ancestry_valid_totals_and_no_aliases() {
        let (project, settings, manifest) = fixture();
        for mutate in 0..5 {
            let mut bad = manifest.clone();
            match mutate {
                0 => bad.total_size_bytes += 1,
                1 => bad.entries[0].sha256 = Some("F".repeat(64)),
                2 => bad.entries[0].relative_path = "missing/tool.exe".into(),
                3 => {
                    let mut alias = bad.entries[0].clone();
                    alias.relative_path = "TOOL.EXE".into();
                    bad.entries.insert(0, alias);
                }
                _ => bad.entries[0].kind = PortableContentEntryKind::Directory,
            }
            assert!(
                compile_assessment(&project, &settings, &bad).is_err(),
                "mutation {mutate}"
            );
        }
    }

    #[test]
    fn stateful_multiple_launches_and_declared_file_assertion_are_supported() {
        let (mut project, mut settings, manifest) = fixture();
        project.scenarios[0].steps.extend([
            ScenarioStep::Launch {
                entrypoint: "main".into(),
                arguments: vec!["--update".into(), "state.db".into()],
            },
            ScenarioStep::ExpectExitCode { value: 0 },
            ScenarioStep::ObserveFile {
                path: "state.db".into(),
            },
        ]);
        settings.assertions.push(AssessmentAssertion {
            id: "database".into(),
            target: AssessmentAssertionTarget::WorkFile {
                path: "state.db".into(),
            },
            expected_sha256: None,
            expected_size_bytes: Some(4096),
        });
        let compiled = compile_assessment(&project, &settings, &manifest).unwrap();
        assert!(matches!(
            compiled.steps[4],
            CompiledAssessmentStep::ExpectExitCode {
                launch_step: 3,
                value: 0
            }
        ));
        compiled.validate().unwrap();
    }

    #[test]
    fn compiled_wire_revalidation_rejects_forged_fields_and_bindings() {
        let (project, settings, manifest) = fixture();
        let plan = compile_assessment(&project, &settings, &manifest).unwrap();
        for mutate in 0..8 {
            let mut bad = plan.clone();
            match mutate {
                0 => bad.semantic_sha256 = "0".repeat(64),
                1 => bad.network_blocked = false,
                2 => bad.settings.process_timeout_seconds = 301,
                3 => bad.settings.working_directory = "../escape".into(),
                4 => {
                    if let CompiledAssessmentStep::Launch { sha256, .. } = &mut bad.steps[1] {
                        *sha256 = "d".repeat(64);
                    }
                }
                5 => {
                    if let CompiledAssessmentStep::ExpectExitCode { launch_step, .. } =
                        &mut bad.steps[2]
                    {
                        *launch_step = 0;
                    }
                }
                6 => {
                    bad.settings.assertions[0].target =
                        AssessmentAssertionTarget::Stdout { launch_step: 99 }
                }
                _ => {
                    if let CompiledAssessmentStep::Launch { arguments, .. } = &mut bad.steps[1] {
                        arguments.push("nul\0arg".into());
                    }
                }
            }
            assert!(bad.validate().is_err(), "mutation {mutate}");
        }
    }

    #[test]
    fn settings_and_wire_versions_and_unknown_fields_fail_closed() {
        let (project, mut settings, manifest) = fixture();
        let mut value = serde_json::to_value(&settings).unwrap();
        value["shell"] = serde_json::json!("unreviewed");
        assert!(serde_json::from_value::<AssessmentSettings>(value).is_err());
        settings.schema_version = "aiw.dev/assessment-settings/future".into();
        assert_eq!(
            compile_assessment(&project, &settings, &manifest).unwrap_err()[0].code,
            AssessmentBlockerCode::UnsupportedVersion
        );
        settings.schema_version = ASSESSMENT_SETTINGS_SCHEMA.into();
        let plan = compile_assessment(&project, &settings, &manifest).unwrap();
        let mut value = serde_json::to_value(&plan).unwrap();
        value["steps"][1]["shell"] = serde_json::json!(true);
        assert!(serde_json::from_value::<CompiledAssessment>(value).is_err());
        let mut future = plan;
        future.schema_version = "future".into();
        assert!(future.validate().is_err());
    }

    #[test]
    fn aggregate_capture_budget_has_exact_native_boundary_and_cannot_be_forged() {
        let (mut project, mut settings, manifest) = fixture();
        settings.stdout_max_bytes = MAX_CAPTURE / 2;
        settings.stderr_max_bytes = MAX_CAPTURE / 2;
        // Seven launches: 7 * (512 KiB + 512 KiB) * 2 + 2 MiB = 16 MiB.
        for _ in 0..6 {
            project.scenarios[0].steps.push(ScenarioStep::Launch {
                entrypoint: "main".into(),
                arguments: vec![],
            });
        }
        let accepted = compile_assessment(&project, &settings, &manifest).unwrap();
        accepted.validate().unwrap();
        let mut oversized = settings.clone();
        oversized.stdout_max_bytes += 1;
        let error = compile_assessment(&project, &oversized, &manifest).unwrap_err();
        assert_eq!(error[0].code, AssessmentBlockerCode::InvalidSettings);
        assert_eq!(error[0].field, "settings.captureBudget");
        project.scenarios[0].steps.push(ScenarioStep::Launch {
            entrypoint: "main".into(),
            arguments: vec![],
        });
        assert!(compile_assessment(&project, &settings, &manifest).is_err());
        let mut forged = accepted;
        forged.settings.stdout_max_bytes += 1;
        assert!(forged.validate().is_err());
        assert!(!safe_assessment_relative_path("bad\u{7f}name"));
    }
}
