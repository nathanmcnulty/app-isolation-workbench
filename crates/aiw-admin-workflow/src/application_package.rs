//! Data-only replay packages. No approvals, sessions, tools or execution credit.
use super::*;
#[cfg(windows)]
use aiw_provider_wsb::assessment::{
    AssessmentAssertion, AssessmentInput, AssessmentMode, AssessmentSettings,
    AssessmentUserContext, CompiledAssessmentStep,
};
use aiw_provider_wsb::assessment::{CompiledAssessment, compile_assessment};
#[cfg(windows)]
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationReplayPackage {
    pub schema_version: String,
    pub project: Project,
    pub compiled: CompiledAssessment,
}

#[derive(Debug)]
pub struct ReplayManifestParseError {
    description: &'static str,
    line: usize,
    column: usize,
}

impl std::fmt::Display for ReplayManifestParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "package.json: {} at line {}, column {}",
            self.description, self.line, self.column
        )
    }
}

impl std::error::Error for ReplayManifestParseError {}

#[cfg(any(windows, test))]
fn parse_replay_manifest(
    bytes: &[u8],
) -> Result<ApplicationReplayPackage, ReplayManifestParseError> {
    serde_json::from_slice(bytes).map_err(|error| ReplayManifestParseError {
        description: match error.classify() {
            serde_json::error::Category::Syntax => "invalid JSON syntax",
            serde_json::error::Category::Eof => "unexpected end of JSON",
            serde_json::error::Category::Data => "JSON does not match the replay manifest schema",
            serde_json::error::Category::Io => "JSON could not be read",
        },
        line: error.line(),
        column: error.column(),
    })
}

const REPLAY_PACKAGE_SCHEMA: &str = "aiw.dev/application-replay-package/v0alpha1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayValidationError {
    MissingManifest,
    UnsupportedSchema,
    InvalidPlan,
    InventoryMismatch {
        missing: usize,
        unexpected: usize,
        wrong_kind: usize,
    },
    ContentMismatch,
    InvalidExpectedManifestSha256,
    ManifestSha256Mismatch,
}

impl std::fmt::Display for ReplayValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingManifest => f.write_str("package.json is required as a file"),
            Self::UnsupportedSchema => {
                write!(
                    f,
                    "package.json schemaVersion must be {REPLAY_PACKAGE_SCHEMA}"
                )
            }
            Self::InvalidPlan => f.write_str(
                "package.json compiled plan fails validation or differs from the project",
            ),
            Self::InventoryMismatch {
                missing,
                unexpected,
                wrong_kind,
            } => write!(
                f,
                "replay inventory differs ({missing} missing, {unexpected} unexpected, {wrong_kind} wrong entry type)"
            ),
            Self::ContentMismatch => {
                f.write_str("replay file size or SHA-256 differs from the reviewed package")
            }
            Self::InvalidExpectedManifestSha256 => {
                f.write_str("expected package manifest hash must be lowercase SHA-256")
            }
            Self::ManifestSha256Mismatch => {
                f.write_str("package.json SHA-256 differs from the supplied review identity")
            }
        }
    }
}

impl std::error::Error for ReplayValidationError {}

impl ApplicationReplayPackage {
    pub fn validate(&self) -> Result<()> {
        use anyhow::Context;

        if self.schema_version != REPLAY_PACKAGE_SCHEMA {
            return Err(ReplayValidationError::UnsupportedSchema.into());
        }
        self.compiled
            .validate()
            .map_err(|e| anyhow!("invalid package plan: {e:?}"))
            .context(ReplayValidationError::InvalidPlan)?;
        let manifest = aiw_probe::PortableContentManifest {
            schema_version: aiw_probe::PORTABLE_MANIFEST_SCHEMA.into(),
            root_path: "external".into(),
            entries: self.compiled.portable_entries.clone(),
            total_size_bytes: self.compiled.portable_total_size_bytes,
            manifest_sha256: self.compiled.portable_manifest_sha256.clone(),
        };
        let actual = compile_assessment(&self.project, &self.compiled.settings, &manifest)
            .map_err(|e| anyhow!("package capabilities blocked: {e:?}"))
            .context(ReplayValidationError::InvalidPlan)?;
        if actual != self.compiled {
            return Err(ReplayValidationError::InvalidPlan.into());
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct VerifiedApplicationReplayPackage {
    pub package: ApplicationReplayPackage,
    pub source: PathBuf,
    pub inputs: BTreeMap<String, PathBuf>,
    manifest_sha256: String,
    held: aiw_windows_platform::HeldPortableDirectory,
}

#[cfg(windows)]
impl VerifiedApplicationReplayPackage {
    pub(super) fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn revalidate(&self) -> Result<()> {
        self.held.revalidate().map_err(Into::into)
    }
}

/// Strict closed inventory, exact hashes and compiler reuse. Never executes.
#[cfg(windows)]
pub fn verify_package(path: &Path) -> Result<VerifiedApplicationReplayPackage> {
    verify_package_with_manifest_sha256(path, None)
}

/// Verify the package and optionally require its exact reviewed manifest bytes.
#[cfg(windows)]
pub fn verify_package_with_manifest_sha256(
    path: &Path,
    expected_manifest_sha256: Option<&str>,
) -> Result<VerifiedApplicationReplayPackage> {
    use aiw_probe::PortableContentEntryKind as Kind;
    if expected_manifest_sha256.is_some_and(|expected| {
        expected.len() != 64
            || !expected
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }) {
        return Err(ReplayValidationError::InvalidExpectedManifestSha256.into());
    }
    let held = aiw_windows_platform::HeldPortableDirectory::open_replay_package(path)?;
    if !held
        .manifest()
        .entries
        .iter()
        .any(|entry| entry.relative_path == "package.json" && entry.kind == Kind::File)
    {
        return Err(ReplayValidationError::MissingManifest.into());
    }
    let root = PathBuf::from(&held.manifest().root_path);
    let manifest_file = aiw_windows_platform::HeldApplicationFile::open_bounded(
        &root.join("package.json"),
        2 * 1024 * 1024,
    )?;
    let package = parse_replay_manifest(&read_file_bounded(
        &root.join("package.json"),
        2 * 1024 * 1024,
    )?)?;
    package.validate()?;
    let mut expected: BTreeMap<String, (Kind, u64, Option<String>)> = BTreeMap::new();
    expected.insert("payload".into(), (Kind::Directory, 0, None));
    expected.insert("inputs".into(), (Kind::Directory, 0, None));
    expected.insert(
        "package.json".into(),
        (
            Kind::File,
            manifest_file.observation().size_bytes,
            Some(manifest_file.observation().sha256.clone()),
        ),
    );
    for entry in &package.compiled.portable_entries {
        expected.insert(
            format!("payload/{}", entry.relative_path),
            (entry.kind, entry.size_bytes, entry.sha256.clone()),
        );
    }
    let mut inputs = BTreeMap::new();
    for (index, input) in package.compiled.settings.inputs.iter().enumerate() {
        let leaf = format!("input-{index:04}.bin");
        expected.insert(
            format!("inputs/{leaf}"),
            (Kind::File, input.size_bytes, Some(input.sha256.clone())),
        );
        inputs.insert(input.id.clone(), root.join("inputs").join(leaf));
    }
    let actual: BTreeMap<_, _> = held
        .manifest()
        .entries
        .iter()
        .map(|entry| {
            (
                entry.relative_path.clone(),
                (entry.kind, entry.size_bytes, entry.sha256.clone()),
            )
        })
        .collect();
    if actual != expected {
        let mut missing = 0;
        let mut wrong_kind = 0;
        for (path, (kind, _, _)) in &expected {
            match actual.get(path) {
                None => missing += 1,
                Some(entry) if entry.0 != *kind => wrong_kind += 1,
                Some(_) => {}
            }
        }
        let unexpected = actual
            .keys()
            .filter(|path| !expected.contains_key(*path))
            .count();
        if missing != 0 || unexpected != 0 || wrong_kind != 0 {
            return Err(ReplayValidationError::InventoryMismatch {
                missing,
                unexpected,
                wrong_kind,
            }
            .into());
        }
        return Err(ReplayValidationError::ContentMismatch.into());
    }
    manifest_file.revalidate()?;
    held.revalidate()?;
    let manifest_sha256 = &manifest_file.observation().sha256;
    if expected_manifest_sha256.is_some_and(|expected| expected != manifest_sha256) {
        return Err(ReplayValidationError::ManifestSha256Mismatch.into());
    }
    Ok(VerifiedApplicationReplayPackage {
        package,
        source: root.join("payload"),
        inputs,
        manifest_sha256: manifest_sha256.clone(),
        held,
    })
}

#[cfg(windows)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayPackageReview {
    schema_version: &'static str,
    package_schema_version: String,
    package_manifest_sha256: String,
    portable_manifest_sha256: String,
    semantic_sha256: String,
    scenario_id: String,
    candidate_id: String,
    mode: AssessmentMode,
    user_context: AssessmentUserContext,
    network_blocking_requested: bool,
    working_directory: String,
    total_timeout_seconds: u32,
    process_timeout_seconds: u32,
    inputs: Vec<AssessmentInput>,
    steps: Vec<ReplayReviewStep>,
    expected_outputs: Vec<AssessmentAssertion>,
}

#[cfg(windows)]
#[derive(Debug, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum ReplayReviewStep {
    StagePortable,
    Launch {
        entrypoint: String,
        relative_path: String,
        argument_count: usize,
    },
    ExpectExitCode {
        launch_step: usize,
        value: i32,
    },
    ObserveFile {
        path: String,
    },
}

/// Review a verified package snapshot without creating a plan, approval or workspace.
#[cfg(windows)]
pub fn review_package(path: &Path) -> Result<ReplayPackageReview> {
    review_package_with_manifest_sha256(path, None)
}

#[cfg(windows)]
pub fn review_package_with_manifest_sha256(
    path: &Path,
    expected_manifest_sha256: Option<&str>,
) -> Result<ReplayPackageReview> {
    let verified = verify_package_with_manifest_sha256(path, expected_manifest_sha256)?;
    verified.revalidate()?;
    Ok(review_verified_package(&verified))
}

#[cfg(windows)]
fn review_verified_package(verified: &VerifiedApplicationReplayPackage) -> ReplayPackageReview {
    let compiled = &verified.package.compiled;
    let steps = compiled
        .steps
        .iter()
        .map(|step| match step {
            CompiledAssessmentStep::StagePortable => ReplayReviewStep::StagePortable,
            CompiledAssessmentStep::Launch {
                entrypoint,
                path,
                arguments,
                ..
            } => ReplayReviewStep::Launch {
                entrypoint: entrypoint.clone(),
                relative_path: path.clone(),
                argument_count: arguments.len(),
            },
            CompiledAssessmentStep::ExpectExitCode { launch_step, value } => {
                ReplayReviewStep::ExpectExitCode {
                    launch_step: *launch_step,
                    value: *value,
                }
            }
            CompiledAssessmentStep::ObserveFile { path } => {
                ReplayReviewStep::ObserveFile { path: path.clone() }
            }
        })
        .collect();
    ReplayPackageReview {
        schema_version: "aiw.dev/application-replay-package-review/v0alpha1",
        package_schema_version: verified.package.schema_version.clone(),
        package_manifest_sha256: verified.manifest_sha256.clone(),
        portable_manifest_sha256: compiled.portable_manifest_sha256.clone(),
        semantic_sha256: compiled.semantic_sha256.clone(),
        scenario_id: compiled.settings.scenario_id.clone(),
        candidate_id: compiled.settings.candidate_id.clone(),
        mode: compiled.mode,
        user_context: compiled.user_context,
        network_blocking_requested: compiled.network_blocked,
        working_directory: compiled.settings.working_directory.clone(),
        total_timeout_seconds: compiled.settings.total_timeout_seconds,
        process_timeout_seconds: compiled.settings.process_timeout_seconds,
        inputs: compiled.settings.inputs.clone(),
        steps,
        expected_outputs: compiled.settings.assertions.clone(),
    }
}

#[cfg(windows)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayPackageComparison {
    schema_version: &'static str,
    baseline: ReplayPackageIdentity,
    candidate: ReplayPackageIdentity,
    changes: ReplayPackageChanges,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_review: Option<ReplayPackageReview>,
}

#[cfg(windows)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayPackageIdentity {
    package_manifest_sha256: String,
    semantic_sha256: String,
    portable_manifest_sha256: String,
}

#[cfg(windows)]
impl From<&VerifiedApplicationReplayPackage> for ReplayPackageIdentity {
    fn from(verified: &VerifiedApplicationReplayPackage) -> Self {
        Self {
            package_manifest_sha256: verified.manifest_sha256.clone(),
            semantic_sha256: verified.package.compiled.semantic_sha256.clone(),
            portable_manifest_sha256: verified.package.compiled.portable_manifest_sha256.clone(),
        }
    }
}

#[cfg(windows)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayPackageChanges {
    manifest_bytes: bool,
    project: bool,
    compiled_plan: bool,
    portable_payload: bool,
    inputs: bool,
    steps: bool,
    expected_outputs: bool,
    requested_run_conditions: bool,
}

#[cfg(windows)]
fn same_requested_conditions(left: &CompiledAssessment, right: &CompiledAssessment) -> bool {
    let a = &left.settings;
    let b = &right.settings;
    left.mode == right.mode
        && left.user_context == right.user_context
        && left.network_blocked == right.network_blocked
        && a.scenario_id == b.scenario_id
        && a.candidate_id == b.candidate_id
        && a.working_directory == b.working_directory
        && a.total_timeout_seconds == b.total_timeout_seconds
        && a.process_timeout_seconds == b.process_timeout_seconds
        && a.stdout_max_bytes == b.stdout_max_bytes
        && a.stderr_max_bytes == b.stderr_max_bytes
        && a.file_max_bytes == b.file_max_bytes
}

/// Compare verified declarations while holding both package inventories.
#[cfg(windows)]
pub fn compare_packages(baseline: &Path, candidate: &Path) -> Result<ReplayPackageComparison> {
    compare_packages_inner(baseline, candidate, false)
}

/// Compare the held snapshots and review that same verified candidate.
#[cfg(windows)]
pub fn compare_packages_with_candidate_review(
    baseline: &Path,
    candidate: &Path,
) -> Result<ReplayPackageComparison> {
    compare_packages_inner(baseline, candidate, true)
}

#[cfg(windows)]
fn compare_packages_inner(
    baseline: &Path,
    candidate: &Path,
    include_candidate_review: bool,
) -> Result<ReplayPackageComparison> {
    let baseline = verify_package(baseline)?;
    let candidate = verify_package(candidate)?;
    baseline.revalidate()?;
    candidate.revalidate()?;
    let left = &baseline.package.compiled;
    let right = &candidate.package.compiled;
    Ok(ReplayPackageComparison {
        schema_version: "aiw.dev/application-replay-package-comparison/v0alpha1",
        baseline: (&baseline).into(),
        candidate: (&candidate).into(),
        changes: ReplayPackageChanges {
            manifest_bytes: baseline.manifest_sha256 != candidate.manifest_sha256,
            project: baseline.package.project != candidate.package.project,
            compiled_plan: left != right,
            portable_payload: left.portable_manifest_sha256 != right.portable_manifest_sha256,
            inputs: left.settings.inputs != right.settings.inputs,
            steps: left.steps != right.steps,
            expected_outputs: left.settings.assertions != right.settings.assertions,
            requested_run_conditions: !same_requested_conditions(left, right),
        },
        candidate_review: include_candidate_review.then(|| review_verified_package(&candidate)),
    })
}

/// Publish external run data to one fresh protected destination, manifest last.
#[cfg(windows)]
pub fn export_package(
    project: &Project,
    settings: &AssessmentSettings,
    source: &Path,
    inputs: &BTreeMap<String, PathBuf>,
    parent: &Path,
    leaf: &str,
) -> Result<PathBuf> {
    use aiw_probe::PortableContentEntryKind as Kind;
    use aiw_windows_platform::{
        CreatedWorkspaceDirectory, HeldApplicationFile, HeldPortableDirectory,
    };
    let held = HeldPortableDirectory::open(source)?;
    let compiled = compile_assessment(project, settings, held.manifest())
        .map_err(|e| anyhow!("package capability blocked: {e:?}"))?;
    let package = ApplicationReplayPackage {
        schema_version: REPLAY_PACKAGE_SCHEMA.into(),
        project: project.clone(),
        compiled,
    };
    package.validate()?;
    let manifest_bytes = serde_json::to_vec_pretty(&package)?;
    if manifest_bytes.len() > 2 * 1024 * 1024 {
        bail!("package manifest exceeds the supported 2MiB bound");
    }
    if inputs.keys().collect::<BTreeSet<_>>() != settings.inputs.iter().map(|i| &i.id).collect() {
        bail!("package input IDs differ from reviewed workflow");
    }
    let mut sources = Vec::new();
    for input in &settings.inputs {
        let file = HeldApplicationFile::open_bounded(&inputs[&input.id], settings.file_max_bytes)?;
        if file.observation().sha256 != input.sha256
            || file.observation().size_bytes != input.size_bytes
        {
            bail!("package input content differs");
        }
        sources.push(file);
    }
    let root = CreatedWorkspaceDirectory::create_protected(parent, leaf)?;
    let destination = root.final_path().to_path_buf();
    let payload = root.create_directory_new("payload")?;
    let mut directories = BTreeMap::from([(String::new(), payload)]);
    for entry in &package.compiled.portable_entries {
        let (parent, name) = entry
            .relative_path
            .rsplit_once('/')
            .unwrap_or(("", &entry.relative_path));
        if entry.kind == Kind::Directory {
            let directory = directories[parent].create_directory_new(name)?;
            directories.insert(entry.relative_path.clone(), directory);
        } else {
            let file = HeldApplicationFile::open_bounded(
                &Path::new(&held.manifest().root_path).join(entry.relative_path.replace('/', "\\")),
                entry.size_bytes,
            )?;
            if file.observation().sha256 != entry.sha256.as_deref().unwrap_or("")
                || file.observation().size_bytes != entry.size_bytes
            {
                bail!("portable content changed during packaging; partial destination preserved");
            }
            let mut copy = directories[parent].create_file_new(name)?;
            file.copy_to(copy.as_file_mut())?;
            copy.as_file_mut().sync_all()?;
            file.revalidate()?;
        }
    }
    let input_directory = root.create_directory_new("inputs")?;
    for (index, file) in sources.iter().enumerate() {
        let mut copy = input_directory.create_file_new(&format!("input-{index:04}.bin"))?;
        file.copy_to(copy.as_file_mut())?;
        copy.as_file_mut().sync_all()?;
        file.revalidate()?;
    }
    held.revalidate()?;
    let mut manifest = root.create_file_new("package.json")?;
    manifest.as_file_mut().write_all(&manifest_bytes)?;
    manifest.as_file_mut().sync_all()?;
    drop(manifest);
    drop(input_directory);
    drop(directories);
    root.revalidate()?;
    drop(root);
    let verified = verify_package(&destination)?;
    verified.revalidate()?;
    Ok(destination)
}

#[cfg(test)]
#[test]
fn replay_manifest_parse_errors_distinguish_schema_and_truncation() {
    let duplicate = b"{\n  \"schemaVersion\": \"v1\",\n  \"schemaVersion\": \"duplicate\"\n}";
    let error = parse_replay_manifest(duplicate).unwrap_err();
    assert_eq!(error.line, 3);
    assert!(error.column > 0);
    assert_eq!(
        error.description,
        "JSON does not match the replay manifest schema"
    );
    assert!(!error.to_string().contains("duplicate"));

    let partial = b"{\n  \"schemaVersion\": ";
    let error = parse_replay_manifest(partial).unwrap_err();
    assert_eq!(error.line, 2);
    assert_eq!(error.description, "unexpected end of JSON");

    let syntax = b"{\n  \"schemaVersion\" = \"v1\"\n}";
    let error = parse_replay_manifest(syntax).unwrap_err();
    assert_eq!(error.line, 2);
    assert_eq!(error.description, "invalid JSON syntax");
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    fn fixture() -> (
        PathBuf,
        PathBuf,
        Project,
        AssessmentSettings,
        BTreeMap<String, PathBuf>,
    ) {
        let root = std::env::temp_dir().join(format!(
            "aiw-generic-package-test-{}-{}",
            std::process::id(),
            nonce()
        ));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        // Inert synthetic metadata test bytes; never a runnable fixture.
        std::fs::write(source.join("tool.exe"), b"inert synthetic payload").unwrap();
        let input = root.join("input.bin");
        std::fs::write(&input, b"test data").unwrap();
        let held = aiw_windows_platform::HeldPortableDirectory::open(&source).unwrap();
        let project: Project = serde_json::from_value(serde_json::json!({
            "schemaVersion":aiw_schema::PROJECT_SCHEMA_VERSION,"kind":aiw_schema::PROJECT_KIND,
            "metadata":{"name":"unlisted-package","displayName":"Unlisted input","owner":"local"},
            "application":{"type":"portableDirectory","path":"external","contentManifestSha256":held.manifest().manifest_sha256,"architecture":"x64","entryPoints":[{"id":"main","path":"tool.exe"}]},
            "isolationIntent":{"runtimeBoundary":"windowsSandbox","network":"blocked","allowClipboard":false,"allowHostFileAccess":false,"allowHostRegistryAccess":false,"requireDescendantCoverage":false},
            "candidates":[{"id":"ordinary","type":"unpackagedBaseline","config":{"type":"baseline"}}],
            "scenarios":[{"id":"workflow","description":"Inert packaging contract only","steps":[{"type":"install"},{"type":"launch","entrypoint":"main","arguments":["input.bin"]},{"type":"expectExitCode","value":0}]}],
            "assertions":{"requireEffectiveBackendMatch":true,"requireTargetTokenEvidence":true,"requireExpectedChildCoverage":false,"requireOfflineCanaryDenied":false,"failOnEvidenceTruncation":true}
        })).unwrap();
        let settings: AssessmentSettings = serde_json::from_value(serde_json::json!({
            "schemaVersion":aiw_provider_wsb::assessment::ASSESSMENT_SETTINGS_SCHEMA,"scenarioId":"workflow","candidateId":"ordinary","workingDirectory":".",
            "inputs":[{"id":"input","path":"input.bin","sha256":hex::encode(Sha256::digest(b"test data")),"sizeBytes":9}],
            "assertions":[{"id":"stdout","target":{"type":"stdout","launchStep":1},"expectedSizeBytes":0}],"totalTimeoutSeconds":60,"processTimeoutSeconds":20,"stdoutMaxBytes":4096,"stderrMaxBytes":4096,"fileMaxBytes":8192
        })).unwrap();
        (
            root,
            source,
            project,
            settings,
            BTreeMap::from([("input".into(), input)]),
        )
    }
    #[test]
    fn replay_package_roundtrip_recompiles_same_data_and_refuses_drift() {
        let (root, source, project, settings, inputs) = fixture();
        let destination =
            export_package(&project, &settings, &source, &inputs, &root, "package").unwrap();
        let verified = verify_package(&destination).unwrap();
        let preview = super::super::application_assessment::preview(
            &verified.package.project,
            &verified.package.compiled.settings,
            &verified.source,
        )
        .unwrap();
        assert_eq!(preview.compiled.as_ref(), Some(&verified.package.compiled));
        assert_eq!(preview.application_executions, 0);
        assert_eq!(
            std::fs::read(&verified.inputs["input"]).unwrap(),
            b"test data"
        );
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(verified.source.join("tool.exe"))
                .is_err()
        );
        verified.revalidate().unwrap();
        drop(verified);
        assert!(export_package(&project, &settings, &source, &inputs, &root, "package").is_err());
        std::fs::write(destination.join("approval.json"), b"{}").unwrap();
        assert!(verify_package(&destination).is_err());
        let second =
            export_package(&project, &settings, &source, &inputs, &root, "second").unwrap();
        let extra =
            aiw_windows_platform::CreatedWorkspaceDirectory::create_protected(&root, "extra")
                .unwrap();
        let extra_file = extra.final_path().join("extra.bin");
        let mut file = extra.create_file_new("extra.bin").unwrap();
        file.as_file_mut().write_all(b"inert").unwrap();
        file.as_file_mut().sync_all().unwrap();
        drop(file);
        drop(extra);
        let moved = second.join("extra.bin");
        std::fs::rename(extra_file, &moved).unwrap();
        let rejected = verify_package(&second).err().unwrap();
        assert_eq!(
            rejected.downcast_ref(),
            Some(&ReplayValidationError::InventoryMismatch {
                missing: 0,
                unexpected: 1,
                wrong_kind: 0,
            }),
            "{rejected:#}"
        );
        std::fs::remove_file(moved).unwrap();
        std::fs::write(second.join("payload").join("tool.exe"), b"changed payload").unwrap();
        let rejected = verify_package(&second).err().unwrap();
        assert_eq!(
            rejected.downcast_ref(),
            Some(&ReplayValidationError::ContentMismatch),
            "{rejected:#}"
        );
    }
    #[test]
    fn replay_accepts_a_payload_at_the_portable_depth_limit() {
        struct TestRoot(PathBuf);
        impl Drop for TestRoot {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }

        let (root, source, mut project, settings, inputs) = fixture();
        let root = TestRoot(root);
        let mut deepest = source.clone();
        for _ in 0..63 {
            deepest.push("d");
            std::fs::create_dir(&deepest).unwrap();
        }
        std::fs::write(deepest.join("extra.bin"), b"additional input").unwrap();
        let held = aiw_windows_platform::HeldPortableDirectory::open(&source).unwrap();
        let aiw_schema::ApplicationSource::PortableDirectory(source_spec) =
            &mut project.application
        else {
            unreachable!("test fixture must declare a portable source");
        };
        source_spec.content_manifest_sha256 = held.manifest().manifest_sha256.clone();
        drop(held);

        let destination =
            export_package(&project, &settings, &source, &inputs, &root.0, "package").unwrap();
        let verified = verify_package(&destination).unwrap();
        assert_eq!(verified.package.compiled.portable_entries.len(), 65);
        assert!(aiw_windows_platform::HeldPortableDirectory::open(&destination).is_err());
        verified.revalidate().unwrap();
    }

    #[test]
    fn package_rejects_input_and_plan_drift_without_creating_destination() {
        let (root, source, project, settings, inputs) = fixture();
        std::fs::write(&inputs["input"], b"drift").unwrap();
        assert!(export_package(&project, &settings, &source, &inputs, &root, "rejected").is_err());
        assert!(!root.join("rejected").exists());
        std::fs::write(&inputs["input"], b"test data").unwrap();
        let destination =
            export_package(&project, &settings, &source, &inputs, &root, "valid").unwrap();
        let mut package = verify_package(&destination).unwrap().package;
        package.project.metadata.display_name = "Another unlisted input".into();
        package.validate().unwrap();
        package.schema_version = "aiw.dev/application-replay-package/v999".into();
        assert_eq!(
            package.validate().unwrap_err().downcast_ref(),
            Some(&ReplayValidationError::UnsupportedSchema)
        );
        package.schema_version = REPLAY_PACKAGE_SCHEMA.into();
        package.compiled.settings.process_timeout_seconds += 1;
        assert_eq!(
            package.validate().unwrap_err().downcast_ref(),
            Some(&ReplayValidationError::InvalidPlan)
        );
    }
}
