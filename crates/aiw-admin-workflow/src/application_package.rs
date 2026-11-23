//! Data-only replay packages. No approvals, sessions, tools or execution credit.
use super::*;
#[cfg(windows)]
use aiw_provider_wsb::assessment::AssessmentSettings;
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
    held: aiw_windows_platform::HeldPortableDirectory,
}

#[cfg(windows)]
impl VerifiedApplicationReplayPackage {
    pub fn revalidate(&self) -> Result<()> {
        self.held.revalidate().map_err(Into::into)
    }
}

/// Strict closed inventory, exact hashes and compiler reuse. Never executes.
#[cfg(windows)]
pub fn verify_package(path: &Path) -> Result<VerifiedApplicationReplayPackage> {
    use aiw_probe::PortableContentEntryKind as Kind;
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
        bail!("replay package inventory or content differs; no import or execution performed");
    }
    manifest_file.revalidate()?;
    held.revalidate()?;
    Ok(VerifiedApplicationReplayPackage {
        package,
        source: root.join("payload"),
        inputs,
        held,
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
        std::fs::write(second.join("payload").join("tool.exe"), b"changed payload").unwrap();
        assert!(verify_package(&second).is_err());
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
