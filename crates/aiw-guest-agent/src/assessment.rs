//! Generic assessed operations remain typed data; no secondary worker role or shell.
use super::*;
use aiw_provider_wsb::{
    assessment::ASSESSMENT_SCOPE,
    assessment_evidence::{
        APPLICATION_ASSESSMENT_EVIDENCE_EVENT, ASSESSMENT_NATIVE_OBSERVATION_SCHEMA,
        assessment_result_reference, verify_assessment_evidence, verify_assessment_progress,
    },
    assessment_observation::{
        APPLICATION_ASSESSMENT_RESULT_SCHEMA, ApplicationAssessmentResult,
        AssessmentAccountCleanup, AssessmentNativeOutcome,
    },
    assessment_request::{
        APPLICATION_ASSESSMENT_AGENT_PATH, APPLICATION_ASSESSMENT_REQUEST_MAX_BYTES,
        APPLICATION_ASSESSMENT_REQUEST_PATH, ApplicationAssessmentGuestRequest,
    },
};

const RESULT: &str = "assessment-result.json";
const LOG: &str = "evidence.jsonl";
const PROGRESS: &str = "assessment-progress.jsonl";
const MAX_RESULT: u64 = 16 * 1024 * 1024;
const MAX_LOG: u64 = 1024 * 1024;

fn fixed_path(actual: &Path, expected: &str) -> bool {
    actual.to_str().is_some_and(|s| {
        s.strip_prefix(r"\\?\")
            .unwrap_or(s)
            .eq_ignore_ascii_case(expected)
    })
}
pub(super) fn request_path_allowed(path: &Path) -> bool {
    fixed_path(path, APPLICATION_ASSESSMENT_REQUEST_PATH)
}
pub(super) fn parse_request(
    path: &Path,
    bytes: &[u8],
) -> Result<ApplicationAssessmentGuestRequest> {
    if !request_path_allowed(path) || bytes.len() as u64 > APPLICATION_ASSESSMENT_REQUEST_MAX_BYTES
    {
        bail!("generic request path or 2 MiB bound refused");
    }
    // Parse the ORIGINAL bytes directly: Value -> typed conversion would erase
    // duplicate keys before strict serde can refuse them.
    let request: ApplicationAssessmentGuestRequest =
        serde_json::from_slice(bytes).context("strict application assessment request")?;
    request.validate().map_err(anyhow::Error::msg)?;
    Ok(request)
}

fn failed(
    request: &ApplicationAssessmentGuestRequest,
    diagnostic: &str,
) -> ApplicationAssessmentResult {
    let diagnostic: String = diagnostic
        .chars()
        .take(1024)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    ApplicationAssessmentResult {
        schema_version: APPLICATION_ASSESSMENT_RESULT_SCHEMA.into(),
        run_id: request.run_id.clone(),
        request_sha256: request.request_sha256.clone(),
        assessment_sha256: request.assessment_sha256.clone(),
        native: AssessmentNativeOutcome {
            schema_version: ASSESSMENT_NATIVE_OBSERVATION_SCHEMA.into(),
            semantic_sha256: request.assessment.semantic_sha256.clone(),
            mode: request.assessment.mode,
            windows: None,
            windows_error: None,
            setup_token: None,
            standard_context: None,
            steps: vec![],
            assertions: vec![],
            collector_write_denied: None,
            collector_access_denials: vec![],
            collector_unimpersonated: None,
            profile_sid: None,
            account_cleanup: AssessmentAccountCleanup::default(),
            profile_cleanup: None,
            driver_errors: vec![
                format!("native assessment failed before a returned outcome: {diagnostic}")
                    .chars()
                    .take(1024)
                    .collect(),
            ],
            driver_completed: false,
            scope: ASSESSMENT_SCOPE.into(),
        },
    }
}

pub(super) fn execute(request: &ApplicationAssessmentGuestRequest) -> Result<()> {
    request.validate().map_err(anyhow::Error::msg)?;
    let image = std::env::current_exe().context("assessment agent current image")?;
    if !fixed_path(&image, APPLICATION_ASSESSMENT_AGENT_PATH) {
        bail!("assessment requires the exact fixed guest agent image");
    }
    let size = ordinary_installer_metadata(&image)?.len();
    if size == 0 || size > 64 * 1024 * 1024 {
        bail!("assessment agent size exceeds bound");
    }
    // The fixed mapped tool is held read-only throughout native execution and
    // publication. Native intake also validates its local image and held code.
    let mut agent = HeldInstaller::open(&image, &request.agent_sha256, size)?;
    let root = Path::new(PAIRED_OUTPUT_ROOT);
    ensure_output_root(root)?;
    #[cfg(windows)]
    let native = aiw_windows_platform::execute_assessment(request);
    #[cfg(not(windows))]
    let native: std::result::Result<AssessmentNativeOutcome, String> =
        Err("application assessment requires the native Windows worker".into());
    let result = match native {
        Ok(native) => ApplicationAssessmentResult {
            schema_version: APPLICATION_ASSESSMENT_RESULT_SCHEMA.into(),
            run_id: request.run_id.clone(),
            request_sha256: request.request_sha256.clone(),
            assessment_sha256: request.assessment_sha256.clone(),
            native,
        },
        Err(error) => failed(request, &error),
    };
    agent.revalidate()?;
    publish(request, root, &result)?;
    agent.revalidate()?;
    Ok(())
}

fn read_bounded_optional(path: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || has_reparse_point(&metadata)
        || metadata.len() > max
    {
        bail!("assessment artifact is not a bounded ordinary file");
    }
    let mut file = open_installer_read_held(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || file.metadata()?.len() != metadata.len() {
        bail!("assessment artifact length changed");
    }
    Ok(Some(bytes))
}

/// No overwrite, no repair and no retry. Incomplete files remain diagnostic;
/// only completion.json authorizes the retained completion verifier to proceed.
fn create_artifact(path: &Path, bytes: &[u8], max: u64) -> Result<()> {
    if bytes.len() as u64 > max {
        bail!("assessment publication exceeds fixed bound");
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    Ok(())
}
fn fact(
    root: &Path,
    name: &str,
    role: ArtifactRole,
    media: &str,
    max: u64,
) -> Result<CompletionArtifact> {
    let bytes =
        read_bounded_optional(&root.join(name), max)?.context("assessment artifact disappeared")?;
    Ok(CompletionArtifact {
        path: name.into(),
        role,
        media_type: media.into(),
        size_bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

fn publish(
    request: &ApplicationAssessmentGuestRequest,
    root: &Path,
    result: &ApplicationAssessmentResult,
) -> Result<()> {
    publish_with(request, root, result, |bytes| {
        #[cfg(windows)]
        {
            aiw_windows_platform::publish_assessment_completion(bytes).map_err(anyhow::Error::msg)
        }
        #[cfg(not(windows))]
        {
            create_artifact(&root.join("completion.json"), bytes, MAX_LOG)
        }
    })
}
fn publish_with(
    request: &ApplicationAssessmentGuestRequest,
    root: &Path,
    result: &ApplicationAssessmentResult,
    finish: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<()> {
    let result_bytes = serde_json::to_vec(result)?;
    let reference = assessment_result_reference(request, result).map_err(anyhow::Error::msg)?;
    let mut evidence = EvidenceLog::new();
    evidence.append(EvidenceEvent {
        observed_utc: "guest-agent-time-not-trusted".into(),
        kind: APPLICATION_ASSESSMENT_EVIDENCE_EVENT.into(),
        source: "aiw-guest-agent".into(),
        payload: serde_json::to_value(reference)?,
    })?;
    let log = evidence_bytes(&evidence)?;
    if log.len() as u64 > MAX_LOG {
        bail!("assessment hash-reference log exceeds 1 MiB");
    }
    // Preserve a returned malformed/partial native observation for diagnosis,
    // but never certify it by completion when its verifier/journal disagrees.
    create_artifact(&root.join(RESULT), &result_bytes, MAX_RESULT)?;
    create_artifact(&root.join(LOG), &log, MAX_LOG)?;
    let evidence_root = evidence.manifest()?.root_hash;
    verify_assessment_evidence(&log, &evidence_root, request, result)
        .map_err(anyhow::Error::msg)?;
    let progress = read_bounded_optional(&root.join(PROGRESS), MAX_RESULT)?;
    if let Some(bytes) = &progress {
        verify_assessment_progress(bytes, request, result).map_err(anyhow::Error::msg)?;
    } else if has_native_facts(&result.native) {
        bail!("native observations require their bound durable progress journal");
    }
    let status = if result.native.driver_completed {
        CompletionStatus::Succeeded
    } else {
        CompletionStatus::Failed
    };
    let mut artifacts = vec![
        fact(
            root,
            RESULT,
            ArtifactRole::ScenarioResults,
            "application/json",
            MAX_RESULT,
        )?,
        fact(
            root,
            LOG,
            ArtifactRole::EvidenceLog,
            "application/x-ndjson",
            MAX_LOG,
        )?,
    ];
    if progress.is_some() {
        artifacts.push(fact(
            root,
            PROGRESS,
            ArtifactRole::DiagnosticLog,
            "application/x-ndjson",
            MAX_RESULT,
        )?);
    }
    let receipt = WindowsSandboxCompletionReceipt {
        schema_version: WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION.into(),
        run_id: request.run_id.clone(),
        sandbox_id: request.sandbox_id.clone(),
        config_sha256: request.config_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        agent_sha256: request.agent_sha256.clone(),
        status,
        exit_code: if status == CompletionStatus::Succeeded {
            0
        } else {
            1
        },
        evidence_root_hash: evidence_root,
        artifacts,
    };
    // The fixed native publisher atomically renames with no replacement only
    // after all artifacts have been closed, validated and remeasured.
    finish(&serde_json::to_vec(&receipt)?)
}
fn has_native_facts(n: &AssessmentNativeOutcome) -> bool {
    n.setup_token.is_some()
        || n.standard_context.is_some()
        || n.windows.is_some()
        || n.windows_error.is_some()
        || !n.steps.is_empty()
        || !n.assertions.is_empty()
        || !n.collector_access_denials.is_empty()
        || n.collector_write_denied.is_some()
        || n.collector_unimpersonated.is_some()
        || n.profile_sid.is_some()
        || n.profile_cleanup.is_some()
        || n.account_cleanup.environment_destroyed.is_some()
        || n.account_cleanup.profile_unloaded.is_some()
        || n.account_cleanup.account_deleted.is_some()
        || !n.account_cleanup.errors.is_empty()
        || n.driver_completed
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> ApplicationAssessmentGuestRequest {
        use aiw_provider_wsb::assessment::*;
        let entries = vec![aiw_probe::PortableContentEntry {
            relative_path: "tool.exe".into(),
            kind: aiw_probe::PortableContentEntryKind::File,
            size_bytes: 3,
            sha256: Some("a".repeat(64)),
        }];
        let digest = assessment_manifest_sha256(&entries);
        let manifest = aiw_probe::PortableContentManifest {
            schema_version: aiw_probe::PORTABLE_MANIFEST_SCHEMA.into(),
            root_path: "private-root".into(),
            entries,
            total_size_bytes: 3,
            manifest_sha256: digest.clone(),
        };
        let project=serde_json::from_value(serde_json::json!({"schemaVersion":"aiw.dev/v0alpha2","kind":"AppIsolationProject","metadata":{"name":"synthetic-unlisted","displayName":"Synthetic contract only","owner":"test"},"application":{"type":"portableDirectory","path":"portable","contentManifestSha256":digest,"architecture":"x64","entryPoints":[{"id":"main","path":"tool.exe"}]},"isolationIntent":{"runtimeBoundary":"windowsSandbox","network":"blocked","allowClipboard":false,"allowHostFileAccess":false,"allowHostRegistryAccess":false,"requireDescendantCoverage":false},"candidates":[{"id":"ordinary","type":"unpackagedBaseline","config":{"type":"baseline"}}],"scenarios":[{"id":"workflow","description":"Synthetic","steps":[{"type":"install"},{"type":"launch","entrypoint":"main"},{"type":"expectExitCode","value":0}]}],"assertions":{"requireEffectiveBackendMatch":true,"requireTargetTokenEvidence":true,"requireExpectedChildCoverage":false,"requireOfflineCanaryDenied":false,"failOnEvidenceTruncation":true}})).unwrap();
        let settings = AssessmentSettings {
            schema_version: ASSESSMENT_SETTINGS_SCHEMA.into(),
            scenario_id: "workflow".into(),
            candidate_id: "ordinary".into(),
            working_directory: ".".into(),
            inputs: vec![],
            assertions: vec![AssessmentAssertion {
                id: "empty-output".into(),
                target: AssessmentAssertionTarget::Stdout { launch_step: 1 },
                expected_sha256: None,
                expected_size_bytes: Some(0),
            }],
            total_timeout_seconds: 60,
            process_timeout_seconds: 20,
            stdout_max_bytes: 4096,
            stderr_max_bytes: 4096,
            file_max_bytes: 8192,
        };
        ApplicationAssessmentGuestRequest::new(
            "synthetic-run".into(),
            "4a0f039f-4bb7-4d14-b1d8-4c9891bc44a3".into(),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            compile_assessment(&project, &settings, &manifest).unwrap(),
        )
        .unwrap()
    }
    fn root() -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "aiw-assessment-publish-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        root
    }
    fn publish_test(
        request: &ApplicationAssessmentGuestRequest,
        root: &Path,
        result: &ApplicationAssessmentResult,
    ) -> Result<()> {
        publish_with(request, root, result, |bytes| {
            create_artifact(&root.join("completion.json"), bytes, MAX_LOG)
        })
    }
    #[test]
    fn generic_request_has_exact_path_raw_duplicate_checks_and_separate_size_frontier() {
        let request = request();
        let mut bytes = serde_json::to_vec(&request).unwrap();
        let fixed = Path::new(APPLICATION_ASSESSMENT_REQUEST_PATH);
        bytes.resize(70 * 1024, b' ');
        assert_eq!(parse_request(fixed, &bytes).unwrap(), request);
        assert!(parse_request(Path::new(r"C:\AIW\Tools\request.json"), &bytes).is_err());
        bytes.resize(
            (APPLICATION_ASSESSMENT_REQUEST_MAX_BYTES + 1) as usize,
            b' ',
        );
        assert!(parse_request(fixed, &bytes).is_err());
        let json = serde_json::to_string(&request).unwrap();
        let duplicate = format!("{{\"runId\":\"shadow\",{}", &json[1..]);
        assert!(parse_request(fixed, duplicate.as_bytes()).is_err());
        let mut value = serde_json::to_value(request).unwrap();
        value["command"] = serde_json::json!("unknown shell");
        assert!(parse_request(fixed, &serde_json::to_vec(&value).unwrap()).is_err());
        for path in [
            r"C:\host\assessment-request.json",
            r"C:\AIW\Tools\assessment-request.json:stream",
            r"C:\AIW\Tools\ASSESS~1.JSON",
        ] {
            assert!(!request_path_allowed(Path::new(path)));
        }
        assert!(Cli::try_parse_from(["aiw-guest-agent", "--assessment-worker"]).is_err());
    }
    #[test]
    fn failed_preheader_result_and_hash_reference_are_receipt_bound_without_execution() {
        let request = request();
        let value = failed(&request, "native preflight unavailable");
        let root = root();
        publish_test(&request, &root, &value).unwrap();
        let receipt: WindowsSandboxCompletionReceipt =
            serde_json::from_slice(&fs::read(root.join("completion.json")).unwrap()).unwrap();
        assert_eq!(receipt.status, CompletionStatus::Failed);
        assert_eq!(receipt.artifacts.len(), 2);
        assert_eq!(receipt.request_sha256, request.request_sha256);
        let parsed: ApplicationAssessmentResult =
            serde_json::from_slice(&fs::read(root.join(RESULT)).unwrap()).unwrap();
        assert_eq!(parsed, value);
        assert!(parsed.native.steps.is_empty());
        assert_eq!(
            parsed.native.account_cleanup,
            AssessmentAccountCleanup::default()
        );
        verify_assessment_evidence(
            &fs::read(root.join(LOG)).unwrap(),
            &receipt.evidence_root_hash,
            &request,
            &value,
        )
        .unwrap();
        let before = fs::read(root.join("completion.json")).unwrap();
        assert!(publish_test(&request, &root, &value).is_err());
        assert_eq!(fs::read(root.join("completion.json")).unwrap(), before);
        for name in [RESULT, LOG, "completion.json"] {
            fs::remove_file(root.join(name)).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn native_facts_without_journal_and_corrupt_journal_never_publish_completion() {
        let request = request();
        for corrupt in [false, true] {
            let root = root();
            let mut value = failed(&request, "failed driver");
            if corrupt {
                fs::write(root.join(PROGRESS), b"{incomplete").unwrap();
            } else {
                value.native.windows = Some(aiw_probe::WindowsVersionObservation {
                    major: 10,
                    minor: 0,
                    build: 26100,
                    revision: 1,
                    observer_architecture: "x86_64".into(),
                });
            }
            assert!(publish_test(&request, &root, &value).is_err());
            assert!(!root.join("completion.json").exists());
            assert!(root.join(RESULT).exists());
            assert!(root.join(LOG).exists());
            for name in [RESULT, LOG, PROGRESS] {
                if root.join(name).exists() {
                    fs::remove_file(root.join(name)).unwrap();
                }
            }
            fs::remove_dir(root).unwrap();
        }
    }
}
