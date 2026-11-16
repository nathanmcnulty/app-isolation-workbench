//! Pure authority regressions. All identities and bytes are synthetic: no
//! filesystem, provider, tool or application is invoked by these tests.
use super::application_assessment::*;
use super::*;
use aiw_probe::{
    ApplicationFileEaAuthority, ApplicationInspectionKind, PortableContentEntry,
    PortableContentEntryKind, PortableContentManifest, PortableDirectoryAuthority,
    PortableDirectoryImportReceipt, PortableEntryAuthority, PortableImportEntry,
};
use aiw_provider_wsb::assessment::*;

fn fixture() -> (
    Project,
    WsbApplicationAssessment,
    aiw_probe::WindowsSandboxStaticIdentity,
) {
    let entries = vec![PortableContentEntry {
        relative_path: "tool.exe".into(),
        kind: PortableContentEntryKind::File,
        size_bytes: 3,
        sha256: Some(hex::encode(Sha256::digest(b"abc"))),
    }];
    let manifest = PortableContentManifest {
        schema_version: aiw_probe::PORTABLE_MANIFEST_SCHEMA.into(),
        root_path: r"C:\private\unlisted".into(),
        manifest_sha256: assessment_manifest_sha256(&entries),
        entries,
        total_size_bytes: 3,
    };
    let project:Project=serde_json::from_value(serde_json::json!({
        "schemaVersion":aiw_schema::PROJECT_SCHEMA_VERSION,"kind":aiw_schema::PROJECT_KIND,
        "metadata":{"name":"unknown-assessment-input","displayName":"Independent unlisted data","owner":"administrator"},
        "application":{"type":"portableDirectory","path":"external-data","contentManifestSha256":manifest.manifest_sha256,"architecture":"x64","entryPoints":[{"id":"main","path":"tool.exe"}]},
        "isolationIntent":{"runtimeBoundary":"windowsSandbox","network":"blocked","allowClipboard":false,"allowHostFileAccess":false,"allowHostRegistryAccess":false,"requireDescendantCoverage":false},
        "candidates":[{"id":"ordinary","type":"unpackagedBaseline","config":{"type":"baseline"}},{"id":"candidate","type":"classicAppContainer","config":{"type":"classicAppContainer","network":"blocked"}}],
        "scenarios":[{"id":"workflow","description":"Synthetic preparation authority only","steps":[{"type":"install"},{"type":"launch","entrypoint":"main","arguments":["input.json"]},{"type":"expectExitCode","value":0}]}],
        "assertions":{"requireEffectiveBackendMatch":true,"requireTargetTokenEvidence":true,"requireExpectedChildCoverage":false,"requireOfflineCanaryDenied":false,"failOnEvidenceTruncation":true}
    })).unwrap();
    let settings = AssessmentSettings {
        schema_version: ASSESSMENT_SETTINGS_SCHEMA.into(),
        scenario_id: "workflow".into(),
        candidate_id: "ordinary".into(),
        working_directory: "samples".into(),
        inputs: vec![AssessmentInput {
            id: "input".into(),
            path: "samples/input.json".into(),
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
    let compiled = compile_assessment(&project, &settings, &manifest).unwrap();
    let id = super::tests::identity;
    let eas = ApplicationFileEaAuthority {
        entries: vec![],
        canonical_sha256: "0".repeat(64),
    };
    let receipt = PortableDirectoryImportReceipt {
        schema_version: aiw_probe::PORTABLE_DIRECTORY_IMPORT_RECEIPT_SCHEMA.into(),
        intake_id: APPLICATION_INTAKE_LEAF.into(),
        source_kind: ApplicationInspectionKind::PortableDirectory,
        source_manifest: manifest.clone(),
        source_authority: PortableDirectoryAuthority {
            schema_version: aiw_probe::PORTABLE_DIRECTORY_AUTHORITY_SCHEMA.into(),
            root_identity: id(r"C:\private\unlisted", 'd'),
            entries: vec![PortableEntryAuthority {
                relative_path: "tool.exe".into(),
                kind: PortableContentEntryKind::File,
                identity: id(r"C:\private\unlisted\tool.exe", 'e'),
                link_count: 1,
                only_unnamed_data_stream: true,
            }],
            manifest_sha256: manifest.manifest_sha256.clone(),
        },
        intake_root: id(r"C:\AIW\run-one\application-intake", '5'),
        intake_root_eas: eas.clone(),
        source_directory: id(r"C:\AIW\run-one\application-intake\source", '6'),
        source_directory_eas: eas.clone(),
        payload_directory: id(r"C:\AIW\run-one\application-intake\source\payload", '7'),
        payload_directory_eas: eas.clone(),
        entries: vec![PortableImportEntry {
            relative_path: "tool.exe".into(),
            kind: PortableContentEntryKind::File,
            identity: id(
                r"C:\AIW\run-one\application-intake\source\payload\tool.exe",
                '9',
            ),
            eas,
            size_bytes: 3,
            sha256: manifest.entries[0].sha256.clone(),
            link_count: 1,
            only_unnamed_data_stream: true,
        }],
        receipt: id(r"C:\AIW\run-one\application-intake\intake.json", '8'),
        entry_count: 1,
        total_size_bytes: 3,
        manifest_sha256: manifest.manifest_sha256.clone(),
    };
    let assessment = WsbApplicationAssessment {
        intake_receipt_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&receipt).unwrap())),
        intake_receipt: receipt,
        compiled,
        fixtures_directory: id(r"C:\AIW\run-one\fixtures", 'a'),
        fixture_directories: vec![id(r"C:\AIW\run-one\fixtures\samples", 'b')],
        inputs: vec![WsbAssessmentInput {
            id: "input".into(),
            path: "samples/input.json".into(),
            sha256: hex::encode(Sha256::digest(b"{}")),
            size_bytes: 2,
            source_identity: id(r"C:\private\input.json", 'f'),
            staged_identity: id(r"C:\AIW\run-one\fixtures\samples\input.json", 'c'),
        }],
    };
    let mut readiness = super::synthetic::readiness();
    readiness.os_version = Some(aiw_probe::WindowsVersionObservation {
        major: 10,
        minor: 0,
        build: 26100,
        revision: 2,
        observer_architecture: "x86_64".into(),
    });
    (
        project,
        assessment,
        super::synthetic::static_identity(&readiness),
    )
}
fn build(
    project: &Project,
    assessment: WsbApplicationAssessment,
    identity: &aiw_probe::WindowsSandboxStaticIdentity,
) -> Result<PreparedWsbArtifacts, WsbPreparationError> {
    build_wsb_application_assessment_preparation(
        "run-one",
        project,
        identity,
        &super::tests::workspace(),
        &super::tests::guest(),
        "now",
        assessment,
    )
}

#[test]
fn static_package_selects_required_protocol_without_claiming_runtime_observation() {
    let (project, assessment, identity) = fixture();
    let original = build(&project, assessment.clone(), &identity).unwrap();
    assert_eq!(original.receipt.provider_protocol.cli_version, "0.8.107.0");

    let mut serviced = identity.clone();
    serviced.package.version = "0.8.114.0".into();
    serviced.package.full_name = "MicrosoftWindows.WindowsSandbox_0.8.114.0_x64".into();
    let current = build(&project, assessment.clone(), &serviced).unwrap();
    let required = aiw_probe::WindowsSandboxCliAdapter::V0_8_114_0.protocol();
    assert_eq!(current.receipt.provider_protocol, required);
    assert!(current.receipt.provider.version.is_none());
    assert!(current.receipt.provider_protocol_observation.is_some());
    assert!(!current.receipt.provider_acquired && !current.receipt.provider_mutated);
    let PlannedAction::ExecuteWindowsSandboxApplicationAssessment {
        provider_protocol, ..
    } = &current.run_plan.actions[2]
    else {
        panic!("current generic action required");
    };
    assert_eq!(provider_protocol.as_ref(), Some(&required));
    assert_ne!(
        original.run_plan.hash().unwrap(),
        current.run_plan.hash().unwrap()
    );

    serviced.package.version = "0.8.115.0".into();
    assert!(matches!(
        build(&project, assessment, &serviced),
        Err(WsbPreparationError::Readiness(_))
    ));
}

#[test]
fn unlisted_portable_plan_is_closed_offline_and_does_not_approve_or_dispatch() {
    let (mut project, assessment, identity) = fixture();
    let first = build(&project, assessment.clone(), &identity).unwrap();
    first.validate().unwrap();
    assert!(first.receipt.approval_required);
    assert!(!first.receipt.provider_acquired);
    assert!(!first.receipt.provider_mutated);
    assert_eq!(first.wsb_plan.mappings.len(), 4);
    let xml = aiw_provider_wsb::render_config(&first.wsb_plan)
        .unwrap()
        .xml;
    assert!(xml.contains("<Networking>Disable</Networking>"));
    assert!(xml.contains("assessment-request.json"));
    project.metadata.display_name = "Another arbitrary descriptive label".into();
    let renamed = build(&project, assessment, &identity).unwrap();
    assert_eq!(
        first
            .receipt
            .application_assessment
            .as_ref()
            .unwrap()
            .compiled,
        renamed
            .receipt
            .application_assessment
            .as_ref()
            .unwrap()
            .compiled
    );
}

#[test]
fn hashes_do_not_authorize_rebinding_intake_or_fixture_roots() {
    let (project, assessment, identity) = fixture();
    let mut wrong = assessment.clone();
    wrong.intake_receipt.payload_directory.final_path = r"C:\foreign\payload".into();
    wrong.intake_receipt_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&wrong.intake_receipt).unwrap(),
    ));
    assert!(build(&project, wrong, &identity).is_err());
    let mut wrong = assessment.clone();
    wrong.inputs[0].staged_identity.final_path = r"C:\foreign\input.json".into();
    assert!(build(&project, wrong, &identity).is_err());
    let mut wrong = assessment.clone();
    wrong.fixture_directories.clear();
    assert!(build(&project, wrong, &identity).is_err());
    let mut wrong = assessment;
    wrong.inputs[0].sha256 = "f".repeat(64);
    assert!(build(&project, wrong, &identity).is_err());
}

#[test]
fn source_workflow_and_policy_changes_require_a_new_exact_plan() {
    let (project, assessment, identity) = fixture();
    let prepared = build(&project, assessment.clone(), &identity).unwrap();
    let approval =
        aiw_orchestrator::ApprovalRecord::for_plan(&prepared.run_plan, "operator", "now").unwrap();
    let mut changed = assessment.clone();
    changed.compiled.settings.process_timeout_seconds += 1;
    assert!(build(&project, changed, &identity).is_err());
    let mut changed = assessment.clone();
    changed.intake_receipt.source_manifest.entries[0].sha256 = Some("f".repeat(64));
    changed.intake_receipt_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&changed.intake_receipt).unwrap(),
    ));
    assert!(build(&project, changed, &identity).is_err());
    let mut candidate = assessment.clone();
    candidate.compiled.settings.candidate_id = "candidate".into();
    candidate.compiled = compile_assessment(
        &project,
        &candidate.compiled.settings,
        &candidate.intake_receipt.source_manifest,
    )
    .unwrap();
    let candidate = build(&project, candidate, &identity).unwrap();
    assert_ne!(approval.plan_hash, candidate.run_plan.hash().unwrap());
    assert_eq!(
        prepared
            .receipt
            .application_assessment
            .as_ref()
            .unwrap()
            .compiled
            .semantic_sha256,
        candidate
            .receipt
            .application_assessment
            .as_ref()
            .unwrap()
            .compiled
            .semantic_sha256
    );
    let mut stale = prepared.clone();
    stale.receipt.application_assessment = candidate.receipt.application_assessment;
    assert!(stale.validate().is_err());
}

#[test]
fn mappings_and_legacy_profiles_cannot_borrow_generic_preparation_authority() {
    let (project, assessment, identity) = fixture();
    let prepared = build(&project, assessment, &identity).unwrap();
    for index in 0..prepared.wsb_plan.mappings.len() {
        let mut wrong = prepared.clone();
        wrong.wsb_plan.mappings[index].sandbox_folder = r"C:\outside".into();
        wrong.receipt.wsb_plan_sha256 = canonical_hash(&wrong.wsb_plan).unwrap();
        assert!(wrong.validate().is_err());
    }
    let mut wrong = prepared.clone();
    wrong.receipt.msi = Some(super::tests::fake_msi_application());
    assert!(wrong.validate().is_err());
    let mut wrong = prepared;
    wrong.receipt.schema_version = WSB_PREPARATION_RECEIPT_SCHEMA_VERSION.into();
    assert!(wrong.validate().is_err());
}

fn large_request() -> super::super::ExecutionGuestRequest {
    let (mut project, assessment, _) = fixture();
    for _ in 0..6 {
        project.scenarios[0].steps.extend([
            aiw_schema::ScenarioStep::Launch {
                entrypoint: "main".into(),
                arguments: vec!["x".repeat(4_000); 3],
            },
            aiw_schema::ScenarioStep::ExpectExitCode { value: 0 },
        ]);
    }
    let compiled = compile_assessment(
        &project,
        &assessment.compiled.settings,
        &assessment.intake_receipt.source_manifest,
    )
    .unwrap();
    let request = aiw_provider_wsb::assessment_request::ApplicationAssessmentGuestRequest::new(
        "request-size-run".into(),
        "89a0192b-477c-4fa6-9d75-5a63e6685bd7".into(),
        "1".repeat(64),
        "2".repeat(64),
        project_revision_hash(&project).unwrap(),
        compiled,
    )
    .unwrap();
    super::super::ExecutionGuestRequest::ApplicationAssessment(Box::new(request))
}

fn request_test_directory() -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "aiw-generic-request-bound-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    directory
}

#[test]
fn generic_request_above_legacy_bound_is_published_read_and_cleaned_without_execution() {
    use super::super::{
        prepare_request_artifact, read_execution_request, remove_owned_request,
        request_pending_path, validate_staging_file,
    };
    let expected = large_request();
    let bytes = serde_json::to_vec(&expected).unwrap();
    assert!(bytes.len() > 64 * 1024 && bytes.len() < 2 * 1024 * 1024);
    let directory = request_test_directory();
    let path = directory.join("assessment-request.json");
    let pending = request_pending_path(&path).unwrap();
    std::fs::write(&pending, vec![b'x'; 70_000]).unwrap();
    validate_staging_file(&pending).unwrap();
    prepare_request_artifact(&path, &expected).unwrap();
    assert!(!pending.exists());
    assert_eq!(read_execution_request(&path).unwrap(), expected);
    // Recovery/retry uses the same bounded typed reader, not a legacy 64KiB path.
    prepare_request_artifact(&path, &expected).unwrap();
    assert_eq!(read_execution_request(&path).unwrap(), expected);
    remove_owned_request(&path, &expected).unwrap();
    assert!(!path.exists() && !pending.exists());
    std::fs::remove_dir(&directory).unwrap();
}

#[test]
fn generic_request_cannot_expand_legacy_names_or_pending_file_limits() {
    use super::super::{
        prepare_request_artifact, read_execution_request, request_pending_path,
        validate_staging_file,
    };
    let expected = large_request();
    let directory = request_test_directory();
    let legacy = directory.join("request.json");
    assert!(prepare_request_artifact(&legacy, &expected).is_err());
    assert!(!legacy.exists());
    let pending = request_pending_path(&legacy).unwrap();
    std::fs::write(&pending, vec![b'x'; 70_000]).unwrap();
    assert!(validate_staging_file(&pending).is_err());
    std::fs::write(&legacy, serde_json::to_vec(&expected).unwrap()).unwrap();
    assert!(read_execution_request(&legacy).is_err());
    std::fs::remove_file(&legacy).unwrap();
    std::fs::remove_file(&pending).unwrap();
    std::fs::remove_dir(&directory).unwrap();
}
