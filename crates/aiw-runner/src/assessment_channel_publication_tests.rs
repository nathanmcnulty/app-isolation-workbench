//! Real FILE/CNG publication checks, with entirely synthetic failed-driver
//! observations. This does not establish a local Start anchor, collector access
//! protection, application execution, provider behavior or isolation.
use super::*;
use aiw_evidence::{ArtifactRole, EvidenceEvent, EvidenceLog};
use aiw_probe::{PortableContentEntry, PortableContentEntryKind, PortableContentManifest};
use aiw_provider_wsb::assessment::{
    ASSESSMENT_SCOPE, ASSESSMENT_SETTINGS_SCHEMA, AssessmentAssertion, AssessmentAssertionTarget,
    AssessmentInput, AssessmentSettings, assessment_manifest_sha256, compile_assessment,
};
use aiw_provider_wsb::assessment_evidence::{
    APPLICATION_ASSESSMENT_EVIDENCE_EVENT, AssessmentFactStatus, assessment_result_reference,
};
use aiw_provider_wsb::assessment_observation::*;
use aiw_provider_wsb::{
    CompletionArtifact, CompletionStatus, WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION,
    WindowsSandboxCompletionReceipt,
};
use aiw_schema::Project;
use aiw_token::{ElevationType, IntegrityEvidence, IntegrityLevel, TokenEvidence, TokenType};
use std::collections::BTreeMap;

struct PublicationFixture {
    request: ApplicationAssessmentGuestRequest,
    binding: AssessmentChannelBinding,
    bootstrap: Vec<u8>,
    acknowledgement: Vec<u8>,
    files: BTreeMap<String, Vec<u8>>,
}

fn sign(intent: ChannelSigningIntent, key: &AssessmentSigningKey) -> AssessmentChannelRecord {
    let signature = key.sign_digest(&intent.signing_digest().unwrap()).unwrap();
    intent.with_signature(&signature)
}

impl PublicationFixture {
    fn new() -> Self {
        let host = AssessmentSigningKey::generate().unwrap();
        let guest = AssessmentSigningKey::generate().unwrap();
        let (project, settings, manifest) = project_fixture();
        let request = ApplicationAssessmentGuestRequest::new_authenticated(
            "publication-fixture".into(),
            "12345678-1234-4234-9234-123456789abc".into(),
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            compile_assessment(&project, &settings, &manifest).unwrap(),
            AssessmentChannelRequest {
                schema_version: ASSESSMENT_CHANNEL_REQUEST_SCHEMA.into(),
                channel_protocol: CHANNEL_PROTOCOL.into(),
                plan_sha256: "4".repeat(64),
                provider_sha256: "5".repeat(64),
                provider_protocol: aiw_probe::WindowsSandboxCliAdapter::V0_8_114_0.protocol(),
                workspace_identity_sha256: "6".repeat(64),
                nonce_hex: "7".repeat(64),
                host_ack_public_key_hex: hex::encode(host.public_key().unwrap()),
            },
        )
        .unwrap();
        let binding = request.channel_binding().unwrap();
        let collector = TokenEvidence {
            schema_version: aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION.into(),
            process_id: 42,
            token_type: TokenType::Primary,
            impersonation_level: None,
            is_app_container: false,
            app_container_sid: None,
            user_sid: "S-1-5-21-1-2-3-504".into(),
            integrity: IntegrityEvidence {
                sid: "S-1-16-12288".into(),
                rid: 12288,
                level: IntegrityLevel::High,
            },
            elevation_type: ElevationType::Full,
            is_elevated: true,
            capabilities: vec![],
            restricted_sid_count: 0,
        };
        let result = ApplicationAssessmentResult {
            schema_version: APPLICATION_ASSESSMENT_RESULT_V2_SCHEMA.into(),
            run_id: request.run_id.clone(),
            request_sha256: request.request_sha256.clone(),
            assessment_sha256: request.assessment_sha256.clone(),
            native: AssessmentNativeOutcome {
                schema_version: ASSESSMENT_NATIVE_OBSERVATION_V2_SCHEMA.into(),
                semantic_sha256: request.assessment.semantic_sha256.clone(),
                mode: request.assessment.mode,
                windows: None,
                windows_error: Some("synthetic pre-dispatch observation failure".into()),
                setup_token: Some(collector.clone()),
                standard_context: None,
                steps: vec![],
                assertions: vec![],
                collector_write_denied: None,
                collector_access_denials: vec![],
                collector_unimpersonated: None,
                collector_protection: None,
                profile_sid: None,
                account_cleanup: AssessmentAccountCleanup::default(),
                profile_cleanup: None,
                driver_errors: vec!["synthetic pre-dispatch setup refused; no app".into()],
                driver_completed: false,
                scope: ASSESSMENT_SCOPE.into(),
            },
        };
        let guest_public = hex::encode(guest.public_key().unwrap());
        let bootstrap = sign(
            signing_intent(
                &binding,
                &guest_public,
                0,
                &"0".repeat(64),
                AssessmentChannelPayload::Bootstrap {
                    schema_version: CHANNEL_SCHEMA.into(),
                    binding: Box::new(binding.clone()),
                    guest_public_key_hex: guest_public.clone(),
                    collector_token: Box::new(collector.clone()),
                    collector_storage: ChannelCollectorStorage::ProtectedGuestLocal,
                },
            )
            .unwrap(),
            &guest,
        )
        .canonical_wire()
        .unwrap();
        let mut state = AssessmentChannelSession::new(binding.clone()).unwrap();
        state.latch_bootstrap(&bootstrap, &CngVerifier).unwrap();
        let acknowledgement = sign(state.begin_ack().unwrap(), &host)
            .canonical_wire()
            .unwrap();
        let mut previous = state
            .accept_ack(&acknowledgement, &CngVerifier)
            .unwrap()
            .commitment()
            .to_owned();
        host.destroy().unwrap();
        let events = [
            AssessmentProgressEvent::Header {
                schema_version: CHANNEL_PROGRESS_SCHEMA.into(),
                run_id: request.run_id.clone(),
                sandbox_id: request.sandbox_id.clone(),
                request_sha256: request.request_sha256.clone(),
                assessment_sha256: request.assessment_sha256.clone(),
                agent_sha256: request.agent_sha256.clone(),
                config_sha256: request.config_sha256.clone(),
                project_revision_sha256: request.project_revision_sha256.clone(),
                collector_token: collector,
            },
            AssessmentProgressEvent::Context {
                windows: None,
                windows_error: result.native.windows_error.clone(),
                standard_context: None,
            },
            AssessmentProgressEvent::Terminal {
                collector_write_denied: None,
                collector_unimpersonated: None,
                profile_sid: None,
                profile_cleanup: None,
                account_cleanup: result.native.account_cleanup.clone(),
                driver_completed: false,
                errors: result.native.driver_errors.clone(),
            },
        ];
        let mut progress = Vec::new();
        for (index, event) in events.into_iter().enumerate() {
            let record = sign(
                signing_intent(
                    &binding,
                    &guest_public,
                    index as u64 + 1,
                    &previous,
                    AssessmentChannelPayload::Progress {
                        schema_version: CHANNEL_PROGRESS_SCHEMA.into(),
                        event: Box::new(event),
                    },
                )
                .unwrap(),
                &guest,
            );
            let mut wire = record.canonical_wire().unwrap();
            wire.push(b'\n');
            previous = state
                .accept_progress_line(&wire, &CngVerifier)
                .unwrap()
                .commitment()
                .to_owned();
            progress.extend_from_slice(&wire);
        }
        let raw_result = serde_json::to_vec_pretty(&result).unwrap();
        let mut log = EvidenceLog::new();
        log.append(EvidenceEvent {
            observed_utc: "synthetic-untrusted-clock".into(),
            kind: APPLICATION_ASSESSMENT_EVIDENCE_EVENT.into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::to_value(assessment_result_reference(&request, &result).unwrap())
                .unwrap(),
        })
        .unwrap();
        let mut evidence = Vec::new();
        for record in log.records() {
            serde_json::to_writer(&mut evidence, record).unwrap();
            evidence.push(b'\n');
        }
        let root = log.manifest().unwrap().root_hash;
        let receipt = WindowsSandboxCompletionReceipt {
            schema_version: WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            config_sha256: request.config_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            agent_sha256: request.agent_sha256.clone(),
            status: CompletionStatus::Failed,
            exit_code: 1,
            evidence_root_hash: root.clone(),
            artifacts: [
                (
                    "assessment-result.json",
                    ArtifactRole::ScenarioResults,
                    "application/json",
                    raw_result.as_slice(),
                ),
                (
                    "evidence.jsonl",
                    ArtifactRole::EvidenceLog,
                    "application/x-ndjson",
                    evidence.as_slice(),
                ),
                (
                    CHANNEL_PROGRESS_LEAF,
                    ArtifactRole::DiagnosticLog,
                    "application/x-ndjson",
                    progress.as_slice(),
                ),
            ]
            .into_iter()
            .map(|(path, role, media, bytes)| CompletionArtifact {
                path: path.into(),
                role,
                media_type: media.into(),
                size_bytes: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(bytes)),
            })
            .collect(),
        };
        let completion = serde_json::to_vec_pretty(&receipt).unwrap();
        let artifacts = [
            (
                ChannelArtifactRole::Result,
                "assessment-result.json",
                raw_result.as_slice(),
            ),
            (
                ChannelArtifactRole::Evidence,
                "evidence.jsonl",
                evidence.as_slice(),
            ),
            (
                ChannelArtifactRole::Completion,
                "completion.json",
                completion.as_slice(),
            ),
            (
                ChannelArtifactRole::Progress,
                CHANNEL_PROGRESS_LEAF,
                progress.as_slice(),
            ),
        ]
        .into_iter()
        .map(|(role, path, bytes)| ChannelArtifact {
            role,
            path: path.into(),
            size_bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        })
        .collect();
        let terminal = sign(
            signing_intent(
                &binding,
                &guest_public,
                4,
                &previous,
                AssessmentChannelPayload::Terminal {
                    schema_version: CHANNEL_SCHEMA.into(),
                    request_sha256: request.request_sha256.clone(),
                    assessment_sha256: request.assessment_sha256.clone(),
                    artifacts,
                    evidence_root_hash: root,
                    last_progress_sequence: 3,
                    last_progress_commitment: previous.clone(),
                },
            )
            .unwrap(),
            &guest,
        )
        .canonical_wire()
        .unwrap();
        guest.destroy().unwrap();
        // All signing keys are destroyed before filesystem publication/admission.
        let files = [
            (CHANNEL_BOOTSTRAP_LEAF, bootstrap.clone()),
            (CHANNEL_ACK_LEAF, acknowledgement.clone()),
            (CHANNEL_TERMINAL_LEAF, terminal),
            ("assessment-result.json", raw_result),
            ("evidence.jsonl", evidence),
            ("completion.json", completion),
            (CHANNEL_PROGRESS_LEAF, progress),
        ]
        .into_iter()
        .map(|(name, bytes)| (name.to_owned(), bytes))
        .collect();
        Self {
            request,
            binding,
            bootstrap,
            acknowledgement,
            files,
        }
    }

    fn replay(&self) -> ReplayedLatch {
        // PUBLIC replay only: no key generation, signing, provider or repair.
        let mut session = AssessmentChannelSession::new(self.binding.clone()).unwrap();
        session
            .latch_bootstrap(&self.bootstrap, &CngVerifier)
            .unwrap();
        let _intent = session.begin_ack().unwrap();
        session
            .accept_ack(&self.acknowledgement, &CngVerifier)
            .unwrap();
        ReplayedLatch {
            session,
            bootstrap: self.bootstrap.clone(),
            acknowledgement: self.acknowledgement.clone(),
        }
    }
}

fn with_workspace(f: impl FnOnce(&HeldRunWorkspace)) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let parent = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "aiw-publication-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&parent).unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let workspace = HeldRunWorkspace::create(&parent, "worker").unwrap();
        f(&workspace);
    }));
    // All held leases unwind before cleanup, even on assertion failure.
    std::fs::remove_dir_all(&parent).unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn write_files(workspace: &HeldRunWorkspace, files: &BTreeMap<String, Vec<u8>>) {
    for (name, bytes) in files {
        std::fs::write(workspace.output_path().join(name), bytes).unwrap();
    }
}

#[test]
fn native_cng_closed_seven_file_failed_driver_publication_is_admitted_without_workflow_credit() {
    let fixture = PublicationFixture::new();
    with_workspace(|workspace| {
        write_files(workspace, &fixture.files);
        assert_eq!(
            std::fs::read_dir(workspace.output_path()).unwrap().count(),
            7
        );
        for kind in AssessmentChannelFile::ALL {
            let file = workspace.open_assessment_channel_file(kind).unwrap();
            eprintln!(
                "publication fixture {kind:?}: observed short alias {:?}",
                file.observed_short_name()
            );
        }
        let held = hold_output(workspace.evidence()).unwrap();
        let admitted =
            verify_closed_publication(&held, &fixture.request, fixture.replay()).unwrap();
        assert!(!admitted.verification.successful);
        assert!(admitted.verification.receipt_verified);
        assert!(!admitted.evidence.driver_complete);
        assert_eq!(
            admitted.evidence.workflow_status,
            AssessmentFactStatus::NotRun
        );
        assert!(admitted.observed.native.steps.is_empty());
        assert!(admitted.observed.native.assertions.is_empty());
        assert!(
            admitted
                .evidence
                .steps
                .iter()
                .all(|row| row.status == AssessmentFactStatus::NotRun)
        );
        assert!(
            admitted
                .evidence
                .assertions
                .iter()
                .all(|row| row.status == AssessmentFactStatus::NotRun)
        );
        // Repeat retained admission with freshly replayed PUBLIC state only.
        let reread = verify_closed_publication(&held, &fixture.request, fixture.replay()).unwrap();
        assert_eq!(admitted.verification, reread.verification);
        assert_eq!(admitted.evidence, reread.evidence);
    });
}

#[test]
fn native_cng_closed_publication_refuses_each_raw_mutation_missing_file_and_foreign_entry() {
    let fixture = PublicationFixture::new();
    let names: Vec<_> = fixture.files.keys().cloned().collect();
    // Whitespace retains JSON semantics where applicable but changes ORIGINAL
    // byte commitments. This includes all four artifacts and both handshake files.
    for name in &names {
        let mut changed = fixture.files.clone();
        changed.get_mut(name).unwrap().push(b' ');
        with_workspace(|workspace| {
            write_files(workspace, &changed);
            let held = hold_output(workspace.evidence()).unwrap();
            assert!(
                verify_closed_publication(&held, &fixture.request, fixture.replay()).is_err(),
                "mutated {name}"
            );
        });
    }
    for name in &names {
        let mut missing = fixture.files.clone();
        missing.remove(name);
        with_workspace(|workspace| {
            write_files(workspace, &missing);
            assert!(hold_output(workspace.evidence()).is_err(), "missing {name}");
        });
    }
    with_workspace(|workspace| {
        write_files(workspace, &fixture.files);
        std::fs::write(workspace.output_path().join("foreign.json"), b"{}").unwrap();
        assert!(hold_output(workspace.evidence()).is_err());
    });
}

// Minimal public compiler fixture copied from provider tests; no private API.
fn project_fixture() -> (Project, AssessmentSettings, PortableContentManifest) {
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
