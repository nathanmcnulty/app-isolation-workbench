use super::*;
use aiw_provider_wsb::{
    CompiledMsiScenario, ImportedMsiDocumentTransferResult, ImportedMsiScenarioResult,
    MAX_INTERACTIVE_DOCUMENT_BYTES, compile_notepad_plus_plus_msi_scenario,
    compile_notepad_plus_plus_msi_scenario_with_document,
};

fn transfer_result(start: &WsbGoldenProbeStart, bytes: &[u8]) -> ImportedMsiScenarioResult {
    let request = msi_request_for(start);
    let input = request.scenario.interactive_document.as_ref().unwrap();
    ImportedMsiScenarioResult::succeeded_with_document_transfer(
        &request,
        0,
        42,
        0,
        Some(ImportedMsiDocumentTransferResult {
            input_sha256: input.input_sha256.clone(),
            input_size_bytes: input.input_size_bytes,
            output_sha256: hex::encode(Sha256::digest(bytes)),
            output_size_bytes: bytes.len() as u64,
        }),
    )
    .unwrap()
}

fn transfer_process(
    start: &WsbGoldenProbeStart,
    result: ImportedMsiScenarioResult,
    bytes: Option<Vec<u8>>,
) -> FakeProcess {
    let writer_start = start.clone();
    successful_msi_process(start, result.clone()).with_start_action(Box::new(move || {
        write_msi_completion(
            &writer_start,
            result,
            false,
            RegistryFixture::Missing,
            ProductRegistrationFixture::Missing,
            bytes.as_deref(),
        );
    }))
}

#[test]
fn transfer_execution_rejects_contradictory_output_after_cleanup() {
    // Each receipt hashes its actual artifact correctly. Cross-artifact binding
    // and the text policy must still reject these otherwise valid completions.
    for case in ["hash", "size", "utf8", "nul", "missing", "input"] {
        let (_root, layout, start, readiness) = setup_msi_profile(Some(b"approved input"));
        let bytes = match case {
            "utf8" => vec![0xff],
            "nul" => b"edited\0text".to_vec(),
            _ => b"edited text".to_vec(),
        };
        let mut result = transfer_result(&start, &bytes);
        let transfer = result.document_transfer.as_mut().unwrap();
        match case {
            "hash" => transfer.output_sha256 = "f".repeat(64),
            "size" => transfer.output_size_bytes += 1,
            "input" => transfer.input_sha256 = "e".repeat(64),
            _ => {}
        }
        let fake = transfer_process(&start, result, (case != "missing").then_some(bytes));
        let error =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap_err();
        assert!(
            matches!(&error, RunnerError::Receipt(detail) if match case {
                "hash" | "size" | "utf8" | "nul" => detail.contains("bounded UTF-8 artifact"),
                "input" => detail.contains("not bound to the approved request"),
                "missing" => !detail.contains("media type"),
                _ => false,
            }),
            "{case}: {error:?}"
        );
        let terminal = layout.read_result().unwrap();
        assert_eq!(terminal.outcome, RunOutcome::Failed, "{case}");
        assert!(terminal.evidence_root.is_none(), "{case}");
        assert!(terminal.cleanup_complete, "{case}");
        assert_eq!(
            observe_wsb_session_status(&layout).unwrap().status,
            WsbSessionDisposition::Clean
        );
        assert!(!request_path(&start).exists());
    }
}

// Exercise native workspace identity and retained reporting without acquiring a
// provider or running an installer. Readiness and worker results are synthetic;
// the preparation builder, journal, artifact verifier and host export are real.
#[test]
fn protected_transfer_preparation_completion_report_and_export() {
    use aiw_windows_platform::HeldRunWorkspace;
    let (fixture, old_layout, mut start, mut readiness) =
        setup_msi_profile(Some(b"approved input"));
    start.provider.version = Some("0.8.107.0".into());
    readiness.provider_binary = Some(start.provider.clone());
    drop(old_layout);
    let project: Project = serde_yaml::from_slice(&fs::read(&start.project_path).unwrap()).unwrap();
    let workspace = HeldRunWorkspace::create(&fixture.0, "w1-run").unwrap();
    let stage = |leaf: &str, bytes: &[u8]| {
        let mut file = workspace.create_tools_file_new(leaf).unwrap().into_file();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let file = workspace.reopen_tools_file_readonly(leaf).unwrap();
        (identity(file.final_path()), file.identity().clone())
    };
    let (agent, _) = stage("aiw-guest-agent.exe", b"deterministic guest fixture");
    let msi = start.msi.as_mut().unwrap();
    let payload = fs::read(&msi.staged_payload.canonical_path).unwrap();
    (msi.staged_payload, msi.staged_identity) = stage("application.msi", &payload);
    let (staged_payload, staged_identity) = stage("document-input.txt", b"approved input");
    msi.staged_document = Some(WsbMsiDocument {
        staged_payload,
        staged_identity,
    });
    let prepared = build_wsb_msi_preparation(
        "w1-run",
        &project,
        &readiness,
        workspace.evidence(),
        &agent,
        "fixture-time",
        msi.clone(),
    )
    .unwrap();
    for (leaf, bytes) in [
        ("plan.json", serde_json::to_vec(&prepared.run_plan).unwrap()),
        (
            "wsb-plan.json",
            serde_json::to_vec(&prepared.wsb_plan).unwrap(),
        ),
        (
            "preparation.json",
            serde_json::to_vec(&prepared.receipt).unwrap(),
        ),
    ] {
        let mut file = workspace.create_root_file_new(leaf).unwrap().into_file();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
    }
    start.run_root = prepared.wsb_plan.workspace_root.clone();
    start.workspace = workspace.evidence().clone();
    start.workspace_identity_sha256 = prepared.receipt.workspace_identity_sha256.clone();
    start.wsb_plan = prepared.wsb_plan.clone();
    start.guest_agent = agent;
    let layout = RunLayout::new(workspace.root_path(), "w1-run").unwrap();
    let import = aiw_orchestrator::WsbPlanningImportReceipt {
        schema_version: aiw_orchestrator::WSB_MSI_PLANNING_IMPORT_RECEIPT_SCHEMA_VERSION.into(),
        run_id: "w1-run".into(),
        imported_at: "fixture-time".into(),
        status: aiw_orchestrator::WsbPlanningImportStatus::PendingApproval,
        project_revision_sha256: prepared.receipt.project_revision_sha256.clone(),
        workspace_root: start.workspace.root.final_path.clone(),
        workspace_identity_sha256: start.workspace_identity_sha256.clone(),
        preparation_receipt_sha256: canonical_hash(&prepared.receipt).unwrap(),
        run_plan_sha256: prepared.run_plan.hash().unwrap(),
        windows_sandbox_plan_sha256: canonical_hash(&prepared.wsb_plan).unwrap(),
        guest_agent_sha256: start.guest_agent.sha256.clone(),
        provider_sha256: start.provider.sha256.clone(),
        run_root: start.workspace.root.final_path.clone(),
        journal_sequence: 1,
        approval_present: false,
        provider_acquired: false,
        provider_mutated: false,
    };
    layout
        .create_or_verify_pending_wsb_import_bound(&workspace, &prepared.run_plan, &import)
        .unwrap();
    layout
        .write_approval(
            &ApprovalRecord::for_plan(&prepared.run_plan, "fixture", "fixture-time").unwrap(),
        )
        .unwrap();
    let output = "edited text: café\r\n".as_bytes();
    let mut diagnostics = crate::create_provider_diagnostics(&workspace, "w1-run").unwrap();
    diagnostics
        .write_all(b"{\"event\":\"test-observation\"}\n")
        .unwrap();
    diagnostics.sync_all().unwrap();
    drop(diagnostics);
    drop(crate::create_provider_diagnostics(&workspace, "w1-run").unwrap());
    let traces: Vec<_> = std::fs::read_dir(layout.run_dir())
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("provider-diagnostics-")
        })
        .collect();
    assert_eq!(traces.len(), 2);
    assert!(
        traces
            .iter()
            .any(|entry| std::fs::read(entry.path()).unwrap()
                == b"{\"event\":\"test-observation\"}\n")
    );
    let result = transfer_result(&start, output);
    let fake = transfer_process(&start, result, Some(output.to_vec()));
    let execution = crate::execute_wsb_golden_probe(
        &start,
        &readiness,
        &layout,
        &fake,
        &TestLease::default(),
        &workspace,
    )
    .unwrap();
    let root = workspace.root_path().to_owned();
    drop(workspace);

    let report =
        report_windows_sandbox_msi_run(&root, "w1-run", &project, &start.guest_agent.sha256)
            .unwrap();
    let WsbMsiRunReport::InteractiveSession(interactive) = report else {
        panic!("expected interactive report")
    };
    assert_eq!(interactive.receipt_sha256, execution.receipt_sha256);
    assert_eq!(
        interactive.schema_version,
        "aiw.dev/wsb-msi-interactive-report/v0alpha2"
    );
    assert!(
        report_windows_sandbox_msi(&root, "w1-run", &project, &start.guest_agent.sha256).is_err()
    );

    // Build the portable scratch recipe independently of the prepared transfer.
    let bundle = fixture.0.join("bundle");
    fs::create_dir(&bundle).unwrap();
    let bundled = compile_notepad_plus_plus_msi_scenario(&project, "install-launch-close").unwrap();
    let project_bytes =
        aiw_evidence::canonical_json_bytes(&serde_json::to_value(&project).unwrap()).unwrap();
    let manifest = crate::SandboxBundleManifest {
        schema_version: crate::SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION.into(),
        profile: bundled.profile.clone(),
        runtime: "windowsSandbox".into(),
        data_contract: "ephemeralInteractiveScratch".into(),
        scenario_id: bundled.scenario_id.clone(),
        scenario_sha256: canonical_hash(&bundled).unwrap(),
        project_sha256: hex::encode(Sha256::digest(&project_bytes)),
        source_import_receipt_sha256: start.msi.as_ref().unwrap().import_receipt_sha256.clone(),
        source_download_metadata_policy: None,
        application_sha256: bundled.application_sha256.clone(),
        application_size_bytes: payload.len() as u64,
    };
    fs::write(bundle.join("project.aiw"), project_bytes).unwrap();
    fs::write(bundle.join("app.msi"), payload).unwrap();
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_hash = hex::encode(Sha256::digest(&manifest_bytes));
    fs::write(bundle.join("manifest.aiw"), manifest_bytes).unwrap();
    let imported = crate::SandboxBundleImport {
        verification: crate::SandboxBundleVerification {
            manifest_sha256: manifest_hash.clone(),
            manifest,
            project: project.clone(),
            scenario: bundled.clone(),
        },
        project: project.clone(),
        scenario: bundled,
        import_receipt: start.msi.as_ref().unwrap().import_receipt.clone(),
    };
    let bundle_report = crate::report_notepad_plus_plus_msi_bundle(
        &bundle,
        &manifest_hash,
        &imported,
        &root,
        "w1-run",
        &start.guest_agent.sha256,
    )
    .unwrap();
    assert!(matches!(
        bundle_report.report,
        WsbMsiRunReport::InteractiveSession(_)
    ));
    let mut changed_import = imported.clone();
    changed_import.import_receipt.intake_id = "foreign-intake".into();
    assert!(
        crate::report_notepad_plus_plus_msi_bundle(
            &bundle,
            &manifest_hash,
            &changed_import,
            &root,
            "w1-run",
            &start.guest_agent.sha256,
        )
        .is_err()
    );

    let destination = fixture.0.join("export.txt");
    let exported = export_windows_sandbox_msi_document(
        &root,
        "w1-run",
        &project,
        &start.guest_agent.sha256,
        &destination,
    )
    .unwrap();
    assert_eq!(fs::read(&destination).unwrap(), output);
    assert_eq!(exported.receipt_sha256, execution.receipt_sha256);
    assert_eq!(exported.output_sha256, hex::encode(Sha256::digest(output)));
    assert!(
        export_windows_sandbox_msi_document(
            &root,
            "w1-run",
            &project,
            &start.guest_agent.sha256,
            &destination
        )
        .is_err()
    );
    assert_eq!(fs::read(&destination).unwrap(), output);
    let inside = root.join("output/forbidden.txt");
    assert!(
        export_windows_sandbox_msi_document(
            &root,
            "w1-run",
            &project,
            &start.guest_agent.sha256,
            &inside
        )
        .is_err()
    );
    assert!(!inside.exists());
    fs::write(root.join("output/document-output.txt"), b"tampered output").unwrap();
    assert!(
        report_windows_sandbox_msi_run(&root, "w1-run", &project, &start.guest_agent.sha256)
            .is_err()
    );
    let rejected = fixture.0.join("rejected.txt");
    assert!(
        export_windows_sandbox_msi_document(
            &root,
            "w1-run",
            &project,
            &start.guest_agent.sha256,
            &rejected
        )
        .is_err()
    );
    assert!(!rejected.exists());
}

#[test]
fn transfer_execution_accepts_empty_and_maximum_utf8_documents() {
    for bytes in [vec![], vec![b'x'; MAX_INTERACTIVE_DOCUMENT_BYTES as usize]] {
        let (_root, layout, start, readiness) = setup_msi_profile(Some(b"input"));
        let result = transfer_result(&start, &bytes);
        let fake = transfer_process(&start, result.clone(), Some(bytes));
        let execution =
            execute_wsb_golden_probe(&start, &readiness, &layout, &fake, &TestLease::default())
                .unwrap();
        assert_eq!(execution.scenario, Some(result));
        assert!(execution.behavior.is_none());
        assert!(execution.standard_user_context.is_some());
        assert!(execution.cleanup_complete);
        assert_eq!(
            layout.read_result().unwrap().outcome,
            RunOutcome::InsufficientEvidence
        );
        assert_eq!(
            msi_execution_schema(&start.msi.unwrap().scenario),
            "aiw.dev/wsb-interactive-msi-execution/v0alpha2"
        );
    }
}

fn interactive_project() -> Project {
    serde_yaml::from_str(include_str!(
        "../../../../examples/notepad-plus-plus-interactive.aiw.yaml"
    ))
    .unwrap()
}

#[test]
fn bundle_allows_only_the_approved_document_specialization() {
    let project = interactive_project();
    let bundled = compile_notepad_plus_plus_msi_scenario(&project, "install-launch-close").unwrap();
    let prepared = compile_notepad_plus_plus_msi_scenario_with_document(
        &project,
        &bundled.scenario_id,
        &"a".repeat(64),
        7,
    )
    .unwrap();
    let verify = |candidate: &CompiledMsiScenario| {
        crate::sandbox_bundle::verify_prepared_scenario(&project, &bundled, candidate)
    };
    verify(&bundled).unwrap();
    verify(&prepared).unwrap();
    for field in [
        "lifetime",
        "application",
        "scenario",
        "command",
        "size",
        "profile",
    ] {
        let mut changed = prepared.clone();
        match field {
            "lifetime" => changed.interactive_session_seconds = Some(120),
            "application" => changed.application_sha256 = "b".repeat(64),
            "scenario" => changed.scenario_id = "other".into(),
            "command" => changed.launch_arguments.push("unexpected".into()),
            "size" => {
                changed
                    .interactive_document
                    .as_mut()
                    .unwrap()
                    .input_size_bytes = MAX_INTERACTIVE_DOCUMENT_BYTES + 1
            }
            "profile" => changed.profile = bundled.profile.clone(),
            _ => unreachable!(),
        }
        assert!(verify(&changed).is_err(), "{field}");
    }
    let mut different_project = project.clone();
    different_project.scenarios[0].steps[3] = aiw_schema::ScenarioStep::WaitForUserClose {
        timeout_seconds: 120,
    };
    assert!(
        crate::sandbox_bundle::verify_prepared_scenario(&different_project, &bundled, &prepared)
            .is_err()
    );

    let assessment: Project = serde_yaml::from_str(include_str!(
        "../../../../examples/notepad-plus-plus-msi.aiw.yaml"
    ))
    .unwrap();
    let assessment =
        compile_notepad_plus_plus_msi_scenario(&assessment, "install-launch-close").unwrap();
    assert!(
        crate::sandbox_bundle::verify_prepared_scenario(&project, &assessment, &prepared).is_err()
    );
}

#[test]
fn execution_schemas_preserve_assessment_versions_and_distinguish_transfer() {
    let project = interactive_project();
    let scratch = compile_notepad_plus_plus_msi_scenario(&project, "install-launch-close").unwrap();
    assert_eq!(
        msi_execution_schema(&scratch),
        "aiw.dev/wsb-interactive-msi-execution/v0alpha1"
    );
    let document = compile_notepad_plus_plus_msi_scenario_with_document(
        &project,
        &scratch.scenario_id,
        &"a".repeat(64),
        0,
    )
    .unwrap();
    assert_eq!(
        msi_execution_schema(&document),
        "aiw.dev/wsb-interactive-msi-execution/v0alpha2"
    );
    let project: Project = serde_yaml::from_str(include_str!(
        "../../../../examples/notepad-plus-plus-msi.aiw.yaml"
    ))
    .unwrap();
    let assessment =
        compile_notepad_plus_plus_msi_scenario(&project, "install-launch-close").unwrap();
    for version in 1..=6 {
        let mut historical = assessment.clone();
        historical.schema_version =
            format!("aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha{version}");
        historical.profile =
            format!("aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha{version}");
        if version < 3 {
            historical.document_exercise = None;
        } else if version == 3 {
            historical.document_exercise.as_mut().unwrap().document_path =
                aiw_provider_wsb::DOCUMENT_EXERCISE_PATH.into();
        }
        historical.validate().unwrap();
        assert_eq!(
            msi_execution_schema(&historical),
            format!("aiw.dev/wsb-imported-msi-execution/v0alpha{version}")
        );
    }
}
