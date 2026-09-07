use super::*;

/// Models interruption after guest completion, while the session is still active.
/// All fault injection is test-only; recovery never repairs a foreign request.
#[test]
#[ignore = "runs the recorded MSI inside Sandbox and injects recovery request drift; requires explicit MSI live inputs"]
fn live_msi_interrupted_completion_rejects_foreign_request_and_recovers() {
    assert_eq!(std::env::var("AIW_RUN_LIVE_WSB_MSI").as_deref(), Ok("1"));
    let guest = PathBuf::from(std::env::var_os("AIW_LIVE_GUEST_AGENT").unwrap());
    let guest_hash = std::env::var("AIW_LIVE_GUEST_AGENT_SHA256").unwrap();
    let receipt_path = PathBuf::from(std::env::var_os("AIW_LIVE_MSI_RECEIPT").unwrap());
    let receipt = serde_json::from_slice(&fs::read(receipt_path).unwrap()).unwrap();
    let project: Project = serde_yaml::from_str(include_str!(
        "../../../examples/notepad-plus-plus-msi.aiw.yaml"
    ))
    .unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let run_id = format!("msi-recovery-{}-{nonce}", std::process::id());
    let parent = std::env::temp_dir().canonicalize().unwrap();
    let project_path = parent.join(format!("{run_id}.project.json"));
    let mut project_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&project_path)
        .unwrap();
    project_file
        .write_all(&serde_json::to_vec(&project).unwrap())
        .unwrap();
    project_file.sync_all().unwrap();
    drop(project_file);
    let artifacts = prepare_windows_sandbox_msi_bundle(
        &run_id,
        &project,
        &guest,
        &guest_hash,
        &parent,
        "live-test-time",
        WsbMsiPreparationInput {
            import_receipt: &receipt,
            scenario_id: "install-launch-close",
        },
    )
    .unwrap();
    let root = PathBuf::from(&artifacts.receipt.workspace.root.final_path);
    eprintln!("MSI_RECOVERY_WORKSPACE={}", root.display());
    import_windows_sandbox_preparation(&root, &project, &guest_hash, "live-test-import").unwrap();
    let layout = RunLayout::new(&root, &run_id).unwrap();
    layout
        .write_approval(
            &aiw_orchestrator::ApprovalRecord::for_plan(
                &artifacts.run_plan,
                "user-authorized live recovery test",
                "live-test-approval",
            )
            .unwrap(),
        )
        .unwrap();
    let mut held = preparation::open_verified_windows_sandbox_preparation(
        &root,
        &project,
        &guest_hash,
        true,
        false,
    )
    .unwrap();
    held.revalidate_imported().unwrap();
    let start = WsbGoldenProbeStart {
        schema_version: "aiw.dev/wsb-imported-msi-start/v0alpha1".to_owned(),
        run_root: artifacts.receipt.workspace.root.final_path.clone(),
        project_path: project_path.to_string_lossy().into_owned(),
        wsb_plan: artifacts.wsb_plan.clone(),
        provider: artifacts.receipt.provider,
        guest_agent: artifacts.receipt.guest_agent,
        workspace: artifacts.receipt.workspace,
        workspace_identity_sha256: artifacts.receipt.workspace_identity_sha256,
        timeout_seconds: 300,
        msi: artifacts.receipt.msi,
    };
    let lease = aiw_windows_platform::acquire_windows_sandbox(&start.provider.sha256).unwrap();
    let readiness = lease.readiness().clone();
    let native = NativeWsbProcess {
        state: std::sync::Mutex::new(NativeWsbState {
            lease,
            started_id: None,
        }),
        plan: start.wsb_plan.clone(),
    };
    let context = prepare_execution(&start, &readiness, &layout, true).unwrap();
    let store = TransactionStore::new(&layout, context.binding.clone());
    prepare_request_artifact(&context.request_path, &context.guest_request).unwrap();
    revalidate_workspace(&start, held.workspace()).unwrap();
    store.create("approved-start").unwrap();
    let operation = run_attempt(&start, &layout, &native, &context, &store);
    // Release process-local handles and lease, omitting normal finalization.
    drop(native);
    drop(held);
    if let Err(error) = operation {
        eprintln!(
            "MSI_RECOVERY_AFTER_ATTEMPT_ERROR={:?}",
            recover_windows_sandbox(&layout)
        );
        panic!("live MSI attempt failed: {error}");
    }

    let original = fs::read(&context.request_path).unwrap();
    let mut foreign = match context.guest_request.clone() {
        ExecutionGuestRequest::ImportedMsi(request) => request,
        _ => panic!("expected MSI request"),
    };
    foreign.run_id = "foreign-run".to_owned();
    foreign.request_sha256 = foreign.recompute_request_sha256().unwrap();
    foreign.validate().unwrap();
    let foreign_bytes = serde_json::to_vec(&foreign).unwrap();
    fs::write(&context.request_path, &foreign_bytes).unwrap();
    let rejected = recover_windows_sandbox(&layout);
    let preserved = fs::read(&context.request_path).unwrap();
    let result_was_absent = !layout.result_path().exists();
    let rejected_state = store.load_current().unwrap().unwrap().current_state();
    let sessions_after_rejection =
        aiw_windows_platform::assess_windows_sandbox().current_session_ids;
    // Remove our injected fault using the retained exact original bytes. This is
    // fixture restoration, never a recovery API or authority-recapture behavior.
    fs::write(&context.request_path, original).unwrap();
    let recovered = recover_windows_sandbox(&layout).unwrap();
    eprintln!(
        "MSI_RECOVERY_RESULT={}",
        serde_json::to_string(&recovered).unwrap()
    );
    assert!(matches!(rejected, Err(RunnerError::RecoveryRequired(_))));
    assert_eq!(preserved, foreign_bytes);
    assert!(result_was_absent);
    assert_eq!(rejected_state, SessionTransactionState::RecoveryRequired);
    assert!(sessions_after_rejection.is_empty());
    assert!(recovered.provider_cleanup_verified && recovered.workspace_cleanup_verified);
    assert!(recovered.terminalizable);
    assert!(!context.request_path.exists());
    let result = layout.read_result().unwrap();
    assert_eq!(result.outcome, RunOutcome::Failed);
    assert!(result.cleanup_complete);
    assert!(result.evidence_root.is_none());
    let result_bytes = fs::read(layout.result_path()).unwrap();
    let journal_bytes = fs::read(layout.journal_path()).unwrap();
    recover_windows_sandbox(&layout).unwrap();
    assert_eq!(fs::read(layout.result_path()).unwrap(), result_bytes);
    assert_eq!(fs::read(layout.journal_path()).unwrap(), journal_bytes);
    assert!(
        aiw_windows_platform::assess_windows_sandbox()
            .current_session_ids
            .is_empty()
    );
    // Preserve all prepared inputs, journal, and untrusted guest artifacts.
}
