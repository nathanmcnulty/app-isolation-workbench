//! Fresh inert fixtures; any runtime readiness request is a test failure.
use super::*;
use std::cell::Cell;
use std::path::PathBuf;
struct StaticOnly {
    identity: aiw_probe::WindowsSandboxStaticIdentity,
    inspections: Cell<u32>,
    runtime: Cell<u32>,
}
impl PreparationProviderInspector for StaticOnly {
    fn static_identity(&self) -> Result<aiw_probe::WindowsSandboxStaticIdentity, String> {
        self.inspections.set(self.inspections.get() + 1);
        Ok(self.identity.clone())
    }
    fn runtime_readiness(&self) -> WindowsSandboxReadiness {
        self.runtime.set(self.runtime.get() + 1);
        panic!("preparation/import/verification attempted runtime provider invocation")
    }
}
#[test]
fn paired_static_prepare_verify_and_import_never_request_runtime_invocation_or_approval() {
    let parent = tests::TempDir::new("static-no-execution");
    let (_source, project, source, ready) =
        synthetic::protected_paired_fixture(&parent.0, "source-run", |_| tests::project());
    let inspector = StaticOnly {
        identity: synthetic::static_identity(&ready),
        inspections: Cell::new(0),
        runtime: Cell::new(0),
    };
    let artifacts = paired::prepare_paired_with_inspector(
        &parent.0,
        "static-run",
        &project,
        Path::new(&source.receipt.guest_agent.canonical_path),
        &source.receipt.guest_agent.sha256,
        "synthetic-time",
        &inspector,
    )
    .unwrap();
    let workspace = PathBuf::from(&artifacts.receipt.workspace.root.final_path);
    assert_eq!(
        artifacts.receipt.schema_version,
        paired::PAIRED_STATIC_PREPARATION_SCHEMA
    );
    assert_eq!(
        artifacts.receipt.provider_protocol_observation,
        Some(ProviderProtocolObservation::RequiredAtStartNotObserved)
    );
    assert!(artifacts.receipt.provider.version.is_none());
    assert!(!artifacts.receipt.provider_acquired && !artifacts.receipt.provider_mutated);
    let held = open_verified_preparation_with_inspector(
        &workspace,
        &project,
        &source.receipt.guest_agent.sha256,
        false,
        false,
        ProviderInspectionMode::PairedStaticOnly,
        &inspector,
    )
    .unwrap();
    assert_eq!(held.artifacts, artifacts);
    drop(held);
    let imported = import_preparation_with_inspector(
        &workspace,
        &project,
        &source.receipt.guest_agent.sha256,
        "synthetic-time",
        ProviderInspectionMode::PairedStaticOnly,
        &inspector,
    )
    .unwrap();
    assert!(
        !imported.receipt.approval_present
            && !imported.receipt.provider_acquired
            && !imported.receipt.provider_mutated
    );
    let held = open_verified_preparation_with_inspector(
        &workspace,
        &project,
        &source.receipt.guest_agent.sha256,
        true,
        false,
        ProviderInspectionMode::PairedStaticOnly,
        &inspector,
    )
    .unwrap();
    assert_eq!(held.artifacts, artifacts);
    let layout = RunLayout::new(&workspace, "static-run").unwrap();
    assert!(layout.retained_snapshot().unwrap().approval.is_none());
    assert!(matches!(
        layout.status().unwrap(),
        RecoveryStatus::PendingApproval { .. }
    ));
    assert_eq!(inspector.inspections.get(), 4);
    assert_eq!(inspector.runtime.get(), 0);
    assert!(!layout.run_dir().join("wsb-session-transaction").exists());
}
#[test]
fn paired_static_receipt_defers_runtime_but_start_requires_every_original_identity_and_empty_sessions()
 {
    let parent = tests::TempDir::new("static-bindings");
    let (_held, _project, artifacts, ready) =
        synthetic::protected_paired_fixture(&parent.0, "w1-run", |_| tests::project());
    let receipt = &artifacts.receipt;
    assert!(runtime_identity_matches_receipt(receipt, &ready).is_ok());
    let identity = synthetic::static_identity(&ready);
    assert!(static_identity_matches_receipt(receipt, &identity).is_ok());
    // Preserve the original observed-protocol receipt contract and serialization.
    let mut legacy = artifacts.clone();
    legacy.receipt.schema_version = paired::PAIRED_PREPARATION_SCHEMA.into();
    legacy.receipt.readiness_schema_version = READINESS_SCHEMA.into();
    legacy.receipt.provider_protocol_observation = None;
    legacy.receipt.provider.version = Some(PINNED_CLI_VERSION.into());
    assert!(legacy.validate().is_ok());
    assert!(legacy.validate_historical().is_ok());
    assert!(
        serde_json::to_value(&legacy.receipt)
            .unwrap()
            .get("providerProtocolObservation")
            .is_none()
    );
    for mutation in 0..11 {
        let mut changed = ready.clone();
        match mutation {
            0 => changed.provider_binary.as_mut().unwrap().sha256 = "f".repeat(64),
            1 => changed.provider_package.as_mut().unwrap().version = "changed".into(),
            2 => changed.catalog_trust.as_mut().unwrap().catalog_sha256 = "f".repeat(64),
            3 => changed.provider_file_identity.as_mut().unwrap().file_id = "f".repeat(16),
            4 => changed.cli_protocol.as_mut().unwrap().cli_version = "changed".into(),
            5 => changed.current_session_ids = vec!["00000000-0000-0000-0000-000000000000".into()],
            6 => changed.current_sessions = ReadinessState::Unknown,
            7 => changed.os_version.as_mut().unwrap().revision += 1,
            8 => changed.sandbox_feature = ReadinessState::Unknown,
            9 => changed.virtualization = ReadinessState::Unknown,
            _ => changed.supported = false,
        }
        assert!(
            runtime_identity_matches_receipt(receipt, &changed).is_err(),
            "runtime mutation {mutation} accepted"
        );
    }
    for mutation in 0..6 {
        let mut changed = identity.clone();
        match mutation {
            0 => changed.provider.sha256 = "f".repeat(64),
            1 => changed.package.version = "changed".into(),
            2 => changed.catalog.catalog_sha256 = "f".repeat(64),
            3 => changed.file_identity.file_id = "f".repeat(16),
            4 => changed.os_version.revision += 1,
            _ => changed.provider.version = Some(PINNED_CLI_VERSION.into()),
        }
        assert!(
            static_identity_matches_receipt(receipt, &changed).is_err(),
            "static mutation {mutation} accepted"
        );
    }
    for mutation in 0..4 {
        let mut changed = artifacts.clone();
        match mutation {
            0 => changed.receipt.provider_protocol_observation = None,
            1 => changed.receipt.schema_version = paired::PAIRED_PREPARATION_SCHEMA.into(),
            2 => changed.receipt.provider.version = Some(PINNED_CLI_VERSION.into()),
            _ => changed.receipt.readiness_schema_version = READINESS_SCHEMA.into(),
        }
        assert!(
            changed.validate().is_err(),
            "receipt semantic drift {mutation} accepted"
        );
    }
}
