//! Inert synthetic preparation shared by offline tests; never probes or executes a provider.
use super::*;
pub(crate) fn readiness() -> WindowsSandboxReadiness {
    WindowsSandboxReadiness {
        schema_version: READINESS_SCHEMA.to_owned(),
        supported: true,
        os_build: Some(26_100),
        os_version: None,
        process_architecture: "x86_64".to_owned(),
        virtualization: ReadinessState::Available,
        sandbox_feature: ReadinessState::Available,
        provider_binary: Some(BinaryIdentity {
            canonical_path: r"C:\Program Files\WindowsApps\wsb.exe".to_owned(),
            sha256: "a".repeat(64),
            size_bytes: 100,
            version: Some(PINNED_CLI_VERSION.to_owned()),
            signature_status: ReadinessState::Available,
        }),
        provider_package: Some(WindowsPackageIdentity {
            name: "MicrosoftWindows.WindowsSandbox".to_owned(),
            full_name: "MicrosoftWindows.WindowsSandbox_1.0.0.0_x64".to_owned(),
            family_name: "MicrosoftWindows.WindowsSandbox_8wekyb3d8bbwe".to_owned(),
            publisher: "CN=Microsoft Corporation".to_owned(),
            publisher_id: "8wekyb3d8bbwe".to_owned(),
            version: "1.0.0.0".to_owned(),
            architecture: "x64".to_owned(),
            signature_kind: "store".to_owned(),
            status_ok: true,
            install_location: r"C:\Program Files\WindowsApps".to_owned(),
        }),
        catalog_trust: Some(CatalogTrustIdentity {
            trust_kind: "catalogMember".to_owned(),
            catalog_path: r"C:\Program Files\WindowsApps\AppxMetadata\CodeIntegrity.cat".to_owned(),
            catalog_sha256: "c".repeat(64),
            catalog_file_identity: WindowsFileIdentity {
                final_path: r"C:\Program Files\WindowsApps\AppxMetadata\CodeIntegrity.cat"
                    .to_owned(),
                volume_serial_number: "2".repeat(16),
                file_id: "5".repeat(32),
            },
            member_tag: "wsb.exe".to_owned(),
            trust_policy: "WinVerifyTrust".to_owned(),
            verification_status: ReadinessState::Available,
        }),
        provider_file_identity: Some(WindowsFileIdentity {
            final_path: r"C:\Program Files\WindowsApps\wsb.exe".to_owned(),
            volume_serial_number: "2".repeat(16),
            file_id: "6".repeat(32),
        }),
        cli_protocol: Some(WindowsSandboxCliProtocol {
            cli_version: PINNED_CLI_VERSION.to_owned(),
            protocol: PINNED_CLI_PROTOCOL.to_owned(),
            list_schema: PINNED_LIST_SCHEMA.to_owned(),
        }),
        app_execution_alias: None,
        current_sessions: ReadinessState::Available,
        current_session_ids: vec![],
        blockers: vec![],
        warnings: vec![],
    }
}

/// Test-only, inert bytes and synthetic readiness. No executable/provider
/// is run; only fresh protected fixture files and normal journal services.
#[cfg(windows)]
pub(crate) fn protected_paired_fixture(
    parent: &Path,
    run_id: &str,
    project_factory: impl FnOnce(&str) -> Project,
) -> (
    aiw_windows_platform::HeldRunWorkspace,
    Project,
    PreparedWsbArtifacts,
    WindowsSandboxReadiness,
) {
    use std::io::Write;
    let held = aiw_windows_platform::HeldRunWorkspace::create(parent, run_id).unwrap();
    let mut ready = readiness();
    let provider_path = parent.join("wsb.exe");
    std::fs::write(&provider_path, b"synthetic-inert-provider-never-executed").unwrap();
    let provider = aiw_windows_platform::HeldApplicationFile::open(&provider_path).unwrap();
    ready.provider_binary.as_mut().unwrap().canonical_path =
        provider_path.to_string_lossy().into_owned();
    ready.provider_binary.as_mut().unwrap().sha256 = provider.observation().sha256.clone();
    ready.provider_binary.as_mut().unwrap().size_bytes = provider.observation().size_bytes;
    ready.provider_file_identity = Some(provider.observation().identity.clone());
    ready.provider_file_identity.as_mut().unwrap().final_path =
        provider_path.to_string_lossy().into_owned();
    // Fake provider authority retains the kernel's 64-bit identity schema;
    // this is not native Store enrollment. Workspace/role IDs below are real
    // protected fixture identities. No provider is ever invoked.
    ready
        .provider_file_identity
        .as_mut()
        .unwrap()
        .volume_serial_number = "00000000".into();
    ready.provider_file_identity.as_mut().unwrap().file_id = "0000000000000000".into();

    let package = ready.provider_package.as_mut().unwrap();
    package.family_name = "MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy".into();
    package.publisher_id = "cw5n1h2txyewy".into();
    package.version = PINNED_CLI_VERSION.into();
    ready.catalog_trust.as_mut().unwrap().trust_policy = "cacheOnlyWholeChainExcludeRoot".into();

    let windows = aiw_probe::WindowsVersionObservation {
        major: 10,
        minor: 0,
        build: 26100,
        revision: 0,
        observer_architecture: "x86_64".into(),
    };
    ready.os_version = Some(windows.clone());
    let mut roles = Vec::new();
    for leaf in [
        GUEST_AGENT_FILE,
        paired::CONTROL_FIXTURE_FILE,
        paired::CONTROL_LAUNCHER_FILE,
    ] {
        let mut file = held.create_tools_file_new(leaf).unwrap().into_file();
        file.write_all(b"synthetic-inert-agent-never-executed")
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
        let bound = held.reopen_tools_file_readonly(leaf).unwrap();
        let input = aiw_windows_platform::HeldApplicationFile::open(bound.final_path()).unwrap();
        roles.push(WsbMsiDocument {
            staged_payload: BinaryIdentity {
                canonical_path: super::provider_path(&bound.final_path().to_string_lossy()),
                sha256: input.observation().sha256.clone(),
                size_bytes: input.observation().size_bytes,
                version: None,
                signature_status: ReadinessState::Unknown,
            },
            staged_identity: bound.identity().clone(),
        });
    }
    let agent = roles.remove(0).staged_payload;
    let fixture = roles.remove(0);
    let launcher = roles.remove(0);
    let profile=aiw_probe::PairedControlProfile {revision:aiw_probe::PAIRED_CONTROL_REVISION.into(),source_sha256:aiw_probe::paired_controls::paired_control_source_sha256(),fixture_sha256:agent.sha256.clone(),fixture_size_bytes:agent.size_bytes,launcher_sha256:agent.sha256.clone(),launcher_size_bytes:agent.size_bytes,origin:aiw_probe::ControlEvidenceOrigin::SyntheticRehearsal,expected_windows:windows,policy:aiw_probe::paired_controls::PairedControlPolicy::ClassicAppContainerNoCapabilitiesFixedChildOutputGrant};
    let project = project_factory(&agent.sha256);
    let base = build_wsb_preparation(
        run_id,
        &project,
        &ready,
        held.evidence(),
        &agent,
        "synthetic-time",
    )
    .unwrap();
    let artifacts = build_wsb_paired_controls_preparation(
        base,
        WsbPairedControls {
            profile,
            fixture,
            launcher,
        },
    )
    .unwrap();
    let staged = stage_bundle(&held, &artifacts).unwrap();
    complete_bundle(&held, &artifacts, staged).unwrap();
    (held, project, artifacts, ready)
}
