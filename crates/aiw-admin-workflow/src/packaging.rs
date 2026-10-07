//! Installer analysis and assembly are separate from compatibility and execution.
use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum NotepadPackageProfile {
    LocalSettingsAssessment,
    InteractiveDocument,
}

/// Only the existing fixed offline Sandbox policy can be selected. Device,
/// resource and exact mapping disclosures are resolved in the replay recipe.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PackageIsolationPreset {
    OfflineWindowsSandbox,
}

impl NotepadPackageProfile {
    fn directory(self) -> &'static str {
        match self {
            Self::LocalSettingsAssessment => "notepad-plus-plus",
            Self::InteractiveDocument => "notepad-plus-plus-interactive",
        }
    }
    fn product(self) -> &'static str {
        match self {
            Self::LocalSettingsAssessment => PRODUCT_ID,
            Self::InteractiveDocument => INTERACTIVE_PRODUCT_ID,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageOption {
    pub profile: NotepadPackageProfile,
    pub project_sha256: String,
    pub isolation_preset: PackageIsolationPreset,
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageAnalysis {
    pub schema_version: String,
    pub installer: aiw_probe::ApplicationInspection,
    pub options: Vec<PackageOption>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotepadPackageRequest {
    pub installer: PathBuf,
    pub profile: NotepadPackageProfile,
    pub isolation_preset: PackageIsolationPreset,
    pub analyzed_installer_sha256: String,
    pub analyzed_project_sha256: String,
    pub evidence_parent: PathBuf,
    pub output_parent: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageResult {
    pub schema_version: String,
    pub profile: NotepadPackageProfile,
    pub isolation_preset: PackageIsolationPreset,
    pub evidence_root: PathBuf,
    pub bundle: aiw_runner::SandboxBundleExport,
    pub next: String,
}

#[cfg(any(windows, test))]
fn fixed_assets(
    root: &Path,
    profile: NotepadPackageProfile,
) -> Result<(Project, ProductAssetManifest)> {
    let manifest: ProductAssetManifest = serde_json::from_slice(&read_file_bounded(
        &root.join("manifest.json"),
        1024 * 1024,
    )?)?;
    let assets = match profile {
        NotepadPackageProfile::LocalSettingsAssessment => manifest.resolve(root)?,
        NotepadPackageProfile::InteractiveDocument => manifest.resolve_interactive(root)?,
    };
    let bytes = read_file_bounded(&assets.project, MAX_CONFIG_BYTES)?;
    if lowercase_sha256(&bytes) != manifest.project_sha256 {
        bail!("packaged project changed; analyze the installer again with intact product assets");
    }
    let project: Project = serde_yaml::from_slice(&bytes)?;
    if project.metadata.name != profile.product()
        || !validate_project_for_planning(&project).is_empty()
    {
        bail!("packaged project is not the selected Notepad++ recipe");
    }
    // Reuse the executor's fixed compiler; package metadata cannot add grants.
    aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario(&project, SCENARIO_ID)
        .map_err(|error| anyhow!("unsupported package recipe: {error}"))?;
    Ok((project, manifest))
}

#[cfg(any(windows, test))]
fn supported_hash(project: &Project) -> Result<&str> {
    match &project.application {
        ApplicationSource::Msi(source) => Ok(&source.sha256),
        _ => bail!("the selected recipe requires an MSI"),
    }
}

/// Read-only identity observation. No intake, provider lease or worker is created.
/// The result is advisory; assembly reopens and revalidates installer and assets.
#[cfg(windows)]
pub fn analyze_notepad_installer(installer: &Path) -> Result<PackageAnalysis> {
    let held = aiw_windows_platform::HeldApplicationFile::open_with_download_metadata(installer)?;
    let observed = held.observation();
    let mut inspection = inspect_application_source(installer, ApplicationInspectionKind::Msi)?;
    if inspection.sha256.as_deref() != Some(&observed.sha256)
        || inspection.size_bytes != Some(observed.size_bytes)
    {
        bail!("installer drifted during analysis");
    }
    inspection.signature_status = held.embedded_signature_status()?;
    inspection
        .canonical_path
        .clone_from(&observed.canonical_path);
    inspection.file_authority = Some(aiw_probe::ApplicationFileAuthority {
        schema_version: if observed.download_metadata.is_empty() {
            aiw_probe::APPLICATION_FILE_AUTHORITY_SCHEMA
        } else {
            aiw_probe::APPLICATION_DOWNLOAD_AUTHORITY_SCHEMA
        }
        .into(),
        identity: observed.identity.clone(),
        size_bytes: observed.size_bytes,
        sha256: observed.sha256.clone(),
        link_count: observed.link_count,
        only_unnamed_data_stream: observed.only_unnamed_data_stream,
        download_metadata: observed.download_metadata.clone(),
    });
    inspection.limitations = vec![
        "Held file identity, streams and embedded signature were observed during analysis. Signature status is not publisher identity or application compatibility.".into(),
        "Analysis grants no import or execution authority; packaging reopens and verifies the selected bytes.".into(),
    ];
    held.revalidate()?;
    let mut options = Vec::new();
    for profile in [
        NotepadPackageProfile::LocalSettingsAssessment,
        NotepadPackageProfile::InteractiveDocument,
    ] {
        let (project, manifest) =
            fixed_assets(&packaged_asset_root(profile.directory())?, profile)?;
        if inspection.sha256.as_deref() == Some(supported_hash(&project)?) {
            options.push(PackageOption {
                profile,
                project_sha256: manifest.project_sha256,
                isolation_preset: PackageIsolationPreset::OfflineWindowsSandbox,
                description: match profile {
                    NotepadPackageProfile::LocalSettingsAssessment => "Fixed assessment with ephemeral local settings; no user document is included.",
                    NotepadPackageProfile::InteractiveDocument => "Interactive document workflow; a bounded text input is selected and approved separately at launch, with explicit verified export.",
                }.into(),
            });
        }
    }
    held.revalidate()?;
    Ok(PackageAnalysis {
        schema_version: "aiw.dev/admin-package-analysis/v0alpha1".into(),
        installer: inspection,
        options,
        limitations: vec![
            "Only the exact supported Notepad++ MSI recipes can be packaged. Other isolation modes and custom grants are unavailable.".into(),
            "Windows Sandbox settings request blocked network and disabled clipboard. Fixed guest-tool and output mappings remain part of the recipe; requested settings are not measured isolation.".into(),
            "Exact runtime mappings, devices, protected-client and resource settings are resolved and disclosed in the fresh replay recipe before approval; packaging does not enable arbitrary settings.".into(),
            "Analysis does not install the application or establish compatibility. The bundle needs a verified Workbench guest/runtime and fresh plan approval and Start before replay.".into(),
        ],
    })
}

/// Assemble and verify a reusable bundle through protected intake. Never executes
/// an installer, approves a plan, starts Sandbox, or overwrites an existing bundle.
#[cfg(windows)]
pub fn create_notepad_package(request: &NotepadPackageRequest) -> Result<PackageResult> {
    create_with_assets(request, &packaged_asset_root(request.profile.directory())?)
}

#[cfg(windows)]
pub(crate) fn import_for_replay(
    bundle: &Path,
    manifest_sha256: &str,
    intake_parent: &Path,
    expected_project: &Project,
) -> Result<aiw_runner::SandboxBundleImport> {
    let verified = aiw_runner::verify_notepad_plus_plus_msi_bundle(bundle, manifest_sha256)?;
    if &verified.project != expected_project {
        bail!(
            "package recipe differs from the selected installed workflow; preserve it and choose the matching workflow or rebuild with current product assets"
        );
    }
    // Import reopens and verifies the closed bundle while holding all objects.
    let imported = aiw_runner::import_notepad_plus_plus_msi_bundle(
        bundle,
        intake_parent,
        "notepad-plus-plus",
        manifest_sha256,
    )?;
    if &imported.project != expected_project {
        bail!("package project changed during import; preserve the intake and use fresh evidence");
    }
    Ok(imported)
}

#[cfg(windows)]
fn create_with_assets(
    request: &NotepadPackageRequest,
    assets_root: &Path,
) -> Result<PackageResult> {
    let (project, manifest) = fixed_assets(assets_root, request.profile)?;
    if !valid_sha256(&request.analyzed_installer_sha256)
        || !valid_sha256(&request.analyzed_project_sha256)
        || manifest.project_sha256 != request.analyzed_project_sha256
        || supported_hash(&project)? != request.analyzed_installer_sha256
    {
        bail!("installer or selected recipe differs from analysis; analyze again before packaging");
    }
    let held =
        aiw_windows_platform::HeldApplicationFile::open_with_download_metadata(&request.installer)?;
    if held.observation().sha256 != request.analyzed_installer_sha256 {
        bail!("installer changed since analysis; no package was created");
    }
    held.revalidate()?;
    let id = format!("package-{}", nonce());
    let evidence_root = create_evidence_root(&request.evidence_parent, &id)?;
    let assembled = (|| -> Result<PackageResult> {
        save_stage(
            &evidence_root,
            "selection",
            &serde_json::json!({
            "profile": request.profile, "isolationPreset": request.isolation_preset, "installerSha256": request.analyzed_installer_sha256,
                "projectSha256": request.analyzed_project_sha256,
                "executionStarted": false,
            }),
        )?;
        let intake_parent = evidence_root.join("intakes");
        std::fs::create_dir(&intake_parent)?;
        let receipt = aiw_windows_platform::import_application_file_with_metadata(
            &intake_parent,
            "notepad-plus-plus",
            ApplicationInspectionKind::Msi,
            &held,
            true,
        )?;
        save_stage(&evidence_root, "intake-receipt", &receipt)?;
        let bundle = aiw_runner::export_notepad_plus_plus_msi_bundle(
            &request.output_parent,
            &format!("bundle-{id}"),
            &project,
            SCENARIO_ID,
            &receipt,
        )?;
        aiw_runner::verify_notepad_plus_plus_msi_bundle(
            Path::new(&bundle.bundle_path),
            &bundle.manifest_sha256,
        )?;
        let result = PackageResult {
        schema_version: "aiw.dev/admin-package-result/v0alpha1".into(),
        profile: request.profile,
        isolation_preset: request.isolation_preset,
        evidence_root: evidence_root.clone(),
        bundle,
        next: "Package assembled and verified, not compatibility-certified. Preserve the manifest hash and evidence. Import through Workbench for fresh recipe review, approval, Start and disposable-worker validation. Preserve incomplete output on failure; retry in fresh locations.".into(),
    };
        save_stage(&result.evidence_root, "package-result", &result)?;
        Ok(result)
    })();
    assembled.map_err(|error| {
        let detail = error.to_string();
        let failure = serde_json::json!({"executionStarted": false, "detail": detail,
            "next": "Preserve this evidence and any partial output. Retry only in fresh locations after correcting the cause."});
        let recorded = save_stage(&evidence_root, "package-failed", &failure).is_ok();
        anyhow!("Packaging stopped; preserve evidence {} and partial output. Failure record written: {recorded}. Cause: {detail}", evidence_root.display())
    })
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn fixture(profile: NotepadPackageProfile) -> (PathBuf, PathBuf, NotepadPackageRequest) {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "aiw-admin-package-{}-{}-{sequence}",
            std::process::id(),
            nonce()
        ));
        let assets = root.join("assets");
        std::fs::create_dir_all(assets.join("tools")).unwrap();
        for leaf in ["evidence", "bundles"] {
            std::fs::create_dir(root.join(leaf)).unwrap();
        }
        let installer = root.join("fixture.msi");
        std::fs::write(&installer, b"inert MSI contract fixture").unwrap();
        let installer_hash = lowercase_sha256(b"inert MSI contract fixture");
        let bytes: &[u8] = match profile {
            NotepadPackageProfile::LocalSettingsAssessment => {
                include_bytes!("../../aiw-cli/product/notepad-plus-plus/project.yaml")
            }
            NotepadPackageProfile::InteractiveDocument => {
                include_bytes!("../../aiw-cli/product/notepad-plus-plus-interactive/project.yaml")
            }
        };
        let mut project: Project = serde_yaml::from_slice(bytes).unwrap();
        let ApplicationSource::Msi(source) = &mut project.application else {
            panic!("MSI fixture")
        };
        source.sha256.clone_from(&installer_hash);
        let project_bytes = serde_yaml::to_string(&project).unwrap();
        let project_hash = lowercase_sha256(project_bytes.as_bytes());
        std::fs::write(assets.join("project.yaml"), project_bytes).unwrap();
        std::fs::write(assets.join("tools/agent.exe"), b"inert agent").unwrap();
        std::fs::write(assets.join("manifest.json"), serde_json::to_vec(&serde_json::json!({
            "schemaVersion": MANIFEST_SCHEMA, "productId": profile.product(), "scenarioId": SCENARIO_ID,
            "projectPath": "project.yaml", "projectSha256": project_hash,
            "guestAgentPath": "tools/agent.exe", "guestAgentSha256": lowercase_sha256(b"inert agent"),
        })).unwrap()).unwrap();
        let request = NotepadPackageRequest {
            installer,
            profile,
            isolation_preset: PackageIsolationPreset::OfflineWindowsSandbox,
            analyzed_installer_sha256: installer_hash,
            analyzed_project_sha256: project_hash,
            evidence_parent: root.join("evidence"),
            output_parent: root.join("bundles"),
        };
        (root, assets, request)
    }

    #[test]
    fn assembly_preserves_selected_recipe_and_retains_verified_result() {
        for profile in [
            NotepadPackageProfile::LocalSettingsAssessment,
            NotepadPackageProfile::InteractiveDocument,
        ] {
            let (root, assets, request) = fixture(profile);
            let result = create_with_assets(&request, &assets).unwrap();
            assert_eq!(
                result.bundle.manifest.application_sha256,
                request.analyzed_installer_sha256
            );
            assert_eq!(result.bundle.manifest.runtime, "windowsSandbox");
            let verified = aiw_runner::verify_notepad_plus_plus_msi_bundle(
                Path::new(&result.bundle.bundle_path),
                &result.bundle.manifest_sha256,
            )
            .unwrap();
            assert_eq!(verified.project.metadata.name, profile.product());
            assert!(result.evidence_root.join("package-result.json").is_file());
            assert!(!result.evidence_root.join("approval.json").exists());
            assert_eq!(
                std::fs::read(&request.installer).unwrap(),
                b"inert MSI contract fixture"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn drift_is_rejected_before_creating_any_package_or_evidence() {
        let (root, assets, mut request) = fixture(NotepadPackageProfile::LocalSettingsAssessment);
        request.analyzed_project_sha256 = "0".repeat(64);
        assert!(create_with_assets(&request, &assets).is_err());
        request.analyzed_project_sha256 = fixed_assets(&assets, request.profile)
            .unwrap()
            .1
            .project_sha256;
        std::fs::write(&request.installer, b"changed installer").unwrap();
        assert!(create_with_assets(&request, &assets).is_err());
        for parent in [&request.evidence_parent, &request.output_parent] {
            assert_eq!(std::fs::read_dir(parent).unwrap().count(), 0);
        }
        assert!(serde_json::from_str::<NotepadPackageProfile>("\"appContainer\"").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_destination_retains_intake_and_never_publishes_success() {
        let (root, assets, mut request) = fixture(NotepadPackageProfile::LocalSettingsAssessment);
        request.output_parent = root.join("missing-output-parent");
        assert!(create_with_assets(&request, &assets).is_err());
        let evidence = std::fs::read_dir(&request.evidence_parent)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(evidence.join("intake-receipt.json").is_file());
        assert!(evidence.join("package-failed.json").is_file());
        assert!(!evidence.join("package-result.json").exists());
        assert!(!request.output_parent.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repackaged_metadata_cannot_enable_network() {
        let (root, assets, request) = fixture(NotepadPackageProfile::LocalSettingsAssessment);
        let mut project: Project =
            serde_yaml::from_slice(&std::fs::read(assets.join("project.yaml")).unwrap()).unwrap();
        project.isolation_intent.network = aiw_schema::NetworkIntent::Allowed;
        let bytes = serde_yaml::to_string(&project).unwrap();
        std::fs::write(assets.join("project.yaml"), &bytes).unwrap();
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(assets.join("manifest.json")).unwrap()).unwrap();
        manifest["projectSha256"] = lowercase_sha256(bytes.as_bytes()).into();
        std::fs::write(
            assets.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(fixed_assets(&assets, request.profile).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_evidence_and_output_parent_uses_distinct_fresh_children() {
        let (root, assets, mut request) = fixture(NotepadPackageProfile::LocalSettingsAssessment);
        request.output_parent.clone_from(&request.evidence_parent);
        let result = create_with_assets(&request, &assets).unwrap();
        assert_ne!(
            result.evidence_root,
            PathBuf::from(&result.bundle.bundle_path)
        );
        assert_eq!(
            std::fs::read_dir(&request.evidence_parent).unwrap().count(),
            2
        );
        assert!(serde_json::from_str::<PackageIsolationPreset>("\"networkAllowed\"").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_import_requires_the_matching_installed_recipe_and_manifest() {
        let (root, assets, request) = fixture(NotepadPackageProfile::LocalSettingsAssessment);
        let result = create_with_assets(&request, &assets).unwrap();
        let (mut project, _) = fixed_assets(&assets, request.profile).unwrap();
        let intake = root.join("replay-intakes");
        std::fs::create_dir(&intake).unwrap();
        let imported = import_for_replay(
            Path::new(&result.bundle.bundle_path),
            &result.bundle.manifest_sha256,
            &intake,
            &project,
        )
        .unwrap();
        assert_eq!(
            imported.import_receipt.sha256,
            request.analyzed_installer_sha256
        );
        let rejected = root.join("rejected-intakes");
        std::fs::create_dir(&rejected).unwrap();
        assert!(
            import_for_replay(
                Path::new(&result.bundle.bundle_path),
                &"0".repeat(64),
                &rejected,
                &project
            )
            .is_err()
        );
        project.metadata.display_name = "different recipe".into();
        assert!(
            import_for_replay(
                Path::new(&result.bundle.bundle_path),
                &result.bundle.manifest_sha256,
                &rejected,
                &project
            )
            .is_err()
        );
        assert_eq!(std::fs::read_dir(&rejected).unwrap().count(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }
}
