//! Installer analysis and assembly are separate from compatibility and execution.
use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SandboxPackageProfile {
    LocalSettingsAssessment,
    InteractiveDocument,
    BambuStudioExport,
}

/// Only the existing fixed offline Sandbox policy can be selected. Device,
/// resource and exact mapping disclosures are resolved in the replay recipe.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PackageIsolationPreset {
    OfflineWindowsSandbox,
}

impl SandboxPackageProfile {
    fn directory(self) -> &'static str {
        match self {
            Self::LocalSettingsAssessment => "notepad-plus-plus",
            Self::InteractiveDocument => "notepad-plus-plus-interactive",
            Self::BambuStudioExport => "bambu-studio",
        }
    }
    fn product(self) -> &'static str {
        match self {
            Self::LocalSettingsAssessment => PRODUCT_ID,
            Self::InteractiveDocument => INTERACTIVE_PRODUCT_ID,
            Self::BambuStudioExport => BAMBU_PRODUCT_ID,
        }
    }
    fn scenario(self) -> &'static str {
        if self == Self::BambuStudioExport {
            BAMBU_SCENARIO_ID
        } else {
            SCENARIO_ID
        }
    }
    fn source_kind(self) -> ApplicationInspectionKind {
        if self == Self::BambuStudioExport {
            ApplicationInspectionKind::Exe
        } else {
            ApplicationInspectionKind::Msi
        }
    }
    fn intake_id(self) -> &'static str {
        if self == Self::BambuStudioExport {
            "bambu-studio"
        } else {
            "notepad-plus-plus"
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxPackageOption {
    pub profile: SandboxPackageProfile,
    pub project_sha256: String,
    pub isolation_preset: PackageIsolationPreset,
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxPackageAnalysis {
    pub schema_version: String,
    pub installer: aiw_probe::ApplicationInspection,
    pub options: Vec<SandboxPackageOption>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxPackageRequest {
    pub installer: PathBuf,
    pub profile: SandboxPackageProfile,
    pub isolation_preset: PackageIsolationPreset,
    pub analyzed_installer_sha256: String,
    pub analyzed_project_sha256: String,
    pub evidence_parent: PathBuf,
    pub output_parent: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxPackageResult {
    pub schema_version: String,
    pub profile: SandboxPackageProfile,
    pub isolation_preset: PackageIsolationPreset,
    pub evidence_root: PathBuf,
    pub bundle: aiw_runner::SandboxBundleExport,
    pub next: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum NotepadPackageProfile {
    LocalSettingsAssessment,
    InteractiveDocument,
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

impl From<NotepadPackageProfile> for SandboxPackageProfile {
    fn from(profile: NotepadPackageProfile) -> Self {
        match profile {
            NotepadPackageProfile::LocalSettingsAssessment => Self::LocalSettingsAssessment,
            NotepadPackageProfile::InteractiveDocument => Self::InteractiveDocument,
        }
    }
}

#[cfg(windows)]
fn notepad_profile(profile: SandboxPackageProfile) -> Result<NotepadPackageProfile> {
    match profile {
        SandboxPackageProfile::LocalSettingsAssessment => {
            Ok(NotepadPackageProfile::LocalSettingsAssessment)
        }
        SandboxPackageProfile::InteractiveDocument => {
            Ok(NotepadPackageProfile::InteractiveDocument)
        }
        SandboxPackageProfile::BambuStudioExport => bail!("Bambu is not a Notepad package profile"),
    }
}

/// Preserve the two-profile v0alpha1 Notepad analysis contract.
#[cfg(windows)]
pub fn analyze_notepad_installer(installer: &Path) -> Result<PackageAnalysis> {
    let analysis = analyze_notepad_sandbox_installer(installer)?;
    let options = analysis
        .options
        .into_iter()
        .map(|option| {
            Ok(PackageOption {
                profile: notepad_profile(option.profile)?,
                project_sha256: option.project_sha256,
                isolation_preset: option.isolation_preset,
                description: option.description,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PackageAnalysis {
        schema_version: "aiw.dev/admin-package-analysis/v0alpha1".into(),
        installer: analysis.installer,
        options,
        limitations: analysis.limitations,
    })
}

/// Preserve the two-profile v0alpha1 Notepad assembly contract.
#[cfg(windows)]
pub fn create_notepad_package(request: &NotepadPackageRequest) -> Result<PackageResult> {
    create_notepad_with_assets(
        request,
        &packaged_asset_root(SandboxPackageProfile::from(request.profile).directory())?,
    )
}

#[cfg(windows)]
fn create_notepad_with_assets(
    request: &NotepadPackageRequest,
    assets_root: &Path,
) -> Result<PackageResult> {
    let request = SandboxPackageRequest {
        installer: request.installer.clone(),
        profile: request.profile.into(),
        isolation_preset: request.isolation_preset,
        analyzed_installer_sha256: request.analyzed_installer_sha256.clone(),
        analyzed_project_sha256: request.analyzed_project_sha256.clone(),
        evidence_parent: request.evidence_parent.clone(),
        output_parent: request.output_parent.clone(),
    };
    let result = assemble_with_assets(&request, assets_root, |result| {
        save_stage(
            &result.evidence_root,
            "package-result",
            &legacy_package_result(result)?,
        )
    })?;
    legacy_package_result(&result)
}

#[cfg(windows)]
fn legacy_package_result(result: &SandboxPackageResult) -> Result<PackageResult> {
    Ok(PackageResult {
        schema_version: "aiw.dev/admin-package-result/v0alpha1".into(),
        profile: notepad_profile(result.profile)?,
        isolation_preset: result.isolation_preset,
        evidence_root: result.evidence_root.clone(),
        bundle: result.bundle.clone(),
        next: result.next.clone(),
    })
}

#[cfg(any(windows, test))]
fn fixed_assets(
    root: &Path,
    profile: SandboxPackageProfile,
) -> Result<(Project, ProductAssetManifest)> {
    let manifest: ProductAssetManifest = serde_json::from_slice(&read_file_bounded(
        &root.join("manifest.json"),
        1024 * 1024,
    )?)?;
    let assets = match profile {
        SandboxPackageProfile::LocalSettingsAssessment => manifest.resolve(root)?,
        SandboxPackageProfile::InteractiveDocument => manifest.resolve_interactive(root)?,
        SandboxPackageProfile::BambuStudioExport => manifest.resolve_bambu(root)?,
    };
    let bytes = read_file_bounded(&assets.project, MAX_CONFIG_BYTES)?;
    if lowercase_sha256(&bytes) != manifest.project_sha256 {
        bail!("packaged project changed; analyze the installer again with intact product assets");
    }
    let project: Project = serde_yaml::from_slice(&bytes)?;
    if project.metadata.name != profile.product()
        || !validate_project_for_planning(&project).is_empty()
    {
        bail!("packaged project is not the selected application recipe");
    }
    // Reuse the executor's fixed compiler; package metadata cannot add grants.
    if profile == SandboxPackageProfile::BambuStudioExport {
        aiw_provider_wsb::compile_bambu_studio_export_scenario(&project, BAMBU_SCENARIO_ID)
            .map_err(|error| anyhow!("unsupported package recipe: {error}"))?;
    } else {
        aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario(&project, SCENARIO_ID)
            .map_err(|error| anyhow!("unsupported package recipe: {error}"))?;
    }
    Ok((project, manifest))
}

#[cfg(any(windows, test))]
fn supported_hash(project: &Project) -> Result<&str> {
    match &project.application {
        ApplicationSource::Msi(source) => Ok(&source.sha256),
        ApplicationSource::Exe(source) => Ok(&source.sha256),
        _ => bail!("the selected recipe requires an MSI or EXE"),
    }
}

/// Read-only identity observation. No intake, provider lease or worker is created.
/// The result is advisory; assembly reopens and revalidates installer and assets.
#[cfg(windows)]
pub fn analyze_notepad_sandbox_installer(installer: &Path) -> Result<SandboxPackageAnalysis> {
    analyze_installer(
        installer,
        &[
            SandboxPackageProfile::LocalSettingsAssessment,
            SandboxPackageProfile::InteractiveDocument,
        ],
        ApplicationInspectionKind::Msi,
    )
}

#[cfg(windows)]
pub fn analyze_bambu_installer(installer: &Path) -> Result<SandboxPackageAnalysis> {
    analyze_installer(
        installer,
        &[SandboxPackageProfile::BambuStudioExport],
        ApplicationInspectionKind::Exe,
    )
}

#[cfg(windows)]
fn analyze_installer(
    installer: &Path,
    profiles: &[SandboxPackageProfile],
    kind: ApplicationInspectionKind,
) -> Result<SandboxPackageAnalysis> {
    let held = aiw_windows_platform::HeldApplicationFile::open_with_download_metadata(installer)?;
    let inspection = installer_inspection::inspect_held_installer(&held, kind)?;
    let mut options = Vec::new();
    for &profile in profiles {
        let (project, manifest) =
            fixed_assets(&packaged_asset_root(profile.directory())?, profile)?;
        if inspection.sha256.as_deref() == Some(supported_hash(&project)?) {
            options.push(SandboxPackageOption {
                profile,
                project_sha256: manifest.project_sha256,
                isolation_preset: PackageIsolationPreset::OfflineWindowsSandbox,
                description: match profile {
                    SandboxPackageProfile::LocalSettingsAssessment => "Fixed assessment with ephemeral local settings; no user document is included.",
                    SandboxPackageProfile::InteractiveDocument => "Interactive document workflow; a bounded text input is selected and approved separately at launch, with explicit verified export.",
                    SandboxPackageProfile::BambuStudioExport => "Fixed standard-user STL-to-3MF export using the reviewed fixture; no slicing, printing or cloud access is tested.",
                }.into(),
            });
        }
    }
    held.revalidate()?;
    Ok(SandboxPackageAnalysis {
        schema_version: "aiw.dev/admin-package-analysis/v0alpha2".into(),
        installer: inspection,
        options,
        limitations: vec![
            "Only the exact supported installer and selected fixed recipes can be packaged. Other isolation modes and custom grants are unavailable.".into(),
            "Windows Sandbox settings request blocked network and disabled clipboard. Fixed guest-tool and output mappings remain part of the recipe; requested settings are not measured isolation.".into(),
            "Exact runtime mappings, devices, protected-client and resource settings are resolved and disclosed in the fresh replay recipe before approval; packaging does not enable arbitrary settings.".into(),
            "Analysis does not install the application or establish compatibility. The bundle needs a verified Workbench guest/runtime and fresh plan approval and Start before replay.".into(),
        ],
    })
}

/// Assemble and verify a reusable bundle through protected intake. Never executes
/// an installer, approves a plan, starts Sandbox, or overwrites an existing bundle.
#[cfg(windows)]
pub fn create_sandbox_package(request: &SandboxPackageRequest) -> Result<SandboxPackageResult> {
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
pub(crate) fn import_bambu_for_replay(
    bundle: &Path,
    manifest_sha256: &str,
    intake_parent: &Path,
    expected_project: &Project,
) -> Result<aiw_runner::BambuSandboxBundleImport> {
    let verified = aiw_runner::verify_bambu_studio_bundle(bundle, manifest_sha256)?;
    if &verified.project != expected_project {
        bail!(
            "Bambu package recipe differs from installed workflow; preserve it and rebuild with current product assets"
        );
    }
    let expected_scenario = aiw_provider_wsb::compile_bambu_studio_export_scenario(
        expected_project,
        BAMBU_SCENARIO_ID,
    )?;
    if verified.scenario != expected_scenario {
        bail!("Bambu package scenario differs from installed workflow");
    }
    let imported = aiw_runner::import_bambu_studio_bundle(
        bundle,
        intake_parent,
        "bambu-studio",
        manifest_sha256,
    )?;
    if &imported.project != expected_project || imported.scenario != expected_scenario {
        bail!(
            "Bambu package recipe changed during import; preserve the intake and use fresh evidence"
        );
    }
    Ok(imported)
}

#[cfg(windows)]
fn create_with_assets(
    request: &SandboxPackageRequest,
    assets_root: &Path,
) -> Result<SandboxPackageResult> {
    assemble_with_assets(request, assets_root, |result| {
        save_stage(&result.evidence_root, "package-result", result)
    })
}

#[cfg(windows)]
fn assemble_with_assets(
    request: &SandboxPackageRequest,
    assets_root: &Path,
    publish: impl FnOnce(&SandboxPackageResult) -> Result<()>,
) -> Result<SandboxPackageResult> {
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
    let assembled = (|| -> Result<SandboxPackageResult> {
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
            request.profile.intake_id(),
            request.profile.source_kind(),
            &held,
            true,
        )?;
        save_stage(&evidence_root, "intake-receipt", &receipt)?;
        let export = if request.profile == SandboxPackageProfile::BambuStudioExport {
            aiw_runner::export_bambu_studio_bundle
        } else {
            aiw_runner::export_notepad_plus_plus_msi_bundle
        };
        let bundle = export(
            &request.output_parent,
            &format!("bundle-{id}"),
            &project,
            request.profile.scenario(),
            &receipt,
        )?;
        if request.profile == SandboxPackageProfile::BambuStudioExport {
            aiw_runner::verify_bambu_studio_bundle(
                Path::new(&bundle.bundle_path),
                &bundle.manifest_sha256,
            )?;
        } else {
            aiw_runner::verify_notepad_plus_plus_msi_bundle(
                Path::new(&bundle.bundle_path),
                &bundle.manifest_sha256,
            )?;
        }
        let result = SandboxPackageResult {
        schema_version: "aiw.dev/admin-package-result/v0alpha2".into(),
        profile: request.profile,
        isolation_preset: request.isolation_preset,
        evidence_root: evidence_root.clone(),
        bundle,
        next: "Package assembled and verified, not compatibility-certified. Preserve the manifest hash and evidence. Import through Workbench for fresh recipe review, approval, Start and disposable-worker validation. Preserve incomplete output on failure; retry in fresh locations.".into(),
    };
        publish(&result)?;
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

    #[test]
    fn legacy_notepad_profile_remains_closed_to_two_variants() {
        for (wire, expected) in [
            (
                "localSettingsAssessment",
                NotepadPackageProfile::LocalSettingsAssessment,
            ),
            (
                "interactiveDocument",
                NotepadPackageProfile::InteractiveDocument,
            ),
        ] {
            assert_eq!(
                serde_json::from_value::<NotepadPackageProfile>(serde_json::json!(wire)).unwrap(),
                expected
            );
        }
        assert!(
            serde_json::from_value::<NotepadPackageProfile>(serde_json::json!("bambuStudioExport"))
                .is_err()
        );
        let value = serde_json::json!({"installer":"inert.exe", "profile":"bambuStudioExport",
            "isolationPreset":"offlineWindowsSandbox", "analyzedInstallerSha256":"0".repeat(64),
            "analyzedProjectSha256":"0".repeat(64), "evidenceParent":"evidence", "outputParent":"output"});
        assert!(serde_json::from_value::<NotepadPackageRequest>(value.clone()).is_err());
        assert!(serde_json::from_value::<SandboxPackageRequest>(value).is_ok());
    }

    #[test]
    fn bambu_installer_and_recipe_drift_reject_before_intake() {
        let (root, assets, mut request) = fixture(SandboxPackageProfile::LocalSettingsAssessment);
        let mut project: Project = serde_json::from_slice(include_bytes!(
            "../../aiw-cli/product/bambu-studio/project.json"
        ))
        .unwrap();
        let installer = root.join("inert.exe");
        std::fs::write(&installer, b"inert EXE, never executed").unwrap();
        request.installer = installer;
        request.profile = SandboxPackageProfile::BambuStudioExport;
        request.analyzed_installer_sha256 =
            aiw_provider_wsb::BAMBU_STUDIO_APPLICATION_SHA256.into();
        let publish_assets = |project: &Project| -> String {
            let bytes = serde_json::to_vec(project).unwrap();
            let project_hash = lowercase_sha256(&bytes);
            std::fs::write(assets.join("project.json"), bytes).unwrap();
            std::fs::write(assets.join("manifest.json"), serde_json::to_vec(&serde_json::json!({
                "schemaVersion": MANIFEST_SCHEMA, "productId": BAMBU_PRODUCT_ID, "scenarioId": BAMBU_SCENARIO_ID,
                "projectPath": "project.json", "projectSha256": project_hash,
                "guestAgentPath": "tools/agent.exe", "guestAgentSha256": lowercase_sha256(b"inert agent"),
            })).unwrap()).unwrap();
            project_hash
        };
        request.analyzed_project_sha256 = publish_assets(&project);
        assert!(
            create_with_assets(&request, &assets)
                .unwrap_err()
                .to_string()
                .contains("installer changed since analysis")
        );
        request.analyzed_installer_sha256 = lowercase_sha256(b"inert EXE, never executed");
        assert!(
            create_with_assets(&request, &assets)
                .unwrap_err()
                .to_string()
                .contains("differs from analysis")
        );
        request.analyzed_installer_sha256 =
            aiw_provider_wsb::BAMBU_STUDIO_APPLICATION_SHA256.into();
        let ApplicationSource::Exe(application) = &mut project.application else {
            panic!("EXE fixture")
        };
        application.silent_arguments.push("/caller-option".into());
        request.analyzed_project_sha256 = publish_assets(&project);
        assert!(
            create_with_assets(&request, &assets)
                .unwrap_err()
                .to_string()
                .contains("unsupported package recipe")
        );
        assert_eq!(
            std::fs::read_dir(&request.evidence_parent).unwrap().count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(&request.output_parent).unwrap().count(),
            0
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    fn fixture(profile: SandboxPackageProfile) -> (PathBuf, PathBuf, SandboxPackageRequest) {
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
            SandboxPackageProfile::LocalSettingsAssessment => {
                include_bytes!("../../aiw-cli/product/notepad-plus-plus/project.yaml")
            }
            SandboxPackageProfile::InteractiveDocument => {
                include_bytes!("../../aiw-cli/product/notepad-plus-plus-interactive/project.yaml")
            }
            SandboxPackageProfile::BambuStudioExport => panic!("Notepad fixture only"),
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
        let request = SandboxPackageRequest {
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
    fn legacy_assembly_returns_and_retains_the_same_v1_result() {
        for profile in [
            SandboxPackageProfile::LocalSettingsAssessment,
            SandboxPackageProfile::InteractiveDocument,
        ] {
            let (root, assets, request) = fixture(profile);
            let legacy = NotepadPackageRequest {
                installer: request.installer,
                profile: notepad_profile(profile).unwrap(),
                isolation_preset: request.isolation_preset,
                analyzed_installer_sha256: request.analyzed_installer_sha256,
                analyzed_project_sha256: request.analyzed_project_sha256,
                evidence_parent: request.evidence_parent,
                output_parent: request.output_parent,
            };
            let result = create_notepad_with_assets(&legacy, &assets).unwrap();
            let retained: serde_json::Value = serde_json::from_slice(
                &std::fs::read(result.evidence_root.join("package-result.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(retained, serde_json::to_value(&result).unwrap());
            assert_eq!(
                retained["schemaVersion"],
                "aiw.dev/admin-package-result/v0alpha1"
            );
            assert_eq!(
                serde_json::from_value::<NotepadPackageProfile>(retained["profile"].clone())
                    .unwrap(),
                legacy.profile
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn assembly_preserves_selected_recipe_and_retains_verified_result() {
        for profile in [
            SandboxPackageProfile::LocalSettingsAssessment,
            SandboxPackageProfile::InteractiveDocument,
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
        let (root, assets, mut request) = fixture(SandboxPackageProfile::LocalSettingsAssessment);
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
        assert!(serde_json::from_str::<SandboxPackageProfile>("\"appContainer\"").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_destination_retains_intake_and_never_publishes_success() {
        let (root, assets, mut request) = fixture(SandboxPackageProfile::LocalSettingsAssessment);
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
        let (root, assets, request) = fixture(SandboxPackageProfile::LocalSettingsAssessment);
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
        let (root, assets, mut request) = fixture(SandboxPackageProfile::LocalSettingsAssessment);
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
        let (root, assets, request) = fixture(SandboxPackageProfile::LocalSettingsAssessment);
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
