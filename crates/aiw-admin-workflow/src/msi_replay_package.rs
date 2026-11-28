//! Exact data-only packages for the generic MSI workflow. No authority is exported.
use super::*;
use aiw_probe::PortableContentEntryKind;
use aiw_provider_wsb::{
    MsiReviewedEntryPoint, compile_generic_msi_install, compile_reviewed_msi_launch,
};
use aiw_windows_platform::{CreatedWorkspaceDirectory, HeldApplicationFile, HeldPortableDirectory};

const SCHEMA: &str = "aiw.dev/msi-replay-package/v0alpha1";
// Fixed 8.3 names survive ordinary Windows copies without NTFS short-name aliases.
const INSTALLER: &str = "app.msi";
const INSTALL_PROJECT: &str = "install.jsn";
const LAUNCH_PROJECT: &str = "launch.jsn";
const MANIFEST: &str = "package.jsn";
const MAX_MSI: u64 = 128 * 1024 * 1024;
const MAX_JSON: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MsiReplayManifest {
    schema_version: String,
    installer_size_bytes: u64,
    install_project_sha256: String,
    launch_project_sha256: String,
    install_scenario: String,
    launch_scenario: String,
    original_selection: MsiReviewedEntryPoint,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MsiReplayReview {
    pub package: PathBuf,
    pub manifest_sha256: String,
    pub manifest: MsiReplayManifest,
    pub approval_included: bool,
    pub application_executions: u32,
}

pub struct VerifiedMsiReplay {
    pub review: MsiReplayReview,
    install_project: Project,
    launch_project: Project,
    held: HeldPortableDirectory,
}

fn exact_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_projects(
    manifest: &MsiReplayManifest,
    install: &Project,
    launch: &Project,
) -> Result<()> {
    if manifest.schema_version != SCHEMA
        || !(1..=MAX_MSI).contains(&manifest.installer_size_bytes)
        || !exact_hex(&manifest.install_project_sha256)
        || !exact_hex(&manifest.launch_project_sha256)
    {
        bail!("MSI replay manifest is unsupported");
    }
    let source = &manifest.original_selection;
    if aiw_orchestrator::project_revision_hash(install)? != source.source_project_revision_sha256 {
        bail!("MSI install project does not match the measured source revision");
    }
    let install = compile_generic_msi_install(install, &manifest.install_scenario, 300, true)
        .map_err(|e| anyhow!("MSI replay install scenario is unsupported: {e}"))?;
    let check_id = if source.source_run_id == "msi-replay-shape" {
        "msi-replay-shape-check"
    } else {
        "msi-replay-shape"
    };
    compile_reviewed_msi_launch(launch, &manifest.launch_scenario, check_id, source)
        .map_err(|e| anyhow!("MSI replay launch scenario is unsupported: {e}"))?;
    if install.application_sha256 != source.installer_sha256 {
        bail!("MSI replay projects and source selection bind different installers");
    }
    Ok(())
}

impl VerifiedMsiReplay {
    /// Independently reopen new install-only evidence. The original selection
    /// is data for comparison, never input authority for a replay launch.
    pub fn verify_fresh_selection(
        &self,
        run_root: &Path,
        run_id: &str,
        guest_agent_sha256: &str,
    ) -> Result<MsiReviewedEntryPoint> {
        self.held.revalidate()?;
        let original = &self.review.manifest.original_selection;
        let actual = aiw_runner::verify_windows_sandbox_msi_entry_point(
            run_root,
            run_id,
            &self.install_project,
            guest_agent_sha256,
            &original.candidate.relative_path,
        )?;
        let actual = actual.selection();
        compare_fresh_selection(original, actual)?;
        compile_reviewed_msi_launch(
            &self.launch_project,
            &self.review.manifest.launch_scenario,
            if run_id == "replay-launch-shape" {
                "replay-launch-shape-check"
            } else {
                "replay-launch-shape"
            },
            actual,
        )
        .map_err(|e| anyhow!("MSI replay launch scenario is unsupported: {e}"))?;
        self.held.revalidate()?;
        Ok(actual.clone())
    }
}

fn compare_fresh_selection(
    original: &MsiReviewedEntryPoint,
    actual: &MsiReviewedEntryPoint,
) -> Result<()> {
    if actual.source_run_id == original.source_run_id
        || actual.source_receipt_sha256 == original.source_receipt_sha256
        || actual.source_evidence_root_hash == original.source_evidence_root_hash
        || actual.source_project_revision_sha256 != original.source_project_revision_sha256
        || actual.installer_sha256 != original.installer_sha256
        || actual.product_code != original.product_code
        || actual.candidate != original.candidate
    {
        bail!("fresh MSI replay evidence does not match the packaged entry point");
    }
    Ok(())
}

pub fn verify_package(path: &Path, expected_manifest_sha256: &str) -> Result<VerifiedMsiReplay> {
    if !exact_hex(expected_manifest_sha256) {
        bail!("an exact reviewed lowercase MSI replay manifest SHA-256 is required");
    }
    let held = HeldPortableDirectory::open_replay_package(path)?;
    let tree = held.manifest();
    let root = PathBuf::from(&tree.root_path);
    let [installer, install_json, launch_json, meta] =
        [INSTALLER, INSTALL_PROJECT, LAUNCH_PROJECT, MANIFEST].map(|name| {
            tree.entries.iter().find(|entry| {
                entry.relative_path == name && entry.kind == PortableContentEntryKind::File
            })
        });
    let (Some(installer), Some(install_json), Some(launch_json), Some(meta)) =
        (installer, install_json, launch_json, meta)
    else {
        bail!("MSI replay package inventory is not exact");
    };
    if tree.entries.len() != 4 || meta.sha256.as_deref() != Some(expected_manifest_sha256) {
        bail!("MSI replay package inventory or manifest hash differs");
    }
    let manifest_bytes = read_file_bounded(&root.join(MANIFEST), MAX_JSON)?;
    if digest(&manifest_bytes) != expected_manifest_sha256 {
        bail!("MSI replay manifest changed");
    }
    let manifest: MsiReplayManifest = serde_json::from_slice(&manifest_bytes)?;
    let install_bytes = read_file_bounded(&root.join(INSTALL_PROJECT), MAX_JSON)?;
    let launch_bytes = read_file_bounded(&root.join(LAUNCH_PROJECT), MAX_JSON)?;
    if installer.size_bytes != manifest.installer_size_bytes
        || installer.sha256.as_deref() != Some(&manifest.original_selection.installer_sha256)
        || install_json.sha256.as_deref() != Some(&manifest.install_project_sha256)
        || launch_json.sha256.as_deref() != Some(&manifest.launch_project_sha256)
        || digest(&install_bytes) != manifest.install_project_sha256
        || digest(&launch_bytes) != manifest.launch_project_sha256
    {
        bail!("MSI replay package payload or project differs");
    }
    let install_project = serde_json::from_slice(&install_bytes)?;
    let launch_project = serde_json::from_slice(&launch_bytes)?;
    validate_projects(&manifest, &install_project, &launch_project)?;
    held.revalidate()?;
    Ok(VerifiedMsiReplay {
        review: MsiReplayReview {
            package: root,
            manifest_sha256: expected_manifest_sha256.into(),
            manifest,
            approval_included: false,
            application_executions: 0,
        },
        install_project,
        launch_project,
        held,
    })
}

/// Reuse a verified source observation to export exact, non-authorizing bytes.
pub struct MsiReplayExport<'a> {
    pub installer: &'a Path,
    pub install_project: &'a Project,
    pub install_scenario: &'a str,
    pub launch_project: &'a Project,
    pub launch_scenario: &'a str,
    pub verified_selection: &'a aiw_runner::VerifiedWsbMsiEntryPoint,
    pub output_parent: &'a Path,
    pub package_id: &'a str,
}

pub fn export_package(input: MsiReplayExport<'_>) -> Result<MsiReplayReview> {
    let source = input.verified_selection.selection();
    let installer = HeldApplicationFile::open_bounded(input.installer, MAX_MSI)?;
    if installer.observation().sha256 != source.installer_sha256 {
        bail!("MSI bytes differ from verified source evidence");
    }
    let install_bytes = serde_json::to_vec_pretty(input.install_project)?;
    let launch_bytes = serde_json::to_vec_pretty(input.launch_project)?;
    let manifest = MsiReplayManifest {
        schema_version: SCHEMA.into(),
        installer_size_bytes: installer.observation().size_bytes,
        install_project_sha256: digest(&install_bytes),
        launch_project_sha256: digest(&launch_bytes),
        install_scenario: input.install_scenario.into(),
        launch_scenario: input.launch_scenario.into(),
        original_selection: source.clone(),
    };
    validate_projects(&manifest, input.install_project, input.launch_project)?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    if [&install_bytes, &launch_bytes, &manifest_bytes]
        .iter()
        .any(|bytes| bytes.len() as u64 > MAX_JSON)
    {
        bail!("MSI replay package metadata exceeds its bound");
    }
    let root = CreatedWorkspaceDirectory::create_protected(input.output_parent, input.package_id)?;
    let destination = root.final_path().to_path_buf();
    {
        let mut copy = root.create_file_new(INSTALLER)?;
        installer.copy_to(copy.as_file_mut())?;
        copy.as_file_mut().sync_all()?;
        installer.revalidate()?;
    }
    // Publish the manifest last so a partial copy cannot be read as a package.
    for (name, bytes) in [
        (INSTALL_PROJECT, &install_bytes),
        (LAUNCH_PROJECT, &launch_bytes),
        (MANIFEST, &manifest_bytes),
    ] {
        let mut copy = root.create_file_new(name)?;
        copy.as_file_mut().write_all(bytes)?;
        copy.as_file_mut().sync_all()?;
    }
    root.revalidate()?;
    drop(root);
    Ok(verify_package(&destination, &digest(&manifest_bytes))?.review)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_requires_new_provenance_and_preserves_all_candidate_identity() {
        let original = MsiReviewedEntryPoint {
            schema_version: aiw_provider_wsb::MSI_ENTRY_POINT_SELECTION_VERSION.into(),
            source_run_id: "original".into(),
            source_receipt_sha256: "a".repeat(64),
            source_evidence_root_hash: "b".repeat(64),
            source_project_revision_sha256: "c".repeat(64),
            installer_sha256: "d".repeat(64),
            product_code: "{3B0346D3-155D-43E5-9561-B9BE51CF2EB6}".into(),
            candidate: aiw_provider_wsb::MsiLaunchCandidate {
                component_code: "{C673C970-25AE-4659-9621-A1FE0598E9DC}".into(),
                relative_path: r"Example\Tool.exe".into(),
                size_bytes: 1024,
                sha256: "e".repeat(64),
            },
        };
        assert!(compare_fresh_selection(&original, &original).is_err());
        let mut fresh = original.clone();
        fresh.source_run_id = "replay".into();
        fresh.source_receipt_sha256 = "1".repeat(64);
        assert!(compare_fresh_selection(&original, &fresh).is_err());
        fresh.source_evidence_root_hash = "2".repeat(64);
        assert!(compare_fresh_selection(&original, &fresh).is_ok());
        let mut drift = fresh.clone();
        drift.candidate.relative_path = r"Example\tool.exe".into();
        assert!(compare_fresh_selection(&original, &drift).is_err());
        drift = fresh.clone();
        drift.candidate.sha256 = "3".repeat(64);
        assert!(compare_fresh_selection(&original, &drift).is_err());
        drift = fresh;
        drift.product_code = "{BD74EE52-17C1-484D-9593-B53377FE00A7}".into();
        assert!(compare_fresh_selection(&original, &drift).is_err());
    }
}
