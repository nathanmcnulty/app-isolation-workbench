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
const INTAKE: &str = "installer";
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
    review: MsiReplayReview,
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
    pub fn into_review(self) -> MsiReplayReview {
        self.review
    }

    /// Prepare discovery by default, or prepare launch from a new matching install.
    pub fn prepare(
        &self,
        guest_agent: &Path,
        guest_agent_sha256: &str,
        evidence_parent: &Path,
        replay_install: Option<(&Path, &str)>,
    ) -> Result<aiw_runner::PreparedWsbArtifacts> {
        if !valid_sha256(guest_agent_sha256) {
            bail!("an independently enrolled guest agent SHA-256 is required");
        }
        self.held.revalidate()?;
        let verified_entry_point = replay_install
            .map(|(root, run_id)| self.verify_fresh_entry_point(root, run_id, guest_agent_sha256))
            .transpose()?;
        let installer =
            HeldApplicationFile::open_bounded(&self.review.package.join(INSTALLER), MAX_MSI)?;
        let manifest = &self.review.manifest;
        if installer.observation().sha256 != manifest.original_selection.installer_sha256
            || installer.observation().size_bytes != manifest.installer_size_bytes
        {
            bail!("MSI replay installer changed");
        }
        aiw_runner::preflight_windows_sandbox_guest_agent(guest_agent, guest_agent_sha256)?;
        let run_id = format!("msi-replay-{}", nonce());
        // Intake verification retains a read-only lease on its immediate
        // parent. Workspace creation needs write authority on a different one.
        let intake_parent = CreatedWorkspaceDirectory::create_protected(
            evidence_parent,
            &format!("{run_id}-inputs"),
        )?;
        let intake_parent_path = intake_parent.final_path().to_path_buf();
        drop(intake_parent);
        let retained_inputs = |recovery_state: &str, detail: String| {
            AiwError {
            code: "AIW_MSI_REPLAY_PREPARATION_INCOMPLETE".into(),
            summary: "MSI replay preparation failed after creating protected inputs".into(),
            stage: "msiReplayPreparation".into(),
            run_id: Some(run_id.clone().into()),
            retryable: false,
            remediation: "Preserve the reported paths and inspect their receipts before retrying. Do not approve or start an incomplete replay preparation.".into(),
            detail: format!(
                "Protected inputs directory: {}. Installer intake location: {}. {recovery_state} {detail}",
                intake_parent_path.display(),
                intake_parent_path.join(INTAKE).display(),
            ).into(),
        }
        };
        let intake = aiw_windows_platform::import_application_file_with_metadata(
            &intake_parent_path,
            INTAKE,
            ApplicationInspectionKind::Msi,
            &installer,
            false,
        )
        .map_err(|error| {
            retained_inputs(
                "Installer intake completion is unconfirmed. No preparation workspace was created.",
                error.to_string(),
            )
        })?;
        let (project, scenario_id) = if verified_entry_point.is_some() {
            (&self.launch_project, manifest.launch_scenario.as_str())
        } else {
            (&self.install_project, manifest.install_scenario.as_str())
        };
        let prepared = aiw_runner::prepare_windows_sandbox_msi_bundle(
            &run_id,
            project,
            guest_agent,
            guest_agent_sha256,
            evidence_parent,
            &now_rfc3339(),
            aiw_runner::WsbMsiPreparationInput {
                import_receipt: &intake,
                scenario_id,
                reviewed_entry_point: verified_entry_point.as_ref(),
                document_input: None,
                launch_profile: None,
            },
        )
        .map_err(|error| {
            let recovery_state = if matches!(error, aiw_runner::WsbPreparationError::WorkspacePreserved { .. }) {
                "Installer intake is published. The preserved preparation workspace requires inspection."
            } else {
                "Installer intake is published. No new preparation workspace was reported."
            };
            retained_inputs(recovery_state, error.to_string())
        })?;
        let workspace = Path::new(&prepared.receipt.workspace.root.final_path);
        aiw_runner::import_windows_sandbox_preparation(
            workspace,
            project,
            guest_agent_sha256,
            &now_rfc3339(),
        )
        .map_err(|error| {
            retained_inputs(
                "Installer intake and preparation are published. Pending-approval import completion is unconfirmed.",
                format!("Preparation workspace: {}. {error}", workspace.display()),
            )
        })?;
        Ok(prepared)
    }

    /// Independently reopen new install-only evidence. The original selection
    /// is data for comparison, never input authority for a replay launch.
    pub fn verify_fresh_selection(
        &self,
        run_root: &Path,
        run_id: &str,
        guest_agent_sha256: &str,
    ) -> Result<MsiReviewedEntryPoint> {
        Ok(self
            .verify_fresh_entry_point(run_root, run_id, guest_agent_sha256)?
            .selection()
            .clone())
    }

    fn verify_fresh_entry_point(
        &self,
        run_root: &Path,
        run_id: &str,
        guest_agent_sha256: &str,
    ) -> Result<aiw_runner::VerifiedWsbMsiEntryPoint> {
        self.held.revalidate()?;
        let original = &self.review.manifest.original_selection;
        let verified = aiw_runner::verify_windows_sandbox_msi_entry_point(
            run_root,
            run_id,
            &self.install_project,
            guest_agent_sha256,
            &original.candidate.relative_path,
        )?;
        let actual = verified.selection();
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
        Ok(verified)
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
        return Err(AiwError {
            code: "AIW_MSI_REPLAY_ENTRY_POINT_MISMATCH".into(),
            summary: "fresh MSI replay evidence does not match the packaged entry point".into(),
            stage: "msiReplayComparison".into(),
            run_id: Some(actual.source_run_id.clone().into()),
            retryable: false,
            remediation: "Review the packaged entry point and the new install-only report before preparing a launch.".into(),
            detail: "The replay launch was not prepared.".into(),
        }
        .into());
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
    use aiw_schema::ScenarioStep;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn selection() -> MsiReviewedEntryPoint {
        MsiReviewedEntryPoint {
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
        }
    }

    #[test]
    fn replay_requires_new_provenance_and_preserves_all_candidate_identity() {
        let original = selection();
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
        let error = compare_fresh_selection(&original, &drift)
            .unwrap_err()
            .downcast::<AiwError>()
            .unwrap();
        assert_eq!(&*error.code, "AIW_MSI_REPLAY_ENTRY_POINT_MISMATCH");
        drift = fresh.clone();
        drift.candidate.size_bytes += 1;
        assert!(compare_fresh_selection(&original, &drift).is_err());
        drift = fresh.clone();
        drift.candidate.component_code = "{BD74EE52-17C1-484D-9593-B53377FE00A7}".into();
        assert!(compare_fresh_selection(&original, &drift).is_err());
        drift = fresh;
        drift.product_code = "{BD74EE52-17C1-484D-9593-B53377FE00A7}".into();
        assert!(compare_fresh_selection(&original, &drift).is_err());
    }

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "aiw-msi-test-{}-{}-{}",
                std::process::id(),
                nonce(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&root).unwrap();
            Self(root.canonicalize().unwrap())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let result = std::fs::remove_dir_all(&self.0);
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }

    fn write_package(package: &Path) -> String {
        std::fs::create_dir(package).unwrap();
        let installer = b"inert fixture bytes";
        let mut original_selection = selection();
        original_selection.installer_sha256 = digest(installer);
        let sample = include_str!("../../../examples/notepad-plus-plus-msi.aiw.yaml");
        let mut launch: Project = serde_yaml::from_str(sample).unwrap();
        let ApplicationSource::Msi(application) = &mut launch.application else {
            panic!("expected an MSI project fixture");
        };
        application
            .sha256
            .clone_from(&original_selection.installer_sha256);
        application.entry_points[0]
            .path
            .clone_from(&original_selection.candidate.relative_path);
        let ScenarioStep::WaitForProcess { image, .. } = &mut launch.scenarios[0].steps[2] else {
            panic!("expected a window readiness step");
        };
        *image = "Tool.exe".into();
        let mut install = launch.clone();
        install.scenarios[0].steps.truncate(1);
        original_selection.source_project_revision_sha256 =
            aiw_orchestrator::project_revision_hash(&install).unwrap();
        let install_bytes = serde_json::to_vec(&install).unwrap();
        let launch_bytes = serde_json::to_vec(&launch).unwrap();
        let manifest = serde_json::to_vec(&MsiReplayManifest {
            schema_version: SCHEMA.into(),
            installer_size_bytes: installer.len() as u64,
            install_project_sha256: digest(&install_bytes),
            launch_project_sha256: digest(&launch_bytes),
            install_scenario: install.scenarios[0].id.clone(),
            launch_scenario: launch.scenarios[0].id.clone(),
            original_selection,
        })
        .unwrap();
        for (name, bytes) in [
            (INSTALLER, installer.as_slice()),
            (INSTALL_PROJECT, &install_bytes),
            (LAUNCH_PROJECT, &launch_bytes),
            (MANIFEST, &manifest),
        ] {
            std::fs::write(package.join(name), bytes).unwrap();
        }
        digest(&manifest)
    }

    #[test]
    fn package_review_rejects_a_wrong_pin_and_changed_payloads() {
        let root = Fixture::new();
        let package = root.0.join("package");
        let pin = write_package(&package);
        assert!(verify_package(&package, &"0".repeat(64)).is_err());
        let verified = verify_package(&package, &pin).unwrap();
        assert_eq!(verified.review.manifest_sha256, pin);
        drop(verified);

        for name in [INSTALLER, INSTALL_PROJECT, LAUNCH_PROJECT, MANIFEST] {
            let path = package.join(name);
            let original = std::fs::read(&path).unwrap();
            let mut changed = original.clone();
            changed[0] ^= 1;
            std::fs::write(&path, changed).unwrap();
            assert!(verify_package(&package, &pin).is_err(), "{name}");
            std::fs::write(&path, original).unwrap();
        }
    }

    #[test]
    fn replay_wrong_guest_agent_pin_does_not_publish_intake() {
        let root = Fixture::new();
        let package = root.0.join("package");
        let verified = verify_package(&package, &write_package(&package)).unwrap();
        let guest_agent = root.0.join("agent.exe");
        std::fs::write(&guest_agent, b"inert guest-agent fixture").unwrap();
        let evidence = root.0.join("evidence");
        std::fs::create_dir(&evidence).unwrap();

        for _ in 0..2 {
            let error = verified
                .prepare(&guest_agent, &"0".repeat(64), &evidence, None)
                .unwrap_err();
            assert!(matches!(
                error.downcast_ref::<aiw_runner::WsbPreparationError>(),
                Some(aiw_runner::WsbPreparationError::GuestAgent(detail))
                    if detail.contains("does not match the expected guest-agent identity")
            ));
            assert!(evidence.read_dir().unwrap().next().is_none());
        }
    }

    #[test]
    fn replay_reports_published_intake_when_planning_fails() {
        let root = Fixture::new();
        let package = root.0.join("package");
        let mut verified = verify_package(&package, &write_package(&package)).unwrap();
        // Force the runner's planning validator to fail before inspecting Sandbox readiness.
        verified.install_project.metadata.id.clear();
        let guest_agent = root.0.join("agent.exe");
        let agent_bytes = b"inert guest-agent fixture";
        std::fs::write(&guest_agent, agent_bytes).unwrap();
        let evidence = root.0.join("evidence");
        std::fs::create_dir(&evidence).unwrap();

        let error = verified
            .prepare(&guest_agent, &digest(agent_bytes), &evidence, None)
            .unwrap_err()
            .downcast::<AiwError>()
            .unwrap();
        assert_eq!(&*error.code, "AIW_MSI_REPLAY_PREPARATION_INCOMPLETE");
        assert!(!error.retryable);
        let run_id = error.run_id.as_deref().unwrap();
        let inputs = evidence.join(format!("{run_id}-inputs"));
        let intake = inputs.join(INTAKE).canonicalize().unwrap();
        assert!(intake.join("intake.json").is_file());
        let intake = intake.to_str().unwrap().trim_start_matches(r"\\?\");
        assert!(error.detail.contains(intake));
        assert!(error.detail.contains("Installer intake is published"));
        assert!(error.detail.contains("project is not valid for planning"));
        assert!(
            error
                .detail
                .contains("No new preparation workspace was reported")
        );
        assert_eq!(evidence.read_dir().unwrap().count(), 1);
    }
}
