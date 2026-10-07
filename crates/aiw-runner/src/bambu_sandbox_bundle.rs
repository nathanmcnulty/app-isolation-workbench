//! Closed reusable input for the existing reviewed Bambu export recipe.
#[cfg(windows)]
use crate::sandbox_bundle::{
    BundlePayloadKind, SandboxBundleError, canonical, contract_error, hash, native,
    open_bundle_files, valid_hash, write_bundle_files,
};
use crate::{SandboxBundleManifest, WsbBambuRunReport};
use aiw_probe::ApplicationFileImportReceipt;
use aiw_provider_wsb::CompiledBambuExportScenario;
use aiw_schema::Project;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::path::Path;

pub const BAMBU_BUNDLE_DATA_CONTRACT: &str = "ephemeralStandardUserStlTo3mfExport";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambuSandboxBundleVerification {
    pub manifest_sha256: String,
    pub manifest: SandboxBundleManifest,
    pub project: Project,
    pub scenario: CompiledBambuExportScenario,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambuSandboxBundleImport {
    pub verification: BambuSandboxBundleVerification,
    pub project: Project,
    pub scenario: CompiledBambuExportScenario,
    pub import_receipt: ApplicationFileImportReceipt,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BambuSandboxBundleRunReport {
    pub schema_version: String,
    pub manifest_sha256: String,
    pub manifest: SandboxBundleManifest,
    pub replay_import_receipt_sha256: String,
    pub report: WsbBambuRunReport,
}

impl BambuSandboxBundleRunReport {
    pub fn to_markdown(&self) -> String {
        format!(
            "# Bambu Sandbox bundle matched to verified run\n\nManifest SHA-256: `{}`\n\nReplay intake receipt SHA-256: `{}`\n\nSource intake receipt SHA-256: `{}`\n\nRuntime: `{}`; bundle data contract: `{}`.\n\nThe supplied bundle and full import record match this retained run's fixed STL-to-3MF recipe. This association is not independent proof of import chronology, provenance or broader isolation. Source download metadata is provenance only: metadata streams are not replayed; the bundle carries the unnamed app.exe stream.\n\n{}",
            self.manifest_sha256,
            self.replay_import_receipt_sha256,
            self.manifest.source_import_receipt_sha256,
            self.manifest.runtime,
            self.manifest.data_contract,
            crate::render_bambu_run_report_markdown(&self.report),
        )
    }
}

#[cfg(windows)]
fn compile(
    project: &Project,
    scenario_id: &str,
) -> Result<CompiledBambuExportScenario, SandboxBundleError> {
    aiw_provider_wsb::compile_bambu_studio_export_scenario(project, scenario_id)
        .map_err(|error| contract_error(error.to_string()))
}

#[cfg(windows)]
fn validate(
    manifest: &SandboxBundleManifest,
    project_bytes: &[u8],
    scenario: &CompiledBambuExportScenario,
) -> Result<(), SandboxBundleError> {
    if manifest.schema_version != crate::SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION
        || manifest.profile != scenario.profile
        || manifest.runtime != "windowsSandbox"
        || manifest.data_contract != BAMBU_BUNDLE_DATA_CONTRACT
        || manifest.scenario_id != scenario.scenario_id
        || manifest.scenario_sha256 != hash(&canonical(scenario)?)
        || manifest.project_sha256 != hash(project_bytes)
        || manifest.application_sha256 != scenario.application_sha256
        || manifest.application_size_bytes == 0
        || manifest.application_size_bytes > 512 * 1024 * 1024
        || !valid_hash(&manifest.source_import_receipt_sha256)
    {
        return Err(contract_error("Bambu semantic binding"));
    }
    Ok(())
}

#[cfg(windows)]
pub fn export_bambu_studio_bundle(
    parent: &Path,
    id: &str,
    project: &Project,
    scenario_id: &str,
    receipt: &ApplicationFileImportReceipt,
) -> Result<crate::SandboxBundleExport, SandboxBundleError> {
    let scenario = compile(project, scenario_id)?;
    let project_bytes = canonical(project)?;
    let manifest = SandboxBundleManifest {
        schema_version: crate::SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION.into(),
        profile: scenario.profile.clone(),
        runtime: "windowsSandbox".into(),
        data_contract: BAMBU_BUNDLE_DATA_CONTRACT.into(),
        scenario_id: scenario.scenario_id.clone(),
        scenario_sha256: hash(&canonical(&scenario)?),
        project_sha256: hash(&project_bytes),
        source_import_receipt_sha256: hash(&canonical(receipt)?),
        source_download_metadata_policy: receipt
            .download_metadata_archive
            .as_ref()
            .map(|archive| archive.policy.clone()),
        application_sha256: receipt.sha256.clone(),
        application_size_bytes: receipt.size_bytes,
    };
    validate(&manifest, &project_bytes, &scenario)?;
    let manifest_bytes = canonical(&manifest)?;
    let bundle_path = write_bundle_files(
        parent,
        id,
        BundlePayloadKind::BambuExe,
        receipt,
        &project_bytes,
        &manifest_bytes,
    )?;
    Ok(crate::SandboxBundleExport {
        bundle_path,
        manifest_sha256: hash(&manifest_bytes),
        manifest,
    })
}

#[cfg(windows)]
struct HeldBambuBundle {
    files: crate::sandbox_bundle::HeldBundleFiles,
    verification: BambuSandboxBundleVerification,
}

#[cfg(windows)]
fn open(dir: &Path, expected: &str) -> Result<HeldBambuBundle, SandboxBundleError> {
    let files = open_bundle_files(dir, expected, BundlePayloadKind::BambuExe)?;
    let manifest: SandboxBundleManifest = serde_json::from_slice(&files.manifest_bytes)
        .map_err(|_| contract_error("Bambu manifest JSON"))?;
    let project: Project = serde_json::from_slice(&files.project_bytes)
        .map_err(|_| contract_error("Bambu project JSON"))?;
    let scenario = compile(&project, &manifest.scenario_id)?;
    validate(&manifest, &files.project_bytes, &scenario)?;
    if files.application.observation().sha256 != manifest.application_sha256
        || files.application.observation().size_bytes != manifest.application_size_bytes
    {
        return Err(contract_error("Bambu application binding"));
    }
    files.application.revalidate().map_err(native)?;
    files.directory.revalidate().map_err(native)?;
    Ok(HeldBambuBundle {
        files,
        verification: BambuSandboxBundleVerification {
            manifest_sha256: expected.into(),
            manifest,
            project,
            scenario,
        },
    })
}

#[cfg(windows)]
pub fn verify_bambu_studio_bundle(
    dir: &Path,
    expected: &str,
) -> Result<BambuSandboxBundleVerification, SandboxBundleError> {
    let held = open(dir, expected)?;
    held.files.directory.revalidate().map_err(native)?;
    Ok(held.verification)
}

#[cfg(windows)]
pub fn import_bambu_studio_bundle(
    dir: &Path,
    parent: &Path,
    id: &str,
    expected: &str,
) -> Result<BambuSandboxBundleImport, SandboxBundleError> {
    let held = open(dir, expected)?;
    let receipt = aiw_windows_platform::import_application_file(
        parent,
        id,
        aiw_probe::ApplicationInspectionKind::Exe,
        &held.files.application,
    )
    .map_err(native)?;
    held.files.directory.revalidate().map_err(native)?;
    if receipt.sha256 != held.verification.manifest.application_sha256
        || receipt.size_bytes != held.verification.manifest.application_size_bytes
    {
        return Err(contract_error("fresh Bambu intake differs from bundle"));
    }
    Ok(BambuSandboxBundleImport {
        project: held.verification.project.clone(),
        scenario: held.verification.scenario.clone(),
        verification: held.verification,
        import_receipt: receipt,
    })
}

#[cfg(windows)]
pub fn report_bambu_studio_bundle(
    dir: &Path,
    expected: &str,
    imported: &BambuSandboxBundleImport,
    workspace: &Path,
    run_id: &str,
    guest_hash: &str,
) -> Result<BambuSandboxBundleRunReport, SandboxBundleError> {
    let held = open(dir, expected)?;
    if imported.verification != held.verification
        || imported.project != held.verification.project
        || imported.scenario != held.verification.scenario
        || imported.import_receipt.source_kind != aiw_probe::ApplicationInspectionKind::Exe
        || imported.import_receipt.sha256 != held.verification.manifest.application_sha256
        || imported.import_receipt.size_bytes != held.verification.manifest.application_size_bytes
    {
        return Err(contract_error("Bambu import record differs from bundle"));
    }
    let report = crate::bambu_report::report_windows_sandbox_bambu_run_bound(
        workspace,
        run_id,
        &imported.project,
        guest_hash,
        Some((&imported.import_receipt, &imported.scenario)),
    )
    .map_err(|error| contract_error(error.to_string()))?;
    held.files.directory.revalidate().map_err(native)?;
    Ok(BambuSandboxBundleRunReport {
        schema_version: "aiw.dev/bambu-sandbox-bundle-run-report/v0alpha1".into(),
        manifest_sha256: held.verification.manifest_sha256,
        manifest: held.verification.manifest,
        replay_import_receipt_sha256: hash(&canonical(&imported.import_receipt)?),
        report,
    })
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::sandbox_bundle::{BundlePayloadKind, open_bundle_files, write_bundle_files};

    fn project() -> Project {
        serde_json::from_str(include_str!("../../../examples/bambu-studio-export.json")).unwrap()
    }

    fn fixture_manifest(project: &Project) -> SandboxBundleManifest {
        let scenario = compile(project, "local-file-export").unwrap();
        SandboxBundleManifest {
            schema_version: crate::SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION.into(),
            profile: scenario.profile.clone(),
            runtime: "windowsSandbox".into(),
            data_contract: BAMBU_BUNDLE_DATA_CONTRACT.into(),
            scenario_id: scenario.scenario_id.clone(),
            scenario_sha256: hash(&canonical(&scenario).unwrap()),
            project_sha256: hash(&canonical(project).unwrap()),
            source_import_receipt_sha256: "0".repeat(64),
            source_download_metadata_policy: None,
            application_sha256: scenario.application_sha256,
            application_size_bytes: 3,
        }
    }

    #[test]
    fn rehashed_manifest_cannot_widen_the_bambu_contract() {
        let project = project();
        let bytes = canonical(&project).unwrap();
        let scenario = compile(&project, "local-file-export").unwrap();
        let manifest = fixture_manifest(&project);
        validate(&manifest, &bytes, &scenario).unwrap();
        for field in [
            "schemaVersion",
            "profile",
            "runtime",
            "dataContract",
            "scenarioId",
            "scenarioSha256",
            "projectSha256",
            "applicationSha256",
            "sourceImportReceiptSha256",
        ] {
            let mut value = serde_json::to_value(&manifest).unwrap();
            value[field] = serde_json::json!("unsupported");
            let changed: SandboxBundleManifest = serde_json::from_value(value).unwrap();
            assert!(
                validate(&changed, &bytes, &scenario).is_err(),
                "accepted {field}"
            );
        }
        for size in [0, 512 * 1024 * 1024 + 1] {
            let mut changed = manifest.clone();
            changed.application_size_bytes = size;
            assert!(validate(&changed, &bytes, &scenario).is_err());
        }
    }

    #[test]
    fn closed_exe_transport_preserves_custody_but_inert_bytes_are_not_a_bambu_package() {
        let root = std::env::temp_dir().join(format!(
            "aiw-bambu-bundle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("inert.exe");
        std::fs::write(&source, b"not an installer").unwrap();
        let source_held = aiw_windows_platform::HeldApplicationFile::open(&source).unwrap();
        let receipt = aiw_windows_platform::import_application_file(
            &root,
            "intake",
            aiw_probe::ApplicationInspectionKind::Exe,
            &source_held,
        )
        .unwrap();
        let project = project();
        let project_bytes = canonical(&project).unwrap();
        let manifest_bytes = canonical(&fixture_manifest(&project)).unwrap();
        // This tests transport only. The production exporter refuses this payload.
        let path = write_bundle_files(
            &root,
            "bundle",
            BundlePayloadKind::BambuExe,
            &receipt,
            &project_bytes,
            &manifest_bytes,
        )
        .unwrap();
        let dir = Path::new(&path);
        let expected = hash(&manifest_bytes);
        let held = open_bundle_files(dir, &expected, BundlePayloadKind::BambuExe).unwrap();
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(dir.join("app.exe"))
                .is_err()
        );
        held.directory.revalidate().unwrap();
        drop(held);
        assert!(verify_bambu_studio_bundle(dir, &expected).is_err());
        assert!(crate::verify_notepad_plus_plus_msi_bundle(dir, &expected).is_err());
        assert!(
            export_bambu_studio_bundle(
                &root,
                "unsupported",
                &project,
                "local-file-export",
                &receipt
            )
            .is_err()
        );
        assert!(!root.join("unsupported").exists());
        assert!(
            write_bundle_files(
                &root,
                "bundle",
                BundlePayloadKind::BambuExe,
                &receipt,
                &project_bytes,
                &manifest_bytes
            )
            .is_err()
        );
        assert!(open_bundle_files(dir, &"0".repeat(64), BundlePayloadKind::BambuExe).is_err());
        for (label, kind, size) in [
            (
                "wrong-kind",
                aiw_probe::ApplicationInspectionKind::Msi,
                receipt.size_bytes,
            ),
            ("zero-size", aiw_probe::ApplicationInspectionKind::Exe, 0),
            (
                "oversized",
                aiw_probe::ApplicationInspectionKind::Exe,
                512 * 1024 * 1024 + 1,
            ),
        ] {
            let mut rejected = receipt.clone();
            rejected.source_kind = kind;
            rejected.size_bytes = size;
            assert!(
                write_bundle_files(
                    &root,
                    label,
                    BundlePayloadKind::BambuExe,
                    &rejected,
                    &project_bytes,
                    &manifest_bytes
                )
                .is_err()
            );
            assert!(!root.join(label).exists());
        }
        std::fs::write(dir.join("extra.ps1"), b"inert extra file").unwrap();
        assert!(open_bundle_files(dir, &expected, BundlePayloadKind::BambuExe).is_err());
        std::fs::remove_file(dir.join("extra.ps1")).unwrap();
        for leaf in ["app.exe", "project.aiw", "manifest.aiw"] {
            let stream = format!("{}:Zone.Identifier", dir.join(leaf).display());
            std::fs::write(&stream, b"ZoneId=3").unwrap();
            assert!(
                open_bundle_files(dir, &expected, BundlePayloadKind::BambuExe).is_err(),
                "accepted stream on {leaf}"
            );
            std::fs::remove_file(stream).unwrap();
        }
        let app = dir.join("app.exe");
        let link = root.join("payload-link.exe");
        std::fs::hard_link(&app, &link).unwrap();
        assert!(open_bundle_files(dir, &expected, BundlePayloadKind::BambuExe).is_err());
        std::fs::remove_file(link).unwrap();
        let original = std::fs::read(&app).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&app)
            .unwrap()
            .set_len(512 * 1024 * 1024 + 1)
            .unwrap();
        assert!(open_bundle_files(dir, &expected, BundlePayloadKind::BambuExe).is_err());
        std::fs::write(&app, original).unwrap();
        open_bundle_files(dir, &expected, BundlePayloadKind::BambuExe).unwrap();
        drop(source_held);
        // Keep protected intake and bundle evidence for diagnostics; no recursive
        // cleanup across protected ownership or another trial's directories.
    }
}
