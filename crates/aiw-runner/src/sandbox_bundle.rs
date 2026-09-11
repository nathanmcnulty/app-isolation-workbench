#[cfg(windows)]
use aiw_evidence::canonical_json_bytes;
#[cfg(windows)]
use aiw_probe::ApplicationInspectionKind;
use aiw_probe::{ApplicationFileImportReceipt, DownloadMetadataPolicy};
use aiw_provider_wsb::CompiledMsiScenario;
#[cfg(windows)]
use aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario;
use aiw_schema::Project;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::{fs, path::Path};
use thiserror::Error;
#[cfg(windows)] use crate::{WsbMsiRunReport, assessment_report::report_windows_sandbox_msi_run_bound};
pub const SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION: &str =
    "aiw.dev/sandbox-application-bundle/v0alpha1";
#[cfg(windows)]
const PROFILE: &str = "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha6";
// 8.3-compatible leaves avoid secondary DOS aliases when recipients copy files.
#[cfg(windows)]
const MANIFEST_FILE: &str = "manifest.aiw";
#[cfg(windows)]
const APPLICATION_FILE: &str = "app.msi";
#[cfg(windows)]
const PROJECT_FILE: &str = "project.aiw";
#[derive(Debug, Error)]
pub enum SandboxBundleError {
    #[error("bundle: {0}")]
    Contract(String),
    #[error("bundle I/O: {0}")]
    Io(String),
    #[cfg(windows)]
    #[error("bundle native: {0}")]
    Native(String),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxBundleManifest {
    pub schema_version: String,
    pub profile: String,
    pub runtime: String,
    pub data_contract: String,
    pub scenario_id: String,
    pub scenario_sha256: String,
    pub project_sha256: String,
    pub source_import_receipt_sha256: String,
    pub source_download_metadata_policy: Option<DownloadMetadataPolicy>,
    pub application_sha256: String,
    pub application_size_bytes: u64,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxBundleExport {
    pub bundle_path: String,
    pub manifest_sha256: String,
    pub manifest: SandboxBundleManifest,
}
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxBundleVerification {
    pub manifest_sha256: String,
    pub manifest: SandboxBundleManifest,
    pub project: Project,
    pub scenario: CompiledMsiScenario,
}
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxBundleImport {
    pub verification: SandboxBundleVerification,
    pub project: Project,
    pub scenario: CompiledMsiScenario,
    pub import_receipt: ApplicationFileImportReceipt,
}
#[cfg(windows)]
pub fn export_notepad_plus_plus_msi_bundle(
    parent: &Path,
    id: &str,
    project: &Project,
    scenario_id: &str,
    receipt: &ApplicationFileImportReceipt,
) -> Result<SandboxBundleExport, SandboxBundleError> {
    use aiw_windows_platform::{CreatedWorkspaceDirectory, open_verified_application_file_import};
    let scenario = compile(project, scenario_id)?;
    let project_bytes = canonical(project)?;
    if project_bytes.len() > 524288 {
        return Err(contract_error("project exceeds bundle bound"));
    }
    let manifest = make_manifest(&project_bytes, receipt, &scenario)?;
    let manifest_bytes = canonical(&manifest)?;
    if receipt.source_kind != ApplicationInspectionKind::Msi {
        return Err(contract_error("MSI intake required"));
    }
    let root = CreatedWorkspaceDirectory::create_protected(parent, id).map_err(native)?;
    // Create the destination before the verified intake locks its parent against
    // writes. Retain source authority for the entire copy and publish manifest last.
    let mut held = open_verified_application_file_import(receipt).map_err(native)?;
    let app = root.create_file_new(APPLICATION_FILE).map_err(native)?;
    held.copy_to(app).map_err(native)?;
    write(&root, PROJECT_FILE, &project_bytes)?;
    write(&root, MANIFEST_FILE, &manifest_bytes)?;
    held.revalidate().map_err(native)?;
    Ok(SandboxBundleExport {
        bundle_path: root.final_path().display().to_string(),
        manifest_sha256: hash(&manifest_bytes),
        manifest,
    })
}
#[cfg(windows)]
pub fn verify_notepad_plus_plus_msi_bundle(
    dir: &Path,
    expected: &str,
) -> Result<SandboxBundleVerification, SandboxBundleError> {
    let held = open_bundle(dir, expected)?;
    held.directory.revalidate().map_err(native)?;
    Ok(held.verification)
}

#[cfg(windows)]
struct HeldBundle {
    directory: aiw_windows_platform::HeldPortableDirectory,
    application: aiw_windows_platform::HeldApplicationFile,
    verification: SandboxBundleVerification,
}

#[cfg(windows)]
fn open_bundle(dir: &Path, expected: &str) -> Result<HeldBundle, SandboxBundleError> {
    use aiw_windows_platform::{HeldApplicationFile, HeldPortableDirectory};
    if !valid_hash(expected) {
        return Err(contract_error(
            "expected manifest hash must be lowercase SHA-256",
        ));
    }
    inventory(dir)?;
    for (leaf, limit) in [
        (MANIFEST_FILE, 65536),
        (PROJECT_FILE, 524288),
        (APPLICATION_FILE, 128 * 1024 * 1024),
    ] {
        let metadata = fs::symlink_metadata(dir.join(leaf))
            .map_err(|e| SandboxBundleError::Io(e.to_string()))?;
        if !metadata.is_file() || metadata.len() > limit {
            return Err(contract_error("bundle file exceeds profile bound"));
        }
    }
    let directory = HeldPortableDirectory::open(dir).map_err(native)?;
    let manifest_file = HeldApplicationFile::open(&dir.join(MANIFEST_FILE)).map_err(native)?;
    let project_file = HeldApplicationFile::open(&dir.join(PROJECT_FILE)).map_err(native)?;
    let application_file =
        HeldApplicationFile::open(&dir.join(APPLICATION_FILE)).map_err(native)?;
    let manifest_bytes = read(&dir.join(MANIFEST_FILE), 65536)?;
    if hash(&manifest_bytes) != expected
        || hash(&manifest_bytes) != manifest_file.observation().sha256
    {
        return Err(contract_error("manifest hash"));
    }
    let manifest: SandboxBundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| contract_error("manifest JSON"))?;
    let project_bytes = read(&dir.join(PROJECT_FILE), 524288)?;
    if hash(&project_bytes) != project_file.observation().sha256 {
        return Err(contract_error("project drift"));
    }
    let project: Project =
        serde_json::from_slice(&project_bytes).map_err(|_| contract_error("project JSON"))?;
    let scenario = compile(&project, &manifest.scenario_id)?;
    validate(&manifest, &project_bytes, &scenario)?;
    if application_file.observation().sha256 != manifest.application_sha256
        || application_file.observation().size_bytes != manifest.application_size_bytes
    {
        return Err(contract_error("application binding"));
    }
    manifest_file.revalidate().map_err(native)?;
    project_file.revalidate().map_err(native)?;
    application_file.revalidate().map_err(native)?;
    directory.revalidate().map_err(native)?;
    inventory(dir)?;
    Ok(HeldBundle {
        directory,
        application: application_file,
        verification: SandboxBundleVerification {
            manifest_sha256: expected.into(),
            manifest,
            project,
            scenario,
        },
    })
}
#[cfg(windows)]
pub fn import_notepad_plus_plus_msi_bundle(
    dir: &Path,
    parent: &Path,
    id: &str,
    expected: &str,
) -> Result<SandboxBundleImport, SandboxBundleError> {
    use aiw_windows_platform::import_application_file;
    // Keep every verified bundle object held across the protected import.
    let held = open_bundle(dir, expected)?;
    let import_receipt = import_application_file(
        parent,
        id,
        ApplicationInspectionKind::Msi,
        &held.application,
    )
    .map_err(native)?;
    held.directory.revalidate().map_err(native)?;
    let verification = held.verification;
    if import_receipt.sha256 != verification.manifest.application_sha256
        || import_receipt.size_bytes != verification.manifest.application_size_bytes
    {
        return Err(contract_error("fresh intake differs from verified bundle"));
    }
    let project = verification.project.clone();
    let scenario = verification.scenario.clone();
    Ok(SandboxBundleImport {
        verification,
        project,
        scenario,
        import_receipt,
    })
}
#[cfg(windows)]
fn compile(p: &Project, id: &str) -> Result<CompiledMsiScenario, SandboxBundleError> {
    compile_notepad_plus_plus_msi_scenario(p, id).map_err(|e| contract_error(e.to_string()))
}
#[cfg(windows)]
fn make_manifest(
    project_bytes: &[u8],
    r: &ApplicationFileImportReceipt,
    s: &CompiledMsiScenario,
) -> Result<SandboxBundleManifest, SandboxBundleError> {
    let x = SandboxBundleManifest {
        schema_version: SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION.into(),
        profile: PROFILE.into(),
        runtime: "windowsSandbox".into(),
        data_contract: "ephemeralStandardUserDocumentRoundTrip".into(),
        scenario_id: s.scenario_id.clone(),
        scenario_sha256: hash(&canonical(s)?),
        project_sha256: hash(project_bytes),
        source_import_receipt_sha256: hash(&canonical(r)?),
        source_download_metadata_policy: r
            .download_metadata_archive
            .as_ref()
            .map(|archive| archive.policy.clone()),
        application_sha256: r.sha256.clone(),
        application_size_bytes: r.size_bytes,
    };
    validate(&x, project_bytes, s)?;
    Ok(x)
}
#[cfg(windows)]
fn validate(
    x: &SandboxBundleManifest,
    p: &[u8],
    s: &CompiledMsiScenario,
) -> Result<(), SandboxBundleError> {
    if x.schema_version != SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION
        || x.profile != PROFILE
        || x.runtime != "windowsSandbox"
        || x.data_contract != "ephemeralStandardUserDocumentRoundTrip"
        || x.scenario_id != s.scenario_id
        || x.scenario_sha256 != hash(&canonical(s)?)
        || x.project_sha256 != hash(p)
        || x.application_sha256 != s.application_sha256
        || x.application_size_bytes == 0
        || x.application_size_bytes > 128 * 1024 * 1024
        || !valid_hash(&x.source_import_receipt_sha256)
    {
        return Err(contract_error("semantic binding"));
    }
    Ok(())
}
#[cfg(windows)]
fn canonical<T: Serialize>(x: &T) -> Result<Vec<u8>, SandboxBundleError> {
    canonical_json_bytes(&serde_json::to_value(x).map_err(|e| contract_error(e.to_string()))?)
        .map_err(|e| contract_error(e.to_string()))
}
#[cfg(windows)]
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
#[cfg(windows)]
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
#[cfg(windows)]
fn contract_error(x: impl Into<String>) -> SandboxBundleError {
    SandboxBundleError::Contract(x.into())
}
#[cfg(windows)]
fn read(p: &Path, max: u64) -> Result<Vec<u8>, SandboxBundleError> {
    use std::io::Read;
    let m = fs::symlink_metadata(p).map_err(|e| SandboxBundleError::Io(e.to_string()))?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > max {
        return Err(contract_error("ordinary bounded file"));
    }
    let mut b = Vec::new();
    fs::File::open(p)
        .map_err(|e| SandboxBundleError::Io(e.to_string()))?
        .take(max + 1)
        .read_to_end(&mut b)
        .map_err(|e| SandboxBundleError::Io(e.to_string()))?;
    if b.len() as u64 != m.len() {
        return Err(contract_error("file drift"));
    }
    Ok(b)
}
#[cfg(windows)]
fn inventory(d: &Path) -> Result<(), SandboxBundleError> {
    let mut n = fs::read_dir(d)
        .map_err(|e| SandboxBundleError::Io(e.to_string()))?
        .take(4)
        .map(|e| {
            e.map_err(|e| SandboxBundleError::Io(e.to_string()))
                .and_then(|e| {
                    e.file_name()
                        .into_string()
                        .map_err(|_| contract_error("name"))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    n.sort();
    if n != [APPLICATION_FILE, MANIFEST_FILE, PROJECT_FILE] {
        Err(contract_error("inventory"))
    } else {
        Ok(())
    }
}
#[cfg(windows)]
fn write(
    r: &aiw_windows_platform::CreatedWorkspaceDirectory,
    n: &str,
    b: &[u8],
) -> Result<(), SandboxBundleError> {
    use std::io::Write;
    let mut f = r.create_file_new(n).map_err(native)?;
    f.as_file_mut()
        .write_all(b)
        .map_err(|e| SandboxBundleError::Io(e.to_string()))?;
    f.as_file_mut()
        .sync_all()
        .map_err(|e| SandboxBundleError::Io(e.to_string()))?;
    Ok(())
}
#[cfg(windows)]
fn native(e: impl std::fmt::Display) -> SandboxBundleError {
    SandboxBundleError::Native(e.to_string())
}

