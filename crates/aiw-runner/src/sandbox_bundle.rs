use aiw_evidence::canonical_json_bytes;
use aiw_probe::{ApplicationFileImportReceipt, ApplicationInspectionKind};
use aiw_provider_wsb::{CompiledMsiScenario, compile_notepad_plus_plus_msi_scenario};
use aiw_schema::Project;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use thiserror::Error;
pub const SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION: &str =
    "aiw.dev/sandbox-application-bundle/v0alpha1";
const PROFILE: &str = "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha6";
const M: &str = "manifest.json";
const A: &str = "application.msi";
const P: &str = "project.json";
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
    let pb = canonical(project)?;
    let manifest = make_manifest(&pb, receipt, &scenario)?;
    let mb = canonical(&manifest)?;
    let root = CreatedWorkspaceDirectory::create_protected(parent, id).map_err(native)?;
    let mut held = open_verified_application_file_import(receipt).map_err(native)?;
    let app = root.create_file_new(A).map_err(native)?;
    held.copy_to(app).map_err(native)?;
    write(&root, P, &pb)?;
    write(&root, M, &mb)?;
    held.revalidate().map_err(native)?;
    Ok(SandboxBundleExport {
        bundle_path: root.final_path().display().to_string(),
        manifest_sha256: hash(&mb),
        manifest,
    })
}
#[cfg(windows)]
pub fn verify_notepad_plus_plus_msi_bundle(
    dir: &Path,
    expected: &str,
) -> Result<SandboxBundleVerification, SandboxBundleError> {
    use aiw_windows_platform::HeldApplicationFile;
    inventory(dir)?;
    let mh = HeldApplicationFile::open(&dir.join(M)).map_err(native)?;
    let ph = HeldApplicationFile::open(&dir.join(P)).map_err(native)?;
    let ah = HeldApplicationFile::open(&dir.join(A)).map_err(native)?;
    let mb = read(&dir.join(M), 65536)?;
    if hash(&mb) != expected || hash(&mb) != mh.observation().sha256 {
        return Err(c("manifest hash"));
    }
    let manifest: SandboxBundleManifest =
        serde_json::from_slice(&mb).map_err(|_| c("manifest JSON"))?;
    let pb = read(&dir.join(P), 524288)?;
    if hash(&pb) != ph.observation().sha256 {
        return Err(c("project drift"));
    }
    let project: Project = serde_json::from_slice(&pb).map_err(|_| c("project JSON"))?;
    let scenario = compile(&project, &manifest.scenario_id)?;
    validate(&manifest, &pb, &scenario)?;
    if ah.observation().sha256 != manifest.application_sha256
        || ah.observation().size_bytes != manifest.application_size_bytes
    {
        return Err(c("application binding"));
    }
    Ok(SandboxBundleVerification {
        manifest_sha256: expected.into(),
        manifest,
        project,
        scenario,
    })
}
#[cfg(windows)]
pub fn import_notepad_plus_plus_msi_bundle(
    dir: &Path,
    expected: &str,
    parent: &Path,
    id: &str,
) -> Result<SandboxBundleImport, SandboxBundleError> {
    use aiw_windows_platform::{HeldApplicationFile, import_application_file};
    let verification = verify_notepad_plus_plus_msi_bundle(dir, expected)?;
    let source = HeldApplicationFile::open(&dir.join(A)).map_err(native)?;
    let import_receipt =
        import_application_file(parent, id, ApplicationInspectionKind::Msi, &source)
            .map_err(native)?;
    let project = verification.project.clone();
    let scenario = verification.scenario.clone();
    Ok(SandboxBundleImport {
        verification,
        import_receipt,
    })
}
fn compile(p: &Project, id: &str) -> Result<CompiledMsiScenario, SandboxBundleError> {
    compile_notepad_plus_plus_msi_scenario(p, id).map_err(|e| c(e.to_string()))
}
fn make_manifest(
    pb: &[u8],
    r: &ApplicationFileImportReceipt,
    s: &CompiledMsiScenario,
) -> Result<SandboxBundleManifest, SandboxBundleError> {
    let x = SandboxBundleManifest {
        schema_version: SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION.into(),
        profile: PROFILE.into(),
        runtime: "windowsSandbox".into(),
        data_contract: "standardUserRuntimeAndProductRegistration".into(),
        scenario_id: s.scenario_id.clone(),
        scenario_sha256: hash(&canonical(s)?),
        project_sha256: hash(pb),
        source_import_receipt_sha256: hash(&canonical(r)?),
        application_sha256: r.sha256.clone(),
        application_size_bytes: r.size_bytes,
    };
    validate(&x, pb, s)?;
    Ok(x)
}
fn validate(
    x: &SandboxBundleManifest,
    p: &[u8],
    s: &CompiledMsiScenario,
) -> Result<(), SandboxBundleError> {
    if x.schema_version != SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION
        || x.profile != PROFILE
        || x.runtime != "windowsSandbox"
        || x.data_contract != "standardUserRuntimeAndProductRegistration"
        || x.scenario_id != s.scenario_id
        || x.scenario_sha256 != hash(&canonical(s)?)
        || x.project_sha256 != hash(p)
        || x.application_sha256 != s.application_sha256
        || x.application_size_bytes == 0
    {
        return Err(c("semantic binding"));
    }
    Ok(())
}
fn canonical<T: Serialize>(x: &T) -> Result<Vec<u8>, SandboxBundleError> {
    canonical_json_bytes(&serde_json::to_value(x).map_err(|e| c(e.to_string()))?)
        .map_err(|e| c(e.to_string()))
}
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn c(x: impl Into<String>) -> SandboxBundleError {
    SandboxBundleError::Contract(x.into())
}
fn read(p: &Path, max: u64) -> Result<Vec<u8>, SandboxBundleError> {
    let m = fs::symlink_metadata(p).map_err(|e| SandboxBundleError::Io(e.to_string()))?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > max {
        return Err(c("ordinary bounded file"));
    }
    let b = fs::read(p).map_err(|e| SandboxBundleError::Io(e.to_string()))?;
    if b.len() as u64 != m.len() {
        return Err(c("file drift"));
    }
    Ok(b)
}
#[cfg(windows)]
fn inventory(d: &Path) -> Result<(), SandboxBundleError> {
    let mut n = fs::read_dir(d)
        .map_err(|e| SandboxBundleError::Io(e.to_string()))?
        .map(|e| {
            e.map_err(|e| SandboxBundleError::Io(e.to_string()))
                .and_then(|e| e.file_name().into_string().map_err(|_| c("name")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    n.sort();
    if n != [A, M, P] {
        Err(c("inventory"))
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
