use crate::WsbMsiRunReport;
#[cfg(windows)]
use crate::assessment_report::report_windows_sandbox_msi_run_bound;
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
pub const SANDBOX_BUNDLE_MANIFEST_SCHEMA_VERSION: &str =
    "aiw.dev/sandbox-application-bundle/v0alpha1";
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

/// Closed file layouts selected by reviewed code, never by manifest paths.
#[cfg(windows)]
#[derive(Clone, Copy)]
pub(crate) enum BundlePayloadKind {
    Msi,
    BambuExe,
}

#[cfg(windows)]
impl BundlePayloadKind {
    fn leaf(self) -> &'static str {
        match self {
            Self::Msi => APPLICATION_FILE,
            Self::BambuExe => "app.exe",
        }
    }

    fn limit(self) -> u64 {
        match self {
            Self::Msi => 128 * 1024 * 1024,
            Self::BambuExe => 512 * 1024 * 1024,
        }
    }

    fn source_kind(self) -> ApplicationInspectionKind {
        match self {
            Self::Msi => ApplicationInspectionKind::Msi,
            Self::BambuExe => ApplicationInspectionKind::Exe,
        }
    }
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxBundleVerification {
    pub manifest_sha256: String,
    pub manifest: SandboxBundleManifest,
    pub project: Project,
    pub scenario: CompiledMsiScenario,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxBundleImport {
    pub verification: SandboxBundleVerification,
    pub project: Project,
    pub scenario: CompiledMsiScenario,
    pub import_receipt: ApplicationFileImportReceipt,
}

/// A supplied bundle and import record matched to a reverified terminal run.
/// This does not independently establish when the bundle was exported/imported.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxBundleRunReport {
    pub schema_version: String,
    pub manifest_sha256: String,
    pub manifest: SandboxBundleManifest,
    pub replay_import_receipt_sha256: String,
    pub report: WsbMsiRunReport,
}

impl SandboxBundleRunReport {
    pub fn to_markdown(&self) -> String {
        format!(
            "# Sandbox bundle matched to verified run\n\nManifest SHA-256: `{}`\n\nReplay intake receipt SHA-256: `{}`\n\nSource intake receipt SHA-256: `{}`\n\nRuntime: `{}`; bundle data contract: `{}`.\n\nThe supplied bundle and import record match this retained run's application and recipe. An optional interactive document transfer is separately bound by the run preparation and approval. This is not independent proof of import chronology or an additional compatibility verdict. Source download metadata is provenance only.\n\n{}",
            self.manifest_sha256,
            self.replay_import_receipt_sha256,
            self.manifest.source_import_receipt_sha256,
            self.manifest.runtime,
            self.manifest.data_contract,
            self.report.to_markdown(),
        )
    }
}

#[cfg(windows)]
pub fn report_notepad_plus_plus_msi_bundle(
    dir: &Path,
    expected_manifest_sha256: &str,
    imported: &SandboxBundleImport,
    workspace: &Path,
    run_id: &str,
    guest_hash: &str,
) -> Result<SandboxBundleRunReport, SandboxBundleError> {
    let held = open_bundle(dir, expected_manifest_sha256)?;
    if imported.verification != held.verification
        || imported.project != held.verification.project
        || imported.scenario != held.verification.scenario
        || imported.import_receipt.source_kind != ApplicationInspectionKind::Msi
        || imported.import_receipt.sha256 != held.verification.manifest.application_sha256
        || imported.import_receipt.size_bytes != held.verification.manifest.application_size_bytes
    {
        return Err(contract_error("import record differs from verified bundle"));
    }
    // Match the intake and recipe inside the reporter's held preparation boundary.
    // A document transfer is a separately approved specialization of scratch.
    // Original intake paths need not exist.
    let report = report_windows_sandbox_msi_run_bound(
        workspace,
        run_id,
        &imported.project,
        guest_hash,
        Some((&imported.import_receipt, &imported.scenario)),
    )
    .map_err(|e| contract_error(e.to_string()))?;
    held.directory.revalidate().map_err(native)?;
    Ok(SandboxBundleRunReport {
        schema_version: "aiw.dev/sandbox-bundle-run-report/v0alpha1".into(),
        manifest_sha256: held.verification.manifest_sha256,
        manifest: held.verification.manifest,
        replay_import_receipt_sha256: hash(&canonical(&imported.import_receipt)?),
        report,
    })
}

#[cfg(windows)]
pub(crate) fn verify_prepared_scenario(
    project: &Project,
    bundled: &CompiledMsiScenario,
    prepared: &CompiledMsiScenario,
) -> Result<(), crate::RunnerError> {
    // Only the fixed scratch recipe may acquire a document at preparation time.
    // Recompile both sides rather than removing fields before comparing them.
    let mut expected = if let Some(document) = &prepared.interactive_document {
        if bundled.interactive_session_seconds.is_none()
            || bundled.requires_document_transfer()
            || compile_notepad_plus_plus_msi_scenario(project, &bundled.scenario_id).as_ref()
                != Ok(bundled)
        {
            return Err(crate::RunnerError::ApprovalBinding);
        }
        aiw_provider_wsb::compile_notepad_plus_plus_msi_scenario_with_document(
            project,
            &bundled.scenario_id,
            &document.input_sha256,
            document.input_size_bytes,
        )
        .map_err(|_| crate::RunnerError::ApprovalBinding)?
    } else {
        bundled.clone()
    };
    // Historical transfer runs retain their originally approved installation
    // deadline and argument contract when associated with their scratch bundle.
    if prepared.schema_version == "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha8"
        && prepared.requires_document_transfer()
    {
        prepared
            .validate()
            .map_err(|_| crate::RunnerError::ApprovalBinding)?;
        expected.schema_version = prepared.schema_version.clone();
        expected.profile = prepared.profile.clone();
        expected.install_timeout_seconds = 120;
        expected.install_arguments.truncate(4);
        expected
            .validate()
            .map_err(|_| crate::RunnerError::ApprovalBinding)?;
    }
    if &expected != prepared {
        return Err(crate::RunnerError::ApprovalBinding);
    }
    Ok(())
}
#[cfg(windows)]
pub fn export_notepad_plus_plus_msi_bundle(
    parent: &Path,
    id: &str,
    project: &Project,
    scenario_id: &str,
    receipt: &ApplicationFileImportReceipt,
) -> Result<SandboxBundleExport, SandboxBundleError> {
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
    let bundle_path = write_bundle_files(
        parent,
        id,
        BundlePayloadKind::Msi,
        receipt,
        &project_bytes,
        &manifest_bytes,
    )?;
    Ok(SandboxBundleExport {
        bundle_path,
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
pub(crate) struct HeldBundleFiles {
    pub directory: aiw_windows_platform::HeldPortableDirectory,
    pub application: aiw_windows_platform::HeldApplicationFile,
    pub manifest_bytes: Vec<u8>,
    pub project_bytes: Vec<u8>,
}

#[cfg(windows)]
fn open_bundle(dir: &Path, expected: &str) -> Result<HeldBundle, SandboxBundleError> {
    let files = open_bundle_files(dir, expected, BundlePayloadKind::Msi)?;
    let manifest: SandboxBundleManifest = serde_json::from_slice(&files.manifest_bytes)
        .map_err(|_| contract_error("manifest JSON"))?;
    let project: Project =
        serde_json::from_slice(&files.project_bytes).map_err(|_| contract_error("project JSON"))?;
    let scenario = compile(&project, &manifest.scenario_id)?;
    validate(&manifest, &files.project_bytes, &scenario)?;
    if files.application.observation().sha256 != manifest.application_sha256
        || files.application.observation().size_bytes != manifest.application_size_bytes
    {
        return Err(contract_error("application binding"));
    }
    files.application.revalidate().map_err(native)?;
    files.directory.revalidate().map_err(native)?;
    Ok(HeldBundle {
        directory: files.directory,
        application: files.application,
        verification: SandboxBundleVerification {
            manifest_sha256: expected.into(),
            manifest,
            project,
            scenario,
        },
    })
}

#[cfg(windows)]
pub(crate) fn open_bundle_files(
    dir: &Path,
    expected: &str,
    kind: BundlePayloadKind,
) -> Result<HeldBundleFiles, SandboxBundleError> {
    use aiw_windows_platform::{HeldApplicationFile, HeldPortableDirectory};
    if !valid_hash(expected) {
        return Err(contract_error(
            "expected manifest hash must be lowercase SHA-256",
        ));
    }
    inventory(dir, kind)?;
    for (leaf, limit) in [
        (MANIFEST_FILE, 65536),
        (PROJECT_FILE, 524288),
        (kind.leaf(), kind.limit()),
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
    let application_file = HeldApplicationFile::open(&dir.join(kind.leaf())).map_err(native)?;
    let manifest_bytes = read(&dir.join(MANIFEST_FILE), 65536)?;
    if hash(&manifest_bytes) != expected
        || hash(&manifest_bytes) != manifest_file.observation().sha256
    {
        return Err(contract_error("manifest hash"));
    }
    let project_bytes = read(&dir.join(PROJECT_FILE), 524288)?;
    if hash(&project_bytes) != project_file.observation().sha256 {
        return Err(contract_error("project drift"));
    }
    manifest_file.revalidate().map_err(native)?;
    project_file.revalidate().map_err(native)?;
    application_file.revalidate().map_err(native)?;
    directory.revalidate().map_err(native)?;
    inventory(dir, kind)?;
    Ok(HeldBundleFiles {
        directory,
        application: application_file,
        manifest_bytes,
        project_bytes,
    })
}

#[cfg(windows)]
pub(crate) fn write_bundle_files(
    parent: &Path,
    id: &str,
    kind: BundlePayloadKind,
    receipt: &ApplicationFileImportReceipt,
    project_bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<String, SandboxBundleError> {
    use aiw_windows_platform::{CreatedWorkspaceDirectory, open_verified_application_file_import};
    if receipt.source_kind != kind.source_kind()
        || receipt.size_bytes == 0
        || receipt.size_bytes > kind.limit()
        || project_bytes.len() > 524288
        || manifest_bytes.len() > 65536
    {
        return Err(contract_error("bundle transport bounds or source kind"));
    }
    // Create before source custody locks its parent; retain it through copy,
    // then publish the closed manifest last. Failure leaves output for diagnosis.
    let root = CreatedWorkspaceDirectory::create_protected(parent, id).map_err(native)?;
    let mut held = open_verified_application_file_import(receipt).map_err(native)?;
    held.copy_to(root.create_file_new(kind.leaf()).map_err(native)?)
        .map_err(native)?;
    write(&root, PROJECT_FILE, project_bytes)?;
    write(&root, MANIFEST_FILE, manifest_bytes)?;
    held.revalidate().map_err(native)?;
    Ok(root.final_path().display().to_string())
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
        profile: s.profile.clone(),
        runtime: "windowsSandbox".into(),
        data_contract: data_contract(s).into(),
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
        || x.profile != s.profile
        || x.runtime != "windowsSandbox"
        || x.data_contract != data_contract(s)
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
pub(crate) fn canonical<T: Serialize>(x: &T) -> Result<Vec<u8>, SandboxBundleError> {
    canonical_json_bytes(&serde_json::to_value(x).map_err(|e| contract_error(e.to_string()))?)
        .map_err(|e| contract_error(e.to_string()))
}
#[cfg(windows)]
fn data_contract(scenario: &CompiledMsiScenario) -> &'static str {
    if scenario.interactive_session_seconds.is_some() {
        "ephemeralInteractiveScratch"
    } else {
        "ephemeralStandardUserDocumentRoundTrip"
    }
}
#[cfg(windows)]
pub(crate) fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
#[cfg(windows)]
pub(crate) fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
#[cfg(windows)]
pub(crate) fn contract_error(x: impl Into<String>) -> SandboxBundleError {
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
fn inventory(d: &Path, kind: BundlePayloadKind) -> Result<(), SandboxBundleError> {
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
    if n != [kind.leaf(), MANIFEST_FILE, PROJECT_FILE] {
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
pub(crate) fn native(e: impl std::fmt::Display) -> SandboxBundleError {
    SandboxBundleError::Native(e.to_string())
}
