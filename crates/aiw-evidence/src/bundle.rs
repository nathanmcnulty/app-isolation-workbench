use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use aiw_schema::is_safe_relative_path;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{CanonicalJsonError, canonical_json_bytes};

pub const ASSESSMENT_BUNDLE_SPEC_SCHEMA_VERSION: &str = "aiw.dev/assessment-bundle-spec/v0alpha1";
pub const ASSESSMENT_BUNDLE_MANIFEST_SCHEMA_VERSION: &str =
    "aiw.dev/assessment-bundle-manifest/v0alpha1";
pub const ASSESSMENT_BUNDLE_VERIFICATION_SCHEMA_VERSION: &str =
    "aiw.dev/assessment-bundle-verification/v0alpha1";
const HASH_ALGORITHM: &str = "sha256";
const PATH_POLICY: &str = "portable-ascii-forward-slash-relative-v1";
const ROOT_HASH_DOMAIN: &[u8] = b"aiw-assessment-bundle-root-v1\0";
const MAX_ARTIFACTS: usize = 256;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum BundlePurpose {
    ProductFeedback,
    VendorEscalation,
    InternalValidation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ContentDeclaration {
    NoKnownSecrets,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ArtifactClass {
    Context,
    Evidence,
    AdvisoryAnalysis,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ArtifactRole {
    ProjectDefinition,
    HostProbe,
    ProviderPlan,
    TokenEvidence,
    EvidenceLog,
    EvidenceManifest,
    RunSummary,
    ComparisonReport,
    CanaryResults,
    ScenarioResults,
    DiagnosticLog,
    Trace,
    Screenshot,
    ReproductionSteps,
    Readme,
    AnalystReport,
}

impl ArtifactRole {
    const fn artifact_class(self) -> ArtifactClass {
        match self {
            Self::ProjectDefinition | Self::ReproductionSteps | Self::Readme => {
                ArtifactClass::Context
            }
            Self::AnalystReport => ArtifactClass::AdvisoryAnalysis,
            Self::HostProbe
            | Self::ProviderPlan
            | Self::TokenEvidence
            | Self::EvidenceLog
            | Self::EvidenceManifest
            | Self::RunSummary
            | Self::ComparisonReport
            | Self::CanaryResults
            | Self::ScenarioResults
            | Self::DiagnosticLog
            | Self::Trace
            | Self::Screenshot => ArtifactClass::Evidence,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleArtifactSpec {
    pub path: String,
    pub role: ArtifactRole,
    pub sensitivity: DataSensitivity,
    pub media_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentBundleSpec {
    pub schema_version: String,
    pub bundle_id: String,
    pub purpose: BundlePurpose,
    pub content_declaration: ContentDeclaration,
    pub artifacts: Vec<BundleArtifactSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleArtifact {
    pub path: String,
    pub role: ArtifactRole,
    pub class: ArtifactClass,
    pub sensitivity: DataSensitivity,
    pub media_type: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentBundleManifest {
    pub schema_version: String,
    pub bundle_id: String,
    pub purpose: BundlePurpose,
    pub content_declaration: ContentDeclaration,
    pub hash_algorithm: String,
    pub path_policy: String,
    pub artifact_count: u64,
    pub total_bytes: u64,
    pub artifacts: Vec<BundleArtifact>,
    pub bundle_root_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleVerification {
    pub schema_version: String,
    pub bundle_id: String,
    pub artifact_count: u64,
    pub total_bytes: u64,
    pub bundle_root_hash: String,
    pub verified: bool,
}

#[derive(Debug, Error)]
pub enum AssessmentBundleError {
    #[error("unsupported assessment bundle spec schema version '{0}'")]
    UnsupportedSpecSchema(String),
    #[error("unsupported assessment bundle manifest schema version '{0}'")]
    UnsupportedManifestSchema(String),
    #[error("bundle ID must contain 1-64 lowercase ASCII letters, digits, or hyphens")]
    InvalidBundleId,
    #[error("assessment bundle must contain at least one artifact")]
    EmptyBundle,
    #[error("assessment bundle has {actual} artifacts; maximum is {maximum}")]
    TooManyArtifacts { actual: usize, maximum: usize },
    #[error("artifact path is not portable and safe: {0}")]
    UnsafeArtifactPath(String),
    #[error("artifact path is duplicated under Windows case rules: {0}")]
    DuplicateArtifactPath(String),
    #[error("raw executable, package, archive, or private-key artifacts are forbidden: {0}")]
    ForbiddenArtifactType(String),
    #[error("artifact media type must be a bounded ASCII type/subtype without parameters: {0}")]
    InvalidMediaType(String),
    #[error("could not inspect bundle root {path}: {source}")]
    RootMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("bundle root is not an ordinary directory: {0}")]
    InvalidRoot(PathBuf),
    #[error("could not canonicalize bundle root {path}: {source}")]
    RootCanonicalization {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not inspect artifact {path}: {source}")]
    ArtifactMetadata {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("artifact path contains a symbolic link or reparse point: {0}")]
    ArtifactLink(String),
    #[error("artifact path has a non-directory parent component: {0}")]
    ArtifactParentNotDirectory(String),
    #[error("artifact is not an ordinary file: {0}")]
    ArtifactNotFile(String),
    #[error("could not canonicalize artifact {path}: {source}")]
    ArtifactCanonicalization {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("artifact escapes the canonical bundle root: {0}")]
    ArtifactEscapesRoot(String),
    #[error("artifact {path} is {actual} bytes; maximum is {maximum} bytes")]
    ArtifactTooLarge {
        path: String,
        actual: u64,
        maximum: u64,
    },
    #[error("assessment bundle is {actual} bytes; maximum is {maximum} bytes")]
    BundleTooLarge { actual: u64, maximum: u64 },
    #[error("could not read artifact {path}: {source}")]
    ArtifactRead {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("manifest field '{field}' must equal '{expected}', found '{actual}'")]
    ManifestConstantMismatch {
        field: &'static str,
        expected: &'static str,
        actual: String,
    },
    #[error("assessment bundle contents do not match the manifest")]
    ManifestMismatch,
    #[error(transparent)]
    CanonicalJson(#[from] CanonicalJsonError),
}

pub fn build_assessment_bundle(
    root: impl AsRef<Path>,
    spec: &AssessmentBundleSpec,
) -> Result<AssessmentBundleManifest, AssessmentBundleError> {
    validate_spec(spec)?;
    let root = root.as_ref();
    let root_metadata =
        fs::symlink_metadata(root).map_err(|source| AssessmentBundleError::RootMetadata {
            path: root.to_path_buf(),
            source,
        })?;
    if !root_metadata.is_dir()
        || root_metadata.file_type().is_symlink()
        || has_reparse_point(&root_metadata)
    {
        return Err(AssessmentBundleError::InvalidRoot(root.to_path_buf()));
    }
    let canonical_root =
        fs::canonicalize(root).map_err(|source| AssessmentBundleError::RootCanonicalization {
            path: root.to_path_buf(),
            source,
        })?;

    let mut specs: Vec<_> = spec.artifacts.iter().collect();
    specs.sort_by_key(|artifact| artifact.path.to_ascii_lowercase());
    let mut artifacts = Vec::with_capacity(specs.len());
    let mut total_bytes = 0_u64;
    for artifact in specs {
        let (size_bytes, sha256) = hash_artifact(root, &canonical_root, &artifact.path)?;
        total_bytes =
            total_bytes
                .checked_add(size_bytes)
                .ok_or(AssessmentBundleError::BundleTooLarge {
                    actual: u64::MAX,
                    maximum: MAX_BUNDLE_BYTES,
                })?;
        if total_bytes > MAX_BUNDLE_BYTES {
            return Err(AssessmentBundleError::BundleTooLarge {
                actual: total_bytes,
                maximum: MAX_BUNDLE_BYTES,
            });
        }
        artifacts.push(BundleArtifact {
            path: artifact.path.clone(),
            role: artifact.role,
            class: artifact.role.artifact_class(),
            sensitivity: artifact.sensitivity,
            media_type: artifact.media_type.clone(),
            size_bytes,
            sha256,
        });
    }

    let mut manifest = AssessmentBundleManifest {
        schema_version: ASSESSMENT_BUNDLE_MANIFEST_SCHEMA_VERSION.to_owned(),
        bundle_id: spec.bundle_id.clone(),
        purpose: spec.purpose,
        content_declaration: spec.content_declaration,
        hash_algorithm: HASH_ALGORITHM.to_owned(),
        path_policy: PATH_POLICY.to_owned(),
        artifact_count: artifacts.len() as u64,
        total_bytes,
        artifacts,
        bundle_root_hash: String::new(),
    };
    manifest.bundle_root_hash = calculate_bundle_root_hash(&manifest)?;
    Ok(manifest)
}

pub fn verify_assessment_bundle(
    root: impl AsRef<Path>,
    manifest: &AssessmentBundleManifest,
) -> Result<BundleVerification, AssessmentBundleError> {
    validate_manifest_constants(manifest)?;
    let spec = AssessmentBundleSpec {
        schema_version: ASSESSMENT_BUNDLE_SPEC_SCHEMA_VERSION.to_owned(),
        bundle_id: manifest.bundle_id.clone(),
        purpose: manifest.purpose,
        content_declaration: manifest.content_declaration,
        artifacts: manifest
            .artifacts
            .iter()
            .map(|artifact| BundleArtifactSpec {
                path: artifact.path.clone(),
                role: artifact.role,
                sensitivity: artifact.sensitivity,
                media_type: artifact.media_type.clone(),
            })
            .collect(),
    };
    let rebuilt = build_assessment_bundle(root, &spec)?;
    if &rebuilt != manifest {
        return Err(AssessmentBundleError::ManifestMismatch);
    }
    Ok(BundleVerification {
        schema_version: ASSESSMENT_BUNDLE_VERIFICATION_SCHEMA_VERSION.to_owned(),
        bundle_id: manifest.bundle_id.clone(),
        artifact_count: manifest.artifact_count,
        total_bytes: manifest.total_bytes,
        bundle_root_hash: manifest.bundle_root_hash.clone(),
        verified: true,
    })
}

fn validate_spec(spec: &AssessmentBundleSpec) -> Result<(), AssessmentBundleError> {
    if spec.schema_version != ASSESSMENT_BUNDLE_SPEC_SCHEMA_VERSION {
        return Err(AssessmentBundleError::UnsupportedSpecSchema(
            spec.schema_version.clone(),
        ));
    }
    if !is_valid_bundle_id(&spec.bundle_id) {
        return Err(AssessmentBundleError::InvalidBundleId);
    }
    if spec.artifacts.is_empty() {
        return Err(AssessmentBundleError::EmptyBundle);
    }
    if spec.artifacts.len() > MAX_ARTIFACTS {
        return Err(AssessmentBundleError::TooManyArtifacts {
            actual: spec.artifacts.len(),
            maximum: MAX_ARTIFACTS,
        });
    }

    let mut paths = BTreeSet::new();
    for artifact in &spec.artifacts {
        validate_artifact_path(&artifact.path)?;
        if !paths.insert(artifact.path.to_ascii_lowercase()) {
            return Err(AssessmentBundleError::DuplicateArtifactPath(
                artifact.path.clone(),
            ));
        }
        if has_forbidden_extension(&artifact.path) {
            return Err(AssessmentBundleError::ForbiddenArtifactType(
                artifact.path.clone(),
            ));
        }
        if !is_valid_media_type(&artifact.media_type) {
            return Err(AssessmentBundleError::InvalidMediaType(
                artifact.media_type.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_manifest_constants(
    manifest: &AssessmentBundleManifest,
) -> Result<(), AssessmentBundleError> {
    if manifest.schema_version != ASSESSMENT_BUNDLE_MANIFEST_SCHEMA_VERSION {
        return Err(AssessmentBundleError::UnsupportedManifestSchema(
            manifest.schema_version.clone(),
        ));
    }
    for (field, expected, actual) in [
        (
            "hashAlgorithm",
            HASH_ALGORITHM,
            manifest.hash_algorithm.as_str(),
        ),
        ("pathPolicy", PATH_POLICY, manifest.path_policy.as_str()),
    ] {
        if actual != expected {
            return Err(AssessmentBundleError::ManifestConstantMismatch {
                field,
                expected,
                actual: actual.to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_artifact_path(path: &str) -> Result<(), AssessmentBundleError> {
    if !path.is_ascii() || path.contains('\\') || !is_safe_relative_path(path) {
        return Err(AssessmentBundleError::UnsafeArtifactPath(path.to_owned()));
    }
    Ok(())
}

fn hash_artifact(
    root: &Path,
    canonical_root: &Path,
    relative_path: &str,
) -> Result<(u64, String), AssessmentBundleError> {
    let segments: Vec<_> = relative_path.split('/').collect();
    let mut path = root.to_path_buf();
    for (index, segment) in segments.iter().enumerate() {
        path.push(segment);
        let metadata = fs::symlink_metadata(&path).map_err(|source| {
            AssessmentBundleError::ArtifactMetadata {
                path: relative_path.to_owned(),
                source,
            }
        })?;
        if metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
            return Err(AssessmentBundleError::ArtifactLink(
                relative_path.to_owned(),
            ));
        }
        if index + 1 < segments.len() && !metadata.is_dir() {
            return Err(AssessmentBundleError::ArtifactParentNotDirectory(
                relative_path.to_owned(),
            ));
        }
    }

    let canonical_path = fs::canonicalize(&path).map_err(|source| {
        AssessmentBundleError::ArtifactCanonicalization {
            path: relative_path.to_owned(),
            source,
        }
    })?;
    if !canonical_path.starts_with(canonical_root) {
        return Err(AssessmentBundleError::ArtifactEscapesRoot(
            relative_path.to_owned(),
        ));
    }

    let mut file =
        File::open(&canonical_path).map_err(|source| AssessmentBundleError::ArtifactRead {
            path: relative_path.to_owned(),
            source,
        })?;
    let metadata = file
        .metadata()
        .map_err(|source| AssessmentBundleError::ArtifactMetadata {
            path: relative_path.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(AssessmentBundleError::ArtifactNotFile(
            relative_path.to_owned(),
        ));
    }
    if metadata.len() > MAX_ARTIFACT_BYTES {
        return Err(AssessmentBundleError::ArtifactTooLarge {
            path: relative_path.to_owned(),
            actual: metadata.len(),
            maximum: MAX_ARTIFACT_BYTES,
        });
    }

    let mut hasher = Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count =
            file.read(&mut buffer)
                .map_err(|source| AssessmentBundleError::ArtifactRead {
                    path: relative_path.to_owned(),
                    source,
                })?;
        if count == 0 {
            break;
        }
        size_bytes += count as u64;
        if size_bytes > MAX_ARTIFACT_BYTES {
            return Err(AssessmentBundleError::ArtifactTooLarge {
                path: relative_path.to_owned(),
                actual: size_bytes,
                maximum: MAX_ARTIFACT_BYTES,
            });
        }
        hasher.update(&buffer[..count]);
    }
    Ok((size_bytes, hex::encode(hasher.finalize())))
}

fn calculate_bundle_root_hash(
    manifest: &AssessmentBundleManifest,
) -> Result<String, AssessmentBundleError> {
    let material = serde_json::json!({
        "schemaVersion": manifest.schema_version,
        "bundleId": manifest.bundle_id,
        "purpose": manifest.purpose,
        "contentDeclaration": manifest.content_declaration,
        "hashAlgorithm": manifest.hash_algorithm,
        "pathPolicy": manifest.path_policy,
        "artifactCount": manifest.artifact_count,
        "totalBytes": manifest.total_bytes,
        "artifacts": manifest.artifacts,
    });
    let canonical = canonical_json_bytes(&material)?;
    let mut hasher = Sha256::new();
    hasher.update(ROOT_HASH_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn is_valid_bundle_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_valid_media_type(value: &str) -> bool {
    if value.len() < 3 || value.len() > 127 || !value.is_ascii() {
        return false;
    }
    let mut parts = value.split('/');
    let Some(kind) = parts.next() else {
        return false;
    };
    let Some(subtype) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || kind.is_empty() || subtype.is_empty() {
        return false;
    }
    kind.bytes().chain(subtype.bytes()).all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(
                byte,
                b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
            )
    })
}

fn has_forbidden_extension(path: &str) -> bool {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "exe"
            | "dll"
            | "msi"
            | "msix"
            | "msixbundle"
            | "appx"
            | "appxbundle"
            | "ps1"
            | "bat"
            | "cmd"
            | "com"
            | "scr"
            | "sys"
            | "cab"
            | "iso"
            | "wim"
            | "vhd"
            | "vhdx"
            | "vhdset"
            | "dmp"
            | "reg"
            | "pfx"
            | "p12"
            | "key"
            | "pem"
            | "zip"
            | "7z"
            | "rar"
            | "tar"
            | "gz"
            | "js"
            | "jse"
            | "vbs"
            | "vbe"
            | "wsf"
            | "wsh"
            | "hta"
            | "lnk"
            | "url"
            | "chm"
            | "wsb"
    )
}

#[cfg(windows)]
fn has_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn has_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aiw-bundle-test-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, path: &str, contents: &[u8]) {
            let destination = self.0.join(path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(destination, contents).unwrap();
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn artifact(path: &str, role: ArtifactRole) -> BundleArtifactSpec {
        BundleArtifactSpec {
            path: path.to_owned(),
            role,
            sensitivity: DataSensitivity::Internal,
            media_type: "application/json".to_owned(),
        }
    }

    fn spec(artifacts: Vec<BundleArtifactSpec>) -> AssessmentBundleSpec {
        AssessmentBundleSpec {
            schema_version: ASSESSMENT_BUNDLE_SPEC_SCHEMA_VERSION.to_owned(),
            bundle_id: "test-run-1".to_owned(),
            purpose: BundlePurpose::InternalValidation,
            content_declaration: ContentDeclaration::NoKnownSecrets,
            artifacts,
        }
    }

    #[test]
    fn build_is_sorted_and_deterministic() {
        let root = TestRoot::new();
        root.write("z.json", br#"{"z":1}"#);
        root.write("a.json", br#"{"a":1}"#);
        let input = spec(vec![
            artifact("z.json", ArtifactRole::RunSummary),
            artifact("a.json", ArtifactRole::HostProbe),
        ]);

        let first = build_assessment_bundle(&root.0, &input).unwrap();
        let second = build_assessment_bundle(&root.0, &input).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.artifacts[0].path, "a.json");
        assert_eq!(first.artifacts[1].path, "z.json");
        assert_eq!(first.artifacts[0].class, ArtifactClass::Evidence);
        assert_eq!(first.bundle_root_hash.len(), 64);
    }

    #[test]
    fn verify_detects_artifact_tampering() {
        let root = TestRoot::new();
        root.write("run.json", br#"{"status":"passed"}"#);
        let input = spec(vec![artifact("run.json", ArtifactRole::RunSummary)]);
        let manifest = build_assessment_bundle(&root.0, &input).unwrap();
        assert!(
            verify_assessment_bundle(&root.0, &manifest)
                .unwrap()
                .verified
        );

        root.write("run.json", br#"{"status":"failed"}"#);
        assert!(matches!(
            verify_assessment_bundle(&root.0, &manifest),
            Err(AssessmentBundleError::ManifestMismatch)
        ));
    }

    #[test]
    fn duplicate_windows_paths_are_rejected() {
        let root = TestRoot::new();
        let input = spec(vec![
            artifact("Run.json", ArtifactRole::RunSummary),
            artifact("run.json", ArtifactRole::RunSummary),
        ]);
        assert!(matches!(
            build_assessment_bundle(&root.0, &input),
            Err(AssessmentBundleError::DuplicateArtifactPath(_))
        ));
    }

    #[test]
    fn traversal_and_raw_binaries_are_rejected() {
        let root = TestRoot::new();
        for path in ["../secret.json", "payload/setup.exe"] {
            let input = spec(vec![artifact(path, ArtifactRole::DiagnosticLog)]);
            assert!(build_assessment_bundle(&root.0, &input).is_err());
        }
    }

    #[test]
    fn analyst_output_is_always_advisory() {
        let root = TestRoot::new();
        root.write("analysis.json", br#"{"summary":"hypothesis"}"#);
        let input = spec(vec![artifact("analysis.json", ArtifactRole::AnalystReport)]);
        let manifest = build_assessment_bundle(&root.0, &input).unwrap();
        assert_eq!(manifest.artifacts[0].class, ArtifactClass::AdvisoryAnalysis);
    }

    #[test]
    fn manifest_metadata_tampering_is_detected() {
        let root = TestRoot::new();
        root.write("run.json", br#"{"status":"passed"}"#);
        let input = spec(vec![artifact("run.json", ArtifactRole::RunSummary)]);
        let mut manifest = build_assessment_bundle(&root.0, &input).unwrap();
        manifest.artifacts[0].sensitivity = DataSensitivity::Public;
        assert!(matches!(
            verify_assessment_bundle(&root.0, &manifest),
            Err(AssessmentBundleError::ManifestMismatch)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_artifact_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new();
        root.write("outside.json", b"{}");
        symlink(root.0.join("outside.json"), root.0.join("linked.json")).unwrap();
        let input = spec(vec![artifact("linked.json", ArtifactRole::HostProbe)]);
        assert!(matches!(
            build_assessment_bundle(&root.0, &input),
            Err(AssessmentBundleError::ArtifactLink(_))
        ));
    }
}
