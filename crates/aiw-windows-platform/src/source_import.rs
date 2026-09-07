//! Receipt-last protected import for one already-held MSI or EXE source.
//!
//! Import is a non-executing copy boundary. It creates new owner-and-SYSTEM
//! objects only, preserves incomplete state on failure, and never grants the
//! imported bytes execution or provider authority.

use std::fs::File;
use std::io::Write;
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};

use aiw_probe::{
    APPLICATION_FILE_AUTHORITY_SCHEMA, APPLICATION_FILE_IMPORT_RECEIPT_SCHEMA,
    APPLICATION_FILE_IMPORT_VERIFICATION_SCHEMA, ApplicationFileAuthority,
    ApplicationFileEaAuthority, ApplicationFileEaEntry, ApplicationFileImportReceipt,
    ApplicationFileImportVerification, ApplicationInspectionKind, WindowsFileIdentity,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT};

use crate::exact_dispose::{
    ExactDisposeError, ExtendedAttributeBinding, FORBIDDEN_ATTRIBUTES, basic_info, file_size,
    hash_file, query_extended_attributes_for_import, reject_case_sensitive_directory,
    source_directory_entries, stabilized_import_extended_attributes, standard_info,
    verify_stream_policy,
};
use crate::source_inspection::{HeldApplicationFile, SourceInspectionError};
use crate::workspace::{
    BoundWorkspaceDirectory, BoundWorkspaceFile, CreatedWorkspaceDirectory, CreatedWorkspaceFile,
    WorkspaceAclPolicy, WorkspaceError, same_path,
};

const RECEIPT_LEAF: &str = "intake.json";
const SOURCE_DIRECTORY_LEAF: &str = "source";
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum SourceImportError {
    #[error("protected intake workspace rejected the operation: {0}")]
    Workspace(#[from] WorkspaceError),
    #[error("held application source rejected the operation: {0}")]
    Source(#[from] SourceInspectionError),
    #[error("protected intake contract is invalid: {0}")]
    Contract(String),
    #[error("protected intake content or identity drifted")]
    Drift,
    #[error("protected intake serialization failed: {0}")]
    Serialization(String),
    #[error("protected intake native observation failed: {0}")]
    Native(String),
}

/// Opaque, read-only authority for one independently verified imported file.
///
/// The import receipt is verified while the intake root, source directory,
/// payload, and receipt file are retained by handle. Callers can only copy the
/// payload into a newly-created protected workspace file, never reopen its
/// recorded path as a new source authority.
#[derive(Debug)]
pub struct HeldVerifiedApplicationFileImport {
    receipt: ApplicationFileImportReceipt,
    verification: ApplicationFileImportVerification,
    root: BoundWorkspaceDirectory,
    source_directory: BoundWorkspaceDirectory,
    payload: BoundWorkspaceFile,
    internal_receipt: BoundWorkspaceFile,
}

impl HeldVerifiedApplicationFileImport {
    /// Returns the fixed verification result while this held authority remains valid.
    pub fn verification(&self) -> &ApplicationFileImportVerification {
        &self.verification
    }

    /// Repeats the complete receipt, namespace, content, EA, and handle checks.
    pub fn revalidate(&self) -> Result<(), SourceImportError> {
        validate_receipt(&self.receipt)?;
        if self.root.identity() != &self.receipt.intake_root
            || self.source_directory.identity() != &self.receipt.source_directory
            || self.payload.identity() != &self.receipt.payload
            || self.internal_receipt.identity() != &self.receipt.receipt
        {
            return Err(SourceImportError::Drift);
        }
        require_names(self.root.as_file(), &[RECEIPT_LEAF, SOURCE_DIRECTORY_LEAF])?;
        verify_directory_file(self.root.as_file())?;
        require_ea_authority(self.root.as_file(), true, &self.receipt.intake_root_eas)?;

        let payload_leaf = payload_leaf(self.receipt.source_kind)?;
        require_names(self.source_directory.as_file(), &[payload_leaf])?;
        verify_directory_file(self.source_directory.as_file())?;
        require_ea_authority(
            self.source_directory.as_file(),
            true,
            &self.receipt.source_directory_eas,
        )?;

        verify_payload(
            self.payload.as_file(),
            self.receipt.size_bytes,
            &self.receipt.sha256,
        )?;
        require_ea_authority(self.payload.as_file(), false, &self.receipt.payload_eas)?;

        let expected_bytes = receipt_bytes(&self.receipt)?;
        let actual_bytes = read_exact_bounded(self.internal_receipt.as_file(), MAX_RECEIPT_BYTES)?;
        if actual_bytes != expected_bytes {
            return Err(SourceImportError::Drift);
        }
        verify_ordinary_file(self.internal_receipt.as_file(), actual_bytes.len() as u64)?;
        require_allowed_receipt_eas(self.internal_receipt.as_file())?;

        self.internal_receipt.revalidate()?;
        self.payload.revalidate()?;
        self.source_directory.revalidate()?;
        self.root.revalidate()?;
        if self.verification != verification_for(&self.receipt, &expected_bytes) {
            return Err(SourceImportError::Drift);
        }
        Ok(())
    }

    /// Copies the retained payload only into a caller-created protected workspace file.
    /// The destination remains held by the caller and both ends are revalidated
    /// before the copy is returned.
    pub fn copy_to(
        &mut self,
        mut destination: CreatedWorkspaceFile,
    ) -> Result<CreatedWorkspaceFile, SourceImportError> {
        self.revalidate()?;
        verify_ordinary_file(destination.as_file(), 0)?;
        destination.revalidate()?;
        let mut source_hash = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = self
                .payload
                .as_file()
                .seek_read(&mut buffer, copied)
                .map_err(native)?;
            if count == 0 {
                break;
            }
            copied = copied.saturating_add(count as u64);
            if copied > self.receipt.size_bytes {
                return Err(SourceImportError::Drift);
            }
            source_hash.update(&buffer[..count]);
            destination
                .as_file_mut()
                .write_all(&buffer[..count])
                .map_err(native)?;
        }
        if copied != self.receipt.size_bytes
            || hex::encode(source_hash.finalize()) != self.receipt.sha256
        {
            return Err(SourceImportError::Drift);
        }
        destination.as_file_mut().flush().map_err(native)?;
        destination.as_file().sync_all().map_err(native)?;
        verify_payload(
            destination.as_file(),
            self.receipt.size_bytes,
            &self.receipt.sha256,
        )?;
        destination.revalidate()?;
        self.revalidate()?;
        Ok(destination)
    }
}

pub fn import_application_file(
    parent: &Path,
    intake_id: &str,
    kind: ApplicationInspectionKind,
    source: &HeldApplicationFile,
) -> Result<ApplicationFileImportReceipt, SourceImportError> {
    let payload_leaf = payload_leaf(kind)?;
    let source_extension = Path::new(&source.observation().canonical_path)
        .extension()
        .and_then(|value| value.to_str())
        .ok_or_else(|| SourceImportError::Contract("source extension is missing".to_owned()))?;
    let expected_extension = payload_leaf
        .rsplit_once('.')
        .map(|(_, extension)| extension)
        .expect("fixed payload leaves have extensions");
    if !source_extension.eq_ignore_ascii_case(expected_extension) {
        return Err(SourceImportError::Contract(
            "held source extension does not match the requested kind".to_owned(),
        ));
    }
    let root = CreatedWorkspaceDirectory::create_protected(parent, intake_id)?;
    let source_directory = root.create_directory_new(SOURCE_DIRECTORY_LEAF)?;
    let mut payload = source_directory.create_file_new(payload_leaf)?;
    source.copy_to(payload.as_file_mut())?;
    verify_payload(
        payload.as_file(),
        source.observation().size_bytes,
        &source.observation().sha256,
    )?;
    payload.revalidate()?;
    let payload_identity = payload.identity().clone();
    drop(payload);
    let payload = source_directory.reopen_file_readonly(payload_leaf)?;
    if payload.identity() != &payload_identity {
        return Err(SourceImportError::Drift);
    }
    verify_payload(
        payload.as_file(),
        source.observation().size_bytes,
        &source.observation().sha256,
    )?;
    verify_directory_file(source_directory.as_file())?;
    verify_directory_file(root.as_file())?;
    source_directory.revalidate()?;
    root.revalidate()?;
    source.revalidate()?;

    // The receipt object exists before its bytes so its stable identity and
    // semantic EA authority can be included without a content-hash cycle.
    // Its bytes are still written, flushed, and synchronized last.
    let mut receipt_file = root.create_file_new(RECEIPT_LEAF)?;
    let intake_root_eas = capture_ea_authority(root.as_file(), true)?;
    let source_directory_eas = capture_ea_authority(source_directory.as_file(), true)?;
    let payload_eas = capture_ea_authority(payload.as_file(), false)?;
    let receipt = ApplicationFileImportReceipt {
        schema_version: APPLICATION_FILE_IMPORT_RECEIPT_SCHEMA.to_owned(),
        intake_id: intake_id.to_owned(),
        source_kind: kind,
        source: ApplicationFileAuthority {
            schema_version: APPLICATION_FILE_AUTHORITY_SCHEMA.to_owned(),
            identity: source.observation().identity.clone(),
            size_bytes: source.observation().size_bytes,
            sha256: source.observation().sha256.clone(),
            link_count: source.observation().link_count,
            only_unnamed_data_stream: source.observation().only_unnamed_data_stream,
        },
        intake_root: root.identity().clone(),
        intake_root_eas,
        source_directory: source_directory.identity().clone(),
        source_directory_eas,
        payload_relative_path: format!("{SOURCE_DIRECTORY_LEAF}/{payload_leaf}"),
        payload: payload_identity,
        payload_eas,
        receipt: receipt_file.identity().clone(),
        size_bytes: source.observation().size_bytes,
        sha256: source.observation().sha256.clone(),
    };
    validate_receipt(&receipt)?;
    let receipt_bytes = receipt_bytes(&receipt)?;
    receipt_file
        .as_file_mut()
        .write_all(&receipt_bytes)
        .map_err(native)?;
    receipt_file.as_file_mut().flush().map_err(native)?;
    receipt_file.as_file().sync_all().map_err(native)?;
    verify_ordinary_file(receipt_file.as_file(), receipt_bytes.len() as u64)?;
    require_ea_authority(root.as_file(), true, &receipt.intake_root_eas)?;
    require_ea_authority(
        source_directory.as_file(),
        true,
        &receipt.source_directory_eas,
    )?;
    require_ea_authority(payload.as_file(), false, &receipt.payload_eas)?;
    require_allowed_receipt_eas(receipt_file.as_file())?;
    receipt_file.revalidate()?;
    source.revalidate()?;

    // Close every destination handle before the independent read-only reopen.
    drop(receipt_file);
    drop(payload);
    drop(source_directory);
    drop(root);
    verify_application_file_import(&receipt)?;
    source.revalidate()?;
    Ok(receipt)
}

pub fn open_verified_application_file_import(
    receipt: &ApplicationFileImportReceipt,
) -> Result<HeldVerifiedApplicationFileImport, SourceImportError> {
    validate_receipt(receipt)?;
    let root = BoundWorkspaceDirectory::reopen_protected(&receipt.intake_root)?;
    let source_directory =
        root.reopen_directory_readonly(SOURCE_DIRECTORY_LEAF, WorkspaceAclPolicy::Protected)?;
    let payload_leaf = payload_leaf(receipt.source_kind)?;
    let payload = source_directory.reopen_file_readonly(payload_leaf)?;
    let internal_receipt = root.reopen_file_readonly(RECEIPT_LEAF)?;
    let expected_bytes = receipt_bytes(receipt)?;
    let verification = verification_for(receipt, &expected_bytes);
    let held = HeldVerifiedApplicationFileImport {
        receipt: receipt.clone(),
        verification,
        root,
        source_directory,
        payload,
        internal_receipt,
    };
    held.revalidate()?;
    Ok(held)
}

pub fn verify_application_file_import(
    receipt: &ApplicationFileImportReceipt,
) -> Result<ApplicationFileImportVerification, SourceImportError> {
    Ok(open_verified_application_file_import(receipt)?
        .verification()
        .clone())
}

fn payload_leaf(kind: ApplicationInspectionKind) -> Result<&'static str, SourceImportError> {
    match kind {
        ApplicationInspectionKind::Msi => Ok("payload.msi"),
        ApplicationInspectionKind::Exe => Ok("payload.exe"),
        ApplicationInspectionKind::PortableDirectory => Err(SourceImportError::Contract(
            "portable-directory copying is outside the file-import contract".to_owned(),
        )),
    }
}

fn validate_receipt(receipt: &ApplicationFileImportReceipt) -> Result<(), SourceImportError> {
    let payload_leaf = payload_leaf(receipt.source_kind)?;
    if receipt.schema_version != APPLICATION_FILE_IMPORT_RECEIPT_SCHEMA
        || receipt.source.schema_version != APPLICATION_FILE_AUTHORITY_SCHEMA
        || receipt.intake_id.is_empty()
        || receipt.intake_id.len() > 64
        || !receipt
            .intake_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || receipt.payload_relative_path != format!("{SOURCE_DIRECTORY_LEAF}/{payload_leaf}")
        || receipt.size_bytes != receipt.source.size_bytes
        || receipt.sha256 != receipt.source.sha256
        || receipt.sha256.len() != 64
        || !receipt.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        || receipt.source.link_count != 1
        || !receipt.source.only_unnamed_data_stream
        || !valid_identity(&receipt.source.identity)
        || !valid_identity(&receipt.intake_root)
        || !valid_identity(&receipt.source_directory)
        || !valid_identity(&receipt.payload)
        || !valid_identity(&receipt.receipt)
        || !valid_ea_authority(&receipt.intake_root_eas)
        || !valid_ea_authority(&receipt.source_directory_eas)
        || !valid_ea_authority(&receipt.payload_eas)
    {
        return Err(SourceImportError::Contract(
            "receipt fields do not satisfy the fixed file-import contract".to_owned(),
        ));
    }
    let root = PathBuf::from(&receipt.intake_root.final_path);
    let source_directory = PathBuf::from(&receipt.source_directory.final_path);
    let payload = PathBuf::from(&receipt.payload.final_path);
    let internal_receipt = PathBuf::from(&receipt.receipt.final_path);
    if !root.is_absolute()
        || root.file_name().and_then(|value| value.to_str()) != Some(&receipt.intake_id)
        || !same_path(&source_directory, root.join(SOURCE_DIRECTORY_LEAF))
        || !same_path(&payload, source_directory.join(payload_leaf))
        || !same_path(&internal_receipt, root.join(RECEIPT_LEAF))
        || receipt.intake_root.volume_serial_number != receipt.source_directory.volume_serial_number
        || receipt.intake_root.volume_serial_number != receipt.payload.volume_serial_number
        || receipt.intake_root.volume_serial_number != receipt.receipt.volume_serial_number
    {
        return Err(SourceImportError::Contract(
            "receipt paths or volume identities are inconsistent".to_owned(),
        ));
    }
    Ok(())
}

fn receipt_bytes(receipt: &ApplicationFileImportReceipt) -> Result<Vec<u8>, SourceImportError> {
    let bytes = serde_json::to_vec(receipt)
        .map_err(|error| SourceImportError::Serialization(error.to_string()))?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(SourceImportError::Contract(
            "receipt exceeds its fixed bound".to_owned(),
        ));
    }
    Ok(bytes)
}

fn verification_for(
    receipt: &ApplicationFileImportReceipt,
    receipt_bytes: &[u8],
) -> ApplicationFileImportVerification {
    ApplicationFileImportVerification {
        schema_version: APPLICATION_FILE_IMPORT_VERIFICATION_SCHEMA.to_owned(),
        receipt_sha256: hex::encode(Sha256::digest(receipt_bytes)),
        intake_root: receipt.intake_root.clone(),
        payload: receipt.payload.clone(),
        verified: true,
    }
}

fn verify_payload(
    file: &File,
    expected_size: u64,
    expected_hash: &str,
) -> Result<(), SourceImportError> {
    verify_ordinary_file(file, expected_size)?;
    let hash = hex::encode(hash_file(file, expected_size).map_err(exact)?);
    if hash != expected_hash {
        return Err(SourceImportError::Drift);
    }
    Ok(())
}

fn verify_ordinary_file(file: &File, expected_size: u64) -> Result<(), SourceImportError> {
    let basic = basic_info(file).map_err(exact)?;
    let standard = standard_info(file).map_err(exact)?;
    if basic.dwFileAttributes
        & (FORBIDDEN_ATTRIBUTES | FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_REPARSE_POINT.0)
        != 0
        || standard.NumberOfLinks != 1
        || file_size(file).map_err(exact)? != expected_size
    {
        return Err(SourceImportError::Drift);
    }
    verify_stream_policy(file, false, expected_size).map_err(exact)?;
    Ok(())
}

fn verify_directory_file(file: &File) -> Result<(), SourceImportError> {
    let basic = basic_info(file).map_err(exact)?;
    if basic.dwFileAttributes & FORBIDDEN_ATTRIBUTES != 0
        || basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
    {
        return Err(SourceImportError::Drift);
    }
    reject_case_sensitive_directory(file).map_err(exact)?;
    verify_stream_policy(file, true, 0).map_err(exact)?;
    Ok(())
}

fn capture_ea_authority(
    file: &File,
    directory: bool,
) -> Result<ApplicationFileEaAuthority, SourceImportError> {
    let binding = stabilized_import_extended_attributes(file, directory).map_err(exact)?;
    Ok(ea_authority(binding))
}

fn ea_authority(binding: ExtendedAttributeBinding) -> ApplicationFileEaAuthority {
    let binding = binding.for_import_receipt();
    ApplicationFileEaAuthority {
        entries: binding
            .entries
            .into_iter()
            .map(|entry| ApplicationFileEaEntry {
                name: entry.name,
                flags: entry.flags,
                value_length: entry.value_length,
                value_sha256: hex::encode(entry.value_sha256),
            })
            .collect(),
        canonical_sha256: hex::encode(binding.canonical_sha256),
    }
}

fn require_ea_authority(
    file: &File,
    directory: bool,
    expected: &ApplicationFileEaAuthority,
) -> Result<(), SourceImportError> {
    if capture_ea_authority(file, directory)? != *expected {
        return Err(SourceImportError::Drift);
    }
    Ok(())
}

fn require_allowed_receipt_eas(file: &File) -> Result<(), SourceImportError> {
    query_extended_attributes_for_import(file, false)
        .map(|_| ())
        .map_err(exact)
}

fn valid_identity(identity: &WindowsFileIdentity) -> bool {
    Path::new(&identity.final_path).is_absolute()
        && valid_lower_hex(&identity.volume_serial_number, 16)
        && valid_lower_hex(&identity.file_id, 32)
}

fn valid_ea_authority(authority: &ApplicationFileEaAuthority) -> bool {
    crate::exact_dispose::valid_import_ea_authority(authority)
}

fn valid_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn require_names(file: &File, expected: &[&str]) -> Result<(), SourceImportError> {
    let mut names = source_directory_entries(file)
        .map_err(exact)?
        .into_iter()
        .map(|entry| entry.name)
        .collect::<Vec<_>>();
    names.sort();
    let mut expected = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    expected.sort();
    if names != expected {
        return Err(SourceImportError::Drift);
    }
    Ok(())
}

fn read_exact_bounded(file: &File, limit: u64) -> Result<Vec<u8>, SourceImportError> {
    let size = file_size(file).map_err(exact)?;
    if size > limit {
        return Err(SourceImportError::Drift);
    }
    let mut bytes = vec![0_u8; size as usize];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let count = file
            .seek_read(&mut bytes[offset..], offset as u64)
            .map_err(native)?;
        if count == 0 {
            return Err(SourceImportError::Drift);
        }
        offset += count;
    }
    if file_size(file).map_err(exact)? != size {
        return Err(SourceImportError::Drift);
    }
    Ok(bytes)
}

fn exact(error: ExactDisposeError) -> SourceImportError {
    SourceImportError::Native(error.to_string())
}

fn native(error: impl std::fmt::Display) -> SourceImportError {
    SourceImportError::Native(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::HeldRunWorkspace;
    use std::fs::{self, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows::Win32::Storage::FileSystem::{
        FILE_ADD_FILE, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Root(PathBuf);

    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aiw-protected-file-import-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn import_fixture(kind: ApplicationInspectionKind) -> (Root, ApplicationFileImportReceipt) {
        let root = Root::new();
        let extension = match kind {
            ApplicationInspectionKind::Msi => "msi",
            ApplicationInspectionKind::Exe => "exe",
            ApplicationInspectionKind::PortableDirectory => unreachable!(),
        };
        let source_path = root.0.join(format!("setup.{extension}"));
        fs::write(&source_path, b"protected-import-source").unwrap();
        let source = HeldApplicationFile::open(&source_path).unwrap();
        let receipt = import_application_file(&root.0, "intake-001", kind, &source).unwrap();
        (root, receipt)
    }

    #[test]
    fn msi_and_exe_import_receipts_verify_after_all_writers_close() {
        for kind in [
            ApplicationInspectionKind::Msi,
            ApplicationInspectionKind::Exe,
        ] {
            let (_root, receipt) = import_fixture(kind);
            let verified = verify_application_file_import(&receipt).unwrap();
            assert!(verified.verified);
            assert_eq!(verified.payload, receipt.payload);
            assert_eq!(verified.receipt_sha256.len(), 64);
        }
    }

    #[test]
    fn held_verification_excludes_payload_writers_and_remains_revalidatable() {
        let (_root, receipt) = import_fixture(ApplicationInspectionKind::Msi);
        let held = open_verified_application_file_import(&receipt).unwrap();
        assert!(
            OpenOptions::new()
                .write(true)
                .open(&receipt.payload.final_path)
                .is_err()
        );
        held.revalidate().unwrap();
    }

    #[test]
    fn held_import_copies_only_to_a_created_workspace_file() {
        let (_root, receipt) = import_fixture(ApplicationInspectionKind::Msi);
        let mut held = open_verified_application_file_import(&receipt).unwrap();
        let staging_parent = Root::new();
        let workspace_parent = staging_parent.0.canonicalize().unwrap();
        let workspace = HeldRunWorkspace::create(&workspace_parent, "staging").unwrap();
        let staged = held
            .copy_to(workspace.create_tools_file_new("application.msi").unwrap())
            .unwrap();
        let expected_path = workspace.tools_path().join("application.msi");
        assert!(same_path(staged.final_path(), &expected_path));
        verify_payload(staged.as_file(), receipt.size_bytes, &receipt.sha256).unwrap();
        let identity = staged.identity().clone();
        drop(staged);
        let reopened = workspace.reopen_tools_file("application.msi").unwrap();
        assert_eq!(reopened.identity(), &identity);
        verify_payload(reopened.as_file(), receipt.size_bytes, &receipt.sha256).unwrap();
        held.revalidate().unwrap();
    }

    #[test]
    fn existing_intake_is_preserved_and_never_adopted() {
        let (root, receipt) = import_fixture(ApplicationInspectionKind::Exe);
        let source_path = root.0.join("second.exe");
        fs::write(&source_path, b"second-source").unwrap();
        let source = HeldApplicationFile::open(&source_path).unwrap();
        assert!(matches!(
            import_application_file(
                &root.0,
                "intake-001",
                ApplicationInspectionKind::Exe,
                &source
            ),
            Err(SourceImportError::Workspace(WorkspaceError::AlreadyExists))
        ));
        verify_application_file_import(&receipt).unwrap();
    }

    #[test]
    fn incomplete_intake_is_preserved_and_same_id_retry_is_rejected() {
        let root = Root::new();
        let partial = CreatedWorkspaceDirectory::create_protected(&root.0, "partial-001").unwrap();
        partial.create_directory_new(SOURCE_DIRECTORY_LEAF).unwrap();
        drop(partial);
        let source_path = root.0.join("source.exe");
        fs::write(&source_path, b"source").unwrap();
        let source = HeldApplicationFile::open(&source_path).unwrap();
        assert!(matches!(
            import_application_file(
                &root.0,
                "partial-001",
                ApplicationInspectionKind::Exe,
                &source
            ),
            Err(SourceImportError::Workspace(WorkspaceError::AlreadyExists))
        ));
        assert!(root.0.join("partial-001").is_dir());
        assert!(!root.0.join("partial-001").join(RECEIPT_LEAF).exists());
    }

    #[test]
    fn interrupted_payload_and_receipt_publication_states_are_preserved_and_rejected() {
        for copied in [false, true] {
            let root = Root::new();
            let intake_id = if copied {
                "payload-flushed"
            } else {
                "payload-created"
            };
            let intake = CreatedWorkspaceDirectory::create_protected(&root.0, intake_id).unwrap();
            let source_directory = intake.create_directory_new(SOURCE_DIRECTORY_LEAF).unwrap();
            let mut payload = source_directory.create_file_new("payload.exe").unwrap();
            if copied {
                payload
                    .as_file_mut()
                    .write_all(b"interrupted-copy")
                    .unwrap();
                payload.as_file_mut().flush().unwrap();
                payload.as_file().sync_all().unwrap();
            }
            drop((payload, source_directory, intake));
            let intake_path = root.0.join(intake_id);
            assert!(intake_path.join("source/payload.exe").is_file());
            assert!(!intake_path.join(RECEIPT_LEAF).exists());

            let source_path = root.0.join("retry.exe");
            fs::write(&source_path, b"retry").unwrap();
            let source = HeldApplicationFile::open(&source_path).unwrap();
            assert!(matches!(
                import_application_file(
                    &root.0,
                    intake_id,
                    ApplicationInspectionKind::Exe,
                    &source
                ),
                Err(SourceImportError::Workspace(WorkspaceError::AlreadyExists))
            ));
            assert!(intake_path.join("source/payload.exe").is_file());
        }

        for bytes in [b"".as_slice(), b"{".as_slice()] {
            let (root, receipt) = import_fixture(ApplicationInspectionKind::Exe);
            let receipt_path = Path::new(&receipt.intake_root.final_path).join(RECEIPT_LEAF);
            fs::write(&receipt_path, bytes).unwrap();
            assert!(verify_application_file_import(&receipt).is_err());

            let source_path = root.0.join("retry.exe");
            fs::write(&source_path, b"retry").unwrap();
            let source = HeldApplicationFile::open(&source_path).unwrap();
            assert!(matches!(
                import_application_file(
                    &root.0,
                    &receipt.intake_id,
                    ApplicationInspectionKind::Exe,
                    &source
                ),
                Err(SourceImportError::Workspace(WorkspaceError::AlreadyExists))
            ));
            assert_eq!(fs::read(receipt_path).unwrap(), bytes);
        }
    }

    #[test]
    fn active_writers_block_read_only_verification_authority() {
        let (_parent_root, parent_receipt) = import_fixture(ApplicationInspectionKind::Exe);
        let parent_path = Path::new(&parent_receipt.intake_root.final_path)
            .parent()
            .unwrap();
        let parent_writer = OpenOptions::new()
            .access_mode(FILE_ADD_FILE.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(parent_path)
            .unwrap();
        assert!(verify_application_file_import(&parent_receipt).is_err());
        drop(parent_writer);
        verify_application_file_import(&parent_receipt).unwrap();

        for select_path in [0, 1, 2, 3] {
            let (_root, receipt) = import_fixture(ApplicationInspectionKind::Exe);
            let root_path = Path::new(&receipt.intake_root.final_path);
            let source_path = Path::new(&receipt.source_directory.final_path);
            let receipt_path = root_path.join(RECEIPT_LEAF);
            if select_path < 2 {
                let path = [root_path, source_path][select_path];
                let writer = OpenOptions::new()
                    .access_mode(FILE_ADD_FILE.0)
                    .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
                    .open(path)
                    .unwrap();
                assert!(verify_application_file_import(&receipt).is_err());
                drop(writer);
                continue;
            }
            let path = [
                Path::new(&receipt.payload.final_path),
                receipt_path.as_path(),
            ][select_path - 2];
            let writer = OpenOptions::new().write(true).open(path).unwrap();
            assert!(verify_application_file_import(&receipt).is_err());
            drop(writer);
        }
    }

    #[test]
    fn payload_receipt_and_namespace_tampering_fail_read_only_verification() {
        let (root, receipt) = import_fixture(ApplicationInspectionKind::Exe);
        fs::write(&receipt.payload.final_path, b"tampered").unwrap();
        assert!(verify_application_file_import(&receipt).is_err());

        let (root_two, receipt_two) = import_fixture(ApplicationInspectionKind::Exe);
        fs::write(
            Path::new(&receipt_two.intake_root.final_path).join("unexpected.txt"),
            b"unexpected",
        )
        .unwrap();
        assert!(verify_application_file_import(&receipt_two).is_err());

        let (root_three, receipt_three) = import_fixture(ApplicationInspectionKind::Exe);
        fs::write(
            Path::new(&receipt_three.intake_root.final_path).join(RECEIPT_LEAF),
            b"{}",
        )
        .unwrap();
        assert!(verify_application_file_import(&receipt_three).is_err());

        let (root_four, receipt_four) = import_fixture(ApplicationInspectionKind::Exe);
        let original_permissions = fs::metadata(&receipt_four.payload.final_path)
            .unwrap()
            .permissions();
        let mut readonly_permissions = original_permissions.clone();
        readonly_permissions.set_readonly(true);
        fs::set_permissions(&receipt_four.payload.final_path, readonly_permissions).unwrap();
        assert!(verify_application_file_import(&receipt_four).is_err());
        fs::set_permissions(&receipt_four.payload.final_path, original_permissions).unwrap();

        drop((root, root_two, root_three, root_four));
    }

    #[test]
    fn externally_tampered_receipt_and_portable_kind_are_rejected() {
        let (_root, receipt) = import_fixture(ApplicationInspectionKind::Msi);
        let mut legacy = receipt.clone();
        legacy.schema_version = "aiw.dev/application-file-import-receipt/v0alpha1".to_owned();
        assert!(matches!(
            verify_application_file_import(&legacy),
            Err(SourceImportError::Contract(_))
        ));
        let mut changed = receipt.clone();
        changed.sha256 = "0".repeat(64);
        assert!(matches!(
            verify_application_file_import(&changed),
            Err(SourceImportError::Contract(_))
        ));
        let mut malformed_source = receipt.clone();
        malformed_source.source.identity.final_path = "relative\\setup.msi".to_owned();
        assert!(matches!(
            verify_application_file_import(&malformed_source),
            Err(SourceImportError::Contract(_))
        ));
        let mut malformed_volume = receipt.clone();
        malformed_volume.source.identity.volume_serial_number = "A".repeat(16);
        assert!(matches!(
            verify_application_file_import(&malformed_volume),
            Err(SourceImportError::Contract(_))
        ));
        let mut changed_eas = receipt.clone();
        changed_eas.payload_eas.canonical_sha256 = "0".repeat(64);
        assert!(verify_application_file_import(&changed_eas).is_err());

        let root = Root::new();
        let source_path = root.0.join("source.exe");
        fs::write(&source_path, b"source").unwrap();
        let source = HeldApplicationFile::open(&source_path).unwrap();
        assert!(matches!(
            import_application_file(
                &root.0,
                "portable-rejected",
                ApplicationInspectionKind::PortableDirectory,
                &source
            ),
            Err(SourceImportError::Contract(_))
        ));
        assert!(!root.0.join("portable-rejected").exists());
        assert!(matches!(
            import_application_file(
                &root.0,
                "kind-mismatch",
                ApplicationInspectionKind::Msi,
                &source
            ),
            Err(SourceImportError::Contract(_))
        ));
        assert!(!root.0.join("kind-mismatch").exists());
    }
}
