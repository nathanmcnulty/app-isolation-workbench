//! Receipt-last protected import for one already-held portable directory.
//!
//! Source bytes are copied only through handles retained by source inspection.
//! Existing intake identifiers are never opened, adopted, repaired, or removed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};

use aiw_probe::{
    ApplicationFileEaAuthority, ApplicationFileEaEntry, ApplicationInspectionKind,
    PORTABLE_DIRECTORY_AUTHORITY_SCHEMA, PORTABLE_DIRECTORY_IMPORT_RECEIPT_SCHEMA,
    PORTABLE_DIRECTORY_IMPORT_VERIFICATION_SCHEMA, PORTABLE_MANIFEST_SCHEMA, PortableContentEntry,
    PortableContentEntryKind, PortableDirectoryImportReceipt, PortableDirectoryImportVerification,
    PortableImportEntry, WindowsFileIdentity,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT};

use crate::exact_dispose::{
    ExactDisposeError, ExtendedAttributeBinding, FORBIDDEN_ATTRIBUTES, basic_info, file_size,
    hash_file, query_extended_attributes_for_import, reject_case_sensitive_directory,
    source_directory_entries, stabilized_extended_attributes, standard_info, verify_stream_policy,
};
use crate::source_inspection::{HeldPortableDirectory, SourceInspectionError};
use crate::workspace::{
    BoundWorkspaceDirectory, BoundWorkspaceFile, CreatedWorkspaceDirectory, WorkspaceAclPolicy,
    WorkspaceError, same_path, validate_new_child_leaf,
};

const RECEIPT_LEAF: &str = "intake.json";
const SOURCE_LEAF: &str = "source";
const PAYLOAD_LEAF: &str = "payload";
const MAX_IMPORT_ENTRIES: usize = 2_048;
const MAX_AGGREGATE_PATH_BYTES: usize = 4 * 1024 * 1024;
const MAX_FINAL_PATH_BYTES: usize = 4_096;
const MAX_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum PortableImportError {
    #[error("protected portable intake workspace rejected the operation: {0}")]
    Workspace(#[from] WorkspaceError),
    #[error("held portable source rejected the operation: {0}")]
    Source(#[from] SourceInspectionError),
    #[error("protected portable intake contract is invalid: {0}")]
    Contract(String),
    #[error("protected portable intake exceeds a fixed bound")]
    Bounds,
    #[error("protected portable intake content or identity drifted")]
    Drift,
    #[error("protected portable intake content or identity drifted: {0}")]
    DriftAt(&'static str),
    #[error("protected portable intake serialization failed: {0}")]
    Serialization(String),
    #[error("protected portable intake native observation failed: {0}")]
    Native(String),
}

pub fn import_portable_directory(
    parent: &Path,
    intake_id: &str,
    source: &HeldPortableDirectory,
) -> Result<PortableDirectoryImportReceipt, PortableImportError> {
    preflight(parent, intake_id, source)?;

    let root = CreatedWorkspaceDirectory::create_protected(parent, intake_id)?;
    let source_directory = root.create_directory_new(SOURCE_LEAF)?;
    let payload = source_directory.create_directory_new(PAYLOAD_LEAF)?;
    let mut directories = BTreeMap::from([(String::new(), payload)]);
    let mut files = BTreeMap::new();
    let manifest = source
        .manifest()
        .entries
        .iter()
        .map(|entry| (entry.relative_path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();

    for source_object in source.copy_plan() {
        let relative_path = source_object.relative_path();
        let expected = manifest
            .get(relative_path)
            .ok_or(PortableImportError::Drift)?;
        if expected.kind != source_object.kind()
            || expected.size_bytes != source_object.size_bytes()
        {
            return Err(PortableImportError::Drift);
        }
        let (parent_path, leaf) = split_relative(relative_path)?;
        let destination_parent = directories
            .get(parent_path)
            .ok_or(PortableImportError::Drift)?;
        match source_object.kind() {
            PortableContentEntryKind::Directory => {
                let directory = destination_parent.create_directory_new(leaf)?;
                verify_directory(directory.as_file(), None)?;
                directories.insert(relative_path.to_owned(), directory);
            }
            PortableContentEntryKind::File => {
                let mut file = destination_parent.create_file_new(leaf)?;
                source_object.copy_file_to(file.as_file_mut())?;
                let expected_hash = expected.sha256.as_deref().ok_or_else(|| {
                    PortableImportError::Contract("file manifest hash is missing".to_owned())
                })?;
                verify_file(file.as_file(), expected.size_bytes, expected_hash, None)?;
                file.revalidate()?;
                let identity = file.identity().clone();
                drop(file);
                let file = destination_parent.reopen_file_readonly(leaf)?;
                require_identity(file.identity(), &identity)?;
                verify_file(file.as_file(), expected.size_bytes, expected_hash, None)?;
                files.insert(relative_path.to_owned(), file);
            }
        }
    }

    // The traversal map holds separate read-only directory handles. The
    // authority map retains every original creation handle through publication.
    require_tree_names(&directories, source.manifest().entries.as_slice())?;
    require_names(source_directory.as_file(), &[PAYLOAD_LEAF])?;
    require_names(root.as_file(), &[SOURCE_LEAF])?;
    verify_directory(source_directory.as_file(), None)?;
    verify_directory(root.as_file(), None)?;
    source.revalidate()?;

    let mut receipt_file = root.create_file_new(RECEIPT_LEAF)?;
    let entries = build_entries(source.manifest().entries.as_slice(), &directories, &files)?;
    let payload_directory = directories.get("").ok_or(PortableImportError::Drift)?;
    let receipt = PortableDirectoryImportReceipt {
        schema_version: PORTABLE_DIRECTORY_IMPORT_RECEIPT_SCHEMA.to_owned(),
        intake_id: intake_id.to_owned(),
        source_kind: ApplicationInspectionKind::PortableDirectory,
        source_manifest: source.manifest().clone(),
        source_authority: source.authority().clone(),
        intake_root: root.identity().clone(),
        intake_root_eas: capture_eas(root.as_file(), true)?,
        source_directory: source_directory.identity().clone(),
        source_directory_eas: capture_eas(source_directory.as_file(), true)?,
        payload_directory: payload_directory.identity().clone(),
        payload_directory_eas: capture_eas(payload_directory.as_file(), true)?,
        entries,
        receipt: receipt_file.identity().clone(),
        entry_count: source.manifest().entries.len() as u32,
        total_size_bytes: source.manifest().total_size_bytes,
        manifest_sha256: source.manifest().manifest_sha256.clone(),
    };
    validate_receipt(&receipt)?;
    let receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|error| PortableImportError::Serialization(error.to_string()))?;
    if receipt_bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(PortableImportError::Bounds);
    }
    receipt_file
        .as_file_mut()
        .write_all(&receipt_bytes)
        .map_err(native)?;
    receipt_file.as_file_mut().flush().map_err(native)?;
    receipt_file.as_file().sync_all().map_err(native)?;
    verify_file(
        receipt_file.as_file(),
        receipt_bytes.len() as u64,
        &hex::encode(Sha256::digest(&receipt_bytes)),
        None,
    )?;
    require_allowed_receipt_eas(receipt_file.as_file())?;
    require_names(root.as_file(), &[RECEIPT_LEAF, SOURCE_LEAF])?;
    require_eas(root.as_file(), true, &receipt.intake_root_eas)?;
    require_eas(
        source_directory.as_file(),
        true,
        &receipt.source_directory_eas,
    )?;
    require_eas(
        payload_directory.as_file(),
        true,
        &receipt.payload_directory_eas,
    )?;
    verify_created_entries(&receipt.entries, &directories, &files)?;
    receipt_file.revalidate()?;

    drop(receipt_file);
    drop(files);
    drop(directories);
    drop(source_directory);
    drop(root);
    verify_portable_directory_import(&receipt)?;
    Ok(receipt)
}

pub fn verify_portable_directory_import(
    receipt: &PortableDirectoryImportReceipt,
) -> Result<PortableDirectoryImportVerification, PortableImportError> {
    validate_receipt(receipt)?;
    let root = BoundWorkspaceDirectory::reopen_protected(&receipt.intake_root)?;
    require_names(root.as_file(), &[RECEIPT_LEAF, SOURCE_LEAF])?;
    verify_directory(root.as_file(), None)?;
    require_eas(root.as_file(), true, &receipt.intake_root_eas)?;
    let source_directory =
        root.reopen_directory_readonly(SOURCE_LEAF, WorkspaceAclPolicy::Protected)?;
    require_identity(source_directory.identity(), &receipt.source_directory)?;
    require_names(source_directory.as_file(), &[PAYLOAD_LEAF])?;
    verify_directory(source_directory.as_file(), None)?;
    require_eas(
        source_directory.as_file(),
        true,
        &receipt.source_directory_eas,
    )?;
    let payload =
        source_directory.reopen_directory_readonly(PAYLOAD_LEAF, WorkspaceAclPolicy::Protected)?;
    require_identity(payload.identity(), &receipt.payload_directory)?;
    verify_directory(payload.as_file(), None)?;
    require_eas(payload.as_file(), true, &receipt.payload_directory_eas)?;

    let mut directories = BTreeMap::from([(String::new(), payload)]);
    let mut files: BTreeMap<String, BoundWorkspaceFile> = BTreeMap::new();
    for entry in &receipt.entries {
        let (parent_path, leaf) = split_relative(&entry.relative_path)?;
        let parent = directories
            .get(parent_path)
            .ok_or(PortableImportError::Drift)?;
        match entry.kind {
            PortableContentEntryKind::Directory => {
                let directory =
                    parent.reopen_directory_readonly(leaf, WorkspaceAclPolicy::Protected)?;
                require_identity(directory.identity(), &entry.identity)?;
                verify_directory(directory.as_file(), Some(entry.link_count))?;
                require_eas(directory.as_file(), true, &entry.eas)?;
                directories.insert(entry.relative_path.clone(), directory);
            }
            PortableContentEntryKind::File => {
                let file = parent.reopen_file_readonly(leaf)?;
                require_identity(file.identity(), &entry.identity)?;
                verify_file(
                    file.as_file(),
                    entry.size_bytes,
                    entry.sha256.as_deref().ok_or(PortableImportError::Drift)?,
                    Some(entry.link_count),
                )?;
                require_eas(file.as_file(), false, &entry.eas)?;
                files.insert(entry.relative_path.clone(), file);
            }
        }
    }
    require_tree_names(&directories, &receipt.source_manifest.entries)?;

    let internal_receipt = root.reopen_file_readonly(RECEIPT_LEAF)?;
    require_identity(internal_receipt.identity(), &receipt.receipt)?;
    let expected_bytes = serde_json::to_vec(receipt)
        .map_err(|error| PortableImportError::Serialization(error.to_string()))?;
    let actual_bytes = read_bounded(internal_receipt.as_file())?;
    if actual_bytes != expected_bytes {
        return Err(PortableImportError::DriftAt("receipt bytes changed"));
    }
    verify_file(
        internal_receipt.as_file(),
        expected_bytes.len() as u64,
        &hex::encode(Sha256::digest(&expected_bytes)),
        None,
    )?;
    require_allowed_receipt_eas(internal_receipt.as_file())?;
    for directory in directories.values() {
        directory.revalidate()?;
    }
    for file in files.values() {
        file.revalidate()?;
    }
    internal_receipt.revalidate()?;
    source_directory.revalidate()?;
    root.revalidate()?;
    Ok(PortableDirectoryImportVerification {
        schema_version: PORTABLE_DIRECTORY_IMPORT_VERIFICATION_SCHEMA.to_owned(),
        receipt_sha256: hex::encode(Sha256::digest(&expected_bytes)),
        intake_root: receipt.intake_root.clone(),
        payload_directory: receipt.payload_directory.clone(),
        manifest_sha256: receipt.manifest_sha256.clone(),
        entry_count: receipt.entry_count,
        verified_entries: receipt.entry_count,
        verified: true,
    })
}

fn preflight(
    parent: &Path,
    intake_id: &str,
    source: &HeldPortableDirectory,
) -> Result<(), PortableImportError> {
    validate_source_contract(source.manifest(), source.authority())?;
    if source.manifest().entries.len() > MAX_IMPORT_ENTRIES {
        return Err(PortableImportError::Bounds);
    }
    let parent = parent
        .canonicalize()
        .map_err(|_| WorkspaceError::InvalidParent)?;
    let projected_payload = parent.join(intake_id).join(SOURCE_LEAF).join(PAYLOAD_LEAF);
    let mut path_bytes = 0_usize;
    for (manifest, authority) in source
        .manifest()
        .entries
        .iter()
        .zip(&source.authority().entries)
    {
        for segment in manifest.relative_path.split('/') {
            validate_new_child_leaf(segment)?;
        }
        let destination = projected_payload.join(manifest.relative_path.replace('/', "\\"));
        for value in [
            manifest.relative_path.as_str(),
            authority.identity.final_path.as_str(),
            destination.to_str().ok_or_else(|| {
                PortableImportError::Contract("projected path is not Unicode".to_owned())
            })?,
        ] {
            if value.len() > MAX_FINAL_PATH_BYTES {
                return Err(PortableImportError::Bounds);
            }
            path_bytes = path_bytes
                .checked_add(value.len())
                .filter(|value| *value <= MAX_AGGREGATE_PATH_BYTES)
                .ok_or(PortableImportError::Bounds)?;
        }
    }
    // This is the final operation before create_protected. A stale held
    // namespace must not cause even an incomplete destination root.
    source.revalidate()?;
    Ok(())
}

fn validate_receipt(receipt: &PortableDirectoryImportReceipt) -> Result<(), PortableImportError> {
    if receipt.schema_version != PORTABLE_DIRECTORY_IMPORT_RECEIPT_SCHEMA
        || receipt.source_kind != ApplicationInspectionKind::PortableDirectory
        || receipt.entry_count as usize != receipt.entries.len()
        || receipt.entries.len() > MAX_IMPORT_ENTRIES
        || receipt.source_manifest.entries.len() != receipt.entries.len()
        || receipt.total_size_bytes > MAX_TOTAL_BYTES
        || !valid_identity(&receipt.intake_root)
        || !valid_identity(&receipt.source_directory)
        || !valid_identity(&receipt.payload_directory)
        || !valid_identity(&receipt.receipt)
        || !valid_eas(&receipt.intake_root_eas)
        || !valid_eas(&receipt.source_directory_eas)
        || !valid_eas(&receipt.payload_directory_eas)
    {
        return contract("receipt header is invalid");
    }
    validate_source_contract(&receipt.source_manifest, &receipt.source_authority)?;
    if receipt.manifest_sha256 != receipt.source_manifest.manifest_sha256
        || receipt.total_size_bytes != receipt.source_manifest.total_size_bytes
        || receipt.entry_count as usize != receipt.source_manifest.entries.len()
    {
        return contract("receipt aggregate evidence is inconsistent");
    }
    validate_intake_id(&receipt.intake_id)?;
    let root = PathBuf::from(&receipt.intake_root.final_path);
    let source = root.join(SOURCE_LEAF);
    let payload = source.join(PAYLOAD_LEAF);
    if root.file_name().and_then(|value| value.to_str()) != Some(&receipt.intake_id)
        || !same_path(&source, &receipt.source_directory.final_path)
        || !same_path(&payload, &receipt.payload_directory.final_path)
        || !same_path(root.join(RECEIPT_LEAF), &receipt.receipt.final_path)
    {
        return contract("receipt destination paths are inconsistent");
    }
    let volume = &receipt.intake_root.volume_serial_number;
    if [
        &receipt.source_directory,
        &receipt.payload_directory,
        &receipt.receipt,
    ]
    .iter()
    .any(|identity| &identity.volume_serial_number != volume)
    {
        return contract("receipt destination volumes are inconsistent");
    }
    for ((entry, manifest), authority) in receipt
        .entries
        .iter()
        .zip(&receipt.source_manifest.entries)
        .zip(&receipt.source_authority.entries)
    {
        if entry.relative_path != manifest.relative_path
            || entry.kind != manifest.kind
            || entry.size_bytes != manifest.size_bytes
            || entry.sha256 != manifest.sha256
            || entry.relative_path != authority.relative_path
            || entry.kind != authority.kind
            || !valid_identity(&entry.identity)
            || !valid_eas(&entry.eas)
            || !entry.only_unnamed_data_stream
            || entry.link_count != 1
            || entry.identity.volume_serial_number != *volume
            || !same_path(
                payload.join(entry.relative_path.replace('/', "\\")),
                &entry.identity.final_path,
            )
        {
            return contract("receipt entry evidence is inconsistent");
        }
    }
    Ok(())
}

fn validate_source_contract(
    manifest: &aiw_probe::PortableContentManifest,
    authority: &aiw_probe::PortableDirectoryAuthority,
) -> Result<(), PortableImportError> {
    if manifest.schema_version != PORTABLE_MANIFEST_SCHEMA
        || authority.schema_version != PORTABLE_DIRECTORY_AUTHORITY_SCHEMA
        || manifest.manifest_sha256 != authority.manifest_sha256
        || manifest.entries.len() != authority.entries.len()
        || manifest.entries.len() > MAX_IMPORT_ENTRIES
        || manifest.total_size_bytes > MAX_TOTAL_BYTES
        || !valid_identity(&authority.root_identity)
    {
        return contract("source manifest authority is invalid");
    }
    let mut previous: Option<&str> = None;
    let mut total = 0_u64;
    for (entry, authority_entry) in manifest.entries.iter().zip(&authority.entries) {
        validate_relative(&entry.relative_path)?;
        if previous.is_some_and(|value| value >= entry.relative_path.as_str())
            || entry.relative_path != authority_entry.relative_path
            || entry.kind != authority_entry.kind
            || !valid_identity(&authority_entry.identity)
            || !authority_entry.only_unnamed_data_stream
            || authority_entry.link_count != 1
        {
            return contract("source entry domain is invalid");
        }
        match entry.kind {
            PortableContentEntryKind::Directory
                if entry.size_bytes != 0 || entry.sha256.is_some() =>
            {
                return contract("directory content evidence is invalid");
            }
            PortableContentEntryKind::File
                if entry
                    .sha256
                    .as_deref()
                    .is_none_or(|value| !valid_hex(value, 64)) =>
            {
                return contract("file content evidence is invalid");
            }
            _ => {}
        }
        total = total
            .checked_add(entry.size_bytes)
            .filter(|value| *value <= MAX_TOTAL_BYTES)
            .ok_or(PortableImportError::Bounds)?;
        previous = Some(&entry.relative_path);
    }
    if total != manifest.total_size_bytes
        || manifest_hash(&manifest.entries)? != manifest.manifest_sha256
    {
        return contract("source manifest aggregate is invalid");
    }
    Ok(())
}

fn build_entries(
    manifest: &[PortableContentEntry],
    directories: &BTreeMap<String, CreatedWorkspaceDirectory>,
    files: &BTreeMap<String, BoundWorkspaceFile>,
) -> Result<Vec<PortableImportEntry>, PortableImportError> {
    manifest
        .iter()
        .map(|entry| {
            let (file, identity) = match entry.kind {
                PortableContentEntryKind::Directory => {
                    let object = directories
                        .get(&entry.relative_path)
                        .ok_or(PortableImportError::Drift)?;
                    (object.as_file(), object.identity())
                }
                PortableContentEntryKind::File => {
                    let object = files
                        .get(&entry.relative_path)
                        .ok_or(PortableImportError::Drift)?;
                    (object.as_file(), object.identity())
                }
            };
            let standard = standard_info(file).map_err(exact)?;
            Ok(PortableImportEntry {
                relative_path: entry.relative_path.clone(),
                kind: entry.kind,
                identity: identity.clone(),
                eas: capture_eas(file, entry.kind == PortableContentEntryKind::Directory)?,
                size_bytes: entry.size_bytes,
                sha256: entry.sha256.clone(),
                link_count: standard.NumberOfLinks,
                only_unnamed_data_stream: true,
            })
        })
        .collect()
}

fn verify_created_entries(
    entries: &[PortableImportEntry],
    directories: &BTreeMap<String, CreatedWorkspaceDirectory>,
    files: &BTreeMap<String, BoundWorkspaceFile>,
) -> Result<(), PortableImportError> {
    for entry in entries {
        match entry.kind {
            PortableContentEntryKind::Directory => {
                let object = directories
                    .get(&entry.relative_path)
                    .ok_or(PortableImportError::Drift)?;
                require_identity(object.identity(), &entry.identity)?;
                verify_directory(object.as_file(), Some(entry.link_count))?;
                require_eas(object.as_file(), true, &entry.eas)?;
                object.revalidate()?;
            }
            PortableContentEntryKind::File => {
                let object = files
                    .get(&entry.relative_path)
                    .ok_or(PortableImportError::Drift)?;
                require_identity(object.identity(), &entry.identity)?;
                verify_file(
                    object.as_file(),
                    entry.size_bytes,
                    entry.sha256.as_deref().ok_or(PortableImportError::Drift)?,
                    Some(entry.link_count),
                )?;
                require_eas(object.as_file(), false, &entry.eas)?;
                object.revalidate()?;
            }
        }
    }
    Ok(())
}

fn require_tree_names<D>(
    directories: &BTreeMap<String, D>,
    entries: &[PortableContentEntry],
) -> Result<(), PortableImportError>
where
    D: DirectoryHandle,
{
    let mut expected: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    expected.entry(String::new()).or_default();
    for entry in entries {
        let (parent, leaf) = split_relative(&entry.relative_path)?;
        expected.entry(parent.to_owned()).or_default().push(leaf);
        if entry.kind == PortableContentEntryKind::Directory {
            expected.entry(entry.relative_path.clone()).or_default();
        }
    }
    for (path, names) in expected {
        let directory = directories.get(&path).ok_or(PortableImportError::Drift)?;
        require_names(directory.directory_file(), &names)?;
    }
    Ok(())
}

trait DirectoryHandle {
    fn directory_file(&self) -> &File;
}

impl DirectoryHandle for CreatedWorkspaceDirectory {
    fn directory_file(&self) -> &File {
        self.as_file()
    }
}

impl DirectoryHandle for BoundWorkspaceDirectory {
    fn directory_file(&self) -> &File {
        self.as_file()
    }
}

fn verify_file(
    file: &File,
    size: u64,
    hash: &str,
    links: Option<u32>,
) -> Result<(), PortableImportError> {
    let basic = basic_info(file).map_err(exact)?;
    let standard = standard_info(file).map_err(exact)?;
    if basic.dwFileAttributes
        & (FORBIDDEN_ATTRIBUTES | FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_REPARSE_POINT.0)
        != 0
        || links.is_some_and(|value| value != standard.NumberOfLinks)
        || standard.NumberOfLinks != 1
        || file_size(file).map_err(exact)? != size
    {
        return Err(PortableImportError::DriftAt("file shape changed"));
    }
    verify_stream_policy(file, false, size).map_err(exact)?;
    if hex::encode(hash_file(file, size).map_err(exact)?) != hash {
        return Err(PortableImportError::DriftAt("file content changed"));
    }
    Ok(())
}

fn verify_directory(file: &File, links: Option<u32>) -> Result<(), PortableImportError> {
    let basic = basic_info(file).map_err(exact)?;
    let standard = standard_info(file).map_err(exact)?;
    if basic.dwFileAttributes & FORBIDDEN_ATTRIBUTES != 0
        || basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || links.is_some_and(|value| value != standard.NumberOfLinks)
    {
        return Err(PortableImportError::DriftAt("directory shape changed"));
    }
    reject_case_sensitive_directory(file).map_err(exact)?;
    verify_stream_policy(file, true, 0).map_err(exact)?;
    Ok(())
}

fn capture_eas(
    file: &File,
    directory: bool,
) -> Result<ApplicationFileEaAuthority, PortableImportError> {
    let binding = stabilized_extended_attributes(file, directory).map_err(exact)?;
    Ok(ea_authority(binding))
}

fn ea_authority(binding: ExtendedAttributeBinding) -> ApplicationFileEaAuthority {
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

fn require_eas(
    file: &File,
    directory: bool,
    expected: &ApplicationFileEaAuthority,
) -> Result<(), PortableImportError> {
    if capture_eas(file, directory)? != *expected {
        return Err(PortableImportError::DriftAt("extended attributes changed"));
    }
    Ok(())
}

fn require_allowed_receipt_eas(file: &File) -> Result<(), PortableImportError> {
    query_extended_attributes_for_import(file, false)
        .map(|_| ())
        .map_err(exact)
}

fn require_names(file: &File, expected: &[&str]) -> Result<(), PortableImportError> {
    let actual = source_directory_entries(file)
        .map_err(exact)?
        .into_iter()
        .map(|entry| entry.name)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().map(|value| (*value).to_owned()).collect();
    if actual != expected {
        return Err(PortableImportError::DriftAt("directory names changed"));
    }
    Ok(())
}

fn read_bounded(file: &File) -> Result<Vec<u8>, PortableImportError> {
    let size = file_size(file).map_err(exact)?;
    if size > MAX_RECEIPT_BYTES {
        return Err(PortableImportError::Bounds);
    }
    let mut bytes = vec![0; size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = file
            .seek_read(&mut bytes[offset..], offset as u64)
            .map_err(native)?;
        if count == 0 {
            return Err(PortableImportError::Drift);
        }
        offset += count;
    }
    if file_size(file).map_err(exact)? != size {
        return Err(PortableImportError::Drift);
    }
    Ok(bytes)
}

fn manifest_hash(entries: &[PortableContentEntry]) -> Result<String, PortableImportError> {
    let mut digest = Sha256::new();
    for entry in entries {
        let path = entry.relative_path.as_bytes();
        digest.update((path.len() as u64).to_le_bytes());
        digest.update(path);
        digest.update([match entry.kind {
            PortableContentEntryKind::Directory => 0,
            PortableContentEntryKind::File => 1,
        }]);
        digest.update(entry.size_bytes.to_le_bytes());
        if let Some(hash) = &entry.sha256 {
            digest.update(hex::decode(hash).map_err(|_| PortableImportError::Drift)?);
        }
    }
    Ok(hex::encode(digest.finalize()))
}

fn validate_relative(value: &str) -> Result<(), PortableImportError> {
    if value.is_empty() || value.len() > 1_024 || value.starts_with('/') || value.ends_with('/') {
        return contract("relative path is invalid");
    }
    for segment in value.split('/') {
        validate_new_child_leaf(segment)?;
    }
    Ok(())
}

fn split_relative(value: &str) -> Result<(&str, &str), PortableImportError> {
    validate_relative(value)?;
    Ok(value.rsplit_once('/').unwrap_or(("", value)))
}

fn validate_intake_id(value: &str) -> Result<(), PortableImportError> {
    if value.is_empty()
        || value.len() > 80
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !value.as_bytes()[0].is_ascii_alphanumeric()
    {
        return contract("intake identifier is invalid");
    }
    Ok(())
}

fn valid_identity(value: &WindowsFileIdentity) -> bool {
    Path::new(&value.final_path).is_absolute()
        && value.final_path.len() <= MAX_FINAL_PATH_BYTES
        && valid_hex(&value.volume_serial_number, 16)
        && valid_hex(&value.file_id, 32)
}

fn valid_eas(value: &ApplicationFileEaAuthority) -> bool {
    valid_hex(&value.canonical_sha256, 64)
        && value.entries.len() <= 4
        && value.entries.iter().all(|entry| {
            !entry.name.is_empty()
                && entry.name.is_ascii()
                && usize::from(entry.value_length) <= 64 * 1024
                && valid_hex(&entry.value_sha256, 64)
        })
}

fn valid_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn require_identity(
    actual: &WindowsFileIdentity,
    expected: &WindowsFileIdentity,
) -> Result<(), PortableImportError> {
    if actual != expected {
        return Err(PortableImportError::DriftAt("object identity changed"));
    }
    Ok(())
}

fn contract<T>(message: &str) -> Result<T, PortableImportError> {
    Err(PortableImportError::Contract(message.to_owned()))
}

fn exact(error: ExactDisposeError) -> PortableImportError {
    PortableImportError::Native(error.to_string())
}

fn native(error: impl std::fmt::Display) -> PortableImportError {
    PortableImportError::Native(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
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
                "aiw-portable-import-{}-{}",
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

    #[test]
    fn nested_portable_import_verifies_independently() {
        let root = Root::new();
        let source_path = root.0.join("portable");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(source_path.join("bin")).unwrap();
        fs::create_dir(source_path.join("empty")).unwrap();
        fs::write(source_path.join("bin").join("app.exe"), b"portable-app").unwrap();
        fs::write(source_path.join("readme.txt"), b"readme").unwrap();
        let held = HeldPortableDirectory::open(&source_path).unwrap();
        let receipt = import_portable_directory(&root.0, "portable-001", &held).unwrap();
        let verification = verify_portable_directory_import(&receipt).unwrap();
        assert!(verification.verified);
        assert_eq!(verification.verified_entries, 4);
        assert_eq!(
            fs::read(
                Path::new(&receipt.payload_directory.final_path)
                    .join("bin")
                    .join("app.exe")
            )
            .unwrap(),
            b"portable-app"
        );
    }

    #[test]
    fn source_drift_fails_before_creating_an_intake_root() {
        let root = Root::new();
        let source_path = root.0.join("portable");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("app.exe"), b"portable-app").unwrap();
        let held = HeldPortableDirectory::open(&source_path).unwrap();
        fs::write(source_path.join("late.txt"), b"late namespace addition").unwrap();

        assert!(matches!(
            import_portable_directory(&root.0, "must-not-exist", &held),
            Err(PortableImportError::Source(SourceInspectionError::Drift))
        ));
        assert!(!root.0.join("must-not-exist").exists());
    }

    #[test]
    fn existing_partial_intake_is_preserved_and_not_adopted() {
        let root = Root::new();
        let partial = CreatedWorkspaceDirectory::create_protected(&root.0, "partial-001").unwrap();
        partial.create_directory_new(SOURCE_LEAF).unwrap();
        drop(partial);
        let source_path = root.0.join("portable");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("app.exe"), b"app").unwrap();
        let held = HeldPortableDirectory::open(&source_path).unwrap();
        assert!(matches!(
            import_portable_directory(&root.0, "partial-001", &held),
            Err(PortableImportError::Workspace(
                WorkspaceError::AlreadyExists
            ))
        ));
        assert!(root.0.join("partial-001").join(SOURCE_LEAF).is_dir());
        assert!(!root.0.join("partial-001").join(RECEIPT_LEAF).exists());
    }

    #[test]
    fn drift_active_parent_writer_and_receipt_prefixes_fail_closed() {
        let root = Root::new();
        let source_path = root.0.join("portable");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("app.exe"), b"portable-app").unwrap();
        let held = HeldPortableDirectory::open(&source_path).unwrap();
        let receipt = import_portable_directory(&root.0, "portable-drift", &held).unwrap();

        let parent = Path::new(&receipt.intake_root.final_path).parent().unwrap();
        let writer = OpenOptions::new()
            .access_mode(FILE_ADD_FILE.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(parent)
            .unwrap();
        assert!(verify_portable_directory_import(&receipt).is_err());
        drop(writer);
        verify_portable_directory_import(&receipt).unwrap();

        fs::write(
            Path::new(&receipt.payload_directory.final_path).join("app.exe"),
            b"tampered",
        )
        .unwrap();
        assert!(verify_portable_directory_import(&receipt).is_err());

        let root_two = Root::new();
        let source_two = root_two.0.join("portable");
        fs::create_dir(&source_two).unwrap();
        fs::write(source_two.join("app.exe"), b"portable-app").unwrap();
        let held_two = HeldPortableDirectory::open(&source_two).unwrap();
        let receipt_two =
            import_portable_directory(&root_two.0, "receipt-prefix", &held_two).unwrap();
        let receipt_path = Path::new(&receipt_two.intake_root.final_path).join(RECEIPT_LEAF);
        fs::write(&receipt_path, b"{").unwrap();
        assert!(verify_portable_directory_import(&receipt_two).is_err());
        assert!(matches!(
            import_portable_directory(&root_two.0, "receipt-prefix", &held_two),
            Err(PortableImportError::Workspace(
                WorkspaceError::AlreadyExists
            ))
        ));
        assert_eq!(fs::read(receipt_path).unwrap(), b"{");
    }

    #[test]
    fn unsupported_destination_name_fails_before_root_creation() {
        let root = Root::new();
        let source_path = root.0.join("portable");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("bad$.txt"), b"content").unwrap();
        let held = HeldPortableDirectory::open(&source_path).unwrap();
        assert!(import_portable_directory(&root.0, "must-not-exist", &held).is_err());
        assert!(!root.0.join("must-not-exist").exists());
    }
}
