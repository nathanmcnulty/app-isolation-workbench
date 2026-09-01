#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const APPLICATION_INSPECTION_SCHEMA: &str = "aiw.dev/application-inspection/v0alpha1";
pub const APPLICATION_FILE_AUTHORITY_SCHEMA: &str = "aiw.dev/application-file-authority/v0alpha1";
pub const APPLICATION_FILE_IMPORT_RECEIPT_SCHEMA: &str =
    "aiw.dev/application-file-import-receipt/v0alpha1";
pub const APPLICATION_FILE_IMPORT_VERIFICATION_SCHEMA: &str =
    "aiw.dev/application-file-import-verification/v0alpha1";
pub const PORTABLE_DIRECTORY_IMPORT_RECEIPT_SCHEMA: &str =
    "aiw.dev/portable-directory-import-receipt/v0alpha1";
pub const PORTABLE_DIRECTORY_IMPORT_VERIFICATION_SCHEMA: &str =
    "aiw.dev/portable-directory-import-verification/v0alpha1";
pub const PORTABLE_MANIFEST_SCHEMA: &str = "aiw.dev/portable-content-manifest/v0alpha1";
pub const PORTABLE_DIRECTORY_AUTHORITY_SCHEMA: &str =
    "aiw.dev/portable-directory-authority/v0alpha1";
const MAX_APPLICATION_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_PORTABLE_FILES: usize = 10_000;
const MAX_PORTABLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ApplicationInspectionKind {
    Msi,
    Exe,
    PortableDirectory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ObservedApplicationArchitecture {
    X64,
    X86,
    Arm64,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortableContentEntryKind {
    Directory,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableContentEntry {
    pub relative_path: String,
    pub kind: PortableContentEntryKind,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableContentManifest {
    pub schema_version: String,
    pub root_path: String,
    pub entries: Vec<PortableContentEntry>,
    pub total_size_bytes: u64,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationFileAuthority {
    pub schema_version: String,
    pub identity: WindowsFileIdentity,
    pub size_bytes: u64,
    pub sha256: String,
    pub link_count: u32,
    pub only_unnamed_data_stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationFileEaEntry {
    pub name: String,
    pub flags: u8,
    pub value_length: u16,
    pub value_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationFileEaAuthority {
    pub entries: Vec<ApplicationFileEaEntry>,
    pub canonical_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationFileImportReceipt {
    pub schema_version: String,
    pub intake_id: String,
    pub source_kind: ApplicationInspectionKind,
    pub source: ApplicationFileAuthority,
    pub intake_root: WindowsFileIdentity,
    pub intake_root_eas: ApplicationFileEaAuthority,
    pub source_directory: WindowsFileIdentity,
    pub source_directory_eas: ApplicationFileEaAuthority,
    pub payload_relative_path: String,
    pub payload: WindowsFileIdentity,
    pub payload_eas: ApplicationFileEaAuthority,
    pub receipt: WindowsFileIdentity,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationFileImportVerification {
    pub schema_version: String,
    pub receipt_sha256: String,
    pub intake_root: WindowsFileIdentity,
    pub payload: WindowsFileIdentity,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableImportEntry {
    pub relative_path: String,
    pub kind: PortableContentEntryKind,
    pub identity: WindowsFileIdentity,
    pub eas: ApplicationFileEaAuthority,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub link_count: u32,
    pub only_unnamed_data_stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableDirectoryImportReceipt {
    pub schema_version: String,
    pub intake_id: String,
    pub source_kind: ApplicationInspectionKind,
    pub source_manifest: PortableContentManifest,
    pub source_authority: PortableDirectoryAuthority,
    pub intake_root: WindowsFileIdentity,
    pub intake_root_eas: ApplicationFileEaAuthority,
    pub source_directory: WindowsFileIdentity,
    pub source_directory_eas: ApplicationFileEaAuthority,
    pub payload_directory: WindowsFileIdentity,
    pub payload_directory_eas: ApplicationFileEaAuthority,
    pub entries: Vec<PortableImportEntry>,
    pub receipt: WindowsFileIdentity,
    pub entry_count: u32,
    pub total_size_bytes: u64,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableDirectoryImportVerification {
    pub schema_version: String,
    pub receipt_sha256: String,
    pub intake_root: WindowsFileIdentity,
    pub payload_directory: WindowsFileIdentity,
    pub manifest_sha256: String,
    pub entry_count: u32,
    pub verified_entries: u32,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableEntryAuthority {
    pub relative_path: String,
    pub kind: PortableContentEntryKind,
    pub identity: WindowsFileIdentity,
    pub link_count: u32,
    pub only_unnamed_data_stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableDirectoryAuthority {
    pub schema_version: String,
    pub root_identity: WindowsFileIdentity,
    pub entries: Vec<PortableEntryAuthority>,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationInspection {
    pub schema_version: String,
    pub kind: ApplicationInspectionKind,
    pub canonical_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    pub architecture: ObservedApplicationArchitecture,
    pub signature_status: ReadinessState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_authority: Option<ApplicationFileAuthority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable_directory_authority: Option<PortableDirectoryAuthority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable_manifest: Option<PortableContentManifest>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ApplicationInspectionError {
    #[error("application source path is missing, inaccessible, or has the wrong type")]
    InvalidSource,
    #[error("application source extension does not match the explicitly selected type")]
    TypeMismatch,
    #[error("application source contains a link or reparse point")]
    LinkRejected,
    #[error("application source contains a non-Unicode, unsafe, or case-colliding path")]
    PathRejected,
    #[error("application source exceeds the fixed inspection bounds")]
    BoundsExceeded,
    #[error("application source changed while it was being inspected")]
    SourceDrift,
    #[error("application source could not be read")]
    Io,
}

const PROBED_TOOLS: &[&str] = &[
    "wsl.exe",
    "WindowsSandbox.exe",
    "wsb.exe",
    "MakeAppx.exe",
    "SignTool.exe",
    "wpr.exe",
    "wpa.exe",
    "gh.exe",
    "cargo.exe",
    "pwsh.exe",
];

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostProbe {
    pub schema_version: String,
    pub os: String,
    pub os_family: String,
    pub process_architecture: String,
    pub environment_architecture: BTreeMap<String, String>,
    pub discovered_tools: BTreeMap<String, Option<String>>,
    pub limitations: Vec<String>,
}

/// A deliberately conservative state.  `Unknown` and `NeedsElevation` are
/// blockers for provider execution; neither is interpreted as support.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReadinessState {
    Available,
    Missing,
    Unknown,
    NeedsElevation,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BinaryIdentity {
    pub canonical_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub version: Option<String>,
    pub signature_status: ReadinessState,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsPackageIdentity {
    pub name: String,
    pub full_name: String,
    pub family_name: String,
    pub publisher: String,
    pub publisher_id: String,
    pub version: String,
    pub architecture: String,
    pub signature_kind: String,
    pub status_ok: bool,
    pub install_location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogTrustIdentity {
    pub trust_kind: String,
    pub catalog_path: String,
    pub catalog_sha256: String,
    pub catalog_file_identity: WindowsFileIdentity,
    pub member_tag: String,
    pub trust_policy: String,
    pub verification_status: ReadinessState,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsFileIdentity {
    pub final_path: String,
    pub volume_serial_number: String,
    pub file_id: String,
}

pub const WINDOWS_WORKSPACE_SCHEMA_VERSION: &str = "aiw.dev/workspace-binding-evidence/v0alpha1";
pub const WINDOWS_WORKSPACE_SECURITY_POLICY: &str = "owner-system-full-control-protected-v1";
pub const WINDOWS_SYSTEM_SID: &str = "S-1-5-18";
pub const DISCARD_INTENT_BINDING_SCHEMA_VERSION: &str =
    "aiw.dev/wsb-discard-intent-binding/v0alpha1";
pub const DISCARD_INTENT_BINDING_POLICY_VERSION: &str = "owner-system-protected-single-file-v1";
pub const WSB_FIXED_TREE_INVENTORY_SCHEMA_VERSION: &str =
    "aiw.dev/wsb-fixed-tree-inventory/v0alpha1";
pub const WSB_FIXED_TREE_CONTRACT_VERSION: &str = "aiw.dev/wsb-fixed-tree/v1-19-objects";
pub const WSB_FIXED_TREE_DELETE_ORDER_VERSION: &str =
    "aiw.dev/wsb-fixed-tree-delete-order/v1-child-first-19-objects";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WsbFixedObjectKind {
    WorkspaceRoot,
    ToolsDirectory,
    OutputDirectory,
    RunsDirectory,
    LocksDirectory,
    RunDirectory,
    JournalHeadsDirectory,
    GuestAgent,
    PreparedPlan,
    WindowsSandboxPlan,
    PreparationReceipt,
    RunLock,
    AuthoritativePlan,
    PlanningImportReceipt,
    EventsJournal,
    RevocationRecord,
    JournalHead1,
    JournalHead2,
    JournalHead3,
}

pub const WSB_FIXED_OBJECT_ORDER: [WsbFixedObjectKind; 19] = [
    WsbFixedObjectKind::WorkspaceRoot,
    WsbFixedObjectKind::ToolsDirectory,
    WsbFixedObjectKind::OutputDirectory,
    WsbFixedObjectKind::RunsDirectory,
    WsbFixedObjectKind::LocksDirectory,
    WsbFixedObjectKind::RunDirectory,
    WsbFixedObjectKind::JournalHeadsDirectory,
    WsbFixedObjectKind::GuestAgent,
    WsbFixedObjectKind::PreparedPlan,
    WsbFixedObjectKind::WindowsSandboxPlan,
    WsbFixedObjectKind::PreparationReceipt,
    WsbFixedObjectKind::RunLock,
    WsbFixedObjectKind::AuthoritativePlan,
    WsbFixedObjectKind::PlanningImportReceipt,
    WsbFixedObjectKind::EventsJournal,
    WsbFixedObjectKind::RevocationRecord,
    WsbFixedObjectKind::JournalHead1,
    WsbFixedObjectKind::JournalHead2,
    WsbFixedObjectKind::JournalHead3,
];

pub const WSB_FIXED_OBJECT_DELETE_ORDER: [WsbFixedObjectKind; 19] = [
    WsbFixedObjectKind::JournalHead3,
    WsbFixedObjectKind::JournalHead2,
    WsbFixedObjectKind::JournalHead1,
    WsbFixedObjectKind::JournalHeadsDirectory,
    WsbFixedObjectKind::RevocationRecord,
    WsbFixedObjectKind::EventsJournal,
    WsbFixedObjectKind::PlanningImportReceipt,
    WsbFixedObjectKind::AuthoritativePlan,
    WsbFixedObjectKind::RunDirectory,
    WsbFixedObjectKind::RunLock,
    WsbFixedObjectKind::LocksDirectory,
    WsbFixedObjectKind::RunsDirectory,
    WsbFixedObjectKind::GuestAgent,
    WsbFixedObjectKind::ToolsDirectory,
    WsbFixedObjectKind::OutputDirectory,
    WsbFixedObjectKind::PreparationReceipt,
    WsbFixedObjectKind::WindowsSandboxPlan,
    WsbFixedObjectKind::PreparedPlan,
    WsbFixedObjectKind::WorkspaceRoot,
];

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbFixedTreeEaBinding {
    pub entries: Vec<DiscardIntentEaEntry>,
    pub canonical_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WsbFixedTreeAclPolicy {
    OwnerSystemProtected,
    OwnerSystemInherited,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WsbFixedTreeStreamPolicy {
    NoStreams,
    UnnamedDataOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbFixedObjectEvidence {
    pub kind: WsbFixedObjectKind,
    pub relative_path: String,
    pub id: DiscardIntentStableId,
    pub is_directory: bool,
    pub attributes: u32,
    pub link_count: u32,
    pub acl_policy: WsbFixedTreeAclPolicy,
    pub stream_policy: WsbFixedTreeStreamPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub ea: WsbFixedTreeEaBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsbFixedTreeInventoryEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub run_id: String,
    pub workspace: WorkspaceBindingEvidence,
    pub parent_id: DiscardIntentStableId,
    pub original_root: String,
    pub tombstone_leaf: String,
    pub objects: Vec<WsbFixedObjectEvidence>,
}

impl WsbFixedTreeInventoryEvidence {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != WSB_FIXED_TREE_INVENTORY_SCHEMA_VERSION
            || self.contract_version != WSB_FIXED_TREE_CONTRACT_VERSION
            || !valid_run_id(&self.run_id)
            || self.workspace.validate().is_err()
            || self.original_root != self.workspace.root.final_path
            || self.parent_id.volume_serial_number != self.workspace.parent.volume_serial_number
            || self.parent_id.file_id != self.workspace.parent.file_id
            || !valid_tombstone_leaf(&self.tombstone_leaf)
            || self.objects.len() != WSB_FIXED_OBJECT_ORDER.len()
        {
            return Err("fixed-tree inventory header is invalid");
        }
        let mut identities = BTreeSet::new();
        identities.insert((
            self.parent_id.volume_serial_number.as_str(),
            self.parent_id.file_id.as_str(),
        ));
        for (object, expected) in self.objects.iter().zip(WSB_FIXED_OBJECT_ORDER) {
            let identity = (
                object.id.volume_serial_number.as_str(),
                object.id.file_id.as_str(),
            );
            if object.kind != expected
                || object.relative_path != expected.relative_path(&self.run_id)
                || object.is_directory != expected.is_directory()
                || (object.attributes & 0x10 != 0) != object.is_directory
                || object.attributes & FIXED_TREE_FORBIDDEN_ATTRIBUTES != 0
                || !fixed_hex(&object.id.volume_serial_number, 16)
                || !fixed_hex(&object.id.file_id, 32)
                || object.id.volume_serial_number != self.parent_id.volume_serial_number
                || object.link_count == 0
                || (!object.is_directory && object.link_count != 1)
                || object.acl_policy != expected.acl_policy()
                || object.stream_policy != expected.stream_policy()
                || !valid_fixed_tree_ea(&object.ea, object.is_directory)
                || !identities.insert(identity)
            {
                return Err("fixed-tree object binding is invalid");
            }
            if object.is_directory {
                if object.size_bytes.is_some() || object.sha256.is_some() {
                    return Err("fixed-tree directory contains file metadata");
                }
            } else {
                let Some(size) = object.size_bytes else {
                    return Err("fixed-tree file metadata is invalid");
                };
                if size > expected.size_limit()
                    || (expected == WsbFixedObjectKind::RunLock && size != 0)
                    || (expected == WsbFixedObjectKind::GuestAgent && size == 0)
                    || object
                        .sha256
                        .as_deref()
                        .is_none_or(|hash| !fixed_hex(hash, 64))
                {
                    return Err("fixed-tree file metadata is invalid");
                }
            }
        }
        let id_matches = |kind: WsbFixedObjectKind, identity: &WindowsFileIdentity| {
            self.objects.iter().any(|object| {
                object.kind == kind
                    && object.id.volume_serial_number == identity.volume_serial_number
                    && object.id.file_id == identity.file_id
            })
        };
        if !id_matches(WsbFixedObjectKind::WorkspaceRoot, &self.workspace.root)
            || !id_matches(WsbFixedObjectKind::ToolsDirectory, &self.workspace.tools)
            || !id_matches(WsbFixedObjectKind::OutputDirectory, &self.workspace.output)
        {
            return Err("fixed-tree workspace identities do not match the inventory");
        }
        Ok(())
    }
}

impl WsbFixedObjectKind {
    const fn is_directory(self) -> bool {
        matches!(
            self,
            Self::WorkspaceRoot
                | Self::ToolsDirectory
                | Self::OutputDirectory
                | Self::RunsDirectory
                | Self::LocksDirectory
                | Self::RunDirectory
                | Self::JournalHeadsDirectory
        )
    }

    const fn acl_policy(self) -> WsbFixedTreeAclPolicy {
        if matches!(
            self,
            Self::WorkspaceRoot | Self::ToolsDirectory | Self::OutputDirectory
        ) {
            WsbFixedTreeAclPolicy::OwnerSystemProtected
        } else {
            WsbFixedTreeAclPolicy::OwnerSystemInherited
        }
    }

    const fn stream_policy(self) -> WsbFixedTreeStreamPolicy {
        if self.is_directory() {
            WsbFixedTreeStreamPolicy::NoStreams
        } else {
            WsbFixedTreeStreamPolicy::UnnamedDataOnly
        }
    }

    pub fn relative_path(self, run_id: &str) -> String {
        match self {
            Self::WorkspaceRoot => ".".to_owned(),
            Self::ToolsDirectory => "tools".to_owned(),
            Self::OutputDirectory => "output".to_owned(),
            Self::RunsDirectory => "runs".to_owned(),
            Self::LocksDirectory => "runs/.locks".to_owned(),
            Self::RunDirectory => format!("runs/{run_id}"),
            Self::JournalHeadsDirectory => format!("runs/{run_id}/journal-heads"),
            Self::GuestAgent => "tools/aiw-guest-agent.exe".to_owned(),
            Self::PreparedPlan => "plan.json".to_owned(),
            Self::WindowsSandboxPlan => "wsb-plan.json".to_owned(),
            Self::PreparationReceipt => "preparation.json".to_owned(),
            Self::RunLock => format!("runs/.locks/{run_id}.lock"),
            Self::AuthoritativePlan => format!("runs/{run_id}/plan.json"),
            Self::PlanningImportReceipt => {
                format!("runs/{run_id}/wsb-planning-import.json")
            }
            Self::EventsJournal => format!("runs/{run_id}/events.jsonl"),
            Self::RevocationRecord => format!("runs/{run_id}/wsb-revocation.json"),
            Self::JournalHead1 => {
                format!("runs/{run_id}/journal-heads/00000000000000000001.json")
            }
            Self::JournalHead2 => {
                format!("runs/{run_id}/journal-heads/00000000000000000002.json")
            }
            Self::JournalHead3 => {
                format!("runs/{run_id}/journal-heads/00000000000000000003.json")
            }
        }
    }

    pub const fn parent(self) -> Option<Self> {
        match self {
            Self::WorkspaceRoot => None,
            Self::ToolsDirectory
            | Self::OutputDirectory
            | Self::RunsDirectory
            | Self::PreparedPlan
            | Self::WindowsSandboxPlan
            | Self::PreparationReceipt => Some(Self::WorkspaceRoot),
            Self::GuestAgent => Some(Self::ToolsDirectory),
            Self::LocksDirectory | Self::RunDirectory => Some(Self::RunsDirectory),
            Self::RunLock => Some(Self::LocksDirectory),
            Self::JournalHeadsDirectory
            | Self::AuthoritativePlan
            | Self::PlanningImportReceipt
            | Self::EventsJournal
            | Self::RevocationRecord => Some(Self::RunDirectory),
            Self::JournalHead1 | Self::JournalHead2 | Self::JournalHead3 => {
                Some(Self::JournalHeadsDirectory)
            }
        }
    }

    const fn size_limit(self) -> u64 {
        match self {
            Self::GuestAgent => 128 * 1024 * 1024,
            Self::EventsJournal => 64 * 1024 * 1024,
            Self::WorkspaceRoot
            | Self::ToolsDirectory
            | Self::OutputDirectory
            | Self::RunsDirectory
            | Self::LocksDirectory
            | Self::RunDirectory
            | Self::JournalHeadsDirectory => 0,
            _ => 1024 * 1024,
        }
    }
}

const FIXED_TREE_FORBIDDEN_ATTRIBUTES: u32 = 0x0000_0001
    | 0x0000_0004
    | 0x0000_0040
    | 0x0000_0100
    | 0x0000_0200
    | 0x0000_0400
    | 0x0000_0800
    | 0x0000_1000
    | 0x0000_4000
    | 0x0000_8000
    | 0x0001_0000
    | 0x0002_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x0010_0000
    | 0x0040_0000;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceBindingEvidence {
    pub schema_version: String,
    pub policy: String,
    pub security_policy_sha256: String,
    pub owner_sid: String,
    pub dacl_protected: bool,
    pub allowed_sids: Vec<String>,
    pub parent: WindowsFileIdentity,
    pub root: WindowsFileIdentity,
    pub tools: WindowsFileIdentity,
    pub output: WindowsFileIdentity,
}

impl WorkspaceBindingEvidence {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != WINDOWS_WORKSPACE_SCHEMA_VERSION
            || self.policy != WINDOWS_WORKSPACE_SECURITY_POLICY
            || !self.dacl_protected
            || !valid_sid_text(&self.owner_sid)
            || self.owner_sid == WINDOWS_SYSTEM_SID
            || self.security_policy_sha256 != workspace_policy_hash(&self.owner_sid)
        {
            return Err("workspace policy binding is invalid");
        }
        if self.allowed_sids.len() != 2
            || !self
                .allowed_sids
                .iter()
                .any(|sid| sid == WINDOWS_SYSTEM_SID)
            || !self.allowed_sids.iter().any(|sid| sid == &self.owner_sid)
        {
            return Err("workspace allowlist is not owner-and-SYSTEM only");
        }
        for identity in [&self.parent, &self.root, &self.tools, &self.output] {
            if identity.final_path.is_empty()
                || identity.final_path.len() > 32_767
                || !fixed_hex(&identity.volume_serial_number, 16)
                || !fixed_hex(&identity.file_id, 32)
            {
                return Err("workspace file identity is invalid");
            }
        }
        let identities = [&self.parent, &self.root, &self.tools, &self.output];
        for (index, left) in identities.iter().enumerate() {
            if identities[index + 1..].iter().any(|right| {
                left.volume_serial_number == right.volume_serial_number
                    && left.file_id == right.file_id
            }) {
                return Err("workspace directory identities are not distinct");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardIntentStableId {
    pub volume_serial_number: String,
    pub file_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardIntentEaEntry {
    pub name: String,
    pub flags: u8,
    pub value_length: u16,
    pub value_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardIntentEaBinding {
    /// Bounded native query response length retained for diagnostics only.
    /// Identity is established by the canonical entries and digest below.
    pub queried_bytes: u32,
    pub entries: Vec<DiscardIntentEaEntry>,
    pub canonical_sha256: String,
}

/// Portable evidence required to reopen one exact staged or final authority.
/// EA values are never serialized; only bounded metadata and value hashes are
/// retained.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardIntentBindingEvidence {
    pub schema_version: String,
    pub policy_version: String,
    pub run_id: String,
    pub owner_sid: String,
    pub store_key: String,
    pub final_path: String,
    pub staging_leaf: String,
    pub parent_id: DiscardIntentStableId,
    pub intent_id: DiscardIntentStableId,
    pub intent_size: u64,
    pub intent_sha256: String,
    pub intent_ea: DiscardIntentEaBinding,
}

impl DiscardIntentBindingEvidence {
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn owner_sid(&self) -> &str {
        &self.owner_sid
    }
    pub fn store_key(&self) -> &str {
        &self.store_key
    }
    pub fn final_path(&self) -> &str {
        &self.final_path
    }
    pub fn parent_id(&self) -> &DiscardIntentStableId {
        &self.parent_id
    }
    pub fn intent_id(&self) -> &DiscardIntentStableId {
        &self.intent_id
    }
    pub fn intent_size(&self) -> u64 {
        self.intent_size
    }
    pub fn intent_sha256(&self) -> &str {
        &self.intent_sha256
    }
    pub fn intent_ea(&self) -> &DiscardIntentEaBinding {
        &self.intent_ea
    }
}

impl DiscardIntentStableId {
    pub fn volume_serial_number(&self) -> &str {
        &self.volume_serial_number
    }
    pub fn file_id(&self) -> &str {
        &self.file_id
    }
}

impl DiscardIntentEaBinding {
    pub fn queried_bytes(&self) -> u32 {
        self.queried_bytes
    }
    pub fn entries(&self) -> &[DiscardIntentEaEntry] {
        &self.entries
    }
    pub fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }
}

impl DiscardIntentEaEntry {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn flags(&self) -> u8 {
        self.flags
    }
    pub fn value_length(&self) -> u16 {
        self.value_length
    }
    pub fn value_sha256(&self) -> &str {
        &self.value_sha256
    }
}

#[must_use]
pub fn workspace_policy_hash(owner_sid: &str) -> String {
    let semantic = format!(
        "policy={WINDOWS_WORKSPACE_SECURITY_POLICY}\nowner={owner_sid}\nallow={owner_sid}:full:object-container-inherit\nallow={WINDOWS_SYSTEM_SID}:full:object-container-inherit\n"
    );
    hex::encode(Sha256::digest(semantic.as_bytes()))
}

fn fixed_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_run_id(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
    !value.is_empty()
        && value.len() <= 128
        && !value.ends_with('.')
        && !reserved
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_tombstone_leaf(value: &str) -> bool {
    value
        .strip_prefix(".aiw-discarded-v1-")
        .is_some_and(|suffix| fixed_hex(suffix, 64))
}

fn valid_fixed_tree_ea(value: &WsbFixedTreeEaBinding, directory: bool) -> bool {
    let valid_names = value.entries.is_empty()
        || (directory
            && value.entries.len() == 1
            && value.entries[0].name == "$KERNEL.SMARTLOCKER.ORIGINCLAIM")
        || (!directory
            && value.entries.len() == 2
            && value.entries[0].name == "$KERNEL.PURGE.SMARTLOCKER.VALID"
            && value.entries[1].name == "$KERNEL.SMARTLOCKER.ORIGINCLAIM")
        || (!directory
            && value.entries.len() == 3
            && value.entries[0].name == "$KERNEL.PURGE.SEC.FILEHASH"
            && value.entries[1].name == "$KERNEL.PURGE.SMARTLOCKER.VALID"
            && value.entries[2].name == "$KERNEL.SMARTLOCKER.ORIGINCLAIM");
    if !valid_names {
        return false;
    }
    let mut canonical = Vec::new();
    for entry in &value.entries {
        let Ok(name_length) = u16::try_from(entry.name.len()) else {
            return false;
        };
        let valid_length = if entry.name == "$KERNEL.PURGE.SMARTLOCKER.VALID" {
            entry.value_length == 4
        } else {
            entry.value_length > 0
        };
        let Ok(value_hash) = hex::decode(&entry.value_sha256) else {
            return false;
        };
        if entry.flags != 0
            || !valid_length
            || !fixed_hex(&entry.value_sha256, 64)
            || value_hash.len() != 32
        {
            return false;
        }
        canonical.extend_from_slice(&name_length.to_le_bytes());
        canonical.extend_from_slice(entry.name.as_bytes());
        canonical.push(entry.flags);
        canonical.extend_from_slice(&entry.value_length.to_le_bytes());
        canonical.extend_from_slice(&value_hash);
    }
    value.canonical_sha256 == hex::encode(Sha256::digest(canonical))
}

fn valid_sid_text(value: &str) -> bool {
    if value.len() < 7 || value.len() > 184 {
        return false;
    }
    let Some(components) = value.strip_prefix("S-1-") else {
        return false;
    };
    let components = components.split('-').collect::<Vec<_>>();
    !components.is_empty()
        && components.len() <= 17
        && components.iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && component.parse::<u64>().is_ok()
        })
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxCliProtocol {
    pub cli_version: String,
    pub protocol: String,
    pub list_schema: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxReadiness {
    pub schema_version: String,
    pub supported: bool,
    pub os_build: Option<u32>,
    pub process_architecture: String,
    pub virtualization: ReadinessState,
    pub sandbox_feature: ReadinessState,
    pub provider_binary: Option<BinaryIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_package: Option<WindowsPackageIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_trust: Option<CatalogTrustIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_file_identity: Option<WindowsFileIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_protocol: Option<WindowsSandboxCliProtocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_execution_alias: Option<String>,
    pub current_sessions: ReadinessState,
    #[serde(default)]
    pub current_session_ids: Vec<String>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[must_use]
pub fn probe_host() -> HostProbe {
    let environment_architecture = ["PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432"]
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|value| (key.to_owned(), value)))
        .collect();
    let discovered_tools = PROBED_TOOLS
        .iter()
        .map(|name| {
            (
                name.trim_end_matches(".exe").to_owned(),
                find_command(name).map(|path| path.to_string_lossy().into_owned()),
            )
        })
        .collect();

    HostProbe {
        schema_version: "aiw.dev/host-probe/v0alpha1".to_owned(),
        os: env::consts::OS.to_owned(),
        os_family: env::consts::FAMILY.to_owned(),
        process_architecture: env::consts::ARCH.to_owned(),
        environment_architecture,
        discovered_tools,
        limitations: vec![
            "This bootstrap probe discovers paths only; it does not verify Windows features, exports, versions, tokens, or effective isolation backends."
                .to_owned(),
        ],
    }
}

/// Read-only readiness assessment for the W1 Windows Sandbox provider.
///
/// It intentionally does not enable features, start providers, elevate, or
/// infer success from a binary being discoverable.  Feature and session state
/// require provider-specific inspection and remain a hard blocker until a
/// later approved capability probe can establish them.
#[must_use]
pub fn assess_windows_sandbox() -> WindowsSandboxReadiness {
    WindowsSandboxReadiness {
        schema_version: "aiw.dev/windows-sandbox-readiness/v0alpha1".to_owned(),
        supported: false,
        os_build: None,
        process_architecture: "unknown".to_owned(),
        virtualization: ReadinessState::Unknown,
        sandbox_feature: ReadinessState::Unknown,
        provider_binary: None,
        provider_package: None,
        catalog_trust: None,
        provider_file_identity: None,
        cli_protocol: None,
        app_execution_alias: None,
        current_sessions: ReadinessState::Unknown,
        current_session_ids: Vec::new(),
        blockers: vec!["AIW_WINDOWS_PLATFORM_UNAVAILABLE: trusted Windows platform/package verification is not implemented.".to_owned()],
        warnings: vec![
            "This assessment is read-only and never trusts PATH, environment state, shell utilities, or App Execution Aliases as execution authority."
                .to_owned(),
            "A discovered provider binary is not a signature, feature, session, or containment proof."
                .to_owned(),
        ],
    }
}

#[must_use]
pub fn measure_binary_identity(path: &Path) -> Option<BinaryIdentity> {
    let canonical_path = path.canonicalize().ok()?;
    let metadata = canonical_path.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let mut file = File::open(&canonical_path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let canonical_display = canonical_path.to_string_lossy();
    let canonical_path = canonical_display
        .strip_prefix("\\\\?\\")
        .unwrap_or(&canonical_display)
        .to_owned();
    Some(BinaryIdentity {
        canonical_path,
        sha256: hex::encode(digest.finalize()),
        size_bytes: metadata.len(),
        version: None,
        signature_status: ReadinessState::Unknown,
    })
}

pub fn inspect_application_source(
    path: &Path,
    kind: ApplicationInspectionKind,
) -> Result<ApplicationInspection, ApplicationInspectionError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ApplicationInspectionError::InvalidSource)?;
    reject_link(&metadata)?;
    let canonical = path
        .canonicalize()
        .map_err(|_| ApplicationInspectionError::InvalidSource)?;
    let canonical_path = display_path(&canonical)?;
    match kind {
        ApplicationInspectionKind::Msi | ApplicationInspectionKind::Exe => {
            if !metadata.is_file() {
                return Err(ApplicationInspectionError::InvalidSource);
            }
            let expected = if kind == ApplicationInspectionKind::Msi {
                "msi"
            } else {
                "exe"
            };
            if !canonical
                .extension()
                .is_some_and(|value| value.to_string_lossy().eq_ignore_ascii_case(expected))
            {
                return Err(ApplicationInspectionError::TypeMismatch);
            }
            reject_multiple_links(&metadata)?;
            let (sha256, size_bytes, architecture) = inspect_stable_file(
                &canonical,
                MAX_APPLICATION_FILE_BYTES,
                kind == ApplicationInspectionKind::Exe,
            )?;
            Ok(ApplicationInspection {
                schema_version: APPLICATION_INSPECTION_SCHEMA.to_owned(),
                kind,
                canonical_path,
                sha256: Some(sha256),
                size_bytes: Some(size_bytes),
                architecture,
                signature_status: ReadinessState::Unknown,
                file_authority: None,
                portable_directory_authority: None,
                portable_manifest: None,
                limitations: vec![
                    "Authenticode signer and trust have not yet been observed; unknown never means trusted.".to_owned(),
                    "Windows hard-link and alternate-stream inspection is not yet part of this read-only snapshot; it cannot authorize import.".to_owned(),
                    "Path checks are observational and do not exclude coordinated same-user replacement; protected import requires a later held-handle boundary.".to_owned(),
                    "Static identity does not execute the source or establish compatibility or containment.".to_owned(),
                ],
            })
        }
        ApplicationInspectionKind::PortableDirectory => {
            if !metadata.is_dir() {
                return Err(ApplicationInspectionError::InvalidSource);
            }
            let manifest = inspect_portable_directory(&canonical)?;
            Ok(ApplicationInspection {
                schema_version: APPLICATION_INSPECTION_SCHEMA.to_owned(),
                kind,
                canonical_path,
                sha256: None,
                size_bytes: Some(manifest.total_size_bytes),
                architecture: ObservedApplicationArchitecture::Unknown,
                signature_status: ReadinessState::Unknown,
                file_authority: None,
                portable_directory_authority: None,
                portable_manifest: Some(manifest),
                limitations: vec![
                    "Entry-point architectures and Authenticode signers have not yet been observed.".to_owned(),
                    "Windows hard-link and alternate-stream inspection is not yet part of this read-only snapshot; it cannot authorize import.".to_owned(),
                    "Portable traversal is path-based and does not exclude coordinated same-user replacement; protected import requires a later handle-relative boundary.".to_owned(),
                    "Static identity does not execute the source or establish compatibility or containment.".to_owned(),
                ],
            })
        }
    }
}

fn inspect_portable_directory(
    root: &Path,
) -> Result<PortableContentManifest, ApplicationInspectionError> {
    let first = capture_portable_directory(root)?;
    let second = capture_portable_directory(root)?;
    if first != second {
        return Err(ApplicationInspectionError::SourceDrift);
    }
    Ok(second)
}

fn capture_portable_directory(
    root: &Path,
) -> Result<PortableContentManifest, ApplicationInspectionError> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    let mut collision_keys = BTreeSet::new();
    let mut total_size_bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|_| ApplicationInspectionError::SourceDrift)?;
        reject_link(&metadata)?;
        if !metadata.is_dir() {
            return Err(ApplicationInspectionError::SourceDrift);
        }
        let children = fs::read_dir(&directory).map_err(|_| ApplicationInspectionError::Io)?;
        for child in children {
            let child = child.map_err(|_| ApplicationInspectionError::Io)?;
            let path = child.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| ApplicationInspectionError::SourceDrift)?;
            reject_link(&metadata)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| ApplicationInspectionError::PathRejected)?;
            let relative = safe_manifest_path(relative)?;
            let key = relative.to_ascii_lowercase();
            if !collision_keys.insert(key) {
                return Err(ApplicationInspectionError::PathRejected);
            }
            if entries.len() >= MAX_PORTABLE_FILES {
                return Err(ApplicationInspectionError::BoundsExceeded);
            }
            if metadata.is_dir() {
                entries.push(PortableContentEntry {
                    relative_path: relative,
                    kind: PortableContentEntryKind::Directory,
                    size_bytes: 0,
                    sha256: None,
                });
                pending.push(path);
            } else if metadata.is_file() {
                reject_multiple_links(&metadata)?;
                let remaining = MAX_PORTABLE_BYTES.saturating_sub(total_size_bytes);
                let (sha256, size_bytes, _) = inspect_stable_file(&path, remaining, false)?;
                total_size_bytes = total_size_bytes
                    .checked_add(size_bytes)
                    .ok_or(ApplicationInspectionError::BoundsExceeded)?;
                entries.push(PortableContentEntry {
                    relative_path: relative,
                    kind: PortableContentEntryKind::File,
                    size_bytes,
                    sha256: Some(sha256),
                });
            } else {
                return Err(ApplicationInspectionError::InvalidSource);
            }
        }
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let mut digest = Sha256::new();
    for entry in &entries {
        let path = entry.relative_path.as_bytes();
        digest.update((path.len() as u64).to_le_bytes());
        digest.update(path);
        digest.update([match entry.kind {
            PortableContentEntryKind::Directory => 0,
            PortableContentEntryKind::File => 1,
        }]);
        digest.update(entry.size_bytes.to_le_bytes());
        if let Some(sha256) = &entry.sha256 {
            digest.update(hex::decode(sha256).map_err(|_| ApplicationInspectionError::Io)?);
        }
    }
    Ok(PortableContentManifest {
        schema_version: PORTABLE_MANIFEST_SCHEMA.to_owned(),
        root_path: display_path(root)?,
        entries,
        total_size_bytes,
        manifest_sha256: hex::encode(digest.finalize()),
    })
}

fn inspect_stable_file(
    path: &Path,
    limit: u64,
    inspect_pe: bool,
) -> Result<(String, u64, ObservedApplicationArchitecture), ApplicationInspectionError> {
    let mut file = File::open(path).map_err(|_| ApplicationInspectionError::Io)?;
    let before = file
        .metadata()
        .map_err(|_| ApplicationInspectionError::Io)?;
    if before.len() > limit {
        return Err(ApplicationInspectionError::BoundsExceeded);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut observed = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ApplicationInspectionError::Io)?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .ok_or(ApplicationInspectionError::BoundsExceeded)?;
        if observed > limit {
            return Err(ApplicationInspectionError::BoundsExceeded);
        }
        digest.update(&buffer[..count]);
    }
    let architecture = if inspect_pe {
        inspect_pe_architecture(&mut file)?
    } else {
        ObservedApplicationArchitecture::Unknown
    };
    let after = file
        .metadata()
        .map_err(|_| ApplicationInspectionError::Io)?;
    if observed != before.len()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
    {
        return Err(ApplicationInspectionError::SourceDrift);
    }
    Ok((hex::encode(digest.finalize()), observed, architecture))
}

fn inspect_pe_architecture(
    file: &mut File,
) -> Result<ObservedApplicationArchitecture, ApplicationInspectionError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ApplicationInspectionError::Io)?;
    let mut dos = [0_u8; 64];
    if file.read_exact(&mut dos).is_err() || &dos[..2] != b"MZ" {
        return Ok(ObservedApplicationArchitecture::Unknown);
    }
    let offset = u32::from_le_bytes(
        dos[60..64]
            .try_into()
            .map_err(|_| ApplicationInspectionError::Io)?,
    ) as u64;
    if offset > 16 * 1024 * 1024 {
        return Ok(ObservedApplicationArchitecture::Unknown);
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| ApplicationInspectionError::Io)?;
    let mut header = [0_u8; 6];
    if file.read_exact(&mut header).is_err() || &header[..4] != b"PE\0\0" {
        return Ok(ObservedApplicationArchitecture::Unknown);
    }
    Ok(match u16::from_le_bytes([header[4], header[5]]) {
        0x8664 => ObservedApplicationArchitecture::X64,
        0x014c => ObservedApplicationArchitecture::X86,
        0xaa64 => ObservedApplicationArchitecture::Arm64,
        _ => ObservedApplicationArchitecture::Unknown,
    })
}

fn safe_manifest_path(path: &Path) -> Result<String, ApplicationInspectionError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(value) = component else {
            return Err(ApplicationInspectionError::PathRejected);
        };
        let value = value
            .to_str()
            .ok_or(ApplicationInspectionError::PathRejected)?;
        if value.is_empty()
            || !value.is_ascii()
            || value == "."
            || value == ".."
            || value.contains([':', '/', '\\'])
            || value.ends_with(['.', ' '])
            || value.bytes().any(|byte| byte < 32)
            || value.contains(['<', '>', '"', '|', '?', '*'])
            || is_reserved_windows_name(value)
        {
            return Err(ApplicationInspectionError::PathRejected);
        }
        parts.push(value);
    }
    let value = parts.join("/");
    if value.is_empty() || value.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(ApplicationInspectionError::PathRejected);
    }
    Ok(value)
}

fn is_reserved_windows_name(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
}

fn display_path(path: &Path) -> Result<String, ApplicationInspectionError> {
    let value = path
        .to_str()
        .ok_or(ApplicationInspectionError::PathRejected)?;
    Ok(value.strip_prefix("\\\\?\\").unwrap_or(value).to_owned())
}

fn reject_link(metadata: &fs::Metadata) -> Result<(), ApplicationInspectionError> {
    if metadata.file_type().is_symlink() || is_windows_reparse(metadata) {
        return Err(ApplicationInspectionError::LinkRejected);
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_windows_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

fn reject_multiple_links(metadata: &fs::Metadata) -> Result<(), ApplicationInspectionError> {
    if link_count(metadata) > 1 {
        Err(ApplicationInspectionError::LinkRejected)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn link_count(_metadata: &fs::Metadata) -> u64 {
    1
}

#[cfg(unix)]
fn link_count(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink()
}

#[cfg(not(any(windows, unix)))]
fn link_count(_metadata: &fs::Metadata) -> u64 {
    u64::MAX
}

/// Production package/alias/handle/signature verification belongs to the
/// future native platform boundary. This placeholder deliberately grants no
/// executable identity authority.
#[must_use]
pub fn measure_windows_sandbox_binary(_path: &Path) -> Option<BinaryIdentity> {
    None
}

#[must_use]
pub fn find_command(name: &str) -> Option<PathBuf> {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        return candidate.is_file().then(|| candidate.to_path_buf());
    }

    let path = env::var_os("PATH")?;
    let has_extension = candidate.extension().is_some();
    let extensions = if cfg!(windows) && !has_extension {
        env::var_os("PATHEXT")
            .map(|value| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|item| !item.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![".COM".to_owned(), ".EXE".to_owned()])
    } else {
        vec![String::new()]
    };

    for directory in env::split_paths(&path) {
        for extension in &extensions {
            let path = directory.join(format!("{name}{extension}"));
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_APPLICATION_INSPECTION: AtomicU64 = AtomicU64::new(1);

    struct InspectionRoot(PathBuf);

    impl InspectionRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aiw-application-inspection-{}-{}",
                std::process::id(),
                NEXT_APPLICATION_INSPECTION.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for InspectionRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixed_tree_inventory() -> WsbFixedTreeInventoryEvidence {
        let owner = "S-1-5-21-1".to_owned();
        let identity = |path: &str, marker: u8| WindowsFileIdentity {
            final_path: path.to_owned(),
            volume_serial_number: "0".repeat(16),
            file_id: format!("{marker:032x}"),
        };
        let workspace = WorkspaceBindingEvidence {
            schema_version: WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
            policy: WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
            security_policy_sha256: workspace_policy_hash(&owner),
            owner_sid: owner.clone(),
            dacl_protected: true,
            allowed_sids: vec![WINDOWS_SYSTEM_SID.to_owned(), owner],
            parent: identity("C:\\AIW", 1),
            root: identity("C:\\AIW\\run-one", 2),
            tools: identity("C:\\AIW\\run-one\\tools", 3),
            output: identity("C:\\AIW\\run-one\\output", 4),
        };
        let objects = WSB_FIXED_OBJECT_ORDER
            .into_iter()
            .enumerate()
            .map(|(index, kind)| {
                let file_id = match kind {
                    WsbFixedObjectKind::WorkspaceRoot => workspace.root.file_id.clone(),
                    WsbFixedObjectKind::ToolsDirectory => workspace.tools.file_id.clone(),
                    WsbFixedObjectKind::OutputDirectory => workspace.output.file_id.clone(),
                    _ => format!("{:032x}", index + 10),
                };
                WsbFixedObjectEvidence {
                    kind,
                    relative_path: kind.relative_path("run-one"),
                    id: DiscardIntentStableId {
                        volume_serial_number: "0".repeat(16),
                        file_id,
                    },
                    is_directory: kind.is_directory(),
                    attributes: if kind.is_directory() { 0x10 } else { 0x20 },
                    link_count: 1,
                    acl_policy: kind.acl_policy(),
                    stream_policy: kind.stream_policy(),
                    size_bytes: (!kind.is_directory()).then_some(
                        if kind == WsbFixedObjectKind::RunLock {
                            0
                        } else {
                            1
                        },
                    ),
                    sha256: (!kind.is_directory()).then(|| "a".repeat(64)),
                    ea: WsbFixedTreeEaBinding {
                        entries: Vec::new(),
                        canonical_sha256: hex::encode(Sha256::digest([])),
                    },
                }
            })
            .collect();
        WsbFixedTreeInventoryEvidence {
            schema_version: WSB_FIXED_TREE_INVENTORY_SCHEMA_VERSION.to_owned(),
            contract_version: WSB_FIXED_TREE_CONTRACT_VERSION.to_owned(),
            run_id: "run-one".to_owned(),
            workspace: workspace.clone(),
            parent_id: DiscardIntentStableId {
                volume_serial_number: workspace.parent.volume_serial_number.clone(),
                file_id: workspace.parent.file_id.clone(),
            },
            original_root: workspace.root.final_path.clone(),
            tombstone_leaf: format!(".aiw-discarded-v1-{}", "b".repeat(64)),
            objects,
        }
    }

    #[test]
    fn probe_has_an_explicit_limitation() {
        let probe = probe_host();
        assert_eq!(probe.schema_version, "aiw.dev/host-probe/v0alpha1");
        assert!(!probe.limitations.is_empty());
        assert!(probe.discovered_tools.contains_key("cargo"));
    }

    #[test]
    fn impossible_tool_is_not_found() {
        assert!(find_command("aiw-this-tool-does-not-exist-8f197f32").is_none());
    }

    #[test]
    fn workspace_binding_contract_rejects_policy_and_identity_tampering() {
        let owner = "S-1-5-21-1".to_owned();
        let identity = |path: &str, marker: u8| WindowsFileIdentity {
            final_path: path.to_owned(),
            volume_serial_number: "0".repeat(16),
            file_id: format!("{marker:032x}"),
        };
        let evidence = WorkspaceBindingEvidence {
            schema_version: WINDOWS_WORKSPACE_SCHEMA_VERSION.to_owned(),
            policy: WINDOWS_WORKSPACE_SECURITY_POLICY.to_owned(),
            security_policy_sha256: workspace_policy_hash(&owner),
            owner_sid: owner.clone(),
            dacl_protected: true,
            allowed_sids: vec![WINDOWS_SYSTEM_SID.to_owned(), owner],
            parent: identity("C:\\AIW", 1),
            root: identity("C:\\AIW\\run", 2),
            tools: identity("C:\\AIW\\run\\tools", 3),
            output: identity("C:\\AIW\\run\\output", 4),
        };
        evidence.validate().unwrap();
        assert_eq!(evidence.security_policy_sha256.len(), 64);

        let mut tampered = evidence.clone();
        tampered.dacl_protected = false;
        assert!(tampered.validate().is_err());
        let mut tampered = evidence.clone();
        tampered.output.file_id = tampered.root.file_id.clone();
        assert!(tampered.validate().is_err());
        let mut tampered = evidence;
        tampered.allowed_sids.push("S-1-5-32-544".to_owned());
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn sandbox_assessment_fails_closed_when_capabilities_are_unverified() {
        let readiness = assess_windows_sandbox();
        assert_eq!(
            readiness.schema_version,
            "aiw.dev/windows-sandbox-readiness/v0alpha1"
        );
        assert!(!readiness.supported);
        assert!(!readiness.blockers.is_empty());
        assert_eq!(readiness.sandbox_feature, ReadinessState::Unknown);
    }

    #[test]
    fn fixed_tree_inventory_is_exact_ordered_and_strict() {
        let evidence = fixed_tree_inventory();
        evidence.validate().unwrap();
        assert_eq!(evidence.objects.len(), 19);

        let mut reordered = evidence.clone();
        reordered.objects.swap(0, 1);
        assert!(reordered.validate().is_err());
        let mut duplicate = evidence.clone();
        duplicate.objects[1] = duplicate.objects[0].clone();
        assert!(duplicate.validate().is_err());
        let mut duplicate_id = evidence.clone();
        duplicate_id.objects[5].id = duplicate_id.objects[4].id.clone();
        assert!(duplicate_id.validate().is_err());
        let mut workspace_mismatch = evidence.clone();
        workspace_mismatch.objects[0].id.file_id = "f".repeat(32);
        assert!(workspace_mismatch.validate().is_err());
        let mut malformed = evidence.clone();
        malformed.objects[7].sha256 = Some("A".repeat(64));
        assert!(malformed.validate().is_err());
        let mut oversized = evidence.clone();
        oversized.objects[7].size_bytes = Some(128 * 1024 * 1024 + 1);
        assert!(oversized.validate().is_err());
        let mut forbidden_attribute = evidence.clone();
        forbidden_attribute.objects[7].attributes |= 0x400;
        assert!(forbidden_attribute.validate().is_err());
        let mut legacy_tombstone = evidence.clone();
        legacy_tombstone.tombstone_leaf = ".aiw-wsb-tombstone-run-one-deadbeef".to_owned();
        assert!(legacy_tombstone.validate().is_err());
    }

    #[test]
    fn fixed_tree_delete_order_is_complete_and_child_first() {
        assert_eq!(
            WSB_FIXED_TREE_DELETE_ORDER_VERSION,
            "aiw.dev/wsb-fixed-tree-delete-order/v1-child-first-19-objects"
        );
        assert_eq!(WSB_FIXED_OBJECT_DELETE_ORDER.len(), 19);
        assert_eq!(
            WSB_FIXED_OBJECT_DELETE_ORDER.last(),
            Some(&WsbFixedObjectKind::WorkspaceRoot)
        );
        for (child_index, child) in WSB_FIXED_OBJECT_DELETE_ORDER.iter().enumerate() {
            if let Some(parent) = child.parent() {
                let parent_index = WSB_FIXED_OBJECT_DELETE_ORDER
                    .iter()
                    .position(|candidate| *candidate == parent)
                    .expect("every fixed parent is in the delete order");
                assert!(
                    child_index < parent_index,
                    "{child:?} must precede {parent:?}"
                );
            }
        }
    }

    #[test]
    fn fixed_tree_inventory_json_rejects_unknown_fields() {
        let evidence = fixed_tree_inventory();
        let mut value = serde_json::to_value(evidence).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<WsbFixedTreeInventoryEvidence>(value).is_err());
    }

    #[test]
    fn fixed_tree_ea_binding_is_semantic_lowercase_and_canonical() {
        let canonical = |entries: &[DiscardIntentEaEntry]| {
            let mut bytes = Vec::new();
            for entry in entries {
                bytes.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
                bytes.extend_from_slice(entry.name.as_bytes());
                bytes.push(entry.flags);
                bytes.extend_from_slice(&entry.value_length.to_le_bytes());
                bytes.extend_from_slice(&hex::decode(&entry.value_sha256).unwrap());
            }
            hex::encode(Sha256::digest(bytes))
        };
        let entries = vec![
            DiscardIntentEaEntry {
                name: "$KERNEL.PURGE.SMARTLOCKER.VALID".to_owned(),
                flags: 0,
                value_length: 4,
                value_sha256: hex::encode(Sha256::digest([1_u8; 4])),
            },
            DiscardIntentEaEntry {
                name: "$KERNEL.SMARTLOCKER.ORIGINCLAIM".to_owned(),
                flags: 0,
                value_length: 16,
                value_sha256: hex::encode(Sha256::digest([2_u8; 16])),
            },
        ];
        let mut evidence = fixed_tree_inventory();
        evidence.objects[7].ea = WsbFixedTreeEaBinding {
            canonical_sha256: canonical(&entries),
            entries: entries.clone(),
        };
        evidence.validate().unwrap();

        let directory_entries = vec![DiscardIntentEaEntry {
            name: "$KERNEL.SMARTLOCKER.ORIGINCLAIM".to_owned(),
            flags: 0,
            value_length: 16,
            value_sha256: hex::encode(Sha256::digest([3_u8; 16])),
        }];
        let mut directory_origin = fixed_tree_inventory();
        directory_origin.objects[0].ea = WsbFixedTreeEaBinding {
            canonical_sha256: canonical(&directory_entries),
            entries: directory_entries,
        };
        directory_origin.validate().unwrap();

        let mut triple_entries = vec![DiscardIntentEaEntry {
            name: "$KERNEL.PURGE.SEC.FILEHASH".to_owned(),
            flags: 0,
            value_length: 32,
            value_sha256: hex::encode(Sha256::digest([4_u8; 32])),
        }];
        triple_entries.extend(entries.clone());
        let mut file_hash_triple = fixed_tree_inventory();
        file_hash_triple.objects[7].ea = WsbFixedTreeEaBinding {
            canonical_sha256: canonical(&triple_entries),
            entries: triple_entries,
        };
        file_hash_triple.validate().unwrap();

        let mut uppercase = evidence.clone();
        uppercase.objects[7].ea.entries[0].value_sha256 = uppercase.objects[7].ea.entries[0]
            .value_sha256
            .to_ascii_uppercase();
        assert!(uppercase.validate().is_err());
        let mut reordered = evidence.clone();
        reordered.objects[7].ea.entries.swap(0, 1);
        reordered.objects[7].ea.canonical_sha256 = canonical(&reordered.objects[7].ea.entries);
        assert!(reordered.validate().is_err());
        let mut flags = evidence.clone();
        flags.objects[7].ea.entries[0].flags = 1;
        flags.objects[7].ea.canonical_sha256 = canonical(&flags.objects[7].ea.entries);
        assert!(flags.validate().is_err());
        let mut invalid_length = evidence.clone();
        invalid_length.objects[7].ea.entries[0].value_length = 3;
        invalid_length.objects[7].ea.canonical_sha256 =
            canonical(&invalid_length.objects[7].ea.entries);
        assert!(invalid_length.validate().is_err());
        let mut digest_mismatch = evidence.clone();
        digest_mismatch.objects[7].ea.canonical_sha256 = "0".repeat(64);
        assert!(digest_mismatch.validate().is_err());
        let mut directory_ea = evidence;
        directory_ea.objects[0].ea = directory_ea.objects[7].ea.clone();
        assert!(directory_ea.validate().is_err());
    }

    #[test]
    fn fixed_tree_run_ids_match_the_native_safe_leaf_contract() {
        for invalid in ["Run-One", "run-one.", "con", "nul.txt", "lpt1", "has space"] {
            let mut evidence = fixed_tree_inventory();
            evidence.run_id = invalid.to_owned();
            assert!(evidence.validate().is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn portable_manifest_is_sorted_deterministic_and_content_bound() {
        let root = InspectionRoot::new();
        fs::create_dir(root.0.join("nested")).unwrap();
        fs::write(root.0.join("z.txt"), b"z").unwrap();
        fs::write(root.0.join("nested").join("a.txt"), b"a").unwrap();
        let first =
            inspect_application_source(&root.0, ApplicationInspectionKind::PortableDirectory)
                .unwrap();
        let second =
            inspect_application_source(&root.0, ApplicationInspectionKind::PortableDirectory)
                .unwrap();
        assert_eq!(first, second);
        let manifest = first.portable_manifest.unwrap();
        assert_eq!(
            manifest
                .entries
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            ["nested", "nested/a.txt", "z.txt"]
        );
        fs::write(root.0.join("z.txt"), b"changed").unwrap();
        let changed =
            inspect_application_source(&root.0, ApplicationInspectionKind::PortableDirectory)
                .unwrap();
        assert_ne!(
            manifest.manifest_sha256,
            changed.portable_manifest.unwrap().manifest_sha256
        );
    }

    #[test]
    fn explicit_file_kind_rejects_extension_mismatch() {
        let root = InspectionRoot::new();
        let source = root.0.join("setup.msi");
        fs::write(&source, b"fixture").unwrap();
        assert_eq!(
            inspect_application_source(&source, ApplicationInspectionKind::Exe),
            Err(ApplicationInspectionError::TypeMismatch)
        );
        for rejected in [
            "CON.txt",
            "nested/file.txt:stream",
            "trailing. ",
            "café.exe",
        ] {
            assert_eq!(
                safe_manifest_path(Path::new(rejected)),
                Err(ApplicationInspectionError::PathRejected)
            );
        }
    }

    #[test]
    fn pe_machine_is_observed_without_executing_the_file() {
        let root = InspectionRoot::new();
        let source = root.0.join("fixture.exe");
        let mut bytes = vec![0_u8; 0x86];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        fs::write(&source, bytes).unwrap();
        let result = inspect_application_source(&source, ApplicationInspectionKind::Exe).unwrap();
        assert_eq!(result.architecture, ObservedApplicationArchitecture::X64);
        assert_eq!(result.signature_status, ReadinessState::Unknown);
    }
}
