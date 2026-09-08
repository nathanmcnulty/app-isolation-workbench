use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ImportedMsiGuestRequest, ImportedMsiScenarioResult};

pub const IMPORTED_MSI_BEHAVIOR_SCHEMA: &str = "aiw.dev/imported-msi-behavior-evidence/v0alpha1";
pub const IMPORTED_MSI_BEHAVIOR_SCHEMA_VERSION: &str = IMPORTED_MSI_BEHAVIOR_SCHEMA;
pub const IMPORTED_MSI_BEHAVIOR_EVENT: &str = "importedMsiBehavior";

pub const DOCUMENT_EXERCISE_PATH: &str = r"C:\AIW\Scenario\document.txt";
pub const DOCUMENT_INITIAL_TEXT: &str = "AIW initial document.\r\n";
pub const DOCUMENT_EXPECTED_TEXT: &str = "AIW application isolation document round-trip.\r\n";

const MAX_SNAPSHOT_ENTRIES: usize = 4096;
const MAX_SNAPSHOT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SNAPSHOT_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 1024;

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "camelCase")]
pub enum ApplicationFileRoot {
    Installation,
    RoamingAppData,
    LocalAppData,
}

impl ApplicationFileRoot {
    const fn order(self) -> u8 {
        match self {
            Self::Installation => 0,
            Self::RoamingAppData => 1,
            Self::LocalAppData => 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationFileEntry {
    pub root: ApplicationFileRoot,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "camelCase")]
pub enum FilesystemCaptureIssueReason {
    Unreadable,
    ReparsePoint,
    LimitExceeded,
    ChangedDuringRead,
}

impl FilesystemCaptureIssueReason {
    const fn order(self) -> u8 {
        match self {
            Self::Unreadable => 0,
            Self::ReparsePoint => 1,
            Self::LimitExceeded => 2,
            Self::ChangedDuringRead => 3,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemCaptureIssue {
    pub root: ApplicationFileRoot,
    pub reason: FilesystemCaptureIssueReason,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationFilesystemSnapshot {
    pub entries: Vec<ApplicationFileEntry>,
    pub issues: Vec<FilesystemCaptureIssue>,
}

impl ApplicationFilesystemSnapshot {
    pub fn validate(&self) -> Result<(), String> {
        if self.entries.len() > MAX_SNAPSHOT_ENTRIES {
            return Err("filesystem snapshot entry count exceeds its bound".to_owned());
        }
        let mut total_bytes = 0u64;
        let mut previous = None;
        for entry in &self.entries {
            validate_file_entry(entry)?;
            total_bytes = total_bytes
                .checked_add(entry.size_bytes)
                .ok_or_else(|| "filesystem snapshot size exceeds its bound".to_owned())?;
            if total_bytes > MAX_SNAPSHOT_TOTAL_BYTES {
                return Err("filesystem snapshot size exceeds its bound".to_owned());
            }
            let key = entry_key(entry);
            if previous.as_ref().is_some_and(|value| value >= &key) {
                return Err("filesystem snapshot entries must be sorted and unique".to_owned());
            }
            previous = Some(key);
        }

        let mut previous_issue = None;
        for issue in &self.issues {
            let key = (issue.root.order(), issue.reason.order());
            if previous_issue.is_some_and(|value| value >= key) {
                return Err("filesystem snapshot issues must be sorted and unique".to_owned());
            }
            previous_issue = Some(key);
        }
        Ok(())
    }

    fn incomplete_roots(&self) -> BTreeSet<ApplicationFileRoot> {
        self.issues.iter().map(|issue| issue.root).collect()
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionalExercise {
    pub opened_document: bool,
    pub saved_document: bool,
    pub expected_sha256: String,
    pub observed_sha256: String,
}

impl FunctionalExercise {
    pub fn validate(&self) -> Result<(), String> {
        let expected_sha256 = sha256_text(DOCUMENT_EXPECTED_TEXT);
        if !self.opened_document
            || !self.saved_document
            || self.expected_sha256 != expected_sha256
            || self.observed_sha256 != expected_sha256
        {
            return Err(
                "functional document exercise does not match the fixed contract".to_owned(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiBehaviorEvidence {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub scenario_sha256: String,
    pub functional_exercise: FunctionalExercise,
    pub before_install: ApplicationFilesystemSnapshot,
    pub after_install: ApplicationFilesystemSnapshot,
    pub after_exercise: ApplicationFilesystemSnapshot,
}

impl ImportedMsiBehaviorEvidence {
    pub fn validate_for(
        &self,
        request: &ImportedMsiGuestRequest,
        result: &ImportedMsiScenarioResult,
    ) -> Result<(), String> {
        result
            .validate_for_request(request)
            .map_err(|error| error.to_string())?;
        if !request.scenario.requires_application_exercise()
            || self.schema_version != IMPORTED_MSI_BEHAVIOR_SCHEMA
            || self.run_id != request.run_id
            || self.sandbox_id != request.sandbox_id
            || self.request_sha256 != request.request_sha256
            || self.scenario_sha256 != request.scenario_sha256
        {
            return Err("imported MSI behavior evidence is not bound to the request".to_owned());
        }
        self.functional_exercise.validate()?;
        self.before_install.validate()?;
        self.after_install.validate()?;
        self.after_exercise.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FilesystemDiffKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSnapshotDiff {
    pub kind: FilesystemDiffKind,
    pub before: Option<ApplicationFileEntry>,
    pub after: Option<ApplicationFileEntry>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSnapshotDiffResult {
    pub diffs: Vec<FilesystemSnapshotDiff>,
    pub incomplete_roots: Vec<ApplicationFileRoot>,
}

pub fn diff_filesystem_snapshots(
    before: &ApplicationFilesystemSnapshot,
    after: &ApplicationFilesystemSnapshot,
) -> Result<FilesystemSnapshotDiffResult, String> {
    before.validate()?;
    after.validate()?;

    let incomplete = before
        .incomplete_roots()
        .union(&after.incomplete_roots())
        .copied()
        .collect::<BTreeSet<_>>();
    let before_entries = complete_entries(before, &incomplete);
    let after_entries = complete_entries(after, &incomplete);
    let keys = before_entries
        .keys()
        .chain(after_entries.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut diffs = Vec::new();
    for key in keys {
        match (before_entries.get(&key), after_entries.get(&key)) {
            (Some(before), Some(after)) if before != after => {
                diffs.push(FilesystemSnapshotDiff {
                    kind: FilesystemDiffKind::Modified,
                    before: Some((*before).clone()),
                    after: Some((*after).clone()),
                });
            }
            (Some(before), None) => diffs.push(FilesystemSnapshotDiff {
                kind: FilesystemDiffKind::Removed,
                before: Some((*before).clone()),
                after: None,
            }),
            (None, Some(after)) => diffs.push(FilesystemSnapshotDiff {
                kind: FilesystemDiffKind::Added,
                before: None,
                after: Some((*after).clone()),
            }),
            _ => {}
        }
    }
    Ok(FilesystemSnapshotDiffResult {
        diffs,
        incomplete_roots: incomplete.into_iter().collect(),
    })
}

pub fn verify_imported_msi_behavior(
    bytes: &[u8],
    expected_root: &str,
    request: &ImportedMsiGuestRequest,
    result: &ImportedMsiScenarioResult,
) -> Result<Option<ImportedMsiBehaviorEvidence>, String> {
    let records = crate::application_token::verified_application_records(bytes, expected_root)?;
    result
        .validate_for_request(request)
        .map_err(|error| error.to_string())?;

    let mut observation = None;
    for record in records
        .iter()
        .filter(|record| record.kind == IMPORTED_MSI_BEHAVIOR_EVENT)
    {
        if observation.is_some() || record.source != "aiw-guest-agent" {
            return Err("duplicate or foreign imported MSI behavior observation".to_owned());
        }
        let current: ImportedMsiBehaviorEvidence =
            serde_json::from_value(record.payload.clone())
                .map_err(|error| format!("invalid imported MSI behavior observation: {error}"))?;
        current.validate_for(request, result)?;
        observation = Some(current);
    }
    if observation.is_none() && request.scenario.requires_application_exercise() {
        return Err("approved MSI profile requires functional exercise evidence".to_owned());
    }
    Ok(observation)
}

fn complete_entries<'a>(
    snapshot: &'a ApplicationFilesystemSnapshot,
    incomplete: &BTreeSet<ApplicationFileRoot>,
) -> BTreeMap<(u8, String), &'a ApplicationFileEntry> {
    snapshot
        .entries
        .iter()
        .filter(|entry| !incomplete.contains(&entry.root))
        .map(|entry| (entry_key(entry), entry))
        .collect()
}

fn validate_file_entry(entry: &ApplicationFileEntry) -> Result<(), String> {
    if entry.path.is_empty()
        || entry.path.len() > MAX_RELATIVE_PATH_BYTES
        || entry.path.starts_with('/')
        || entry.path.ends_with('/')
        || entry.path.contains(['\\', '\0'])
        || entry.path.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.contains(':')
                || segment.ends_with([' ', '.'])
                || is_reserved_device_name(segment)
                || segment.chars().any(char::is_control)
        })
        || entry.size_bytes > MAX_SNAPSHOT_FILE_BYTES
        || !is_lower_hex_sha256(&entry.sha256)
    {
        return Err("application filesystem entry is invalid".to_owned());
    }
    Ok(())
}

fn is_reserved_device_name(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                suffix.len() == 1 && suffix.as_bytes()[0].is_ascii_digit() && suffix != "0"
            })
}

fn entry_key(entry: &ApplicationFileEntry) -> (u8, String) {
    (entry.root.order(), entry.path.to_lowercase())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompiledMsiScenario;
    use aiw_evidence::{EvidenceEvent, EvidenceLog};

    fn request() -> ImportedMsiGuestRequest {
        ImportedMsiGuestRequest::new(
            "run-one",
            "12345678-1234-abcd-9876-1234567890ab",
            "a".repeat(64),
            "b".repeat(64),
            CompiledMsiScenario {
                schema_version: "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha2".into(),
                profile: "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha2".into(),
                scenario_id: "first-run".into(),
                application_sha256: "c".repeat(64),
                installer_path: r"C:\AIW\Tools\application.msi".into(),
                install_arguments: vec![
                    "/i".into(),
                    r"C:\AIW\Tools\application.msi".into(),
                    "/qn".into(),
                    "/norestart".into(),
                ],
                install_timeout_seconds: 120,
                launch_path: r"C:\Program Files\Notepad++\notepad++.exe".into(),
                launch_arguments: vec![],
                process_image: "notepad++.exe".into(),
                process_wait_timeout_seconds: 30,
                graceful_close_timeout_seconds: 15,
                expected_exit_code: 0,
                document_exercise: None,
            },
            "c".repeat(64),
            1024,
            "d".repeat(64),
        )
        .unwrap()
    }

    fn result(request: &ImportedMsiGuestRequest) -> ImportedMsiScenarioResult {
        ImportedMsiScenarioResult::succeeded(request, 0, 42, 0).unwrap()
    }

    fn request_with_profile(
        schema_version: &str,
        profile: &str,
        document_exercise: Option<crate::FixedDocumentExercise>,
    ) -> ImportedMsiGuestRequest {
        let mut request = request();
        request.scenario.schema_version = schema_version.to_owned();
        request.scenario.profile = profile.to_owned();
        request.scenario.document_exercise = document_exercise;
        request.scenario_sha256 = request.scenario.canonical_sha256().unwrap();
        request.request_sha256 = request.request_sha256().unwrap();
        request.validate().unwrap();
        request
    }

    fn legacy_request() -> ImportedMsiGuestRequest {
        request_with_profile(
            "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha1",
            "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha1",
            None,
        )
    }

    fn v3_request() -> ImportedMsiGuestRequest {
        request_with_profile(
            "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha3",
            "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha3",
            Some(crate::FixedDocumentExercise {
                document_path: DOCUMENT_EXERCISE_PATH.into(),
                initial_sha256: sha256_text(DOCUMENT_INITIAL_TEXT),
                expected_sha256: sha256_text(DOCUMENT_EXPECTED_TEXT),
            }),
        )
    }

    fn entry(root: ApplicationFileRoot, path: &str, hash: char) -> ApplicationFileEntry {
        ApplicationFileEntry {
            root,
            path: path.into(),
            size_bytes: 4,
            sha256: hash.to_string().repeat(64),
        }
    }

    fn snapshot(entries: Vec<ApplicationFileEntry>) -> ApplicationFilesystemSnapshot {
        ApplicationFilesystemSnapshot {
            entries,
            issues: vec![],
        }
    }

    fn behavior(request: &ImportedMsiGuestRequest) -> ImportedMsiBehaviorEvidence {
        ImportedMsiBehaviorEvidence {
            schema_version: IMPORTED_MSI_BEHAVIOR_SCHEMA.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            functional_exercise: FunctionalExercise {
                opened_document: true,
                saved_document: true,
                expected_sha256: sha256_text(DOCUMENT_EXPECTED_TEXT),
                observed_sha256: sha256_text(DOCUMENT_EXPECTED_TEXT),
            },
            before_install: snapshot(vec![entry(ApplicationFileRoot::Installation, "a.txt", 'a')]),
            after_install: snapshot(vec![
                entry(ApplicationFileRoot::Installation, "a.txt", 'a'),
                entry(ApplicationFileRoot::Installation, "installed.exe", 'b'),
            ]),
            after_exercise: snapshot(vec![
                entry(ApplicationFileRoot::Installation, "a.txt", 'a'),
                entry(ApplicationFileRoot::Installation, "installed.exe", 'b'),
                entry(ApplicationFileRoot::LocalAppData, "state.json", 'c'),
            ]),
        }
    }

    fn evidence_bytes(value: &ImportedMsiBehaviorEvidence) -> (Vec<u8>, String) {
        evidence_bytes_for_events(vec![EvidenceEvent {
            observed_utc: "2026-09-07T00:00:00Z".into(),
            kind: IMPORTED_MSI_BEHAVIOR_EVENT.into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::to_value(value).unwrap(),
        }])
    }

    fn evidence_bytes_for_events(events: Vec<EvidenceEvent>) -> (Vec<u8>, String) {
        let mut log = EvidenceLog::new();
        for event in events {
            log.append(event).unwrap();
        }
        let root = log.manifest().unwrap().root_hash;
        let bytes = log
            .records()
            .iter()
            .map(|record| serde_json::to_vec(record).unwrap())
            .fold(Vec::new(), |mut bytes, record| {
                bytes.extend_from_slice(&record);
                bytes.push(b'\n');
                bytes
            });
        (bytes, root)
    }

    #[test]
    fn verifies_bound_behavior_and_legacy_absence() {
        let request = v3_request();
        let scenario_result = result(&request);
        let value = behavior(&request);
        let (bytes, root) = evidence_bytes(&value);
        assert_eq!(
            verify_imported_msi_behavior(&bytes, &root, &request, &scenario_result).unwrap(),
            Some(value)
        );

        let mut log = EvidenceLog::new();
        log.append(EvidenceEvent {
            observed_utc: "2026-09-07T00:00:00Z".into(),
            kind: "otherEvent".into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::json!({"ok": true}),
        })
        .unwrap();
        let root = log.manifest().unwrap().root_hash;
        let bytes = serde_json::to_vec(log.records().first().unwrap()).unwrap();
        let v2 = super::tests::request();
        let v2_result = result(&v2);
        assert_eq!(
            verify_imported_msi_behavior(&bytes, &root, &v2, &v2_result).unwrap(),
            None
        );
        let injected = behavior(&v2);
        let (injected_bytes, injected_root) = evidence_bytes(&injected);
        assert!(
            verify_imported_msi_behavior(&injected_bytes, &injected_root, &v2, &v2_result).is_err()
        );
        let legacy = legacy_request();
        let legacy_result = result(&legacy);
        assert_eq!(
            verify_imported_msi_behavior(&bytes, &root, &legacy, &legacy_result).unwrap(),
            None
        );

        let current = v3_request();
        let current_result = result(&current);
        assert!(verify_imported_msi_behavior(&bytes, &root, &current, &current_result).is_err());

        let value = behavior(&request);
        let event = |source: &str| EvidenceEvent {
            observed_utc: "2026-09-07T00:00:00Z".into(),
            kind: IMPORTED_MSI_BEHAVIOR_EVENT.into(),
            source: source.into(),
            payload: serde_json::to_value(&value).unwrap(),
        };
        let (bytes, root) =
            evidence_bytes_for_events(vec![event("aiw-guest-agent"), event("aiw-guest-agent")]);
        assert!(verify_imported_msi_behavior(&bytes, &root, &request, &scenario_result).is_err());
        let (bytes, root) = evidence_bytes_for_events(vec![event("foreign-agent")]);
        assert!(verify_imported_msi_behavior(&bytes, &root, &request, &scenario_result).is_err());
    }

    #[test]
    fn diffs_complete_roots_and_suppresses_incomplete_roots() {
        let before = snapshot(vec![
            entry(ApplicationFileRoot::Installation, "changed.txt", 'a'),
            entry(ApplicationFileRoot::Installation, "removed.txt", 'b'),
            entry(ApplicationFileRoot::RoamingAppData, "blocked.txt", 'c'),
        ]);
        let after = ApplicationFilesystemSnapshot {
            entries: vec![
                entry(ApplicationFileRoot::Installation, "added.txt", 'd'),
                entry(ApplicationFileRoot::Installation, "changed.txt", 'e'),
                entry(ApplicationFileRoot::RoamingAppData, "blocked.txt", 'f'),
            ],
            issues: vec![FilesystemCaptureIssue {
                root: ApplicationFileRoot::RoamingAppData,
                reason: FilesystemCaptureIssueReason::Unreadable,
            }],
        };
        let diff = diff_filesystem_snapshots(&before, &after).unwrap();
        assert_eq!(
            diff.incomplete_roots,
            vec![ApplicationFileRoot::RoamingAppData]
        );
        assert_eq!(diff.diffs.len(), 3);
        assert!(
            diff.diffs
                .iter()
                .any(|value| value.kind == FilesystemDiffKind::Added)
        );
        assert!(
            diff.diffs
                .iter()
                .any(|value| value.kind == FilesystemDiffKind::Removed)
        );
        assert!(
            diff.diffs
                .iter()
                .any(|value| value.kind == FilesystemDiffKind::Modified)
        );
    }

    #[test]
    fn rejects_traversal_duplicates_and_binding_tamper() {
        let mut invalid = snapshot(vec![entry(
            ApplicationFileRoot::Installation,
            "../escape",
            'a',
        )]);
        assert!(invalid.validate().is_err());
        invalid.entries = vec![
            entry(ApplicationFileRoot::Installation, "a.txt", 'a'),
            entry(ApplicationFileRoot::Installation, "A.TXT", 'b'),
        ];
        assert!(invalid.validate().is_err());
        for path in ["alias.", "alias ", "CON.txt", "Lpt1.log"] {
            invalid.entries = vec![entry(ApplicationFileRoot::Installation, path, 'a')];
            assert!(invalid.validate().is_err(), "{path}");
        }

        let request = v3_request();
        let result = result(&request);
        let value = behavior(&request);
        let (bytes, root) = evidence_bytes(&value);
        let mut changed = value;
        changed.request_sha256 = "e".repeat(64);
        let (changed_bytes, changed_root) = evidence_bytes(&changed);
        assert!(
            verify_imported_msi_behavior(&changed_bytes, &changed_root, &request, &result).is_err()
        );
        assert!(verify_imported_msi_behavior(&bytes, &"f".repeat(64), &request, &result).is_err());
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn rejects_oversized_logs_unknown_schema_and_malformed_hashes() {
        let request = v3_request();
        let result = result(&request);
        let value = behavior(&request);
        let (bytes, root) = evidence_bytes(&value);
        let mut record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        record["schemaVersion"] = serde_json::json!("unknown");
        let unknown = serde_json::to_vec(&record).unwrap();
        assert!(verify_imported_msi_behavior(&unknown, &root, &request, &result).is_err());

        record["schemaVersion"] = serde_json::json!(aiw_evidence::EVIDENCE_RECORD_SCHEMA_VERSION);
        record["hash"] = serde_json::json!("a".repeat(64));
        let malformed = serde_json::to_vec(&record).unwrap();
        assert!(verify_imported_msi_behavior(&malformed, &root, &request, &result).is_err());
        assert!(
            verify_imported_msi_behavior(
                &vec![b'x'; crate::MAX_APPLICATION_EVIDENCE_BYTES + 1],
                &root,
                &request,
                &result
            )
            .is_err()
        );

        let mut log = EvidenceLog::new();
        for sequence in 0..=128 {
            log.append(EvidenceEvent {
                observed_utc: format!("2026-09-07T00:00:{sequence:02}Z"),
                kind: "otherEvent".into(),
                source: "aiw-guest-agent".into(),
                payload: serde_json::json!({"sequence": sequence}),
            })
            .unwrap();
        }
        let root = log.manifest().unwrap().root_hash;
        let bytes = log
            .records()
            .iter()
            .map(|record| serde_json::to_vec(record).unwrap())
            .fold(Vec::new(), |mut bytes, record| {
                bytes.extend_from_slice(&record);
                bytes.push(b'\n');
                bytes
            });
        assert!(verify_imported_msi_behavior(&bytes, &root, &request, &result).is_err());
    }

    #[test]
    fn functional_exercise_uses_fixed_round_trip_hash() {
        assert_eq!(DOCUMENT_EXERCISE_PATH, r"C:\AIW\Scenario\document.txt");
        assert_ne!(DOCUMENT_INITIAL_TEXT, DOCUMENT_EXPECTED_TEXT);
        assert_eq!(
            sha256_text(DOCUMENT_EXPECTED_TEXT),
            "55666bc7399b14c1cdb77f1e0261e3b6f09e49aec11cda7de1685d73b8a7c9fc"
        );
        let mut exercise = behavior(&request()).functional_exercise;
        exercise.observed_sha256 = "a".repeat(64);
        assert!(exercise.validate().is_err());
    }
}
