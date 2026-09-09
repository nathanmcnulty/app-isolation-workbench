use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ImportedMsiGuestRequest, ImportedMsiRuntimeContext, ImportedMsiScenarioResult,
    application_token::verified_application_records,
};

pub const IMPORTED_MSI_REGISTRY_SCHEMA_VERSION: &str =
    "aiw.dev/imported-msi-registry-evidence/v0alpha1";
pub const IMPORTED_MSI_REGISTRY_SCHEMA: &str = IMPORTED_MSI_REGISTRY_SCHEMA_VERSION;
pub const IMPORTED_MSI_REGISTRY_EVENT: &str = "importedMsiRegistry";
const MAX_KEYS: usize = 256;
const MAX_VALUES: usize = 1024;
const MAX_VALUE_BYTES: u64 = 64 * 1024;
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DEPTH: usize = 16;

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "camelCase")]
pub enum ApplicationRegistryRoot {
    MachineApplication,
    UserApplication,
}

impl ApplicationRegistryRoot {
    const fn order(self) -> u8 {
        match self {
            Self::MachineApplication => 0,
            Self::UserApplication => 1,
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "camelCase")]
pub enum RegistryView {
    Registry64,
    Registry32,
}

impl RegistryView {
    const fn order(self) -> u8 {
        match self {
            Self::Registry64 => 0,
            Self::Registry32 => 1,
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryScope {
    pub root: ApplicationRegistryRoot,
    pub view: RegistryView,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryKeyEntry {
    pub root: ApplicationRegistryRoot,
    pub view: RegistryView,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryValueEntry {
    pub root: ApplicationRegistryRoot,
    pub view: RegistryView,
    pub path: String,
    pub name: String,
    pub value_type: u32,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "camelCase")]
pub enum RegistryCaptureIssueReason {
    Unreadable,
    SymbolicLink,
    LimitExceeded,
    ChangedDuringRead,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryCaptureIssue {
    pub root: ApplicationRegistryRoot,
    pub view: RegistryView,
    pub reason: RegistryCaptureIssueReason,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationRegistrySnapshot {
    pub keys: Vec<RegistryKeyEntry>,
    pub values: Vec<RegistryValueEntry>,
    pub absent_roots: Vec<RegistryScope>,
    pub issues: Vec<RegistryCaptureIssue>,
}

impl ApplicationRegistrySnapshot {
    pub fn validate(&self) -> Result<(), String> {
        if self.keys.len() > MAX_KEYS || self.values.len() > MAX_VALUES {
            return Err("registry snapshot count exceeds its bound".into());
        }
        let mut total = 0u64;
        let mut key_ids = BTreeSet::new();
        let mut previous_key = None;
        for key in &self.keys {
            validate_path(&key.path)?;
            let current = id(key.root, key.view, &key.path);
            if previous_key.as_ref().is_some_and(|old| old >= &current) {
                return Err("registry keys must be sorted and unique".into());
            }
            previous_key = Some(current.clone());
            if !key_ids.insert(current) {
                return Err("duplicate registry key".into());
            }
        }
        let mut value_ids = BTreeSet::new();
        let mut previous_value = None;
        for value in &self.values {
            validate_path(&value.path)?;
            if value.name.len() > 256
                || !value.name.is_ascii()
                || value.name.bytes().any(|c| !(0x20..=0x7e).contains(&c))
            {
                return Err("invalid registry value name".into());
            }
            if value.size_bytes > MAX_VALUE_BYTES {
                return Err("registry value exceeds its bound".into());
            }
            total = total
                .checked_add(value.size_bytes)
                .ok_or("registry snapshot size exceeds its bound")?;
            if total > MAX_TOTAL_BYTES
                || value.sha256.len() != 64
                || !value
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err("invalid registry value hash or size".into());
            }
            if !key_ids.contains(&id(value.root, value.view, &value.path)) {
                return Err("registry value has no captured key".into());
            }
            let current = (
                id(value.root, value.view, &value.path),
                value.name.to_ascii_lowercase(),
            );
            if previous_value.as_ref().is_some_and(|old| old >= &current) {
                return Err("registry values must be sorted and unique".into());
            }
            previous_value = Some(current.clone());
            if !value_ids.insert(current) {
                return Err("duplicate registry value".into());
            }
        }
        for key in &self.keys {
            if !key.path.is_empty() {
                let mut parent = key.path.as_str();
                while let Some((prefix, _)) = parent.rsplit_once('\\') {
                    if !key_ids.contains(&id(key.root, key.view, prefix)) {
                        return Err("registry key is missing a captured parent".into());
                    }
                    parent = prefix;
                }
                if !key_ids.contains(&id(key.root, key.view, "")) {
                    return Err("registry key is missing its captured root".into());
                }
            }
        }
        let mut absent = BTreeSet::new();
        let mut previous_absent = None;
        for scope in &self.absent_roots {
            if previous_absent.as_ref().is_some_and(|old| old >= scope) {
                return Err("absent registry roots must be sorted and unique".into());
            }
            previous_absent = Some(*scope);
            if !absent.insert(*scope) {
                return Err("duplicate absent registry root".into());
            }
        }
        let mut issues = BTreeSet::new();
        let mut previous_issue = None;
        for issue in &self.issues {
            let current = (issue.root, issue.view, issue.reason);
            if previous_issue.as_ref().is_some_and(|old| old >= &current) {
                return Err("registry issues must be sorted and unique".into());
            }
            previous_issue = Some(current);
            if !issues.insert((issue.root, issue.view)) {
                return Err("duplicate registry issue".into());
            }
        }
        for scope in all_scopes() {
            let has_key = key_ids.contains(&id(scope.root, scope.view, ""));
            if absent.contains(&scope) && (has_key || issues.contains(&(scope.root, scope.view))) {
                return Err("registry scope has contradictory status".into());
            }
            if !has_key && !absent.contains(&scope) && !issues.contains(&(scope.root, scope.view)) {
                return Err("registry snapshot does not classify every root".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiRegistryEvidence {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub scenario_sha256: String,
    pub user_sid: String,
    pub before_install: ApplicationRegistrySnapshot,
    pub after_install: ApplicationRegistrySnapshot,
    pub after_exercise: ApplicationRegistrySnapshot,
}

impl ImportedMsiRegistryEvidence {
    pub fn new(
        request: &ImportedMsiGuestRequest,
        result: &ImportedMsiScenarioResult,
        context: &ImportedMsiRuntimeContext,
        before_install: ApplicationRegistrySnapshot,
        after_install: ApplicationRegistrySnapshot,
        after_exercise: ApplicationRegistrySnapshot,
    ) -> Result<Self, String> {
        let value = Self {
            schema_version: IMPORTED_MSI_REGISTRY_SCHEMA_VERSION.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            user_sid: context.context.user_sid.clone(),
            before_install,
            after_install,
            after_exercise,
        };
        value.validate_for(request, result, context)?;
        Ok(value)
    }
    pub fn validate_for(
        &self,
        request: &ImportedMsiGuestRequest,
        result: &ImportedMsiScenarioResult,
        context: &ImportedMsiRuntimeContext,
    ) -> Result<(), String> {
        result
            .validate_for_request(request)
            .map_err(|e| e.to_string())?;
        if !request.scenario.requires_registry_observations()
            || self.schema_version != IMPORTED_MSI_REGISTRY_SCHEMA_VERSION
            || self.run_id != request.run_id
            || self.sandbox_id != request.sandbox_id
            || self.request_sha256 != request.request_sha256
            || self.scenario_sha256 != request.scenario_sha256
            || self.user_sid != context.context.user_sid
            || context.schema_version != crate::IMPORTED_MSI_RUNTIME_CONTEXT_SCHEMA_VERSION
            || context.run_id != request.run_id
            || context.sandbox_id != request.sandbox_id
            || context.request_sha256 != request.request_sha256
            || context.scenario_sha256 != request.scenario_sha256
            || context.process_id != result.launch_process_id
        {
            return Err(
                "imported MSI registry evidence is not bound to the v5 standard-user request"
                    .into(),
            );
        }
        context.context.validate()?;
        self.before_install.validate()?;
        self.after_install.validate()?;
        self.after_exercise.validate()?;
        Ok(())
    }
}

pub fn verify_msi_registry_evidence(
    bytes: &[u8],
    expected_root: &str,
    request: &ImportedMsiGuestRequest,
    result: &ImportedMsiScenarioResult,
    context: Option<&ImportedMsiRuntimeContext>,
) -> Result<Option<ImportedMsiRegistryEvidence>, String> {
    let records = verified_application_records(bytes, expected_root)?;
    let mut found = None;
    for record in records
        .iter()
        .filter(|r| r.kind == IMPORTED_MSI_REGISTRY_EVENT)
    {
        if found.is_some() || record.source != "aiw-guest-agent" {
            return Err("duplicate or foreign imported MSI registry evidence".into());
        }
        let context = context.ok_or("registry evidence requires standard-user context")?;
        let value: ImportedMsiRegistryEvidence = serde_json::from_value(record.payload.clone())
            .map_err(|e| format!("invalid imported MSI registry evidence: {e}"))?;
        value.validate_for(request, result, context)?;
        found = Some(value);
    }
    if found.is_none() && request.scenario.requires_registry_observations() {
        return Err("v5 profile requires registry evidence".into());
    }
    Ok(found)
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistryDiffKind {
    Added,
    Removed,
    Modified,
}
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryKeyDiff {
    pub kind: RegistryDiffKind,
    pub entry: RegistryKeyEntry,
}
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryValueDiff {
    pub kind: RegistryDiffKind,
    pub before: Option<RegistryValueEntry>,
    pub after: Option<RegistryValueEntry>,
}
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrySnapshotDiff {
    pub key_changes: Vec<RegistryKeyDiff>,
    pub value_changes: Vec<RegistryValueDiff>,
    pub incomplete_scopes: Vec<RegistryScope>,
}

pub fn diff_registry_snapshots(
    before: &ApplicationRegistrySnapshot,
    after: &ApplicationRegistrySnapshot,
) -> Result<RegistrySnapshotDiff, String> {
    before.validate()?;
    after.validate()?;
    let incomplete: BTreeSet<_> = before
        .issues
        .iter()
        .chain(after.issues.iter())
        .map(|i| RegistryScope {
            root: i.root,
            view: i.view,
        })
        .collect();
    let keys = |s: &ApplicationRegistrySnapshot| {
        s.keys
            .iter()
            .filter(|e| {
                !incomplete.contains(&RegistryScope {
                    root: e.root,
                    view: e.view,
                })
            })
            .map(|e| (id(e.root, e.view, &e.path), e.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let values = |s: &ApplicationRegistrySnapshot| {
        s.values
            .iter()
            .filter(|e| {
                !incomplete.contains(&RegistryScope {
                    root: e.root,
                    view: e.view,
                })
            })
            .map(|e| {
                (
                    (id(e.root, e.view, &e.path), e.name.to_ascii_lowercase()),
                    e.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let bk = keys(before);
    let ak = keys(after);
    let mut key_changes = Vec::new();
    for (k, v) in &ak {
        if !bk.contains_key(k) {
            key_changes.push(RegistryKeyDiff {
                kind: RegistryDiffKind::Added,
                entry: (*v).clone(),
            });
        }
    }
    for (k, v) in &bk {
        if !ak.contains_key(k) {
            key_changes.push(RegistryKeyDiff {
                kind: RegistryDiffKind::Removed,
                entry: (*v).clone(),
            });
        }
    }
    let bv = values(before);
    let av = values(after);
    let mut value_changes = Vec::new();
    for (k, v) in &av {
        match bv.get(k) {
            None => value_changes.push(RegistryValueDiff {
                kind: RegistryDiffKind::Added,
                before: None,
                after: Some((*v).clone()),
            }),
            Some(old) if *old != *v => value_changes.push(RegistryValueDiff {
                kind: RegistryDiffKind::Modified,
                before: Some((*old).clone()),
                after: Some((*v).clone()),
            }),
            _ => {}
        }
    }
    for (k, v) in &bv {
        if !av.contains_key(k) {
            value_changes.push(RegistryValueDiff {
                kind: RegistryDiffKind::Removed,
                before: Some((*v).clone()),
                after: None,
            });
        }
    }
    Ok(RegistrySnapshotDiff {
        key_changes,
        value_changes,
        incomplete_scopes: incomplete.into_iter().collect(),
    })
}

fn all_scopes() -> [RegistryScope; 4] {
    [
        RegistryScope {
            root: ApplicationRegistryRoot::MachineApplication,
            view: RegistryView::Registry64,
        },
        RegistryScope {
            root: ApplicationRegistryRoot::MachineApplication,
            view: RegistryView::Registry32,
        },
        RegistryScope {
            root: ApplicationRegistryRoot::UserApplication,
            view: RegistryView::Registry64,
        },
        RegistryScope {
            root: ApplicationRegistryRoot::UserApplication,
            view: RegistryView::Registry32,
        },
    ]
}
fn id(root: ApplicationRegistryRoot, view: RegistryView, path: &str) -> (u8, u8, String) {
    (root.order(), view.order(), path.to_ascii_lowercase())
}
fn validate_path(path: &str) -> Result<(), String> {
    if path.len() > 1024
        || !path.is_ascii()
        || path.split('\\').count() > MAX_DEPTH
        || path.chars().any(|c| c.is_control() || c == '/')
        || (!path.is_empty()
            && path
                .split('\\')
                .any(|p| p.is_empty() || p == "." || p == ".." || p.ends_with([' ', '.'])))
    {
        return Err("invalid registry relative path".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompiledMsiScenario, FixedDocumentExercise, ImportedMsiRuntimeContext};
    use aiw_evidence::{EvidenceEvent, EvidenceLog};
    use sha2::{Digest, Sha256};

    fn snapshot() -> ApplicationRegistrySnapshot {
        ApplicationRegistrySnapshot {
            keys: all_scopes()
                .iter()
                .map(|s| RegistryKeyEntry {
                    root: s.root,
                    view: s.view,
                    path: String::new(),
                })
                .collect(),
            values: Vec::new(),
            absent_roots: Vec::new(),
            issues: Vec::new(),
        }
    }

    fn v5_request() -> ImportedMsiGuestRequest {
        let scenario = CompiledMsiScenario {
            schema_version: "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha5".into(),
            profile: "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha5".into(),
            scenario_id: "first-run".into(),
            application_sha256: "a".repeat(64),
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
            document_exercise: Some(FixedDocumentExercise {
                document_path: crate::STANDARD_USER_DOCUMENT_EXERCISE_PATH.into(),
                initial_sha256: hex::encode(Sha256::digest(
                    crate::DOCUMENT_INITIAL_TEXT.as_bytes(),
                )),
                expected_sha256: hex::encode(Sha256::digest(
                    crate::DOCUMENT_EXPECTED_TEXT.as_bytes(),
                )),
            }),
        };
        ImportedMsiGuestRequest::new(
            "run-one",
            "11111111-1111-1111-1111-111111111111",
            "b".repeat(64),
            "c".repeat(64),
            scenario,
            "a".repeat(64),
            1024,
            "d".repeat(64),
        )
        .unwrap()
    }

    fn runtime(
        request: &ImportedMsiGuestRequest,
        result: &ImportedMsiScenarioResult,
    ) -> ImportedMsiRuntimeContext {
        ImportedMsiRuntimeContext {
            schema_version: crate::IMPORTED_MSI_RUNTIME_CONTEXT_SCHEMA_VERSION.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            process_id: result.launch_process_id,
            context: crate::StandardUserRuntimeContext {
                user_sid: "S-1-5-21-1-2-3-4".into(),
                profile_path: crate::STANDARD_USER_PROFILE_PATH.into(),
                roaming_app_data: r"C:\Users\AiwStandardUser\AppData\Roaming".into(),
                local_app_data: r"C:\Users\AiwStandardUser\AppData\Local".into(),
                administrators_enabled: false,
            },
        }
    }

    fn log_bytes(events: Vec<(&str, serde_json::Value)>) -> (Vec<u8>, String) {
        let mut log = EvidenceLog::new();
        for (source, payload) in events {
            log.append(EvidenceEvent {
                observed_utc: "2026-09-09T00:00:00Z".into(),
                kind: IMPORTED_MSI_REGISTRY_EVENT.into(),
                source: source.into(),
                payload,
            })
            .unwrap();
        }
        let root = log.manifest().unwrap().root_hash;
        let mut bytes = Vec::new();
        for record in log.records() {
            serde_json::to_writer(&mut bytes, record).unwrap();
            bytes.push(b'\n');
        }
        (bytes, root)
    }

    fn evidence(
        request: &ImportedMsiGuestRequest,
        result: &ImportedMsiScenarioResult,
        context: &ImportedMsiRuntimeContext,
    ) -> ImportedMsiRegistryEvidence {
        ImportedMsiRegistryEvidence::new(
            request,
            result,
            context,
            snapshot(),
            snapshot(),
            snapshot(),
        )
        .unwrap()
    }

    #[test]
    fn validates_all_scopes_and_metadata_only_values() {
        let mut value = snapshot();
        value.values.push(RegistryValueEntry {
            root: ApplicationRegistryRoot::MachineApplication,
            view: RegistryView::Registry64,
            path: String::new(),
            name: "InstallLocation".into(),
            value_type: 1,
            size_bytes: 4,
            sha256: "a".repeat(64),
        });
        value.values.push(RegistryValueEntry {
            root: ApplicationRegistryRoot::UserApplication,
            view: RegistryView::Registry32,
            path: String::new(),
            name: String::new(),
            value_type: 1,
            size_bytes: 0,
            sha256: "b".repeat(64),
        });
        value.validate().unwrap();
    }

    #[test]
    fn rejects_missing_scope_parent_value_and_bounds() {
        let mut value = snapshot();
        value.keys.pop();
        assert!(value.validate().is_err());
        let mut value = snapshot();
        value.keys[0].path = "bad\u{0001}path".into();
        assert!(value.validate().is_err());
        let mut value = snapshot();
        value.keys.push(RegistryKeyEntry {
            root: ApplicationRegistryRoot::MachineApplication,
            view: RegistryView::Registry64,
            path: "Child".into(),
        });
        assert!(value.validate().is_err());
        let mut value = snapshot();
        value.values.push(RegistryValueEntry {
            root: ApplicationRegistryRoot::UserApplication,
            view: RegistryView::Registry32,
            path: String::new(),
            name: "x".into(),
            value_type: 1,
            size_bytes: MAX_VALUE_BYTES + 1,
            sha256: "a".repeat(64),
        });
        assert!(value.validate().is_err());
    }

    #[test]
    fn incomplete_scope_is_excluded_from_diff() {
        let before = snapshot();
        let mut after = snapshot();
        after.issues.push(RegistryCaptureIssue {
            root: ApplicationRegistryRoot::UserApplication,
            view: RegistryView::Registry64,
            reason: RegistryCaptureIssueReason::Unreadable,
        });
        let diff = diff_registry_snapshots(&before, &after).unwrap();
        assert_eq!(diff.incomplete_scopes.len(), 1);
        assert!(diff.key_changes.is_empty());
    }

    #[test]
    fn verifier_binds_current_event_and_rejects_missing_foreign_duplicate_and_tamper() {
        let request = v5_request();
        let result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
        let context = runtime(&request, &result);
        let payload = serde_json::to_value(evidence(&request, &result, &context)).unwrap();
        let (bytes, root) = log_bytes(vec![("aiw-guest-agent", payload.clone())]);
        assert!(
            verify_msi_registry_evidence(&bytes, &root, &request, &result, Some(&context))
                .unwrap()
                .is_some()
        );
        let (empty, empty_root) = log_bytes(vec![]);
        assert!(
            verify_msi_registry_evidence(&empty, &empty_root, &request, &result, Some(&context))
                .is_err()
        );
        let (foreign, foreign_root) = log_bytes(vec![("other", payload.clone())]);
        assert!(
            verify_msi_registry_evidence(
                &foreign,
                &foreign_root,
                &request,
                &result,
                Some(&context)
            )
            .is_err()
        );
        let (duplicate, duplicate_root) = log_bytes(vec![
            ("aiw-guest-agent", payload.clone()),
            ("aiw-guest-agent", payload),
        ]);
        assert!(
            verify_msi_registry_evidence(
                &duplicate,
                &duplicate_root,
                &request,
                &result,
                Some(&context)
            )
            .is_err()
        );
        let mut tampered = serde_json::to_value(evidence(&request, &result, &context)).unwrap();
        tampered["userSid"] = serde_json::json!("S-1-5-21-1-2-3-5");
        let (tampered_bytes, tampered_root) = log_bytes(vec![("aiw-guest-agent", tampered)]);
        assert!(
            verify_msi_registry_evidence(
                &tampered_bytes,
                &tampered_root,
                &request,
                &result,
                Some(&context)
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_v4_event_is_absent_but_present_registry_event_is_rejected() {
        let mut request = v5_request();
        request.scenario.schema_version =
            "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha4".into();
        request.scenario.profile = "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha4".into();
        request.scenario_sha256 = request.scenario.canonical_sha256().unwrap();
        request.request_sha256 = request.request_sha256().unwrap();
        let result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
        let mut log = EvidenceLog::new();
        log.append(EvidenceEvent {
            observed_utc: "2026-09-09T00:00:00Z".into(),
            kind: "legacyEvidence".into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::json!({"ok": true}),
        })
        .unwrap();
        let root = log.manifest().unwrap().root_hash;
        let mut empty = Vec::new();
        for record in log.records() {
            serde_json::to_writer(&mut empty, record).unwrap();
            empty.push(b'\n');
        }
        assert!(
            verify_msi_registry_evidence(&empty, &root, &request, &result, None)
                .unwrap()
                .is_none()
        );
        let context = runtime(&request, &result);
        let payload = serde_json::to_value(evidence(&request, &result, &context)).unwrap();
        let (present, present_root) = log_bytes(vec![("aiw-guest-agent", payload)]);
        assert!(
            verify_msi_registry_evidence(
                &present,
                &present_root,
                &request,
                &result,
                Some(&context)
            )
            .is_err()
        );
    }
}
