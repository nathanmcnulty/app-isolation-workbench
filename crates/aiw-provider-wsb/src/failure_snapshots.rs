use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ApplicationFilesystemSnapshot, ApplicationRegistrySnapshot, ImportedMsiFailedAttempt,
    ImportedMsiGuestRequest, MsiExecutionStage, MsiStageStatus, StandardUserRuntimeContext,
    application_token::verified_application_records,
};

pub const IMPORTED_MSI_FAILED_SNAPSHOTS_SCHEMA_VERSION: &str =
    "aiw.dev/imported-msi-failed-snapshots/v0alpha1";
pub const IMPORTED_MSI_FAILED_SNAPSHOTS_EVENT: &str = "importedMsiFailedSnapshots";

/// Filesystem and registry observations captured at one completed failure-path stage.
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailedSnapshotPhase {
    pub files: ApplicationFilesystemSnapshot,
    pub registry: ApplicationRegistrySnapshot,
}

impl FailedSnapshotPhase {
    fn validate(&self) -> Result<(), String> {
        self.files.validate()?;
        self.registry.validate()
    }
}

/// Failure-path observations are emitted separately so partially completed runs
/// do not enlarge the bounded scenario-result receipt.
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiFailedSnapshots {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub scenario_sha256: String,
    #[serde(default)]
    pub capture_context: Option<StandardUserRuntimeContext>,
    #[serde(default)]
    pub before_install: Option<FailedSnapshotPhase>,
    #[serde(default)]
    pub after_install: Option<FailedSnapshotPhase>,
    #[serde(default)]
    pub after_exercise: Option<FailedSnapshotPhase>,
}

impl ImportedMsiFailedSnapshots {
    pub fn validate_for(
        &self,
        request: &ImportedMsiGuestRequest,
        attempt: &ImportedMsiFailedAttempt,
    ) -> Result<(), String> {
        attempt.validate_for_request(request)?;
        if !request.scenario.requires_registry_observations()
            || self.schema_version != IMPORTED_MSI_FAILED_SNAPSHOTS_SCHEMA_VERSION
            || self.run_id != request.run_id
            || self.sandbox_id != request.sandbox_id
            || self.request_sha256 != request.request_sha256
            || self.scenario_sha256 != request.scenario_sha256
        {
            return Err(
                "imported MSI failed snapshots are not bound to the v5 failed attempt".into(),
            );
        }

        self.validate_phase(
            MsiExecutionStage::BeforeInstallCapture,
            self.before_install.as_ref(),
            attempt,
        )?;
        self.validate_phase(
            MsiExecutionStage::AfterInstallCapture,
            self.after_install.as_ref(),
            attempt,
        )?;
        self.validate_phase(
            MsiExecutionStage::AfterExerciseCapture,
            self.after_exercise.as_ref(),
            attempt,
        )?;

        if self.capture_context.is_some() != self.before_install.is_some() {
            return Err(
                "failed snapshot capture context must accompany before-install capture".into(),
            );
        }
        if let Some(context) = &self.capture_context {
            context.validate()?;
        }
        Ok(())
    }

    fn validate_phase(
        &self,
        stage: MsiExecutionStage,
        phase: Option<&FailedSnapshotPhase>,
        attempt: &ImportedMsiFailedAttempt,
    ) -> Result<(), String> {
        let passed = attempt
            .progress
            .stages
            .iter()
            .find(|result| result.stage == stage)
            .is_some_and(|result| result.status == MsiStageStatus::Passed);
        if phase.is_some() != passed {
            return Err("failed snapshot phases must match completed capture stages".into());
        }
        if let Some(phase) = phase {
            phase.validate()?;
        }
        Ok(())
    }
}

/// Reverify failure-path snapshots against the completion root. This optional
/// retention event is absent from older receipts, including v5 failure receipts
/// produced before snapshot collection was added.
pub fn verify_msi_failed_snapshots(
    bytes: &[u8],
    expected_root: &str,
    request: &ImportedMsiGuestRequest,
    attempt: &ImportedMsiFailedAttempt,
) -> Result<Option<ImportedMsiFailedSnapshots>, String> {
    attempt.validate_for_request(request)?;
    let records = verified_application_records(bytes, expected_root)?;
    let mut found = None;
    for record in records
        .iter()
        .filter(|record| record.kind == IMPORTED_MSI_FAILED_SNAPSHOTS_EVENT)
    {
        if found.is_some() || record.source != "aiw-guest-agent" {
            return Err("duplicate or foreign imported MSI failed snapshots".into());
        }
        let snapshots: ImportedMsiFailedSnapshots = serde_json::from_value(record.payload.clone())
            .map_err(|error| format!("invalid imported MSI failed snapshots: {error}"))?;
        snapshots.validate_for(request, attempt)?;
        found = Some(snapshots);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ApplicationRegistryRoot, CompiledMsiScenario, FixedDocumentExercise, MsiStageResult,
        RegistryScope, RegistryView,
    };
    use aiw_evidence::{EvidenceEvent, EvidenceLog};
    use sha2::Digest;

    fn request(version: &str) -> ImportedMsiGuestRequest {
        ImportedMsiGuestRequest::new(
            "run-one",
            "12345678-1234-abcd-9876-1234567890ab",
            "a".repeat(64),
            "b".repeat(64),
            CompiledMsiScenario {
                schema_version: version.into(),
                profile: version.replace(
                    "windows-sandbox-compiled-msi-scenario",
                    "windows-sandbox/notepad-plus-plus-msi",
                ),
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
                document_exercise: if version.ends_with("v0alpha2") {
                    None
                } else if version.ends_with("v0alpha3") {
                    Some(FixedDocumentExercise {
                        document_path: crate::DOCUMENT_EXERCISE_PATH.into(),
                        initial_sha256: hex::encode(sha2::Sha256::digest(
                            crate::DOCUMENT_INITIAL_TEXT.as_bytes(),
                        )),
                        expected_sha256: hex::encode(sha2::Sha256::digest(
                            crate::DOCUMENT_EXPECTED_TEXT.as_bytes(),
                        )),
                    })
                } else {
                    Some(FixedDocumentExercise {
                        document_path: crate::STANDARD_USER_DOCUMENT_EXERCISE_PATH.into(),
                        initial_sha256: hex::encode(sha2::Sha256::digest(
                            crate::DOCUMENT_INITIAL_TEXT.as_bytes(),
                        )),
                        expected_sha256: hex::encode(sha2::Sha256::digest(
                            crate::DOCUMENT_EXPECTED_TEXT.as_bytes(),
                        )),
                    })
                },
            },
            "c".repeat(64),
            1024,
            "d".repeat(64),
        )
        .unwrap()
    }

    fn stages(failed: usize) -> Vec<MsiStageResult> {
        MsiExecutionStage::ORDERED
            .into_iter()
            .enumerate()
            .map(|(index, stage)| MsiStageResult {
                stage,
                status: if index < failed {
                    MsiStageStatus::Passed
                } else if index == failed {
                    MsiStageStatus::Failed
                } else {
                    MsiStageStatus::NotReached
                },
            })
            .collect()
    }

    fn phase() -> FailedSnapshotPhase {
        FailedSnapshotPhase {
            files: ApplicationFilesystemSnapshot {
                entries: vec![],
                issues: vec![],
            },
            registry: ApplicationRegistrySnapshot {
                keys: vec![],
                values: vec![],
                issues: vec![],
                absent_roots: vec![
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
                ],
            },
        }
    }

    fn context() -> StandardUserRuntimeContext {
        StandardUserRuntimeContext {
            user_sid: "S-1-5-21-1-2-3-1001".into(),
            profile_path: r"C:\Users\AiwStandardUser".into(),
            roaming_app_data: r"C:\Users\AiwStandardUser\AppData\Roaming".into(),
            local_app_data: r"C:\Users\AiwStandardUser\AppData\Local".into(),
            administrators_enabled: false,
        }
    }

    fn snapshots(
        request: &ImportedMsiGuestRequest,
        failed: usize,
    ) -> (ImportedMsiFailedAttempt, ImportedMsiFailedSnapshots) {
        let attempt = ImportedMsiFailedAttempt::new(request, stages(failed), "failed").unwrap();
        let value = ImportedMsiFailedSnapshots {
            schema_version: IMPORTED_MSI_FAILED_SNAPSHOTS_SCHEMA_VERSION.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            capture_context: (failed > 0).then(context),
            before_install: (failed > 0).then(phase),
            after_install: (failed > 2).then(phase),
            after_exercise: (failed > 8).then(phase),
        };
        (attempt, value)
    }

    fn evidence(events: Vec<EvidenceEvent>) -> (Vec<u8>, String) {
        let mut log = EvidenceLog::new();
        for event in events {
            log.append(event).unwrap();
        }
        let root = log.manifest().unwrap().root_hash;
        let bytes = log
            .records()
            .iter()
            .flat_map(|record| {
                let mut line = serde_json::to_vec(record).unwrap();
                line.push(b'\n');
                line
            })
            .collect();
        (bytes, root)
    }

    fn event(value: &ImportedMsiFailedSnapshots) -> EvidenceEvent {
        EvidenceEvent {
            observed_utc: "2026-09-09T00:00:00Z".into(),
            kind: IMPORTED_MSI_FAILED_SNAPSHOTS_EVENT.into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::to_value(value).unwrap(),
        }
    }

    #[test]
    fn binds_each_failure_prefix_and_serializes_explicit_nulls() {
        let request = request("aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha5");
        for failed in 0..MsiExecutionStage::ORDERED.len() {
            let (attempt, value) = snapshots(&request, failed);
            value
                .validate_for(&request, &attempt)
                .expect("each failure prefix is valid");
        }
        let (_, value) = snapshots(&request, 0);
        let json = serde_json::to_value(value).unwrap();
        assert!(json["captureContext"].is_null());
        assert!(json["beforeInstall"].is_null());
        assert!(json["afterInstall"].is_null());
        assert!(json["afterExercise"].is_null());
    }

    #[test]
    fn rejects_invalid_snapshot_bounds_and_context_shape() {
        let request = request("aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha5");
        let (attempt, mut value) = snapshots(&request, 1);
        value.before_install.as_mut().unwrap().files.entries = vec![crate::ApplicationFileEntry {
            root: crate::ApplicationFileRoot::Installation,
            path: "a".repeat(1025),
            size_bytes: 0,
            sha256: "a".repeat(64),
        }];
        assert!(value.validate_for(&request, &attempt).is_err());
        let (_, mut value) = snapshots(&request, 1);
        value
            .capture_context
            .as_mut()
            .unwrap()
            .administrators_enabled = true;
        assert!(value.validate_for(&request, &attempt).is_err());
    }

    #[test]
    fn verifier_rejects_tampered_duplicate_foreign_and_legacy_events() {
        let current_request = request("aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha5");
        let (attempt, value) = snapshots(&current_request, 1);
        let (bytes, root) = evidence(vec![event(&value)]);
        assert_eq!(
            verify_msi_failed_snapshots(&bytes, &root, &current_request, &attempt).unwrap(),
            Some(value.clone())
        );
        assert!(
            verify_msi_failed_snapshots(&bytes, &"e".repeat(64), &current_request, &attempt)
                .is_err()
        );
        let (duplicate, duplicate_root) = evidence(vec![event(&value), event(&value)]);
        assert!(
            verify_msi_failed_snapshots(&duplicate, &duplicate_root, &current_request, &attempt)
                .is_err()
        );
        let mut foreign = event(&value);
        foreign.source = "other".into();
        let (foreign, foreign_root) = evidence(vec![foreign]);
        assert!(
            verify_msi_failed_snapshots(&foreign, &foreign_root, &current_request, &attempt)
                .is_err()
        );
        let legacy = request("aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha4");
        let legacy_attempt = ImportedMsiFailedAttempt::new(&legacy, stages(1), "failed").unwrap();
        assert!(verify_msi_failed_snapshots(&bytes, &root, &legacy, &legacy_attempt).is_err());
    }

    #[test]
    fn v5_and_legacy_absence_are_preserved_as_unmeasured() {
        let current = request("aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha5");
        let current_attempt = ImportedMsiFailedAttempt::new(&current, stages(1), "failed").unwrap();
        let legacy = request("aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha4");
        let attempt = ImportedMsiFailedAttempt::new(&legacy, stages(1), "failed").unwrap();
        let (bytes, root) = evidence(vec![EvidenceEvent {
            observed_utc: "2026-09-09T00:00:00Z".into(),
            kind: "other".into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::json!({}),
        }]);
        assert_eq!(
            verify_msi_failed_snapshots(&bytes, &root, &legacy, &attempt).unwrap(),
            None
        );
        assert_eq!(
            verify_msi_failed_snapshots(&bytes, &root, &current, &current_attempt).unwrap(),
            None
        );
    }
}
