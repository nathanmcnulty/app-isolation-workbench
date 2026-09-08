use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ImportedMsiGuestRequest, application_token::verified_application_records};

pub const IMPORTED_MSI_STAGE_PROGRESS_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-imported-msi-stage-progress/v0alpha1";
pub const IMPORTED_MSI_STAGE_PROGRESS_SCHEMA: &str = IMPORTED_MSI_STAGE_PROGRESS_SCHEMA_VERSION;
pub const IMPORTED_MSI_STAGE_PROGRESS_EVENT: &str = "importedMsiStageProgress";
pub const IMPORTED_MSI_FAILED_ATTEMPT_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-imported-msi-failed-attempt/v0alpha1";
pub const IMPORTED_MSI_FAILED_ATTEMPT_SCHEMA: &str = IMPORTED_MSI_FAILED_ATTEMPT_SCHEMA_VERSION;

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "camelCase")]
pub enum MsiExecutionStage {
    BeforeInstallCapture,
    Install,
    AfterInstallCapture,
    PrepareDocument,
    Launch,
    OpenDocument,
    EditSaveDocument,
    Close,
    AfterExerciseCapture,
}

impl MsiExecutionStage {
    pub const ORDERED: [Self; 9] = [
        Self::BeforeInstallCapture,
        Self::Install,
        Self::AfterInstallCapture,
        Self::PrepareDocument,
        Self::Launch,
        Self::OpenDocument,
        Self::EditSaveDocument,
        Self::Close,
        Self::AfterExerciseCapture,
    ];
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MsiStageStatus {
    Passed,
    Failed,
    NotReached,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MsiStageResult {
    pub stage: MsiExecutionStage,
    pub status: MsiStageStatus,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiStageProgress {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub scenario_sha256: String,
    pub stages: Vec<MsiStageResult>,
}

impl ImportedMsiStageProgress {
    pub fn new(
        request: &ImportedMsiGuestRequest,
        stages: Vec<MsiStageResult>,
    ) -> Result<Self, String> {
        let progress = Self {
            schema_version: IMPORTED_MSI_STAGE_PROGRESS_SCHEMA_VERSION.to_owned(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            stages,
        };
        progress.validate_for_request(request)?;
        Ok(progress)
    }

    pub fn validate_for_request(&self, request: &ImportedMsiGuestRequest) -> Result<(), String> {
        self.validate_shape()?;
        request.validate().map_err(|error| error.to_string())?;
        if !request.scenario.requires_application_exercise() {
            return Err("stage progress requires the v3 fixed document scenario".to_owned());
        }
        if self.run_id != request.run_id
            || self.sandbox_id != request.sandbox_id
            || self.request_sha256 != request.request_sha256
            || self.scenario_sha256 != request.scenario_sha256
        {
            return Err("imported MSI stage progress is not bound to the request".to_owned());
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), String> {
        if self.schema_version != IMPORTED_MSI_STAGE_PROGRESS_SCHEMA_VERSION {
            return Err("unsupported imported MSI stage progress schema".to_owned());
        }
        if self.stages.len() != MsiExecutionStage::ORDERED.len() {
            return Err("imported MSI stage progress must contain exactly nine stages".to_owned());
        }
        for (actual, expected) in self.stages.iter().zip(MsiExecutionStage::ORDERED) {
            if actual.stage != expected {
                return Err("imported MSI stage progress has an invalid stage order".to_owned());
            }
        }
        validate_statuses(&self.stages)
    }

    pub fn successful(&self) -> bool {
        self.validate_shape().is_ok()
            && self
                .stages
                .iter()
                .all(|stage| stage.status == MsiStageStatus::Passed)
    }
}

fn validate_statuses(stages: &[MsiStageResult]) -> Result<(), String> {
    let mut failed = false;
    for (index, stage) in stages.iter().enumerate() {
        match stage.status {
            MsiStageStatus::Passed if failed => {
                return Err("passed stage follows a failed stage".to_owned());
            }
            MsiStageStatus::Failed if failed => {
                return Err("stage progress contains multiple failed stages".to_owned());
            }
            MsiStageStatus::Failed => failed = true,
            MsiStageStatus::NotReached if !failed => {
                return Err("not-reached stage precedes a failed stage".to_owned());
            }
            MsiStageStatus::NotReached if index == 0 => {
                return Err("stage progress cannot begin with not-reached".to_owned());
            }
            MsiStageStatus::NotReached => {}
            MsiStageStatus::Passed => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiFailedAttempt {
    pub schema_version: String,
    pub progress: ImportedMsiStageProgress,
    pub diagnostic: String,
}

impl ImportedMsiFailedAttempt {
    pub fn new(
        request: &ImportedMsiGuestRequest,
        stages: Vec<MsiStageResult>,
        diagnostic: impl Into<String>,
    ) -> Result<Self, String> {
        let progress = ImportedMsiStageProgress::new(request, stages)?;
        Self::from_progress(progress, diagnostic)
    }

    pub fn from_progress(
        progress: ImportedMsiStageProgress,
        diagnostic: impl Into<String>,
    ) -> Result<Self, String> {
        let attempt = Self {
            schema_version: IMPORTED_MSI_FAILED_ATTEMPT_SCHEMA_VERSION.to_owned(),
            progress,
            diagnostic: diagnostic.into(),
        };
        attempt.validate()?;
        Ok(attempt)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.progress.validate_shape()?;
        if self.schema_version != IMPORTED_MSI_FAILED_ATTEMPT_SCHEMA_VERSION
            || self.diagnostic.is_empty()
            || self.diagnostic.chars().count() > 2048
            || self.diagnostic.chars().any(char::is_control)
            || self.progress.successful()
        {
            return Err("imported MSI failed attempt is invalid".to_owned());
        }
        Ok(())
    }

    pub fn validate_for_request(&self, request: &ImportedMsiGuestRequest) -> Result<(), String> {
        self.validate()?;
        self.progress.validate_for_request(request)
    }
}

/// Reverify the bytes against an already verified evidence root before using
/// optional progress. Legacy binaries may omit this event.
pub fn verify_imported_msi_stage_progress(
    bytes: &[u8],
    expected_root: &str,
    request: &ImportedMsiGuestRequest,
) -> Result<Option<ImportedMsiStageProgress>, String> {
    let records = verified_application_records(bytes, expected_root)?;
    let mut observation = None;
    for record in records
        .iter()
        .filter(|record| record.kind == IMPORTED_MSI_STAGE_PROGRESS_EVENT)
    {
        if observation.is_some() || record.source != "aiw-guest-agent" {
            return Err("duplicate or foreign imported MSI stage progress".to_owned());
        }
        let current: ImportedMsiStageProgress = serde_json::from_value(record.payload.clone())
            .map_err(|error| format!("invalid imported MSI stage progress: {error}"))?;
        current.validate_for_request(request)?;
        observation = Some(current);
    }
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompiledMsiScenario, FixedDocumentExercise};
    use aiw_evidence::{EvidenceEvent, EvidenceLog};
    use sha2::Digest;

    fn request() -> ImportedMsiGuestRequest {
        ImportedMsiGuestRequest::new(
            "run-one",
            "12345678-1234-abcd-9876-1234567890ab",
            "a".repeat(64),
            "b".repeat(64),
            CompiledMsiScenario {
                schema_version: "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha3".into(),
                profile: "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha3".into(),
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
                document_exercise: Some(FixedDocumentExercise {
                    document_path: crate::DOCUMENT_EXERCISE_PATH.into(),
                    initial_sha256: hex::encode(sha2::Sha256::digest(
                        crate::DOCUMENT_INITIAL_TEXT.as_bytes(),
                    )),
                    expected_sha256: hex::encode(sha2::Sha256::digest(
                        crate::DOCUMENT_EXPECTED_TEXT.as_bytes(),
                    )),
                }),
            },
            "c".repeat(64),
            1024,
            "d".repeat(64),
        )
        .unwrap()
    }

    fn stages(status: Option<usize>) -> Vec<MsiStageResult> {
        MsiExecutionStage::ORDERED
            .into_iter()
            .enumerate()
            .map(|(index, stage)| MsiStageResult {
                stage,
                status: match status {
                    Some(failed) if index == failed => MsiStageStatus::Failed,
                    Some(failed) if index > failed => MsiStageStatus::NotReached,
                    _ => MsiStageStatus::Passed,
                },
            })
            .collect()
    }

    fn evidence(progress: &ImportedMsiStageProgress) -> (Vec<u8>, String) {
        let mut log = EvidenceLog::new();
        log.append(EvidenceEvent {
            observed_utc: "2026-09-07T00:00:00Z".into(),
            kind: IMPORTED_MSI_STAGE_PROGRESS_EVENT.into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::to_value(progress).unwrap(),
        })
        .unwrap();
        let root = log.manifest().unwrap().root_hash;
        let bytes = log
            .records()
            .iter()
            .map(|record| {
                let mut line = serde_json::to_vec(record).unwrap();
                line.push(b'\n');
                line
            })
            .fold(Vec::new(), |mut bytes, line| {
                bytes.extend(line);
                bytes
            });
        (bytes, root)
    }

    #[test]
    fn accepts_ordered_success_and_failed_prefix() {
        let request = request();
        let success = ImportedMsiStageProgress::new(&request, stages(None)).unwrap();
        assert!(success.successful());
        let failed = ImportedMsiStageProgress::new(&request, stages(Some(4))).unwrap();
        assert!(!failed.successful());
        assert_eq!(failed.stages[5].status, MsiStageStatus::NotReached);
    }

    #[test]
    fn accepts_failure_at_every_stage_including_final_stage() {
        let request = request();
        for index in 0..MsiExecutionStage::ORDERED.len() {
            let progress = ImportedMsiStageProgress::new(&request, stages(Some(index)))
                .expect("each single failed prefix is valid");
            assert!(!progress.successful());
            assert_eq!(progress.stages[index].status, MsiStageStatus::Failed);
        }
    }

    #[test]
    fn rejects_bad_order_statuses_and_bindings() {
        let request = request();
        let mut value = stages(None);
        value.swap(0, 1);
        assert!(ImportedMsiStageProgress::new(&request, value).is_err());
        let mut value = stages(Some(4));
        value[6].status = MsiStageStatus::Passed;
        assert!(ImportedMsiStageProgress::new(&request, value).is_err());
        let mut progress = ImportedMsiStageProgress::new(&request, stages(None)).unwrap();
        progress.request_sha256 = "e".repeat(64);
        assert!(progress.validate_for_request(&request).is_err());
        progress.request_sha256 = request.request_sha256.clone();
        progress.schema_version = "unknown".into();
        assert!(progress.validate_for_request(&request).is_err());
    }

    #[test]
    fn verifier_checks_root_duplicate_foreign_and_legacy_absence() {
        let request = request();
        let progress = ImportedMsiStageProgress::new(&request, stages(None)).unwrap();
        let (bytes, root) = evidence(&progress);
        assert_eq!(
            verify_imported_msi_stage_progress(&bytes, &root, &request)
                .unwrap()
                .unwrap(),
            progress
        );
        assert!(verify_imported_msi_stage_progress(&bytes, &"f".repeat(64), &request).is_err());

        let mut v3_without_progress = EvidenceLog::new();
        v3_without_progress
            .append(EvidenceEvent {
                observed_utc: "2026-09-07T00:00:00Z".into(),
                kind: "otherEvent".into(),
                source: "aiw-guest-agent".into(),
                payload: serde_json::json!({}),
            })
            .unwrap();
        let v3_root = v3_without_progress.manifest().unwrap().root_hash;
        let v3_bytes = v3_without_progress
            .records()
            .iter()
            .map(|record| {
                let mut line = serde_json::to_vec(record).unwrap();
                line.push(b'\n');
                line
            })
            .fold(Vec::new(), |mut bytes, line| {
                bytes.extend(line);
                bytes
            });
        assert_eq!(
            verify_imported_msi_stage_progress(&v3_bytes, &v3_root, &request).unwrap(),
            None
        );

        let legacy = crate::ImportedMsiGuestRequest::new(
            "legacy",
            request.sandbox_id.clone(),
            request.config_sha256.clone(),
            request.agent_sha256.clone(),
            {
                let mut scenario = request.scenario.clone();
                scenario.schema_version =
                    "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha2".into();
                scenario.profile = "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha2".into();
                scenario.document_exercise = None;
                scenario
            },
            request.installer_sha256.clone(),
            request.installer_size_bytes,
            request.import_receipt_sha256.clone(),
        )
        .unwrap();
        let mut empty = EvidenceLog::new();
        empty
            .append(EvidenceEvent {
                observed_utc: "2026-09-07T00:00:00Z".into(),
                kind: "otherEvent".into(),
                source: "aiw-guest-agent".into(),
                payload: serde_json::json!({}),
            })
            .unwrap();
        let legacy_root = empty.manifest().unwrap().root_hash;
        let legacy_bytes = empty
            .records()
            .iter()
            .map(|record| {
                let mut line = serde_json::to_vec(record).unwrap();
                line.push(b'\n');
                line
            })
            .fold(Vec::new(), |mut bytes, line| {
                bytes.extend(line);
                bytes
            });
        assert_eq!(
            verify_imported_msi_stage_progress(&legacy_bytes, &legacy_root, &legacy).unwrap(),
            None
        );

        let mut duplicate = EvidenceLog::new();
        for _ in 0..2 {
            duplicate
                .append(EvidenceEvent {
                    observed_utc: "2026-09-07T00:00:00Z".into(),
                    kind: IMPORTED_MSI_STAGE_PROGRESS_EVENT.into(),
                    source: "aiw-guest-agent".into(),
                    payload: serde_json::to_value(&progress).unwrap(),
                })
                .unwrap();
        }
        let duplicate_root = duplicate.manifest().unwrap().root_hash;
        let duplicate_bytes = duplicate
            .records()
            .iter()
            .map(|record| {
                let mut line = serde_json::to_vec(record).unwrap();
                line.push(b'\n');
                line
            })
            .fold(Vec::new(), |mut bytes, line| {
                bytes.extend(line);
                bytes
            });
        assert!(
            verify_imported_msi_stage_progress(&duplicate_bytes, &duplicate_root, &request)
                .is_err()
        );
    }

    #[test]
    fn failed_attempt_requires_diagnostic_and_failed_progress() {
        let request = request();
        let attempt =
            ImportedMsiFailedAttempt::new(&request, stages(Some(4)), "UI action failed").unwrap();
        attempt.validate_for_request(&request).unwrap();
        assert!(ImportedMsiFailedAttempt::new(&request, stages(None), "no failure").is_err());
        assert!(ImportedMsiFailedAttempt::new(&request, stages(Some(4)), "\n").is_err());
    }
}
