//! Strict request and result contracts for the fixed imported-Bambu guest profile.

use aiw_evidence::canonical_json_bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::CompiledBambuExportScenario;

pub const IMPORTED_BAMBU_GUEST_REQUEST_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-imported-bambu-guest-request/v0alpha1";
pub const IMPORTED_BAMBU_SCENARIO_RESULT_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-imported-bambu-scenario-result/v0alpha1";

const STAGED_INSTALLER_PATH: &str = r"C:\AIW\Tools\application.exe";
const OUTPUT_ROOT: &str = r"C:\AIW\Output";
const SCENARIO_RESULT_PATH: &str = "scenario-result.json";
const EVIDENCE_LOG_PATH: &str = "evidence.jsonl";
const RECEIPT_PATH: &str = "completion.json";
const MAX_INSTALLER_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedBambuGuestRequest {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub config_sha256: String,
    pub request_sha256: String,
    pub agent_sha256: String,
    pub scenario: CompiledBambuExportScenario,
    pub scenario_sha256: String,
    pub installer_path: String,
    pub installer_sha256: String,
    pub installer_size_bytes: u64,
    pub import_receipt_sha256: String,
    pub output_root: String,
    pub scenario_result_path: String,
    pub evidence_log_path: String,
    pub receipt_path: String,
}

impl ImportedBambuGuestRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: impl Into<String>,
        sandbox_id: impl Into<String>,
        config_sha256: impl Into<String>,
        agent_sha256: impl Into<String>,
        scenario: CompiledBambuExportScenario,
        installer_sha256: impl Into<String>,
        installer_size_bytes: u64,
        import_receipt_sha256: impl Into<String>,
    ) -> Result<Self, ImportedBambuRequestError> {
        let scenario_sha256 = scenario
            .canonical_sha256()
            .map_err(ImportedBambuRequestError::Scenario)?;
        let mut value = Self {
            schema_version: IMPORTED_BAMBU_GUEST_REQUEST_SCHEMA_VERSION.to_owned(),
            run_id: run_id.into(),
            sandbox_id: sandbox_id.into(),
            config_sha256: config_sha256.into(),
            request_sha256: String::new(),
            agent_sha256: agent_sha256.into(),
            scenario,
            scenario_sha256,
            installer_path: STAGED_INSTALLER_PATH.to_owned(),
            installer_sha256: installer_sha256.into(),
            installer_size_bytes,
            import_receipt_sha256: import_receipt_sha256.into(),
            output_root: OUTPUT_ROOT.to_owned(),
            scenario_result_path: SCENARIO_RESULT_PATH.to_owned(),
            evidence_log_path: EVIDENCE_LOG_PATH.to_owned(),
            receipt_path: RECEIPT_PATH.to_owned(),
        };
        value.validate_unbound()?;
        value.request_sha256 = value.recompute_request_sha256()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ImportedBambuRequestError> {
        self.validate_unbound()?;
        if self.request_sha256 != self.recompute_request_sha256()? {
            return Err(ImportedBambuRequestError::RequestHashMismatch);
        }
        Ok(())
    }

    pub fn recompute_request_sha256(&self) -> Result<String, ImportedBambuRequestError> {
        self.validate_unbound()?;
        let mut value = serde_json::to_value(self)
            .map_err(|error| ImportedBambuRequestError::Canonicalization(error.to_string()))?;
        value["requestSha256"] = serde_json::Value::String(String::new());
        let bytes = canonical_json_bytes(&value)
            .map_err(|error| ImportedBambuRequestError::Canonicalization(error.to_string()))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    /// Recomputes the canonical request binding with `requestSha256` blank.
    pub fn request_sha256(&self) -> Result<String, ImportedBambuRequestError> {
        self.recompute_request_sha256()
    }

    fn validate_unbound(&self) -> Result<(), ImportedBambuRequestError> {
        if self.schema_version != IMPORTED_BAMBU_GUEST_REQUEST_SCHEMA_VERSION
            || !valid_id(&self.run_id)
            || !canonical_sandbox_id(&self.sandbox_id)
            || !lower_hex_sha256(&self.config_sha256)
            || !lower_hex_sha256(&self.agent_sha256)
            || !lower_hex_sha256(&self.scenario_sha256)
            || !lower_hex_sha256(&self.installer_sha256)
            || !lower_hex_sha256(&self.import_receipt_sha256)
            || self.installer_size_bytes == 0
            || self.installer_size_bytes > MAX_INSTALLER_BYTES
            || self.installer_path != STAGED_INSTALLER_PATH
            || self.output_root != OUTPUT_ROOT
            || self.scenario_result_path != SCENARIO_RESULT_PATH
            || self.evidence_log_path != EVIDENCE_LOG_PATH
            || self.receipt_path != RECEIPT_PATH
        {
            return Err(ImportedBambuRequestError::InvalidRequest);
        }
        self.scenario
            .validate()
            .map_err(ImportedBambuRequestError::Scenario)?;
        if self.scenario_sha256
            != self
                .scenario
                .canonical_sha256()
                .map_err(ImportedBambuRequestError::Scenario)?
            || self.scenario.application_sha256 != self.installer_sha256
        {
            return Err(ImportedBambuRequestError::ScenarioBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImportedBambuRequestError {
    #[error("imported Bambu request is outside the fixed profile")]
    InvalidRequest,
    #[error("imported Bambu request hash does not match the canonical request")]
    RequestHashMismatch,
    #[error("imported Bambu request scenario binding is inconsistent")]
    ScenarioBindingMismatch,
    #[error("imported Bambu scenario is invalid: {0}")]
    Scenario(crate::BambuExportCompileError),
    #[error("imported Bambu scenario result is invalid")]
    InvalidResult,
    #[error("imported Bambu scenario result is not bound to the approved request")]
    ResultBindingMismatch,
    #[error("could not canonicalize imported Bambu request: {0}")]
    Canonicalization(String),
}

fn lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn canonical_sandbox_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}

pub const BAMBU_SCENARIO_EVENT: &str = "bambuScenarioResult";

#[derive(Debug, Clone, Copy, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BambuExecutionStage {
    Install,
    PrepareFixture,
    Export,
    CollectArtifact,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BambuScenarioStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedBambuScenarioResult {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub scenario_sha256: String,
    pub status: BambuScenarioStatus,
    pub completed_stages: Vec<BambuExecutionStage>,
    pub failed_stage: Option<BambuExecutionStage>,
    pub diagnostic: Option<String>,
    pub install_exit_code: Option<i32>,
    pub launch_process_id: Option<u32>,
    pub launch_exit_code: Option<i32>,
    pub application_token: Option<aiw_token::TokenEvidence>,
    pub standard_user_context: Option<crate::StandardUserRuntimeContext>,
    pub artifact_sha256: Option<String>,
    pub artifact_size_bytes: Option<u64>,
}

impl ImportedBambuScenarioResult {
    pub fn for_request(request: &ImportedBambuGuestRequest) -> Self {
        Self {
            schema_version: IMPORTED_BAMBU_SCENARIO_RESULT_SCHEMA_VERSION.to_owned(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            status: BambuScenarioStatus::Failed,
            completed_stages: vec![],
            failed_stage: Some(BambuExecutionStage::Install),
            diagnostic: Some("scenario did not complete".to_owned()),
            install_exit_code: None,
            launch_process_id: None,
            launch_exit_code: None,
            application_token: None,
            standard_user_context: None,
            artifact_sha256: None,
            artifact_size_bytes: None,
        }
    }

    pub fn successful(&self) -> bool {
        self.status == BambuScenarioStatus::Succeeded
    }

    pub fn validate_for_request(&self, request: &ImportedBambuGuestRequest) -> Result<(), String> {
        request.validate().map_err(|e| e.to_string())?;
        if self.schema_version != IMPORTED_BAMBU_SCENARIO_RESULT_SCHEMA_VERSION
            || self.run_id != request.run_id
            || self.sandbox_id != request.sandbox_id
            || self.request_sha256 != request.request_sha256
            || self.scenario_sha256 != request.scenario_sha256
        {
            return Err("Bambu result binding mismatch".to_owned());
        }
        let stages = [
            BambuExecutionStage::Install,
            BambuExecutionStage::PrepareFixture,
            BambuExecutionStage::Export,
            BambuExecutionStage::CollectArtifact,
        ];
        if self.completed_stages.len() > stages.len()
            || self.completed_stages != stages[..self.completed_stages.len()]
        {
            return Err("invalid Bambu stage prefix".to_owned());
        }
        if self.successful() {
            if self.completed_stages != stages
                || self.failed_stage.is_some()
                || self.diagnostic.is_some()
                || self.install_exit_code != Some(0)
                || self.launch_exit_code != Some(0)
                || self.launch_process_id.is_none_or(|pid| pid == 0)
                || self
                    .artifact_sha256
                    .as_ref()
                    .is_none_or(|hash| !lower_hex_sha256(hash))
                || self
                    .artifact_size_bytes
                    .is_none_or(|size| size == 0 || size > crate::BAMBU_MAX_ARTIFACT_BYTES)
                || self.application_token.is_none()
                || self.standard_user_context.is_none()
            {
                return Err("incomplete successful Bambu observation".to_owned());
            }
        } else if self.failed_stage != stages.get(self.completed_stages.len()).copied()
            || self.failed_stage.is_none()
            || self.diagnostic.as_ref().is_none_or(|text| {
                text.is_empty() || text.len() > 2048 || text.chars().any(char::is_control)
            })
            || self.artifact_sha256.is_some()
            || self.artifact_size_bytes.is_some()
        {
            return Err("invalid Bambu failure observation".to_owned());
        }
        match (
            &self.application_token,
            &self.standard_user_context,
            self.launch_process_id,
        ) {
            (Some(token), Some(context), Some(pid)) if pid != 0 && token.process_id == pid => {
                context.validate_token(token)?
            }
            (None, None, None) if !self.successful() => {}
            _ => return Err("Bambu target identity is inconsistent".to_owned()),
        }
        Ok(())
    }
}

pub fn verify_bambu_scenario_evidence(
    bytes: &[u8],
    root: &str,
    request: &ImportedBambuGuestRequest,
    result: &ImportedBambuScenarioResult,
) -> Result<(), String> {
    result.validate_for_request(request)?;
    let records = crate::application_token::verified_application_records(bytes, root)?;
    if records.len() != 1
        || records[0].kind != BAMBU_SCENARIO_EVENT
        || records[0].source != "aiw-guest-agent"
        || records[0].payload != serde_json::to_value(result).map_err(|e| e.to_string())?
    {
        return Err("Bambu result differs from receipt-bound evidence".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ImportedBambuGuestRequest {
        let project =
            serde_json::from_str(include_str!("../../../examples/bambu-studio-export.json"))
                .unwrap();
        let scenario =
            crate::compile_bambu_studio_export_scenario(&project, "local-file-export").unwrap();
        ImportedBambuGuestRequest::new(
            "run-one",
            "12345678-1234-1234-1234-123456789012",
            "a".repeat(64),
            "b".repeat(64),
            scenario.clone(),
            scenario.application_sha256,
            429_037_864,
            "c".repeat(64),
        )
        .unwrap()
    }

    #[test]
    fn approval_binding_rejects_command_fixture_and_request_drift() {
        let original = request();
        for field in [
            "installerPath",
            "scenarioSha256",
            "requestSha256",
            "agentSha256",
        ] {
            let mut wire = serde_json::to_value(&original).unwrap();
            wire[field] = serde_json::json!("changed");
            let edited: ImportedBambuGuestRequest = serde_json::from_value(wire).unwrap();
            assert!(edited.validate().is_err(), "accepted {field}");
        }
        let mut edited = original.clone();
        edited.scenario.launch_arguments.push("--slice".to_owned());
        assert!(edited.recompute_request_sha256().is_err());
        let mut edited = original;
        edited.scenario.fixture_sha256 = "d".repeat(64);
        assert!(edited.recompute_request_sha256().is_err());
    }

    #[test]
    fn failed_prefix_cannot_be_promoted_to_export_success() {
        let request = request();
        let mut result = ImportedBambuScenarioResult::for_request(&request);
        result.completed_stages = vec![BambuExecutionStage::Install];
        result.failed_stage = Some(BambuExecutionStage::PrepareFixture);
        result.validate_for_request(&request).unwrap();
        result.status = BambuScenarioStatus::Succeeded;
        assert!(result.validate_for_request(&request).is_err());
        result.status = BambuScenarioStatus::Failed;
        result.artifact_sha256 = Some("a".repeat(64));
        assert!(result.validate_for_request(&request).is_err());
        result.artifact_sha256 = None;
        result.failed_stage = Some(BambuExecutionStage::Export);
        assert!(result.validate_for_request(&request).is_err());
    }

    #[test]
    fn evidence_requires_exact_source_payload_and_external_root() {
        let request = request();
        let result = ImportedBambuScenarioResult::for_request(&request);
        let mut log = aiw_evidence::EvidenceLog::new();
        log.append(aiw_evidence::EvidenceEvent {
            observed_utc: "test-clock".to_owned(),
            kind: BAMBU_SCENARIO_EVENT.to_owned(),
            source: "aiw-guest-agent".to_owned(),
            payload: serde_json::to_value(&result).unwrap(),
        })
        .unwrap();
        let bytes = serde_json::to_vec(&log.records()[0]).unwrap();
        let root = log.manifest().unwrap().root_hash;
        verify_bambu_scenario_evidence(&bytes, &root, &request, &result).unwrap();
        assert!(
            verify_bambu_scenario_evidence(&bytes, &"a".repeat(64), &request, &result).is_err()
        );
        let mut changed = result;
        changed.diagnostic = Some("different error".to_owned());
        assert!(verify_bambu_scenario_evidence(&bytes, &root, &request, &changed).is_err());
    }
}
