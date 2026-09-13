//! Strict request and result contracts for the fixed imported-MSI guest profile.

use aiw_evidence::canonical_json_bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::CompiledMsiScenario;

pub const IMPORTED_MSI_GUEST_REQUEST_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-imported-msi-guest-request/v0alpha1";
pub const IMPORTED_MSI_SCENARIO_RESULT_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-imported-msi-scenario-result/v0alpha1";
pub const IMPORTED_MSI_DOCUMENT_SCENARIO_RESULT_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-imported-msi-scenario-result/v0alpha3";

const STAGED_INSTALLER_PATH: &str = r"C:\AIW\Tools\application.msi";
const OUTPUT_ROOT: &str = r"C:\AIW\Output";
const SCENARIO_RESULT_PATH: &str = "scenario-result.json";
const EVIDENCE_LOG_PATH: &str = "evidence.jsonl";
const RECEIPT_PATH: &str = "completion.json";
const MAX_INSTALLER_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiGuestRequest {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub config_sha256: String,
    pub request_sha256: String,
    pub agent_sha256: String,
    pub scenario: CompiledMsiScenario,
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

impl ImportedMsiGuestRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: impl Into<String>,
        sandbox_id: impl Into<String>,
        config_sha256: impl Into<String>,
        agent_sha256: impl Into<String>,
        scenario: CompiledMsiScenario,
        installer_sha256: impl Into<String>,
        installer_size_bytes: u64,
        import_receipt_sha256: impl Into<String>,
    ) -> Result<Self, ImportedMsiRequestError> {
        let scenario_sha256 = scenario
            .canonical_sha256()
            .map_err(ImportedMsiRequestError::Scenario)?;
        let mut value = Self {
            schema_version: IMPORTED_MSI_GUEST_REQUEST_SCHEMA_VERSION.to_owned(),
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

    pub fn validate(&self) -> Result<(), ImportedMsiRequestError> {
        self.validate_unbound()?;
        if self.request_sha256 != self.recompute_request_sha256()? {
            return Err(ImportedMsiRequestError::RequestHashMismatch);
        }
        Ok(())
    }

    pub fn recompute_request_sha256(&self) -> Result<String, ImportedMsiRequestError> {
        self.validate_unbound()?;
        let mut value = serde_json::to_value(self)
            .map_err(|error| ImportedMsiRequestError::Canonicalization(error.to_string()))?;
        value["requestSha256"] = serde_json::Value::String(String::new());
        let bytes = canonical_json_bytes(&value)
            .map_err(|error| ImportedMsiRequestError::Canonicalization(error.to_string()))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    /// Recomputes the canonical request binding with `requestSha256` blank.
    pub fn request_sha256(&self) -> Result<String, ImportedMsiRequestError> {
        self.recompute_request_sha256()
    }

    fn validate_unbound(&self) -> Result<(), ImportedMsiRequestError> {
        if self.schema_version != IMPORTED_MSI_GUEST_REQUEST_SCHEMA_VERSION
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
            return Err(ImportedMsiRequestError::InvalidRequest);
        }
        self.scenario
            .validate()
            .map_err(ImportedMsiRequestError::Scenario)?;
        if self.scenario_sha256
            != self
                .scenario
                .canonical_sha256()
                .map_err(ImportedMsiRequestError::Scenario)?
            || self.scenario.application_sha256 != self.installer_sha256
        {
            return Err(ImportedMsiRequestError::ScenarioBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ImportedMsiScenarioStatus {
    Succeeded,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiScenarioResult {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub config_sha256: String,
    pub request_sha256: String,
    pub agent_sha256: String,
    pub scenario_id: String,
    pub scenario_sha256: String,
    pub installer_sha256: String,
    pub status: ImportedMsiScenarioStatus,
    pub install_exit_code: i32,
    pub launch_process_id: u32,
    pub launch_exit_code: i32,
    pub process_observed: bool,
    pub graceful_close_requested: bool,
    pub process_closed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_transfer: Option<ImportedMsiDocumentTransferResult>,
}

/// Receipt-bound measurements for the interactive text transfer profile.
/// The bytes themselves are published as a separate completion artifact so a
/// host can choose whether and where to export them.
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiDocumentTransferResult {
    pub input_sha256: String,
    pub input_size_bytes: u64,
    pub output_sha256: String,
    pub output_size_bytes: u64,
}

impl ImportedMsiDocumentTransferResult {
    pub fn validate(&self) -> Result<(), ImportedMsiRequestError> {
        if !lower_hex_sha256(&self.input_sha256)
            || !lower_hex_sha256(&self.output_sha256)
            || self.input_size_bytes > crate::MAX_INTERACTIVE_DOCUMENT_BYTES
            || self.output_size_bytes > crate::MAX_INTERACTIVE_DOCUMENT_BYTES
        {
            return Err(ImportedMsiRequestError::InvalidResult);
        }
        Ok(())
    }
}

impl ImportedMsiScenarioResult {
    pub fn succeeded(
        request: &ImportedMsiGuestRequest,
        install_exit_code: i32,
        launch_process_id: u32,
        launch_exit_code: i32,
    ) -> Result<Self, ImportedMsiRequestError> {
        Self::succeeded_with_document_transfer(
            request,
            install_exit_code,
            launch_process_id,
            launch_exit_code,
            None,
        )
    }

    pub fn succeeded_with_document_transfer(
        request: &ImportedMsiGuestRequest,
        install_exit_code: i32,
        launch_process_id: u32,
        launch_exit_code: i32,
        document_transfer: Option<ImportedMsiDocumentTransferResult>,
    ) -> Result<Self, ImportedMsiRequestError> {
        let value = Self {
            schema_version: if request.scenario.requires_document_transfer() {
                IMPORTED_MSI_DOCUMENT_SCENARIO_RESULT_SCHEMA_VERSION.to_owned()
            } else if request.scenario.interactive_session_seconds.is_some() {
                "aiw.dev/windows-sandbox-imported-msi-scenario-result/v0alpha2".to_owned()
            } else {
                IMPORTED_MSI_SCENARIO_RESULT_SCHEMA_VERSION.to_owned()
            },
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            config_sha256: request.config_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            agent_sha256: request.agent_sha256.clone(),
            scenario_id: request.scenario.scenario_id.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            installer_sha256: request.installer_sha256.clone(),
            status: ImportedMsiScenarioStatus::Succeeded,
            install_exit_code,
            launch_process_id,
            launch_exit_code,
            process_observed: true,
            graceful_close_requested: request.scenario.interactive_session_seconds.is_none(),
            process_closed: true,
            document_transfer,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ImportedMsiRequestError> {
        let interactive =
            self.schema_version == "aiw.dev/windows-sandbox-imported-msi-scenario-result/v0alpha2";
        let interactive_document =
            self.schema_version == IMPORTED_MSI_DOCUMENT_SCENARIO_RESULT_SCHEMA_VERSION;
        if (self.schema_version != IMPORTED_MSI_SCENARIO_RESULT_SCHEMA_VERSION
            && !interactive
            && !interactive_document)
            || !valid_id(&self.run_id)
            || !canonical_sandbox_id(&self.sandbox_id)
            || !lower_hex_sha256(&self.config_sha256)
            || !lower_hex_sha256(&self.request_sha256)
            || !lower_hex_sha256(&self.agent_sha256)
            || !valid_id(&self.scenario_id)
            || !lower_hex_sha256(&self.scenario_sha256)
            || !lower_hex_sha256(&self.installer_sha256)
            || self.status != ImportedMsiScenarioStatus::Succeeded
            || self.install_exit_code != 0
            || self.launch_process_id == 0
            || self.launch_exit_code != 0
            || !self.process_observed
            || self.graceful_close_requested == (interactive || interactive_document)
            || !self.process_closed
        {
            return Err(ImportedMsiRequestError::InvalidResult);
        }
        if interactive_document {
            self.document_transfer
                .as_ref()
                .ok_or(ImportedMsiRequestError::InvalidResult)?
                .validate()?;
        } else if self.document_transfer.is_some() {
            return Err(ImportedMsiRequestError::InvalidResult);
        }
        Ok(())
    }

    /// Verifies the result is a successful completion of this exact request.
    pub fn validate_for_request(
        &self,
        request: &ImportedMsiGuestRequest,
    ) -> Result<(), ImportedMsiRequestError> {
        request.validate()?;
        self.validate()?;
        let result_interactive = self.schema_version
            == "aiw.dev/windows-sandbox-imported-msi-scenario-result/v0alpha2"
            || self.schema_version == IMPORTED_MSI_DOCUMENT_SCENARIO_RESULT_SCHEMA_VERSION;
        if self.run_id != request.run_id
            || result_interactive != request.scenario.interactive_session_seconds.is_some()
            || (self.schema_version == IMPORTED_MSI_DOCUMENT_SCENARIO_RESULT_SCHEMA_VERSION)
                != request.scenario.requires_document_transfer()
            || self.sandbox_id != request.sandbox_id
            || self.config_sha256 != request.config_sha256
            || self.request_sha256 != request.request_sha256
            || self.agent_sha256 != request.agent_sha256
            || self.scenario_id != request.scenario.scenario_id
            || self.scenario_sha256 != request.scenario_sha256
            || self.installer_sha256 != request.installer_sha256
            || self.launch_exit_code != request.scenario.expected_exit_code
        {
            return Err(ImportedMsiRequestError::ResultBindingMismatch);
        }
        if request.scenario.requires_document_transfer() {
            let transfer = self
                .document_transfer
                .as_ref()
                .ok_or(ImportedMsiRequestError::ResultBindingMismatch)?;
            let contract = request
                .scenario
                .interactive_document
                .as_ref()
                .ok_or(ImportedMsiRequestError::ResultBindingMismatch)?;
            if transfer.input_sha256 != contract.input_sha256
                || transfer.input_size_bytes != contract.input_size_bytes
            {
                return Err(ImportedMsiRequestError::ResultBindingMismatch);
            }
        }
        Ok(())
    }

    pub fn successful(&self) -> bool {
        matches!(self.status, ImportedMsiScenarioStatus::Succeeded)
            && self.install_exit_code == 0
            && self.launch_process_id != 0
            && self.launch_exit_code == 0
            && self.process_observed
            && (self.graceful_close_requested
                || self.schema_version
                    == "aiw.dev/windows-sandbox-imported-msi-scenario-result/v0alpha2"
                || self.schema_version == IMPORTED_MSI_DOCUMENT_SCENARIO_RESULT_SCHEMA_VERSION)
            && self.process_closed
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImportedMsiRequestError {
    #[error("imported MSI request is outside the fixed profile")]
    InvalidRequest,
    #[error("imported MSI request hash does not match the canonical request")]
    RequestHashMismatch,
    #[error("imported MSI request scenario binding is inconsistent")]
    ScenarioBindingMismatch,
    #[error("imported MSI scenario is invalid: {0}")]
    Scenario(crate::ScenarioCompileError),
    #[error("imported MSI scenario result is invalid")]
    InvalidResult,
    #[error("imported MSI scenario result is not bound to the approved request")]
    ResultBindingMismatch,
    #[error("could not canonicalize imported MSI request: {0}")]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario() -> CompiledMsiScenario {
        CompiledMsiScenario {
            schema_version: "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha1".to_owned(),
            profile: "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha1".to_owned(),
            scenario_id: "first-run".to_owned(),
            application_sha256: "a".repeat(64),
            installer_path: STAGED_INSTALLER_PATH.to_owned(),
            install_arguments: vec![
                "/i".to_owned(),
                STAGED_INSTALLER_PATH.to_owned(),
                "/qn".to_owned(),
                "/norestart".to_owned(),
            ],
            install_timeout_seconds: 120,
            launch_path: r"C:\Program Files\Notepad++\notepad++.exe".to_owned(),
            launch_arguments: Vec::new(),
            process_image: "notepad++.exe".to_owned(),
            process_wait_timeout_seconds: 30,
            graceful_close_timeout_seconds: 15,
            expected_exit_code: 0,
            interactive_session_seconds: None,
            document_exercise: None,
            interactive_document: None,
        }
    }

    fn request() -> ImportedMsiGuestRequest {
        ImportedMsiGuestRequest::new(
            "run-1",
            "11111111-1111-1111-1111-111111111111",
            "b".repeat(64),
            "c".repeat(64),
            scenario(),
            "a".repeat(64),
            1024,
            "d".repeat(64),
        )
        .unwrap()
    }

    #[test]
    fn request_is_canonically_bound_to_scenario_and_installer() {
        let request = request();
        request.validate().unwrap();
        assert_eq!(
            request.request_sha256,
            request.recompute_request_sha256().unwrap()
        );
        ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
    }

    #[test]
    fn rejects_tampered_request_and_result_values() {
        let mut tampered_request = request();
        tampered_request.installer_path = r"C:\other.msi".to_owned();
        assert_eq!(
            tampered_request.validate(),
            Err(ImportedMsiRequestError::InvalidRequest)
        );

        let request = request();
        let mut result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
        result.process_closed = false;
        assert_eq!(
            result.validate(),
            Err(ImportedMsiRequestError::InvalidResult)
        );

        let mut result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
        result.run_id = "other-run".to_owned();
        assert_eq!(
            result.validate_for_request(&request),
            Err(ImportedMsiRequestError::ResultBindingMismatch)
        );
    }

    #[test]
    fn rejects_installer_larger_than_guest_profile_bound() {
        assert_eq!(
            ImportedMsiGuestRequest::new(
                "run-1",
                "11111111-1111-1111-1111-111111111111",
                "b".repeat(64),
                "c".repeat(64),
                scenario(),
                "a".repeat(64),
                MAX_INSTALLER_BYTES + 1,
                "d".repeat(64),
            ),
            Err(ImportedMsiRequestError::InvalidRequest)
        );
    }

    #[test]
    fn transfer_result_is_bound_to_the_typed_input_contract() {
        let mut request = request();
        request.scenario.schema_version =
            crate::COMPILED_MSI_INTERACTIVE_DOCUMENT_SCENARIO_SCHEMA_VERSION.to_owned();
        request.scenario.profile = crate::NOTEPAD_PLUS_PLUS_INTERACTIVE_DOCUMENT_PROFILE.to_owned();
        request.scenario.interactive_session_seconds = Some(60);
        request.scenario.interactive_document = Some(crate::InteractiveDocumentTransfer {
            input_sha256: "e".repeat(64),
            input_size_bytes: 7,
        });
        request.scenario_sha256 = request.scenario.canonical_sha256().unwrap();
        request.request_sha256 = request.request_sha256().unwrap();
        request.validate().unwrap();

        let result = ImportedMsiScenarioResult::succeeded_with_document_transfer(
            &request,
            0,
            42,
            0,
            Some(ImportedMsiDocumentTransferResult {
                input_sha256: "e".repeat(64),
                input_size_bytes: 7,
                output_sha256: "f".repeat(64),
                output_size_bytes: 9,
            }),
        )
        .unwrap();
        result.validate_for_request(&request).unwrap();

        let mut tampered = result.clone();
        tampered
            .document_transfer
            .as_mut()
            .unwrap()
            .input_size_bytes = 8;
        assert_eq!(
            tampered.validate_for_request(&request),
            Err(ImportedMsiRequestError::ResultBindingMismatch)
        );
        let missing = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0);
        assert_eq!(missing, Err(ImportedMsiRequestError::InvalidResult));
    }
}
