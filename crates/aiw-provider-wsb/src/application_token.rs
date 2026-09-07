use aiw_evidence::{EvidenceRecord, verify_records};
use aiw_token::{TOKEN_EVIDENCE_SCHEMA_VERSION, TokenEvidence, TokenType};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ImportedMsiGuestRequest, ImportedMsiScenarioResult};

pub const MSI_APPLICATION_TOKEN_SCHEMA: &str = "aiw.dev/msi-application-token/v0alpha1";
pub const MSI_APPLICATION_TOKEN_EVENT: &str = "importedMsiApplicationToken";

/// A guest-reported snapshot of the launched root process, not host attestation
/// or descendant coverage. Token collection occurs after its window is observed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiApplicationToken {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub scenario_sha256: String,
    pub token: TokenEvidence,
}

impl ImportedMsiApplicationToken {
    pub fn new(
        request: &ImportedMsiGuestRequest,
        result: &ImportedMsiScenarioResult,
        token: TokenEvidence,
    ) -> Result<Self, String> {
        let observation = Self {
            schema_version: MSI_APPLICATION_TOKEN_SCHEMA.to_owned(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            token,
        };
        observation.validate_for(request, result)?;
        Ok(observation)
    }

    pub fn validate_for(
        &self,
        request: &ImportedMsiGuestRequest,
        result: &ImportedMsiScenarioResult,
    ) -> Result<(), String> {
        result
            .validate_for_request(request)
            .map_err(|e| e.to_string())?;
        if self.schema_version != MSI_APPLICATION_TOKEN_SCHEMA
            || self.run_id != request.run_id
            || self.sandbox_id != request.sandbox_id
            || self.request_sha256 != request.request_sha256
            || self.scenario_sha256 != request.scenario_sha256
            || self.token.schema_version != TOKEN_EVIDENCE_SCHEMA_VERSION
            || self.token.process_id != result.launch_process_id
            || self.token.token_type != TokenType::Primary
            || self.token.impersonation_level.is_some()
            || self.token.user_sid.is_empty()
            || self.token.integrity.sid.is_empty()
            || self.token.integrity.level
                != aiw_token::classify_integrity_rid(self.token.integrity.rid)
            || self.token.is_app_container != self.token.app_container_sid.is_some()
        {
            return Err(
                "application token observation is not bound to the launched MSI process".to_owned(),
            );
        }
        Ok(())
    }
}

/// Reverify the bytes against an already verified completion root before using
/// an optional observation. An old log without this event has missing evidence.
pub fn verify_msi_application_token(
    bytes: &[u8],
    expected_root: &str,
    request: &ImportedMsiGuestRequest,
    result: &ImportedMsiScenarioResult,
) -> Result<Option<ImportedMsiApplicationToken>, String> {
    if bytes.len() > 1024 * 1024 {
        return Err("application evidence log exceeds its bound".to_owned());
    }
    let mut records = Vec::<EvidenceRecord>::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if records.len() >= 128 || line.len() > 64 * 1024 {
            return Err("application evidence record exceeds its bound".to_owned());
        }
        records.push(
            serde_json::from_slice(line)
                .map_err(|e| format!("invalid application evidence: {e}"))?,
        );
    }
    let manifest = verify_records(&records).map_err(|e| e.to_string())?;
    if records.is_empty() || manifest.root_hash != expected_root {
        return Err("application evidence differs from verified completion".to_owned());
    }
    result
        .validate_for_request(request)
        .map_err(|e| e.to_string())?;
    let mut observation = None;
    for record in records
        .iter()
        .filter(|r| r.kind == MSI_APPLICATION_TOKEN_EVENT)
    {
        if observation.is_some() || record.source != "aiw-guest-agent" {
            return Err("duplicate or foreign application token observation".to_owned());
        }
        let current: ImportedMsiApplicationToken =
            serde_json::from_value(record.payload.clone())
                .map_err(|e| format!("invalid application token observation: {e}"))?;
        current.validate_for(request, result)?;
        observation = Some(current);
    }
    if observation.is_none() && request.scenario.requires_application_token() {
        return Err("approved MSI profile requires application token evidence".to_owned());
    }
    Ok(observation)
}
