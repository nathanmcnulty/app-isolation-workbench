use aiw_token::{ElevationType, IntegrityLevel, TokenType};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ImportedMsiApplicationToken, ImportedMsiGuestRequest, ImportedMsiScenarioResult,
    application_token::verified_application_records,
};

pub const IMPORTED_MSI_RUNTIME_CONTEXT_SCHEMA_VERSION: &str =
    "aiw.dev/windows-sandbox-imported-msi-runtime-context/v0alpha1";
pub const IMPORTED_MSI_RUNTIME_CONTEXT_SCHEMA: &str = IMPORTED_MSI_RUNTIME_CONTEXT_SCHEMA_VERSION;
pub const IMPORTED_MSI_RUNTIME_CONTEXT_EVENT: &str = "importedMsiRuntimeContext";
pub const STANDARD_USER_ACCOUNT_NAME: &str = "AiwStandardUser";
pub const STANDARD_USER_PROFILE_PATH: &str = r"C:\Users\AiwStandardUser";

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StandardUserRuntimeContext {
    pub user_sid: String,
    pub profile_path: String,
    pub roaming_app_data: String,
    pub local_app_data: String,
    pub administrators_enabled: bool,
}

impl StandardUserRuntimeContext {
    pub fn validate(&self) -> Result<(), String> {
        if !valid_account_sid(&self.user_sid)
            || self.administrators_enabled
            || !self
                .profile_path
                .eq_ignore_ascii_case(STANDARD_USER_PROFILE_PATH)
            || !self
                .roaming_app_data
                .eq_ignore_ascii_case(r"C:\Users\AiwStandardUser\AppData\Roaming")
            || !self
                .local_app_data
                .eq_ignore_ascii_case(r"C:\Users\AiwStandardUser\AppData\Local")
        {
            return Err("standard-user runtime context has invalid identity or paths".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiRuntimeContext {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub scenario_sha256: String,
    pub process_id: u32,
    pub context: StandardUserRuntimeContext,
}

impl ImportedMsiRuntimeContext {
    pub fn new(
        request: &ImportedMsiGuestRequest,
        result: &ImportedMsiScenarioResult,
        application_token: &ImportedMsiApplicationToken,
        context: StandardUserRuntimeContext,
    ) -> Result<Self, String> {
        let value = Self {
            schema_version: IMPORTED_MSI_RUNTIME_CONTEXT_SCHEMA_VERSION.to_owned(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            process_id: result.launch_process_id,
            context,
        };
        value.validate_for(request, result, application_token)?;
        Ok(value)
    }

    pub fn validate_for(
        &self,
        request: &ImportedMsiGuestRequest,
        result: &ImportedMsiScenarioResult,
        application_token: &ImportedMsiApplicationToken,
    ) -> Result<(), String> {
        result
            .validate_for_request(request)
            .map_err(|e| e.to_string())?;
        application_token.validate_for(request, result)?;
        let token = &application_token.token;
        if !request.scenario.requires_standard_user()
            || self.schema_version != IMPORTED_MSI_RUNTIME_CONTEXT_SCHEMA_VERSION
            || self.run_id != request.run_id
            || self.sandbox_id != request.sandbox_id
            || self.request_sha256 != request.request_sha256
            || self.scenario_sha256 != request.scenario_sha256
            || self.process_id != result.launch_process_id
            || self.process_id != token.process_id
            || self.context.user_sid != token.user_sid
            || token.token_type != TokenType::Primary
            || token.impersonation_level.is_some()
            || token.is_app_container
            || token.app_container_sid.is_some()
            || token.restricted_sid_count != 0
            || token.is_elevated
            || token.elevation_type != ElevationType::Default
            || token.integrity.level != IntegrityLevel::Medium
            || token.integrity.rid != 0x2000
            || token.integrity.sid != "S-1-16-8192"
            || !token.capabilities.is_empty()
        {
            return Err(
                "imported MSI runtime context is not a bounded standard-user observation"
                    .to_owned(),
            );
        }
        self.context.validate()
    }
}

pub fn verify_imported_msi_runtime_context(
    bytes: &[u8],
    expected_root: &str,
    request: &ImportedMsiGuestRequest,
    result: &ImportedMsiScenarioResult,
    application_token: Option<&ImportedMsiApplicationToken>,
) -> Result<Option<ImportedMsiRuntimeContext>, String> {
    result
        .validate_for_request(request)
        .map_err(|e| e.to_string())?;
    let records = verified_application_records(bytes, expected_root)?;
    let mut observation = None;
    for record in records
        .iter()
        .filter(|r| r.kind == IMPORTED_MSI_RUNTIME_CONTEXT_EVENT)
    {
        if observation.is_some() || record.source != "aiw-guest-agent" {
            return Err("duplicate or foreign imported MSI runtime context".to_owned());
        }
        let current: ImportedMsiRuntimeContext = serde_json::from_value(record.payload.clone())
            .map_err(|e| format!("invalid imported MSI runtime context: {e}"))?;
        let token = application_token.ok_or_else(|| {
            "runtime context evidence requires matching application token evidence".to_owned()
        })?;
        current.validate_for(request, result, token)?;
        observation = Some(current);
    }
    if observation.is_none() && request.scenario.requires_standard_user() {
        return Err("v4 standard-user profile requires runtime context evidence".to_owned());
    }
    Ok(observation)
}

pub fn verify_msi_runtime_context(
    bytes: &[u8],
    expected_root: &str,
    request: &ImportedMsiGuestRequest,
    result: &ImportedMsiScenarioResult,
    application_token: Option<&ImportedMsiApplicationToken>,
) -> Result<Option<ImportedMsiRuntimeContext>, String> {
    verify_imported_msi_runtime_context(bytes, expected_root, request, result, application_token)
}

fn valid_account_sid(value: &str) -> bool {
    let Some(account) = value.strip_prefix("S-1-5-21-") else {
        return false;
    };
    let parts: Vec<_> = account.split('-').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            part.parse::<u32>()
                .is_ok_and(|number| number.to_string() == *part)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompiledMsiScenario, FixedDocumentExercise};
    use aiw_evidence::{EvidenceEvent, EvidenceLog};
    use aiw_token::{IntegrityEvidence, TOKEN_EVIDENCE_SCHEMA_VERSION};
    use sha2::{Digest, Sha256};

    fn request() -> ImportedMsiGuestRequest {
        let scenario = CompiledMsiScenario {
            schema_version: "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha4".into(),
            profile: "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha4".into(),
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

    fn token(pid: u32) -> aiw_token::TokenEvidence {
        aiw_token::TokenEvidence {
            schema_version: TOKEN_EVIDENCE_SCHEMA_VERSION.into(),
            process_id: pid,
            token_type: TokenType::Primary,
            impersonation_level: None,
            is_app_container: false,
            app_container_sid: None,
            user_sid: "S-1-5-21-1-2-3-4".into(),
            integrity: IntegrityEvidence {
                sid: "S-1-16-8192".into(),
                rid: 8192,
                level: IntegrityLevel::Medium,
            },
            elevation_type: ElevationType::Default,
            is_elevated: false,
            capabilities: vec![],
            restricted_sid_count: 0,
        }
    }

    fn context() -> StandardUserRuntimeContext {
        StandardUserRuntimeContext {
            user_sid: "S-1-5-21-1-2-3-4".into(),
            profile_path: STANDARD_USER_PROFILE_PATH.into(),
            roaming_app_data: r"C:\Users\AiwStandardUser\AppData\Roaming".into(),
            local_app_data: r"C:\Users\AiwStandardUser\AppData\Local".into(),
            administrators_enabled: false,
        }
    }

    fn log_bytes(payloads: Vec<serde_json::Value>) -> (Vec<u8>, String) {
        let mut log = EvidenceLog::new();
        for payload in payloads {
            log.append(EvidenceEvent {
                observed_utc: "2026-09-08T00:00:00Z".into(),
                kind: IMPORTED_MSI_RUNTIME_CONTEXT_EVENT.into(),
                source: "aiw-guest-agent".into(),
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

    #[test]
    fn context_rejects_arbitrary_profile_and_traversal() {
        let context = StandardUserRuntimeContext {
            user_sid: "S-1-5-21-test".to_owned(),
            profile_path: r"C:\Users\Other".to_owned(),
            roaming_app_data: r"C:\Users\Other\AppData\Roaming".to_owned(),
            local_app_data: r"C:\Users\AiwStandardUser\..\Other".to_owned(),
            administrators_enabled: false,
        };
        assert!(context.validate().is_err());
    }

    #[test]
    fn successful_event_round_trip_and_missing_v4_event_are_strict() {
        let request = request();
        let result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
        let token = ImportedMsiApplicationToken::new(&request, &result, token(42)).unwrap();
        let event = ImportedMsiRuntimeContext::new(&request, &result, &token, context()).unwrap();
        let (bytes, root) = log_bytes(vec![serde_json::to_value(&event).unwrap()]);
        assert!(
            verify_msi_runtime_context(&bytes, &root, &request, &result, Some(&token))
                .unwrap()
                .is_some()
        );
        let (empty, empty_root) = log_bytes(vec![]);
        assert!(
            verify_msi_runtime_context(&empty, &empty_root, &request, &result, Some(&token))
                .is_err()
        );
    }

    #[test]
    fn wrong_identity_token_and_context_values_fail_without_panicking() {
        let request = request();
        let result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
        let token = ImportedMsiApplicationToken::new(&request, &result, token(42)).unwrap();
        for mutate in [
            |c: &mut StandardUserRuntimeContext| c.user_sid = "S-1-5-21-1-2-3-5".into(),
            |c: &mut StandardUserRuntimeContext| c.profile_path = r"C:\Users\Other".into(),
            |c: &mut StandardUserRuntimeContext| {
                c.local_app_data = r"C:\Users\AiwStandardUser\AppData\Local\..\Other".into()
            },
            |c: &mut StandardUserRuntimeContext| c.administrators_enabled = true,
        ] {
            let mut value = context();
            mutate(&mut value);
            assert!(ImportedMsiRuntimeContext::new(&request, &result, &token, value).is_err());
        }
        let mut high = token.clone();
        high.token.is_elevated = true;
        assert!(ImportedMsiRuntimeContext::new(&request, &result, &high, context()).is_err());
    }
}
