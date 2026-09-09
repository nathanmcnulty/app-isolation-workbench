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
}
