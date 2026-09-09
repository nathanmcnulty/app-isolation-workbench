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
        if self.user_sid.is_empty()
            || self.administrators_enabled
            || !valid_fixed_path(&self.profile_path)
            || !same_path(&self.profile_path, STANDARD_USER_PROFILE_PATH)
            || !valid_fixed_path(&self.roaming_app_data)
            || !valid_fixed_path(&self.local_app_data)
            || !is_descendant(&self.roaming_app_data, &self.profile_path)
            || !is_descendant(&self.local_app_data, &self.profile_path)
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
            || !(0x2000..=0x20ff).contains(&token.integrity.rid)
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

fn valid_fixed_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !value.contains(['\0', '\r', '\n', '\t', '/', '%'])
        && value.split('\\').skip(1).all(|part| {
            !part.is_empty() && part != "." && part != ".." && !part.ends_with([' ', '.'])
        })
}

fn same_path(left: &str, right: &str) -> bool {
    left.trim_end_matches('\\')
        .eq_ignore_ascii_case(right.trim_end_matches('\\'))
}

fn is_descendant(path: &str, parent: &str) -> bool {
    let prefix = format!("{}\\", parent.trim_end_matches('\\'));
    path.len() > prefix.len() && path[..prefix.len()].eq_ignore_ascii_case(&prefix)
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
