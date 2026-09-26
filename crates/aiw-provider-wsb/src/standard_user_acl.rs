//! Fixed guest standard-user file ACL control, not an outer Sandbox isolation claim.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STANDARD_USER_ACL_PROTECTED_PATH: &str = r"C:\AIW\acl-canary.txt";
pub const STANDARD_USER_ACL_POSITIVE_PATH: &str =
    r"C:\Users\AiwStandardUser\AppData\Local\AIW\Scenario\acl-positive.txt";
pub const STANDARD_USER_ACL_CONTROL_BYTES: &[u8] = b"AIW fixed standard-user ACL control v1\r\n";

#[derive(Debug, Clone, Copy, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MsiRequiredObservations {
    StandardUserAclV1,
}

impl MsiRequiredObservations {
    pub fn validate_for(self, scenario: &crate::CompiledMsiScenario) -> Result<(), String> {
        scenario.validate().map_err(|error| error.to_string())?;
        if !matches!(
            scenario.schema_version.as_str(),
            crate::COMPILED_MSI_SCENARIO_SCHEMA_VERSION
                | crate::COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION
                | crate::scenario::LEGACY_COMPILED_MSI_LOCAL_SETTINGS_SCENARIO_SCHEMA_VERSION
        ) || !scenario.requires_standard_user()
            || !scenario.requires_application_exercise()
            || scenario.interactive_session_seconds.is_some()
        {
            return Err(
                "standard-user ACL control requires the fixed automated MSI profile".into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StandardUserAclObservation {
    pub process_id: u32,
    pub user_sid: String,
    pub protected_path: String,
    pub protected_owner_sid: String,
    pub protected_volume_serial: u32,
    pub protected_file_id: u64,
    pub protected_sha256: String,
    pub protected_size_bytes: u64,
    pub protected_acl_verified: bool,
    pub denied_read_error: u32,
    pub positive_path: String,
    pub positive_volume_serial: u32,
    pub positive_file_id: u64,
    pub positive_sha256: String,
    pub positive_size_bytes: u64,
}

impl StandardUserAclObservation {
    pub fn validate(&self) -> Result<(), String> {
        let expected_hash = hex::encode(Sha256::digest(STANDARD_USER_ACL_CONTROL_BYTES));
        if self.process_id == 0
            || !crate::runtime_context::valid_account_sid(&self.user_sid)
            || !(crate::runtime_context::valid_account_sid(&self.protected_owner_sid)
                || self.protected_owner_sid == "S-1-5-18")
            || self.protected_owner_sid == self.user_sid
            || self.protected_path != STANDARD_USER_ACL_PROTECTED_PATH
            || self.positive_path != STANDARD_USER_ACL_POSITIVE_PATH
            || self.protected_file_id == 0
            || self.positive_file_id == 0
            || (self.protected_volume_serial == self.positive_volume_serial
                && self.protected_file_id == self.positive_file_id)
            || !self.protected_acl_verified
            || self.denied_read_error != 5
            || self.protected_sha256 != expected_hash
            || self.positive_sha256 != expected_hash
            || self.protected_size_bytes != STANDARD_USER_ACL_CONTROL_BYTES.len() as u64
            || self.positive_size_bytes != STANDARD_USER_ACL_CONTROL_BYTES.len() as u64
        {
            return Err("standard-user ACL control is absent, invalid, or did not pass".into());
        }
        Ok(())
    }
}
