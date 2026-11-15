//! Closed transport for a reviewed application assessment. This contract does
//! not authorize execution: preparation, approval and Start bind it separately.
use aiw_evidence::canonical_json_bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assessment::CompiledAssessment;

pub const APPLICATION_ASSESSMENT_REQUEST_SCHEMA: &str =
    "aiw.dev/application-assessment-request/v0alpha1";
pub const APPLICATION_ASSESSMENT_REQUEST_PATH: &str = r"C:\AIW\Tools\assessment-request.json";
pub const APPLICATION_ASSESSMENT_RESULT_PATH: &str = r"C:\AIW\Output\assessment-result.json";
pub const APPLICATION_ASSESSMENT_AGENT_PATH: &str = r"C:\AIW\Tools\aiw-guest-agent.exe";
pub const APPLICATION_ASSESSMENT_REQUEST_MAX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationAssessmentGuestRequest {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub config_sha256: String,
    pub agent_sha256: String,
    pub project_revision_sha256: String,
    pub assessment_sha256: String,
    pub assessment: CompiledAssessment,
    pub request_sha256: String,
}

pub fn assessment_value_sha256(value: &impl Serialize) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let bytes = canonical_json_bytes(&value).map_err(|error| error.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn sandbox_id_valid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
        && value
            .bytes()
            .any(|byte| (b'1'..=b'9').contains(&byte) || (b'a'..=b'f').contains(&byte))
}

impl ApplicationAssessmentGuestRequest {
    pub fn request_hash(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.request_sha256.clear();
        assessment_value_sha256(&value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: String,
        sandbox_id: String,
        config_sha256: String,
        agent_sha256: String,
        project_revision_sha256: String,
        assessment: CompiledAssessment,
    ) -> Result<Self, String> {
        let mut value = Self {
            schema_version: APPLICATION_ASSESSMENT_REQUEST_SCHEMA.into(),
            run_id,
            sandbox_id,
            config_sha256,
            agent_sha256,
            project_revision_sha256,
            assessment_sha256: assessment_value_sha256(&assessment)?,
            assessment,
            request_sha256: String::new(),
        };
        value.request_sha256 = value.request_hash()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != APPLICATION_ASSESSMENT_REQUEST_SCHEMA
            || self.run_id.is_empty()
            || self.run_id.len() > 80
            || !self
                .run_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || matches!(self.run_id.as_str(), "." | "..")
            || !sandbox_id_valid(&self.sandbox_id)
            || [
                &self.config_sha256,
                &self.agent_sha256,
                &self.project_revision_sha256,
                &self.assessment_sha256,
                &self.request_sha256,
            ]
            .iter()
            .any(|hash| !hash_valid(hash))
        {
            return Err(
                "application assessment request version or execution binding is invalid".into(),
            );
        }
        self.assessment
            .validate()
            .map_err(|error| format!("compiled assessment rejected: {error:?}"))?;
        if assessment_value_sha256(&self.assessment)? != self.assessment_sha256
            || self.request_hash()? != self.request_sha256
        {
            return Err(
                "application assessment request content differs from its bound identity".into(),
            );
        }
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > APPLICATION_ASSESSMENT_REQUEST_MAX_BYTES {
            return Err("complete application assessment request exceeds its size bound".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ApplicationAssessmentGuestRequest {
        let (project, settings, manifest) = crate::assessment::tests::fixture();
        let assessment =
            crate::assessment::compile_assessment(&project, &settings, &manifest).unwrap();
        ApplicationAssessmentGuestRequest::new(
            "external-application-run".into(),
            "4a0f039f-4bb7-4d14-b1d8-4c9891bc44a3".into(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            assessment,
        )
        .unwrap()
    }

    #[test]
    fn request_binding_rejects_stale_run_session_code_and_plan_content() {
        let request = request();
        request.validate().unwrap();
        let wire = serde_json::to_vec(&request).unwrap();
        let retained: ApplicationAssessmentGuestRequest = serde_json::from_slice(&wire).unwrap();
        assert_eq!(retained, request);
        for field in [
            "configSha256",
            "agentSha256",
            "projectRevisionSha256",
            "assessmentSha256",
        ] {
            let mut value = serde_json::to_value(&request).unwrap();
            value[field] = serde_json::json!("9".repeat(64));
            let changed: ApplicationAssessmentGuestRequest = serde_json::from_value(value).unwrap();
            assert!(changed.validate().is_err(), "{field}");
        }
        let mut changed = request.clone();
        changed.run_id = "other-run".into();
        assert!(changed.validate().is_err());
        changed = request.clone();
        changed.sandbox_id = "5a0f039f-4bb7-4d14-b1d8-4c9891bc44a3".into();
        assert!(changed.validate().is_err());
        changed = request;
        changed.assessment.settings.inputs[0].sha256 = "d".repeat(64);
        // A fresh outer hash cannot bless an internally inconsistent workflow.
        changed.assessment_sha256 = assessment_value_sha256(&changed.assessment).unwrap();
        changed.request_sha256 = changed.request_hash().unwrap();
        assert!(changed.validate().is_err());
    }

    #[test]
    fn request_wire_rejects_unknown_authority_fields_and_duplicate_bindings() {
        let request = request();
        let mut value = serde_json::to_value(&request).unwrap();
        value["command"] = serde_json::json!("unapproved shell text");
        assert!(serde_json::from_value::<ApplicationAssessmentGuestRequest>(value).is_err());
        let json = serde_json::to_string(&request).unwrap();
        let duplicate = format!("{{\"runId\":\"shadow\",{}", &json[1..]);
        assert!(serde_json::from_str::<ApplicationAssessmentGuestRequest>(&duplicate).is_err());
        let mut future = request;
        future.schema_version = "future".into();
        future.request_sha256 = future.request_hash().unwrap();
        assert!(future.validate().is_err());
    }
    #[test]
    fn request_path_and_identifiers_cannot_introduce_an_external_command() {
        assert_eq!(
            APPLICATION_ASSESSMENT_REQUEST_PATH,
            r"C:\AIW\Tools\assessment-request.json"
        );
        assert!(sandbox_id_valid("4a0f039f-4bb7-4d14-b1d8-4c9891bc44a3"));
        for value in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "4A0F039F-4BB7-4D14-B1D8-4C9891BC44A3",
            "../worker",
        ] {
            assert!(!sandbox_id_valid(value));
        }
        assert!(!hash_valid(&"0".repeat(64)));
        assert!(!hash_valid(&"A".repeat(64)));
    }
}
