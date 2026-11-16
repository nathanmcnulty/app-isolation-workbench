//! Closed transport for a reviewed application assessment. This contract does
//! not authorize execution: preparation, approval and Start bind it separately.
use aiw_evidence::canonical_json_bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assessment::CompiledAssessment;

pub const APPLICATION_ASSESSMENT_REQUEST_SCHEMA: &str =
    "aiw.dev/application-assessment-request/v0alpha1";
pub const APPLICATION_ASSESSMENT_REQUEST_V2_SCHEMA: &str =
    "aiw.dev/application-assessment-request/v0alpha2";
pub const ASSESSMENT_CHANNEL_REQUEST_SCHEMA: &str = "aiw.dev/assessment-channel-request/v0alpha1";
pub const APPLICATION_ASSESSMENT_REQUEST_PATH: &str = r"C:\AIW\Tools\assessment-request.json";
pub const APPLICATION_ASSESSMENT_RESULT_PATH: &str = r"C:\AIW\Output\assessment-result.json";
pub const APPLICATION_ASSESSMENT_AGENT_PATH: &str = r"C:\AIW\Tools\aiw-guest-agent.exe";
pub const APPLICATION_ASSESSMENT_REQUEST_MAX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentChannelRequest {
    pub schema_version: String,
    pub channel_protocol: String,
    pub plan_sha256: String,
    pub provider_sha256: String,
    pub provider_protocol: aiw_probe::WindowsSandboxCliProtocol,
    pub workspace_identity_sha256: String,
    pub nonce_hex: String,
    pub host_ack_public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, JsonSchema)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<AssessmentChannelRequest>,
}

// Preserve alpha1 bytes and reject even an explicit channel:null there. Option
// alone erases wire presence; this field's custom type tracks it separately.
#[derive(Default)]
struct ChannelPresence {
    present: bool,
    value: Option<AssessmentChannelRequest>,
}
impl<'de> Deserialize<'de> for ChannelPresence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self {
            present: true,
            value: Option::<AssessmentChannelRequest>::deserialize(deserializer)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestWire {
    schema_version: String,
    run_id: String,
    sandbox_id: String,
    config_sha256: String,
    agent_sha256: String,
    project_revision_sha256: String,
    assessment_sha256: String,
    assessment: CompiledAssessment,
    request_sha256: String,
    #[serde(default)]
    channel: ChannelPresence,
}
impl<'de> Deserialize<'de> for ApplicationAssessmentGuestRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let w = RequestWire::deserialize(deserializer)?;
        if w.schema_version == APPLICATION_ASSESSMENT_REQUEST_SCHEMA && w.channel.present {
            return Err(serde::de::Error::custom(
                "historical assessment request cannot contain channel",
            ));
        }
        Ok(Self {
            schema_version: w.schema_version,
            run_id: w.run_id,
            sandbox_id: w.sandbox_id,
            config_sha256: w.config_sha256,
            agent_sha256: w.agent_sha256,
            project_revision_sha256: w.project_revision_sha256,
            assessment_sha256: w.assessment_sha256,
            assessment: w.assessment,
            request_sha256: w.request_sha256,
            channel: w.channel.value,
        })
    }
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
            channel: None,
        };
        value.request_sha256 = value.request_hash()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !matches!(
            (self.schema_version.as_str(), self.channel.is_some()),
            (APPLICATION_ASSESSMENT_REQUEST_SCHEMA, false)
                | (APPLICATION_ASSESSMENT_REQUEST_V2_SCHEMA, true)
        ) || self.run_id.is_empty()
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
        if self.channel.is_some() {
            self.channel_binding_unchecked()?.validate()?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_authenticated(
        run_id: String,
        sandbox_id: String,
        config_sha256: String,
        agent_sha256: String,
        project_revision_sha256: String,
        assessment: CompiledAssessment,
        channel: AssessmentChannelRequest,
    ) -> Result<Self, String> {
        let mut value = Self {
            schema_version: APPLICATION_ASSESSMENT_REQUEST_V2_SCHEMA.into(),
            run_id,
            sandbox_id,
            config_sha256,
            agent_sha256,
            project_revision_sha256,
            assessment_sha256: assessment_value_sha256(&assessment)?,
            assessment,
            request_sha256: String::new(),
            channel: Some(channel),
        };
        value.request_sha256 = value.request_hash()?;
        value.validate()?;
        Ok(value)
    }
    pub fn require_authenticated_execution(&self) -> Result<(), String> {
        self.channel_binding().map(|_| ())
    }
    pub fn channel_binding(
        &self,
    ) -> Result<crate::assessment_channel::AssessmentChannelBinding, String> {
        self.validate()?;
        self.channel_binding_unchecked()
    }
    fn channel_binding_unchecked(
        &self,
    ) -> Result<crate::assessment_channel::AssessmentChannelBinding, String> {
        use crate::assessment_channel::{
            AssessmentChannelBinding, CHANNEL_PROTOCOL, CHANNEL_SCHEMA,
        };
        let channel = self.channel.as_ref().ok_or(
            "historical assessment request is read-only; authenticated execution required",
        )?;
        if self.schema_version != APPLICATION_ASSESSMENT_REQUEST_V2_SCHEMA
            || channel.schema_version != ASSESSMENT_CHANNEL_REQUEST_SCHEMA
            || channel.channel_protocol != CHANNEL_PROTOCOL
        {
            return Err("assessment channel request version refused".into());
        }
        Ok(AssessmentChannelBinding {
            schema_version: CHANNEL_SCHEMA.into(),
            channel_protocol: channel.channel_protocol.clone(),
            run_id: self.run_id.clone(),
            plan_sha256: channel.plan_sha256.clone(),
            project_revision_sha256: self.project_revision_sha256.clone(),
            assessment_sha256: self.assessment_sha256.clone(),
            semantic_sha256: self.assessment.semantic_sha256.clone(),
            application_content_manifest_sha256: self.assessment.portable_manifest_sha256.clone(),
            agent_sha256: self.agent_sha256.clone(),
            provider_sha256: channel.provider_sha256.clone(),
            provider_protocol: channel.provider_protocol.clone(),
            config_sha256: self.config_sha256.clone(),
            sandbox_id: self.sandbox_id.clone(),
            workspace_identity_sha256: channel.workspace_identity_sha256.clone(),
            request_sha256: self.request_sha256.clone(),
            nonce_hex: channel.nonce_hex.clone(),
            host_ack_public_key_hex: channel.host_ack_public_key_hex.clone(),
        })
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
    fn channel() -> AssessmentChannelRequest {
        let mut key = [1u8; 72];
        key[..8].copy_from_slice(&[0x45, 0x43, 0x53, 0x31, 32, 0, 0, 0]);
        AssessmentChannelRequest {
            schema_version: ASSESSMENT_CHANNEL_REQUEST_SCHEMA.into(),
            channel_protocol: crate::assessment_channel::CHANNEL_PROTOCOL.into(),
            plan_sha256: "d".repeat(64),
            provider_sha256: "e".repeat(64),
            provider_protocol: aiw_probe::WindowsSandboxCliAdapter::V0_8_114_0.protocol(),
            workspace_identity_sha256: "f".repeat(64),
            nonce_hex: "1".repeat(64),
            host_ack_public_key_hex: hex::encode(key),
        }
    }
    #[test]
    fn historical_wire_has_no_channel_and_refuses_even_explicit_null() {
        let old = request();
        let bytes = serde_json::to_vec(&old).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("channel").is_none());
        assert!(old.require_authenticated_execution().is_err());
        for extra in [
            serde_json::Value::Null,
            serde_json::to_value(channel()).unwrap(),
        ] {
            let mut changed = value.clone();
            changed["channel"] = extra;
            assert!(serde_json::from_value::<ApplicationAssessmentGuestRequest>(changed).is_err());
        }
        let mut legacy_shape = value;
        legacy_shape["requestSha256"] = serde_json::json!("");
        assert_eq!(
            old.request_hash().unwrap(),
            assessment_value_sha256(&legacy_shape).unwrap()
        );
    }
    #[test]
    fn authenticated_request_commits_public_entropy_without_a_hash_cycle() {
        let old = request();
        let r = ApplicationAssessmentGuestRequest::new_authenticated(
            old.run_id,
            old.sandbox_id,
            old.config_sha256,
            old.agent_sha256,
            old.project_revision_sha256,
            old.assessment,
            channel(),
        )
        .unwrap();
        r.require_authenticated_execution().unwrap();
        let binding = r.channel_binding().unwrap();
        assert_eq!(binding.request_sha256, r.request_sha256);
        assert_eq!(
            binding.application_content_manifest_sha256,
            r.assessment.portable_manifest_sha256
        );
        assert_eq!(binding.plan_sha256, r.channel.as_ref().unwrap().plan_sha256);
        assert_eq!(
            serde_json::from_slice::<ApplicationAssessmentGuestRequest>(
                &serde_json::to_vec(&r).unwrap()
            )
            .unwrap(),
            r
        );
        let mut changed = r.clone();
        changed.channel.as_mut().unwrap().nonce_hex = "2".repeat(64);
        assert!(changed.validate().is_err());
        changed.request_sha256 = changed.request_hash().unwrap();
        changed.validate().unwrap();
        assert_ne!(changed.request_sha256, r.request_sha256);
        changed
            .channel
            .as_mut()
            .unwrap()
            .provider_protocol
            .cli_version = "0.8.115.0".into();
        changed.request_sha256 = changed.request_hash().unwrap();
        assert!(changed.validate().is_err());
        let mut missing = r;
        missing.channel = None;
        missing.request_sha256 = missing.request_hash().unwrap();
        assert!(missing.validate().is_err());
    }
}
