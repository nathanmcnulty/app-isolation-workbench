//! Isolated signed-collector transport contract. No launch or native evidence admission.
//!
//! The expected binding MUST come from independently trusted, owned local Start
//! state. A self-contained imported transcript can fabricate both key pairs.
//! Authentication here proves neither collector protection nor application success.
use aiw_evidence::canonical_json_bytes;
use aiw_probe::WindowsSandboxCliProtocol;
use aiw_token::{IntegrityLevel, TokenEvidence, TokenType};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    assessment::{AssessmentMode, CompiledAssessment, CompiledAssessmentStep},
    assessment_observation::AssessmentProgressEvent,
};

pub const CHANNEL_SCHEMA: &str = "aiw.dev/assessment-channel/v0alpha1";
pub const CHANNEL_PROTOCOL: &str = "signedCollector/p256-sha256/v1";
pub const CHANNEL_PROGRESS_SCHEMA: &str = "aiw.dev/assessment-channel-progress/v0alpha1";
pub const MAX_BOOTSTRAP_BYTES: usize = 16 * 1024;
pub const MAX_ACK_BYTES: usize = 8 * 1024;
pub const MAX_TERMINAL_BYTES: usize = 64 * 1024;
pub const MAX_INPUT_BYTES: usize = 4 * 1024;
pub const MAX_PROGRESS_RECORD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PROGRESS_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROGRESS_RECORDS: u64 = 512;
pub const MAX_PRODUCER_BYTES: u64 = 35 * 1024 * 1024;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
type Result<T> = std::result::Result<T, String>;

/// Production implementations must use vetted cryptography (the platform CNG
/// verify_digest API has these exact byte widths and imports/validates the point).
/// A successful synthetic test verifier is NOT cryptographic or native proof.
pub trait AssessmentChannelVerifier {
    fn verify_digest(
        &self,
        public_key: &[u8; 72],
        digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentChannelBinding {
    pub schema_version: String,
    pub channel_protocol: String,
    pub run_id: String,
    pub plan_sha256: String,
    pub project_revision_sha256: String,
    pub assessment_sha256: String,
    pub semantic_sha256: String,
    /// CompiledAssessment.portable_manifest_sha256, never AIW build provenance.
    pub application_content_manifest_sha256: String,
    pub agent_sha256: String,
    pub provider_sha256: String,
    pub provider_protocol: WindowsSandboxCliProtocol,
    pub config_sha256: String,
    pub sandbox_id: String,
    pub workspace_identity_sha256: String,
    pub request_sha256: String,
    pub nonce_hex: String,
    pub host_ack_public_key_hex: String,
}

fn require(condition: bool, detail: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(detail.into())
    }
}
fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn hash_valid(value: &str) -> bool {
    lower_hex(value, 32) && value != ZERO_HASH
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    canonical_json_bytes(&serde_json::to_value(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
pub fn public_key_bytes(value: &str) -> Result<[u8; 72]> {
    require(lower_hex(value, 72), "channel public key hex refused")?;
    let bytes: [u8; 72] = hex::decode(value)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "channel public key length")?;
    require(
        bytes[..8] == [0x45, 0x43, 0x53, 0x31, 32, 0, 0, 0],
        "channel P256 public blob header refused",
    )?;
    // Curve-point validity is checked by the cryptographic verifier, not this shape check.
    Ok(bytes)
}
fn signature_bytes(value: &str) -> Result<[u8; 64]> {
    require(lower_hex(value, 64), "channel signature hex refused")?;
    hex::decode(value)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "channel signature length".into())
}
impl AssessmentChannelBinding {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == CHANNEL_SCHEMA && self.channel_protocol == CHANNEL_PROTOCOL,
            "channel binding version refused",
        )?;
        require(
            !self.run_id.is_empty()
                && self.run_id.len() <= 80
                && self
                    .run_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && !matches!(self.run_id.as_str(), "." | ".."),
            "channel run id refused",
        )?;
        require(
            self.sandbox_id.len() == 36
                && self.sandbox_id.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }
                })
                && self.sandbox_id != "00000000-0000-0000-0000-000000000000",
            "channel session id refused",
        )?;
        for h in [
            &self.plan_sha256,
            &self.project_revision_sha256,
            &self.assessment_sha256,
            &self.semantic_sha256,
            &self.application_content_manifest_sha256,
            &self.agent_sha256,
            &self.provider_sha256,
            &self.config_sha256,
            &self.workspace_identity_sha256,
            &self.request_sha256,
        ] {
            require(hash_valid(h), "channel binding hash refused")?;
        }
        require(
            lower_hex(&self.nonce_hex, 32) && self.nonce_hex != ZERO_HASH,
            "channel nonce refused",
        )?;
        self.provider_protocol.adapter().map_err(str::to_owned)?;
        public_key_bytes(&self.host_ack_public_key_hex)?;
        require(
            canonical(self)?.len() <= MAX_INPUT_BYTES,
            "channel context exceeds bound",
        )
    }
    pub fn context_sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(sha(&canonical(self)?))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ChannelRecordKind {
    Bootstrap,
    HostAck,
    Progress,
    Terminal,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelSignatureInput {
    pub schema_version: String,
    pub channel_protocol: String,
    pub kind: ChannelRecordKind,
    pub context_sha256: String,
    pub guest_key_sha256: String,
    pub sequence: u64,
    pub previous_commitment: String,
    pub payload_size: u64,
    pub payload_sha256: String,
}
impl ChannelSignatureInput {
    fn bytes(&self) -> Result<Vec<u8>> {
        require(
            self.schema_version == CHANNEL_SCHEMA
                && self.channel_protocol == CHANNEL_PROTOCOL
                && hash_valid(&self.context_sha256)
                && hash_valid(&self.guest_key_sha256)
                && hash_valid(&self.payload_sha256)
                && lower_hex(&self.previous_commitment, 32),
            "channel signing input refused",
        )?;
        let b = canonical(self)?;
        require(
            b.len() <= MAX_INPUT_BYTES,
            "channel signing input too large",
        )?;
        Ok(b)
    }
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        let mut h = Sha256::new();
        h.update(b"AIW-ASSESSMENT-SIGN\0v1\0");
        h.update(self.bytes()?);
        Ok(h.finalize().into())
    }
    /// Signature randomness/malleability never changes this message identity.
    pub fn message_commitment(&self) -> Result<String> {
        let mut h = Sha256::new();
        h.update(b"AIW-ASSESSMENT-COMMIT\0v1\0");
        h.update(self.bytes()?);
        Ok(hex::encode(h.finalize()))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ChannelCollectorStorage {
    ProtectedGuestLocal,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ChannelAcknowledgement {
    AllowOneDispatch,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ChannelArtifactRole {
    Result,
    Evidence,
    Completion,
    Progress,
}
impl ChannelArtifactRole {
    fn path(self) -> &'static str {
        match self {
            Self::Result => "assessment-result.json",
            Self::Evidence => "evidence.jsonl",
            Self::Completion => "completion.json",
            Self::Progress => "assessment-channel-progress.jsonl",
        }
    }
    fn limit(self) -> u64 {
        match self {
            Self::Result | Self::Progress => 16 * 1024 * 1024,
            Self::Evidence | Self::Completion => 1024 * 1024,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelArtifact {
    pub role: ChannelArtifactRole,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AssessmentChannelPayload {
    Bootstrap {
        schema_version: String,
        binding: Box<AssessmentChannelBinding>,
        guest_public_key_hex: String,
        collector_token: Box<TokenEvidence>,
        collector_storage: ChannelCollectorStorage,
    },
    HostAck {
        schema_version: String,
        context_sha256: String,
        bootstrap_commitment: String,
        guest_public_key_hex: String,
        host_ack_public_key_hex: String,
        acknowledgement: ChannelAcknowledgement,
    },
    /// Authenticated transport facts only. The versioned local-collector semantic
    /// reducer is deliberately NOT implemented by this isolated module.
    Progress {
        schema_version: String,
        event: Box<AssessmentProgressEvent>,
    },
    Terminal {
        schema_version: String,
        request_sha256: String,
        assessment_sha256: String,
        artifacts: Vec<ChannelArtifact>,
        evidence_root_hash: String,
        last_progress_sequence: u64,
        last_progress_commitment: String,
    },
}
impl AssessmentChannelPayload {
    pub fn kind(&self) -> ChannelRecordKind {
        match self {
            Self::Bootstrap { .. } => ChannelRecordKind::Bootstrap,
            Self::HostAck { .. } => ChannelRecordKind::HostAck,
            Self::Progress { .. } => ChannelRecordKind::Progress,
            Self::Terminal { .. } => ChannelRecordKind::Terminal,
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Bootstrap {
                schema_version,
                binding,
                guest_public_key_hex,
                collector_token,
                ..
            } => {
                require(schema_version == CHANNEL_SCHEMA, "bootstrap schema refused")?;
                binding.validate()?;
                public_key_bytes(guest_public_key_hex)?;
                require(
                    guest_public_key_hex != &binding.host_ack_public_key_hex,
                    "channel key roles must differ",
                )?;
                require(
                    collector_token.schema_version == aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
                        && collector_token.process_id != 0
                        && collector_token.token_type == TokenType::Primary
                        && collector_token.impersonation_level.is_none()
                        && collector_token.is_elevated
                        && !collector_token.is_app_container
                        && collector_token.app_container_sid.is_none()
                        && collector_token.capabilities.is_empty()
                        && collector_token.restricted_sid_count == 0
                        && collector_token.integrity.level == IntegrityLevel::High
                        && collector_token.integrity.rid == 12288
                        && collector_token.integrity.sid == "S-1-16-12288"
                        && collector_token.user_sid.starts_with("S-1-")
                        && collector_token.user_sid.len() <= 184,
                    "bootstrap collector token shape refused",
                )?;
            }
            Self::HostAck {
                schema_version,
                context_sha256,
                bootstrap_commitment,
                guest_public_key_hex,
                host_ack_public_key_hex,
                ..
            } => {
                require(
                    schema_version == CHANNEL_SCHEMA
                        && hash_valid(context_sha256)
                        && hash_valid(bootstrap_commitment),
                    "ACK payload refused",
                )?;
                public_key_bytes(guest_public_key_hex)?;
                public_key_bytes(host_ack_public_key_hex)?;
            }
            Self::Progress { schema_version, .. } => require(
                schema_version == CHANNEL_PROGRESS_SCHEMA,
                "progress payload schema refused",
            )?,
            Self::Terminal {
                schema_version,
                request_sha256,
                assessment_sha256,
                artifacts,
                evidence_root_hash,
                last_progress_commitment,
                ..
            } => {
                require(
                    schema_version == CHANNEL_SCHEMA
                        && hash_valid(request_sha256)
                        && hash_valid(assessment_sha256)
                        && hash_valid(evidence_root_hash)
                        && hash_valid(last_progress_commitment),
                    "terminal payload refused",
                )?;
                require(artifacts.len() == 4, "terminal artifact count refused")?;
                for (a, role) in artifacts.iter().zip([
                    ChannelArtifactRole::Result,
                    ChannelArtifactRole::Evidence,
                    ChannelArtifactRole::Completion,
                    ChannelArtifactRole::Progress,
                ]) {
                    require(
                        a.role == role
                            && a.path == role.path()
                            && a.size_bytes > 0
                            && a.size_bytes <= role.limit()
                            && hash_valid(&a.sha256),
                        "terminal artifact roster/size/hash refused",
                    )?;
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentChannelRecord {
    pub input: ChannelSignatureInput,
    pub payload: AssessmentChannelPayload,
    pub signature_hex: String,
}
/// Public signing material only, never a verified message or execution authority.
#[derive(Debug)]
pub struct ChannelSigningIntent {
    input: ChannelSignatureInput,
    payload: AssessmentChannelPayload,
}
impl ChannelSigningIntent {
    pub fn input(&self) -> &ChannelSignatureInput {
        &self.input
    }
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        self.input.signing_digest()
    }
    pub fn with_signature(self, signature: &[u8; 64]) -> AssessmentChannelRecord {
        AssessmentChannelRecord {
            input: self.input,
            payload: self.payload,
            signature_hex: hex::encode(signature),
        }
    }
}
/// Construct digest/material; callers must separately consume their one-shot
/// signing intent BEFORE invoking a signer. This function performs no signing.
pub fn signing_intent(
    binding: &AssessmentChannelBinding,
    guest_key: &str,
    sequence: u64,
    previous_commitment: &str,
    payload: AssessmentChannelPayload,
) -> Result<ChannelSigningIntent> {
    binding.validate()?;
    payload.validate()?;
    let key = public_key_bytes(guest_key)?;
    let bytes = canonical(&payload)?;
    let input = ChannelSignatureInput {
        schema_version: CHANNEL_SCHEMA.into(),
        channel_protocol: CHANNEL_PROTOCOL.into(),
        kind: payload.kind(),
        context_sha256: binding.context_sha256()?,
        guest_key_sha256: sha(&key),
        sequence,
        previous_commitment: previous_commitment.into(),
        payload_size: bytes.len() as u64,
        payload_sha256: sha(&bytes),
    };
    input.bytes()?;
    Ok(ChannelSigningIntent { input, payload })
}
impl AssessmentChannelRecord {
    pub fn canonical_wire(&self) -> Result<Vec<u8>> {
        self.payload.validate()?;
        self.input.bytes()?;
        signature_bytes(&self.signature_hex)?;
        require(
            self.input.kind == self.payload.kind(),
            "channel record kind differs from payload",
        )?;
        let payload = canonical(&self.payload)?;
        require(
            self.input.payload_size == payload.len() as u64
                && self.input.payload_sha256 == sha(&payload),
            "channel payload length/hash differs",
        )?;
        let bytes = canonical(self)?;
        let cap = match self.input.kind {
            ChannelRecordKind::Bootstrap => MAX_BOOTSTRAP_BYTES,
            ChannelRecordKind::HostAck => MAX_ACK_BYTES,
            ChannelRecordKind::Progress => MAX_PROGRESS_RECORD_BYTES - 1,
            ChannelRecordKind::Terminal => MAX_TERMINAL_BYTES,
        };
        require(bytes.len() <= cap, "channel complete record exceeds bound")?;
        Ok(bytes)
    }
}
fn parse(bytes: &[u8], kind: ChannelRecordKind) -> Result<AssessmentChannelRecord> {
    let cap = match kind {
        ChannelRecordKind::Bootstrap => MAX_BOOTSTRAP_BYTES,
        ChannelRecordKind::HostAck => MAX_ACK_BYTES,
        ChannelRecordKind::Progress => MAX_PROGRESS_RECORD_BYTES - 1,
        ChannelRecordKind::Terminal => MAX_TERMINAL_BYTES,
    };
    require(
        !bytes.is_empty() && bytes.len() <= cap,
        "channel raw record length refused",
    )?;
    let value: AssessmentChannelRecord =
        serde_json::from_slice(bytes).map_err(|_| "strict channel record refused".to_owned())?;
    require(
        value.input.kind == kind && value.canonical_wire()? == bytes,
        "channel kind/noncanonical wire refused",
    )?;
    Ok(value)
}

#[derive(Debug, Clone)]
pub struct VerifiedChannelRecord {
    record: AssessmentChannelRecord,
    commitment: String,
    wire_sha256: String,
}
impl VerifiedChannelRecord {
    pub fn record(&self) -> &AssessmentChannelRecord {
        &self.record
    }
    pub fn commitment(&self) -> &str {
        &self.commitment
    }
    pub fn wire_sha256(&self) -> &str {
        &self.wire_sha256
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitBootstrap,
    Latched,
    AckIntent,
    Active,
    Terminal,
    Refused,
}
/// In-memory one-attempt protocol state, deliberately not Deserialize/Serialize.
/// Does NOT prove file/process denial, no impersonation, native execution, or
/// authorize dispatch. Its expected binding must be trusted local Start state.
pub struct AssessmentChannelSession {
    expected: AssessmentChannelBinding,
    phase: Phase,
    guest_key: String,
    collector_token: Option<TokenEvidence>,
    bootstrap_commitment: String,
    last_commitment: String,
    sequence: u64,
    progress_wire_bytes: usize,
    progress_hash: Sha256,
    progress_terminal_seen: bool,
    bootstrap_bytes: usize,
    ack_bytes: usize,
}
impl AssessmentChannelSession {
    pub fn new(expected_from_trusted_local_start: AssessmentChannelBinding) -> Result<Self> {
        expected_from_trusted_local_start.validate()?;
        Ok(Self {
            expected: expected_from_trusted_local_start,
            phase: Phase::AwaitBootstrap,
            guest_key: String::new(),
            collector_token: None,
            bootstrap_commitment: String::new(),
            last_commitment: String::new(),
            sequence: 0,
            progress_wire_bytes: 0,
            progress_hash: Sha256::new(),
            progress_terminal_seen: false,
            bootstrap_bytes: 0,
            ack_bytes: 0,
        })
    }
    fn verify(
        &self,
        record: AssessmentChannelRecord,
        bytes: &[u8],
        key: &str,
        verifier: &impl AssessmentChannelVerifier,
    ) -> Result<VerifiedChannelRecord> {
        require(
            record.input.context_sha256 == self.expected.context_sha256()?
                && record.input.guest_key_sha256 == sha(&public_key_bytes(&self.guest_key)?),
            "channel expected context/key differs",
        )?;
        verifier.verify_digest(
            &public_key_bytes(key)?,
            &record.input.signing_digest()?,
            &signature_bytes(&record.signature_hex)?,
        )?;
        let commitment = record.input.message_commitment()?;
        Ok(VerifiedChannelRecord {
            record,
            commitment,
            wire_sha256: sha(bytes),
        })
    }
    /// One CLOSED bootstrap read. Invalid input consumes this attempt without
    /// latching a key; repeated/bootstrap replacement is never admitted.
    pub fn latch_bootstrap(
        &mut self,
        bytes: &[u8],
        verifier: &impl AssessmentChannelVerifier,
    ) -> Result<VerifiedChannelRecord> {
        require(
            self.phase == Phase::AwaitBootstrap,
            "bootstrap latch already consumed",
        )?;
        self.phase = Phase::Refused;
        let record = parse(bytes, ChannelRecordKind::Bootstrap)?;
        let (binding, key, token) = match &record.payload {
            AssessmentChannelPayload::Bootstrap {
                binding,
                guest_public_key_hex,
                collector_token,
                ..
            } => (
                binding,
                guest_public_key_hex.clone(),
                collector_token.as_ref().clone(),
            ),
            _ => return Err("bootstrap payload missing".into()),
        };
        require(
            binding.as_ref() == &self.expected
                && record.input.sequence == 0
                && record.input.previous_commitment == ZERO_HASH,
            "bootstrap expected binding/position differs",
        )?;
        // Store only after the full cryptographic check; verify uses this key's
        // content identity but no observer-provided key can replace expected.
        let guest_hash = sha(&public_key_bytes(&key)?);
        require(
            record.input.context_sha256 == self.expected.context_sha256()?
                && record.input.guest_key_sha256 == guest_hash,
            "bootstrap context/key differs",
        )?;
        verifier.verify_digest(
            &public_key_bytes(&key)?,
            &record.input.signing_digest()?,
            &signature_bytes(&record.signature_hex)?,
        )?;
        let commitment = record.input.message_commitment()?;
        self.guest_key = key;
        self.collector_token = Some(token);
        self.bootstrap_commitment = commitment.clone();
        self.bootstrap_bytes = bytes.len();
        self.phase = Phase::Latched;
        Ok(VerifiedChannelRecord {
            record,
            commitment,
            wire_sha256: sha(bytes),
        })
    }
    /// Consumes the single ACK signing/read intent, before signer or publication.
    /// On restore, derives expected public ACK; never generates entropy/signs.
    pub fn begin_ack(&mut self) -> Result<ChannelSigningIntent> {
        require(
            self.phase == Phase::Latched,
            "ACK intent unavailable/already consumed",
        )?;
        self.phase = Phase::Refused;
        let payload = AssessmentChannelPayload::HostAck {
            schema_version: CHANNEL_SCHEMA.into(),
            context_sha256: self.expected.context_sha256()?,
            bootstrap_commitment: self.bootstrap_commitment.clone(),
            guest_public_key_hex: self.guest_key.clone(),
            host_ack_public_key_hex: self.expected.host_ack_public_key_hex.clone(),
            acknowledgement: ChannelAcknowledgement::AllowOneDispatch,
        };
        let intent = signing_intent(
            &self.expected,
            &self.guest_key,
            0,
            &self.bootstrap_commitment,
            payload,
        )?;
        self.phase = Phase::AckIntent;
        Ok(intent)
    }
    pub fn accept_ack(
        &mut self,
        bytes: &[u8],
        verifier: &impl AssessmentChannelVerifier,
    ) -> Result<VerifiedChannelRecord> {
        require(
            self.phase == Phase::AckIntent,
            "ACK read unavailable/already consumed",
        )?;
        self.phase = Phase::Refused;
        let record = parse(bytes, ChannelRecordKind::HostAck)?;
        match &record.payload {
            AssessmentChannelPayload::HostAck {
                context_sha256,
                bootstrap_commitment,
                guest_public_key_hex,
                host_ack_public_key_hex,
                ..
            } => require(
                context_sha256 == &self.expected.context_sha256()?
                    && bootstrap_commitment == &self.bootstrap_commitment
                    && guest_public_key_hex == &self.guest_key
                    && host_ack_public_key_hex == &self.expected.host_ack_public_key_hex,
                "ACK payload differs from latch",
            )?,
            _ => return Err("ACK payload absent".into()),
        }
        require(
            record.input.sequence == 0
                && record.input.previous_commitment == self.bootstrap_commitment,
            "ACK sequence/parent differs",
        )?;
        let verified = self.verify(
            record,
            bytes,
            &self.expected.host_ack_public_key_hex,
            verifier,
        )?;
        self.last_commitment = verified.commitment.clone();
        self.ack_bytes = bytes.len();
        self.phase = Phase::Active;
        Ok(verified)
    }
    /// Call after any failed/ambiguous publication. No re-key/re-ACK/resume API.
    pub fn refuse(&mut self) {
        self.phase = Phase::Refused;
    }
    pub fn ack_verified(&self) -> bool {
        matches!(self.phase, Phase::Active | Phase::Terminal)
    }
    /// Full canonical record plus ONE LF, counted inside all wire caps. Invalid
    /// input fails this attempt closed; this is not an incremental repair API.
    pub fn accept_progress_line(
        &mut self,
        wire: &[u8],
        verifier: &impl AssessmentChannelVerifier,
    ) -> Result<VerifiedChannelRecord> {
        require(
            self.phase == Phase::Active,
            "progress outside acknowledged stream",
        )?;
        self.phase = Phase::Refused;
        require(
            !self.progress_terminal_seen,
            "progress follows final progress event",
        )?;
        require(
            wire.ends_with(b"\n") && wire.len() <= MAX_PROGRESS_RECORD_BYTES,
            "progress truncated/oversized",
        )?;
        let total = self
            .progress_wire_bytes
            .checked_add(wire.len())
            .ok_or("progress bytes overflow")?;
        require(
            total <= MAX_PROGRESS_BYTES && self.sequence < MAX_PROGRESS_RECORDS,
            "progress aggregate/count bound",
        )?;
        let record = parse(&wire[..wire.len() - 1], ChannelRecordKind::Progress)?;
        require(
            record.input.sequence == self.sequence + 1
                && record.input.previous_commitment == self.last_commitment,
            "progress replay/order/parent differs",
        )?;
        let event = match &record.payload {
            AssessmentChannelPayload::Progress { event, .. } => event,
            _ => return Err("progress payload absent".into()),
        };
        if self.sequence == 0 {
            match event.as_ref() {
                AssessmentProgressEvent::Header {
                    schema_version,
                    run_id,
                    sandbox_id,
                    request_sha256,
                    assessment_sha256,
                    agent_sha256,
                    config_sha256,
                    project_revision_sha256,
                    collector_token,
                } => require(
                    schema_version == CHANNEL_PROGRESS_SCHEMA
                        && run_id == &self.expected.run_id
                        && sandbox_id == &self.expected.sandbox_id
                        && request_sha256 == &self.expected.request_sha256
                        && assessment_sha256 == &self.expected.assessment_sha256
                        && agent_sha256 == &self.expected.agent_sha256
                        && config_sha256 == &self.expected.config_sha256
                        && project_revision_sha256 == &self.expected.project_revision_sha256
                        && Some(collector_token) == self.collector_token.as_ref(),
                    "authenticated progress header differs",
                )?,
                _ => return Err("first signed progress is not header".into()),
            }
        } else {
            require(
                !matches!(event.as_ref(), AssessmentProgressEvent::Header { .. }),
                "repeated signed header",
            )?;
        }
        let terminal = matches!(event.as_ref(), AssessmentProgressEvent::Terminal { .. });
        let verified = self.verify(record, wire, &self.guest_key, verifier)?;
        self.progress_hash.update(wire);
        self.progress_wire_bytes = total;
        self.sequence += 1;
        self.last_commitment = verified.commitment.clone();
        self.progress_terminal_seen = terminal;
        self.phase = Phase::Active;
        Ok(verified)
    }
    /// Consumes terminal intent BEFORE parsing/verification; a failed attempt
    /// cannot be replaced. Does not admit result semantics or cleanup claims.
    pub fn accept_terminal(
        &mut self,
        wire: &[u8],
        verifier: &impl AssessmentChannelVerifier,
    ) -> Result<VerifiedChannelRecord> {
        require(
            self.phase == Phase::Active,
            "terminal before acknowledged stream",
        )?;
        self.phase = Phase::Refused;
        require(
            self.progress_terminal_seen,
            "terminal before final progress",
        )?;
        let record = parse(wire, ChannelRecordKind::Terminal)?;
        require(
            record.input.sequence == self.sequence + 1
                && record.input.previous_commitment == self.last_commitment,
            "terminal sequence/parent differs",
        )?;
        let artifacts = match &record.payload {
            AssessmentChannelPayload::Terminal {
                request_sha256,
                assessment_sha256,
                artifacts,
                last_progress_sequence,
                last_progress_commitment,
                ..
            } => {
                require(
                    request_sha256 == &self.expected.request_sha256
                        && assessment_sha256 == &self.expected.assessment_sha256
                        && *last_progress_sequence == self.sequence
                        && last_progress_commitment == &self.last_commitment,
                    "terminal facts differ from channel",
                )?;
                artifacts
            }
            _ => return Err("terminal payload absent".into()),
        };
        let progress = &artifacts[3];
        require(
            progress.size_bytes == self.progress_wire_bytes as u64
                && progress.sha256 == hex::encode(self.progress_hash.clone().finalize()),
            "terminal raw progress digest/length differs",
        )?;
        let total = artifacts.iter().try_fold(
            (self.bootstrap_bytes + self.ack_bytes + wire.len()) as u64,
            |sum, a| {
                sum.checked_add(a.size_bytes)
                    .ok_or("producer bytes overflow")
            },
        )?;
        require(total <= MAX_PRODUCER_BYTES, "producer aggregate bound")?;
        let verified = self.verify(record, wire, &self.guest_key, verifier)?;
        self.phase = Phase::Terminal;
        Ok(verified)
    }
}

/// A count bound derived from actual compiled shape, not a producer completion
/// boolean. Protection event roster must be closed before native integration.
pub fn progress_record_bound(plan: &CompiledAssessment, protection_events: u64) -> Result<u64> {
    plan.validate()
        .map_err(|_| "channel plan refused".to_owned())?;
    count_bound(
        plan.steps.len() as u64,
        plan.steps
            .iter()
            .filter(|s| matches!(s, CompiledAssessmentStep::Launch { .. }))
            .count() as u64,
        plan.settings.assertions.len() as u64,
        plan.mode == AssessmentMode::ClassicAppContainer,
        protection_events,
    )
}
fn count_bound(
    steps: u64,
    launches: u64,
    assertions: u64,
    classic: bool,
    protection_events: u64,
) -> Result<u64> {
    require(
        (1..=64).contains(&steps)
            && launches > 0
            && launches < steps
            && assertions <= 128
            && protection_events <= 32,
        "signed progress plan counts unsupported",
    )?;
    let n = 19_u64
        .checked_add(u64::from(classic))
        .and_then(|n| n.checked_add(steps))
        .and_then(|n| n.checked_add(launches))
        .and_then(|n| n.checked_add(assertions))
        .and_then(|n| n.checked_add(protection_events))
        .ok_or("progress count overflow")?;
    require(
        n <= MAX_PROGRESS_RECORDS,
        "signed progress count exceeds bound",
    )?;
    Ok(n)
}
/// Checks conservative length bounds including framing. The compiler must
/// independently DERIVE these byte bounds from its closed DTO/string limits;
/// passing arbitrary small estimates is not execution authority.
pub fn check_progress_wire_budget(
    payload_bytes: u64,
    framing_bytes: u64,
    largest_payload: u64,
    largest_framing: u64,
    records: u64,
) -> Result<()> {
    require(
        records > 0 && records <= MAX_PROGRESS_RECORDS,
        "wire preflight count refused",
    )?;
    require(
        payload_bytes > 0
            && framing_bytes > 0
            && largest_payload > 0
            && largest_framing > 0
            && payload_bytes >= largest_payload
            && framing_bytes >= largest_framing,
        "wire preflight estimates are inconsistent",
    )?;
    let framing = maximum_progress_framing_bytes()?;
    require(
        framing_bytes
            >= framing
                .checked_mul(records)
                .ok_or("framing reservation overflow")?
            && largest_framing >= framing,
        "wire preflight omitted fixed authentication framing",
    )?;
    let total = payload_bytes
        .checked_add(framing_bytes)
        .ok_or("wire budget overflow")?;
    let largest = largest_payload
        .checked_add(largest_framing)
        .ok_or("record budget overflow")?;
    require(
        total <= MAX_PROGRESS_BYTES as u64
            && largest <= MAX_PROGRESS_RECORD_BYTES as u64
            && largest <= total,
        "complete signed wire preflight exceeds bound",
    )
}

/// Conservative fixed wrapper/input/signature overhead, including one LF.
/// Payload and sequence u64::MAX reserve more digits than the accepted bounds.
pub fn maximum_progress_framing_bytes() -> Result<u64> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Template {
        input: ChannelSignatureInput,
        payload: (),
        signature_hex: String,
    }
    let input = ChannelSignatureInput {
        schema_version: CHANNEL_SCHEMA.into(),
        channel_protocol: CHANNEL_PROTOCOL.into(),
        kind: ChannelRecordKind::Progress,
        context_sha256: "1".repeat(64),
        guest_key_sha256: "1".repeat(64),
        sequence: u64::MAX,
        previous_commitment: "1".repeat(64),
        payload_size: u64::MAX,
        payload_sha256: "1".repeat(64),
    };
    input.bytes()?;
    // Unit serializes as null; subtract its four bytes, add the actual LF.
    Ok((canonical(&Template {
        input,
        payload: (),
        signature_hex: "1".repeat(128),
    })?
    .len()
        - 4
        + 1) as u64)
}

/// Raw manifest verification only, not native semantic or cleanup admission.
pub fn verify_channel_artifact(
    terminal: &VerifiedChannelRecord,
    role: ChannelArtifactRole,
    bytes: &[u8],
) -> Result<()> {
    let artifacts = match &terminal.record.payload {
        AssessmentChannelPayload::Terminal { artifacts, .. } => artifacts,
        _ => return Err("verified record is not terminal".into()),
    };
    let artifact = artifacts
        .iter()
        .find(|a| a.role == role)
        .ok_or("terminal artifact absent")?;
    require(
        bytes.len() as u64 == artifact.size_bytes && sha(bytes) == artifact.sha256,
        "raw channel artifact differs",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment_observation::AssessmentAccountCleanup;
    use aiw_probe::WindowsSandboxCliAdapter;
    use aiw_token::{ElevationType, IntegrityEvidence};

    // Deliberately NOT ECDSA and the synthetic blobs need not be curve points.
    // Only tests association/state/parser gates; CNG native proof is separate.
    struct SyntheticVerifier;
    fn synthetic_signature(key: &[u8; 72], digest: &[u8; 32]) -> [u8; 64] {
        let mut h = Sha256::new();
        h.update(key);
        h.update(digest);
        let mut sig = [0; 64];
        sig[..32].copy_from_slice(&h.finalize());
        sig
    }
    impl AssessmentChannelVerifier for SyntheticVerifier {
        fn verify_digest(&self, key: &[u8; 72], digest: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
            let expected = synthetic_signature(key, digest);
            require(
                sig[..32] == expected[..32] && sig[32..63] == [0; 31] && sig[63] <= 1,
                "synthetic signature mismatch",
            )
        }
    }
    fn key(fill: u8) -> String {
        let mut b = [fill; 72];
        b[..8].copy_from_slice(&[0x45, 0x43, 0x53, 0x31, 32, 0, 0, 0]);
        hex::encode(b)
    }
    fn binding() -> AssessmentChannelBinding {
        AssessmentChannelBinding {
            schema_version: CHANNEL_SCHEMA.into(),
            channel_protocol: CHANNEL_PROTOCOL.into(),
            run_id: "assessment-123".into(),
            plan_sha256: "1".repeat(64),
            project_revision_sha256: "2".repeat(64),
            assessment_sha256: "3".repeat(64),
            semantic_sha256: "4".repeat(64),
            application_content_manifest_sha256: "5".repeat(64),
            agent_sha256: "6".repeat(64),
            provider_sha256: "7".repeat(64),
            provider_protocol: WindowsSandboxCliAdapter::V0_8_114_0.protocol(),
            config_sha256: "8".repeat(64),
            sandbox_id: "12345678-1234-4234-9234-123456789abc".into(),
            workspace_identity_sha256: "9".repeat(64),
            request_sha256: "a".repeat(64),
            nonce_hex: "b".repeat(64),
            host_ack_public_key_hex: key(1),
        }
    }
    fn collector() -> TokenEvidence {
        TokenEvidence {
            schema_version: aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION.into(),
            process_id: 42,
            token_type: TokenType::Primary,
            impersonation_level: None,
            is_app_container: false,
            app_container_sid: None,
            user_sid: "S-1-5-21-1-2-3-504".into(),
            integrity: IntegrityEvidence {
                sid: "S-1-16-12288".into(),
                rid: 12288,
                level: IntegrityLevel::High,
            },
            elevation_type: ElevationType::Full,
            is_elevated: true,
            capabilities: vec![],
            restricted_sid_count: 0,
        }
    }
    fn signed(intent: ChannelSigningIntent, key: &str) -> AssessmentChannelRecord {
        let sig = synthetic_signature(
            &public_key_bytes(key).unwrap(),
            &intent.signing_digest().unwrap(),
        );
        intent.with_signature(&sig)
    }
    fn bootstrap(b: &AssessmentChannelBinding, k: &str) -> AssessmentChannelRecord {
        signed(
            signing_intent(
                b,
                k,
                0,
                ZERO_HASH,
                AssessmentChannelPayload::Bootstrap {
                    schema_version: CHANNEL_SCHEMA.into(),
                    binding: Box::new(b.clone()),
                    guest_public_key_hex: k.into(),
                    collector_token: Box::new(collector()),
                    collector_storage: ChannelCollectorStorage::ProtectedGuestLocal,
                },
            )
            .unwrap(),
            k,
        )
    }
    fn active() -> AssessmentChannelSession {
        let b = binding();
        let k = key(2);
        let mut s = AssessmentChannelSession::new(b.clone()).unwrap();
        s.latch_bootstrap(
            &bootstrap(&b, &k).canonical_wire().unwrap(),
            &SyntheticVerifier,
        )
        .unwrap();
        let ack = signed(s.begin_ack().unwrap(), &b.host_ack_public_key_hex);
        s.accept_ack(&ack.canonical_wire().unwrap(), &SyntheticVerifier)
            .unwrap();
        s
    }
    fn header(s: &AssessmentChannelSession) -> AssessmentProgressEvent {
        let b = &s.expected;
        AssessmentProgressEvent::Header {
            schema_version: CHANNEL_PROGRESS_SCHEMA.into(),
            run_id: b.run_id.clone(),
            sandbox_id: b.sandbox_id.clone(),
            request_sha256: b.request_sha256.clone(),
            assessment_sha256: b.assessment_sha256.clone(),
            agent_sha256: b.agent_sha256.clone(),
            config_sha256: b.config_sha256.clone(),
            project_revision_sha256: b.project_revision_sha256.clone(),
            collector_token: collector(),
        }
    }
    fn progress(s: &AssessmentChannelSession, event: AssessmentProgressEvent) -> Vec<u8> {
        let mut wire = signed(
            signing_intent(
                &s.expected,
                &s.guest_key,
                s.sequence + 1,
                &s.last_commitment,
                AssessmentChannelPayload::Progress {
                    schema_version: CHANNEL_PROGRESS_SCHEMA.into(),
                    event: Box::new(event),
                },
            )
            .unwrap(),
            &s.guest_key,
        )
        .canonical_wire()
        .unwrap();
        wire.push(b'\n');
        wire
    }
    fn end_event() -> AssessmentProgressEvent {
        AssessmentProgressEvent::Terminal {
            collector_write_denied: None,
            collector_unimpersonated: None,
            profile_sid: None,
            profile_cleanup: None,
            account_cleanup: AssessmentAccountCleanup::default(),
            driver_completed: false,
            errors: vec!["synthetic not-run; no native evidence".into()],
        }
    }
    fn terminal(s: &AssessmentChannelSession) -> AssessmentChannelRecord {
        let mut artifacts = vec![];
        for (role, bytes) in [
            (ChannelArtifactRole::Result, b"result".as_slice()),
            (ChannelArtifactRole::Evidence, b"evidence".as_slice()),
            (ChannelArtifactRole::Completion, b"receipt".as_slice()),
        ] {
            artifacts.push(ChannelArtifact {
                role,
                path: role.path().into(),
                size_bytes: bytes.len() as u64,
                sha256: sha(bytes),
            });
        }
        artifacts.push(ChannelArtifact {
            role: ChannelArtifactRole::Progress,
            path: ChannelArtifactRole::Progress.path().into(),
            size_bytes: s.progress_wire_bytes as u64,
            sha256: hex::encode(s.progress_hash.clone().finalize()),
        });
        signed(
            signing_intent(
                &s.expected,
                &s.guest_key,
                s.sequence + 1,
                &s.last_commitment,
                AssessmentChannelPayload::Terminal {
                    schema_version: CHANNEL_SCHEMA.into(),
                    request_sha256: s.expected.request_sha256.clone(),
                    assessment_sha256: s.expected.assessment_sha256.clone(),
                    artifacts,
                    evidence_root_hash: "c".repeat(64),
                    last_progress_sequence: s.sequence,
                    last_progress_commitment: s.last_commitment.clone(),
                },
            )
            .unwrap(),
            &s.guest_key,
        )
    }
    fn ended() -> AssessmentChannelSession {
        let mut s = active();
        let h = progress(&s, header(&s));
        s.accept_progress_line(&h, &SyntheticVerifier).unwrap();
        let end = progress(&s, end_event());
        s.accept_progress_line(&end, &SyntheticVerifier).unwrap();
        s
    }

    #[test]
    fn synthetic_complete_transport_retains_failed_facts_without_native_credit() {
        let mut s = ended();
        let wire = terminal(&s).canonical_wire().unwrap();
        let verified = s.accept_terminal(&wire, &SyntheticVerifier).unwrap();
        verify_channel_artifact(&verified, ChannelArtifactRole::Result, b"result").unwrap();
        assert!(
            verify_channel_artifact(&verified, ChannelArtifactRole::Result, b"forged").is_err()
        );
        assert!(s.accept_terminal(&wire, &SyntheticVerifier).is_err());
        assert!(s.accept_progress_line(b"{}\n", &SyntheticVerifier).is_err());
        // No API returns VerifiedAssessmentEvidence/driver completion here.
    }
    #[test]
    fn expected_local_binding_cannot_be_replaced_by_self_signed_bootstrap() {
        let original = binding();
        for field in 0..7 {
            let mut foreign = original.clone();
            match field {
                0 => foreign.request_sha256 = "d".repeat(64),
                1 => foreign.plan_sha256 = "e".repeat(64),
                2 => foreign.nonce_hex = "f".repeat(64),
                3 => foreign.host_ack_public_key_hex = key(3),
                4 => foreign.application_content_manifest_sha256 = "d".repeat(64),
                5 => foreign.provider_protocol = WindowsSandboxCliAdapter::V0_8_107_0.protocol(),
                _ => foreign.run_id = "another-run".into(),
            }
            let mut s = AssessmentChannelSession::new(original.clone()).unwrap();
            assert!(
                s.latch_bootstrap(
                    &bootstrap(&foreign, &key(2)).canonical_wire().unwrap(),
                    &SyntheticVerifier
                )
                .is_err()
            );
            assert!(s.guest_key.is_empty());
            assert!(!s.ack_verified());
            assert!(
                s.latch_bootstrap(
                    &bootstrap(&original, &key(2)).canonical_wire().unwrap(),
                    &SyntheticVerifier
                )
                .is_err()
            );
        }
    }
    #[test]
    fn ack_is_one_closed_read_with_fixed_key_roles_and_consumed_failures() {
        let b = binding();
        let k = key(2);
        let wire = bootstrap(&b, &k).canonical_wire().unwrap();
        let mut s = AssessmentChannelSession::new(b.clone()).unwrap();
        assert!(s.begin_ack().is_err());
        s.latch_bootstrap(&wire, &SyntheticVerifier).unwrap();
        assert!(
            s.latch_bootstrap(
                &bootstrap(&b, &key(3)).canonical_wire().unwrap(),
                &SyntheticVerifier
            )
            .is_err()
        );
        assert_eq!(s.guest_key, k);
        let intent = s.begin_ack().unwrap();
        assert!(s.begin_ack().is_err());
        let wrong_key_ack = signed(intent, &k).canonical_wire().unwrap();
        assert!(s.accept_ack(&wrong_key_ack, &SyntheticVerifier).is_err());
        assert!(!s.ack_verified());
        assert!(s.begin_ack().is_err());
        let mut active = active();
        active.refuse();
        assert!(!active.ack_verified());
        assert!(active.begin_ack().is_err());
    }
    #[test]
    fn strict_wire_rejects_unknown_duplicate_noncanonical_and_truncated_data() {
        let wire = bootstrap(&binding(), &key(2)).canonical_wire().unwrap();
        let mut unknown: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        unknown["extra"] = serde_json::json!(true);
        let mut reflected: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        let private_field = "private-diagnostic-sentinel-".repeat(80);
        reflected[private_field.as_str()] = serde_json::json!(true);
        assert_eq!(
            parse(
                &canonical(&reflected).unwrap(),
                ChannelRecordKind::Bootstrap
            )
            .unwrap_err(),
            "strict channel record refused"
        );
        assert!(parse(&canonical(&unknown).unwrap(), ChannelRecordKind::Bootstrap).is_err());
        let input = canonical(&parse(&wire, ChannelRecordKind::Bootstrap).unwrap().input).unwrap();
        let mut duplicate = b"{\"input\":".to_vec();
        duplicate.extend_from_slice(&input);
        duplicate.push(b',');
        duplicate.extend_from_slice(&wire[1..]);
        assert!(parse(&duplicate, ChannelRecordKind::Bootstrap).is_err());
        let mut spaced = wire.clone();
        spaced.push(b' ');
        assert!(parse(&spaced, ChannelRecordKind::Bootstrap).is_err());
        assert!(parse(&wire[..wire.len() - 1], ChannelRecordKind::Bootstrap).is_err());
        assert!(
            parse(
                &vec![b'x'; MAX_BOOTSTRAP_BYTES + 1],
                ChannelRecordKind::Bootstrap
            )
            .is_err()
        );
        assert!(parse(&wire, ChannelRecordKind::HostAck).is_err());
    }
    #[test]
    fn content_commitment_is_signature_independent_and_exact_u64() {
        let b = binding();
        let mut record = bootstrap(&b, &key(2));
        let before = record.input.message_commitment().unwrap();
        let wire = record.canonical_wire().unwrap();
        record.signature_hex.replace_range(126..128, "01");
        assert_ne!(wire, record.canonical_wire().unwrap());
        assert_eq!(before, record.input.message_commitment().unwrap());
        AssessmentChannelSession::new(b)
            .unwrap()
            .latch_bootstrap(&record.canonical_wire().unwrap(), &SyntheticVerifier)
            .unwrap();
        record.input.sequence = u64::MAX;
        let bytes = record.input.bytes().unwrap();
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains("18446744073709551615")
        );
        let original = record.input.signing_digest().unwrap();
        record.input.channel_protocol = "other-domain".into();
        assert!(record.input.signing_digest().is_err());
        record.input.channel_protocol = CHANNEL_PROTOCOL.into();
        record.input.payload_sha256 = "f".repeat(64);
        assert_ne!(original, record.input.signing_digest().unwrap());
    }
    #[test]
    fn progress_replay_order_truncation_and_unsigned_early_terminal_fail_closed() {
        let mut s = active();
        let first = progress(&s, header(&s));
        s.accept_progress_line(&first, &SyntheticVerifier).unwrap();
        assert!(s.accept_progress_line(&first, &SyntheticVerifier).is_err());
        assert!(!s.ack_verified());
        let mut s = active();
        let mut no_lf = progress(&s, header(&s));
        no_lf.pop();
        assert!(s.accept_progress_line(&no_lf, &SyntheticVerifier).is_err());
        let mut s = active();
        let first = progress(&s, header(&s));
        let mut record = parse(&first[..first.len() - 1], ChannelRecordKind::Progress).unwrap();
        record.input.sequence = 2;
        let sig = synthetic_signature(
            &public_key_bytes(&s.guest_key).unwrap(),
            &record.input.signing_digest().unwrap(),
        );
        record.signature_hex = hex::encode(sig);
        let mut skipped = record.canonical_wire().unwrap();
        skipped.push(b'\n');
        assert!(
            s.accept_progress_line(&skipped, &SyntheticVerifier)
                .is_err()
        );
        let mut s = active();
        assert!(
            s.accept_terminal(br#"{"successful":true}"#, &SyntheticVerifier)
                .is_err()
        );
        assert!(!s.ack_verified());
        let mut s = active();
        let first = progress(&s, header(&s));
        s.accept_progress_line(&first, &SyntheticVerifier).unwrap();
        let second_header = progress(&s, header(&s));
        assert!(
            s.accept_progress_line(&second_header, &SyntheticVerifier)
                .is_err()
        );
    }
    #[test]
    fn terminal_manifest_must_bind_actual_raw_progress_and_closed_roster() {
        for mutation in 0..4 {
            let mut s = ended();
            let mut record = terminal(&s);
            if let AssessmentChannelPayload::Terminal {
                artifacts,
                last_progress_commitment,
                ..
            } = &mut record.payload
            {
                match mutation {
                    0 => artifacts[3].sha256 = "e".repeat(64),
                    1 => artifacts[3].size_bytes += 1,
                    2 => artifacts[0].path = "foreign.json".into(),
                    _ => *last_progress_commitment = "f".repeat(64),
                }
            }
            let bytes = canonical(&record.payload).unwrap();
            record.input.payload_size = bytes.len() as u64;
            record.input.payload_sha256 = sha(&bytes);
            record.signature_hex = hex::encode(synthetic_signature(
                &public_key_bytes(&s.guest_key).unwrap(),
                &record.input.signing_digest().unwrap(),
            ));
            assert!(
                s.accept_terminal(&canonical(&record).unwrap(), &SyntheticVerifier)
                    .is_err()
            );
            assert!(!s.ack_verified());
        }
    }
    #[test]
    fn wire_budget_counts_framing_and_real_maximum_plan_records() {
        assert_eq!(count_bound(64, 63, 128, true, 0).unwrap(), 275);
        assert_eq!(count_bound(64, 63, 128, false, 0).unwrap(), 274);
        assert_eq!(count_bound(64, 63, 128, true, 14).unwrap(), 289);
        assert!(count_bound(64, 64, 128, true, 0).is_err());
        assert!(count_bound(64, 63, 129, true, 0).is_err());
        assert!(count_bound(64, 63, 128, true, 33).is_err());
        let (project, settings, manifest) = crate::assessment::tests::fixture();
        let plan = crate::assessment::compile_assessment(&project, &settings, &manifest).unwrap();
        assert!(progress_record_bound(&plan, 14).is_ok());
        let mut bad_plan = plan.clone();
        bad_plan.semantic_sha256 = "private-plan-marker-".repeat(200);
        assert_eq!(
            progress_record_bound(&bad_plan, 14).unwrap_err(),
            "channel plan refused"
        );
        let framing = maximum_progress_framing_bytes().unwrap();
        check_progress_wire_budget(
            MAX_PROGRESS_BYTES as u64 - framing * 512,
            framing * 512,
            MAX_PROGRESS_RECORD_BYTES as u64 - framing,
            framing,
            512,
        )
        .unwrap();
        assert!(check_progress_wire_budget(4096, 1, 1024, 1, 1).is_err());
        assert!(check_progress_wire_budget(MAX_PROGRESS_BYTES as u64, 1, 1, 1, 512).is_err());
        assert!(check_progress_wire_budget(1, 1, 1, 1, 513).is_err());
        assert!(check_progress_wire_budget(u64::MAX, 1, 1, 1, 1).is_err());
        assert!(check_progress_wire_budget(16, 1, 16, 1, 0).is_err());
        assert!(
            check_progress_wire_budget(
                MAX_PROGRESS_BYTES as u64,
                0,
                MAX_PROGRESS_RECORD_BYTES as u64,
                1,
                1
            )
            .is_err()
        );
    }
    #[test]
    fn bad_blob_signature_and_mixed_provider_fields_are_refused() {
        for bad in [
            "A".repeat(144),
            "0".repeat(144),
            key(2) + "00",
            key(2)[..142].to_owned(),
        ] {
            assert!(public_key_bytes(&bad).is_err());
        }
        let mut b = binding();
        b.provider_protocol.cli_version = "0.8.115.0".into();
        assert!(b.validate().is_err());
        let mut r = bootstrap(&binding(), &key(2));
        r.signature_hex = "0".repeat(126);
        assert!(r.canonical_wire().is_err());
        r = bootstrap(&binding(), &key(2));
        r.input.kind = ChannelRecordKind::Terminal;
        assert!(r.canonical_wire().is_err());
        r = bootstrap(&binding(), &key(2));
        r.payload = AssessmentChannelPayload::Progress {
            schema_version: "wrong".into(),
            event: Box::new(end_event()),
        };
        assert!(r.canonical_wire().is_err());
    }

    #[test]
    fn full_wire_count_and_closed_read_caps_fail_without_repair() {
        let mut s = active();
        s.progress_wire_bytes = MAX_PROGRESS_BYTES;
        let line = progress(&s, header(&s));
        assert!(s.accept_progress_line(&line, &SyntheticVerifier).is_err());
        assert!(!s.ack_verified());
        let mut s = active();
        s.sequence = MAX_PROGRESS_RECORDS;
        let line = progress(&s, end_event());
        assert!(s.accept_progress_line(&line, &SyntheticVerifier).is_err());
        let mut s = active();
        assert!(
            s.accept_progress_line(
                &vec![b'\n'; MAX_PROGRESS_RECORD_BYTES + 1],
                &SyntheticVerifier
            )
            .is_err()
        );
        assert!(parse(&vec![b'x'; MAX_ACK_BYTES + 1], ChannelRecordKind::HostAck).is_err());
        assert!(
            parse(
                &vec![b'x'; MAX_TERMINAL_BYTES + 1],
                ChannelRecordKind::Terminal
            )
            .is_err()
        );
        let mut s = ended();
        let wire = terminal(&s).canonical_wire().unwrap();
        let mut r = terminal(&s);
        r.signature_hex = "0".repeat(128);
        assert!(
            s.accept_terminal(&r.canonical_wire().unwrap(), &SyntheticVerifier)
                .is_err()
        );
        assert!(s.accept_terminal(&wire, &SyntheticVerifier).is_err());
    }
}
