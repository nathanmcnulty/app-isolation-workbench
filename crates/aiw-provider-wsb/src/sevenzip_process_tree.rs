//! Pure validation of bounded creation-time observations, never launch authority.
//! Chain membership does not establish parent edges or broker/all-host coverage.
use aiw_token::{TokenEvidence, TokenType};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SEVENZIP_PROCESS_CHAIN_SCHEMA: &str = "aiw.dev/sevenzip-process-chain/v0alpha1";
pub const SEVENZIP_PROCESS_CHAIN_SCOPE: &str = "instrumented inherited DEBUG_PROCESS CreateProcess chain; excludes brokers and all-host coverage";
pub const MAX_CHAIN_PROCESSES: usize = 64;
pub const MAX_CHAIN_EVENTS: u32 = 4096;
pub const MAX_CHAIN_GAPS: usize = 32;
pub const MAX_CHAIN_GAP_CHARS: usize = 512;
pub const MAX_CHAIN_IMAGE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipImageObservation {
    pub process_image_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub volume_serial_number: u32,
    pub file_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipProcessObservation {
    pub ordinal: usize,
    pub process_id: u32,
    pub create_event_sequence: u32,
    pub creation_time_100ns: Option<u64>,
    pub token_before_continue: Option<TokenEvidence>,
    pub image_before_continue: Option<SevenZipImageObservation>,
    pub exit_code: Option<u32>,
    pub exit_event_sequence: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipProcessChain {
    pub schema_version: String,
    pub scope: String,
    pub root_process_id: u32,
    pub events_processed: u32,
    pub processes: Vec<SevenZipProcessObservation>,
    pub timed_out: bool,
    pub owned_job_termination_requested: bool,
    pub owned_job_termination_succeeded: bool,
    pub job_total_processes: Option<u32>,
    pub job_active_processes: Option<u32>,
    pub job_limit_terminated_processes: Option<u32>,
    pub job_accounting_reconciled: bool,
    pub debugger_chain_complete: bool,
    pub requires_debugger_process_exit: bool,
    pub gaps: Vec<String>,
}

/// Supply only from independently validated suspended-root observations and
/// approved fixed code identity. Never construct this from the trace itself.
/// The caller must validate root token policy independently of this record.
pub struct SevenZipExpectedRootBinding<'a> {
    pub process_id: u32,
    pub creation_time_100ns: u64,
    pub held_token: &'a TokenEvidence,
    pub fixed_image_path: &'a str,
    pub image_sha256: &'a str,
    pub image_size_bytes: u64,
    /// Only None or Some(3): the fixed root/fast-child/grandchild control.
    /// Some(3) additionally requires every image to match the pinned helper.
    pub expected_control_processes: Option<usize>,
}

fn bounded(value: &str, chars: usize) -> bool {
    value.chars().count() <= chars && value.len() <= chars * 4
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn same_path(actual: &str, expected: &str) -> bool {
    actual
        .strip_prefix(r"\\?\")
        .unwrap_or(actual)
        .eq_ignore_ascii_case(expected.strip_prefix(r"\\?\").unwrap_or(expected))
}
fn token_shape(token: &TokenEvidence) -> bool {
    bounded(&token.schema_version, 128)
        && bounded(&token.user_sid, 256)
        && bounded(&token.integrity.sid, 256)
        && token
            .app_container_sid
            .as_ref()
            .is_none_or(|sid| bounded(sid, 256))
        && token.capabilities.len() <= 64
        && token.capabilities.iter().all(|c| bounded(&c.sid, 256))
}
fn primary(token: &TokenEvidence, pid: u32) -> bool {
    token.schema_version == aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
        && token.process_id == pid
        && token.token_type == TokenType::Primary
        && token.impersonation_level.is_none()
        && !token.is_elevated
}

/// Closed interpretation policy; callers cannot authorize elevation with a flag.
#[derive(Clone, Copy)]
enum CompletionPolicy {
    ApplicationOrControl,
    InstallationSetup,
}
impl CompletionPolicy {
    fn primary(self, token: &TokenEvidence, pid: u32) -> bool {
        match self {
            Self::ApplicationOrControl => primary(token, pid),
            Self::InstallationSetup => {
                token.schema_version == aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
                    && token.process_id == pid
                    && token.token_type == TokenType::Primary
                    && token.impersonation_level.is_none()
                    && token.is_elevated
                    && !token.is_app_container
                    && token.app_container_sid.is_none()
                    && token.capabilities.is_empty()
                    && token.integrity.level == aiw_token::IntegrityLevel::High
                    && token.integrity.rid == 12288
                    && token.integrity.sid == "S-1-16-12288"
            }
        }
    }

    fn root_path(self, path: &str) -> bool {
        match self {
            Self::ApplicationOrControl => [
                r"C:\AIW\SevenZip\App\7z.exe",
                r"C:\AIW\SevenZip\sevenzip_assessment.exe",
            ]
            .iter()
            .any(|expected| same_path(path, expected)),
            Self::InstallationSetup => same_path(path, r"C:\AIW\SevenZip\7z2605-x64.exe"),
        }
    }
}
fn same_boundary(actual: &TokenEvidence, expected: &TokenEvidence) -> bool {
    let mut normalized = actual.clone();
    normalized.process_id = expected.process_id;
    normalized == *expected
}
fn bound_image(
    image: &SevenZipImageObservation,
    expected: &SevenZipExpectedRootBinding<'_>,
) -> bool {
    same_path(&image.process_image_path, expected.fixed_image_path)
        && image.sha256 == expected.image_sha256
        && image.size_bytes == expected.image_size_bytes
}

impl SevenZipProcessChain {
    /// Bounds only: incomplete and semantically malformed measurements remain
    /// representable for retained diagnostics. Consumers must bound input bytes
    /// before deserializing; this check does not turn a partial trace into proof.
    pub fn validate_shape(&self) -> Result<(), String> {
        if !bounded(&self.schema_version, 128)
            || !bounded(&self.scope, 512)
            || self.processes.len() > MAX_CHAIN_PROCESSES
            || self.events_processed > MAX_CHAIN_EVENTS
            || self.gaps.len() > MAX_CHAIN_GAPS
            || self.gaps.iter().any(|g| !bounded(g, MAX_CHAIN_GAP_CHARS))
        {
            return Err("process-chain envelope exceeds bounds".into());
        }
        for process in &self.processes {
            if process
                .token_before_continue
                .as_ref()
                .is_some_and(|t| !token_shape(t))
                || process.image_before_continue.as_ref().is_some_and(|i| {
                    !bounded(&i.process_image_path, 32768)
                        || !bounded(&i.sha256, 128)
                        || i.size_bytes > MAX_CHAIN_IMAGE_BYTES
                })
            {
                return Err("process-chain measurement exceeds bounds".into());
            }
        }
        Ok(())
    }

    /// Reconstruct completeness from observations. Neither summary success flag
    /// supplies missing measurements. A complete trace may still record a
    /// nonzero application exit; function compatibility is evaluated separately.
    pub fn verify_complete(
        &self,
        expected: &SevenZipExpectedRootBinding<'_>,
    ) -> Result<(), String> {
        self.verify_complete_with_policy(expected, CompletionPolicy::ApplicationOrControl)
    }

    /// Completeness for the single pinned elevated installation/setup phase.
    /// This is not candidate-isolated installation or installation success.
    /// The caller separately binds the held root to the approved Sandbox setup
    /// actor/environment. Every observed token must retain that full boundary.
    pub fn verify_installation_complete(
        &self,
        expected: &SevenZipExpectedRootBinding<'_>,
    ) -> Result<(), String> {
        if !same_path(expected.fixed_image_path, r"C:\AIW\SevenZip\7z2605-x64.exe")
            || expected.image_sha256 != aiw_probe::sevenzip::SEVENZIP_INSTALLER_SHA256
            || expected.image_size_bytes != aiw_probe::sevenzip::SEVENZIP_INSTALLER_SIZE_BYTES
            || expected.expected_control_processes.is_some()
        {
            return Err("fixed official installer setup binding required".into());
        }
        self.verify_complete_with_policy(expected, CompletionPolicy::InstallationSetup)
    }

    fn verify_complete_with_policy(
        &self,
        expected: &SevenZipExpectedRootBinding<'_>,
        policy: CompletionPolicy,
    ) -> Result<(), String> {
        self.validate_shape()?;
        if expected.process_id == 0
            || expected.creation_time_100ns == 0
            || !token_shape(expected.held_token)
            || !policy.primary(expected.held_token, expected.process_id)
            || !hash(expected.image_sha256)
            || expected.image_size_bytes == 0
            || expected.image_size_bytes > MAX_CHAIN_IMAGE_BYTES
            || expected.fixed_image_path.is_empty()
            || !bounded(expected.fixed_image_path, 32768)
            || expected.fixed_image_path.contains('\0')
            || !policy.root_path(expected.fixed_image_path)
            || !matches!(expected.expected_control_processes, None | Some(3))
            || (expected.expected_control_processes.is_some()
                && !same_path(
                    expected.fixed_image_path,
                    r"C:\AIW\SevenZip\sevenzip_assessment.exe",
                ))
        {
            return Err("independently validated fixed root binding required".into());
        }
        if self.schema_version != SEVENZIP_PROCESS_CHAIN_SCHEMA
            || self.scope != SEVENZIP_PROCESS_CHAIN_SCOPE
            || self.root_process_id != expected.process_id
            || self.processes.is_empty()
            || self.timed_out
            || !self.gaps.is_empty()
            || self.requires_debugger_process_exit
            || !self.debugger_chain_complete
            || !self.job_accounting_reconciled
            || self.owned_job_termination_requested != self.owned_job_termination_succeeded
            || self.job_total_processes != Some(self.processes.len() as u32)
            || self.job_active_processes != Some(0)
            || self.job_limit_terminated_processes != Some(0)
            || expected
                .expected_control_processes
                .is_some_and(|n| n != self.processes.len())
        {
            return Err("process-chain coverage, owned cleanup or job facts incomplete".into());
        }
        let mut sequences = BTreeSet::new();
        let mut lifetimes = BTreeMap::<u32, (u32, u64)>::new();
        let mut previous_create = 0;
        for (ordinal, process) in self.processes.iter().enumerate() {
            let token = process
                .token_before_continue
                .as_ref()
                .ok_or("missing creation-time token")?;
            let image = process
                .image_before_continue
                .as_ref()
                .ok_or("missing creation-time image")?;
            let time = process
                .creation_time_100ns
                .filter(|t| *t != 0)
                .ok_or("missing creation time")?;
            let exit = process.exit_event_sequence.ok_or("missing exit sequence")?;
            if process.ordinal != ordinal
                || process.process_id == 0
                || process.create_event_sequence <= previous_create
                || exit <= process.create_event_sequence
                || exit > self.events_processed
                || process.exit_code.is_none()
                || !sequences.insert(process.create_event_sequence)
                || !sequences.insert(exit)
                || !policy.primary(token, process.process_id)
                || !same_boundary(token, expected.held_token)
                || time < expected.creation_time_100ns
                || !hash(&image.sha256)
                || image.size_bytes == 0
                || image.process_image_path.is_empty()
                || image.process_image_path.contains('\0')
                || image.file_index == 0
            {
                return Err("process-chain event/token/image facts inconsistent".into());
            }
            if let Some((prior_exit, prior_time)) = lifetimes.get(&process.process_id)
                && (process.create_event_sequence <= *prior_exit || time <= *prior_time)
            {
                return Err("overlapping or non-increasing reused PID lifetime".into());
            }
            lifetimes.insert(process.process_id, (exit, time));
            previous_create = process.create_event_sequence;
            if ordinal == 0
                && (process.process_id != expected.process_id
                    || time != expected.creation_time_100ns
                    || token != expected.held_token
                    || !bound_image(image, expected))
            {
                return Err("root differs from independently held binding".into());
            }
            if expected.expected_control_processes.is_some() && !bound_image(image, expected) {
                return Err("fixed three-process control image differs".into());
            }
        }
        // Positive flags cannot replace the facts above. Negative flags remain
        // an explicit collection gap; contradictory evidence is not verified.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn token(pid: u32) -> TokenEvidence {
        serde_json::from_value(serde_json::json!({
            "schemaVersion":aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,"processId":pid,
            "tokenType":"primary","isElevated":false,"isAppContainer":true,
            "userSid":"S-1-5-21-1-2-3-1001","integrity":{"sid":"S-1-16-4096","rid":4096,"level":"low"},
            "elevationType":"default","capabilities":[],"restrictedSidCount":0,
            "appContainerSid":"S-1-15-2-123"
        })).unwrap()
    }
    fn process(
        ordinal: usize,
        pid: u32,
        create: u32,
        exit: u32,
        time: u64,
    ) -> SevenZipProcessObservation {
        SevenZipProcessObservation {
            ordinal,
            process_id: pid,
            create_event_sequence: create,
            exit_event_sequence: Some(exit),
            creation_time_100ns: Some(time),
            token_before_continue: Some(token(pid)),
            exit_code: Some(0),
            image_before_continue: Some(SevenZipImageObservation {
                process_image_path: r"C:\AIW\SevenZip\sevenzip_assessment.exe".into(),
                sha256: "a".repeat(64),
                size_bytes: 100,
                volume_serial_number: 1,
                file_index: pid as u64,
            }),
        }
    }
    fn chain() -> SevenZipProcessChain {
        SevenZipProcessChain {
            schema_version: SEVENZIP_PROCESS_CHAIN_SCHEMA.into(),
            scope: SEVENZIP_PROCESS_CHAIN_SCOPE.into(),
            root_process_id: 10,
            events_processed: 8,
            processes: vec![
                process(0, 10, 1, 4, 100),
                process(1, 11, 2, 7, 101),
                process(2, 12, 3, 8, 102),
            ],
            timed_out: false,
            owned_job_termination_requested: true,
            owned_job_termination_succeeded: true,
            job_total_processes: Some(3),
            job_active_processes: Some(0),
            job_limit_terminated_processes: Some(0),
            job_accounting_reconciled: true,
            debugger_chain_complete: true,
            requires_debugger_process_exit: false,
            gaps: vec![],
        }
    }
    fn binding(token: &TokenEvidence) -> SevenZipExpectedRootBinding<'_> {
        SevenZipExpectedRootBinding {
            process_id: 10,
            creation_time_100ns: 100,
            held_token: token,
            fixed_image_path: r"C:\AIW\SevenZip\sevenzip_assessment.exe",
            image_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            image_size_bytes: 100,
            expected_control_processes: Some(3),
        }
    }
    #[test]
    fn root_exits_first_and_nonzero_exit_remains_measured() {
        let mut c = chain();
        c.processes[0].exit_code = Some(7);
        assert!(c.verify_complete(&binding(&token(10))).is_ok());
        c.owned_job_termination_requested = false;
        c.owned_job_termination_succeeded = false;
        assert!(c.verify_complete(&binding(&token(10))).is_ok());
        c.debugger_chain_complete = false;
        c.job_accounting_reconciled = false;
        assert!(c.verify_complete(&binding(&token(10))).is_err());
    }
    #[test]
    fn success_flags_never_replace_missing_or_inconsistent_facts() {
        let mutations: Vec<fn(&mut SevenZipProcessChain)> = vec![
            |c| c.processes[1].token_before_continue = None,
            |c| {
                c.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .process_id = 999
            },
            |c| {
                c.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .user_sid = "other".into()
            },
            |c| {
                c.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .schema_version = "wrong".into()
            },
            |c| {
                c.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .token_type = TokenType::Impersonation
            },
            |c| {
                c.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .is_elevated = true
            },
            |c| {
                c.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .is_app_container = false
            },
            |c| {
                c.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .app_container_sid = None
            },
            |c| {
                c.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .capabilities
                    .push(aiw_token::SidAndAttributes {
                        sid: "S-1-15-3-1".into(),
                        attributes: 4,
                    })
            },
            |c| c.processes[1].image_before_continue = None,
            |c| c.processes[1].exit_event_sequence = None,
            |c| c.processes[1].exit_code = None,
            |c| c.processes[1].exit_event_sequence = Some(3),
            |c| c.processes[1].create_event_sequence = 0,
            |c| c.processes[1].ordinal = 8,
            |c| c.processes[0].creation_time_100ns = Some(999),
            |c| {
                c.processes[0]
                    .image_before_continue
                    .as_mut()
                    .unwrap()
                    .sha256 = "b".repeat(64)
            },
            |c| c.root_process_id = 99,
            |c| c.scope = "all descendants including brokers".into(),
            |c| c.job_total_processes = Some(4),
            |c| c.job_active_processes = Some(1),
            |c| c.job_limit_terminated_processes = Some(1),
            |c| c.gaps.push("unmeasured token".into()),
            |c| c.timed_out = true,
            |c| c.requires_debugger_process_exit = true,
            |c| c.owned_job_termination_requested = false,
            |c| c.owned_job_termination_succeeded = false,
        ];
        for mutate in mutations {
            let mut c = chain();
            mutate(&mut c);
            assert!(c.validate_shape().is_ok());
            assert!(c.verify_complete(&binding(&token(10))).is_err());
        }
    }
    #[test]
    fn reused_pid_needs_disjoint_events_and_increasing_creation_time() {
        let mut c = chain();
        c.processes[1].exit_event_sequence = Some(3);
        c.processes[2] = process(2, 11, 5, 8, 102);
        assert!(c.verify_complete(&binding(&token(10))).is_ok());
        c.processes[2].create_event_sequence = 3;
        assert!(c.verify_complete(&binding(&token(10))).is_err());
        c.processes[2].create_event_sequence = 5;
        c.processes[2].creation_time_100ns = Some(101);
        assert!(c.verify_complete(&binding(&token(10))).is_err());
    }
    #[test]
    fn independent_binding_and_fixed_control_are_required() {
        let c = chain();
        let t = token(10);
        let mut b = binding(&t);
        b.expected_control_processes = Some(2);
        assert!(c.verify_complete(&b).is_err());
        b.expected_control_processes = None;
        let mut app = c;
        app.processes[1]
            .image_before_continue
            .as_mut()
            .unwrap()
            .sha256 = "b".repeat(64);
        assert!(app.verify_complete(&b).is_ok());
        b.expected_control_processes = Some(3);
        assert!(app.verify_complete(&b).is_err());
    }
    #[test]
    fn bounded_partial_records_round_trip_but_do_not_prove_completeness() {
        let mut c = chain();
        c.processes.clear();
        c.gaps = vec!["token missing".into()];
        let bytes = serde_json::to_vec(&c).unwrap();
        let restored: SevenZipProcessChain = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored, c);
        assert!(c.validate_shape().is_ok());
        assert!(c.verify_complete(&binding(&token(10))).is_err());
        c.gaps = vec!["x".repeat(513)];
        assert!(c.validate_shape().is_err());
        c.gaps = vec![];
        c.events_processed = 4097;
        assert!(c.validate_shape().is_err());
        c.events_processed = 0;
        c.processes = vec![process(0, 10, 1, 2, 100); 65];
        assert!(c.validate_shape().is_err());
        let mut value = serde_json::to_value(chain()).unwrap();
        value["parentPid"] = 1.into();
        assert!(serde_json::from_value::<SevenZipProcessChain>(value).is_err());
    }
}
