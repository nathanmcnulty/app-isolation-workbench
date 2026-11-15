//! Closed installation/setup and actual 7-Zip use traces. Completeness is not
//! application success, candidate-isolated installation, or general isolation.
use crate::sevenzip_process_tree::{
    MAX_CHAIN_IMAGE_BYTES, MAX_CHAIN_PROCESSES, SEVENZIP_PROCESS_CHAIN_SCOPE,
    SevenZipExpectedRootBinding, SevenZipImageObservation, SevenZipProcessChain,
};
use aiw_token::TokenEvidence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const SEVENZIP_EXECUTION_TRACE_SCHEMA: &str = "aiw.dev/sevenzip-execution-trace/v0alpha1";
pub const SEVENZIP_EXECUTION_TRACE_SUMMARY_SCHEMA: &str =
    "aiw.dev/sevenzip-execution-trace-summary/v0alpha1";
pub const SEVENZIP_EXECUTION_APPLICATION_PATH: &str = r"C:\AIW\SevenZip\App\7z.exe";
pub const SEVENZIP_EXECUTION_INSTALLER_PATH: &str = r"C:\AIW\SevenZip\7z2605-x64.exe";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SevenZipExecutionPhase {
    InstallationSetup,
    Create,
    Test,
    Extract,
}
impl SevenZipExecutionPhase {
    pub fn fixed_image_path(self) -> &'static str {
        match self {
            Self::InstallationSetup => SEVENZIP_EXECUTION_INSTALLER_PATH,
            Self::Create | Self::Test | Self::Extract => SEVENZIP_EXECUTION_APPLICATION_PATH,
        }
    }
}

/// A separately retained suspended-process-handle observation, measured before
/// Resume. Its authority comes from the reviewed producer and request-bound
/// custody, not its inclusion in the same DTO as the debug-event chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipExecutionRootBinding {
    pub process_id: u32,
    pub creation_time_100ns: u64,
    pub held_token: TokenEvidence,
}

/// Same event hFile retained until its EXIT event. The logical path is cached
/// from CREATE; this is not a later PID/path reopen or loaded-memory measurement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipImageLifetime {
    pub ordinal: usize,
    pub process_id: u32,
    pub create_event_sequence: u32,
    pub image_after_exit: Option<SevenZipImageObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipExecutionTrace {
    pub schema_version: String,
    pub phase: SevenZipExecutionPhase,
    pub root_binding: SevenZipExecutionRootBinding,
    pub chain: SevenZipProcessChain,
    pub image_lifetimes: Vec<SevenZipImageLifetime>,
}

/// Safe counts and actual root exit only. No PID, SID, image path, inferred
/// parent edges, trusted-child classification or compatibility verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipExecutionTraceSummary {
    pub schema_version: String,
    pub phase: SevenZipExecutionPhase,
    pub observed_processes: u32,
    pub paired_exits: u32,
    pub root_exit_code: u32,
    pub lifetime_images_revalidated: bool,
    pub exact_job_reconciled: bool,
    pub scope: String,
}

/// Request-verified summaries of actually observed operations, without raw
/// identities or a compatibility, cleanup or effective-isolation verdict.
/// Installation is common elevated setup, outside the isolation candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipExecutionCoverage {
    pub installation_setup: SevenZipExecutionTraceSummary,
    /// Present invocations only, in Create/Test/Extract order. No invented rows.
    pub baseline: Vec<SevenZipExecutionTraceSummary>,
    pub candidate: Vec<SevenZipExecutionTraceSummary>,
}

fn bounded(value: &str, chars: usize) -> bool {
    value.chars().count() <= chars && value.len() <= chars * 4
}
impl SevenZipExecutionTrace {
    /// Bounds only. Partial or malformed observations remain representable;
    /// consumers must also bound bytes before deserializing this structure.
    pub fn validate_shape(&self) -> Result<(), String> {
        self.chain.validate_shape()?;
        let token = &self.root_binding.held_token;
        if !bounded(&self.schema_version, 128)
            || !bounded(&token.schema_version, 128)
            || !bounded(&token.user_sid, 256)
            || !bounded(&token.integrity.sid, 256)
            || token
                .app_container_sid
                .as_ref()
                .is_some_and(|v| !bounded(v, 256))
            || token.capabilities.len() > 64
            || token.capabilities.iter().any(|v| !bounded(&v.sid, 256))
            || self.image_lifetimes.len() > MAX_CHAIN_PROCESSES
            || self.image_lifetimes.iter().any(|v| {
                v.image_after_exit.as_ref().is_some_and(|image| {
                    !bounded(&image.process_image_path, 32768)
                        || !bounded(&image.sha256, 128)
                        || image.size_bytes > MAX_CHAIN_IMAGE_BYTES
                })
            })
        {
            return Err("execution-trace observation exceeds bounds".into());
        }
        Ok(())
    }
}

/// The caller independently binds the phase/code pins to the approved request
/// and installed immutable image, and validates the suspended root's actual
/// user/profile/environment policy and closed argv/cwd. A phase label alone
/// cannot prove a command line. Never derive expected code from the chain.
/// InstallationSetup is solely elevated common setup observation; it does not
/// assert that installation was attempted under an isolation candidate.
///
/// All application descendants are observations, not a fixed helper/console
/// allowlist. They must have the same full intended token boundary and paired
/// events/job accounting, and exactly match their own same-event exit images.
/// This does not verify loaded memory, DLLs, brokers, registry or all-host scope.
pub fn verify_execution_trace(
    trace: &SevenZipExecutionTrace,
    expected_phase: SevenZipExecutionPhase,
    expected_image_sha256: &str,
    expected_image_size: u64,
) -> Result<SevenZipExecutionTraceSummary, String> {
    trace.validate_shape()?;
    if trace.schema_version != SEVENZIP_EXECUTION_TRACE_SCHEMA || trace.phase != expected_phase {
        return Err("execution-trace schema or approved phase differs".into());
    }
    let binding = SevenZipExpectedRootBinding {
        process_id: trace.root_binding.process_id,
        creation_time_100ns: trace.root_binding.creation_time_100ns,
        held_token: &trace.root_binding.held_token,
        fixed_image_path: expected_phase.fixed_image_path(),
        image_sha256: expected_image_sha256,
        image_size_bytes: expected_image_size,
        expected_control_processes: None,
    };
    match expected_phase {
        SevenZipExecutionPhase::InstallationSetup => {
            trace.chain.verify_installation_complete(&binding)?
        }
        SevenZipExecutionPhase::Create
        | SevenZipExecutionPhase::Test
        | SevenZipExecutionPhase::Extract => trace.chain.verify_complete(&binding)?,
    }
    if trace.image_lifetimes.len() != trace.chain.processes.len() {
        return Err("missing or additional image lifetime observations".into());
    }
    for (process, lifetime) in trace.chain.processes.iter().zip(&trace.image_lifetimes) {
        let image = process
            .image_before_continue
            .as_ref()
            .ok_or("missing event image")?;
        if lifetime.ordinal != process.ordinal
            || lifetime.process_id != process.process_id
            || lifetime.create_event_sequence != process.create_event_sequence
            || image.volume_serial_number == 0
            || lifetime.image_after_exit.as_ref() != Some(image)
        {
            return Err("image lifetime event association or revalidation differs".into());
        }
    }
    Ok(SevenZipExecutionTraceSummary {
        schema_version: SEVENZIP_EXECUTION_TRACE_SUMMARY_SCHEMA.into(),
        phase: expected_phase,
        observed_processes: trace.chain.processes.len() as u32,
        paired_exits: trace.chain.processes.len() as u32,
        root_exit_code: trace.chain.processes[0]
            .exit_code
            .ok_or("missing root exit")?,
        lifetime_images_revalidated: true,
        exact_job_reconciled: true,
        scope: SEVENZIP_PROCESS_CHAIN_SCOPE.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sevenzip_process_tree::{SEVENZIP_PROCESS_CHAIN_SCHEMA, SevenZipProcessObservation};
    use aiw_token::{IntegrityLevel, TokenType};

    const CODE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TIME: u64 = 36_028_797_018_964_091;

    fn token(pid: u32, phase: SevenZipExecutionPhase, candidate: bool) -> TokenEvidence {
        let setup = phase == SevenZipExecutionPhase::InstallationSetup;
        let rid = if setup {
            12288
        } else if candidate {
            4096
        } else {
            8192
        };
        serde_json::from_value(serde_json::json!({
            "schemaVersion":aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,"processId":pid,"tokenType":"primary",
            "isElevated":setup,"isAppContainer":candidate,"userSid":"S-1-5-21-1-2-3-1001","elevationType":if setup {"full"} else {"default"},
            "integrity":{"sid":format!("S-1-16-{rid}"),"rid":rid,"level":if setup {"high"}else if candidate{"low"}else{"medium"}},
            "capabilities":[],"restrictedSidCount":0,"appContainerSid":if candidate {Some("S-1-15-2-1-2-3-4-5-6-7")}else{None}
        })).unwrap()
    }
    fn pins(phase: SevenZipExecutionPhase) -> (&'static str, u64) {
        if phase == SevenZipExecutionPhase::InstallationSetup {
            (
                aiw_probe::sevenzip::SEVENZIP_INSTALLER_SHA256,
                aiw_probe::sevenzip::SEVENZIP_INSTALLER_SIZE_BYTES,
            )
        } else {
            (CODE, 100)
        }
    }
    fn fixture(phase: SevenZipExecutionPhase, candidate: bool) -> SevenZipExecutionTrace {
        let (code, size) = pins(phase);
        let processes = (0..3usize)
            .map(|ordinal| {
                let pid = 10 + ordinal as u32;
                SevenZipProcessObservation {
                    ordinal,
                    process_id: pid,
                    create_event_sequence: [1, 2, 5][ordinal],
                    exit_event_sequence: Some([4, 7, 8][ordinal]),
                    creation_time_100ns: Some(TIME + ordinal as u64),
                    token_before_continue: Some(token(pid, phase, candidate)),
                    exit_code: Some(if ordinal == 0 { 7 } else { 0 }),
                    image_before_continue: Some(SevenZipImageObservation {
                        process_image_path: if ordinal == 0 {
                            phase.fixed_image_path().into()
                        } else {
                            format!(r"C:\Observed\child-{ordinal}.exe")
                        },
                        sha256: if ordinal == 0 {
                            code.into()
                        } else {
                            "b".repeat(64)
                        },
                        size_bytes: if ordinal == 0 { size } else { 200 },
                        volume_serial_number: 9,
                        file_index: TIME + ordinal as u64,
                    }),
                }
            })
            .collect::<Vec<_>>();
        let image_lifetimes = processes
            .iter()
            .map(|p| SevenZipImageLifetime {
                ordinal: p.ordinal,
                process_id: p.process_id,
                create_event_sequence: p.create_event_sequence,
                image_after_exit: p.image_before_continue.clone(),
            })
            .collect();
        SevenZipExecutionTrace {
            schema_version: SEVENZIP_EXECUTION_TRACE_SCHEMA.into(),
            phase,
            root_binding: SevenZipExecutionRootBinding {
                process_id: 10,
                creation_time_100ns: TIME,
                held_token: token(10, phase, candidate),
            },
            image_lifetimes,
            chain: SevenZipProcessChain {
                schema_version: SEVENZIP_PROCESS_CHAIN_SCHEMA.into(),
                scope: SEVENZIP_PROCESS_CHAIN_SCOPE.into(),
                root_process_id: 10,
                events_processed: 8,
                processes,
                timed_out: false,
                owned_job_termination_requested: false,
                owned_job_termination_succeeded: false,
                job_total_processes: Some(3),
                job_active_processes: Some(0),
                job_limit_terminated_processes: Some(0),
                job_accounting_reconciled: true,
                debugger_chain_complete: true,
                requires_debugger_process_exit: false,
                gaps: vec![],
            },
        }
    }
    fn verify(trace: &SevenZipExecutionTrace) -> Result<SevenZipExecutionTraceSummary, String> {
        let (code, size) = pins(trace.phase);
        verify_execution_trace(trace, trace.phase, code, size)
    }
    fn synchronize_lifetimes(trace: &mut SevenZipExecutionTrace) {
        for (p, l) in trace.chain.processes.iter().zip(&mut trace.image_lifetimes) {
            l.process_id = p.process_id;
            l.create_event_sequence = p.create_event_sequence;
            l.image_after_exit = p.image_before_continue.clone();
        }
    }

    #[test]
    fn actual_use_observes_arbitrary_children_and_keeps_nonzero_root_exit_separate() {
        for phase in [
            SevenZipExecutionPhase::Create,
            SevenZipExecutionPhase::Test,
            SevenZipExecutionPhase::Extract,
        ] {
            for candidate in [false, true] {
                let trace = fixture(phase, candidate);
                let summary = verify(&trace).unwrap();
                assert_eq!(summary.root_exit_code, 7);
                assert_eq!(summary.observed_processes, 3);
                assert!(summary.lifetime_images_revalidated && summary.exact_job_reconciled);
                let encoded = serde_json::to_string(&summary).unwrap();
                assert!(
                    !encoded.contains("S-1-")
                        && !encoded.contains("C:\\")
                        && !encoded.contains("compatibility")
                );
            }
        }
    }

    #[test]
    fn elevated_installation_is_exclusively_the_fixed_setup_role() {
        let trace = fixture(SevenZipExecutionPhase::InstallationSetup, false);
        verify(&trace).unwrap();
        let (code, size) = pins(trace.phase);
        let binding = SevenZipExpectedRootBinding {
            process_id: 10,
            creation_time_100ns: TIME,
            held_token: &trace.root_binding.held_token,
            fixed_image_path: trace.phase.fixed_image_path(),
            image_sha256: code,
            image_size_bytes: size,
            expected_control_processes: None,
        };
        assert!(trace.chain.verify_complete(&binding).is_err());
        trace.chain.verify_installation_complete(&binding).unwrap();
        let mut wrong = binding;
        wrong.fixed_image_path = SEVENZIP_EXECUTION_APPLICATION_PATH;
        assert!(trace.chain.verify_installation_complete(&wrong).is_err());
        assert!(
            verify_execution_trace(&trace, SevenZipExecutionPhase::Create, code, size).is_err()
        );
        assert!(verify_execution_trace(&trace, trace.phase, CODE, size).is_err());
        assert!(verify_execution_trace(&trace, trace.phase, code, size + 1).is_err());
        let ordinary = fixture(SevenZipExecutionPhase::Create, false);
        assert!(
            verify_execution_trace(
                &ordinary,
                SevenZipExecutionPhase::InstallationSetup,
                code,
                size
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_application_path_still_rejects_an_elevated_boundary() {
        let mut trace = fixture(SevenZipExecutionPhase::Create, false);
        trace.root_binding.held_token = token(10, SevenZipExecutionPhase::InstallationSetup, false);
        for process in &mut trace.chain.processes {
            process.token_before_continue = Some(token(
                process.process_id,
                SevenZipExecutionPhase::InstallationSetup,
                false,
            ));
        }
        let expected = SevenZipExpectedRootBinding {
            process_id: 10,
            creation_time_100ns: TIME,
            held_token: &trace.root_binding.held_token,
            fixed_image_path: SEVENZIP_EXECUTION_APPLICATION_PATH,
            image_sha256: CODE,
            image_size_bytes: 100,
            expected_control_processes: None,
        };
        assert!(trace.chain.verify_complete(&expected).is_err());
        assert!(verify(&trace).is_err());
    }

    #[test]
    fn installation_boundary_drift_is_not_normalized_away() {
        let mutations: Vec<fn(&mut TokenEvidence)> = vec![
            |t| t.is_elevated = false,
            |t| t.is_app_container = true,
            |t| t.app_container_sid = Some("S-1-15-2-1".into()),
            |t| t.integrity.rid = 8192,
            |t| t.integrity.sid = "S-1-16-8192".into(),
            |t| t.integrity.level = IntegrityLevel::Medium,
            |t| {
                t.capabilities.push(aiw_token::SidAndAttributes {
                    sid: "S-1-15-3-1".into(),
                    attributes: 4,
                })
            },
            |t| t.token_type = TokenType::Impersonation,
            |t| t.schema_version = "wrong".into(),
        ];
        for mutate in mutations {
            let mut trace = fixture(SevenZipExecutionPhase::InstallationSetup, false);
            mutate(&mut trace.root_binding.held_token);
            for p in &mut trace.chain.processes {
                mutate(p.token_before_continue.as_mut().unwrap());
            }
            assert!(verify(&trace).is_err());
        }
        let mut drift = fixture(SevenZipExecutionPhase::InstallationSetup, false);
        drift.chain.processes[1]
            .token_before_continue
            .as_mut()
            .unwrap()
            .user_sid = "other".into();
        assert!(verify(&drift).is_err());
    }

    #[test]
    fn missing_or_forged_lifetime_measurements_are_not_complete() {
        let mutations: Vec<fn(&mut SevenZipExecutionTrace)> = vec![
            |t| {
                t.image_lifetimes.pop();
            },
            |t| t.image_lifetimes.push(t.image_lifetimes[0].clone()),
            |t| t.image_lifetimes[1].ordinal = 0,
            |t| t.image_lifetimes[1].process_id += 1,
            |t| t.image_lifetimes[1].create_event_sequence += 1,
            |t| t.image_lifetimes[1].image_after_exit = None,
            |t| {
                t.image_lifetimes[1]
                    .image_after_exit
                    .as_mut()
                    .unwrap()
                    .sha256 = CODE.into()
            },
            |t| {
                t.image_lifetimes[1]
                    .image_after_exit
                    .as_mut()
                    .unwrap()
                    .size_bytes += 1
            },
            |t| {
                t.image_lifetimes[1]
                    .image_after_exit
                    .as_mut()
                    .unwrap()
                    .file_index += 1
            },
            |t| {
                t.image_lifetimes[1]
                    .image_after_exit
                    .as_mut()
                    .unwrap()
                    .volume_serial_number += 1
            },
            |t| {
                t.image_lifetimes[1]
                    .image_after_exit
                    .as_mut()
                    .unwrap()
                    .process_image_path = "other".into()
            },
        ];
        for mutate in mutations {
            let mut trace = fixture(SevenZipExecutionPhase::Test, true);
            mutate(&mut trace);
            assert!(verify(&trace).is_err());
        }
    }

    #[test]
    fn root_policy_phase_code_and_chain_facts_remain_required() {
        let mutations: Vec<fn(&mut SevenZipExecutionTrace)> = vec![
            |t| t.schema_version = "old".into(),
            |t| t.root_binding.process_id = 11,
            |t| t.root_binding.creation_time_100ns += 1,
            |t| t.root_binding.held_token.process_id = 11,
            |t| t.root_binding.held_token.user_sid = "other".into(),
            |t| {
                t.chain.processes[0]
                    .image_before_continue
                    .as_mut()
                    .unwrap()
                    .sha256 = "c".repeat(64)
            },
            |t| t.chain.processes[1].token_before_continue = None,
            |t| {
                t.chain.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .process_id = 10
            },
            |t| {
                t.chain.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .is_elevated = true
            },
            |t| t.chain.processes[1].creation_time_100ns = Some(TIME - 1),
            |t| t.chain.processes[1].exit_event_sequence = None,
            |t| t.chain.processes[1].exit_event_sequence = Some(5),
            |t| t.chain.job_total_processes = Some(4),
            |t| t.chain.job_active_processes = Some(1),
            |t| t.chain.job_limit_terminated_processes = Some(1),
            |t| t.chain.gaps.push("gap".into()),
            |t| t.chain.debugger_chain_complete = false,
            |t| t.chain.job_accounting_reconciled = false,
            |t| t.chain.requires_debugger_process_exit = true,
            |t| t.chain.timed_out = true,
        ];
        for mutate in mutations {
            let mut trace = fixture(SevenZipExecutionPhase::Extract, false);
            mutate(&mut trace);
            assert!(verify(&trace).is_err());
        }
        let trace = fixture(SevenZipExecutionPhase::Create, false);
        assert!(verify_execution_trace(&trace, SevenZipExecutionPhase::Test, CODE, 100).is_err());
        assert!(verify_execution_trace(&trace, trace.phase, "bad", 100).is_err());
    }

    #[test]
    fn pid_reuse_needs_disjoint_events_and_full_width_increasing_times() {
        let mut trace = fixture(SevenZipExecutionPhase::Create, false);
        trace.chain.processes[2].process_id = 10;
        trace.chain.processes[2]
            .token_before_continue
            .as_mut()
            .unwrap()
            .process_id = 10;
        synchronize_lifetimes(&mut trace);
        verify(&trace).unwrap();
        let mut time = trace.clone();
        time.chain.processes[2].creation_time_100ns = Some(TIME);
        assert!(verify(&time).is_err());
        trace.chain.processes[0].exit_event_sequence = Some(6);
        assert!(verify(&trace).is_err());
    }

    #[test]
    fn bounded_partial_dtos_and_historical_chain_serialization_stay_separate() {
        let mut trace = fixture(SevenZipExecutionPhase::Create, false);
        let chain_bytes = serde_json::to_vec(&trace.chain).unwrap();
        let encoded = serde_json::to_string(&trace).unwrap();
        assert!(encoded.contains(&TIME.to_string()));
        let decoded: SevenZipExecutionTrace = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, trace);
        assert_eq!(serde_json::to_vec(&decoded.chain).unwrap(), chain_bytes);
        trace.image_lifetimes[0].image_after_exit = None;
        trace.validate_shape().unwrap();
        assert!(verify(&trace).is_err());
        let mut unknown = serde_json::to_value(&trace).unwrap();
        unknown["complete"] = true.into();
        assert!(serde_json::from_value::<SevenZipExecutionTrace>(unknown).is_err());
        let mut unknown = serde_json::to_value(&trace.root_binding).unwrap();
        unknown["callerValidated"] = true.into();
        assert!(serde_json::from_value::<SevenZipExecutionRootBinding>(unknown).is_err());
        trace.image_lifetimes = vec![trace.image_lifetimes[0].clone(); MAX_CHAIN_PROCESSES + 1];
        assert!(trace.validate_shape().is_err());
    }
}
