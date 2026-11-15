//! Fixed first-party control code evidence, distinct from physical object identity.
//! This contract never authorizes execution or verifies application compatibility,
//! loaded memory, DLLs, registry controls, MXC, brokers or all-host coverage.
use crate::sevenzip_process_tree::{
    MAX_CHAIN_IMAGE_BYTES, MAX_CHAIN_PROCESSES, SEVENZIP_PROCESS_CHAIN_SCOPE,
    SevenZipExpectedRootBinding, SevenZipImageObservation, SevenZipProcessChain,
};
use crate::sevenzip_tree_control::{
    SEVENZIP_TREE_CONTROL_CONSOLE, SEVENZIP_TREE_CONTROL_HELPER, SevenZipConsoleSupportObservation,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const SEVENZIP_CODE_CONTROL_TRACE_SCHEMA: &str = "aiw.dev/sevenzip-code-control-trace/v0alpha1";
pub const SEVENZIP_CODE_CONTROL_SUMMARY_SCHEMA: &str =
    "aiw.dev/sevenzip-code-control-summary/v0alpha1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SevenZipControlCodeClass {
    RootCode,
    ConsoleSupport,
}

/// Actual per-event observations. Optional fields retain incomplete collection;
/// an asserted class alone never supplies missing image or process facts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipControlCodeEvidence {
    pub ordinal: usize,
    pub process_id: u32,
    pub create_event_sequence: u32,
    pub code_class_before_continue: Option<SevenZipControlCodeClass>,
    pub image_after_exit: Option<SevenZipImageObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipCodeControlTrace {
    pub schema_version: String,
    pub chain: SevenZipProcessChain,
    pub code_evidence: Vec<SevenZipControlCodeEvidence>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SevenZipConsoleIdentityRelation {
    NoConsoleObserved,
    AllObservedPairsEqual,
    AtLeastOnePairDifferent,
}

/// Even equal observed legacy fields do not establish cross-namespace physical
/// equivalence. This contract makes only the separately checked code claim.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SevenZipPhysicalObjectEquivalence {
    Unproved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipCodeControlSummary {
    pub schema_version: String,
    pub scope: String,
    pub observed_processes: u32,
    pub helper_processes: u32,
    pub console_support_processes: u32,
    pub paired_exits: u32,
    pub root_exited_before_helper_child: bool,
    pub root_exited_before_grandchild_create: bool,
    pub all_observed_tokens_match_root_boundary: bool,
    pub exact_job_reconciled: bool,
    pub code_checked_before_continue: bool,
    pub same_event_image_revalidated: bool,
    pub console_identity_relation: SevenZipConsoleIdentityRelation,
    pub physical_object_equivalence: SevenZipPhysicalObjectEquivalence,
}

fn same_path(actual: &str, expected: &str) -> bool {
    actual
        .strip_prefix(r"\\?\")
        .unwrap_or(actual)
        .eq_ignore_ascii_case(expected.strip_prefix(r"\\?\").unwrap_or(expected))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl SevenZipCodeControlTrace {
    /// Bounds only; partial and semantically malformed facts remain retainable.
    /// Consumers must bound serialized bytes before deserializing this DTO.
    pub fn validate_shape(&self) -> Result<(), String> {
        self.chain.validate_shape()?;
        if self.schema_version.chars().count() > 128
            || self.schema_version.len() > 512
            || self.code_evidence.len() > MAX_CHAIN_PROCESSES
            || self.code_evidence.iter().any(|e| {
                e.image_after_exit.as_ref().is_some_and(|image| {
                    image.process_image_path.chars().count() > 32768
                        || image.process_image_path.len() > 32768 * 4
                        || image.sha256.chars().count() > 128
                        || image.sha256.len() > 512
                        || image.size_bytes > MAX_CHAIN_IMAGE_BYTES
                })
            })
        {
            return Err("code-control evidence exceeds bounds".into());
        }
        Ok(())
    }
}

/// The caller supplies independently approved root code and predeclared OS code,
/// not expectations inferred from this event. Legacy IDs are actual nonzero
/// observations; matching content does not assert that two file objects coincide.
pub fn classify_control_image(
    image: &SevenZipImageObservation,
    root_sha256: &str,
    root_size: u64,
    console: &SevenZipConsoleSupportObservation,
) -> Result<SevenZipControlCodeClass, String> {
    console.validate_pinned()?;
    if !valid_hash(root_sha256)
        || root_size == 0
        || root_size > MAX_CHAIN_IMAGE_BYTES
        || image.volume_serial_number == 0
        || image.file_index == 0
    {
        return Err("independent bounded code pins and observed image identity required".into());
    }
    if same_path(&image.process_image_path, SEVENZIP_TREE_CONTROL_HELPER)
        && image.sha256 == root_sha256
        && image.size_bytes == root_size
    {
        Ok(SevenZipControlCodeClass::RootCode)
    } else if same_path(&image.process_image_path, SEVENZIP_TREE_CONTROL_CONSOLE)
        && image.sha256 == console.sha256
        && image.size_bytes == console.size_bytes
    {
        Ok(SevenZipControlCodeClass::ConsoleSupport)
    } else {
        Err("image differs from the fixed helper or declared OS support code".into())
    }
}

/// Recompute a new fixed positive control. The caller independently validates
/// suspended-root token policy and retains the external code sources. The native
/// producer must record these classes before continuing their exact debug events
/// and revalidate the same event hFile after exit; this DTO is not launch authority.
pub fn verify_code_control(
    trace: &SevenZipCodeControlTrace,
    root: &SevenZipExpectedRootBinding<'_>,
    console: &SevenZipConsoleSupportObservation,
) -> Result<SevenZipCodeControlSummary, String> {
    trace.validate_shape()?;
    console.validate_pinned()?;
    if trace.schema_version != SEVENZIP_CODE_CONTROL_TRACE_SCHEMA
        || !same_path(root.fixed_image_path, SEVENZIP_TREE_CONTROL_HELPER)
        || root.expected_control_processes.is_some()
    {
        return Err("new fixed code-control schema and independent helper binding required".into());
    }
    let chain = &trace.chain;
    chain.verify_complete(root)?;
    if !(3..=6).contains(&chain.processes.len())
        || trace.code_evidence.len() != chain.processes.len()
    {
        return Err(
            "three helper roles, at most three supports and every code observation required".into(),
        );
    }
    let mut helpers = Vec::new();
    let mut supports = 0_u32;
    let mut identity_differs = false;
    for (process, evidence) in chain.processes.iter().zip(&trace.code_evidence) {
        let image = process
            .image_before_continue
            .as_ref()
            .ok_or("missing creation-event image")?;
        let class =
            classify_control_image(image, root.image_sha256, root.image_size_bytes, console)?;
        if evidence.ordinal != process.ordinal
            || evidence.process_id != process.process_id
            || evidence.create_event_sequence != process.create_event_sequence
            || evidence.code_class_before_continue != Some(class)
            || evidence.image_after_exit.as_ref() != Some(image)
        {
            return Err(
                "code gate, event association or same-event image revalidation differs".into(),
            );
        }
        match class {
            SevenZipControlCodeClass::RootCode => helpers.push(process),
            SevenZipControlCodeClass::ConsoleSupport => {
                if process.exit_code != Some(0) {
                    return Err("console support did not exit successfully".into());
                }
                supports += 1;
                identity_differs |= image.volume_serial_number != console.volume_serial_number
                    || image.file_index != console.file_index;
            }
        }
    }
    if helpers.len() != 3
        || supports > 3
        || helpers[0].ordinal != 0
        || helpers[0].process_id != root.process_id
        || helpers.iter().map(|p| p.exit_code).collect::<Vec<_>>() != [Some(31), Some(32), Some(33)]
        || helpers[0].exit_event_sequence >= helpers[1].exit_event_sequence
        || helpers[0]
            .exit_event_sequence
            .is_none_or(|exit| exit >= helpers[2].create_event_sequence)
    {
        return Err("fixed helper roles or root-first process ordering differs".into());
    }
    Ok(SevenZipCodeControlSummary {
        schema_version: SEVENZIP_CODE_CONTROL_SUMMARY_SCHEMA.into(),
        scope: SEVENZIP_PROCESS_CHAIN_SCOPE.into(),
        observed_processes: chain.processes.len() as u32,
        helper_processes: 3,
        console_support_processes: supports,
        paired_exits: chain.processes.len() as u32,
        root_exited_before_helper_child: true,
        root_exited_before_grandchild_create: true,
        all_observed_tokens_match_root_boundary: true,
        exact_job_reconciled: true,
        code_checked_before_continue: true,
        same_event_image_revalidated: true,
        console_identity_relation: if supports == 0 {
            SevenZipConsoleIdentityRelation::NoConsoleObserved
        } else if identity_differs {
            SevenZipConsoleIdentityRelation::AtLeastOnePairDifferent
        } else {
            SevenZipConsoleIdentityRelation::AllObservedPairsEqual
        },
        physical_object_equivalence: SevenZipPhysicalObjectEquivalence::Unproved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sevenzip_process_tree::{SEVENZIP_PROCESS_CHAIN_SCHEMA, SevenZipProcessObservation};
    use crate::sevenzip_tree_control::{
        SEVENZIP_CONSOLE_SUPPORT_SCHEMA, SEVENZIP_CONSOLE_SUPPORT_SHA256,
        SEVENZIP_CONSOLE_SUPPORT_SIZE, verify_control,
    };
    use aiw_token::TokenEvidence;

    const ROOT_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TIME: u64 = 36_028_797_018_964_091;

    fn token(pid: u32, candidate: bool) -> TokenEvidence {
        serde_json::from_value(serde_json::json!({
            "schemaVersion":aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,"processId":pid,
            "tokenType":"primary","isElevated":false,"isAppContainer":candidate,
            "userSid":"S-1-5-21-1-2-3-1001","elevationType":"default",
            "integrity":{"sid":if candidate {"S-1-16-4096"} else {"S-1-16-8192"},
                "rid":if candidate {4096} else {8192},"level":if candidate {"low"} else {"medium"}},
            "capabilities":[],"restrictedSidCount":0,
            "appContainerSid":if candidate {Some("S-1-15-2-1-2-3-4-5-6-7")} else {None}
        }))
        .unwrap()
    }
    fn console() -> SevenZipConsoleSupportObservation {
        SevenZipConsoleSupportObservation {
            schema_version: SEVENZIP_CONSOLE_SUPPORT_SCHEMA.into(),
            windows: aiw_probe::WindowsVersionObservation {
                major: 10,
                minor: 0,
                build: 26100,
                revision: 9711,
                observer_architecture: "x86_64".into(),
            },
            canonical_path: SEVENZIP_TREE_CONTROL_CONSOLE.into(),
            identity: aiw_probe::WindowsFileIdentity {
                final_path: SEVENZIP_TREE_CONTROL_CONSOLE.into(),
                volume_serial_number: "1234567890abcdef".into(),
                file_id: "1234567890abcdef1234567890abcdef".into(),
            },
            sha256: SEVENZIP_CONSOLE_SUPPORT_SHA256.into(),
            size_bytes: SEVENZIP_CONSOLE_SUPPORT_SIZE,
            volume_serial_number: 7,
            file_index: 99,
        }
    }
    fn root(token: &TokenEvidence) -> SevenZipExpectedRootBinding<'_> {
        SevenZipExpectedRootBinding {
            process_id: 10,
            creation_time_100ns: TIME,
            held_token: token,
            fixed_image_path: SEVENZIP_TREE_CONTROL_HELPER,
            image_sha256: ROOT_HASH,
            image_size_bytes: 100,
            expected_control_processes: None,
        }
    }
    fn fixture(support_count: usize, candidate: bool, different: bool) -> SevenZipCodeControlTrace {
        let mut processes = Vec::new();
        for role in 0..3usize {
            for support in [false, true] {
                if support && role >= support_count {
                    continue;
                }
                let ordinal = processes.len();
                let pid = 10 + ordinal as u32;
                processes.push(SevenZipProcessObservation {
                    ordinal,
                    process_id: pid,
                    create_event_sequence: if support {
                        [2, 6, 9][role]
                    } else {
                        [1, 3, 8][role]
                    },
                    creation_time_100ns: Some(TIME + ordinal as u64),
                    token_before_continue: Some(token(pid, candidate)),
                    image_before_continue: Some(SevenZipImageObservation {
                        process_image_path: if support {
                            SEVENZIP_TREE_CONTROL_CONSOLE
                        } else {
                            SEVENZIP_TREE_CONTROL_HELPER
                        }
                        .into(),
                        sha256: if support {
                            SEVENZIP_CONSOLE_SUPPORT_SHA256
                        } else {
                            ROOT_HASH
                        }
                        .into(),
                        size_bytes: if support {
                            SEVENZIP_CONSOLE_SUPPORT_SIZE
                        } else {
                            100
                        },
                        volume_serial_number: if support && !different { 7 } else { 11 },
                        file_index: if support && !different {
                            99
                        } else {
                            TIME + ordinal as u64
                        },
                    }),
                    exit_code: Some(if support { 0 } else { 31 + role as u32 }),
                    exit_event_sequence: Some(if support {
                        [5, 11, 16][role]
                    } else {
                        [4, 10, 15][role]
                    }),
                });
            }
        }
        let code_evidence = processes
            .iter()
            .map(|p| SevenZipControlCodeEvidence {
                ordinal: p.ordinal,
                process_id: p.process_id,
                create_event_sequence: p.create_event_sequence,
                code_class_before_continue: Some(if p.exit_code == Some(0) {
                    SevenZipControlCodeClass::ConsoleSupport
                } else {
                    SevenZipControlCodeClass::RootCode
                }),
                image_after_exit: p.image_before_continue.clone(),
            })
            .collect();
        SevenZipCodeControlTrace {
            schema_version: SEVENZIP_CODE_CONTROL_TRACE_SCHEMA.into(),
            code_evidence,
            chain: SevenZipProcessChain {
                schema_version: SEVENZIP_PROCESS_CHAIN_SCHEMA.into(),
                scope: SEVENZIP_PROCESS_CHAIN_SCOPE.into(),
                root_process_id: 10,
                events_processed: 30,
                job_total_processes: Some(processes.len() as u32),
                processes,
                timed_out: false,
                owned_job_termination_requested: false,
                owned_job_termination_succeeded: false,
                job_active_processes: Some(0),
                job_limit_terminated_processes: Some(0),
                job_accounting_reconciled: true,
                debugger_chain_complete: true,
                requires_debugger_process_exit: false,
                gaps: vec![],
            },
        }
    }

    #[test]
    fn code_bound_controls_count_every_process_without_claiming_physical_equivalence() {
        for candidate in [false, true] {
            for count in 0..=3 {
                for different in [false, true] {
                    let trace = fixture(count, candidate, different);
                    let t = token(10, candidate);
                    let result = verify_code_control(&trace, &root(&t), &console()).unwrap();
                    assert_eq!(result.observed_processes, 3 + count as u32);
                    assert_eq!(result.helper_processes, 3);
                    assert_eq!(result.console_support_processes, count as u32);
                    assert!(
                        result.code_checked_before_continue && result.same_event_image_revalidated
                    );
                    assert_eq!(
                        result.physical_object_equivalence,
                        SevenZipPhysicalObjectEquivalence::Unproved
                    );
                    assert_eq!(
                        result.console_identity_relation,
                        if count == 0 {
                            SevenZipConsoleIdentityRelation::NoConsoleObserved
                        } else if different {
                            SevenZipConsoleIdentityRelation::AtLeastOnePairDifferent
                        } else {
                            SevenZipConsoleIdentityRelation::AllObservedPairsEqual
                        }
                    );
                    let encoded = serde_json::to_string(&result).unwrap();
                    assert!(!encoded.contains("S-1-") && !encoded.contains("C:\\"));
                    if count > 0 && different {
                        assert!(
                            verify_control(&trace.chain, &root(&t), &console().expected_binding())
                                .is_err()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn classifier_requires_independent_pins_and_both_observed_identity_fields() {
        let image = fixture(3, false, true).chain.processes[1]
            .image_before_continue
            .clone()
            .unwrap();
        assert_eq!(
            classify_control_image(&image, ROOT_HASH, 100, &console()).unwrap(),
            SevenZipControlCodeClass::ConsoleSupport
        );
        for mutate in [
            |i: &mut SevenZipImageObservation| i.sha256 = "b".repeat(64),
            |i: &mut SevenZipImageObservation| i.size_bytes += 1,
            |i: &mut SevenZipImageObservation| {
                i.process_image_path = r"C:\other\conhost.exe".into()
            },
            |i: &mut SevenZipImageObservation| i.volume_serial_number = 0,
            |i: &mut SevenZipImageObservation| i.file_index = 0,
        ] {
            let mut bad = image.clone();
            mutate(&mut bad);
            assert!(classify_control_image(&bad, ROOT_HASH, 100, &console()).is_err());
        }
        assert!(classify_control_image(&image, "wrong", 100, &console()).is_err());
        assert!(classify_control_image(&image, ROOT_HASH, 0, &console()).is_err());
        let mut bad = console();
        bad.windows.revision += 1;
        assert!(classify_control_image(&image, ROOT_HASH, 100, &bad).is_err());
    }

    #[test]
    fn missing_or_changed_event_gate_and_exit_measurements_cannot_pass() {
        let mutations: Vec<fn(&mut SevenZipCodeControlTrace)> = vec![
            |t| t.schema_version = "old".into(),
            |t| {
                t.code_evidence.pop();
            },
            |t| t.code_evidence.push(t.code_evidence[0].clone()),
            |t| t.code_evidence[1].code_class_before_continue = None,
            |t| {
                t.code_evidence[1].code_class_before_continue =
                    Some(SevenZipControlCodeClass::RootCode)
            },
            |t| t.code_evidence[1].image_after_exit = None,
            |t| t.code_evidence[1].image_after_exit.as_mut().unwrap().sha256 = "b".repeat(64),
            |t| {
                t.code_evidence[1]
                    .image_after_exit
                    .as_mut()
                    .unwrap()
                    .size_bytes += 1
            },
            |t| {
                t.code_evidence[1]
                    .image_after_exit
                    .as_mut()
                    .unwrap()
                    .file_index += 1
            },
            |t| {
                t.code_evidence[1]
                    .image_after_exit
                    .as_mut()
                    .unwrap()
                    .volume_serial_number += 1
            },
            |t| {
                t.code_evidence[1]
                    .image_after_exit
                    .as_mut()
                    .unwrap()
                    .process_image_path = r"C:\other\conhost.exe".into()
            },
            |t| t.code_evidence[1].ordinal = 0,
            |t| t.code_evidence[1].process_id += 1,
            |t| t.code_evidence[1].create_event_sequence += 1,
        ];
        let t = token(10, true);
        for mutate in mutations {
            let mut trace = fixture(3, true, true);
            mutate(&mut trace);
            assert!(verify_code_control(&trace, &root(&t), &console()).is_err());
        }
    }

    #[test]
    fn token_time_pid_reuse_job_and_role_gaps_remain_failures() {
        let mutations: Vec<fn(&mut SevenZipCodeControlTrace)> = vec![
            |t| t.chain.processes[1].token_before_continue = None,
            |t| {
                t.chain.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .user_sid = "other".into()
            },
            |t| {
                t.chain.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .is_app_container = false
            },
            |t| {
                t.chain.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .process_id = 10
            },
            |t| t.chain.processes[1].creation_time_100ns = Some(TIME - 1),
            |t| t.chain.processes[0].creation_time_100ns = Some(TIME + 1),
            |t| t.chain.processes[1].process_id = 10,
            |t| t.chain.processes[1].exit_event_sequence = None,
            |t| t.chain.processes[1].exit_event_sequence = Some(3),
            |t| t.chain.processes[0].exit_event_sequence = Some(12),
            |t| t.chain.processes[0].exit_event_sequence = None,
            |t| t.chain.processes[2].exit_code = Some(0),
            |t| t.chain.processes[1].exit_code = Some(1),
            |t| t.chain.job_total_processes = Some(5),
            |t| t.chain.job_active_processes = Some(1),
            |t| t.chain.job_limit_terminated_processes = Some(1),
            |t| t.chain.gaps.push("gap".into()),
            |t| t.chain.debugger_chain_complete = false,
            |t| t.chain.job_accounting_reconciled = false,
            |t| t.chain.requires_debugger_process_exit = true,
            |t| t.chain.timed_out = true,
        ];
        let t = token(10, true);
        for mutate in mutations {
            let mut trace = fixture(3, true, true);
            mutate(&mut trace);
            assert!(verify_code_control(&trace, &root(&t), &console()).is_err());
        }
    }

    #[test]
    fn independent_root_and_historical_three_process_mode_cannot_be_substituted() {
        let trace = fixture(3, false, true);
        let t = token(10, false);
        let mut expected = root(&t);
        expected.image_sha256 = SEVENZIP_CONSOLE_SUPPORT_SHA256;
        assert!(verify_code_control(&trace, &expected, &console()).is_err());
        let mut expected = root(&t);
        expected.creation_time_100ns = TIME + 1;
        assert!(verify_code_control(&trace, &expected, &console()).is_err());
        let mut expected = root(&t);
        expected.expected_control_processes = Some(3);
        assert!(verify_code_control(&trace, &expected, &console()).is_err());
    }

    #[test]
    fn complete_chain_still_requires_root_exit_before_grandchild_creation() {
        let mut trace = fixture(0, false, true);
        trace.chain.processes[0].exit_event_sequence = Some(9);
        let t = token(10, false);
        trace.chain.verify_complete(&root(&t)).unwrap();
        assert!(verify_code_control(&trace, &root(&t), &console()).is_err());
    }

    #[test]
    fn reused_pid_requires_disjoint_lifetimes_and_increasing_actual_creation_time() {
        let mut trace = fixture(0, false, true);
        trace.chain.processes[2].process_id = 10;
        trace.chain.processes[2]
            .token_before_continue
            .as_mut()
            .unwrap()
            .process_id = 10;
        trace.code_evidence[2].process_id = 10;
        let t = token(10, false);
        verify_code_control(&trace, &root(&t), &console()).unwrap();
        let mut nonincreasing = trace.clone();
        nonincreasing.chain.processes[2].creation_time_100ns = Some(TIME);
        assert!(nonincreasing.chain.verify_complete(&root(&t)).is_err());
        assert!(verify_code_control(&nonincreasing, &root(&t), &console()).is_err());
        trace.chain.processes[0].exit_event_sequence = Some(9);
        assert!(trace.chain.verify_complete(&root(&t)).is_err());
        assert!(verify_code_control(&trace, &root(&t), &console()).is_err());
    }

    #[test]
    fn consistent_unknown_or_changed_code_cannot_be_approved_by_a_recorded_class() {
        let mutations: Vec<fn(&mut SevenZipImageObservation)> = vec![
            |image| image.process_image_path = r"C:\other\conhost.exe".into(),
            |image| image.sha256 = "b".repeat(64),
            |image| image.size_bytes += 1,
        ];
        for mutate in mutations {
            let mut trace = fixture(3, false, true);
            mutate(
                trace.chain.processes[1]
                    .image_before_continue
                    .as_mut()
                    .unwrap(),
            );
            trace.code_evidence[1].image_after_exit =
                trace.chain.processes[1].image_before_continue.clone();
            let t = token(10, false);
            trace.chain.verify_complete(&root(&t)).unwrap();
            assert!(verify_code_control(&trace, &root(&t), &console()).is_err());
        }
    }

    #[test]
    fn partial_shape_is_bounded_and_serialization_preserves_full_width_integers() {
        let mut partial = fixture(3, false, true);
        partial.code_evidence[0].image_after_exit = None;
        partial.code_evidence[0].code_class_before_continue = None;
        partial.validate_shape().unwrap();
        assert!(verify_code_control(&partial, &root(&token(10, false)), &console()).is_err());
        let trace = fixture(3, false, true);
        let encoded = serde_json::to_string(&trace).unwrap();
        assert!(encoded.contains(&TIME.to_string()));
        let decoded: SevenZipCodeControlTrace = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, trace);
        let mut unknown = serde_json::to_value(&trace).unwrap();
        unknown["complete"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SevenZipCodeControlTrace>(unknown).is_err());
        let mut unknown = serde_json::to_value(&trace.code_evidence[0]).unwrap();
        unknown["callerValidated"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SevenZipControlCodeEvidence>(unknown).is_err());
        let mut oversized = trace.clone();
        oversized.code_evidence = vec![trace.code_evidence[0].clone(); MAX_CHAIN_PROCESSES + 1];
        assert!(oversized.validate_shape().is_err());
    }
}
