//! New fixed control contract with independently held console-support code.
//! This does not relax the historical exact-three-process contract, authorize
//! execution, or verify an application's compatibility or general isolation.
use crate::sevenzip_process_tree::{
    MAX_CHAIN_IMAGE_BYTES, SEVENZIP_PROCESS_CHAIN_SCOPE, SevenZipExpectedRootBinding,
    SevenZipProcessChain,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const SEVENZIP_TREE_CONTROL_SCHEMA: &str = "aiw.dev/sevenzip-tree-control-summary/v0alpha1";
pub const SEVENZIP_TREE_CONTROL_HELPER: &str = r"C:\AIW\SevenZip\sevenzip_assessment.exe";
pub const SEVENZIP_TREE_CONTROL_CONSOLE: &str = r"C:\Windows\System32\conhost.exe";
pub const SEVENZIP_CONSOLE_SUPPORT_SCHEMA: &str = "aiw.dev/sevenzip-console-support/v0alpha1";
pub const SEVENZIP_CONSOLE_SUPPORT_PATH: &str = SEVENZIP_TREE_CONTROL_CONSOLE;
pub const SEVENZIP_CONSOLE_SUPPORT_SHA256: &str =
    "c86146188b78e484f32cc29e2331689659943b47689a85570342044f499938ac";
pub const SEVENZIP_CONSOLE_SUPPORT_SIZE: u64 = 1_003_520;

/// Closed observation of independently predeclared System32 support bytes.
/// Provenance requires the exact OS/path/pin and the caller's live identity
/// hold; this record neither verifies Authenticode nor supplies launch authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipConsoleSupportObservation {
    pub schema_version: String,
    pub windows: aiw_probe::WindowsVersionObservation,
    pub canonical_path: String,
    pub identity: aiw_probe::WindowsFileIdentity,
    pub sha256: String,
    pub size_bytes: u64,
    pub volume_serial_number: u32,
    pub file_index: u64,
}

impl SevenZipConsoleSupportObservation {
    pub fn validate_pinned(&self) -> Result<(), String> {
        self.windows.validate()?;
        let lower_hex = |value: &str, length: usize| {
            value.len() == length
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && value.bytes().any(|b| b != b'0')
        };
        if self.schema_version != SEVENZIP_CONSOLE_SUPPORT_SCHEMA
            || (
                self.windows.major,
                self.windows.minor,
                self.windows.build,
                self.windows.revision,
                self.windows.observer_architecture.as_str(),
            ) != (10, 0, 26100, 9711, "x86_64")
            || !same_path(&self.canonical_path, SEVENZIP_CONSOLE_SUPPORT_PATH)
            || !same_path(&self.identity.final_path, SEVENZIP_CONSOLE_SUPPORT_PATH)
            || self.sha256 != SEVENZIP_CONSOLE_SUPPORT_SHA256
            || self.size_bytes != SEVENZIP_CONSOLE_SUPPORT_SIZE
            || self.volume_serial_number == 0
            || self.file_index == 0
            || !lower_hex(&self.identity.volume_serial_number, 16)
            || !lower_hex(&self.identity.file_id, 32)
        {
            return Err("console support differs from fixed OS/code/identity contract".into());
        }
        Ok(())
    }

    /// Call validate_pinned first and retain/revalidate the independently held
    /// source. This borrowing conversion itself does not validate provenance.
    pub fn expected_binding(&self) -> SevenZipExpectedConsoleBinding<'_> {
        SevenZipExpectedConsoleBinding {
            image_sha256: &self.sha256,
            image_size_bytes: self.size_bytes,
            volume_serial_number: self.volume_serial_number,
            file_index: self.file_index,
        }
    }
}

/// Supply from a separately held, independently validated guest System32 image.
/// The caller establishes Windows provenance and retains the live file across
/// collection. Never derive these expectations from the chain being verified.
/// Identity uses the same BY_HANDLE_FILE_INFORMATION fields as debug events.
pub struct SevenZipExpectedConsoleBinding<'a> {
    pub image_sha256: &'a str,
    pub image_size_bytes: u64,
    pub volume_serial_number: u32,
    pub file_index: u64,
}

/// Sanitized findings for this fixed first-party control only. Counts include
/// every observed process. No PID, SID, path or inferred parent edge is exported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipTreeControlSummary {
    pub schema_version: String,
    pub scope: String,
    pub observed_processes: u32,
    pub helper_processes: u32,
    pub console_support_processes: u32,
    pub paired_exits: u32,
    pub root_exited_before_helper_child: bool,
    pub all_observed_tokens_match_root_boundary: bool,
    pub exact_job_reconciled: bool,
}

fn same_path(actual: &str, expected: &str) -> bool {
    actual
        .strip_prefix(r"\\?\")
        .unwrap_or(actual)
        .eq_ignore_ascii_case(expected.strip_prefix(r"\\?\").unwrap_or(expected))
}

/// Validate the new positive control from all creation/exit measurements and
/// externally supplied code bindings. No support process receives an exception
/// from the root token policy; candidate support outside that boundary refuses
/// the control. Brokers/all-host coverage remain outside the stated scope.
pub fn verify_control(
    chain: &SevenZipProcessChain,
    root: &SevenZipExpectedRootBinding<'_>,
    console: &SevenZipExpectedConsoleBinding<'_>,
) -> Result<SevenZipTreeControlSummary, String> {
    if !same_path(root.fixed_image_path, SEVENZIP_TREE_CONTROL_HELPER)
        || root.expected_control_processes.is_some()
        || console.image_sha256.len() != 64
        || !console
            .image_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || console.image_size_bytes == 0
        || console.image_size_bytes >= MAX_CHAIN_IMAGE_BYTES
        || console.volume_serial_number == 0
        || console.file_index == 0
    {
        return Err("independently held fixed helper/console code bindings required".into());
    }
    // This proves token consistency for EVERY record, paired events, PID reuse
    // rules, job totals/absence, and complete coverage before classification.
    chain.verify_complete(root)?;
    if !(3..=6).contains(&chain.processes.len()) {
        return Err(
            "fixed control requires three helpers and at most three console supports".into(),
        );
    }
    let mut helpers = Vec::new();
    let mut supports = 0_u32;
    for process in &chain.processes {
        let image = process
            .image_before_continue
            .as_ref()
            .ok_or("fixed control lacks creation-time image")?;
        if same_path(&image.process_image_path, SEVENZIP_TREE_CONTROL_HELPER) {
            if image.sha256 != root.image_sha256 || image.size_bytes != root.image_size_bytes {
                return Err("helper role code differs from held root code".into());
            }
            helpers.push(process);
        } else if same_path(&image.process_image_path, SEVENZIP_TREE_CONTROL_CONSOLE) {
            if image.sha256 != console.image_sha256
                || image.size_bytes != console.image_size_bytes
                || image.volume_serial_number != console.volume_serial_number
                || image.file_index != console.file_index
                || process.exit_code != Some(0)
            {
                return Err("console support differs from independently held image or exit".into());
            }
            supports += 1;
        } else {
            return Err("unrecognized image in fixed helper/console control".into());
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
        return Err("fixed helper roles, root-first exits or console count differ".into());
    }
    // verify_complete already enforces increasing create sequences in ordinal
    // order, so helper roles retain creation order despite interleaved support.
    Ok(SevenZipTreeControlSummary {
        schema_version: SEVENZIP_TREE_CONTROL_SCHEMA.into(),
        scope: SEVENZIP_PROCESS_CHAIN_SCOPE.into(),
        observed_processes: chain.processes.len() as u32,
        helper_processes: 3,
        console_support_processes: supports,
        paired_exits: chain.processes.len() as u32,
        root_exited_before_helper_child: true,
        all_observed_tokens_match_root_boundary: true,
        exact_job_reconciled: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sevenzip_process_tree::{
        SEVENZIP_PROCESS_CHAIN_SCHEMA, SevenZipImageObservation, SevenZipProcessObservation,
    };
    use aiw_token::TokenEvidence;

    const HELPER_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CONSOLE_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
    fn console() -> SevenZipExpectedConsoleBinding<'static> {
        SevenZipExpectedConsoleBinding {
            image_sha256: CONSOLE_HASH,
            image_size_bytes: 200,
            volume_serial_number: 7,
            file_index: 99,
        }
    }
    fn root(token: &TokenEvidence) -> SevenZipExpectedRootBinding<'_> {
        SevenZipExpectedRootBinding {
            process_id: 10,
            creation_time_100ns: 36_028_797_018_964_091,
            held_token: token,
            fixed_image_path: SEVENZIP_TREE_CONTROL_HELPER,
            image_sha256: HELPER_HASH,
            image_size_bytes: 100,
            expected_control_processes: None,
        }
    }
    fn chain(support_count: usize, candidate: bool) -> SevenZipProcessChain {
        let mut processes = Vec::new();
        for role in 0..3 {
            let ordinal = processes.len();
            let pid = 10 + ordinal as u32;
            processes.push(SevenZipProcessObservation {
                ordinal,
                process_id: pid,
                create_event_sequence: [1, 3, 8][role as usize],
                creation_time_100ns: Some(36_028_797_018_964_091 + ordinal as u64),
                token_before_continue: Some(token(pid, candidate)),
                image_before_continue: Some(SevenZipImageObservation {
                    process_image_path: SEVENZIP_TREE_CONTROL_HELPER.into(),
                    sha256: HELPER_HASH.into(),
                    size_bytes: 100,
                    volume_serial_number: 1,
                    file_index: 2,
                }),
                exit_code: Some(31 + role),
                exit_event_sequence: Some([4, 10, 15][role as usize]),
            });
            if role < support_count as u32 {
                let ordinal = processes.len();
                let pid = 10 + ordinal as u32;
                processes.push(SevenZipProcessObservation {
                    ordinal,
                    process_id: pid,
                    create_event_sequence: [2, 6, 9][role as usize],
                    creation_time_100ns: Some(36_028_797_018_964_091 + ordinal as u64),
                    token_before_continue: Some(token(pid, candidate)),
                    image_before_continue: Some(SevenZipImageObservation {
                        process_image_path: SEVENZIP_TREE_CONTROL_CONSOLE.into(),
                        sha256: CONSOLE_HASH.into(),
                        size_bytes: 200,
                        volume_serial_number: 7,
                        file_index: 99,
                    }),
                    exit_code: Some(0),
                    exit_event_sequence: Some([5, 11, 16][role as usize]),
                });
            }
        }
        SevenZipProcessChain {
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
        }
    }
    #[test]
    fn three_helpers_and_interleaved_held_supports_are_verified_in_both_boundaries() {
        for candidate in [false, true] {
            for support_count in 0..=3 {
                let c = chain(support_count, candidate);
                let summary = verify_control(&c, &root(&token(10, candidate)), &console()).unwrap();
                assert_eq!(summary.observed_processes, 3 + support_count as u32);
                assert_eq!(summary.console_support_processes, support_count as u32);
                assert_eq!(summary.helper_processes, 3);
                assert_eq!(summary.paired_exits, summary.observed_processes);
                let encoded = serde_json::to_string(&summary).unwrap();
                assert!(!encoded.contains("S-1-") && !encoded.contains("C:\\"));
                assert_eq!(
                    serde_json::from_str::<SevenZipTreeControlSummary>(&encoded).unwrap(),
                    summary
                );
            }
        }
    }
    #[test]
    fn every_image_identity_token_exit_and_total_is_checked_without_filtering() {
        let mutations: Vec<fn(&mut SevenZipProcessChain)> = vec![
            |c| {
                c.processes[1]
                    .image_before_continue
                    .as_mut()
                    .unwrap()
                    .sha256 = "c".repeat(64)
            },
            |c| {
                c.processes[1]
                    .image_before_continue
                    .as_mut()
                    .unwrap()
                    .size_bytes = 201
            },
            |c| {
                c.processes[1]
                    .image_before_continue
                    .as_mut()
                    .unwrap()
                    .process_image_path = r"C:\other\conhost.exe".into()
            },
            |c| {
                c.processes[1]
                    .image_before_continue
                    .as_mut()
                    .unwrap()
                    .volume_serial_number = 8
            },
            |c| {
                c.processes[1]
                    .image_before_continue
                    .as_mut()
                    .unwrap()
                    .file_index = 100
            },
            |c| {
                c.processes[2]
                    .image_before_continue
                    .as_mut()
                    .unwrap()
                    .sha256 = "c".repeat(64)
            },
            |c| {
                c.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .is_app_container = true
            },
            |c| {
                c.processes[1]
                    .token_before_continue
                    .as_mut()
                    .unwrap()
                    .user_sid = "other".into()
            },
            |c| c.processes[1].exit_code = Some(1),
            |c| c.processes[2].exit_code = Some(0),
            |c| c.processes[0].exit_event_sequence = Some(29),
            |c| c.job_total_processes = Some(3),
            |c| c.job_total_processes = None,
            |c| c.job_active_processes = Some(1),
            |c| c.gaps.push("missing event".into()),
            |c| c.processes[1].token_before_continue = None,
            |c| c.processes[1].exit_event_sequence = None,
            |c| {
                c.processes[1]
                    .image_before_continue
                    .as_mut()
                    .unwrap()
                    .process_image_path = r"C:\Windows\System32\other.exe".into()
            },
            |c| c.processes[1].image_before_continue = c.processes[0].image_before_continue.clone(),
        ];
        for mutate in mutations {
            let mut c = chain(3, false);
            mutate(&mut c);
            assert!(verify_control(&c, &root(&token(10, false)), &console()).is_err());
        }
        let mut c = chain(3, true);
        c.processes[1].token_before_continue = Some(token(c.processes[1].process_id, false));
        assert!(verify_control(&c, &root(&token(10, true)), &console()).is_err());
    }
    #[test]
    fn expected_console_and_helper_bindings_are_external_and_strict() {
        let c = chain(3, false);
        let t = token(10, false);
        let mut r = root(&t);
        r.expected_control_processes = Some(3);
        assert!(verify_control(&c, &r, &console()).is_err());
        r.expected_control_processes = None;
        r.fixed_image_path = r"C:\AIW\SevenZip\App\7z.exe";
        assert!(verify_control(&c, &r, &console()).is_err());
        for binding in [
            SevenZipExpectedConsoleBinding {
                image_sha256: "bad",
                ..console()
            },
            SevenZipExpectedConsoleBinding {
                image_size_bytes: 0,
                ..console()
            },
            SevenZipExpectedConsoleBinding {
                image_size_bytes: MAX_CHAIN_IMAGE_BYTES,
                ..console()
            },
            SevenZipExpectedConsoleBinding {
                file_index: 0,
                ..console()
            },
            SevenZipExpectedConsoleBinding {
                volume_serial_number: 0,
                ..console()
            },
            SevenZipExpectedConsoleBinding {
                image_sha256: HELPER_HASH,
                ..console()
            },
        ] {
            assert!(verify_control(&c, &root(&t), &binding).is_err());
        }
    }
    #[test]
    fn extra_or_missing_helpers_and_support_as_root_are_refused() {
        let t = token(10, false);
        let mut c = chain(3, false);
        c.processes.pop();
        c.job_total_processes = Some(5);
        // Removing one support is permitted, without dropping any helper.
        assert!(verify_control(&c, &root(&t), &console()).is_ok());
        c.processes.pop();
        c.job_total_processes = Some(4);
        assert!(verify_control(&c, &root(&t), &console()).is_err());
        let mut c = chain(3, false);
        c.processes[0].image_before_continue = c.processes[1].image_before_continue.clone();
        assert!(verify_control(&c, &root(&t), &console()).is_err());
        let mut c = chain(3, false);
        let mut extra = c.processes[5].clone();
        extra.ordinal = 6;
        extra.process_id = 99;
        extra.token_before_continue = Some(token(99, false));
        extra.creation_time_100ns = Some(36_028_797_018_964_099);
        extra.create_event_sequence = 7;
        extra.exit_event_sequence = Some(28);
        c.processes.push(extra);
        c.job_total_processes = Some(7);
        assert!(verify_control(&c, &root(&t), &console()).is_err());
    }

    #[test]
    fn complete_trace_with_root_exiting_after_grandchild_creation_is_not_this_control() {
        let mut c = chain(0, false);
        c.processes[0].exit_event_sequence = Some(9);
        let t = token(10, false);
        assert!(c.verify_complete(&root(&t)).is_ok());
        assert!(verify_control(&c, &root(&t), &console()).is_err());
    }

    fn pinned_observation() -> SevenZipConsoleSupportObservation {
        SevenZipConsoleSupportObservation {
            schema_version: SEVENZIP_CONSOLE_SUPPORT_SCHEMA.into(),
            windows: aiw_probe::WindowsVersionObservation {
                major: 10,
                minor: 0,
                build: 26100,
                revision: 9711,
                observer_architecture: "x86_64".into(),
            },
            canonical_path: SEVENZIP_CONSOLE_SUPPORT_PATH.into(),
            identity: aiw_probe::WindowsFileIdentity {
                final_path: SEVENZIP_CONSOLE_SUPPORT_PATH.into(),
                volume_serial_number: "1234567890abcdef".into(),
                file_id: "1234567890abcdef1234567890abcdef".into(),
            },
            sha256: SEVENZIP_CONSOLE_SUPPORT_SHA256.into(),
            size_bytes: SEVENZIP_CONSOLE_SUPPORT_SIZE,
            volume_serial_number: 7,
            file_index: 99,
        }
    }
    #[test]
    fn pinned_console_observation_is_closed_and_has_no_signature_claim() {
        let observed = pinned_observation();
        observed.validate_pinned().unwrap();
        let binding = observed.expected_binding();
        assert_eq!(binding.image_sha256, SEVENZIP_CONSOLE_SUPPORT_SHA256);
        assert_eq!(binding.volume_serial_number, 7);
        let encoded = serde_json::to_value(&observed).unwrap();
        let decoded: SevenZipConsoleSupportObservation =
            serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded, observed);
        let mut extra = encoded;
        extra["signatureVerified"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SevenZipConsoleSupportObservation>(extra).is_err());
    }
    #[test]
    fn pinned_observation_rejects_os_code_path_and_both_identity_drifts() {
        let mutations: Vec<fn(&mut SevenZipConsoleSupportObservation)> = vec![
            |v| v.schema_version = "wrong".into(),
            |v| v.windows.revision += 1,
            |v| v.windows.build += 1,
            |v| v.windows.observer_architecture = "aarch64".into(),
            |v| v.canonical_path = r"C:\other\conhost.exe".into(),
            |v| v.identity.final_path = r"C:\other\conhost.exe".into(),
            |v| v.sha256 = "0".repeat(64),
            |v| v.size_bytes += 1,
            |v| v.volume_serial_number = 0,
            |v| v.file_index = 0,
            |v| v.identity.volume_serial_number = "0".repeat(16),
            |v| v.identity.file_id = "0".repeat(32),
            |v| v.identity.file_id = "A".repeat(32),
            |v| v.identity.file_id = "1".repeat(31),
        ];
        for mutate in mutations {
            let mut observed = pinned_observation();
            mutate(&mut observed);
            assert!(observed.validate_pinned().is_err());
        }
    }
}
