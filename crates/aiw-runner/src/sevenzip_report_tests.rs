//! Inert retained-output fixtures. No installer, guest, or provider is executed.
use super::*;
use crate::sevenzip_report::{SevenZipExecutionProvenance, SevenZipReportEvidenceStatus};
use crate::sevenzip_report_output::read_sevenzip_output;
use aiw_evidence::{ArtifactRole, EvidenceEvent, EvidenceLog};
use aiw_probe::sevenzip::*;
use aiw_provider_wsb::sevenzip::*;
use aiw_provider_wsb::{CompletionArtifact, CompletionStatus, WindowsSandboxCompletionReceipt};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

const USER: &str = "S-1-5-21-11-22-33-1001";
const PACKAGE: &str = "S-1-15-2-1-2-3-4-5-6-7";
const LEAVES: [&str; 3] = ["scenario-result.json", "evidence.jsonl", "completion.json"];

struct Fixture {
    root: PathBuf,
    request: SevenZipRequest,
    result: SevenZipResult,
}
impl Fixture {
    fn new(partial: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "aiw-sz-report-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let profile = aiw_probe::SevenZipProfile {
            revision: SEVENZIP_PROFILE_REVISION.into(),
            source_sha256: seven_zip_source_sha256(),
            installer_sha256: SEVENZIP_INSTALLER_SHA256.into(),
            installer_size_bytes: SEVENZIP_INSTALLER_SIZE_BYTES,
            agent_sha256: "a".repeat(64),
            agent_size_bytes: 100,
            launcher_sha256: "a".repeat(64),
            launcher_size_bytes: 100,
            origin: aiw_probe::ControlEvidenceOrigin::SyntheticRehearsal,
            expected_windows: aiw_probe::paired_controls::parse_guest_windows("10.0.26100.2")
                .unwrap(),
            expected_host_windows: aiw_probe::paired_controls::parse_guest_windows("10.0.26300.1")
                .unwrap(),
            policy: SevenZipPolicy::ClassicAppContainerNoCapabilitiesReadInputWriteOutput,
        };
        let request = SevenZipRequest::new(
            "inert-sevenzip-report",
            "11111111-2222-3333-4444-555555555555",
            &"f".repeat(64),
            &"a".repeat(64),
            profile,
        )
        .unwrap();
        let mut result = SevenZipResult::for_request(&request).unwrap();
        result.windows = Some(request.profile.expected_windows.clone());
        result.launcher_token = process(1, false).held_token;
        let image = SevenZipFileDigest::for_bytes(b"inert image bytes, never executed");
        let dll = SevenZipFileDigest::for_bytes(b"inert DLL bytes, never loaded");
        result.installation = Some(SevenZipInstallation {
            exit_code: Some(0),
            timed_out: false,
            job_empty: Some(true),
            files_after: Some(BTreeMap::from([
                ("7z.exe".into(), image.clone()),
                ("7z.dll".into(), dll.clone()),
            ])),
        });
        result.code_binding = Some(SevenZipCodeBinding {
            image_before: image.clone(),
            image_after: image,
            dll_before: dll.clone(),
            dll_after: dll,
        });
        let mut capture = process(2, false);
        capture.exit_code = Some(23);
        let bytes = SevenZipFileDigest::for_bytes(SEVENZIP_DRIVER_BYTES);
        capture.stdout_sha256 = Some(bytes.sha256);
        capture.stdout_size_bytes = Some(bytes.size_bytes);
        let mut deadline = process(3, false);
        deadline.exit_code = None;
        deadline.timed_out = true;
        result.driver_controls = Some(SevenZipDriverControls { capture, deadline });
        result.baseline = Some(variant(10, false));
        if partial {
            // A genuine measured prefix, with no candidate/profile/denial invented.
            result.baseline.as_mut().unwrap().test = None;
            result.baseline.as_mut().unwrap().extract = None;
            result.baseline.as_mut().unwrap().input_after = None;
            result.baseline.as_mut().unwrap().extracted = None;
            result.baseline.as_mut().unwrap().archive = None;
            result.driver_error = Some(SevenZipDriverError::DriverIncomplete);
        } else {
            result.package_sid = Some(PACKAGE.into());
            result.candidate = Some(variant(20, true));
            let denied = Some(SevenZipAccessObservation {
                native_code: 5,
                read: None,
            });
            result.canaries = Some(SevenZipCanaries {
                baseline_process: Some(process(4, false)),
                candidate_process: Some(process(5, true)),
                baseline_outside_read: Some(SevenZipAccessObservation {
                    native_code: 0,
                    read: Some(SevenZipFileDigest::for_bytes(SEVENZIP_CANARY_BYTES)),
                }),
                candidate_outside_read: denied.clone(),
                candidate_input_write: denied.clone(),
                candidate_input_file_delete: denied.clone(),
                candidate_input_directory_delete: denied,
            });
            result.profile_deleted = Some(true);
        }
        result.validate(&request).unwrap();
        let fixture = Self {
            root,
            request,
            result,
        };
        fixture.publish(if partial {
            CompletionStatus::Failed
        } else {
            CompletionStatus::Succeeded
        });
        fixture
    }
    fn publish(&self, status: CompletionStatus) {
        let mut log = EvidenceLog::new();
        log.append(EvidenceEvent {
            observed_utc: "synthetic-time".into(),
            kind: SEVENZIP_EVENT.into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::to_value(&self.result).unwrap(),
        })
        .unwrap();
        let mut bytes = vec![];
        for record in log.records() {
            bytes.extend(serde_json::to_vec(record).unwrap());
            bytes.push(b'\n');
        }
        fs::write(
            self.root.join("scenario-result.json"),
            serde_json::to_vec(&self.result).unwrap(),
        )
        .unwrap();
        fs::write(self.root.join("evidence.jsonl"), &bytes).unwrap();
        let receipt = WindowsSandboxCompletionReceipt {
            schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION
                .into(),
            run_id: self.request.run_id.clone(),
            sandbox_id: self.request.sandbox_id.clone(),
            config_sha256: self.request.config_sha256.clone(),
            request_sha256: self.request.request_sha256.clone(),
            agent_sha256: self.request.agent_sha256.clone(),
            status,
            exit_code: if status == CompletionStatus::Succeeded {
                0
            } else {
                1
            },
            evidence_root_hash: log.manifest().unwrap().root_hash,
            artifacts: [
                artifact(
                    &self.root,
                    "scenario-result.json",
                    ArtifactRole::ScenarioResults,
                    "application/json",
                ),
                artifact(
                    &self.root,
                    "evidence.jsonl",
                    ArtifactRole::EvidenceLog,
                    "application/x-ndjson",
                ),
            ]
            .into(),
        };
        fs::write(
            self.root.join("completion.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
    }
    fn report(
        &self,
        cleanup: Option<bool>,
        provenance: SevenZipExecutionProvenance,
    ) -> SevenZipRunReport {
        read_sevenzip_output(
            &self.root,
            &self.request,
            cleanup,
            Some(RunOutcome::InsufficientEvidence),
            provenance,
            &"e".repeat(64),
        )
        .unwrap()
    }
    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (
                    path.file_name().unwrap().to_str().unwrap().into(),
                    fs::read(path).unwrap(),
                )
            })
            .collect()
    }
    fn receipt(&self) -> WindowsSandboxCompletionReceipt {
        serde_json::from_slice(&fs::read(self.root.join("completion.json")).unwrap()).unwrap()
    }
    fn replace_receipt(&self, receipt: &WindowsSandboxCompletionReceipt) {
        fs::write(
            self.root.join("completion.json"),
            serde_json::to_vec(receipt).unwrap(),
        )
        .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only explicitly named files in this exclusively created shallow fixture.
        for leaf in LEAVES {
            let _ = fs::remove_file(self.root.join(leaf));
        }
        let _ = fs::remove_dir(&self.root);
    }
}
fn artifact(root: &Path, leaf: &str, role: ArtifactRole, media_type: &str) -> CompletionArtifact {
    let file = SevenZipFileDigest::for_bytes(&fs::read(root.join(leaf)).unwrap());
    CompletionArtifact {
        path: leaf.into(),
        role,
        media_type: media_type.into(),
        sha256: file.sha256,
        size_bytes: file.size_bytes,
    }
}
fn process(pid: u32, candidate: bool) -> SevenZipInvocation {
    let rid = if candidate { 4096 } else { 8192 };
    let mut token = serde_json::json!({"schemaVersion":"aiw.dev/token-evidence/v0alpha1","processId":pid,"tokenType":"primary",
        "isAppContainer":candidate,"userSid":USER,"integrity":{"sid":format!("S-1-16-{rid}"),"rid":rid,"level":if candidate {"low"} else {"medium"}},
        "elevationType":"default","isElevated":false,"capabilities":[],"restrictedSidCount":0});
    if candidate {
        token["appContainerSid"] = serde_json::json!(PACKAGE);
    }
    let output = SevenZipFileDigest::for_bytes(b"inert capture");
    SevenZipInvocation {
        process_id: pid,
        exit_code: Some(0),
        timed_out: false,
        held_token: Some(serde_json::from_value(token).unwrap()),
        job_empty: Some(true),
        stdout_sha256: Some(output.sha256),
        stdout_size_bytes: Some(output.size_bytes),
    }
}
fn variant(first: u32, candidate: bool) -> SevenZipVariant {
    SevenZipVariant {
        input_before: Some(sevenzip_fixture_inventory()),
        create: Some(process(first, candidate)),
        test: Some(process(first + 1, candidate)),
        extract: Some(process(first + 2, candidate)),
        input_after: Some(sevenzip_fixture_inventory()),
        extracted: Some(sevenzip_fixture_inventory()),
        archive: Some(SevenZipFileDigest {
            sha256: if candidate {
                "c".repeat(64)
            } else {
                "b".repeat(64)
            },
            size_bytes: if candidate { 579 } else { 578 },
        }),
    }
}

#[test]
fn sevenzip_retained_failed_receipt_keeps_measured_prefix_and_missing_candidate_unknown() {
    let fixture = Fixture::new(true);
    let before = fixture.snapshot();
    let report = fixture.report(Some(true), SevenZipExecutionProvenance::ApprovedDispatch);
    assert_eq!(
        report.evidence_status,
        SevenZipReportEvidenceStatus::DriverIncomplete
    );
    assert_eq!(report.observations.as_ref(), Some(&fixture.result));
    let comparison = report.comparison.unwrap();
    assert_eq!(
        comparison.reason,
        SevenZipComparisonReason::DriverIncomplete
    );
    assert!(!comparison.eligible && !comparison.production_acceptance);
    assert_eq!(
        comparison.functions[0].baseline,
        SevenZipFunctionStatus::Passed
    );
    assert!(
        comparison
            .functions
            .iter()
            .all(|row| row.candidate == SevenZipFunctionStatus::Unmeasured)
    );
    assert_eq!(before, fixture.snapshot());
}

#[test]
fn sevenzip_retained_reader_preserves_bytes_and_requires_dispatch_and_known_cleanup() {
    let fixture = Fixture::new(false);
    let before = fixture.snapshot();
    for provenance in [
        SevenZipExecutionProvenance::ApprovalUnavailable,
        SevenZipExecutionProvenance::ApprovedWithoutDispatch,
    ] {
        let report = fixture.report(Some(true), provenance);
        assert_eq!(report.evidence_status, SevenZipReportEvidenceStatus::Absent);
        assert!(report.observations.is_none() && report.comparison.is_none());
    }
    for cleanup in [None, Some(false)] {
        let report = fixture.report(cleanup, SevenZipExecutionProvenance::ApprovedDispatch);
        let comparison = report.comparison.unwrap();
        assert_eq!(comparison.reason, SevenZipComparisonReason::CleanupUnknown);
        assert!(!comparison.eligible && !comparison.selected_controls_verified);
    }
    let first = fixture.report(Some(true), SevenZipExecutionProvenance::ApprovedDispatch);
    let second = fixture.report(Some(true), SevenZipExecutionProvenance::ApprovedDispatch);
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap()
    );
    assert!(first.comparison.unwrap().eligible);
    assert!(first.function_deltas.is_some());
    // This test calls only the output reader, which has no execution/lease input.
    // Unchanged whole-directory bytes also exclude request/approval/run writes.
    assert_eq!(before, fixture.snapshot());
}

#[test]
fn sevenzip_retained_rejects_status_parity_root_and_outer_hash_consistent_payload_tampering() {
    let fixture = Fixture::new(true);
    let mut receipt = fixture.receipt();
    receipt.status = CompletionStatus::Succeeded;
    receipt.exit_code = 0;
    fixture.replace_receipt(&receipt);
    assert_eq!(
        fixture
            .report(Some(true), SevenZipExecutionProvenance::ApprovedDispatch)
            .evidence_status,
        SevenZipReportEvidenceStatus::Rejected
    );
    let fixture = Fixture::new(false);
    let mut receipt = fixture.receipt();
    receipt.evidence_root_hash = "0".repeat(64);
    fixture.replace_receipt(&receipt);
    assert_eq!(
        fixture
            .report(Some(true), SevenZipExecutionProvenance::ApprovedDispatch)
            .evidence_status,
        SevenZipReportEvidenceStatus::Rejected
    );
    let fixture = Fixture::new(false);
    let mut changed = fixture.result.clone();
    changed.driver_error = Some(SevenZipDriverError::DriverIncomplete);
    fs::write(
        fixture.root.join("scenario-result.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    let mut receipt = fixture.receipt();
    receipt.artifacts[0] = artifact(
        &fixture.root,
        "scenario-result.json",
        ArtifactRole::ScenarioResults,
        "application/json",
    );
    fixture.replace_receipt(&receipt);
    let report = fixture.report(Some(true), SevenZipExecutionProvenance::ApprovedDispatch);
    assert_eq!(
        report.evidence_status,
        SevenZipReportEvidenceStatus::Rejected
    );
    assert!(report.observations.is_none() && report.comparison.is_none());
}

#[cfg(windows)]
#[test]
fn sevenzip_held_output_refuses_writers_and_renames_through_verification() {
    use crate::sevenzip_report_output::hold_sevenzip_output;
    let fixture = Fixture::new(false);
    let before = fixture.snapshot();
    let held = hold_sevenzip_output(&fixture.root).unwrap();
    assert_eq!(held.len(), 3);
    for leaf in LEAVES {
        let path = fixture.root.join(leaf);
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::rename(&path, fixture.root.join("unexpected-rename.json")).is_err());
    }
    let report = fixture.report(Some(true), SevenZipExecutionProvenance::ApprovedDispatch);
    assert!(report.comparison.unwrap().eligible);
    for file in &held {
        file.revalidate().unwrap();
    }
    assert_eq!(before, fixture.snapshot());
    drop(held);
}
