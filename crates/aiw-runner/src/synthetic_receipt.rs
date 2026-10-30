//! Synthetic receipt publication reused by fixed offline rehearsals.
use super::*;
use aiw_provider_wsb::{PairedControlResult, PairedControlsRequest};
pub(crate) fn write_pair_completion(start: &WsbGoldenProbeStart, mutation: usize) {
    let request: PairedControlsRequest = read_bounded_json(
        &Path::new(&start.workspace.tools.final_path).join("request.json"),
        64 * 1024,
    )
    .unwrap();
    let mut result: PairedControlResult = serde_json::from_str(include_str!(
        "../../../fixtures/paired-controls/synthetic-result.json"
    ))
    .unwrap();
    result.run_id = request.run_id.clone();
    result.sandbox_id = request.sandbox_id.clone();
    result.request_sha256 = request.request_sha256.clone();
    result.profile_sha256 = request.profile.hash().unwrap();
    result.windows = request.profile.expected_windows.clone();
    match mutation {
        1 => {
            result.baseline.file.outcome = aiw_provider_wsb::ControlAccess::NotFound;
            result.baseline.file.native_code = Some(2);
            result.baseline.file.sha256 = None;
            result.baseline.file.size_bytes = None;
        }
        2 => {
            result.candidate.registry.outcome = aiw_provider_wsb::ControlAccess::NotFound;
            result.candidate.registry.native_code = Some(2);
        }
        3 => result.driver_complete = false,
        4 => result.candidate.file.native_code = Some(2),
        _ => {}
    }
    let output = Path::new(&start.workspace.output.final_path);
    let payload = if mutation == 7 || mutation == 8 {
        let mut failure =
            aiw_provider_wsb::paired_controls::PairedControlDriverFailure::for_request(&request)
                .unwrap();
        if mutation == 8 {
            failure.request_sha256 = "f".repeat(64);
        }
        serde_json::to_value(failure).unwrap()
    } else {
        serde_json::to_value(&result).unwrap()
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    publish_test_file(&output.join("scenario-result.json"), &bytes);
    let mut evidence = aiw_evidence::EvidenceLog::new();
    evidence
        .append(aiw_evidence::EvidenceEvent {
            observed_utc: "synthetic-untrusted-time".into(),
            kind: if mutation == 7 || mutation == 8 {
                "pairedControlsDriverFailure"
            } else {
                "pairedControls"
            }
            .into(),
            source: "aiw-guest-agent".into(),
            payload,
        })
        .unwrap();
    if mutation == 5 || mutation == 6 {
        evidence
            .append(aiw_evidence::EvidenceEvent {
                observed_utc: "synthetic-untrusted-time".into(),
                kind: "pairedControls".into(),
                source: "aiw-guest-agent".into(),
                payload: serde_json::to_value(&result).unwrap(),
            })
            .unwrap();
    }
    let mut log = vec![];
    let mut records = evidence.records().iter().collect::<Vec<_>>();
    if mutation == 6 {
        records.reverse();
    }
    for record in records {
        serde_json::to_writer(&mut log, record).unwrap();
        log.push(b'\n');
    }
    publish_test_file(&output.join("evidence.jsonl"), &log);
    let artifact = |path: &str, role: aiw_evidence::ArtifactRole, media: &str, bytes: &[u8]| {
        aiw_provider_wsb::CompletionArtifact {
            path: path.into(),
            role,
            media_type: media.into(),
            size_bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    };
    let receipt = aiw_provider_wsb::WindowsSandboxCompletionReceipt {
        schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION.into(),
        run_id: request.run_id,
        sandbox_id: request.sandbox_id,
        config_sha256: request.config_sha256,
        request_sha256: request.request_sha256,
        agent_sha256: request.agent_sha256,
        status: if mutation == 7 || mutation == 8 {
            aiw_provider_wsb::CompletionStatus::Failed
        } else {
            aiw_provider_wsb::CompletionStatus::Succeeded
        },
        exit_code: if mutation == 7 || mutation == 8 { 1 } else { 0 },
        evidence_root_hash: evidence.manifest().unwrap().root_hash,
        artifacts: vec![
            artifact(
                "scenario-result.json",
                aiw_evidence::ArtifactRole::ScenarioResults,
                "application/json",
                &bytes,
            ),
            artifact(
                "evidence.jsonl",
                aiw_evidence::ArtifactRole::EvidenceLog,
                "application/x-ndjson",
                &log,
            ),
        ],
    };
    publish_test_file(
        &output.join("completion.json"),
        &serde_json::to_vec(&receipt).unwrap(),
    );
}
pub(crate) fn publish_test_file(path: &Path, bytes: &[u8]) {
    let name = path.file_name().unwrap().to_string_lossy();
    let pending = path.with_file_name(format!("{name}.pending"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::hard_link(&pending, path).unwrap();
    fs::remove_file(pending).unwrap();
}
