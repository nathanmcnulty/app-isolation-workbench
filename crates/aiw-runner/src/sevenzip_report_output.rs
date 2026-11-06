//! Bounded output verification shared by the retained reader and focused tests.
use super::*;
use crate::sevenzip_report::{
    SevenZipExecutionProvenance, SevenZipReportEvidenceStatus, SevenZipRunReport,
};
use aiw_provider_wsb::sevenzip::{SevenZipRequest, SevenZipResult, verify_sevenzip_evidence};

#[cfg(windows)]
pub(super) fn hold_sevenzip_output(
    output: &Path,
) -> Result<Vec<aiw_windows_platform::HeldApplicationFile>, RunnerError> {
    let mut held = vec![];
    for leaf in ["completion.json", "scenario-result.json", "evidence.jsonl"] {
        let path = output.join(leaf);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(RunnerError::Drift),
            Ok(_) => held.push(
                aiw_windows_platform::HeldApplicationFile::open_bounded(
                    &path,
                    aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64,
                )
                .map_err(|_| RunnerError::Drift)?,
            ),
        }
    }
    Ok(held)
}

pub(super) fn read_sevenzip_output(
    output: &Path,
    request: &SevenZipRequest,
    cleanup: Option<bool>,
    outcome: Option<RunOutcome>,
    provenance: SevenZipExecutionProvenance,
    revision: &str,
) -> Result<SevenZipRunReport, RunnerError> {
    request.validate().map_err(RunnerError::Receipt)?;
    let mut report = SevenZipRunReport {
        schema_version: "aiw.dev/sevenzip-run-report/v0alpha1".into(),
        run_id: request.run_id.clone(), request_sha256: request.request_sha256.clone(),
        project_revision_sha256: revision.into(), profile: request.profile.clone(),
        recorded_outcome: outcome, recorded_cleanup_verified: cleanup,
        evidence_status: SevenZipReportEvidenceStatus::Absent,
        receipt_sha256: None, evidence_root_hash: None, observations: None, comparison: None, function_deltas: None,
        evidence_gaps: vec!["GUI, shell, uninstall, registry/system changes, network/IPC/UI, all descendants and endpoint equivalence remain unmeasured".into(),
            "Cleanup is historical; reading never checks current worker state".into()],
    };
    if !matches!(provenance, SevenZipExecutionProvenance::ApprovedDispatch) {
        report.evidence_gaps.push(
            "Committed approval and dispatch are required to accept execution observations".into(),
        );
        return Ok(report);
    }
    let mut expectation = completion_expectation(
        &request.run_id,
        &request.sandbox_id,
        &request.config_sha256,
        &request.agent_sha256,
        &request.request_sha256,
    );
    expectation.artifacts[0].path = "scenario-result.json".into();
    expectation.artifacts[0].role = aiw_evidence::ArtifactRole::ScenarioResults;
    expectation.artifacts[0].maximum_bytes = 512 * 1024;
    expectation.artifacts[1].maximum_bytes =
        aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64;
    #[cfg(windows)]
    let held_output = hold_sevenzip_output(output)?;
    #[cfg(windows)]
    if held_output.len() != 3 {
        report.evidence_status = if held_output.is_empty() {
            SevenZipReportEvidenceStatus::Absent
        } else {
            SevenZipReportEvidenceStatus::Rejected
        };
        return Ok(report);
    }
    let verified = match verify_completion_receipt(output, &expectation) {
        Ok(value) => value,
        Err(_) => {
            if !matches!(fs::symlink_metadata(output.join("completion.json")), Err(e) if e.kind()==std::io::ErrorKind::NotFound)
            {
                report.evidence_status = SevenZipReportEvidenceStatus::Rejected;
            }
            return Ok(report);
        }
    };
    let observation = (|| {
        let observed: SevenZipResult =
            read_bounded_json(&output.join("scenario-result.json"), 512 * 1024)?;
        let bytes = read_bounded_bytes(
            &output.join("evidence.jsonl"),
            aiw_provider_wsb::MAX_APPLICATION_EVIDENCE_BYTES as u64,
        )?;
        verify_sevenzip_evidence(&bytes, &verified.evidence_root_hash, request, &observed)
            .map_err(RunnerError::Receipt)?;
        // Failed and interrupted attempts retain their facts but never gain eligibility.
        let eligibility_cleanup = if outcome == Some(RunOutcome::InsufficientEvidence) {
            cleanup
        } else {
            None
        };
        let comparison = observed
            .compare(request, eligibility_cleanup)
            .map_err(RunnerError::Receipt)?;
        if verified.successful != observed.driver_error.is_none() {
            return Err(RunnerError::Receipt(
                "7-Zip completion status disagrees with driver facts".into(),
            ));
        }
        Ok::<_, RunnerError>((observed, comparison))
    })();
    match observation {
        Ok((observed, comparison)) => {
            // Reuse the shared scenario delta primitive. Backend differences are
            // deliberate; neither deltas nor function success prove containment.
            let summary = |candidate: bool| aiw_core::RunSummary {
                schema_version: "aiw.dev/run-summary/v0alpha1".into(),
                run_id: format!(
                    "{}-{}",
                    request.run_id,
                    if candidate { "candidate" } else { "baseline" }
                ),
                project_hash: revision.into(),
                candidate_id: if candidate {
                    "appContainer"
                } else {
                    "standardUser"
                }
                .into(),
                os_build: format!("{}", request.profile.expected_windows.build),
                effective_backend: if candidate {
                    "classicAppContainerZeroCapabilities"
                } else {
                    "standardUser"
                }
                .into(),
                scenarios: comparison
                    .functions
                    .iter()
                    .map(|row| {
                        use aiw_provider_wsb::sevenzip::SevenZipFunctionStatus as S;
                        let status = match if candidate {
                            row.candidate
                        } else {
                            row.baseline
                        } {
                            S::Passed => aiw_core::ScenarioStatus::Passed,
                            S::Failed => aiw_core::ScenarioStatus::Failed,
                            S::NotReached => aiw_core::ScenarioStatus::Skipped,
                            S::Unmeasured => aiw_core::ScenarioStatus::Incomplete,
                        };
                        (
                            format!("{:?}", row.function),
                            aiw_core::ScenarioResult {
                                status,
                                evidence_ids: vec![verified.evidence_root_hash.clone()],
                                detail: None,
                            },
                        )
                    })
                    .collect(),
                assertions: Default::default(),
                evidence_root_hash: verified.evidence_root_hash.clone(),
            };
            report.function_deltas = Some(aiw_core::compare_runs(&summary(false), &summary(true)));
            report.evidence_status = if observed.driver_error.is_some() {
                SevenZipReportEvidenceStatus::DriverIncomplete
            } else {
                SevenZipReportEvidenceStatus::Verified
            };
            report.observations = Some(observed);
            report.comparison = Some(comparison);
            report.receipt_sha256 = Some(verified.receipt_sha256);
            report.evidence_root_hash = Some(verified.evidence_root_hash);
        }
        Err(_) => report.evidence_status = SevenZipReportEvidenceStatus::Rejected,
    }
    #[cfg(windows)]
    for file in held_output {
        file.revalidate().map_err(|_| RunnerError::Drift)?;
    }
    Ok(report)
}
