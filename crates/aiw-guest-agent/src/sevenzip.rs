//! Closed secondary role dispatch and receipt-last typed 7-Zip publication.
use super::*;
use aiw_provider_wsb::sevenzip::{
    SEVENZIP_EVENT, SevenZipDriverError, SevenZipRequest, SevenZipResult,
};

fn role_allowed(path: Option<&Path>, args: &[std::ffi::OsString]) -> bool {
    path.and_then(Path::to_str).is_some_and(|path| {
        path.strip_prefix(r"\\?\")
            .unwrap_or(path)
            .eq_ignore_ascii_case(r"C:\AIW\SevenZip\sevenzip_assessment.exe")
    }) && args.len() == 1
        && matches!(
            args[0].to_str(),
            Some("--driver-control" | "--deadline-control" | "--boundary-control" | "--workflow")
        )
}
pub(super) fn fixed_role() -> Option<ExitCode> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let path = std::env::current_exe().ok();
    let secondary_path = path
        .as_deref()
        .and_then(Path::file_name)
        .is_some_and(|name| {
            name.to_string_lossy()
                .eq_ignore_ascii_case("sevenzip_assessment.exe")
        });
    let role_args = args.iter().any(|arg| {
        matches!(
            arg.to_str(),
            Some("--driver-control" | "--deadline-control" | "--boundary-control" | "--workflow")
        )
    });
    if !secondary_path && !role_args {
        return None;
    }
    if !role_allowed(path.as_deref(), &args) {
        return Some(ExitCode::FAILURE);
    }
    #[cfg(windows)]
    return Some(match aiw_windows_platform::run_fixed_sevenzip_role() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("AIW_SEVENZIP_FIXED_ROLE_FAILED: {error}");
            ExitCode::FAILURE
        }
    });
    #[cfg(not(windows))]
    Some(ExitCode::FAILURE)
}

pub(super) fn execute(request: &SevenZipRequest) -> Result<()> {
    request.validate().map_err(anyhow::Error::msg)?;
    request.profile.validate().map_err(anyhow::Error::msg)?;
    let root = Path::new(PAIRED_OUTPUT_ROOT);
    ensure_output_root(root)?;
    #[cfg(windows)]
    let observed = aiw_windows_platform::execute_fixed_sevenzip(request);
    #[cfg(not(windows))]
    let observed: std::result::Result<SevenZipResult, String> =
        Err("7-Zip requires native Windows guest".into());
    let result = match observed {
        Ok(value) => value,
        Err(error) => {
            eprintln!(
                "AIW_SEVENZIP_DRIVER_INCOMPLETE: {}",
                bounded_diagnostic(&error)
            );
            let mut result = SevenZipResult::for_request(request).map_err(anyhow::Error::msg)?;
            result.driver_error = Some(SevenZipDriverError::DriverIncomplete);
            result
        }
    };
    publish(request, root, &result)
}

fn publish(request: &SevenZipRequest, root: &Path, result: &SevenZipResult) -> Result<()> {
    result.validate(request).map_err(anyhow::Error::msg)?;
    let status = if result.driver_error.is_some() {
        CompletionStatus::Failed
    } else {
        CompletionStatus::Succeeded
    };
    let payload = serde_json::to_value(result)?;
    let mut evidence = EvidenceLog::new();
    evidence.append(EvidenceEvent {
        observed_utc: "guest-agent-time-not-trusted".into(),
        kind: SEVENZIP_EVENT.into(),
        source: "aiw-guest-agent".into(),
        payload: payload.clone(),
    })?;
    let bytes = evidence_bytes(&evidence)?;
    let root_hash = evidence.manifest()?.root_hash;
    aiw_provider_wsb::sevenzip::verify_sevenzip_evidence(&bytes, &root_hash, request, result)
        .map_err(anyhow::Error::msg)?;
    write_new_json(&root.join("scenario-result.json"), &payload)?;
    write_new_bytes(&root.join("evidence.jsonl"), &bytes)?;
    let receipt = WindowsSandboxCompletionReceipt {
        schema_version: WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION.into(),
        run_id: request.run_id.clone(),
        sandbox_id: request.sandbox_id.clone(),
        config_sha256: request.config_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        agent_sha256: request.agent_sha256.clone(),
        status,
        exit_code: if status == CompletionStatus::Succeeded {
            0
        } else {
            1
        },
        evidence_root_hash: root_hash,
        artifacts: vec![
            completion_artifact(
                &root.join("scenario-result.json"),
                "scenario-result.json",
                ArtifactRole::ScenarioResults,
                "application/json",
            )?,
            completion_artifact(
                &root.join("evidence.jsonl"),
                "evidence.jsonl",
                ArtifactRole::EvidenceLog,
                "application/x-ndjson",
            )?,
        ],
    };
    write_receipt_last(&root.join("completion.json"), &receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> SevenZipRequest {
        use aiw_probe::sevenzip::*;
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
            expected_windows: aiw_probe::paired_controls::parse_guest_windows("10.0.26100.1")
                .unwrap(),
            expected_host_windows: aiw_probe::paired_controls::parse_guest_windows("10.0.26300.1")
                .unwrap(),
            policy: SevenZipPolicy::ClassicAppContainerNoCapabilitiesReadInputWriteOutput,
        };
        SevenZipRequest::new(
            "sevenzip-publication",
            "61e939ef-1e05-4b59-9593-3df457b10428",
            &"b".repeat(64),
            &"a".repeat(64),
            profile,
        )
        .unwrap()
    }
    fn root(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "aiw-sevenzip-publish-{}-{label}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        root
    }
    fn remove(root: PathBuf) {
        for leaf in ["scenario-result.json", "evidence.jsonl", "completion.json"] {
            let path = root.join(leaf);
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn sevenzip_roles_reject_host_tools_unknown_and_extra_arguments() {
        let args = [std::ffi::OsString::from("--workflow")];
        assert!(role_allowed(
            Some(Path::new(r"C:\AIW\SevenZip\sevenzip_assessment.exe")),
            &args
        ));
        for path in [
            r"C:\AIW\Tools\aiw-guest-agent.exe",
            r"C:\AIW\Tools\sevenzip_assessment.exe",
            r"C:\host\sevenzip_assessment.exe",
        ] {
            assert!(!role_allowed(Some(Path::new(path)), &args));
        }
        assert!(!role_allowed(None, &args));
        assert!(!role_allowed(
            Some(Path::new(r"C:\AIW\SevenZip\sevenzip_assessment.exe")),
            &["--workflow".into(), "extra".into()]
        ));
    }
    #[test]
    fn sevenzip_partial_publication_is_bound_and_receipt_last_without_execution() {
        let request = request();
        let mut result = SevenZipResult::for_request(&request).unwrap();
        result.driver_error = Some(SevenZipDriverError::DriverIncomplete);
        let output = root("partial");
        publish(&request, &output, &result).unwrap();
        let receipt: WindowsSandboxCompletionReceipt =
            serde_json::from_slice(&fs::read(output.join("completion.json")).unwrap()).unwrap();
        assert_eq!(receipt.status, CompletionStatus::Failed);
        assert_eq!(receipt.run_id, request.run_id);
        assert_eq!(receipt.request_sha256, request.request_sha256);
        assert_eq!(receipt.artifacts.len(), 2);
        let bytes = fs::read(output.join("evidence.jsonl")).unwrap();
        aiw_provider_wsb::sevenzip::verify_sevenzip_evidence(
            &bytes,
            &receipt.evidence_root_hash,
            &request,
            &result,
        )
        .unwrap();
        assert!(publish(&request, &output, &result).is_err());
        remove(output);
        let output = root("collision");
        write_new_bytes(&output.join("evidence.jsonl"), b"original").unwrap();
        let original = fs::read(output.join("evidence.jsonl")).unwrap();
        assert!(publish(&request, &output, &result).is_err());
        assert!(!output.join("completion.json").exists());
        assert_eq!(fs::read(output.join("evidence.jsonl")).unwrap(), original);
        remove(output);
    }
    #[test]
    fn sevenzip_request_parser_is_closed_and_result_cannot_change_binding() {
        let request = request();
        let output = root("request");
        let path = output.join("request.json");
        write_new_json(&path, &request).unwrap();
        assert!(matches!(
            read_request(&path).unwrap(),
            GuestRequest::SevenZip(_)
        ));
        let mut result = SevenZipResult::for_request(&request).unwrap();
        result.request_sha256 = "c".repeat(64);
        assert!(publish(&request, &output, &result).is_err());
        assert!(!output.join("completion.json").exists());
        fs::remove_file(path).unwrap();
        remove(output);
    }
}
