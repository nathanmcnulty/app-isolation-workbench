//! Original-host reader for production VM MSIX runs. No provider connection.
use crate::ApplicationReportFunctions;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmMsixAssessmentReport {
    pub schema_version: String,
    pub run_id: String,
    pub plan_sha256: String,
    pub request_sha256: String,
    pub nonce: String,
    pub workflow_verified: bool,
    pub cleanup_complete: bool,
    pub functions: ApplicationReportFunctions,
    pub isolation: String,
    pub broader_compatibility: String,
    pub summary: String,
}

/// Pure final recovery gate shared by execution, resumed cleanup and reporting.
/// Validate before publishing any terminal cleanup-complete result.
pub fn verify_vm_msix_recovery(
    worker: &aiw_probe::VmMsixWorkerProfile,
    nonce: &str,
    proofs: &Value,
) -> Result<(), String> {
    worker.validate()?;
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Recovery nonce invalid".into());
    }
    if proofs["nonce"] != nonce {
        return Err("Recovery nonce differs".into());
    }
    for operation in ["restore", "connect", "release"] {
        let proof = &proofs[operation];
        let completed = operation == "release" && proof["operation"] == "completed";
        if proof["schemaVersion"] != "aiw.dev/vm-msix-hypervisor/v0alpha1"
            || (!completed && proof["operation"] != operation)
            || proof["vmId"] != 107
            || proof["workerUuid"] != worker.worker_uuid
            || proof["nonce"] != nonce
            || proof["checkpoint"] != worker.checkpoint
            || proof["checkpointConfigSha256"] != worker.checkpoint_config_sha256
            || proof["providerSha256"] != worker.provider_sha256
            || proof["running"] != true
        {
            return Err("Final external cold recovery proof differs".into());
        }
        let phase = if operation == "restore" {
            "restored"
        } else if operation == "connect" || completed {
            "online-clean"
        } else {
            "none"
        };
        if proof["phase"] != phase || proof["leasePresent"] != (operation != "release") {
            return Err("Final lease phase differs".into());
        }
    }
    let clean = &proofs["clean"];
    if clean["clean"] != true
        || clean["workerUuid"]
            .as_str()
            .is_none_or(|v| !v.eq_ignore_ascii_case(&worker.worker_uuid))
        || clean["trialArtifactsAbsent"] != true
        || clean["automaticSignInDisabled"] != true
    {
        return Err("Restored clean readback incomplete".into());
    }
    Ok(())
}

#[cfg(windows)]
pub fn report_vm_msix_run(
    workspace: &Path,
    run_id: &str,
) -> Result<VmMsixAssessmentReport, String> {
    use aiw_orchestrator::{RunLayout, RunOutcome, open_vm_msix_preparation};
    use aiw_windows_platform::{HeldApplicationFile, HeldPortableDirectory};
    use sha2::{Digest, Sha256};
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::Read,
    };
    let error = |e: &dyn std::fmt::Display| e.to_string();
    let layout = RunLayout::new(workspace, run_id).map_err(|e| error(&e))?;
    let plan = layout.read_plan().map_err(|e| error(&e))?;
    let held = open_vm_msix_preparation(&plan).map_err(|e| error(&e))?;
    let approval = layout.read_approval().map_err(|e| error(&e))?;
    let result = layout.read_result().map_err(|e| error(&e))?;
    let plan_hash = plan.hash().map_err(|e| error(&e))?;
    if approval.plan_hash != plan_hash || !result.cleanup_complete {
        return Err("Approved terminal run and cleanup required".into());
    }
    let read = |name: &str| -> Result<Vec<u8>, String> {
        let file = held
            .workspace
            .reopen_output_file(name)
            .map_err(|e| error(&e))?;
        let mut bytes = Vec::new();
        file.as_file()
            .take(262145)
            .read_to_end(&mut bytes)
            .map_err(|e| error(&e))?;
        if bytes.len() > 262144 {
            return Err("VM report receipt bound exceeded".into());
        }
        file.revalidate().map_err(|e| error(&e))?;
        Ok(bytes)
    };
    let json = |name: &str| -> Result<Value, String> {
        serde_json::from_slice(&read(name)?).map_err(|e| error(&e))
    };
    let report = json("report.json")?;
    let request_file = held
        .workspace
        .reopen_tools_file_readonly("request.json")
        .map_err(|e| error(&e))?;
    let mut bytes = Vec::new();
    request_file
        .as_file()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| error(&e))?;
    let request: aiw_probe::MsixWorkerRequest =
        serde_json::from_slice(&bytes).map_err(|e| error(&e))?;
    request.validate()?;
    let request_hash = request.hash()?;
    if request.run_id != run_id
        || request.plan_sha256 != plan_hash
        || request.worker_profile_sha256 != held.preparation.worker.hash()?
        || report["schemaVersion"] != "aiw.dev/vm-msix-assessment/v0alpha1"
        || report["runId"] != run_id
        || report["planSha256"] != plan_hash
        || report["requestSha256"] != request_hash
        || report["nonce"] != request.nonce
        || report["cleanupComplete"] != true
        || !report["workflowVerified"].is_boolean()
    {
        return Err("Retained MSIX report/request binding differs".into());
    }
    let recovered = if held
        .workspace
        .output_path()
        .join("recovery-complete.json")
        .exists()
    {
        Some(json("recovery-complete.json")?)
    } else {
        None
    };
    let proofs = if let Some(recovery) = &recovered {
        recovery.clone()
    } else {
        serde_json::json!({"nonce":request.nonce,"restore":json("final-restore.json")?,"connect":json("final-connect.json")?,"clean":json("final-clean.json")?,"release":json("lease-released.json")?})
    };
    verify_vm_msix_recovery(&held.preparation.worker, &request.nonce, &proofs)?;
    let verified = report["workflowVerified"] == true && recovered.is_none();
    if (verified && result.outcome != RunOutcome::InsufficientEvidence)
        || (!verified && result.outcome != RunOutcome::Failed)
    {
        return Err("Terminal outcome contradicts MSIX workflow report".into());
    }
    let mut functions = ApplicationReportFunctions::default();
    if verified {
        let guest =
            HeldPortableDirectory::open(&workspace.join("output/guest")).map_err(|e| error(&e))?;
        if guest.manifest().entries.len() > 512
            || guest.manifest().total_size_bytes > 16 * 1024 * 1024
        {
            return Err("Retained guest evidence bound exceeded".into());
        }
        let mut files = BTreeMap::new();
        let mut handles = Vec::new();
        for entry in &guest.manifest().entries {
            if entry.kind == aiw_probe::PortableContentEntryKind::Directory {
                continue;
            }
            if entry.size_bytes > 4 * 1024 * 1024 {
                return Err("Retained evidence file bound exceeded".into());
            }
            let file = HeldApplicationFile::open_bounded(
                &workspace.join("output/guest").join(&entry.relative_path),
                4 * 1024 * 1024,
            )
            .map_err(|e| error(&e))?;
            let bytes = file.read_bounded(4 * 1024 * 1024).map_err(|e| error(&e))?;
            files.insert(entry.relative_path.replace('\\', "/"), bytes);
            handles.push(file);
        }
        let receipt = |name: &str| -> Result<Value, String> {
            let bytes = files
                .get(name)
                .ok_or_else(|| format!("Missing native receipt {name}"))?;
            serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
                .map_err(|e| error(&e))
        };
        let terminal = receipt("result.json")?;
        let control = receipt("control-result.json")?;
        let job = receipt("job-cleanup.json")?;
        if terminal["schemaVersion"] != "aiw.dev/msix-worker-result/v0alpha1"
            || terminal["requestSha256"] != request_hash
            || terminal["nonce"] != request.nonce
            || terminal["planSha256"] != plan_hash
            || terminal["workerUuid"] != request.worker_uuid
            || terminal["agentSha256"] != request.agent_sha256
            || terminal["lifecyclePassed"] != true
            || terminal["jobEmpty"] != true
            || terminal["privilegedPackageProcessAbsenceVerified"] != true
            || terminal["researchOnly"] != false
        {
            return Err("Native terminal receipt incomplete".into());
        }
        if control["passed"] != true
            || control["observedExitCode"] != 42
            || control["expectedExitCode"] != 42
            || control["jobEmpty"] != true
            || control["nonce"] != request.nonce
            || control["requestSha256"] != request_hash
            || control["authenticationId"] != terminal["authenticationId"]
            || control["userSid"] != terminal["userSid"]
            || control["sessionId"] != terminal["sessionId"]
        {
            return Err("Same-logon native control binding differs".into());
        }
        if job["nonce"] != request.nonce
            || job["inOwnedJob"] != true
            || job["exitCode"] != 0
            || job["activeJobProcesses"] != 0
            || ["operationError", "normalCleanupError", "cleanupError"]
                .iter()
                .any(|k| !job.get(*k).is_some_and(Value::is_null))
        {
            return Err("Owned process job cleanup incomplete".into());
        }
        for name in ["inventory-before.json", "inventory-after.json"] {
            let inventory = receipt(name)?;
            for value in [
                &inventory["packages"],
                &inventory["provisioned"],
                &inventory["processes"]["matches"],
                &inventory["processes"]["queryErrors"],
            ] {
                if !value.as_array().is_some_and(Vec::is_empty) {
                    return Err("Privileged package/process absence incomplete".into());
                }
            }
            if inventory["runNonce"] != request.nonce
                || inventory["observerSid"] != "S-1-5-18"
                || inventory["observerSessionId"] != 0
            {
                return Err("Privileged inventory nonce differs".into());
            }
        }
        let mut observed = BTreeSet::new();
        for entry in terminal["files"]
            .as_array()
            .ok_or("Native inventory missing")?
        {
            let name = entry["path"]
                .as_str()
                .ok_or("Native inventory path missing")?;
            let bytes = files.get(name).ok_or("Native artifact missing")?;
            if !observed.insert(name)
                || entry["sha256"] != hex::encode(Sha256::digest(bytes))
                || entry["bytes"] != bytes.len() as u64
            {
                return Err("Native artifact inventory differs".into());
            }
        }
        if files
            .keys()
            .filter(|name| name.starts_with("evidence/"))
            .any(|name| !observed.contains(name.as_str()))
        {
            return Err("Uninventoried lifecycle evidence".into());
        }
        let lifecycle = files
            .iter()
            .filter_map(|(name, bytes)| {
                name.strip_prefix("evidence/")
                    .map(|name| (name.to_owned(), bytes.clone()))
            })
            .collect();
        let assembly = held
            .workspace
            .reopen_tools_file_readonly("assembly.json")
            .map_err(|e| error(&e))?;
        let mut bytes = Vec::new();
        assembly
            .as_file()
            .take(4 * 1024 * 1024)
            .read_to_end(&mut bytes)
            .map_err(|e| error(&e))?;
        aiw_evidence::verify_notepad_msix_lifecycle(
            &lifecycle,
            &serde_json::from_slice(&bytes).map_err(|e| error(&e))?,
            terminal["userSid"].as_str().ok_or("Native SID missing")?,
            u32::try_from(
                terminal["sessionId"]
                    .as_u64()
                    .ok_or("Native session missing")?,
            )
            .map_err(|e| error(&e))?,
        )?;
        let lifecycle_result = receipt("evidence/msix-lifecycle/result.json")?;
        let cleanup = receipt("evidence/msix-lifecycle/cleanup.json")?;
        if lifecycle_result["completed"] != true
            || lifecycle_result["researchOnly"] != false
            || lifecycle_result["registrationCleanup"] != "verified"
            || lifecycle_result["payloadUnchanged"] != true
            || cleanup["installLocationPresent"] != false
        {
            return Err("Production lifecycle cleanup incomplete".into());
        }
        for file in handles {
            file.revalidate().map_err(|e| error(&e))?;
        }
        guest.revalidate().map_err(|e| error(&e))?;
        functions = ApplicationReportFunctions {
            install: Some(true),
            launch: Some(true),
            open_document: Some(true),
            edit_save_document: Some(true),
            close: Some(true),
            uninstall: Some(true),
            ..Default::default()
        };
    }
    request_file.revalidate().map_err(|e| error(&e))?;
    held.workspace.revalidate().map_err(|e| error(&e))?;
    Ok(VmMsixAssessmentReport {
        schema_version: "aiw.dev/vm-msix-assessment/v0alpha1".into(),
        run_id: run_id.into(),
        plan_sha256: plan_hash,
        request_sha256: request_hash,
        nonce: request.nonce,
        workflow_verified: verified,
        cleanup_complete: true,
        functions,
        isolation: "notMeasured".into(),
        broader_compatibility: "notMeasured".into(),
        summary: if verified {
            "Fixed MSIX install, launch, open, edit/save, close and uninstall verified; VM107 cold recovery verified. General compatibility and isolation remain unmeasured.".into()
        } else {
            "MSIX workflow incomplete; retained cold recovery verified. Inspect raw failure evidence before creating a new trial.".into()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn profile() -> aiw_probe::VmMsixWorkerProfile {
        serde_json::from_value(json!({"schemaVersion":"aiw.dev/vm-msix-worker-profile/v0alpha1","vmId":107,"workerUuid":aiw_probe::MSIX_WORKER_UUID,"workerMac":"CC:34:21:B8:5A:31","checkpoint":aiw_probe::MSIX_WORKER_CHECKPOINT,"checkpointConfigSha256":"c".repeat(64),"providerSha256":"d".repeat(64),"hypervisorAddress":"192.168.1.6","hypervisorHostKeySha256":"SHA256:J/kc0UwUBil5TFBQbQhwBoRKnDoRlZ8ggXAhmYEpq1E","httpsAddress":"192.168.1.174","httpsCertificateSha1":"BC14DCC4E37F83161EBB55AF8624E36A79E19256"})).unwrap()
    }
    #[test]
    fn cleanup_cannot_be_terminal_without_matching_cold_restore_clean_readback_and_release() {
        let worker = profile();
        let nonce = "a".repeat(64);
        let mut proofs = json!({"nonce":nonce,"clean":{"clean":true,"workerUuid":worker.worker_uuid,"trialArtifactsAbsent":true,"automaticSignInDisabled":true}});
        for (op, phase, lease) in [
            ("restore", "restored", true),
            ("connect", "online-clean", true),
            ("release", "none", false),
        ] {
            proofs[op] = json!({"schemaVersion":"aiw.dev/vm-msix-hypervisor/v0alpha1","operation":op,"phase":phase,"leasePresent":lease,"vmId":107,"workerUuid":worker.worker_uuid,"nonce":nonce,"checkpoint":worker.checkpoint,"checkpointConfigSha256":worker.checkpoint_config_sha256,"providerSha256":worker.provider_sha256,"running":true});
        }
        verify_vm_msix_recovery(&worker, &nonce, &proofs).unwrap();
        for (section, key, bad) in [
            ("restore", "phase", json!("dirty")),
            ("restore", "checkpoint", json!("other")),
            ("connect", "workerUuid", json!("wrong")),
            ("release", "leasePresent", json!(true)),
            ("clean", "automaticSignInDisabled", json!(false)),
            ("release", "nonce", json!("b".repeat(64))),
        ] {
            let mut changed = proofs.clone();
            changed[section][key] = bad;
            assert!(
                verify_vm_msix_recovery(&worker, &nonce, &changed).is_err(),
                "{section}.{key}"
            );
        }
        proofs["release"]["operation"] = "completed".into();
        proofs["release"]["phase"] = "online-clean".into();
        verify_vm_msix_recovery(&worker, &nonce, &proofs).unwrap();
        proofs["restore"] = Value::Null;
        assert!(verify_vm_msix_recovery(&worker, &nonce, &proofs).is_err());
    }
}
