//! Fixed VM107 execution service. Approval, exclusive external lease, native
//! control, evidence verification and cold recovery are one host-owned flow.
use super::*;
use aiw_orchestrator::{
    PlannedAction, RunLifecycleKind, RunOutcome, RunPlan, RunResult, VM_MSIX_PREPARATION_SCHEMA,
    VmMsixExecutionBinding, VmMsixPreparation, VmMsixPreparedFile,
};
use aiw_probe::{MsixWorkerRequest, VmMsixRecipe, VmMsixWorkerProfile};
use aiw_windows_platform::{HeldApplicationFile, HeldRunWorkspace};
use anyhow::Context;
use base64::Engine;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PS: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const SSH: &str = r"C:\Windows\System32\OpenSSH\ssh.exe";
const TRANSPORT: &str = include_str!("../../../scripts/vm-msix/transport.ps1");
const PROVIDER: &str = include_str!("../../../scripts/vm-msix/proxmox-worker107.sh");
const PRODUCT: &str = "notepad-plus-plus-msix-vm107";
// The clean-source package builder compiles the native worker first, then pins
// its bytes into this host binary. A manifest beside the app cannot enroll code.
const EXPECTED_AGENT_SHA256: Option<&str> = option_env!("AIW_MSIX_WORKER_SHA256");

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn provider_hash() -> String {
    hash(PROVIDER.replace("\r\n", "\n").as_bytes())
}
fn filetime() -> Result<i64> {
    Ok(
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() / 100)?
            + 116444736000000000,
    )
}
fn command_json(command: &mut Command, seconds: u64, bound: usize) -> Result<Value> {
    use std::os::windows::process::CommandExt;
    command
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().context("Missing transport stdout")?;
    let stderr = child.stderr.take().context("Missing transport stderr")?;
    let out = std::thread::spawn(move || {
        let mut b = Vec::new();
        stdout.take(bound as u64 + 1).read_to_end(&mut b).map(|_| b)
    });
    let err = std::thread::spawn(move || {
        let mut b = Vec::new();
        stderr.take(65537).read_to_end(&mut b).map(|_| b)
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > Duration::from_secs(seconds) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Transport deadline exceeded; dispatch is uncertain, never replay")
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let bytes = out
        .join()
        .map_err(|_| anyhow!("Transport output reader failed"))??;
    let errors = err
        .join()
        .map_err(|_| anyhow!("Transport diagnostic reader failed"))??;
    if !status.success() || bytes.len() > bound || errors.len() > 65536 {
        bail!(
            "Fixed transport failed: {}",
            String::from_utf8_lossy(&errors)
                .chars()
                .take(3000)
                .collect::<String>()
        )
    }
    Ok(serde_json::from_slice(
        bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes),
    )?)
}
fn provider(
    operation: &str,
    nonce: Option<&str>,
    expected: Option<&VmMsixWorkerProfile>,
) -> Result<Value> {
    if !matches!(
        operation,
        "probe" | "acquire" | "inspect" | "completed" | "restore" | "connect" | "begin" | "release"
    ) {
        bail!("Closed provider operation required")
    }
    let verb = if operation == "probe" {
        "msix-probe".into()
    } else {
        let nonce = nonce.context("Lease nonce required")?;
        if nonce.len() != 64
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("Invalid lease nonce")
        }
        format!("msix-{operation}:{nonce}")
    };
    let user = PathBuf::from(std::env::var_os("USERPROFILE").context("Operator profile required")?);
    let known_hosts_path = user.join(".ssh/aiw_proxmox_known_hosts");
    let known_hosts = HeldApplicationFile::open_bounded(&known_hosts_path, 4096)?;
    if std::str::from_utf8(&known_hosts.read_bounded(4096)?)?.trim()
        != "192.168.1.6 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF2/+iVcLLgZNd0rXqBjr8XDN3pMpkrLMUxmGpZUngYY"
    {
        bail!("Pinned Proxmox known-host key differs")
    }
    let value = command_json(
        Command::new(SSH)
            .args([
                "-T",
                "-F",
                "NUL",
                "-o",
                "GlobalKnownHostsFile=NUL",
                "-o",
                "HostKeyAlgorithms=ssh-ed25519",
                "-o",
                "UpdateHostKeys=no",
                "-o",
                "ControlPath=none",
                "-o",
                "IdentityAgent=none",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
            ])
            .arg(format!("UserKnownHostsFile={}", known_hosts_path.display()))
            .arg("-i")
            .arg(user.join(".ssh/aiw_proxmox_ed25519"))
            .args(["root@192.168.1.6", &verb]),
        240,
        65536,
    )?;
    known_hosts.revalidate()?;
    if value["schemaVersion"] != "aiw.dev/vm-msix-hypervisor/v0alpha1"
        || value["vmId"] != 107
        || value["workerUuid"] != aiw_probe::MSIX_WORKER_UUID
        || value["operation"] != operation
        || value["providerSha256"] != provider_hash()
        || value["checkpoint"] != aiw_probe::MSIX_WORKER_CHECKPOINT
    {
        bail!("Exact reviewed VM107 provider response required")
    }
    if let Some(nonce) = nonce {
        if value["nonce"] != nonce {
            bail!("Lease response nonce differs")
        }
    }
    if let Some(profile) = expected {
        if value["checkpointConfigSha256"] != profile.checkpoint_config_sha256
            || value["providerSha256"] != profile.provider_sha256
        {
            bail!("Approved recovery/provider identity drift")
        }
    }
    Ok(value)
}
fn powershell_workspace_path(workspace: &Path) -> Result<PathBuf> {
    // Held workspace paths may carry the Win32 verbatim prefix. PowerShell 5.1's
    // FileSystem provider cannot Join-Path that form. Keep the held identity and
    // pass its equivalent local DOS spelling to the fixed transport only.
    let spelling = workspace
        .to_str()
        .context("Unicode workspace path required")?;
    Ok(PathBuf::from(
        spelling.strip_prefix(r"\\?\").unwrap_or(spelling),
    ))
}
fn transport(operation: &str, run_id: &str, workspace: &Path) -> Result<Value> {
    let workspace = powershell_workspace_path(workspace)?;
    command_json(
        Command::new(PS)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(workspace.join("tools/transport.ps1"))
            .args(["-Operation", operation, "-RunId", run_id, "-Workspace"])
            .arg(&workspace),
        120,
        32 * 1024 * 1024,
    )
}

fn write_tools(workspace: &HeldRunWorkspace, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = workspace.create_tools_file_new(name)?;
    file.as_file_mut().write_all(bytes)?;
    file.as_file_mut().sync_all()?;
    file.revalidate()?;
    Ok(())
}
fn stage(workspace: &HeldRunWorkspace, name: &str, value: &impl Serialize) -> Result<()> {
    let mut file = workspace.create_output_file_new(&format!("{name}.json"))?;
    file.as_file_mut()
        .write_all(&serde_json::to_vec_pretty(value)?)?;
    file.as_file_mut().sync_all()?;
    file.revalidate()?;
    Ok(())
}
fn read_stage(workspace: &HeldRunWorkspace, name: &str) -> Result<Value> {
    let file = workspace.reopen_output_file(name)?;
    let mut bytes = Vec::new();
    file.as_file().take(262145).read_to_end(&mut bytes)?;
    if bytes.len() > 262144 {
        bail!("Host stage bound exceeded")
    }
    let value = serde_json::from_slice(&bytes)?;
    file.revalidate()?;
    Ok(value)
}
fn wait_clean(workspace: &Path, run_id: &str) -> Result<Value> {
    let start = Instant::now();
    let mut last = String::new();
    // The cold checkpoint boots with its NIC down. Restored Windows networking
    // and WinRM have taken several minutes to become ready after hot reconnect.
    while start.elapsed() < Duration::from_secs(360) {
        match transport("Clean", run_id, workspace) {
            Ok(value) => return Ok(value),
            Err(error) => last = error.to_string(),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    bail!("Restored TLS/identity/clean inventory not verified: {last}")
}
fn wait_operation(
    workspace: &HeldRunWorkspace,
    run_id: &str,
    nonce: &str,
    operation: &str,
    seconds: u64,
) -> Result<Value> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        let value = transport("Status", run_id, workspace.root_path())?;
        if value["nonce"] != nonce {
            bail!("Status nonce differs")
        }
        if !value["records"]["failure"].is_null() {
            bail!("Native worker failed; preserve evidence and restore")
        }
        let terminal = &value["records"][format!("{operation}-transport")];
        if !terminal.is_null() {
            stage(workspace, &format!("{operation}-status"), &value)?;
            if terminal["nonce"] != nonce
                || terminal["completed"] != true
                || terminal["exitCode"] != 0
            {
                bail!("Native {operation} did not complete successfully")
            }
            return Ok(value);
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    bail!("Native {operation} deadline exceeded; never replay")
}

/// Uses packaged fixed assets; the caller selects only the exact supported MSIX.
pub fn assess_with_gate(
    package: &Path,
    evidence_parent: &Path,
    identity: &str,
    gate: &dyn ApprovalGate,
) -> Result<AdminAssessmentResult> {
    let agent_sha=EXPECTED_AGENT_SHA256.context("This desktop has no compiled MSIX worker identity. Use the clean-source MSIX desktop package builder.")?;
    if !valid_sha256(agent_sha) {
        bail!("Compiled MSIX worker identity invalid")
    }
    if identity.trim().is_empty() {
        bail!("Operator identity required")
    }
    let run_id = format!("msix-{}", super::nonce());
    let evidence_root = create_evidence_root(evidence_parent, &run_id)?;
    let workspace = HeldRunWorkspace::create(&evidence_root, "workspace")?;
    let asset_root = std::env::current_exe()?
        .parent()
        .context("Product directory missing")?
        .join("product/msix-worker107");
    let mut files = Vec::new();
    for (name, expected) in [
        ("agent.exe", Some(agent_sha)),
        ("assembly.json", Some(aiw_probe::MSIX_ASSEMBLY_SHA256)),
        ("signing.json", Some(aiw_probe::MSIX_SIGNING_SHA256)),
    ] {
        let source = HeldApplicationFile::open_bounded(&asset_root.join(name), 32 * 1024 * 1024)?;
        let bytes = source.read_bounded(32 * 1024 * 1024)?;
        if expected.is_some_and(|expected| hash(&bytes) != expected) {
            bail!("Packaged fixed MSIX metadata differs")
        }
        write_tools(&workspace, name, &bytes)?;
        source.revalidate()?;
        files.push(VmMsixPreparedFile {
            leaf: name.into(),
            sha256: hash(&bytes),
            size_bytes: bytes.len() as u64,
        });
    }
    write_tools(&workspace, "transport.ps1", TRANSPORT.as_bytes())?;
    files.push(VmMsixPreparedFile {
        leaf: "transport.ps1".into(),
        sha256: hash(TRANSPORT.as_bytes()),
        size_bytes: TRANSPORT.len() as u64,
    });
    let proof = provider("probe", None, None)?;
    if proof["leasePresent"] != false {
        bail!("VM107 already leased; preserve prior run and recover its exact nonce")
    }
    let worker = VmMsixWorkerProfile {
        schema_version: "aiw.dev/vm-msix-worker-profile/v0alpha1".into(),
        vm_id: 107,
        worker_uuid: aiw_probe::MSIX_WORKER_UUID.into(),
        worker_mac: "CC:34:21:B8:5A:31".into(),
        checkpoint: aiw_probe::MSIX_WORKER_CHECKPOINT.into(),
        checkpoint_config_sha256: proof["checkpointConfigSha256"]
            .as_str()
            .context("Checkpoint proof missing")?
            .into(),
        provider_sha256: provider_hash(),
        hypervisor_address: "192.168.1.6".into(),
        hypervisor_host_key_sha256: "SHA256:J/kc0UwUBil5TFBQbQhwBoRKnDoRlZ8ggXAhmYEpq1E".into(),
        https_address: "192.168.1.174".into(),
        https_certificate_sha1: "BC14DCC4E37F83161EBB55AF8624E36A79E19256".into(),
    };
    worker.validate().map_err(anyhow::Error::msg)?;
    let source = HeldApplicationFile::open_with_download_metadata(package)?;
    if source.observation().sha256 != aiw_probe::MSIX_PACKAGE_SHA256 {
        bail!("Select the exact supported signed Notepad++8.9.8 MSIX")
    }
    let intake = evidence_root.join("intakes");
    std::fs::create_dir(&intake)?;
    let package_import = aiw_windows_platform::import_application_file_with_metadata(
        &intake,
        "notepad-msix",
        ApplicationInspectionKind::Msix,
        &source,
        true,
    )?;
    let prepared = VmMsixPreparation {
        schema_version: VM_MSIX_PREPARATION_SCHEMA.into(),
        run_id: run_id.clone(),
        worker: worker.clone(),
        workspace: workspace.evidence().clone(),
        package_import,
        files,
    };
    write_tools(
        &workspace,
        "msix-preparation.json",
        &serde_json::to_vec_pretty(&prepared)?,
    )?;
    let binding = VmMsixExecutionBinding {
        preparation_sha256: prepared.hash().map_err(anyhow::Error::msg)?,
        worker_profile_sha256: worker.hash().map_err(anyhow::Error::msg)?,
        package_sha256: aiw_probe::MSIX_PACKAGE_SHA256.into(),
        workspace: Box::new(workspace.evidence().clone()),
    };
    let plan=RunPlan::new(&run_id,PRODUCT,prepared.hash().map_err(anyhow::Error::msg)?,RunLifecycleKind::Assessment,now_rfc3339(),vec![PlannedAction::ExecuteVmMsix{binding:Box::new(binding)}],vec!["Dedicated VM107 is rebooted and cold-restored; its NIC permits lab-network access during the trial. A fresh standard account uses temporary automatic sign-in, cleared before control. Fixed medium full-trust package, not AppContainer; broader isolation is not measured.".into()])?;
    let layout = RunLayout::new(workspace.root_path(), &run_id)?;
    layout.create(&plan)?;
    let review = ApprovalReview {
        run_id: run_id.clone(),
        workspace: workspace.root_path().into(),
        evidence_root: evidence_root.clone(),
        recipe: json!({"profile":PRODUCT,"worker":worker,"executionAssets":prepared.files,"preparationSha256":prepared.hash().map_err(anyhow::Error::msg)?,"packageSha256":aiw_probe::MSIX_PACKAGE_SHA256,"workflow":"Install, launch, open document, append AIW packaged validation plus Enter, save, close, verify payload/configuration, uninstall, collect evidence, cold restore","documentTemplate":"C:\\Users\\AiwStandardUser\\AppData\\Local\\AIW\\msix-<run nonce>\\msix-lifecycle\\document.txt","deadlineSeconds":1800,"isolation":"notMeasured","externalRecoveryLease":true}),
        plan: plan.clone(),
        proposed_approval: ApprovalRecord::for_plan(&plan, identity.trim(), now_rfc3339())?,
    };
    let approved = approve_review(gate, &review)?;
    let started = approved && wait_for_start(gate, &review)?;
    if !started {
        return Ok(AdminAssessmentResult {
            schema_version: MANIFEST_SCHEMA,
            product_id: PRODUCT,
            operator_identity: identity.into(),
            evidence_root,
            run_id,
            workspace: workspace.root_path().into(),
            execution_mode: "dedicatedVmMsix",
            approval_recorded: approved,
            execution_started: false,
            next: "No worker was acquired. Use a new run when ready.",
            summary: None,
        });
    }
    let held = aiw_orchestrator::open_vm_msix_preparation(&plan)?;
    let approval = layout.read_approval()?;
    if approval.plan_hash != plan.hash()? || layout.read_plan()? != plan {
        bail!("Approved plan drift before Start")
    }
    // Cryptographic nonce from the platform CSPRNG; not a clock-derived run ID.
    let nonce_value=command_json(Command::new(PS).args(["-NoProfile","-NonInteractive","-Command","$r=[byte[]]::new(32);$g=[Security.Cryptography.RandomNumberGenerator]::Create();try{$g.GetBytes($r);ConvertTo-Json ([BitConverter]::ToString($r).Replace('-','').ToLowerInvariant())}finally{$g.Dispose()}"]),15,1024)?;
    let nonce = nonce_value
        .as_str()
        .context("Random nonce missing")?
        .to_owned();
    let before = filetime()?;
    let request = MsixWorkerRequest {
        schema_version: aiw_probe::MSIX_WORKER_REQUEST_SCHEMA.into(),
        run_id: run_id.clone(),
        nonce: nonce.clone(),
        recipe: VmMsixRecipe::Notepad898MediumFullTrust,
        plan_sha256: plan.hash()?,
        worker_profile_sha256: worker.hash().map_err(anyhow::Error::msg)?,
        agent_sha256: prepared
            .files
            .iter()
            .find(|f| f.leaf == "agent.exe")
            .context("Agent missing")?
            .sha256
            .clone(),
        package_sha256: aiw_probe::MSIX_PACKAGE_SHA256.into(),
        assembly_sha256: aiw_probe::MSIX_ASSEMBLY_SHA256.into(),
        signing_sha256: aiw_probe::MSIX_SIGNING_SHA256.into(),
        worker_uuid: aiw_probe::MSIX_WORKER_UUID.into(),
        not_before_file_time: before,
        not_after_file_time: before + 18_000_000_000,
    };
    request.validate().map_err(anyhow::Error::msg)?;
    write_tools(&workspace, "request.json", &serde_json::to_vec(&request)?)?;
    let _request_hold = workspace.reopen_tools_file_readonly("request.json")?;
    stage(
        &workspace,
        "start-intent",
        &json!({"nonce":nonce,"requestSha256":request.hash().map_err(anyhow::Error::msg)?,"planSha256":plan.hash()?,"automaticRetry":false}),
    )?;
    // From acquire intent onward, failure always retains explicit recovery state.
    let execution = (|| -> Result<()> {
        gate.progress("Acquiring VM107 and restoring its approved clean checkpoint.");
        stage(&workspace, "acquire-intent", &json!({"nonce":nonce}))?;
        let lease = provider("acquire", Some(&nonce), Some(&worker))?;
        stage(&workspace, "lease-acquired", &lease)?;
        let restored = provider("restore", Some(&nonce), Some(&worker))?;
        stage(&workspace, "initial-restore", &restored)?;
        stage(
            &workspace,
            "initial-connect",
            &provider("connect", Some(&nonce), Some(&worker))?,
        )?;
        stage(
            &workspace,
            "initial-clean",
            &wait_clean(workspace.root_path(), &run_id)?,
        )?;
        stage(
            &workspace,
            "begin",
            &provider("begin", Some(&nonce), Some(&worker))?,
        )?;
        gate.progress("Staging approved inputs and creating the disposable standard-user session.");
        stage(&workspace, "stage-intent", &json!({"nonce":nonce}))?;
        stage(
            &workspace,
            "guest-staged",
            &transport("Stage", &run_id, workspace.root_path())?,
        )?;
        stage(&workspace, "enroll-intent", &json!({"nonce":nonce}))?;
        stage(
            &workspace,
            "enroll-dispatch",
            &transport("Enroll", &run_id, workspace.root_path())?,
        )?;
        wait_operation(&workspace, &run_id, &nonce, "enroll", 120)?;
        stage(&workspace, "restart-intent", &json!({"nonce":nonce}))?;
        stage(
            &workspace,
            "restart-dispatch",
            &transport("Restart", &run_id, workspace.root_path())?,
        )?;
        std::thread::sleep(Duration::from_secs(25));
        // Only read-only status reconnects may repeat; no mutation dispatch repeats.
        let start = Instant::now();
        loop {
            if transport("Status", &run_id, workspace.root_path()).is_ok() {
                break;
            }
            if start.elapsed() > Duration::from_secs(150) {
                bail!("Worker did not return after reboot")
            };
            std::thread::sleep(Duration::from_secs(5));
        }
        gate.progress("Verifying the native process control in the fresh standard-user session.");
        stage(&workspace, "control-intent", &json!({"nonce":nonce}))?;
        stage(
            &workspace,
            "control-dispatch",
            &transport("Control", &run_id, workspace.root_path())?,
        )?;
        wait_operation(&workspace, &run_id, &nonce, "control", 150)?;
        stage(&workspace, "run-intent", &json!({"nonce":nonce}))?;
        stage(
            &workspace,
            "run-dispatch",
            &transport("Run", &run_id, workspace.root_path())?,
        )?;
        gate.progress(&format!("In VM107 Notepad++, open C:\\Users\\AiwStandardUser\\AppData\\Local\\AIW\\msix-{nonce}\\msix-lifecycle\\document.txt. Append AIW packaged validation and Enter. Save and close the editor. The run has a 20-minute deadline."));
        wait_operation(&workspace, &run_id, &nonce, "run", 1250)?;
        Ok(())
    })();
    gate.progress("Collecting bounded worker evidence before cold recovery.");
    let collected = transport("Collect", &run_id, workspace.root_path())
        .and_then(|value| collect(&workspace, &request, &value));
    if let Err(error) = &collected {
        let _ = stage(
            &workspace,
            "collection-failed",
            &json!({"error":error.to_string()}),
        );
    }
    gate.progress("Restoring VM107 and verifying its clean identity, accounts, package state and TLS connection.");
    let recovery = (|| -> Result<()> {
        stage(&workspace, "recovery-intent", &json!({"nonce":nonce}))?;
        stage(
            &workspace,
            "final-restore",
            &provider("restore", Some(&nonce), Some(&worker))?,
        )?;
        stage(
            &workspace,
            "final-connect",
            &provider("connect", Some(&nonce), Some(&worker))?,
        )?;
        stage(
            &workspace,
            "final-clean",
            &wait_clean(workspace.root_path(), &run_id)?,
        )?;
        stage(
            &workspace,
            "lease-released",
            &provider("release", Some(&nonce), Some(&worker))?,
        )?;
        aiw_runner::verify_vm_msix_recovery(&worker,&nonce,&json!({"nonce":nonce,"restore":read_stage(&workspace,"final-restore.json")?,"connect":read_stage(&workspace,"final-connect.json")?,"clean":read_stage(&workspace,"final-clean.json")?,"release":read_stage(&workspace,"lease-released.json")?})).map_err(anyhow::Error::msg)?;
        Ok(())
    })();
    held.workspace.revalidate()?;
    if let Err(error) = recovery {
        stage(
            &workspace,
            "recovery-required",
            &json!({"nonce":nonce,"error":error.to_string(),"automaticRetry":false}),
        )?;
        bail!(
            "VM107 recovery required. Preserve {} and its exact lease nonce. {}",
            workspace.root_path().display(),
            error
        )
    }
    let verified = execution.is_ok() && collected.is_ok();
    let summary = if verified {
        "Fixed signed Notepad++ MSIX lifecycle verified: install, launch, open, edit, save, close, payload/configuration checks and uninstall. VM107 cold restore and clean readback verified. Broader compatibility and isolation remain not measured.".to_owned()
    } else {
        format!(
            "MSIX workflow incomplete. VM107 cold restore and clean readback verified. Execution: {}. Evidence: {}. Preserve this run; use a new approved run after diagnosis.",
            execution
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_else(|| "completed".into()),
            collected
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_else(|| "verified".into())
        )
    };
    stage(
        &workspace,
        "report",
        &json!({"schemaVersion":"aiw.dev/vm-msix-assessment/v0alpha1","runId":run_id,"planSha256":plan.hash()?,"requestSha256":request.hash().map_err(anyhow::Error::msg)?,"nonce":nonce,"workflowVerified":verified,"cleanupComplete":true,"broaderCompatibility":"notMeasured","isolation":"notMeasured","summary":summary}),
    )?;
    layout.write_result(&RunResult::new(
        &run_id,
        if verified {
            RunOutcome::InsufficientEvidence
        } else {
            RunOutcome::Failed
        },
        now_rfc3339(),
        Some(evidence_root.display().to_string()),
        true,
        &summary,
    )?)?;
    Ok(AdminAssessmentResult {
        schema_version: MANIFEST_SCHEMA,
        product_id: PRODUCT,
        operator_identity: identity.into(),
        evidence_root,
        run_id,
        workspace: workspace.root_path().into(),
        execution_mode: "dedicatedVmMsix",
        approval_recorded: true,
        execution_started: true,
        next: "Read the retained evidence. General compatibility and isolation are not measured.",
        summary: Some(summary),
    })
}

fn collect(workspace: &HeldRunWorkspace, request: &MsixWorkerRequest, value: &Value) -> Result<()> {
    if value["nonce"] != request.nonce {
        bail!("Collected nonce differs")
    }
    let entries = value["files"]
        .as_array()
        .context("Evidence file list missing")?;
    if entries.len() > 512 {
        bail!("Evidence file count exceeded")
    }
    let mut files = BTreeMap::new();
    let mut total = 0;
    let destination = workspace.create_output_directory_new("guest")?;
    // Reject duplicate/path tricks before materializing any untrusted names.
    for entry in entries {
        let name = entry["path"].as_str().context("Evidence path missing")?;
        if name.len() > 512
            || name.split('/').any(|p| {
                p.is_empty()
                    || p == "."
                    || p == ".."
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            bail!("Evidence path rejected")
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(entry["base64"].as_str().context("Evidence bytes missing")?)?;
        total += bytes.len();
        if bytes.len() > 4 * 1024 * 1024
            || total > 16 * 1024 * 1024
            || entry["bytes"] != bytes.len() as u64
            || entry["sha256"] != hash(&bytes)
            || files.insert(name.to_owned(), bytes).is_some()
        {
            bail!("Evidence hash/length/count rejected")
        }
    }
    for (name, bytes) in &files {
        let path = destination.final_path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?
        }
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    destination.revalidate()?;
    let receipt = |name: &str| -> Result<Value> {
        let bytes = files
            .get(name)
            .with_context(|| format!("Missing worker receipt {name}"))?;
        Ok(serde_json::from_slice(
            bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes),
        )?)
    };
    let control = receipt("control-result.json")?;
    let job = receipt("job-cleanup.json")?;
    if control["passed"] != true
        || control["observedExitCode"] != 42
        || control["jobEmpty"] != true
        || control["nonce"] != request.nonce
        || control["requestSha256"] != request.hash().map_err(anyhow::Error::msg)?
        || job["nonce"] != request.nonce
        || job["inOwnedJob"] != true
        || job["exitCode"] != 0
        || job["activeJobProcesses"] != 0
        || ["operationError", "normalCleanupError", "cleanupError"]
            .iter()
            .any(|k| !job.get(*k).is_some_and(Value::is_null))
    {
        bail!("Native control/job verification incomplete")
    }
    for name in ["inventory-before.json", "inventory-after.json"] {
        let inventory = receipt(name)?;
        if inventory["runNonce"] != request.nonce
            || inventory["observerSid"] != "S-1-5-18"
            || inventory["observerSessionId"] != 0
        {
            bail!("Privileged inventory authority differs")
        }
        for field in [
            &inventory["packages"],
            &inventory["provisioned"],
            &inventory["processes"]["matches"],
            &inventory["processes"]["queryErrors"],
        ] {
            if !field.as_array().is_some_and(Vec::is_empty) {
                bail!("Privileged package/process absence incomplete")
            }
        }
    }
    let terminal: Value = serde_json::from_slice(
        files
            .get("result.json")
            .context("Native terminal receipt absent")?,
    )?;
    if terminal["schemaVersion"] != "aiw.dev/msix-worker-result/v0alpha1"
        || terminal["requestSha256"] != request.hash().map_err(anyhow::Error::msg)?
        || terminal["nonce"] != request.nonce
        || terminal["planSha256"] != request.plan_sha256
        || terminal["workerUuid"] != request.worker_uuid
        || terminal["agentSha256"] != request.agent_sha256
        || terminal["lifecyclePassed"] != true
        || terminal["jobEmpty"] != true
        || terminal["privilegedPackageProcessAbsenceVerified"] != true
        || terminal["researchOnly"] != false
        || terminal["authenticationId"] != control["authenticationId"]
        || terminal["userSid"] != control["userSid"]
        || terminal["sessionId"] != control["sessionId"]
    {
        bail!("Native terminal bindings incomplete")
    }
    for entry in terminal["files"]
        .as_array()
        .context("Native evidence inventory missing")?
    {
        let name = entry["path"].as_str().context("Native path missing")?;
        let bytes = files.get(name).context("Native artifact absent")?;
        if entry["sha256"] != hash(bytes) || entry["bytes"] != bytes.len() as u64 {
            bail!("Native artifact binding differs")
        }
    }
    let lifecycle = files
        .iter()
        .filter_map(|(name, bytes)| {
            name.strip_prefix("evidence/")
                .map(|name| (name.to_owned(), bytes.clone()))
        })
        .collect();
    let assembly = workspace.reopen_tools_file_readonly("assembly.json")?;
    let mut bytes = Vec::new();
    assembly
        .as_file()
        .take(4 * 1024 * 1024)
        .read_to_end(&mut bytes)?;
    aiw_evidence::verify_notepad_msix_lifecycle(
        &lifecycle,
        &serde_json::from_slice(&bytes)?,
        terminal["userSid"].as_str().context("Native SID absent")?,
        u32::try_from(
            terminal["sessionId"]
                .as_u64()
                .context("Native session absent")?,
        )?,
    )
    .map_err(anyhow::Error::msg)
}

/// Retained production report, only after its exact plan/result and protected
/// workspace binding have been reopened. Never launches or repairs a worker.
pub fn read_report(workspace: &Path, run_id: &str) -> Result<Value> {
    Ok(serde_json::to_value(
        aiw_runner::report_vm_msix_run(workspace, run_id).map_err(anyhow::Error::msg)?,
    )?)
}

/// Exact retained-lease recovery only. It cannot stage, enroll or run an app.
pub fn recover(workspace_path: &Path, run_id: &str, gate: &dyn ApprovalGate) -> Result<Value> {
    let layout = RunLayout::new(workspace_path, run_id)?;
    let plan = layout.read_plan()?;
    let held = aiw_orchestrator::open_vm_msix_preparation(&plan)?;
    if layout.read_approval()?.plan_hash != plan.hash()? {
        bail!("Exact original approval required for recovery")
    }
    if layout.result_path().exists() {
        return read_report(workspace_path, run_id);
    }
    let request_file = held.workspace.reopen_tools_file_readonly("request.json")?;
    let mut bytes = Vec::new();
    request_file.as_file().take(65537).read_to_end(&mut bytes)?;
    let request: MsixWorkerRequest = serde_json::from_slice(&bytes)?;
    request.validate().map_err(anyhow::Error::msg)?;
    if request.run_id != run_id
        || request.plan_sha256 != plan.hash()?
        || request.worker_profile_sha256
            != held.preparation.worker.hash().map_err(anyhow::Error::msg)?
    {
        bail!("Original recovery request differs")
    }
    let worker = &held.preparation.worker;
    // An earlier successful recovery needs only its retained read-only report.
    if held
        .workspace
        .output_path()
        .join("recovery-complete.json")
        .exists()
    {
        return finish_recovery(&layout, &held.workspace, &request, worker);
    }
    let state = provider("inspect", Some(&request.nonce), Some(worker));
    stage(
        &held.workspace,
        &format!("recovery-resume-intent-{}", super::nonce()),
        &json!({"nonce":request.nonce,"leaseObserved":state.is_ok()}),
    )?;
    gate.progress(
        "Recovering the retained VM107 lease. No application operation will be repeated.",
    );
    let (restored, connected, clean, released) = if state.is_ok() {
        let restored = provider("restore", Some(&request.nonce), Some(worker))?;
        let connected = provider("connect", Some(&request.nonce), Some(worker))?;
        let clean = wait_clean(workspace_path, run_id)?;
        let released = provider("release", Some(&request.nonce), Some(worker))?;
        (restored, connected, clean, released)
    } else {
        // A lost release response is resolved from the durable completed nonce,
        // never by adopting another lease or repeating application execution.
        let released = provider("completed", Some(&request.nonce), Some(worker))?;
        if released["leasePresent"] != false {
            bail!("Another run owns VM107; original completion remains retained")
        }
        let read = |name: &str| -> Result<Value> {
            let f = held.workspace.reopen_output_file(name)?;
            let mut b = Vec::new();
            f.as_file().take(65537).read_to_end(&mut b)?;
            Ok(serde_json::from_slice(&b)?)
        };
        let restored = read("final-restore.json")?;
        let connected = read("final-connect.json")?;
        let clean = wait_clean(workspace_path, run_id)?;
        (restored, connected, clean, released)
    };
    stage(
        &held.workspace,
        "recovery-complete",
        &json!({"nonce":request.nonce,"restore":restored,"connect":connected,"clean":clean,"release":released}),
    )?;
    finish_recovery(&layout, &held.workspace, &request, worker)
}
fn finish_recovery(
    layout: &RunLayout,
    workspace: &HeldRunWorkspace,
    request: &MsixWorkerRequest,
    worker: &VmMsixWorkerProfile,
) -> Result<Value> {
    let marker = workspace.reopen_output_file("recovery-complete.json")?;
    let mut bytes = Vec::new();
    marker.as_file().take(262145).read_to_end(&mut bytes)?;
    if bytes.len() > 262144 {
        bail!("Recovery proof bound exceeded")
    }
    aiw_runner::verify_vm_msix_recovery(worker, &request.nonce, &serde_json::from_slice(&bytes)?)
        .map_err(anyhow::Error::msg)?;
    marker.revalidate()?;
    let run_id = &request.run_id;
    let summary = "Application result incomplete; exact retained VM107 lease recovered, cold restore and clean TLS readback verified. No application operation replayed.";
    if !workspace.output_path().join("report.json").exists() {
        stage(
            workspace,
            "report",
            &json!({"schemaVersion":"aiw.dev/vm-msix-assessment/v0alpha1","runId":run_id,"planSha256":request.plan_sha256,"requestSha256":request.hash().map_err(anyhow::Error::msg)?,"nonce":request.nonce,"workflowVerified":false,"cleanupComplete":true,"summary":summary}),
        )?;
    }
    layout.write_result(&RunResult::new(
        run_id,
        RunOutcome::Failed,
        now_rfc3339(),
        None,
        true,
        summary,
    )?)?;
    read_report(workspace.root_path(), run_id)
}

#[cfg(test)]
mod transport_path_tests {
    use super::*;

    #[test]
    fn held_canonical_workspace_is_usable_by_powershell_filesystem_provider() {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = powershell_workspace_path(&root).unwrap();
        let result = command_json(
            Command::new(PS)
                .args(["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; $p=Join-Path $env:AIW_MSIX_PATH_TEST 'tools'; @{ usable=($p -like '*\\tools') -and (Test-Path -LiteralPath $env:AIW_MSIX_PATH_TEST) } | ConvertTo-Json -Compress"])
                .env("AIW_MSIX_PATH_TEST", &path),
            30,
            4096,
        ).unwrap();
        assert_eq!(result["usable"], true);
    }
}
