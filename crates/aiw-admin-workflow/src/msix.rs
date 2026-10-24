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

const PS: &str = aiw_probe::powershell::POWERSHELL_EXECUTABLE;
const SSH: &str = r"C:\Windows\System32\OpenSSH\ssh.exe";
const TRANSPORT: &str = include_str!("../../../scripts/vm-msix/transport.ps1");
const RUNTIME_OBSERVER: &str = include_str!("../../../scripts/vm-msix/observe-runtime.ps1");
const PROVIDER: &str = include_str!("../../../scripts/vm-msix/proxmox-worker107.sh");
const PRODUCT: &str = "notepad-plus-plus-msix-vm107";
// The clean-source package builder compiles the native worker first, then pins
// its bytes into this host binary. A manifest beside the app cannot enroll code.
const EXPECTED_AGENT_SHA256: Option<&str> = option_env!("AIW_MSIX_WORKER_SHA256");

// The October24 bounded harness is historical source at abd17ea. Its completed
// nonce must never be replayed through this migrated execution baseline.

fn ps_executable() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = std::env::var_os("AIW_TEST_PWSH") {
        let path = PathBuf::from(path);
        assert!(
            path.is_absolute()
                && path
                    .file_name()
                    .is_some_and(|n| n.eq_ignore_ascii_case("pwsh.exe")),
            "Explicit absolute inert-test pwsh image required"
        );
        return path;
    }
    PathBuf::from(PS)
}

#[cfg(test)]
static POWERSHELL_TEST_PROCESS: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    #[cfg(test)]
    let _test_process = if command.get_program() == ps_executable().as_os_str() {
        Some(
            POWERSHELL_TEST_PROCESS
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
        )
    } else {
        None
    };
    #[cfg(not(test))]
    let runtime = if command.get_program() == std::ffi::OsStr::new(PS) {
        Some(
            aiw_windows_platform::observe_machine_powershell().map_err(|e| {
                anyhow!("Approved machine runtime unavailable before dispatch: {e}")
            })?,
        )
    } else {
        None
    };
    let program = command.get_program().to_string_lossy().into_owned();
    command
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().context("Missing transport stdout")?;
    let stderr = child.stderr.take().context("Missing transport stderr")?;
    let (out_tx, out_rx) = std::sync::mpsc::channel();
    let (err_tx, err_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(bound as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = out_tx.send(result);
    });
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stderr.take(65537).read_to_end(&mut bytes).map(|_| bytes);
        let _ = err_tx.send(result);
    });
    let start = Instant::now();
    let deadline = Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let errors = err_rx
                .try_recv()
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
            bail!(
                "Transport deadline exceeded after {seconds}s in {program}; dispatch is uncertain, never replay. Diagnostics: {}",
                String::from_utf8_lossy(&errors)
                    .chars()
                    .take(3000)
                    .collect::<String>()
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let bytes = out_rx.recv_timeout(deadline.saturating_sub(start.elapsed()))
        .map_err(|_| anyhow!("Transport stdout pipe remained open at {seconds}s deadline in {program}; dispatch is uncertain, never replay"))??;
    let errors = err_rx.recv_timeout(deadline.saturating_sub(start.elapsed()))
        .map_err(|_| anyhow!("Transport stderr pipe remained open at {seconds}s deadline in {program}; dispatch is uncertain, never replay"))??;
    #[cfg(not(test))]
    if let Some(runtime) = runtime {
        runtime
            .revalidate()
            .map_err(|e| anyhow!("Held runtime changed: {e}"))?;
    }
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
        || !value["checkpoint"].as_str().is_some_and(|v| {
            matches!(
                v,
                aiw_probe::MSIX_WORKER_CHECKPOINT | aiw_probe::MSIX_CORE_WORKER_CHECKPOINT
            )
        })
    {
        bail!("Exact reviewed VM107 provider response required")
    }
    if let Some(nonce) = nonce
        && value["nonce"] != nonce
    {
        bail!("Lease response nonce differs")
    }
    if let Some(profile) = expected
        && (value["checkpointConfigSha256"] != profile.checkpoint_config_sha256
            || value["providerSha256"] != profile.provider_sha256)
    {
        bail!("Approved recovery/provider identity drift")
    }
    Ok(value)
}
fn powershell_workspace_path(workspace: &Path) -> Result<PathBuf> {
    // Held workspace paths may carry the Win32 verbatim prefix. PowerShell's
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
    transport_file(
        &workspace.join("tools/transport.ps1"),
        operation,
        run_id,
        &workspace,
    )
}
fn transport_file(script: &Path, operation: &str, run_id: &str, workspace: &Path) -> Result<Value> {
    command_json(
        Command::new(ps_executable())
            // A desktop launched by PowerShell7 can inherit its module path.
            // Let the selected Core runtime initialize its own native providers/modules.
            .env_remove("PSModulePath")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(script)
            .args(["-Operation", operation, "-RunId", run_id, "-Workspace"])
            .arg(workspace),
        120,
        32 * 1024 * 1024,
    )
}

fn recovery_script(
    workspace: &HeldRunWorkspace,
) -> Result<aiw_windows_platform::BoundWorkspaceFile> {
    let name = format!("recovery-transport-{}.ps1", hash(TRANSPORT.as_bytes()));
    if !workspace.output_path().join(&name).exists() {
        let mut file = workspace
            .create_output_file_new(&format!("recovery-helper-{}.pending", super::nonce()))?;
        file.as_file_mut().write_all(TRANSPORT.as_bytes())?;
        file.as_file_mut().sync_all()?;
        let output = workspace.reopen_root_directory(
            "output",
            aiw_windows_platform::WorkspaceAclPolicy::Protected,
        )?;
        let mut file = file.publish_into_bound(&output, &name)?;
        file.as_file_mut().sync_all()?;
    }
    let file = workspace.reopen_output_file_readonly(&name)?;
    let mut bytes = Vec::new();
    file.as_file()
        .take(TRANSPORT.len() as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes != TRANSPORT.as_bytes() {
        bail!("Compiled recovery collector identity differs")
    }
    std::io::Seek::rewind(&mut file.as_file())?;
    file.revalidate()?;
    Ok(file)
}
fn recovery_transport(
    operation: &str,
    request: &MsixWorkerRequest,
    workspace: &HeldRunWorkspace,
) -> Result<Value> {
    if !matches!(operation, "Collect" | "Clean") {
        bail!("Recovery helper permits read-only collection/clean inspection only")
    }
    let script = recovery_script(workspace)?;
    let path = powershell_workspace_path(script.final_path())?;
    let root = powershell_workspace_path(workspace.root_path())?;
    let value = transport_file(&path, operation, &request.run_id, &root)?;
    script.revalidate()?;
    Ok(value)
}

fn observe_runtime_binding(
    workspace: &HeldRunWorkspace,
) -> Result<aiw_probe::powershell::PowerShellExecutionBinding> {
    let leaf = format!("runtime-observer-{}.ps1", hash(RUNTIME_OBSERVER.as_bytes()));
    let mut created = workspace.create_output_file_new(&leaf)?;
    created
        .as_file_mut()
        .write_all(RUNTIME_OBSERVER.as_bytes())?;
    created.as_file_mut().sync_all()?;
    created.revalidate()?;
    drop(created);
    let script = workspace.reopen_output_file_readonly(&leaf)?;
    let value = command_json(
        Command::new(ps_executable())
            .env_remove("PSModulePath")
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
            .arg(powershell_workspace_path(script.final_path())?),
        120,
        65536,
    )?;
    script.revalidate()?;
    if value["workerUuid"]
        .as_str()
        .is_none_or(|v| !v.eq_ignore_ascii_case(aiw_probe::MSIX_WORKER_UUID))
    {
        bail!("Runtime observation worker identity differs")
    }
    let binding = aiw_probe::powershell::PowerShellExecutionBinding {
        host: serde_json::from_value(value["host"].clone())?,
        worker: serde_json::from_value(value["worker"].clone())?,
        wsman: Some(serde_json::from_value(value["wsman"].clone())?),
        endpoint: value["endpoint"]
            .as_str()
            .context("Explicit runtime endpoint missing")?
            .into(),
    };
    binding.validate_execution().map_err(anyhow::Error::msg)?;
    Ok(binding)
}

fn write_tools(workspace: &HeldRunWorkspace, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = workspace.create_tools_file_new(name)?;
    file.as_file_mut().write_all(bytes)?;
    file.as_file_mut().sync_all()?;
    file.revalidate()?;
    Ok(())
}
fn stage(workspace: &HeldRunWorkspace, name: &str, value: &impl Serialize) -> Result<()> {
    // A crash may leave a uniquely named pending file, never a published proof.
    let mut file = workspace.create_output_file_new(&format!("pending-{}.json", super::nonce()))?;
    file.as_file_mut()
        .write_all(&serde_json::to_vec_pretty(value)?)?;
    file.as_file_mut().sync_all()?;
    file.revalidate()?;
    let output = workspace.reopen_root_directory(
        "output",
        aiw_windows_platform::WorkspaceAclPolicy::Protected,
    )?;
    let mut published = file.publish_into_bound(&output, &format!("{name}.json"))?;
    published.as_file_mut().sync_all()?;
    published.revalidate()?;
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

// The same state machine is exercised by failure-injection tests. The real
// implementation exposes only the fixed provider/transport verbs above.
trait VmOperations {
    fn provider(
        &mut self,
        op: &str,
        request: &MsixWorkerRequest,
        worker: &VmMsixWorkerProfile,
    ) -> Result<Value>;
    fn transport(
        &mut self,
        op: &str,
        request: &MsixWorkerRequest,
        workspace: &HeldRunWorkspace,
    ) -> Result<Value>;
    fn clean(&mut self, request: &MsixWorkerRequest, workspace: &HeldRunWorkspace)
    -> Result<Value>;
    fn pause(&mut self) {
        std::thread::sleep(Duration::from_secs(5));
    }
}
struct RealVm;
struct RecoveryVm;
impl VmOperations for RecoveryVm {
    fn provider(
        &mut self,
        op: &str,
        request: &MsixWorkerRequest,
        worker: &VmMsixWorkerProfile,
    ) -> Result<Value> {
        provider(op, Some(&request.nonce), Some(worker))
    }
    fn transport(
        &mut self,
        op: &str,
        request: &MsixWorkerRequest,
        workspace: &HeldRunWorkspace,
    ) -> Result<Value> {
        recovery_transport(op, request, workspace)
    }
    fn clean(
        &mut self,
        request: &MsixWorkerRequest,
        workspace: &HeldRunWorkspace,
    ) -> Result<Value> {
        let start = Instant::now();
        loop {
            if let Ok(value) = recovery_transport("Clean", request, workspace) {
                return Ok(value);
            }
            if start.elapsed() >= Duration::from_secs(360) {
                bail!("Restored clean inspection deadline exceeded")
            }
            self.pause();
        }
    }
}
impl VmOperations for RealVm {
    fn provider(
        &mut self,
        op: &str,
        request: &MsixWorkerRequest,
        worker: &VmMsixWorkerProfile,
    ) -> Result<Value> {
        provider(op, Some(&request.nonce), Some(worker))
    }
    fn transport(
        &mut self,
        op: &str,
        request: &MsixWorkerRequest,
        workspace: &HeldRunWorkspace,
    ) -> Result<Value> {
        transport(op, &request.run_id, workspace.root_path())
    }
    fn clean(
        &mut self,
        request: &MsixWorkerRequest,
        workspace: &HeldRunWorkspace,
    ) -> Result<Value> {
        wait_clean(workspace.root_path(), &request.run_id)
    }
}
fn ready_then_control(
    workspace: &HeldRunWorkspace,
    request: &MsixWorkerRequest,
    io: &mut impl VmOperations,
    deadline: Duration,
) -> Result<()> {
    let enrollment = read_stage(workspace, "enroll-status.json")?;
    let account = &enrollment["records"]["enroll-result"];
    let sid = account["userSid"]
        .as_str()
        .context("Enrolled SID missing")?;
    if account["runNonce"] != request.nonce {
        bail!("Enrollment nonce differs")
    }
    let start = Instant::now();
    loop {
        if let Ok(value) = io.transport("Ready", request, workspace) {
            if value["fatal"] == true
                || value["nonce"] != request.nonce
                || value["workerUuid"] != request.worker_uuid
                || value["userSid"] != sid
                || !sid.starts_with("S-1-5-21-3556347314-2314855617-1438300668-")
                || sid == "S-1-5-21-3556347314-2314855617-1438300668-1001"
            {
                bail!("Contradictory interactive readiness identity: {value}")
            }
            if value["ready"] == true {
                if value["sessionId"].as_u64().is_none_or(|id| id == 0)
                    || value["profileLoaded"] != true
                    || value["active"] != true
                    || value["accountBound"] != true
                {
                    bail!("Incomplete interactive readiness proof")
                }
                stage(workspace, "interactive-ready", &value)?;
                break;
            }
            if value["ready"] != false {
                bail!("Missing readiness state")
            }
        } // Only connection/read-only readiness may retry.
        if start.elapsed() >= deadline {
            bail!("Run-owned interactive session readiness deadline exceeded")
        }
        io.pause();
    }
    stage(workspace, "control-intent", &json!({"nonce":request.nonce}))?;
    stage(
        workspace,
        "control-dispatch",
        &io.transport("Control", request, workspace)?,
    )
}

fn read_export(workspace: &HeldRunWorkspace, request: &MsixWorkerRequest) -> Result<Value> {
    let marker = read_stage(workspace, "collection-authoritative-complete.json")?;
    if marker["nonce"] != request.nonce
        || marker["requestSha256"] != request.hash().map_err(anyhow::Error::msg)?
    {
        bail!("Export marker binding differs")
    }
    let leaf = marker["export"].as_str().context("Export name missing")?;
    let file = workspace.reopen_output_file(leaf)?;
    let mut bytes = Vec::new();
    file.as_file()
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 32 * 1024 * 1024 || marker["sha256"] != hash(&bytes) {
        bail!("Durable export differs")
    }
    file.revalidate()?;
    let value = serde_json::from_slice(&bytes)?;
    decode_collection(request, &value)?;
    require_dispatched_raw_source(workspace, &value)?;
    Ok(value)
}
fn require_dispatched_raw_source(workspace: &HeldRunWorkspace, value: &Value) -> Result<()> {
    if workspace.output_path().join("run-intent.json").exists()
        && value["rawEvidence"]["present"] != true
    {
        bail!("Host application dispatch intent requires authoritative raw source; preserve lease")
    }
    Ok(())
}
fn retain_export(
    workspace: &HeldRunWorkspace,
    request: &MsixWorkerRequest,
    io: &mut impl VmOperations,
) -> Result<Value> {
    if workspace
        .output_path()
        .join("collection-authoritative-complete.json")
        .exists()
    {
        return read_export(workspace, request);
    }
    let value = io.transport("Collect", request, workspace)?;
    decode_collection(request, &value)?;
    require_dispatched_raw_source(workspace, &value)?;
    let name = format!("collection-{}", super::nonce());
    stage(workspace, &name, &value)?;
    // Receipt last. A partial export never grants permission to erase the guest.
    stage(
        workspace,
        "collection-authoritative-complete",
        &json!({"nonce":request.nonce,"requestSha256":request.hash().map_err(anyhow::Error::msg)?,"export":format!("{name}.json"),"sha256":hash(&serde_json::to_vec_pretty(&value)?)}),
    )?;
    read_export(workspace, request)
}

fn cold_recover(
    workspace: &HeldRunWorkspace,
    request: &MsixWorkerRequest,
    worker: &VmMsixWorkerProfile,
    io: &mut impl VmOperations,
) -> Result<Value> {
    let intent_path = workspace.output_path().join("recovery-release-intent.json");
    let active = io.provider("inspect", request, worker).is_ok();
    let proofs = if intent_path.exists() {
        let value = read_stage(workspace, "recovery-release-intent.json")?;
        if value["nonce"] != request.nonce
            || value["requestSha256"] != request.hash().map_err(anyhow::Error::msg)?
        {
            bail!("Recovery attempt binding differs")
        }
        value
    } else if active {
        // A crash can precede collection entirely. Never erase the only copy.
        if workspace.output_path().join("stage-intent.json").exists() {
            retain_export(workspace, request, io).context(
                "Evidence collection required; original lease retained, rollback not dispatched",
            )?;
        }
        let restored = io.provider("restore", request, worker)?;
        let connected = io.provider("connect", request, worker)?;
        let clean = io.clean(request, workspace)?;
        let value = json!({"nonce":request.nonce,"requestSha256":request.hash().map_err(anyhow::Error::msg)?,"restore":restored,"connect":connected,"clean":clean});
        stage(workspace, "recovery-release-intent", &value)?;
        value
    } else {
        // Compatibility with an original-path release made before this fix.
        let value = json!({"nonce":request.nonce,"requestSha256":request.hash().map_err(anyhow::Error::msg)?,"restore":read_stage(workspace,"final-restore.json")?,"connect":read_stage(workspace,"final-connect.json")?,"clean":read_stage(workspace,"final-clean.json")?});
        stage(workspace, "recovery-release-intent", &value)?;
        value
    };
    // Validate the retained pre-release attempt before any release mutation.
    let mut checked = proofs.clone();
    let mut expected_release = checked["connect"].clone();
    expected_release["operation"] = json!("release");
    expected_release["phase"] = json!("none");
    expected_release["leasePresent"] = json!(false);
    checked["release"] = expected_release;
    verify_recovery_runtime(request, &checked)?;
    aiw_runner::verify_vm_msix_recovery(worker, &request.nonce, &checked)
        .map_err(anyhow::Error::msg)?;
    let released = io.provider(
        if active { "release" } else { "completed" },
        request,
        worker,
    )?;
    let mut proofs = proofs;
    proofs["release"] = released;
    aiw_runner::verify_vm_msix_recovery(worker, &request.nonce, &proofs)
        .map_err(anyhow::Error::msg)?;
    Ok(proofs)
}

fn verify_recovery_runtime(request: &MsixWorkerRequest, proofs: &Value) -> Result<()> {
    if let Some(runtime) = &request.power_shell_runtime {
        runtime.validate().map_err(anyhow::Error::msg)?;
        if proofs["clean"]["powerShellRuntime"] != serde_json::to_value(&runtime.worker)? {
            bail!("Restored Core runtime identity differs from the approved baseline; retain lease")
        }
        if let Some(wsman) = &runtime.wsman
            && proofs["clean"]["powerShellEndpoint"] != serde_json::to_value(wsman)?
        {
            bail!("Restored WSMan endpoint differs from the approved baseline; retain lease")
        }
    }
    Ok(())
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
    let host_runtime = aiw_windows_platform::observe_machine_powershell().map_err(|e| {
        anyhow!("Stable machine PowerShell Core >=7.6 setup is required before acquisition: {e}")
    })?;
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
    if proof["checkpoint"] != aiw_probe::MSIX_CORE_WORKER_CHECKPOINT {
        bail!(
            "PowerShell 7.6 migration requires separately approved VM107 runtime/endpoint provisioning and a newly pinned runtime-equipped cold baseline; the historical baseline cannot be acquired for migrated execution"
        )
    }
    let runtime_binding = observe_runtime_binding(&workspace)?;
    if runtime_binding.host != host_runtime.identity {
        bail!("Host runtime differs from the held preflight identity")
    }
    host_runtime
        .revalidate()
        .map_err(|e| anyhow!("Host runtime changed: {e}"))?;
    let worker = VmMsixWorkerProfile {
        schema_version: "aiw.dev/vm-msix-worker-profile/v0alpha1".into(),
        vm_id: 107,
        worker_uuid: aiw_probe::MSIX_WORKER_UUID.into(),
        worker_mac: "CC:34:21:B8:5A:31".into(),
        checkpoint: aiw_probe::MSIX_CORE_WORKER_CHECKPOINT.into(),
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
        power_shell_runtime: Some(runtime_binding.clone()),
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
    let nonce_value=command_json(Command::new(ps_executable()).args(["-NoProfile","-NonInteractive","-Command",&format!("{}\n{}", aiw_probe::powershell::POWERSHELL_RUNTIME_GUARD, "$r=[byte[]]::new(32);$g=[Security.Cryptography.RandomNumberGenerator]::Create();try{$g.GetBytes($r);ConvertTo-Json ([BitConverter]::ToString($r).Replace('-','').ToLowerInvariant())}finally{$g.Dispose()}")]),15,1024)?;
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
        power_shell_runtime: Some(runtime_binding.clone()),
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
        host_runtime
            .revalidate()
            .map_err(|e| anyhow!("Held approved host runtime differs before acquisition: {e}"))?;
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
        gate.progress("Verifying the native process control in the fresh standard-user session.");
        ready_then_control(&workspace, &request, &mut RealVm, Duration::from_secs(360))?;
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
    if let Err(error) = &execution {
        stage(
            &workspace,
            "execution-failed",
            &json!({"nonce":nonce,"error":error.to_string(),"automaticRetry":false}),
        )?;
    }
    gate.progress("Collecting bounded worker evidence before cold recovery.");
    let exported = if workspace.output_path().join("stage-intent.json").exists() {
        retain_export(&workspace, &request, &mut RealVm).map(Some)
    } else {
        // No Stage dispatch was possible; do not query an unrelated guest run
        // after a failed/uncertain acquire. Recovery still requires exact proof.
        Ok(None)
    };
    let collected = exported
        .as_ref()
        .map_err(|e| anyhow!(e.to_string()))
        .and_then(|value| value.as_ref().context("No guest intake was dispatched"))
        .and_then(|value| collect(&workspace, &request, value));
    if let Err(error) = &collected {
        let _ = stage(
            &workspace,
            "collection-failed",
            &json!({"error":error.to_string()}),
        );
    }
    if let Err(error) = exported {
        bail!(
            "Evidence collection required; VM107 and its original lease are preserved. Retry explicit recovery to collect without replaying application execution. {}: {error}",
            workspace.root_path().display()
        )
    }
    gate.progress("Restoring VM107 and verifying its clean identity, accounts, package state and TLS connection.");
    let recovery = (|| -> Result<()> {
        stage(&workspace, "recovery-intent", &json!({"nonce":nonce}))?;
        let proofs = cold_recover(&workspace, &request, &worker, &mut RealVm)?;
        for (name, field) in [
            ("final-restore", "restore"),
            ("final-connect", "connect"),
            ("final-clean", "clean"),
            ("lease-released", "release"),
        ] {
            stage(&workspace, name, &proofs[field])?;
        }
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
        // This field is a generic evidence root hash, not the folder path.
        // VM MSIX reports reverify their held native receipt/artifact inventory;
        // they do not currently publish a generic evidence root hash.
        None,
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

fn decode_collection(
    request: &MsixWorkerRequest,
    value: &Value,
) -> Result<BTreeMap<String, Vec<u8>>> {
    if value["nonce"] != request.nonce {
        bail!("Collected nonce differs")
    }
    if value["quiescent"] != true {
        bail!("Worker is still running; retain lease and evidence")
    }
    if value["enumerationComplete"] != true {
        bail!("Incomplete evidence enumeration; retain lease and evidence")
    }
    let entries = value["files"]
        .as_array()
        .context("Evidence file list missing")?;
    if entries.len() > 512 {
        bail!("Evidence file count exceeded")
    }
    let mut files = BTreeMap::new();
    let mut total = 0;
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
    let raw = &value["rawEvidence"];
    if raw["complete"] != true
        || raw["source"] != "runOwnedProfile"
        || raw["nonce"] != request.nonce
    {
        bail!("Authoritative raw source completeness proof required")
    }
    let inventory = raw["files"]
        .as_array()
        .context("Raw evidence inventory missing")?;
    let mut names = std::collections::BTreeSet::new();
    for entry in inventory {
        let name = entry["path"].as_str().context("Raw evidence path absent")?;
        let bytes = files.get(name).context("Authoritative raw file absent")?;
        if !name.starts_with("raw/")
            || !names.insert(name.to_owned())
            || entry["sha256"] != hash(bytes)
            || entry["bytes"] != bytes.len() as u64
        {
            bail!("Authoritative raw evidence inventory differs")
        }
    }
    if names
        != files
            .keys()
            .filter(|name| name.starts_with("raw/"))
            .cloned()
            .collect()
    {
        bail!("Authoritative raw evidence file set differs")
    }
    if raw["present"] == true {
        let sid = raw["userSid"]
            .as_str()
            .context("Raw evidence SID missing")?;
        if !sid.starts_with("S-1-5-21-3556347314-2314855617-1438300668-")
            || sid == "S-1-5-21-3556347314-2314855617-1438300668-1001"
            || names.is_empty()
        {
            bail!("Authoritative raw evidence identity/files missing")
        }
    } else if raw["present"] != false
        || !names.is_empty()
        || ["run-dispatch.json", "run-started.json", "result.json"]
            .iter()
            .any(|name| files.contains_key(*name))
    {
        bail!("Dispatched application raw evidence missing")
    }
    Ok(files)
}
fn collect(workspace: &HeldRunWorkspace, request: &MsixWorkerRequest, value: &Value) -> Result<()> {
    let files = decode_collection(request, value)?;
    let destination = workspace.create_output_directory_new("guest")?;
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
    if let Some(runtime) = &request.power_shell_runtime {
        let lifecycle_worker = receipt("evidence/msix-lifecycle/worker.json")?;
        runtime
            .verify_worker_receipts(&[&terminal, &control, &lifecycle_worker])
            .map_err(anyhow::Error::msg)?;
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
    if request.power_shell_runtime != held.preparation.power_shell_runtime {
        bail!("Original preparation/request runtime bindings differ")
    }
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
    if !held
        .workspace
        .output_path()
        .join("recovery-release-intent.json")
        .exists()
    {
        request.execution_runtime().map_err(|e| anyhow!("Incompatible outstanding legacy preparation; original inputs and lease are preserved. Obtain an explicit recovery/setup plan: {e}"))?;
    }
    gate.progress("Collecting retained evidence and recovering the exact VM107 lease without application replay.");
    let proofs = cold_recover(&held.workspace, &request, worker, &mut RecoveryVm)?;
    stage(&held.workspace, "recovery-complete", &proofs)?;
    finish_recovery(&layout, &held.workspace, &request, worker)
}
fn finish_recovery(
    layout: &RunLayout,
    workspace: &HeldRunWorkspace,
    request: &MsixWorkerRequest,
    worker: &VmMsixWorkerProfile,
) -> Result<Value> {
    persist_recovery_result(layout, workspace, request, worker)?;
    read_report(workspace.root_path(), &request.run_id)
}
fn persist_recovery_result(
    layout: &RunLayout,
    workspace: &HeldRunWorkspace,
    request: &MsixWorkerRequest,
    worker: &VmMsixWorkerProfile,
) -> Result<()> {
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
    Ok(())
}

#[cfg(test)]
mod transport_path_tests {
    use super::*;
    #[test]
    fn exited_transport_with_descendant_held_pipe_respects_original_deadline() {
        // Fixed inert child: no AIW/worker dispatch, and its descendants exit
        // after three local loopback pings even if this assertion fails.
        let start = Instant::now();
        let error = command_json(
            Command::new(r"C:\Windows\System32\cmd.exe").args([
                "/d",
                "/c",
                "start /b cmd.exe /d /c ping.exe -n 4 127.0.0.1 ^>nul & exit /b 0",
            ]),
            1,
            4096,
        )
        .unwrap_err();
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "Pipe observer exceeded the fixed deadline: {error:#}"
        );
        assert!(
            error.to_string().contains("pipe remained open"),
            "{error:#}"
        );
    }

    #[test]
    fn authoritative_export_regressions_execute_actual_core_collector() {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/vm-msix/tests/test-authoritative-export.ps1");
        let value = command_json(Command::new(ps_executable()).env_remove("PSModulePath")
            .env("AIW_EXPORT_REGRESSION",script)
            .args(["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command","$ErrorActionPreference='Stop'; & $env:AIW_EXPORT_REGRESSION | Out-Null; @{passed=$true;applicationExecuted=$false}|ConvertTo-Json -Compress"]),120,4096).unwrap();
        assert_eq!(value["passed"], true);
    }

    #[test]
    fn collect_transport_does_not_suppress_enumeration_failure_in_core() {
        let value = command_json(Command::new(ps_executable()).env_remove("PSModulePath")
            .env("AIW_COLLECTION_TEST_SOURCE", TRANSPORT)
            .args(["-NoProfile", "-NonInteractive", "-Command", r#"$ErrorActionPreference='Stop';$t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseInput($env:AIW_COLLECTION_TEST_SOURCE,[ref]$t,[ref]$e);if($e.Count){throw ($e|Out-String)};$b=@($a.FindAll({param($n)$n -is [Management.Automation.Language.ScriptBlockExpressionAst] -and $n.ScriptBlock.ParamBlock -and $n.ScriptBlock.ParamBlock.Parameters.Count -eq 2 -and $n.Extent.Text.Contains('enumerationComplete')},$true));if($b.Count -ne 1){throw 'One fixed export block required'};function Get-ScheduledTask {};function Get-Process {};function Test-Path {param($LiteralPath) $LiteralPath -ceq 'C:\AIWTest'};function Get-Item {[pscustomobject]@{Attributes=[IO.FileAttributes]::Directory}};function Get-ChildItem {throw 'injected export enumeration failure'};$block=$b[0].ScriptBlock.GetScriptBlock();try{$null=& $block 'C:\AIWTest' ('a'*64);throw 'Enumeration error swallowed'}catch{if($_.Exception.Message -cne 'injected export enumeration failure'){throw};@{rejected=$true;applicationExecuted=$false}|ConvertTo-Json -Compress}"#]),30,4096).unwrap();
        assert_eq!(value["rejected"], true);
    }

    #[test]
    fn readiness_transport_parses_and_readonly_wts_observer_compiles_in_core() {
        let value = command_json(Command::new(ps_executable()).env_remove("PSModulePath")
            .env("AIW_READINESS_TEST_SOURCE", TRANSPORT)
            .args(["-NoProfile", "-NonInteractive", "-Command", r#"$ErrorActionPreference='Stop';$t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseInput($env:AIW_READINESS_TEST_SOURCE,[ref]$t,[ref]$e);if($e.Count){throw ($e|Out-String)};$c=@($a.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Type'},$true));if($c.Count -ne 2){throw 'One fixed native observer required'};$s=@($c[0].CommandElements|Where-Object{$_ -is [Management.Automation.Language.StringConstantExpressionAst]})[-1].Value;Add-Type -TypeDefinition $s;@{compiled=([AiwReadiness].GetMethod('Active') -ne $null);applicationExecuted=$false}|ConvertTo-Json -Compress"#]),30,4096).unwrap();
        assert_eq!(value["compiled"], true);
        assert_eq!(value["applicationExecuted"], false);
    }

    #[test]
    fn held_canonical_workspace_is_usable_by_powershell_filesystem_provider() {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = powershell_workspace_path(&root).unwrap();
        let result = command_json(
            Command::new(ps_executable())
                .env_remove("PSModulePath")
                .args(["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; $p=Join-Path $env:AIW_MSIX_PATH_TEST 'tools'; $cert=Get-Item Cert:\\CurrentUser; @{ usable=($p -like '*\\tools') -and (Test-Path -LiteralPath $env:AIW_MSIX_PATH_TEST); certificateProvider=$cert.PSProvider.Name } | ConvertTo-Json -Compress"])
                .env("AIW_MSIX_PATH_TEST", &path),
            30,
            4096,
        ).unwrap();
        assert_eq!(result["usable"], true);
        assert_eq!(result["certificateProvider"], "Certificate");
    }
}

#[cfg(test)]
mod failure_sequence_tests {
    use super::*;
    use std::collections::VecDeque;

    fn fixture() -> (
        HeldRunWorkspace,
        RunLayout,
        MsixWorkerRequest,
        VmMsixWorkerProfile,
    ) {
        let parent = std::env::temp_dir().join(format!("mw-{}", super::super::nonce()));
        std::fs::create_dir(&parent).unwrap();
        let root = create_evidence_root(&parent, "msix-review-test").unwrap();
        let workspace = HeldRunWorkspace::create(&root, "workspace").unwrap();
        let worker: VmMsixWorkerProfile = serde_json::from_value(json!({"schemaVersion":"aiw.dev/vm-msix-worker-profile/v0alpha1","vmId":107,"workerUuid":aiw_probe::MSIX_WORKER_UUID,"workerMac":"CC:34:21:B8:5A:31","checkpoint":aiw_probe::MSIX_WORKER_CHECKPOINT,"checkpointConfigSha256":"c".repeat(64),"providerSha256":"d".repeat(64),"hypervisorAddress":"192.168.1.6","hypervisorHostKeySha256":"SHA256:J/kc0UwUBil5TFBQbQhwBoRKnDoRlZ8ggXAhmYEpq1E","httpsAddress":"192.168.1.174","httpsCertificateSha1":"BC14DCC4E37F83161EBB55AF8624E36A79E19256"})).unwrap();
        let plan = RunPlan::new(
            "msix-review-test",
            PRODUCT,
            "e".repeat(64),
            RunLifecycleKind::Assessment,
            "2026-10-23T00:00:00Z",
            vec![
                PlannedAction::AssessHost,
                PlannedAction::ExecuteScenario {
                    scenario_id: "install".into(),
                },
            ],
            vec![],
        )
        .unwrap();
        let layout = RunLayout::new(workspace.root_path(), &plan.run_id).unwrap();
        layout.create(&plan).unwrap();
        layout
            .write_approval(
                &ApprovalRecord::for_plan(&plan, "reviewer", "2026-10-23T00:00:01Z").unwrap(),
            )
            .unwrap();
        let request = MsixWorkerRequest {
            schema_version: aiw_probe::MSIX_WORKER_REQUEST_SCHEMA.into(),
            run_id: plan.run_id.clone(),
            nonce: "a".repeat(64),
            recipe: VmMsixRecipe::Notepad898MediumFullTrust,
            plan_sha256: plan.hash().unwrap(),
            worker_profile_sha256: worker.hash().unwrap(),
            agent_sha256: "b".repeat(64),
            package_sha256: aiw_probe::MSIX_PACKAGE_SHA256.into(),
            assembly_sha256: aiw_probe::MSIX_ASSEMBLY_SHA256.into(),
            signing_sha256: aiw_probe::MSIX_SIGNING_SHA256.into(),
            worker_uuid: aiw_probe::MSIX_WORKER_UUID.into(),
            power_shell_runtime: None,
            not_before_file_time: 100,
            not_after_file_time: 18_000_000_100,
        };
        stage(&workspace, "stage-intent", &json!({"nonce":request.nonce})).unwrap();
        stage(&workspace,"enroll-status",&json!({"records":{"enroll-result":{"runNonce":request.nonce,"userSid":"S-1-5-21-3556347314-2314855617-1438300668-1006"}}})).unwrap();
        (workspace, layout, request, worker)
    }
    #[derive(Default)]
    struct MockVm {
        calls: Vec<String>,
        released: bool,
        lose_release_reply: bool,
        fail_collection: bool,
        incomplete_collection: bool,
        ready: VecDeque<Value>,
    }
    impl VmOperations for MockVm {
        fn provider(
            &mut self,
            op: &str,
            request: &MsixWorkerRequest,
            worker: &VmMsixWorkerProfile,
        ) -> Result<Value> {
            self.calls.push(op.into());
            if op == "inspect" && self.released {
                bail!("No active lease")
            }
            if op == "release" {
                self.released = true;
                if self.lose_release_reply {
                    bail!("Reply lost after remote release")
                }
            }
            let phase = match op {
                "restore" => "restored",
                "release" => "none",
                _ => "online-clean",
            };
            Ok(
                json!({"schemaVersion":"aiw.dev/vm-msix-hypervisor/v0alpha1","operation":op,"phase":phase,"leasePresent":!self.released,"vmId":107,"workerUuid":worker.worker_uuid,"nonce":request.nonce,"checkpoint":worker.checkpoint,"checkpointConfigSha256":worker.checkpoint_config_sha256,"providerSha256":worker.provider_sha256,"running":true}),
            )
        }
        fn transport(
            &mut self,
            op: &str,
            request: &MsixWorkerRequest,
            _: &HeldRunWorkspace,
        ) -> Result<Value> {
            self.calls.push(op.into());
            match op {
                "Collect" if self.fail_collection => bail!("Temporary WinRM export failure"),
                "Collect" => {
                    let bytes = b"retained failure diagnostics";
                    Ok(
                        json!({"nonce":request.nonce,"quiescent":true,"enumerationComplete":!self.incomplete_collection,"rawEvidence":{"complete":true,"source":"runOwnedProfile","nonce":request.nonce,"present":true,"userSid":"S-1-5-21-3556347314-2314855617-1438300668-1006","files":[{"path":"raw/failure.txt","sha256":hash(bytes),"bytes":bytes.len()}]},"files":[{"path":"raw/failure.txt","sha256":hash(bytes),"bytes":bytes.len(),"base64":base64::engine::general_purpose::STANDARD.encode(bytes)}]}),
                    )
                }
                "Ready" => self
                    .ready
                    .pop_front()
                    .context("Readiness transport unavailable"),
                "Control" => Ok(json!({"dispatched":true,"nonce":request.nonce})),
                _ => panic!("Unexpected operation: {op}"),
            }
        }
        fn clean(&mut self, request: &MsixWorkerRequest, _: &HeldRunWorkspace) -> Result<Value> {
            self.calls.push("Clean".into());
            Ok(
                json!({"clean":true,"workerUuid":request.worker_uuid,"trialArtifactsAbsent":true,"automaticSignInDisabled":true}),
            )
        }
        fn pause(&mut self) {}
    }
    fn terminal(
        workspace: &HeldRunWorkspace,
        layout: &RunLayout,
        request: &MsixWorkerRequest,
        worker: &VmMsixWorkerProfile,
        proofs: &Value,
    ) {
        stage(workspace, "recovery-complete", proofs).unwrap();
        persist_recovery_result(layout, workspace, request, worker).unwrap();
        let snapshot = layout.completed_snapshot().unwrap();
        assert!(snapshot.result.cleanup_complete);
        assert_eq!(snapshot.result.outcome, RunOutcome::Failed);
    }
    #[test]
    fn resumed_recovery_finalizes_after_lost_release_reply_without_original_final_files() {
        let (workspace, layout, request, worker) = fixture();
        let mut io = MockVm {
            lose_release_reply: true,
            ..Default::default()
        };
        assert!(cold_recover(&workspace, &request, &worker, &mut io).is_err());
        assert!(
            workspace
                .output_path()
                .join("recovery-release-intent.json")
                .exists()
        );
        assert!(!workspace.output_path().join("final-restore.json").exists());
        io.calls.clear();
        let proofs = cold_recover(&workspace, &request, &worker, &mut io).unwrap();
        terminal(&workspace, &layout, &request, &worker, &proofs);
        assert_eq!(io.calls, vec!["inspect", "completed"]);
    }
    #[test]
    fn resumed_recovery_finalizes_after_interruption_immediately_after_release() {
        let (workspace, layout, request, worker) = fixture();
        let mut io = MockVm::default();
        let _lost = cold_recover(&workspace, &request, &worker, &mut io).unwrap();
        assert!(
            !workspace
                .output_path()
                .join("recovery-complete.json")
                .exists()
        );
        io.calls.clear();
        let proofs = cold_recover(&workspace, &request, &worker, &mut io).unwrap();
        terminal(&workspace, &layout, &request, &worker, &proofs);
        assert_eq!(io.calls, vec!["inspect", "completed"]);
    }
    #[test]
    fn failed_collection_retains_lease_and_guest_until_readonly_retry_exports_bytes() {
        let (workspace, _, request, worker) = fixture();
        let mut io = MockVm {
            fail_collection: true,
            ..Default::default()
        };
        assert!(cold_recover(&workspace, &request, &worker, &mut io).is_err());
        assert_eq!(io.calls, vec!["inspect", "Collect"]);
        assert!(!io.released);
        io.fail_collection = false;
        cold_recover(&workspace, &request, &worker, &mut io).unwrap();
        assert!(read_export(&workspace, &request).is_ok());
        assert!(
            io.calls.iter().position(|c| c == "restore").unwrap()
                > io.calls.iter().rposition(|c| c == "Collect").unwrap()
        );
        assert!(
            !io.calls
                .iter()
                .any(|c| matches!(c.as_str(), "acquire" | "Run" | "Control" | "Enroll"))
        );
    }
    #[test]
    fn incomplete_enumeration_cannot_publish_export_marker_or_dispatch_rollback() {
        let (workspace, _, request, worker) = fixture();
        let mut io = MockVm {
            incomplete_collection: true,
            ..Default::default()
        };
        assert!(cold_recover(&workspace, &request, &worker, &mut io).is_err());
        assert_eq!(io.calls, vec!["inspect", "Collect"]);
        assert!(
            !workspace
                .output_path()
                .join("collection-authoritative-complete.json")
                .exists()
        );
        assert!(!io.released);
    }
    #[test]
    fn old_prepared_inputs_stay_unchanged_while_current_readonly_helper_recovers() {
        let (workspace, _, request, worker) = fixture();
        let old = b"param($Operation) # original transport: no authoritative export protocol";
        write_tools(&workspace, "transport.ps1", old).unwrap();
        for leaf in ["agent.exe", "request.json", "assembly.json", "signing.json"] {
            write_tools(&workspace, leaf, b"approved input bytes").unwrap();
        }
        stage(
            &workspace,
            "collection-complete",
            &json!({"nonce":request.nonce,"legacy":true}),
        )
        .unwrap();
        let old_hold = workspace
            .reopen_tools_file_readonly("transport.ps1")
            .unwrap();
        let helper = recovery_script(&workspace).unwrap();
        assert_ne!(helper.final_path(), old_hold.final_path());
        let mut helper_bytes = Vec::new();
        helper.as_file().read_to_end(&mut helper_bytes).unwrap();
        assert_eq!(helper_bytes, TRANSPORT.as_bytes());
        assert!(recovery_transport("Run", &request, &workspace).is_err());
        let mut io = MockVm::default();
        cold_recover(&workspace, &request, &worker, &mut io).unwrap();
        assert!(io.calls.contains(&"Collect".into()));
        for leaf in [
            "transport.ps1",
            "agent.exe",
            "request.json",
            "assembly.json",
            "signing.json",
        ] {
            let file = workspace.reopen_tools_file_readonly(leaf).unwrap();
            let mut bytes = Vec::new();
            file.as_file().read_to_end(&mut bytes).unwrap();
            assert_eq!(
                bytes,
                if leaf == "transport.ps1" {
                    old.as_slice()
                } else {
                    b"approved input bytes".as_slice()
                }
            );
        }
        assert_eq!(
            read_stage(&workspace, "collection-complete.json").unwrap()["legacy"],
            true
        );
        assert!(read_export(&workspace, &request).is_ok());
    }
    #[test]
    fn held_recovery_helper_is_readable_by_supported_core_without_releasing_identity() {
        let (workspace, _, _, _) = fixture();
        let helper = recovery_script(&workspace).unwrap();
        let value=command_json(Command::new(ps_executable()).env_remove("PSModulePath")
            .env("AIW_HELD_RECOVERY_SCRIPT",powershell_workspace_path(helper.final_path()).unwrap())
            .args(["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop';$s=[IO.File]::ReadAllText($env:AIW_HELD_RECOVERY_SCRIPT);$null=[ScriptBlock]::Create($s);@{parsed=$true}|ConvertTo-Json -Compress"]),30,4096).unwrap();
        assert_eq!(value["parsed"], true);
        helper.revalidate().unwrap();
        assert!(
            workspace
                .reopen_output_file(helper.final_path().file_name().unwrap().to_str().unwrap())
                .is_err()
        );
    }
    #[test]
    fn old_format_export_never_bypasses_authoritative_completeness() {
        let (workspace, _, request, worker) = fixture();
        stage(
            &workspace,
            "collection-complete",
            &json!({"nonce":request.nonce,"legacy":true}),
        )
        .unwrap();
        let mut io = MockVm {
            fail_collection: true,
            ..Default::default()
        };
        assert!(cold_recover(&workspace, &request, &worker, &mut io).is_err());
        assert_eq!(io.calls, vec!["inspect", "Collect"]);
        io.fail_collection = false;
        let mut value = io.transport("Collect", &request, &workspace).unwrap();
        value.as_object_mut().unwrap().remove("rawEvidence");
        assert!(decode_collection(&request, &value).is_err());
        value["rawEvidence"] = json!({"complete":true,"source":"runOwnedProfile","nonce":request.nonce,"present":true,"userSid":"S-1-5-21-3556347314-2314855617-1438300668-1006","files":[]});
        assert!(decode_collection(&request, &value).is_err());
    }
    #[test]
    fn host_dispatch_intent_rejects_absent_source_even_when_guest_markers_are_missing() {
        let (workspace, _, request, _) = fixture();
        stage(&workspace, "run-intent", &json!({"nonce":request.nonce})).unwrap();
        let value = json!({"nonce":request.nonce,"quiescent":true,"enumerationComplete":true,"files":[],"rawEvidence":{"complete":true,"source":"runOwnedProfile","nonce":request.nonce,"present":false,"files":[]}});
        assert!(decode_collection(&request, &value).is_ok());
        assert!(require_dispatched_raw_source(&workspace, &value).is_err());
    }
    #[test]
    fn crash_before_collection_exports_before_rollback_and_failed_lifecycle_can_clean() {
        let (workspace, _, request, worker) = fixture();
        let mut io = MockVm::default();
        let exported = retain_export(&workspace, &request, &mut io).unwrap();
        // The complete raw export survives even though its lifecycle is failed.
        assert!(collect(&workspace, &request, &exported).is_err());
        assert!(read_export(&workspace, &request).is_ok());
        cold_recover(&workspace, &request, &worker, &mut io).unwrap();
        assert_eq!(
            io.calls
                .iter()
                .filter(|op| op.as_str() == "Collect")
                .count(),
            1
        );
        assert!(io.released);
    }
    fn readiness(request: &MsixWorkerRequest, ready: bool) -> Value {
        json!({"nonce":request.nonce,"workerUuid":request.worker_uuid,"userSid":"S-1-5-21-3556347314-2314855617-1438300668-1006","ready":ready,"active":ready,"profileLoaded":ready,"accountBound":true,"sessionId":if ready {1} else {0}})
    }
    #[test]
    fn reachable_winrm_waits_for_interactive_readiness_before_one_control_dispatch() {
        let (workspace, _, request, _) = fixture();
        let mut io = MockVm {
            ready: VecDeque::from([
                readiness(&request, false),
                readiness(&request, false),
                readiness(&request, true),
            ]),
            ..Default::default()
        };
        ready_then_control(&workspace, &request, &mut io, Duration::from_secs(5)).unwrap();
        assert_eq!(io.calls, vec!["Ready", "Ready", "Ready", "Control"]);
    }
    #[test]
    fn readiness_timeout_or_wrong_user_session_never_dispatches_control() {
        for mutation in ["timeout", "userSid", "sessionId", "profileLoaded", "nonce"] {
            let (workspace, _, request, _) = fixture();
            let mut value = readiness(&request, mutation != "timeout");
            match mutation {
                "userSid" => {
                    value["userSid"] = json!("S-1-5-21-3556347314-2314855617-1438300668-1007")
                }
                "sessionId" => value["sessionId"] = json!(0),
                "profileLoaded" => value["profileLoaded"] = json!(false),
                "nonce" => value["nonce"] = json!("b".repeat(64)),
                _ => {}
            }
            let mut io = MockVm {
                ready: VecDeque::from([value]),
                ..Default::default()
            };
            assert!(
                ready_then_control(&workspace, &request, &mut io, Duration::ZERO).is_err(),
                "{mutation}"
            );
            assert_eq!(io.calls, vec!["Ready"]);
        }
    }
}
