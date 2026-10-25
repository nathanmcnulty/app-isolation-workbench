//! Fresh, explicitly opted-in Core 7.6.7 VM107 control/fixture acceptance.
//! This test never dispatches Run and cannot resume a previous native trial.
use super::*;

const OPT_IN: &str = "core76-vm107-bounded-v1";
const FIXTURE_SCRIPT: &str =
    include_str!("../../../../scripts/vm-msix/tests/invoke-core76-bounded-fixture.ps1");

struct RecoveryGate;
impl ApprovalGate for RecoveryGate {
    fn progress(&self, message: &str) {
        eprintln!("{message}");
    }
    fn review(&self, _: &ApprovalReview) -> Result<Option<String>> {
        bail!("Recovery must use the retained approval")
    }
    fn wait_for_start(&self, _: &ApprovalReview) -> Result<bool> {
        Ok(false)
    }
}
struct DelayedControl {
    pending: usize,
    ready: usize,
    controls: usize,
    restarted: bool,
}
impl VmOperations for DelayedControl {
    fn provider(
        &mut self,
        _: &str,
        _: &MsixWorkerRequest,
        _: &VmMsixWorkerProfile,
    ) -> Result<Value> {
        bail!("Readiness cannot mutate the provider")
    }
    fn clean(&mut self, _: &MsixWorkerRequest, _: &HeldRunWorkspace) -> Result<Value> {
        bail!("Readiness cannot restore")
    }
    fn transport(
        &mut self,
        op: &str,
        request: &MsixWorkerRequest,
        workspace: &HeldRunWorkspace,
    ) -> Result<Value> {
        match op {
            "Ready" => {
                let script = recovery_script(workspace)?;
                let value = transport_file(
                    &powershell_workspace_path(script.final_path())?,
                    "Ready",
                    &request.run_id,
                    &powershell_workspace_path(workspace.root_path())?,
                )?;
                script.revalidate()?;
                if value["ready"] == false && value["fatal"] != true {
                    self.pending += 1;
                    stage(
                        workspace,
                        &format!("acceptance-ready-pending-{}", self.pending),
                        &value,
                    )?;
                    if !self.restarted {
                        eprintln!(
                            "WinRM reachable with no interactive session; delaying restart for five seconds. Control dispatch count is zero."
                        );
                        std::thread::sleep(Duration::from_secs(5));
                        stage(
                            workspace,
                            "restart-intent",
                            &json!({"nonce":request.nonce,"boundedAcceptance":true}),
                        )?;
                        let restart = transport("Restart", &request.run_id, workspace.root_path())?;
                        stage(workspace, "restart-dispatch", &restart)?;
                        self.restarted = true;
                    }
                }
                if value["ready"] == true {
                    self.ready += 1;
                }
                Ok(value)
            }
            "Control" => {
                if self.pending == 0 || self.ready == 0 || self.controls != 0 {
                    bail!("Delayed readiness/control sequence differs")
                }
                self.controls += 1;
                transport("Control", &request.run_id, workspace.root_path())
            }
            _ => bail!("Bounded acceptance never dispatches {op}"),
        }
    }
}
fn fixture(mode: &str, workspace: &HeldRunWorkspace, request: &MsixWorkerRequest) -> Result<Value> {
    if !matches!(
        mode,
        "CreateRawWithNamedStream"
            | "ClearNamedStream"
            | "AddPartialCache"
            | "QueuedConsumerRegression"
    ) {
        bail!("Unsupported closed acceptance fixture mode")
    }
    stage(
        workspace,
        &format!("acceptance-fixture-intent-{}", mode.to_ascii_lowercase()),
        &json!({"nonce":request.nonce,"mode":mode,"automaticRetry":false}),
    )?;
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/vm-msix/tests/invoke-core76-bounded-fixture.ps1");
    let held = HeldApplicationFile::open_bounded(&path, 65536)?;
    if held.read_bounded(65536)? != FIXTURE_SCRIPT.as_bytes() {
        bail!("Fixed acceptance fixture source differs")
    }
    let collector = recovery_script(workspace)?;
    let value = command_json(
        Command::new(PS)
            .env_remove("PSModulePath")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&path)
            .args(["-Mode", mode, "-Workspace"])
            .arg(powershell_workspace_path(workspace.root_path())?)
            .args([
                "-RequestSha256",
                &request.hash().map_err(anyhow::Error::msg)?,
                "-RequestFileSha256",
                &hash(&serde_json::to_vec(request)?),
            ])
            .args(["-TransportPath"])
            .arg(powershell_workspace_path(collector.final_path())?)
            .args(["-TransportSha256", &hash(TRANSPORT.as_bytes())]),
        120,
        65536,
    )?;
    held.revalidate()?;
    collector.revalidate()?;
    Ok(value)
}
fn assert_raw(value: &Value, request: &MsixWorkerRequest) -> Result<()> {
    let files = decode_collection(request, value)?;
    let expected = b"AIW Core76 bounded raw evidence acceptance\r\n";
    if files
        .get("raw/msix-lifecycle/document.txt")
        .map(Vec::as_slice)
        != Some(expected.as_slice())
        || value["rawEvidence"]["files"].as_array().map(Vec::len) != Some(3)
        || files
            .get("raw/msix-lifecycle/probe.json")
            .map(Vec::as_slice)
            != Some(b"{\"acceptanceFixture\":true,\"applicationExecuted\":false}".as_slice())
    {
        bail!("Bounded authoritative fixture bytes/count differ")
    }
    let started: Value = serde_json::from_slice(
        files
            .get("raw/child-started.json")
            .context("Authoritative child fixture missing")?,
    )?;
    if started["nonce"] != request.nonce
        || started["applicationExecuted"] != false
        || started["acceptanceFixture"] != true
    {
        bail!("Authoritative fixture nonce/content differs")
    }
    Ok(())
}

/// Independently supplied receipt/worker hashes are required. Holding every
/// exact payload prevents replacement during preparation; this verifier never
/// executes any package image or accepts paths from an unbounded manifest.
fn verify_fresh_package(
    root: &Path,
    revision: &str,
    receipt_sha: &str,
    worker_sha: &str,
) -> Result<Vec<HeldApplicationFile>> {
    const PAYLOAD: [&str; 6] = [
        "LICENSE",
        "README.txt",
        "aiw-desktop.exe",
        "product/msix-worker107/agent.exe",
        "product/msix-worker107/assembly.json",
        "product/msix-worker107/signing.json",
    ];
    let receipt = HeldApplicationFile::open_bounded(&root.join("receipt.json"), 65536)?;
    let bytes = receipt.read_bounded(65536)?;
    if hash(&bytes) != receipt_sha {
        bail!("Independently supplied package receipt differs")
    }
    let manifest: Value = serde_json::from_slice(&bytes)?;
    if manifest["schemaVersion"] != "aiw.dev/msix-desktop-package/v0alpha1"
        || manifest["sourceRevision"] != revision
        || manifest["workerSha256"] != worker_sha
        || manifest["receiptLast"] != true
        || manifest["unsigned"] != true
    {
        bail!("Fresh unsigned source package receipt identity differs")
    }
    let records = manifest["files"]
        .as_array()
        .context("Package inventory absent")?;
    if records.len() != PAYLOAD.len() {
        bail!("Exact six-file native package required")
    }
    let mut held = vec![receipt];
    for leaf in PAYLOAD {
        let matches = records
            .iter()
            .filter(|r| r["path"] == leaf)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            bail!("Missing/duplicate approved payload: {leaf}")
        }
        let record = matches[0];
        let expected = record["sha256"].as_str().context("Payload SHA256 absent")?;
        let size = record["bytes"].as_u64().context("Payload size absent")?;
        if !valid_sha256(expected) || size == 0 || size > 128 * 1024 * 1024 {
            bail!("Payload identity/bound differs")
        }
        let file = HeldApplicationFile::open_bounded(&root.join(leaf), 128 * 1024 * 1024)?;
        let bytes = file.read_bounded(128 * 1024 * 1024)?;
        if bytes.len() as u64 != size || hash(&bytes) != expected {
            bail!("Fresh package payload differs: {leaf}")
        }
        let pinned = match leaf {
            "product/msix-worker107/agent.exe" => Some(worker_sha),
            "product/msix-worker107/assembly.json" => Some(aiw_probe::MSIX_ASSEMBLY_SHA256),
            "product/msix-worker107/signing.json" => Some(aiw_probe::MSIX_SIGNING_SHA256),
            _ => None,
        };
        if pinned.is_some_and(|p| expected != p) {
            bail!("Fixed packaged worker/metadata differs: {leaf}")
        }
        file.revalidate()?;
        held.push(file);
    }
    fn inventory(root: &Path, at: &Path, depth: u8, result: &mut Vec<String>) -> Result<()> {
        use std::os::windows::fs::MetadataExt;
        if depth > 3 || std::fs::symlink_metadata(at)?.file_attributes() & 0x400 != 0 {
            bail!("Unexpected package directory/reparse point")
        }
        for entry in std::fs::read_dir(at)? {
            let path = entry?.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.file_attributes() & 0x400 != 0 {
                bail!("Package reparse entry refused")
            }
            if meta.is_dir() {
                let relative = path
                    .strip_prefix(root)?
                    .to_str()
                    .context("Unicode package directory required")?
                    .replace('\\', "/");
                if !matches!(relative.as_str(), "product" | "product/msix-worker107") {
                    bail!("Unexpected package directory refused")
                }
                inventory(root, &path, depth + 1, result)?;
            } else if meta.is_file() {
                result.push(
                    path.strip_prefix(root)?
                        .to_str()
                        .context("Unicode package path required")?
                        .replace('\\', "/"),
                );
                if result.len() > 7 {
                    bail!("Extra package files refused")
                }
            } else {
                bail!("Ordinary package file required")
            }
        }
        Ok(())
    }
    let mut observed = Vec::new();
    inventory(root, root, 0, &mut observed)?;
    observed.sort();
    let mut expected = PAYLOAD.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    expected.push("receipt.json".into());
    expected.sort();
    if observed != expected {
        bail!("Package inventory contains unexpected files")
    }
    for file in &held {
        file.revalidate()?;
    }
    Ok(held)
}
fn assert_tools(
    workspace: &HeldRunWorkspace,
    prepared: &VmMsixPreparation,
    request: &MsixWorkerRequest,
) -> Result<()> {
    let preparation_file = workspace.reopen_tools_file_readonly("msix-preparation.json")?;
    let mut preparation_bytes = Vec::new();
    preparation_file
        .as_file()
        .read_to_end(&mut preparation_bytes)?;
    if preparation_bytes != serde_json::to_vec_pretty(prepared)? {
        bail!("Original approved preparation changed")
    }
    preparation_file.revalidate()?;
    let layout = RunLayout::new(workspace.root_path(), &request.run_id)?;
    if layout.read_plan()?.hash()? != request.plan_sha256
        || layout.read_approval()?.plan_hash != request.plan_sha256
    {
        bail!("Original approved plan/approval changed")
    }
    for item in &prepared.files {
        let file = workspace.reopen_tools_file_readonly(&item.leaf)?;
        let mut bytes = Vec::new();
        file.as_file().read_to_end(&mut bytes)?;
        if bytes.len() as u64 != item.size_bytes || hash(&bytes) != item.sha256 {
            bail!("Approved {} changed", item.leaf)
        }
        file.revalidate()?;
    }
    let file = workspace.reopen_tools_file_readonly("request.json")?;
    let mut bytes = Vec::new();
    file.as_file().read_to_end(&mut bytes)?;
    if hash(&bytes) != hash(&serde_json::to_vec(request)?)
        || serde_json::from_slice::<MsixWorkerRequest>(&bytes)?
            .hash()
            .map_err(anyhow::Error::msg)?
            != request.hash().map_err(anyhow::Error::msg)?
    {
        bail!("Approved request changed")
    }
    file.revalidate()?;
    Ok(())
}

fn fresh_nonce() -> Result<String> {
    let random = command_json(Command::new(PS).env_remove("PSModulePath").args([
        "-NoProfile", "-NonInteractive", "-Command",
        "$r=[byte[]]::new(32);[Security.Cryptography.RandomNumberGenerator]::Fill($r);[Convert]::ToHexString($r).ToLowerInvariant()|ConvertTo-Json -Compress",
    ]), 15, 1024)?;
    let nonce = random.as_str().context("CSPRNG nonce missing")?.to_owned();
    if !valid_sha256(&nonce) {
        bail!("CSPRNG nonce differs")
    }
    Ok(nonce)
}

/// A newly manufactured old-schema preparation is never a historical run.
/// Public recovery must reject its absent runtime binding before publishing or
/// executing any helper, without rewriting the original approved inputs.
fn legacy_runtime_rejected(
    evidence: &Path,
    prepared: &VmMsixPreparation,
    request: &MsixWorkerRequest,
    source: &HeldRunWorkspace,
) -> Result<Value> {
    let workspace = HeldRunWorkspace::create(evidence, "legacy-prepared-workspace")?;
    let mut old = prepared.clone();
    old.run_id = format!("msix-core76-legacy-rejected-{}", super::super::nonce());
    old.workspace = workspace.evidence().clone();
    old.power_shell_runtime = None;
    for item in &old.files {
        let file = source.reopen_tools_file_readonly(&item.leaf)?;
        let mut bytes = Vec::new();
        file.as_file().read_to_end(&mut bytes)?;
        if bytes.len() as u64 != item.size_bytes || hash(&bytes) != item.sha256 {
            bail!("Legacy rejection fixture source changed")
        }
        write_tools(&workspace, &item.leaf, &bytes)?;
        file.revalidate()?;
    }
    write_tools(
        &workspace,
        "msix-preparation.json",
        &serde_json::to_vec_pretty(&old)?,
    )?;
    let binding = VmMsixExecutionBinding {
        preparation_sha256: old.hash().map_err(anyhow::Error::msg)?,
        worker_profile_sha256: old.worker.hash().map_err(anyhow::Error::msg)?,
        package_sha256: aiw_probe::MSIX_PACKAGE_SHA256.into(),
        workspace: Box::new(old.workspace.clone()),
    };
    let plan = RunPlan::new(&old.run_id, PRODUCT, old.hash().map_err(anyhow::Error::msg)?, RunLifecycleKind::Assessment,
        now_rfc3339(), vec![PlannedAction::ExecuteVmMsix{binding:Box::new(binding)}],
        vec!["Fresh local absent-runtime legacy preparation rejection fixture. No VM acquisition or execution is authorized.".into()])?;
    let layout = RunLayout::new(workspace.root_path(), &old.run_id)?;
    layout.create(&plan)?;
    layout.write_approval(&ApprovalRecord::for_plan(
        &plan,
        "approved local legacy rejection fixture",
        now_rfc3339(),
    )?)?;
    let mut old_request = request.clone();
    old_request.run_id = old.run_id.clone();
    old_request.nonce = fresh_nonce()?;
    old_request.plan_sha256 = plan.hash()?;
    old_request.power_shell_runtime = None;
    old_request.validate().map_err(anyhow::Error::msg)?;
    write_tools(
        &workspace,
        "request.json",
        &serde_json::to_vec(&old_request)?,
    )?;
    let failure = recover(workspace.root_path(), &old.run_id, &RecoveryGate)
        .err()
        .context("Legacy preparation unexpectedly reached recovery")?;
    if !format!("{failure:#}").contains("Incompatible outstanding legacy preparation") {
        bail!("Legacy preparation rejected for a different reason: {failure:#}")
    }
    if std::fs::read_dir(workspace.output_path())?.next().is_some() {
        bail!("Legacy preparation published a helper or execution stage before rejection")
    }
    assert_tools(&workspace, &old, &old_request)?;
    Ok(
        json!({"runId":old.run_id,"runtimeBindingAbsent":true,"publicRecoveryRejected":true,"helperPublished":false,"applicationExecuted":false,"approvedInputsUnchanged":true,"historicalRunReplayed":false}),
    )
}

#[test]
#[ignore = "approved live VM107 Core-only native acceptance: fresh package and exact opt-in required"]
fn vm107_core76_bounded_windows_acceptance() -> Result<()> {
    if std::env::var("AIW_VM107_CORE76_BOUNDED_ACCEPTANCE").as_deref() != Ok(OPT_IN)
        || std::env::var_os("AIW_TEST_PWSH").is_some()
        || std::env::var_os("AIW_VM107_BOUNDED_RESUME").is_some()
    {
        bail!(
            "Exact fresh Core-only opt-in required; inert runtime overrides and historical resume are forbidden"
        )
    }
    let package_root = PathBuf::from(std::env::var("AIW_VM107_CORE76_PACKAGE_ROOT")?);
    if !package_root.is_absolute() {
        bail!("Absolute freshly verified package directory required")
    }
    let agent_sha = std::env::var("AIW_VM107_CORE76_WORKER_SHA256")?;
    let receipt_sha = std::env::var("AIW_VM107_CORE76_RECEIPT_SHA256")?;
    let source_revision = std::env::var("AIW_VM107_CORE76_SOURCE_CHECKPOINT")?;
    if !valid_sha256(&agent_sha)
        || !valid_sha256(&receipt_sha)
        || source_revision.len() != 40
        || !source_revision
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        bail!("Independently supplied fresh package/checkpoint identities required")
    }
    let package_holds =
        verify_fresh_package(&package_root, &source_revision, &receipt_sha, &agent_sha)?;
    let host_runtime = aiw_windows_platform::observe_machine_powershell()
        .map_err(|e| anyhow!("Installed Core runtime required: {e}"))?;
    if host_runtime.identity.version != "7.6.7" {
        bail!("This native acceptance is approved only for Core 7.6.7")
    }
    let probe = provider("probe", None, None)?;
    if probe["leasePresent"] != false
        || probe["checkpoint"] != aiw_probe::MSIX_CORE_WORKER_CHECKPOINT
        || probe["providerSha256"] != provider_hash()
    {
        bail!("Existing lease: do not adopt or replay")
    }
    let fresh_id = super::super::nonce();
    let run_id = format!("msix-core76-bounded-{fresh_id}");
    let parent = Path::new(r"C:\AIW-Resume-20261021");
    let evidence = create_evidence_root(parent, &format!("powershell76-native-{fresh_id}"))?;
    let workspace = HeldRunWorkspace::create(&evidence, "workspace")?;
    let worker: VmMsixWorkerProfile = serde_json::from_value(
        json!({"schemaVersion":"aiw.dev/vm-msix-worker-profile/v0alpha1","vmId":107,"workerUuid":aiw_probe::MSIX_WORKER_UUID,"workerMac":"CC:34:21:B8:5A:31","checkpoint":aiw_probe::MSIX_CORE_WORKER_CHECKPOINT,"checkpointConfigSha256":probe["checkpointConfigSha256"],"providerSha256":provider_hash(),"hypervisorAddress":"192.168.1.6","hypervisorHostKeySha256":"SHA256:J/kc0UwUBil5TFBQbQhwBoRKnDoRlZ8ggXAhmYEpq1E","httpsAddress":"192.168.1.174","httpsCertificateSha1":"BC14DCC4E37F83161EBB55AF8624E36A79E19256"}),
    )?;
    worker.validate().map_err(anyhow::Error::msg)?;
    let runtime_binding = observe_runtime_binding(&workspace)?;
    if runtime_binding.host != host_runtime.identity
        || runtime_binding.worker.version != "7.6.7"
        || runtime_binding.wsman.as_ref().map(|w| w.version.as_str()) != Some("7.6.7")
    {
        bail!("Exact independently observed host/worker/WSMan 7.6.7 binding required")
    }
    host_runtime
        .revalidate()
        .map_err(|error| anyhow!(error.to_string()))?;
    let assets = package_root.join("product/msix-worker107");
    let mut files = Vec::new();
    for (leaf, expected) in [
        ("agent.exe", agent_sha.as_str()),
        ("assembly.json", aiw_probe::MSIX_ASSEMBLY_SHA256),
        ("signing.json", aiw_probe::MSIX_SIGNING_SHA256),
    ] {
        let source = HeldApplicationFile::open_bounded(&assets.join(leaf), 32 * 1024 * 1024)?;
        let bytes = source.read_bounded(32 * 1024 * 1024)?;
        if hash(&bytes) != expected {
            bail!("Fresh packaged acceptance asset differs: {leaf}")
        }
        write_tools(&workspace, leaf, &bytes)?;
        source.revalidate()?;
        files.push(VmMsixPreparedFile {
            leaf: leaf.into(),
            sha256: expected.into(),
            size_bytes: bytes.len() as u64,
        });
    }
    // Preserve the approved preparation verbatim. Recovery must publish a held
    // current collector into output rather than rewrite this tools input.
    let prepared_transport =
        format!("# Fresh Core preparation fixture; legacy optional cache layout.\r\n{TRANSPORT}");
    write_tools(&workspace, "transport.ps1", prepared_transport.as_bytes())?;
    files.push(VmMsixPreparedFile {
        leaf: "transport.ps1".into(),
        sha256: hash(prepared_transport.as_bytes()),
        size_bytes: prepared_transport.len() as u64,
    });
    let package = HeldApplicationFile::open_with_download_metadata(Path::new(
        r"C:\AIW-Resume-20261021\assets\inputs\application.msix",
    ))?;
    if package.observation().sha256 != aiw_probe::MSIX_PACKAGE_SHA256 {
        bail!("Fixed signed input differs")
    }
    let intake = evidence.join("intakes");
    std::fs::create_dir(&intake)?;
    let package_import = aiw_windows_platform::import_application_file_with_metadata(
        &intake,
        "notepad-msix",
        ApplicationInspectionKind::Msix,
        &package,
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
    let plan=RunPlan::new(&run_id,PRODUCT,prepared.hash().map_err(anyhow::Error::msg)?,RunLifecycleKind::Assessment,now_rfc3339(),vec![PlannedAction::ExecuteVmMsix{binding:Box::new(binding)}],vec!["User-authorized fresh Core 7.6.7 bounded acceptance: VM107 only, retained Core preparation with legacy cache layout, delayed sign-in, native exit42 Control and inert raw fixtures, final cold recovery. Application Run is forbidden; queued-state injection is an exact-consumer regression, not a native scheduler observation.".into()])?;
    let layout = RunLayout::new(workspace.root_path(), &run_id)?;
    layout.create(&plan)?;
    layout.write_approval(&ApprovalRecord::for_plan(
        &plan,
        "user-authorized bounded acceptance",
        now_rfc3339(),
    )?)?;
    let nonce = fresh_nonce()?;
    let before = filetime()?;
    let request = MsixWorkerRequest {
        schema_version: aiw_probe::MSIX_WORKER_REQUEST_SCHEMA.into(),
        run_id: run_id.clone(),
        nonce: nonce.clone(),
        recipe: VmMsixRecipe::Notepad898MediumFullTrust,
        plan_sha256: plan.hash()?,
        worker_profile_sha256: worker.hash().map_err(anyhow::Error::msg)?,
        agent_sha256: agent_sha.clone(),
        package_sha256: aiw_probe::MSIX_PACKAGE_SHA256.into(),
        assembly_sha256: aiw_probe::MSIX_ASSEMBLY_SHA256.into(),
        signing_sha256: aiw_probe::MSIX_SIGNING_SHA256.into(),
        worker_uuid: aiw_probe::MSIX_WORKER_UUID.into(),
        power_shell_runtime: Some(runtime_binding),
        not_before_file_time: before,
        not_after_file_time: before + 18_000_000_000,
    };
    request.validate().map_err(anyhow::Error::msg)?;
    write_tools(&workspace, "request.json", &serde_json::to_vec(&request)?)?;
    stage(
        &workspace,
        "acceptance-legacy-runtime-rejected",
        &legacy_runtime_rejected(&evidence, &prepared, &request, &workspace)?,
    )?;
    let held = aiw_orchestrator::open_vm_msix_preparation(&plan)?;
    stage(
        &workspace,
        "start-intent",
        &json!({"nonce":nonce,"requestSha256":request.hash().map_err(anyhow::Error::msg)?,"boundedAcceptance":true,"applicationRunPermitted":false,"sourceRevision":source_revision,"packageReceiptSha256":receipt_sha}),
    )?;
    eprintln!(
        "BOUND WORKSPACE: {} RUN: {run_id} NONCE: {nonce}",
        workspace.root_path().display()
    );
    for file in &package_holds {
        file.revalidate()?;
    }
    execute_bounded(workspace, prepared, request, held)
}
fn execute_bounded(
    workspace: HeldRunWorkspace,
    prepared: VmMsixPreparation,
    request: MsixWorkerRequest,
    held: aiw_orchestrator::HeldVmMsixPreparation,
) -> Result<()> {
    let run_id = request.run_id.clone();
    let nonce = request.nonce.clone();
    let worker = prepared.worker.clone();
    let result = (|| -> Result<()> {
        {
            stage(
                &workspace,
                "acquire-intent",
                &json!({"nonce":nonce,"boundedAcceptance":true}),
            )?;
            stage(
                &workspace,
                "lease-acquired",
                &provider("acquire", Some(&nonce), Some(&worker))?,
            )?;
            eprintln!("Restoring the exact cold checkpoint.");
            stage(
                &workspace,
                "initial-restore",
                &provider("restore", Some(&nonce), Some(&worker))?,
            )?;
            stage(
                &workspace,
                "initial-connect",
                &provider("connect", Some(&nonce), Some(&worker))?,
            )?;
        }
        {
            stage(
                &workspace,
                "initial-clean",
                &RecoveryVm.clean(&request, &workspace)?,
            )?;
            stage(
                &workspace,
                "begin",
                &provider("begin", Some(&nonce), Some(&worker))?,
            )?;
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
            let mut delayed = DelayedControl {
                pending: 0,
                ready: 0,
                controls: 0,
                restarted: false,
            };
            eprintln!("Polling actual delayed interactive readiness before native Control.");
            ready_then_control(&workspace, &request, &mut delayed, Duration::from_secs(360))?;
            let status = wait_operation(&workspace, &run_id, &nonce, "control", 150)?;
            let control = &status["records"]["control-result"];
            let ready = read_stage(&workspace, "interactive-ready.json")?;
            if control["passed"] != true
                || control["observedExitCode"] != 42
                || control["expectedExitCode"] != 42
                || control["jobEmpty"] != true
                || control["nonce"] != nonce
                || control["requestSha256"] != request.hash().map_err(anyhow::Error::msg)?
                || control["userSid"] != ready["userSid"]
                || control["sessionId"] != ready["sessionId"]
                || control["heldProcessId"].as_u64().is_none_or(|p| p == 0)
                || control["authenticationId"]
                    .as_str()
                    .is_none_or(str::is_empty)
            {
                bail!("Native fixed Control42/session/job proof differs")
            }
            request
                .power_shell_runtime
                .as_ref()
                .context("Core binding absent")?
                .verify_worker_receipts(&[control])
                .map_err(anyhow::Error::msg)?;
            stage(&workspace, "acceptance-native-control", control)?;
            if delayed.pending == 0 || delayed.ready == 0 || delayed.controls != 1 {
                bail!("Bounded delayed Control counts differ")
            }
            stage(
                &workspace,
                "acceptance-delayed-readiness",
                &json!({"pendingObservations":delayed.pending,"readyObservations":delayed.ready,"controlDispatches":delayed.controls,"runDispatches":0,"passed":true}),
            )?;
        }
        eprintln!(
            "Creating inert authoritative fixtures with a deliberate export-blocking stream."
        );
        let created = fixture("CreateRawWithNamedStream", &workspace, &request)?;
        let task = &created["controlTaskProof"];
        if task["completed"] != true
            || task["exitCode"] != 0
            || task["lastTaskResult"] != 0
            || task["state"] != "Ready"
            || task["activeProjectTasks"] != 0
            || task["activeApplicationOrAgentProcesses"] != 0
            || task["nonce"] != nonce
        {
            bail!("Native Control task terminal/quiescence proof differs")
        }
        stage(&workspace, "acceptance-fixture-created", &created)?;
        let blocked = cold_recover(&workspace, &request, &worker, &mut RecoveryVm)
            .context("Expected collection to block before rollback");
        let error = blocked
            .err()
            .context("Unsafe rollback: blocked raw export unexpectedly succeeded")?;
        if !error.chain().any(|cause| {
            cause
                .to_string()
                .contains("Named raw evidence stream refused")
        }) {
            bail!(
                "Blocked-export fixture failed for an unexpected reason; preserve the exact dirty lease: {error:#}"
            )
        }
        stage(
            &workspace,
            "acceptance-export-blocked",
            &json!({"error":format!("{error:#}"),"expected":true,"expectedProductionRejection":"Named raw evidence stream refused"}),
        )?;
        let dirty = provider("inspect", Some(&nonce), Some(&worker))?;
        if dirty["phase"] != "dirty"
            || dirty["leasePresent"] != true
            || workspace
                .output_path()
                .join("recovery-release-intent.json")
                .exists()
            || workspace
                .output_path()
                .join("collection-authoritative-complete.json")
                .exists()
        {
            bail!("Blocked export did not preserve dirty lease")
        }
        stage(&workspace, "acceptance-dirty-lease-retained", &dirty)?;
        stage(
            &workspace,
            "acceptance-fixture-unblocked",
            &fixture("ClearNamedStream", &workspace, &request)?,
        )?;
        let original = RecoveryVm.transport("Collect", &request, &workspace)?;
        assert_raw(&original, &request)?;
        if original["files"]
            .as_array()
            .context("Export missing")?
            .iter()
            .any(|e| {
                e["path"]
                    .as_str()
                    .is_some_and(|p| p.starts_with("evidence/"))
            })
        {
            bail!("Crash-before-copy fixture unexpectedly had a controller cache")
        }
        stage(
            &workspace,
            "acceptance-no-controller-copy",
            &json!({"passed":true,"rawFiles":3,"export":original}),
        )?;
        stage(
            &workspace,
            "acceptance-partial-cache-created",
            &fixture("AddPartialCache", &workspace, &request)?,
        )?;
        if workspace
            .output_path()
            .join("collection-authoritative-complete.json")
            .exists()
        {
            bail!("Recovery must collect the partial-cache state itself")
        }
        let queued = fixture("QueuedConsumerRegression", &workspace, &request)?;
        if queued["queuedRejected"] != true
            || queued["processObservationInjectedEmpty"] != true
            || queued["nativeSchedulerQueueObserved"] != false
        {
            bail!("Exact-consumer queued-state regression receipt differs")
        }
        stage(&workspace, "acceptance-queued-consumer-regression", &queued)?;
        assert_tools(&workspace, &prepared, &request)?;
        eprintln!(
            "Recovering the retained Core preparation with a legacy partial cache through the current read-only helper."
        );
        let report = recover(workspace.root_path(), &run_id, &RecoveryGate)?;
        if report["cleanupComplete"] != true || report["workflowVerified"] != false {
            bail!("Bounded recovery terminal report differs")
        }
        let partial = read_export(&workspace, &request)?;
        assert_raw(&partial, &request)?;
        let files = decode_collection(&request, &partial)?;
        if files
            .get("evidence/msix-lifecycle/document.txt")
            .map(Vec::as_slice)
            != Some(b"deliberately incomplete cached copy".as_slice())
        {
            bail!("Public recovery did not collect the partial-cache state")
        }
        stage(&workspace, "acceptance-partial-cache-export", &partial)?;
        assert_tools(&workspace, &prepared, &request)?;
        held.workspace.revalidate()?;
        stage(
            &workspace,
            "acceptance-result",
            &json!({"scope":"core76BoundedWindowsAcceptance","powerShellVersion":"7.6.7","rawEvidenceRecovery":true,"legacyPartialCacheLayout":true,"retainedCorePreparation":true,"legacyMissingRuntimeRecoveryRejectedBeforeHelper":true,"historical5_1PreparationExecuted":false,"queuedConsumerRegression":true,"nativeSchedulerQueueObserved":false,"delayedInteractiveReadiness":true,"approvedInputsUnchanged":true,"applicationRunDispatches":0,"fullApplicationTrial":false,"cleanupComplete":true,"report":report}),
        )?;
        Ok(())
    })();
    if let Err(error) = &result {
        let _ = stage(
            &workspace,
            &format!("acceptance-failed-{}", super::super::nonce()),
            &json!({"error":format!("{error:#}"),"nonce":nonce,"workspace":workspace.root_path(),"automaticRetry":false}),
        );
    }
    result
}
