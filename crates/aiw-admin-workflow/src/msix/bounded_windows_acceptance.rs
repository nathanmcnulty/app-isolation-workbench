//! Explicitly opted-in VM107 control/fixture acceptance. Never dispatches Run.
use super::*;

const REVIEWED: &str = "f30c80e919b157f15e7ce7b407f13e2734f8eac6";
const ROOT: &str = r"C:\AIW-Resume-20261021\bounded-windows-f30c80e";
const OLD_TRANSPORT_SHA: &str = "006c069a056c81ff8cd3232f1ceb33dc808f070edb070725e7854fb057e62813";
const OLD_AGENT_SHA: &str = "8ce377e1b1e826e4a9115f949b3e4dd85e28c32b3f1541887ffb93a01e55a472";
const FIXTURE_SCRIPT: &str =
    include_str!("../../../../scripts/vm-msix/tests/invoke-bounded-windows-fixture.ps1");

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
    stage(
        workspace,
        &format!("acceptance-fixture-intent-{}", mode.to_ascii_lowercase()),
        &json!({"nonce":request.nonce,"mode":mode,"automaticRetry":false}),
    )?;
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/vm-msix/tests/invoke-bounded-windows-fixture.ps1");
    let held = HeldApplicationFile::open_bounded(&path, 65536)?;
    if held.read_bounded(65536)? != FIXTURE_SCRIPT.as_bytes() {
        bail!("Fixed acceptance fixture source differs")
    }
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
            ]),
        120,
        65536,
    )?;
    held.revalidate()?;
    Ok(value)
}
fn assert_raw(value: &Value, request: &MsixWorkerRequest) -> Result<()> {
    let files = decode_collection(request, value)?;
    let expected = b"AIW bounded raw evidence acceptance\r\n";
    if files
        .get("raw/msix-lifecycle/document.txt")
        .map(Vec::as_slice)
        != Some(expected.as_slice())
        || value["rawEvidence"]["files"].as_array().map(Vec::len) != Some(3)
    {
        bail!("Bounded authoritative fixture bytes/count differ")
    }
    Ok(())
}
fn assert_tools(
    workspace: &HeldRunWorkspace,
    prepared: &VmMsixPreparation,
    request: &MsixWorkerRequest,
) -> Result<()> {
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
    Ok(())
}

#[test]
#[ignore = "explicit user-authorized live VM107 acceptance; requires the exact opt-in and retained pinned assets"]
fn vm107_bounded_windows_acceptance() -> Result<()> {
    if std::env::var("AIW_VM107_BOUNDED_ACCEPTANCE").as_deref() != Ok(REVIEWED) {
        bail!("Exact reviewed-revision live opt-in required")
    }
    if std::env::var("AIW_VM107_BOUNDED_RESUME").is_ok() {
        return resume_initial_checkpoint();
    }
    let probe = provider("probe", None, None)?;
    if probe["leasePresent"] != false {
        bail!("Existing lease: do not adopt or replay")
    }
    let run_id = format!("msix-bounded-{}", super::super::nonce());
    let evidence = create_evidence_root(Path::new(ROOT), &run_id)?;
    let workspace = HeldRunWorkspace::create(&evidence, "workspace")?;
    let worker: VmMsixWorkerProfile = serde_json::from_value(
        json!({"schemaVersion":"aiw.dev/vm-msix-worker-profile/v0alpha1","vmId":107,"workerUuid":aiw_probe::MSIX_WORKER_UUID,"workerMac":"CC:34:21:B8:5A:31","checkpoint":aiw_probe::MSIX_WORKER_CHECKPOINT,"checkpointConfigSha256":probe["checkpointConfigSha256"],"providerSha256":provider_hash(),"hypervisorAddress":"192.168.1.6","hypervisorHostKeySha256":"SHA256:J/kc0UwUBil5TFBQbQhwBoRKnDoRlZ8ggXAhmYEpq1E","httpsAddress":"192.168.1.174","httpsCertificateSha1":"BC14DCC4E37F83161EBB55AF8624E36A79E19256"}),
    )?;
    worker.validate().map_err(anyhow::Error::msg)?;
    let mut files = Vec::new();
    for (leaf, path, expected) in [
        (
            "agent.exe",
            r"C:\AIW-Resume-20261021\production-msix-desktop-reportfix\product\msix-worker107\agent.exe",
            OLD_AGENT_SHA,
        ),
        (
            "transport.ps1",
            r"C:\AIW-Resume-20261021\bounded-windows-f30c80e\old-transport.ps1",
            OLD_TRANSPORT_SHA,
        ),
        (
            "assembly.json",
            r"C:\AIW-Resume-20261021\assets\inputs\assembly.json",
            aiw_probe::MSIX_ASSEMBLY_SHA256,
        ),
        (
            "signing.json",
            r"C:\AIW-Resume-20261021\assets\inputs\signing.json",
            aiw_probe::MSIX_SIGNING_SHA256,
        ),
    ] {
        let file = HeldApplicationFile::open_bounded(Path::new(path), 32 * 1024 * 1024)?;
        let bytes = file.read_bounded(32 * 1024 * 1024)?;
        if hash(&bytes) != expected {
            bail!("Pinned bounded acceptance asset differs: {leaf}")
        }
        write_tools(&workspace, leaf, &bytes)?;
        file.revalidate()?;
        files.push(VmMsixPreparedFile {
            leaf: leaf.into(),
            sha256: expected.into(),
            size_bytes: bytes.len() as u64,
        });
    }
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
    let plan=RunPlan::new(&run_id,PRODUCT,prepared.hash().map_err(anyhow::Error::msg)?,RunLifecycleKind::Assessment,now_rfc3339(),vec![PlannedAction::ExecuteVmMsix{binding:Box::new(binding)}],vec!["User-authorized bounded Windows acceptance: fresh VM107 lease, old approved preparation, delayed sign-in, native exit42 Control and inert raw fixtures, final cold recovery. Application Run is forbidden; no MSIX install or full trial.".into()])?;
    let layout = RunLayout::new(workspace.root_path(), &run_id)?;
    layout.create(&plan)?;
    layout.write_approval(&ApprovalRecord::for_plan(
        &plan,
        "user-authorized bounded acceptance",
        now_rfc3339(),
    )?)?;
    let random=command_json(Command::new(PS).args(["-NoProfile","-NonInteractive","-Command","$r=[byte[]]::new(32);$g=[Security.Cryptography.RandomNumberGenerator]::Create();try{$g.GetBytes($r);ConvertTo-Json ([BitConverter]::ToString($r).Replace('-','').ToLowerInvariant())}finally{$g.Dispose()}"]),15,1024)?;
    let nonce = random.as_str().context("CSPRNG nonce missing")?.to_owned();
    let before = filetime()?;
    let request = MsixWorkerRequest {
        schema_version: aiw_probe::MSIX_WORKER_REQUEST_SCHEMA.into(),
        run_id: run_id.clone(),
        nonce: nonce.clone(),
        recipe: VmMsixRecipe::Notepad898MediumFullTrust,
        plan_sha256: plan.hash()?,
        worker_profile_sha256: worker.hash().map_err(anyhow::Error::msg)?,
        agent_sha256: OLD_AGENT_SHA.into(),
        package_sha256: aiw_probe::MSIX_PACKAGE_SHA256.into(),
        assembly_sha256: aiw_probe::MSIX_ASSEMBLY_SHA256.into(),
        signing_sha256: aiw_probe::MSIX_SIGNING_SHA256.into(),
        worker_uuid: aiw_probe::MSIX_WORKER_UUID.into(),
        not_before_file_time: before,
        not_after_file_time: before + 18_000_000_000,
    };
    request.validate().map_err(anyhow::Error::msg)?;
    write_tools(&workspace, "request.json", &serde_json::to_vec(&request)?)?;
    let held = aiw_orchestrator::open_vm_msix_preparation(&plan)?;
    stage(
        &workspace,
        "start-intent",
        &json!({"nonce":nonce,"requestSha256":request.hash().map_err(anyhow::Error::msg)?,"boundedAcceptance":true,"applicationRunPermitted":false}),
    )?;
    eprintln!(
        "BOUND WORKSPACE: {} RUN: {run_id} NONCE: {nonce}",
        workspace.root_path().display()
    );
    execute_bounded(workspace, prepared, request, held, false, false)
}
fn execute_bounded(
    workspace: HeldRunWorkspace,
    prepared: VmMsixPreparation,
    request: MsixWorkerRequest,
    held: aiw_orchestrator::HeldVmMsixPreparation,
    resume: bool,
    post_control: bool,
) -> Result<()> {
    let run_id = request.run_id.clone();
    let nonce = request.nonce.clone();
    let worker = prepared.worker.clone();
    let result = (|| -> Result<()> {
        if !resume {
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
        if !post_control {
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
            wait_operation(&workspace, &run_id, &nonce, "control", 150)?;
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
        stage(
            &workspace,
            "acceptance-fixture-created",
            &fixture("CreateRawWithNamedStream", &workspace, &request)?,
        )?;
        let blocked = cold_recover(&workspace, &request, &worker, &mut RecoveryVm)
            .context("Expected collection to block before rollback");
        let error = blocked
            .err()
            .context("Unsafe rollback: blocked raw export unexpectedly succeeded")?;
        stage(
            &workspace,
            "acceptance-export-blocked",
            &json!({"error":format!("{error:#}"),"expected":true}),
        )?;
        let dirty = provider("inspect", Some(&nonce), Some(&worker))?;
        if dirty["phase"] != "dirty"
            || dirty["leasePresent"] != true
            || workspace
                .output_path()
                .join("recovery-release-intent.json")
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
        assert_tools(&workspace, &prepared, &request)?;
        eprintln!(
            "Recovering this old-format approved workspace through the current read-only helper."
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
            &json!({"reviewedBase":REVIEWED,"runtimeCorrection":"held read-only output authority for PowerShell helper","resumedBeforeEnrollment":resume,"scope":"boundedWindowsAcceptance","rawEvidenceRecovery":true,"oldPreparedWorkspace":true,"delayedInteractiveReadiness":true,"approvedInputsUnchanged":true,"applicationRunDispatches":0,"fullApplicationTrial":false,"cleanupComplete":true,"report":report}),
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

fn resume_initial_checkpoint() -> Result<()> {
    const RUN: &str = "msix-bounded-1792816990610240800";
    let post_control = std::env::var("AIW_VM107_BOUNDED_RESUME").as_deref()
        == Ok("msix-bounded-1792816990610240800:post-control");
    if !post_control && std::env::var("AIW_VM107_BOUNDED_RESUME").as_deref() != Ok(RUN) {
        bail!("Only this retained pre-enrollment acceptance may resume")
    }
    let path = Path::new(ROOT).join(RUN).join("workspace");
    let layout = RunLayout::new(&path, RUN)?;
    let plan = layout.read_plan()?;
    if layout.read_approval()?.plan_hash != plan.hash()? {
        bail!("Retained original approval differs")
    }
    let held = aiw_orchestrator::open_vm_msix_preparation(&plan)?;
    let prepared = held.preparation.clone();
    let workspace = HeldRunWorkspace::reopen_bound(&prepared.workspace)?;
    if !post_control {
        for name in [
            "initial-clean.json",
            "begin.json",
            "stage-intent.json",
            "enroll-intent.json",
            "control-intent.json",
            "run-intent.json",
        ] {
            if workspace.output_path().join(name).exists() {
                bail!("Resume is restricted to the unchanged pre-enrollment checkpoint: {name}")
            }
        }
    }
    let file = workspace.reopen_tools_file_readonly("request.json")?;
    let mut bytes = Vec::new();
    file.as_file().take(65537).read_to_end(&mut bytes)?;
    let request: MsixWorkerRequest = serde_json::from_slice(&bytes)?;
    request
        .validate_at(filetime()?)
        .map_err(anyhow::Error::msg)?;
    if request.run_id != RUN
        || request.plan_sha256 != plan.hash()?
        || request.worker_profile_sha256 != prepared.worker.hash().map_err(anyhow::Error::msg)?
        || request.agent_sha256 != OLD_AGENT_SHA
    {
        bail!("Retained acceptance request differs")
    }
    let state = provider("inspect", Some(&request.nonce), Some(&prepared.worker))?;
    let expected_phase = if post_control {
        "dirty"
    } else {
        "online-clean"
    };
    if state["phase"] != expected_phase || state["leasePresent"] != true {
        bail!("Pre-enrollment lease phase differs")
    }
    if post_control {
        for name in [
            "acceptance-fixture-created.json",
            "acceptance-fixture-intent-createrawwithnamedstream.json",
            "run-intent.json",
            "collection-authoritative-complete.json",
            "recovery-restore.json",
        ] {
            if workspace.output_path().join(name).exists() {
                bail!("Post-Control resume requires no fixture/recovery dispatch: {name}")
            }
        }
        let readiness = read_stage(&workspace, "acceptance-delayed-readiness.json")?;
        let control = read_stage(&workspace, "control-status.json")?;
        let result = &control["records"]["control-result"];
        if readiness["passed"] != true
            || readiness["controlDispatches"] != 1
            || readiness["runDispatches"] != 0
            || result["nonce"] != request.nonce
            || result["requestSha256"] != request.hash().map_err(anyhow::Error::msg)?
            || result["passed"] != true
            || result["observedExitCode"] != 42
            || result["jobEmpty"] != true
        {
            bail!("Exact terminal delayed-Control proof required")
        }
        assert_tools(&workspace, &prepared, &request)?;
    }
    stage(
        &workspace,
        &format!("acceptance-resume-{}", super::super::nonce()),
        &json!({"nonce":request.nonce,"retainedState":state,"runtimeCorrection":"read-only helper authority","noMutatingDispatchRepeated":true,"postControl":post_control}),
    )?;
    eprintln!(
        "Resuming the exact recorded acceptance checkpoint; no prior mutating dispatch is repeated."
    );
    execute_bounded(workspace, prepared, request, held, true, post_control)
}
