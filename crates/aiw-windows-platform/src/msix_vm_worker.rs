//! Fixed production VM107 worker. Invoked only by the host's approved typed
//! protocol, never with caller-selected commands, scripts, or package identities.
use crate::{
    HeldApplicationFile, guest_msi::GuestProcess, primary_interactive_user::PrimaryInteractiveUser,
    source_inspection::HeldEvidenceDirectory,
};
use aiw_probe::MsixWorkerRequest;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use windows::Win32::System::{JobObjects::IsProcessInJob, Threading::GetCurrentProcess};
use windows::core::BOOL;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use aiw_probe::powershell::{POWERSHELL_EXECUTABLE as POWERSHELL, POWERSHELL_RUNTIME_GUARD};
const BASE: &str = r"C:\ProgramData\AIW\MsixWorker";
const CONTROL_SHA256: &str = "15cd209c995b7d3009c91ca40892d5b8f1fb162f3e5f10716642ea278e8e0d7b";

// Windows servicing hardlinks OS images. Keep the application intake's single-link
// policy separate: this private opener is used only for the fixed OS control.
fn hold_os_control(path: &Path, expected_sha256: &str) -> Result<(File, File)> {
    let directory = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .custom_flags(0x02200000)
        .open(path.parent().ok_or("OS control parent absent")?)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err("Non-reparse OS control directory required".into());
    }
    // FILE_SHARE_READ denies replacement and writes through every hardlink while
    // both handles remain live through the suspended launch and job cleanup.
    let mut image = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)?;
    let metadata = image.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & 0x400 != 0
        || metadata.len() > 16 * 1024 * 1024
    {
        return Err("Bounded non-reparse OS control image required".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = image.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if hex::encode(digest.finalize()) != expected_sha256 {
        return Err("Pinned OS control image differs".into());
    }
    Ok((directory, image))
}
fn now() -> Result<i64> {
    Ok(i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
            / 100,
    )? + 116444736000000000)
}
fn time_left(request: &MsixWorkerRequest, cap: u64) -> Result<Duration> {
    Ok(bounded_wait(request.not_after_file_time, now()?, cap))
}
fn bounded_wait(not_after: i64, observed: i64, cap: u64) -> Duration {
    let ticks = not_after.saturating_sub(observed).max(0);
    Duration::from_secs((ticks as u64 / 10_000_000).min(cap))
}
fn read_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("MSIX JSON bound exceeded".into());
    }
    Ok(serde_json::from_slice(
        bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes),
    )?)
}
fn publish(root: &Path, name: &str, value: &Value) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(format!("{name}.pending")))?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    drop(file);
    fs::rename(root.join(format!("{name}.pending")), root.join(name))?;
    Ok(())
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn fixed_script(path: &Path, bytes: &[u8]) -> Result<HeldApplicationFile> {
    if !path.exists() {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    let held = HeldApplicationFile::open_bounded(path, 128 * 1024)?;
    if held.observation().sha256 != sha(bytes) {
        return Err("Compiled worker script identity differs".into());
    }
    Ok(held)
}
fn system_source() -> String {
    let script = include_str!("msix_worker/system.ps1");
    // param must be the first executable statement. Observer source is fixed and
    // inserted only before the two inventory operations, after their UUID guard.
    let anchor = "# C# process observer and inventory function are inserted from fixed compiled";
    let at = script.find(anchor).expect("fixed inventory source anchor");
    crate::powershell::compiled_script_entry(&format!(
        "#Requires -Version 7.6\n#Requires -PSEdition Core\n{}\nAdd-Type -TypeDefinition @'\n{}\n'@\n{}\n{}",
        script[..at].replacen("$ErrorActionPreference='Stop'", POWERSHELL_RUNTIME_GUARD, 1),
        include_str!("research_msix_native.cs"),
        include_str!("research_msix_inventory.ps1"),
        &script[at..]
    ))
}
fn lifecycle_source() -> String {
    crate::powershell::compiled_script_entry(&format!(
        "#Requires -Version 7.6\n#Requires -PSEdition Core\n{POWERSHELL_RUNTIME_GUARD}\nAdd-Type -TypeDefinition @'\n{}\n'@\n{}\nfunction Invoke-AiwDriverControl {{\nparam([string]$EvidenceDirectory)\n{}\n}}\n{}",
        include_str!("research_msix_native.cs"),
        include_str!("research_msix_inventory.ps1"),
        include_str!("research_msix_driver_control.ps1"),
        include_str!("msix_worker/lifecycle.ps1")
    ))
}
fn execute_ps(arguments: &[String], timeout: u64) -> Result<()> {
    let runtime = crate::powershell::HeldPowerShell::observe()?;
    let process = GuestProcess::start(POWERSHELL, arguments)?;
    let operation = process.wait_for_exit(Duration::from_secs(timeout));
    let normal = if operation.as_ref().is_ok_and(|code| *code == 0) {
        process.verify_empty_after_success()
    } else {
        Ok(())
    };
    let cleanup = process.cleanup();
    let empty = process.active_processes();
    let code = operation?;
    normal?;
    cleanup?;
    runtime.revalidate()?;
    if code != 0 || empty? != 0 {
        return Err(format!("Fixed worker PowerShell exit={code}; inspect retained stage").into());
    }
    Ok(())
}
fn ps_file(path: &Path, operation: Option<&str>, timeout: u64) -> Result<()> {
    let mut args = vec![
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-File".into(),
        path.to_str().ok_or("Non-Unicode script path")?.into(),
    ];
    if let Some(op) = operation {
        args.push("-Operation".into());
        args.push(op.into());
    }
    execute_ps(&args, timeout)
}
fn uuid_guard() -> Result<()> {
    // Read-only exact identity before any native write or account/package mutation.
    let script = "$ErrorActionPreference='Stop';if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'){throw 'Wrong disposable worker'}";
    execute_ps(
        &[
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            script.into(),
        ],
        30,
    )
}
fn in_job() -> Result<bool> {
    let mut answer = BOOL(0);
    // SAFETY: current-process pseudo handle is valid and output BOOL is live.
    unsafe { IsProcessInJob(GetCurrentProcess(), None, &mut answer) }?;
    Ok(answer.as_bool())
}
fn collect(root: &Path, destination: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let held = HeldEvidenceDirectory::open(root)?;
    fs::create_dir(destination)?;
    let mut files = BTreeMap::new();
    for object in held.copy_plan() {
        let name = object.relative_path();
        let target = destination.join(name);
        if object.kind() == aiw_probe::PortableContentEntryKind::Directory {
            fs::create_dir(&target)?;
            continue;
        }
        if object.size_bytes() > 4 * 1024 * 1024 {
            return Err("MSIX evidence file exceeds bound".into());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        object.copy_file_to(&mut file)?;
        file.sync_all()?;
        drop(file);
        files.insert(name.replace('\\', "/"), fs::read(target)?);
    }
    held.revalidate()?;
    Ok(files)
}

pub fn run() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2
        || !aiw_probe::valid_msix_run_id(&arguments[1])
        || !matches!(
            arguments[0].as_str(),
            "enroll" | "clear-logon" | "control" | "run" | "lifecycle-child"
        )
    {
        return Err("Closed MSIX operation and run ID required".into());
    }
    let operation = &arguments[0];
    let run_id = &arguments[1];
    let root = Path::new(BASE).join(run_id);
    let image = HeldApplicationFile::open(&std::env::current_exe()?)?;
    if !image.observation().canonical_path.eq_ignore_ascii_case(
        root.join("agent.exe")
            .to_str()
            .ok_or("Invalid agent path")?,
    ) {
        return Err("Fixed staged worker agent path required".into());
    }
    let request_file = HeldApplicationFile::open_bounded(&root.join("request.json"), 65536)?;
    let request: MsixWorkerRequest = serde_json::from_slice(&request_file.read_bounded(65536)?)?;
    request.validate()?;
    let runtime = crate::powershell::HeldPowerShell::observe()?;
    let approved_runtime = request
        .power_shell_runtime
        .as_ref()
        .ok_or("Legacy preparation is evidence-only; new approved runtime preparation required")?;
    approved_runtime.validate()?;
    if runtime.identity != approved_runtime.worker {
        return Err("Approved worker PowerShell runtime identity differs".into());
    }
    if request.run_id != *run_id || image.observation().sha256 != request.agent_sha256 {
        return Err("Request/agent image identity differs".into());
    }
    if operation != "clear-logon" {
        request.validate_at(now()?)?;
    }
    let token = aiw_token::collect_current_process_token()?;
    if operation == "lifecycle-child" {
        if token.is_elevated || token.is_app_container || token.integrity.rid != 8192 {
            return Err("Standard medium worker child required".into());
        }
    } else if token.user_sid != "S-1-5-18" {
        return Err("SYSTEM worker controller required".into());
    }
    uuid_guard()?;
    let mut inputs = Vec::new();
    for (name, expected) in [
        ("application.msix", &request.package_sha256),
        ("assembly.json", &request.assembly_sha256),
        ("signing.json", &request.signing_sha256),
    ] {
        let held =
            HeldApplicationFile::open_bounded(&root.join("input").join(name), 16 * 1024 * 1024)?;
        if held.observation().sha256 != *expected {
            return Err(format!("Approved MSIX input differs: {name}").into());
        }
        inputs.push(held);
    }
    let system = root.join("system.ps1");
    let workflow = root.join("workflow.ps1");
    if operation == "lifecycle-child" {
        let held = fixed_script(&workflow, lifecycle_source().as_bytes())?;
        let account = read_json(&root.join("account.json"))?;
        if account["runNonce"] != request.nonce || account["userSid"] != token.user_sid {
            return Err("Run-owned child SID differs".into());
        }
        let output = PathBuf::from(std::env::var("LOCALAPPDATA")?)
            .join("AIW")
            .join(format!("msix-{}", request.nonce));
        if output.exists() {
            return Err("Existing MSIX child output refused".into());
        }
        fs::create_dir_all(output.parent().ok_or("Missing output parent")?)?;
        fs::create_dir(&output)?;
        publish(
            &output,
            "child-started.json",
            &json!({"runId":run_id,"nonce":request.nonce,"planSha256":request.plan_sha256,"agentSha256":request.agent_sha256,"userSid":token.user_sid,"pid":std::process::id(),"powerShellRuntime":runtime.identity}),
        )?;
        let outcome = ps_file(&workflow, None, 1100);
        held.revalidate()?;
        if let Err(error) = &outcome {
            let _ = publish(
                &output,
                "native-child-failure.json",
                &json!({"error":error.to_string(),"nonce":request.nonce}),
            );
        }
        return outcome;
    }
    let _system = fixed_script(&system, system_source().as_bytes())?;
    let _workflow = fixed_script(&workflow, lifecycle_source().as_bytes())?;
    if operation == "enroll" {
        return ps_file(&system, Some("enroll"), 120);
    }
    if operation == "clear-logon" {
        return ps_file(&system, Some("clear-logon"), 30);
    }
    if in_job()? {
        return Err(
            "MSIX native controller must be outside the transport job; no child was launched"
                .into(),
        );
    }
    if operation == "control" {
        ps_file(&system, Some("prepare"), 30)?;
    }
    let session = read_json(&root.join("session.json"))?;
    let sid = session["userSid"]
        .as_str()
        .ok_or("Prepared account SID missing")?;
    let session_id = u32::try_from(
        session["sessionId"]
            .as_u64()
            .ok_or("Prepared session missing")?,
    )?;
    if session["runNonce"] != request.nonce {
        return Err("Prepared session nonce differs".into());
    }
    let user = PrimaryInteractiveUser::establish(sid, session_id)?;
    if operation == "control" {
        publish(
            &root,
            "control-started.json",
            &json!({"requestSha256":request.hash()?,"nonce":request.nonce,"powerShellRuntime":runtime.identity}),
        )?;
        let _control_image =
            hold_os_control(Path::new(r"C:\Windows\System32\cmd.exe"), CONTROL_SHA256)?;
        let child = GuestProcess::start_msix_driver_control(&user)?;
        let pid = child.process_id();
        let owned = child.is_in_owned_job()?;
        let exit = child.wait_for_exit(time_left(&request, 20)?);
        let normal = child.verify_empty_after_success();
        let cleanup = child.cleanup();
        let empty = child.active_processes();
        if exit? != 42 || !owned || normal.is_err() || cleanup.is_err() || empty? != 0 {
            return Err("Native fixed control or cleanup failed".into());
        }
        publish(
            &root,
            "control-result.json",
            &json!({"passed":true,"expectedExitCode":42,"observedExitCode":42,"jobEmpty":true,"heldProcessId":pid,"userSid":sid,"sessionId":session_id,"authenticationId":user.authentication_id,"requestSha256":request.hash()?,"nonce":request.nonce,"powerShellRuntime":runtime.identity}),
        )?;
        return Ok(());
    }
    let control = read_json(&root.join("control-result.json"))?;
    if control["passed"] != true
        || control["nonce"] != request.nonce
        || control["requestSha256"] != request.hash()?
        || control["authenticationId"] != user.authentication_id
    {
        return Err("Measured same-logon control required".into());
    }
    publish(
        &root,
        "run-started.json",
        &json!({"requestSha256":request.hash()?,"nonce":request.nonce,"planSha256":request.plan_sha256}),
    )?;
    let attempt = (|| -> Result<()> {
        ps_file(&system, Some("before"), 120)?;
        let child = GuestProcess::start_msix_worker_child(&user, run_id)?;
        let child_pid = child.process_id();
        let owned = child.is_in_owned_job()?;
        let exit = child.wait_for_exit(time_left(&request, 1200)?);
        let normal = child.verify_empty_after_success();
        let cleanup = child.cleanup();
        let active = child.active_processes();
        publish(
            &root,
            "job-cleanup.json",
            &json!({"childPid":child_pid,"inOwnedJob":owned,"exitCode":exit.as_ref().ok(),"operationError":exit.as_ref().err().map(ToString::to_string),"normalCleanupError":normal.as_ref().err().map(ToString::to_string),"cleanupError":cleanup.as_ref().err().map(ToString::to_string),"activeJobProcesses":active.as_ref().ok(),"nonce":request.nonce}),
        )?;
        if exit? != 0 || !owned {
            return Err("MSIX child failed; cold recovery required".into());
        }
        normal?;
        cleanup?;
        if active? != 0 {
            return Err("Owned MSIX job remains".into());
        }
        ps_file(&system, Some("after"), 120)?;
        let source = Path::new(&user.context().local_app_data)
            .join("AIW")
            .join(format!("msix-{}", request.nonce));
        let files = collect(&source, &root.join("evidence"))?;
        let assembly: Value = serde_json::from_slice(&inputs[1].read_bounded(16 * 1024 * 1024)?)?;
        aiw_evidence::verify_notepad_msix_lifecycle(&files, &assembly, sid, session_id)?;
        let worker_runtime = read_json(&root.join("evidence/msix-lifecycle/worker.json"))?;
        if worker_runtime["powerShellRuntime"] != serde_json::to_value(&runtime.identity)? {
            return Err(
                "Standard-user runtime receipt differs from approved SYSTEM runtime".into(),
            );
        }
        let lifecycle = read_json(&root.join("evidence/msix-lifecycle/result.json"))?;
        if lifecycle["completed"] != true
            || lifecycle["researchOnly"] != false
            || lifecycle["registrationCleanup"] != "verified"
            || lifecycle["payloadUnchanged"] != true
        {
            return Err("Production lifecycle terminal receipt incomplete".into());
        }
        let artifacts=files.iter().map(|(name,bytes)|json!({"path":format!("evidence/{name}"),"sha256":sha(bytes),"bytes":bytes.len()})).collect::<Vec<_>>();
        publish(
            &root,
            "result.json",
            &json!({"schemaVersion":"aiw.dev/msix-worker-result/v0alpha1","requestSha256":request.hash()?,"planSha256":request.plan_sha256,"nonce":request.nonce,"workerUuid":request.worker_uuid,"agentSha256":request.agent_sha256,"userSid":sid,"sessionId":session_id,"authenticationId":user.authentication_id,"lifecyclePassed":true,"jobEmpty":true,"privilegedPackageProcessAbsenceVerified":true,"files":artifacts,"isolation":"notMeasured","researchOnly":false,"powerShellRuntime":runtime.identity}),
        )?;
        Ok(())
    })();
    if let Err(error) = &attempt {
        let source = Path::new(&user.context().local_app_data)
            .join("AIW")
            .join(format!("msix-{}", request.nonce));
        if source.exists() && !root.join("evidence").exists() {
            let _ = collect(&source, &root.join("failed-evidence"));
        }
        let _ = publish(
            &root,
            "failure.json",
            &json!({"schemaVersion":"aiw.dev/msix-worker-failure/v0alpha1","nonce":request.nonce,"requestSha256":request.hash()?,"error":error.to_string(),"automaticRetry":false,"coldRestoreRequired":true}),
        );
    }
    request_file.revalidate()?;
    image.revalidate()?;
    attempt
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_worker_scripts_parse_with_driver_control_scoped_to_its_function() {
        for source in [system_source(), lifecycle_source()] {
            assert_eq!(
                source
                    .lines()
                    .filter(|line| line.eq_ignore_ascii_case("#Requires -PSEdition Core"))
                    .count(),
                1
            );
            assert_eq!(
                source
                    .lines()
                    .filter(|line| line.eq_ignore_ascii_case("#Requires -Version 7.6"))
                    .count(),
                1
            );
            assert!(source.contains("Stable x64 PowerShell Core >=7.6 required"));
        }
        let root = std::env::temp_dir().join(format!(
            "aiw-script-structure-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("workflow.ps1"), lifecycle_source()).unwrap();
        fs::write(root.join("system.ps1"), system_source()).unwrap();
        // Parse the exact generated scripts without executing application or
        // enrollment operations. An unwrapped driver body passed syntax checks
        // but ran before its EvidenceDirectory parameter existed in the guest.
        let output = crate::powershell::inert_test_output(std::process::Command::new(crate::powershell::test_executable())
            .args(["-NoProfile", "-NonInteractive", "-Command", r#"
$ErrorActionPreference='Stop'
foreach($name in @('system.ps1','workflow.ps1')) {
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:AIW_TEST_SCRIPT_ROOT $name),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
 if($name -eq 'system.ps1' -and !$ast.ParamBlock){throw 'System operation parameter must remain at script scope'}
 if($name -eq 'workflow.ps1'){
  $functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-AiwDriverControl'},$true))
  if($functions.Count -ne 1){throw 'One scoped driver control function required'}
  $function=$functions[0]
  if($function.Body.ParamBlock.Parameters.Count -ne 1 -or $function.Body.ParamBlock.Parameters[0].Name.VariablePath.UserPath -cne 'EvidenceDirectory'){throw 'Driver evidence parameter absent'}
  $references=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -ceq 'EvidenceDirectory'},$true))
  if(!$references.Count){throw 'Driver evidence references absent'}
  foreach($reference in $references){if($reference.Extent.StartOffset -lt $function.Extent.StartOffset -or $reference.Extent.EndOffset -gt $function.Extent.EndOffset){throw 'Driver body escaped its function'}}
  $calls=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Invoke-AiwDriverControl'},$true))
  if($calls.Count -ne 1 -or $calls[0].Extent.StartOffset -le $function.Extent.EndOffset){throw 'Lifecycle must explicitly invoke the defined control'}
 }
}
"#])
            .env("AIW_TEST_SCRIPT_ROOT", &root)
            .env_remove("PSModulePath")
            ).unwrap();
        fs::remove_dir_all(&root).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn os_control_accepts_servicing_hardlinks_without_weakening_application_intake() {
        let root = std::env::temp_dir().join(format!(
            "aiw-os-control-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let image = root.join("control.exe");
        let alias = root.join("servicing-link.exe");
        fs::write(&image, b"fixed control fixture").unwrap();
        fs::hard_link(&image, &alias).unwrap();
        assert!(HeldApplicationFile::open(&image).is_err());
        let held = hold_os_control(&image, &sha(b"fixed control fixture")).unwrap();
        assert!(OpenOptions::new().write(true).open(&alias).is_err());
        drop(held);
        assert!(hold_os_control(&image, &sha(b"different image")).is_err());
        assert!(hold_os_control(&root, &sha(b"fixed control fixture")).is_err());
        // A junction is a reparse point and must fail before image hashing.
        let junction = root.join("redirected");
        let status = std::process::Command::new(r"C:\Windows\System32\cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&root)
            .output()
            .unwrap();
        assert!(status.status.success());
        assert!(
            hold_os_control(
                &junction.join("control.exe"),
                &sha(b"fixed control fixture")
            )
            .is_err()
        );
        fs::remove_dir(&junction).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }
    #[test]
    fn application_wait_never_extends_the_approved_deadline() {
        assert_eq!(bounded_wait(50_000_000, 0, 20), Duration::from_secs(5));
        assert_eq!(bounded_wait(50_000_000, 0, 2), Duration::from_secs(2));
        assert_eq!(bounded_wait(50_000_000, 50_000_001, 20), Duration::ZERO);
        assert_eq!(bounded_wait(9_999_999, 0, 20), Duration::ZERO);
        assert_eq!(
            bounded_wait(i64::MAX, i64::MIN, 1200),
            Duration::from_secs(1200)
        );
    }
}
