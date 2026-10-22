//! Fixed production VM107 worker. Invoked only by the host's approved typed
//! protocol, never with caller-selected commands, scripts, or package identities.
use crate::{
    HeldApplicationFile, HeldPortableDirectory, guest_msi::GuestProcess,
    primary_interactive_user::PrimaryInteractiveUser,
};
use aiw_probe::MsixWorkerRequest;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use windows::Win32::System::{JobObjects::IsProcessInJob, Threading::GetCurrentProcess};
use windows::core::BOOL;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const BASE: &str = r"C:\ProgramData\AIW\MsixWorker";
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
    format!(
        "{}\nAdd-Type -TypeDefinition @'\n{}\n'@\n{}\n{}",
        &script[..at],
        include_str!("research_msix_native.cs"),
        include_str!("research_msix_inventory.ps1"),
        &script[at..]
    )
}
fn lifecycle_source() -> String {
    format!(
        "Add-Type -TypeDefinition @'\n{}\n'@\n{}\n{}\n{}",
        include_str!("research_msix_native.cs"),
        include_str!("research_msix_inventory.ps1"),
        include_str!("research_msix_driver_control.ps1"),
        include_str!("msix_worker/lifecycle.ps1")
    )
}
fn execute_ps(arguments: &[String], timeout: u64) -> Result<()> {
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
    let held = HeldPortableDirectory::open(root)?;
    if held.manifest().entries.len() > 512 || held.manifest().total_size_bytes > 16 * 1024 * 1024 {
        return Err("MSIX evidence tree exceeds bound".into());
    }
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
            &json!({"runId":run_id,"nonce":request.nonce,"planSha256":request.plan_sha256,"agentSha256":request.agent_sha256,"userSid":token.user_sid,"pid":std::process::id()}),
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
            &json!({"requestSha256":request.hash()?,"nonce":request.nonce}),
        )?;
        let cmd = HeldApplicationFile::open(Path::new(r"C:\Windows\System32\cmd.exe"))?;
        if cmd.observation().sha256
            != "15cd209c995b7d3009c91ca40892d5b8f1fb162f3e5f10716642ea278e8e0d7b"
        {
            return Err("Pinned project control image differs".into());
        }
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
            &json!({"passed":true,"expectedExitCode":42,"observedExitCode":42,"jobEmpty":true,"heldProcessId":pid,"userSid":sid,"sessionId":session_id,"authenticationId":user.authentication_id,"requestSha256":request.hash()?,"nonce":request.nonce}),
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
            &json!({"schemaVersion":"aiw.dev/msix-worker-result/v0alpha1","requestSha256":request.hash()?,"planSha256":request.plan_sha256,"nonce":request.nonce,"workerUuid":request.worker_uuid,"agentSha256":request.agent_sha256,"userSid":sid,"sessionId":session_id,"authenticationId":user.authentication_id,"lifecyclePassed":true,"jobEmpty":true,"privilegedPackageProcessAbsenceVerified":true,"files":artifacts,"isolation":"notMeasured","researchOnly":false}),
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
