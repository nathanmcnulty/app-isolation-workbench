//! Closed research trial, excluded from production builds. All commands and
//! input identities are compiled in; this is not a script execution interface.
use crate::guest_msi::GuestProcess;
use crate::guest_standard_user::StandardUserSession;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsHandle;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

const INPUT: &str = r"C:\AIW-Msix-Lifecycle-Input";
const EXE: &str = r"C:\AIW-Msix-Lifecycle-Input\msix_standard_user_lifecycle.exe";
const OUTPUT: &str = r"C:\AIW-Msix-Lifecycle-Output";
const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const INPUTS: [(&str, &str); 3] = [
    (
        "application.msix",
        "2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437",
    ),
    (
        "assembly.json",
        "d7eca3af76598534d29e411b4d4775d61e6ffe11174aa5a171b44bfe2a080c38",
    ),
    (
        "signing.json",
        "670e6f9e44211848c305c61261aa2ed6e2c94fac229214ec843cd4c9afab9e80",
    ),
];
type TrialResult<T> = Result<T, Box<dyn std::error::Error>>;

#[link(name = "Advapi32")]
unsafe extern "system" {
    fn GetUserNameW(buffer: *mut u16, length: *mut u32) -> i32;
}
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
    fn GetComputerNameW(buffer: *mut u16, length: *mut u32) -> i32;
}

fn user_name() -> TrialResult<String> {
    let mut buffer = [0u16; 256];
    let mut length = buffer.len() as u32;
    // SAFETY: writable bounded buffer and count remain live during the call.
    if unsafe { GetUserNameW(buffer.as_mut_ptr(), &mut length) } == 0
        || length == 0
        || length as usize > buffer.len()
    {
        return Err("Native username query failed".into());
    }
    Ok(String::from_utf16(&buffer[..length as usize - 1])?)
}

fn record(root: &Path, name: &str, value: serde_json::Value) -> TrialResult<()> {
    std::fs::write(root.join(name), serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

fn hold_inputs() -> TrialResult<Vec<File>> {
    let mut names = std::fs::read_dir(INPUT)?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    let mut expected = INPUTS
        .iter()
        .map(|(name, _)| std::ffi::OsString::from(name))
        .collect::<Vec<_>>();
    expected.push("msix_standard_user_lifecycle.exe".into());
    expected.sort();
    if names != expected {
        return Err("Closed mapped input inventory differs".into());
    }
    let mut held = Vec::new();
    for (name, expected) in INPUTS {
        // Share read only: Windows prevents replacement or writing while held.
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(Path::new(INPUT).join(name))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.file_attributes() & 0x400 != 0
            || metadata.len() > 16 * 1024 * 1024
        {
            return Err("Research input is not a bounded regular non-reparse file".into());
        }
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let size = file.read(&mut buffer)?;
            if size == 0 {
                break;
            }
            digest.update(&buffer[..size]);
        }
        if hex::encode(digest.finalize()) != expected {
            return Err(format!("Fixed input identity differs: {name}").into());
        }
        held.push(file);
    }
    Ok(held)
}

fn session_id(pid: u32) -> TrialResult<u32> {
    let mut session = 0;
    // SAFETY: writable session result remains live for the synchronous query.
    if unsafe { ProcessIdToSessionId(pid, &mut session) } == 0 {
        return Err(format!(
            "Native session query failed: {}",
            windows::core::Error::from_thread()
        )
        .into());
    }
    Ok(session)
}

fn hold_self() -> TrialResult<(File, String)> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(EXE)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & 0x400 != 0
        || metadata.len() > 16 * 1024 * 1024
    {
        return Err("Fixed research image refused".into());
    }
    let mut digest = Sha256::new();
    let mut bytes = [0u8; 65536];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        digest.update(&bytes[..count]);
    }
    Ok((file, hex::encode(digest.finalize())))
}

#[derive(Clone, Copy)]
enum InventoryStage {
    Before,
    BeforeCleanup,
    After,
}
impl InventoryStage {
    fn name(self) -> &'static str {
        match self {
            Self::Before => "parent-before.json",
            Self::BeforeCleanup => "parent-before-cleanup.json",
            Self::After => "parent-after.json",
        }
    }
}
fn native_prefix() -> String {
    format!(
        "$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n{}\n'@\n{}\n",
        include_str!("research_msix_native.cs"),
        include_str!("research_msix_inventory.ps1")
    )
}
fn parent_inventory(evidence: &Path, stage: InventoryStage) -> TrialResult<()> {
    // The destination is selected only from this closed enum, never caller text.
    let command = format!(
        "{}\n@{{packages=@(Get-AppxPackage -AllUsers -Name AIWResearch.NotepadPP|Select-Object PackageFullName,InstallLocation,PackageUserInformation);provisioned=@(Get-AppxProvisionedPackage -Online|Where-Object DisplayName -eq AIWResearch.NotepadPP|Select-Object PackageName);processes=Get-AiwPackageProcessInventory;configurationPaths=@('C:\\Users\\AiwStandardUser\\AppData\\Roaming\\Notepad++','C:\\Users\\AiwStandardUser\\AppData\\Local\\Packages\\AIWResearch.NotepadPP_q1fhfzcjv9wt6'|ForEach-Object {{@{{path=$_;present=(Test-Path -LiteralPath $_)}}}})}}|ConvertTo-Json -Depth 8|Set-Content C:\\AIW-Msix-Lifecycle-Output\\standard-user-lifecycle\\{} -Encoding UTF8",
        native_prefix(),
        stage.name()
    );
    let child = GuestProcess::start(
        POWERSHELL,
        &[
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            command,
        ],
    )?;
    let operation = child.wait_for_exit(Duration::from_secs(45));
    let normal = if operation.as_ref().is_ok_and(|code| *code == 0) {
        child.verify_empty_after_success()
    } else {
        Ok(())
    };
    let cleanup = child.cleanup();
    let code = operation?;
    normal?;
    cleanup?;
    if code != 0 {
        return Err("Parent registration inventory failed".into());
    }
    let bytes = std::fs::read(evidence.join(stage.name()))?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes))?;
    require_global_inventory(&value)
}
fn require_global_inventory(value: &serde_json::Value) -> TrialResult<()> {
    for name in ["packages", "provisioned"] {
        if !value[name].as_array().is_some_and(Vec::is_empty) {
            return Err(format!("Parent {name} inventory is not empty").into());
        }
    }
    require_empty_process_inventory(&value["processes"])?;
    Ok(())
}

fn script() -> String {
    format!(
        "{}\nfunction Invoke-AiwDriverControl {{\nparam([string]$EvidenceDirectory)\n{}\n}}\n{}",
        native_prefix(),
        include_str!("research_msix_driver_control.ps1"),
        include_str!("research_msix_lifecycle.ps1")
    )
}

pub fn run() -> TrialResult<()> {
    if !std::env::current_exe()?
        .to_string_lossy()
        .eq_ignore_ascii_case(EXE)
    {
        return Err("Fixed mapped executable required".into());
    }
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let (_image, image_hash) = hold_self()?;
    if arguments.len() == 1
        && (arguments[0] == "lifecycle-child" || arguments[0] == "vm-lifecycle-child")
    {
        if user_name()? != "AiwStandardUser" {
            return Err("Fixed standard user required".into());
        }
        let local = Path::new(r"C:\Users\AiwStandardUser\AppData\Local\AIW");
        let mut stage = "nativeToken";
        let attempt = (|| -> TrialResult<()> {
            let token = aiw_token::collect_current_process_token()?;
            if token.is_elevated || token.is_app_container || token.integrity.rid != 8192 {
                return Err("Medium non-elevated child required".into());
            }
            if arguments[0] == "vm-lifecycle-child" {
                stage = "primaryInteractiveContext";
                verify_primary_interactive(local, &image_hash)?;
            }
            stage = "heldInputs";
            let _inputs = hold_inputs()?;
            record(
                local,
                "child-identity.json",
                serde_json::json!({"pid":std::process::id(),"sid":token.user_sid,"sessionId":session_id(std::process::id())?,"imagePath":EXE,"imageSha256":image_hash}),
            )?;
            // Parent established this exact user's profile and granted this path.
            let stdout = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(local.join("lifecycle.stdout.log"))?;
            let stderr = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(local.join("lifecycle.stderr.log"))?;
            let fixed_script = script();
            let quoted = aiw_windows_command_line::join_arguments([
                POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &fixed_script,
            ]);
            if quoted.encode_utf16().count() >= 32767 {
                return Err("Fixed PowerShell command exceeds native limit".into());
            }
            stage = "supervisorSpawn";
            let mut supervisor = Command::new(POWERSHELL)
                .args(["-NoProfile", "-NonInteractive", "-Command", &fixed_script])
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr))
                .spawn()?;
            stage = "supervisorToken";
            let observation = aiw_token::collect_process_token(supervisor.as_handle())?;
            if observation.user_sid != token.user_sid
                || observation.is_elevated
                || observation.is_app_container
                || observation.integrity.rid != 8192
                || session_id(supervisor.id())? != session_id(std::process::id())?
            {
                return Err("PowerShell supervisor token/session differs".into());
            }
            record(
                local,
                "powershell-launch.json",
                serde_json::json!({"pid":supervisor.id(),"heldHandle":true,"token":observation,"sessionId":session_id(supervisor.id())?}),
            )?;
            stage = "supervisorWait";
            let code = supervisor.wait()?;
            if !code.success() {
                return Err(format!("Fixed lifecycle PowerShell exited {code}").into());
            }
            Ok(())
        })();
        if let Err(error) = &attempt {
            if let Err(export) = record(
                local,
                "native-child-failure.json",
                serde_json::json!({"stage":stage,"error":error.to_string(),"pid":std::process::id(),"researchOnly":true}),
            ) {
                return Err(format!("{error};nativeFailureExport={export}").into());
            }
        }
        return attempt;
    }
    if arguments.len() == 1 && arguments[0] == "vm-controller" {
        return run_vm_parent(&image_hash, false);
    }
    if arguments.len() == 1 && arguments[0] == "vm-launch-control" {
        return run_vm_parent(&image_hash, true);
    }
    if !arguments.is_empty() || user_name()? != "WDAGUtilityAccount" {
        return Err("Closed parent requires Sandbox operator and no arguments".into());
    }
    let evidence = Path::new(OUTPUT).join("standard-user-lifecycle");
    if std::fs::read_dir(OUTPUT)?.next().is_some() {
        return Err("Fresh mapped output required".into());
    }
    std::fs::create_dir(&evidence)?;
    let attempt = run_parent(&evidence);
    if let Err(error) = &attempt {
        record(
            &evidence,
            "failure.json",
            serde_json::json!({"error":error.to_string(),"researchOnly":true,"recovery":"dispose exact owned Sandbox; retain stage"}),
        )?;
    }
    attempt
}

fn run_parent(evidence: &Path) -> TrialResult<()> {
    let _inputs = hold_inputs()?;
    let (_image, image_hash) = hold_self()?;
    parent_inventory(evidence, InventoryStage::Before)?;
    let standard = StandardUserSession::establish()?;
    record(
        evidence,
        "context.json",
        serde_json::to_value(standard.context())?,
    )?;
    standard.impersonate(|| {
        for name in [
            "msix_standard_user_lifecycle.exe",
            "application.msix",
            "assembly.json",
            "signing.json",
        ] {
            File::open(Path::new(INPUT).join(name)).map_err(|error| {
                crate::GuestMsiExecutionError::Process(format!(
                    "Standard-user input access: {error}"
                ))
            })?;
        }
        std::fs::create_dir_all(standard.document_root())
            .map_err(|error| crate::GuestMsiExecutionError::Process(error.to_string()))
    })?;
    let child = GuestProcess::start_standard_user(EXE, &["lifecycle-child".into()], &standard)?;
    finish_lifecycle(
        evidence,
        &child,
        &standard.context().user_sid,
        standard.document_root(),
        &image_hash,
        false,
    )
}

fn finish_lifecycle(
    evidence: &Path,
    child: &GuestProcess,
    expected_sid: &str,
    source: &Path,
    image_hash: &str,
    primary: bool,
) -> TrialResult<()> {
    let operation = (|| -> TrialResult<()> {
        let assigned = child.is_in_owned_job()?;
        if !assigned {
            return Err("Native child not in exact owned job".into());
        }
        let expected_session = session_id(child.process_id())?;
        record(
            evidence,
            "child-started.json",
            serde_json::json!({"pid":child.process_id(),"heldHandle":true,"deadlineSeconds":1200,"inOwnedJob":assigned,"sessionId":expected_session,"imageSha256":image_hash}),
        )?;
        record(
            evidence,
            "child-token.json",
            serde_json::to_value(child.collect_token()?)?,
        )?;
        let code = child.wait_for_exit(Duration::from_secs(1200))?;
        record(
            evidence,
            "child-exit.json",
            serde_json::json!({"pid":child.process_id(),"exitCode":code}),
        )?;
        if code != 0 {
            return Err(format!("Fixed lifecycle child exited {code}").into());
        }
        let identity: serde_json::Value =
            serde_json::from_slice(&std::fs::read(source.join("child-identity.json"))?)?;
        if identity["pid"] != child.process_id()
            || identity["sid"] != expected_sid
            || identity["sessionId"] != expected_session
            || identity["imagePath"] != EXE
            || identity["imageSha256"] != image_hash
        {
            return Err("Child identity differs from held launch".into());
        }
        Ok(())
    })();
    // Cleanup always precedes export or success publication, even on failure.
    let before_inventory = child.diagnostic_processes();
    let external_inventory = parent_inventory(evidence, InventoryStage::BeforeCleanup);
    let normal = if operation.is_ok() {
        child.verify_empty_after_success()
    } else {
        Ok(())
    };
    let cleanup = child.cleanup();
    let active = child.active_processes();
    record(
        evidence,
        "job-cleanup.json",
        serde_json::json!({
            "operationError":operation.as_ref().err().map(ToString::to_string),
            "normalCleanupError":normal.as_ref().err().map(ToString::to_string),
            "cleanupError":cleanup.as_ref().err().map(ToString::to_string),
            "activeJobProcesses":active.as_ref().ok(),
            "readbackError":active.as_ref().err().map(ToString::to_string),
            "beforeInventory":before_inventory.as_ref().ok(),
            "beforeInventoryError":before_inventory.as_ref().err().map(ToString::to_string),
            "externalInventoryError":external_inventory.as_ref().err().map(ToString::to_string),
            "brokeredApplicationScope":"not inferred from job; exact worker disposal required"
        }),
    )?;
    let exported = export(source, evidence);
    if let Err(error) = &exported {
        record(
            evidence,
            "export-failure.json",
            serde_json::json!({"exportError":error.to_string(),"primaryError":operation.as_ref().err().map(ToString::to_string)}),
        )?;
    }
    if operation.is_err()
        || normal.is_err()
        || cleanup.is_err()
        || exported.is_err()
        || external_inventory.is_err()
        || !active.as_ref().is_ok_and(|count| *count == 0)
    {
        return Err(format!("operation={:?};normalCleanup={normal:?};jobCleanup={cleanup:?};export={exported:?};externalInventory={external_inventory:?};jobReadback={active:?}",operation.as_ref().err().map(ToString::to_string)).into());
    }
    operation?;
    exported?;
    normal?;
    cleanup?;
    if active? != 0 {
        return Err("Owned job not empty".into());
    }
    parent_inventory(evidence, InventoryStage::After)?;
    let read = |name: &str| -> TrialResult<serde_json::Value> {
        let bytes = std::fs::read(evidence.join(name))?;
        Ok(serde_json::from_slice(
            bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes),
        )?)
    };
    let worker = read("msix-lifecycle/worker.json")?;
    let supervisor = read("powershell-launch.json")?;
    if worker["operatorSid"] != expected_sid
        || worker["sessionId"] != supervisor["sessionId"]
        || worker["supervisorPid"] != supervisor["pid"]
        || worker["inInheritedJob"] != true
    {
        return Err("Retained PowerShell identity differs".into());
    }
    let raw = std::fs::read(evidence.join("msix-lifecycle/result.json"))?;
    let result: serde_json::Value =
        serde_json::from_slice(raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&raw))?;
    if result["completed"] != true
        || result["signedSha256"] != INPUTS[0].1
        || result["packageFullName"] != "AIWResearch.NotepadPP_8.9.8.0_x64__q1fhfzcjv9wt6"
    {
        return Err("Closed lifecycle terminal result differs".into());
    }
    let assembly: serde_json::Value =
        serde_json::from_slice(&std::fs::read(Path::new(INPUT).join("assembly.json"))?)?;
    validate_lifecycle(
        evidence,
        &assembly,
        expected_sid,
        session_id(child.process_id())?,
    )?;
    if primary {
        let context = read_receipt(evidence, "primary-context.json")?;
        let receipt = read_receipt(evidence, "primary-session.json")?;
        if receipt["verified"] != true
            || receipt["runNonce"] != context["runNonce"]
            || receipt["observation"]["UserSid"] != expected_sid
            || receipt["observation"]["SessionId"] != session_id(child.process_id())?
            || receipt["observation"]["AuthenticationId"] != context["authenticationId"]
        {
            return Err("Primary interactive receipt differs".into());
        }
    }
    record(
        evidence,
        "result.json",
        serde_json::json!({"researchOnly":true,"passed":true,"jobEmpty":true,"applicationLifecycle":"see retained stage observations","workerCleanup":if primary {"retain evidence; restore dedicated VM boundary after failure; exact account cleanup after success"} else {"dispose exact owned Sandbox"},"isolation":"notMeasured"}),
    )
}

fn read_receipt(root: &Path, name: &str) -> TrialResult<serde_json::Value> {
    let bytes = std::fs::read(root.join(name))?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("Receipt exceeds closed research bound".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes))?;
    if !value.is_object() && !value.is_array() {
        return Err("Structured receipt missing".into());
    }
    Ok(value)
}

const PREPARATION: &str = r"C:\AIW-Msix-Lifecycle-Preparation.json";
const VM_ID: &str = "cb7cc9f0-81f7-4326-8c52-828e42673d11";
const VM_OPERATOR_SID: &str = "S-1-5-21-3407263227-439785483-4249424476-500";
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrimaryPreparation {
    schema_version: String,
    vm_id: String,
    source_image_sha256: String,
    user_sid: String,
    session_id: u32,
    not_before_file_time: i64,
    not_after_file_time: i64,
    run_nonce: String,
    account_created: bool,
    account_name: String,
}
fn validate_preparation(value: &PrimaryPreparation, image_hash: &str, now: i64) -> TrialResult<()> {
    let sid_prefix = "S-1-5-21-3407263227-439785483-4249424476-";
    let rid = value
        .user_sid
        .strip_prefix(sid_prefix)
        .and_then(|v| v.parse::<u32>().ok());
    if value.schema_version != "aiw.dev/research-primary-msix/v1"
        || value.vm_id != VM_ID
        || value.source_image_sha256 != image_hash
        || !rid.is_some_and(|v| v >= 1000)
        || value.session_id == 0
        || value.account_name != "AiwStandardUser"
        || !value.account_created
        || value.run_nonce.len() != 64
        || !value
            .run_nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || value.not_before_file_time <= 0
        || now < value.not_before_file_time
        || now > value.not_after_file_time
        || value
            .not_after_file_time
            .checked_sub(value.not_before_file_time)
            .is_none_or(|span| span > 1800 * 10_000_000)
    {
        return Err("Closed run-owned primary preparation differs or expired".into());
    }
    Ok(())
}
fn run_fixed_powershell(command: String, deadline: u64) -> TrialResult<()> {
    let child = GuestProcess::start(
        POWERSHELL,
        &[
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            command,
        ],
    )?;
    let operation = (|| {
        let code = child.wait_for_exit(Duration::from_secs(deadline))?;
        if code != 0 {
            return Err(crate::GuestMsiExecutionError::Process(format!(
                "Fixed primary-context PowerShell failed: {code}"
            )));
        }
        child.verify_empty_after_success()
    })();
    let cleanup = child.cleanup();
    crate::guest_msi::complete_process_operation(operation, cleanup)?;
    Ok(())
}
fn run_vm_parent(image_hash: &str, launch_control: bool) -> TrialResult<()> {
    let token = aiw_token::collect_current_process_token()?;
    if token.user_sid != "S-1-5-18" || session_id(std::process::id())? != 0 {
        return Err("Dedicated VM controller requires LocalSystem session zero".into());
    }
    // An impersonated thread cannot borrow SYSTEM process authority.
    use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
    let mut thread_token = windows::Win32::Foundation::HANDLE::default();
    // SAFETY: current thread pseudo handle and writable output handle.
    match unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            windows::Win32::Security::TOKEN_QUERY,
            true,
            &mut thread_token,
        )
    } {
        Ok(()) => {
            use std::os::windows::io::{FromRawHandle, OwnedHandle};
            // SAFETY: successful query transferred a real token handle.
            let _held = unsafe { OwnedHandle::from_raw_handle(thread_token.0) };
            return Err("Impersonated VM controller refused".into());
        }
        Err(error) if error.code() == windows::core::HRESULT::from_win32(1008) => {}
        Err(error) => return Err(error.into()),
    }
    let mut computer = [0u16; 256];
    let mut length = computer.len() as u32;
    // SAFETY: bounded writable native computer-name buffer.
    if unsafe { GetComputerNameW(computer.as_mut_ptr(), &mut length) } == 0
        || !String::from_utf16(&computer[..length as usize])?.eq_ignore_ascii_case("aiwcleanhost")
    {
        return Err("Pinned dedicated VM computer required".into());
    }
    let _input_directory = hold_directory(Path::new(INPUT))?;
    let _output_directory = hold_directory(Path::new(OUTPUT))?;
    let _inputs = hold_inputs()?;
    let (_image, _) = hold_self()?;
    let mut preparation_file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(PREPARATION)?;
    let metadata = preparation_file.metadata()?;
    if !metadata.is_file() || metadata.len() > 8192 || metadata.file_attributes() & 0x400 != 0 {
        return Err("Bounded held preparation required".into());
    }
    let mut bytes = Vec::new();
    preparation_file.read_to_end(&mut bytes)?;
    let prepared: PrimaryPreparation =
        serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes))?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
            / 100,
    )? + 116444736000000000;
    validate_preparation(&prepared, image_hash, now)?;
    let command = format!(
        r#"$ErrorActionPreference='Stop'
{identity}
$acl=Get-Acl -LiteralPath '{PREPARATION}';$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
if(!$acl.AreAccessRulesProtected -or $owner -notin @('S-1-5-18','{VM_OPERATOR_SID}')){{throw 'Protected preparation owner differs'}}
$rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]);if($rules.Count -eq 0){{throw 'Preparation ACL absent'}}
foreach($rule in $rules){{$sid=$rule.IdentityReference.Value;if($rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or $sid -notin @('S-1-5-18','{VM_OPERATOR_SID}','{sid}')){{throw 'Preparation ACL principal differs'}};if($sid -ceq '{sid}'){{$allowed=[int64][Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [int64][Security.AccessControl.FileSystemRights]::Synchronize;if(([int64]$rule.FileSystemRights -band (-bnot $allowed)) -ne 0){{throw 'Application user may write preparation'}}}}}}
if(!(Test-Path -LiteralPath 'Registry::HKEY_USERS\{sid}')){{throw 'Actual interactive profile hive not loaded'}}
$user=Get-LocalUser -Name AiwStandardUser;if($user.SID.Value -cne '{sid}'){{throw 'Prepared account SID differs'}}
"#,
        sid = prepared.user_sid,
        identity = azure_identity_script()
    );
    run_fixed_powershell(command, 30)?;
    let evidence = Path::new(OUTPUT).join("standard-user-lifecycle");
    if std::fs::read_dir(OUTPUT)?.next().is_some() {
        return Err("Fresh dedicated VM output required".into());
    }
    std::fs::create_dir(&evidence)?;
    let attempt = (|| -> TrialResult<()> {
        record(
            &evidence,
            "controller-job.json",
            controller_job_observation()?,
        )?;
        parent_inventory(&evidence, InventoryStage::Before)?;
        let user = crate::research_msix_primary_user::PrimaryInteractiveUser::establish(
            &prepared.user_sid,
            prepared.session_id,
        )?;
        record(
            &evidence,
            "context.json",
            serde_json::to_value(user.context())?,
        )?;
        record(
            &evidence,
            "primary-context.json",
            serde_json::json!({"prepared":prepared,"runNonce":prepared.run_nonce,"authenticationId":user.authentication_id,"sourceImageSha256":image_hash}),
        )?;
        if launch_control {
            return run_primary_launch_control(&evidence, &user);
        }
        // Grant only read access to the fixed context; the application writes its
        // own profile, never this privileged evidence destination.
        run_fixed_powershell(
            format!(
                r#"$ErrorActionPreference='Stop';$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'));foreach($sid in @('S-1-5-18','{VM_OPERATOR_SID}')){{$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}};$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('{sid}'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath '{OUTPUT}' -AclObject $acl"#,
                sid = prepared.user_sid
            ),
            30,
        )?;
        let source = Path::new(r"C:\Users\AiwStandardUser\AppData\Local\AIW");
        crate::guest_standard_user::impersonate_primary_token(user.token_handle(), || {
            if source.exists() {
                return Err(crate::GuestMsiExecutionError::Process(
                    "Fresh interactive evidence required".into(),
                ));
            }
            std::fs::create_dir(source)
                .map_err(|e| crate::GuestMsiExecutionError::Process(e.to_string()))
        })?;
        let _source_directory = hold_directory(source)?;
        let child = GuestProcess::start_primary_interactive(&user)?;
        finish_lifecycle(
            &evidence,
            &child,
            &prepared.user_sid,
            source,
            image_hash,
            true,
        )
    })();
    if let Err(error) = &attempt {
        record(
            &evidence,
            "failure.json",
            serde_json::json!({"error":error.to_string(),"researchOnly":true,"controlOnly":launch_control,"recovery":"retain stage; restore exact dedicated VM boundary; no account adoption or automatic retry"}),
        )?;
    }
    attempt
}

fn run_primary_launch_control(
    evidence: &Path,
    user: &crate::research_msix_primary_user::PrimaryInteractiveUser,
) -> TrialResult<()> {
    let path = Path::new(r"C:\Windows\System32\cmd.exe");
    let _directory = hold_directory(path.parent().ok_or("OS control parent absent")?)?;
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
    let hash = hex::encode(digest.finalize());
    run_fixed_powershell(
        "$ErrorActionPreference='Stop';$s=Get-AuthenticodeSignature -LiteralPath 'C:\\Windows\\System32\\cmd.exe';if($s.Status -ne 'Valid'){throw 'OS control signature invalid'}".into(),
        30,
    )?;
    record(
        evidence,
        "launch-control-request.json",
        serde_json::json!({
            "controlOnly":true,"imagePath":path,"imageSha256":hash,
            "signatureValid":true,"expectedExitCode":42,"breakawayRequested":false,
            "userSid":user.context().user_sid,"sessionId":user.session,
            "authenticationId":user.authentication_id
        }),
    )?;
    let child = GuestProcess::start_primary_launch_control(user)?;
    let operation = (|| {
        let code = child.wait_for_exit(Duration::from_secs(10))?;
        if code != 42 {
            return Err(crate::GuestMsiExecutionError::Process(format!(
                "Fixed primary launch control exited {code}"
            )));
        }
        child.verify_empty_after_success()?;
        Ok(code)
    })();
    let cleanup = child.cleanup();
    let code = crate::guest_msi::complete_process_operation(operation, cleanup)?;
    // A control receipt is deliberately distinct from lifecycle result.json.
    record(
        evidence,
        "launch-control-result.json",
        serde_json::json!({
            "researchOnly":true,"controlOnly":true,"passed":true,
            "exitCode":code,"processId":child.process_id(),"jobEmpty":true,
            "applicationCompatibility":"notMeasured","isolation":"notMeasured"
        }),
    )
}

// Diagnostic only: a nested job query describes the immediate job, not every
// ancestor. It neither grants breakaway nor establishes child-job ownership.
fn controller_job_observation() -> TrialResult<serde_json::Value> {
    use windows::Win32::System::JobObjects::{
        IsProcessInJob, JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;
    let mut member = windows::core::BOOL(0);
    // SAFETY: current-process pseudo handle and writable membership output.
    unsafe { IsProcessInJob(GetCurrentProcess(), None, &mut member) }?;
    let mut limits = None;
    let mut ui_restrictions = None;
    if member.as_bool() {
        let mut extended = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut ui = JOBOBJECT_BASIC_UI_RESTRICTIONS::default();
        // SAFETY: NULL selects this process's immediate job; each output has
        // the exact native structure size. No job settings are modified.
        unsafe {
            QueryInformationJobObject(
                None,
                JobObjectExtendedLimitInformation,
                (&mut extended as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&extended) as u32,
                None,
            )?;
            QueryInformationJobObject(
                None,
                JobObjectBasicUIRestrictions,
                (&mut ui as *mut JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                std::mem::size_of_val(&ui) as u32,
                None,
            )?;
        }
        limits = Some(extended.BasicLimitInformation.LimitFlags.0);
        ui_restrictions = Some(ui.UIRestrictionsClass.0);
    }
    Ok(serde_json::json!({
        "processId": std::process::id(),
        "sessionId": session_id(std::process::id())?,
        "inAnyJob": member.as_bool(),
        "queryScope": "immediateJobOnly",
        "limitFlags": limits,
        "uiRestrictions": ui_restrictions,
        "diagnosticOnly": true
    }))
}
fn hold_directory(path: &Path) -> TrialResult<File> {
    // Allow child writes, deny delete/rename of this exact directory entry.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .custom_flags(0x02200000)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err("Held non-reparse research directory required".into());
    }
    Ok(file)
}
fn verify_primary_interactive(local: &Path, image_hash: &str) -> TrialResult<()> {
    let context = read_receipt(
        &Path::new(OUTPUT).join("standard-user-lifecycle"),
        "primary-context.json",
    )?;
    let prepared: PrimaryPreparation = serde_json::from_value(context["prepared"].clone())?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
            / 100,
    )? + 116444736000000000;
    validate_preparation(&prepared, image_hash, now)?;
    if context["sourceImageSha256"] != image_hash {
        return Err("Held primary child source identity differs".into());
    }
    run_fixed_powershell(primary_observation_script(), 30)?;
    let receipt = read_receipt(local, "primary-session.json")?;
    if receipt["verified"] != true || receipt["runNonce"] != prepared.run_nonce {
        return Err("Verified primary-context binding absent".into());
    }
    Ok(())
}
fn primary_native_source() -> String {
    let interactive = include_str!("research_msix_interactive.cs")
        .lines()
        .filter(|line| !line.starts_with("using "))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "using System.Diagnostics;\nusing System.Security.Principal;\n{}\n{interactive}",
        include_str!("research_msix_native.cs")
    )
}
fn azure_identity_script() -> String {
    format!(
        r#"$request=[Net.HttpWebRequest]::Create('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01');$request.Proxy=$null;$request.Timeout=5000;$request.ReadWriteTimeout=5000;$request.Headers.Add('Metadata','true');$response=$request.GetResponse()
try{{$reader=[IO.StreamReader]::new($response.GetResponseStream());try{{$metadata=$reader.ReadToEnd()|ConvertFrom-Json}}finally{{$reader.Dispose()}}}}finally{{$response.Dispose()}}
if($metadata.vmId -cne '{VM_ID}' -or $metadata.name -cne 'aiw-clean-host-0921' -or $metadata.subscriptionId -cne '43babb60-9e73-4dc8-b769-4401c01aad73'){{throw 'Pinned Azure VM identity differs'}}"#
    )
}
fn primary_observation_script() -> String {
    format!(
        r#"$ErrorActionPreference='Stop'
try {{
{identity}
Add-Type -TypeDefinition @'
{native}
'@
$context=Get-Content -LiteralPath 'C:\AIW-Msix-Lifecycle-Output\standard-user-lifecycle\primary-context.json' -Raw|ConvertFrom-Json
$acl=Get-Acl -LiteralPath 'C:\AIW-Msix-Lifecycle-Output';if(!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18'){{throw 'Protected SYSTEM context directory required'}}
foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){{$sid=$rule.IdentityReference.Value;if($rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or $sid -notin @('S-1-5-18','{VM_OPERATOR_SID}',$context.prepared.userSid)){{throw 'Primary context ACL differs'}};if($sid -ceq $context.prepared.userSid){{$allowed=[int64][Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [int64][Security.AccessControl.FileSystemRights]::Synchronize;if(([int64]$rule.FileSystemRights -band (-bnot $allowed)) -ne 0){{throw 'Application user may write primary context'}}}}}}
if((Get-Acl -LiteralPath 'C:\AIW-Msix-Lifecycle-Output\standard-user-lifecycle\primary-context.json').GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18'){{throw 'Primary context record owner differs'}}
$value=[AiwInteractiveNative]::ObserveCurrent();[AiwInteractiveNative]::RequireOwnedStandardSession($value,$context.prepared.userSid,$context.prepared.notBeforeFileTime,$context.prepared.notAfterFileTime)
if($value.AuthenticationId -cne $context.authenticationId -or $value.SessionId -ne $context.prepared.sessionId){{throw 'WTS primary authentication differs'}}
$record=@{{verified=$true;runNonce=$context.runNonce;observation=$value}}|ConvertTo-Json -Depth 10
$bytes=[Text.Encoding]::UTF8.GetBytes($record);$file=[IO.File]::Open('C:\Users\AiwStandardUser\AppData\Local\AIW\primary-session.json',[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}}finally{{$file.Dispose()}}
}} catch {{
$primary=$_;$record=@{{stage='primaryInteractiveSession';exception=$_.Exception.ToString();errorRecord=($_|Out-String);applicationTrialStarted=$false}}|ConvertTo-Json -Depth 8
$bytes=[Text.Encoding]::UTF8.GetBytes($record);$file=[IO.File]::Open('C:\Users\AiwStandardUser\AppData\Local\AIW\primary-session-failure.json',[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}}finally{{$file.Dispose()}};throw $primary
}}
"#,
        native = primary_native_source(),
        identity = azure_identity_script()
    )
}
fn require_empty_process_inventory(value: &serde_json::Value) -> TrialResult<()> {
    for key in ["matches", "queryErrors"] {
        if !value[key].as_array().is_some_and(Vec::is_empty) {
            return Err(format!("Package process {key} is not proven empty").into());
        }
    }
    let diagnostics = value["nonPackageImageUnavailable"]
        .as_array()
        .ok_or("Missing non-package image query diagnostics")?;
    if diagnostics.len() > 512 {
        return Err("Image query diagnostic bound exceeded".into());
    }
    for process in diagnostics {
        if process["Pid"].as_u64().is_none_or(|pid| pid <= 4)
            || process["PackageIdentityStatus"] != "noPackage"
            || process["Name"]
                .as_str()
                .is_none_or(|name| name.is_empty() || name.eq_ignore_ascii_case("notepad++"))
            || !process
                .get("PackageFullName")
                .is_some_and(serde_json::Value::is_null)
            || !process
                .get("ImagePath")
                .is_some_and(serde_json::Value::is_null)
            || process["ImageQueryError"]
                .as_i64()
                .is_none_or(|code| code <= 0)
        {
            return Err("Image query diagnostics lack positive no-package evidence".into());
        }
    }
    Ok(())
}
fn require_application_user_process_diagnostics(value: &serde_json::Value) -> TrialResult<()> {
    if value["queryAuthority"] != "applicationUserDiagnostic"
        || value["globalAbsenceVerified"] != false
    {
        return Err("Application-user process diagnostic authority missing".into());
    }
    let errors = value["queryErrors"]
        .as_array()
        .ok_or("Missing process query diagnostics")?;
    if errors.len() > 512 {
        return Err("Process query diagnostic bound exceeded".into());
    }
    for error in errors {
        if error["pid"].as_u64().is_none_or(|pid| pid <= 4)
            || error["name"]
                .as_str()
                .is_none_or(|name| name.is_empty() || name.eq_ignore_ascii_case("notepad++"))
            || error["error"]
                .as_str()
                .is_none_or(|message| message.is_empty() || message.len() > 4096)
        {
            return Err("Unknown or named-target process diagnostic refused".into());
        }
    }
    // Retain unknown queries in the original receipt. Reuse positive-match and
    // no-package image validation here; only the privileged parent's inventories
    // before and after job cleanup can establish global absence.
    let mut observed = value.clone();
    observed["queryErrors"] = serde_json::json!([]);
    require_empty_process_inventory(&observed)
}
const LIFECYCLE_RECEIPTS: &[&str] = &[
    "install-started.json",
    "worker.json",
    "preflight-inventory.json",
    "package-processes-before.json",
    "driver-control/control.json",
    "driver-controls-completed.json",
    "package-input.json",
    "config-before.json",
    "post-install-inventory.json",
    "installed.json",
    "manifest-before.json",
    "config-installed-before-launch.json",
    "payload-before.json",
    "document-input.json",
    "activation-suspended.json",
    "activation-returned.json",
    "activated.json",
    "application-window.json",
    "awaiting-edit.json",
    "editor-exit.json",
    "package-processes-after-close.json",
    "document-output.json",
    "config-after.json",
    "payload-after.json",
    "manifest-after.json",
    "uninstall-started.json",
    "package-processes-after-uninstall.json",
    "cleanup.json",
    "result.json",
];
fn validate_lifecycle(
    root: &Path,
    assembly: &serde_json::Value,
    sid: &str,
    session: u32,
) -> TrialResult<()> {
    let stages = root.join("msix-lifecycle");
    for name in LIFECYCLE_RECEIPTS {
        read_receipt(&stages, name)?;
    }
    if std::fs::read(stages.join("installed-manifest.xml"))?.is_empty() {
        return Err("Installed manifest evidence absent".into());
    }
    for name in ["native-child-failure.json", "failure.json"] {
        if root.join(name).exists() {
            return Err("Failure evidence precludes terminal success".into());
        }
    }
    if stages.join("failure.json").exists() {
        return Err("Failed application trial cannot publish success".into());
    }
    let get = |name: &str| read_receipt(&stages, name);
    let worker = get("worker.json")?;
    let worker_token = &worker["operatorToken"];
    if worker["operatorSid"] != sid
        || worker["sessionId"] != session
        || worker["inInheritedJob"] != true
        || worker_token["UserSid"] != sid
        || worker_token["TokenSessionId"] != session
        || worker_token["IsElevated"] != false
        || worker_token["AdministratorsEnabled"] != false
        || worker_token["IsAppContainer"] != false
        || worker_token["IntegritySid"] != "S-1-16-8192"
    {
        return Err("Standard supervisor observations differ".into());
    }
    for name in ["config-before.json", "config-installed-before-launch.json"] {
        if !get(name)?.as_array().is_some_and(Vec::is_empty) {
            return Err("Configuration preflight not empty".into());
        }
    }
    let preflight = get("preflight-inventory.json")?;
    for key in ["packages", "processes"] {
        if !preflight[key].as_array().is_some_and(Vec::is_empty) {
            return Err("Application preflight not empty".into());
        }
    }
    let control = get("driver-control/control.json")?;
    let modes = control["controls"]
        .as_array()
        .ok_or("Driver controls are not an array")?;
    if control["passed"] != true || control["sessionId"] != session || modes.len() != 3 {
        return Err("Closed driver controls incomplete".into());
    }
    let mut pids = std::collections::BTreeSet::new();
    for (index, mode) in ["success", "failure", "deadline"].into_iter().enumerate() {
        let record = &modes[index];
        if record["mode"] != mode
            || record["heldHandle"] != true
            || record["inInheritedJob"] != true
            || record["exited"] != true
            || record["imagePath"].as_str() != Some(POWERSHELL)
            || !record["pid"].as_u64().is_some_and(|pid| {
                pid > 0
                    && record["startTime"]
                        .as_str()
                        .is_some_and(|time| !time.is_empty() && pids.insert((pid, time.to_owned())))
            })
            || record["deadlineHit"] != (mode == "deadline")
            || (mode == "success" && record["exitCode"] != 0)
            || (mode == "failure" && record["exitCode"] != 42)
            || (mode == "deadline" && !record["exitCode"].as_i64().is_some_and(|code| code != 0))
        {
            return Err(format!("Closed {mode} control differs").into());
        }
        for (stream, expected) in [
            ("stdout", "aiw-owned-control-out"),
            ("stderr", "aiw-owned-control-error"),
        ] {
            let bytes = std::fs::read(stages.join(format!("driver-control/{mode}.{stream}.log")))?;
            if bytes.len() > 1024 || std::str::from_utf8(&bytes)?.trim() != expected {
                return Err("Control stream identity differs".into());
            }
        }
    }
    if get("driver-controls-completed.json")?["controlsPassed"] != true {
        return Err("Pre-install control checkpoint missing".into());
    }
    let input = get("package-input.json")?;
    if input["signedSha256"] != INPUTS[0].1
        || input["publisher"] != "CN=Nathan McNulty, O=Nathan McNulty, L=Soldotna, S=Alaska, C=US"
        || input["sourceSha256"]
            != "b269383239464a945d17cfabfccf53935b83d80d907922310fdfd50d80274c66"
        || input["sizeBytes"] != 8641353
        || input["signatureStatus"] != "Valid"
        || input["signerThumbprint"] != "AD05F224A248CE998FEF1EF6EA75CBF72747EE38"
        || !input["timestampThumbprint"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    {
        return Err("Retained signed input binding differs".into());
    }
    let inventory = assembly["payloadInventory"]
        .as_array()
        .ok_or("Assembly inventory missing")?;
    let before = get("payload-before.json")?;
    let before = before.as_array().ok_or("Payload observation missing")?;
    if inventory.len() != 220 || before.len() != 220 {
        return Err("Complete 220-entry payload required".into());
    }
    for (expected, observed) in inventory.iter().zip(before) {
        if expected["path"] != observed["path"] || expected["sha256"] != observed["sha256"] {
            return Err("Installed payload differs from pinned inventory".into());
        }
    }
    let after = get("payload-after.json")?;
    if after["matchesOriginalInventory"] != true || after["filesChecked"] != 220 {
        return Err("Post-workflow payload check missing".into());
    }
    let expected_manifest = inventory
        .iter()
        .find(|entry| entry["path"] == "AppxManifest.xml")
        .ok_or("Manifest inventory missing")?;
    if get("manifest-before.json")?["sha256"] != expected_manifest["sha256"]
        || get("manifest-after.json")?["sha256"] != expected_manifest["sha256"]
    {
        return Err("Raw installed manifest identity differs".into());
    }
    let installed = get("installed.json")?;
    if installed["packageFullName"] != "AIWResearch.NotepadPP_8.9.8.0_x64__q1fhfzcjv9wt6"
        || installed["packageFamilyName"] != "AIWResearch.NotepadPP_q1fhfzcjv9wt6"
    {
        return Err("Installed identity differs".into());
    }
    let post_install = get("post-install-inventory.json")?;
    if !post_install.as_array().is_some_and(|items| {
        items.len() == 1 && items[0]["PackageFullName"] == installed["packageFullName"]
    }) {
        return Err("Exact registration readback missing".into());
    }
    let activated = get("activated.json")?;
    let suspended = get("activation-suspended.json")?;
    for key in [
        "processId",
        "sessionId",
        "startTime",
        "imagePath",
        "imageSha256",
        "packageObservation",
        "applicationUserModelId",
        "inAnyJob",
        "launchMethod",
    ] {
        if suspended[key] != activated[key] {
            return Err("Suspended application observation differs".into());
        }
    }
    let observation = &activated["packageObservation"];
    let expected_image = inventory
        .iter()
        .find(|entry| entry["path"] == "Application/notepad++.exe")
        .ok_or("Image inventory missing")?;
    let pid = activated["processId"]
        .as_u64()
        .filter(|pid| *pid > 0)
        .ok_or("Activated process PID missing")?;
    let image_path = installed["installLocation"]
        .as_str()
        .ok_or("Installed location missing")?
        .to_owned()
        + r"\Application\notepad++.exe";
    if activated["applicationUserModelId"] != "AIWResearch.NotepadPP_q1fhfzcjv9wt6!Notepad"
        || !activated["inAnyJob"].is_boolean()
        || activated["identityVerifiedBeforeResume"] != true
        || activated["launchMethod"] != "fixedInstalledExecutableSuspended"
        || activated["sessionId"] != session
        || activated["imageSha256"] != expected_image["sha256"]
        || !activated["imagePath"]
            .as_str()
            .is_some_and(|path| path.eq_ignore_ascii_case(&image_path))
        || observation["PackageFullName"] != installed["packageFullName"]
        || observation["UserSid"] != sid
        || observation["TokenSessionId"] != session
        || observation["IntegritySid"] != "S-1-16-8192"
        || observation["IsElevated"] != false
        || observation["IsAppContainer"] != false
        || observation["AdministratorsEnabled"] != false
    {
        return Err("Actual application token/image identity differs".into());
    }
    let returned = get("activation-returned.json")?;
    let window = get("application-window.json")?;
    let exit = get("editor-exit.json")?;
    if returned["processId"] != pid
        || returned["resumed"] != true
        || returned["launchMethod"] != "fixedInstalledExecutableSuspended"
        || window["processId"] != pid
        || window["visible"] != true
        || window["ownedProcessHandle"] != true
        || !window["window"].as_u64().is_some_and(|handle| handle > 0)
        || exit["processId"] != pid
        || exit["closed"] != true
        || exit["exitCode"] != 0
    {
        return Err("Held application window/exit observations differ".into());
    }
    const INITIAL: &[u8] = b"AIW MSIX package lifecycle\r\n";
    const EXPECTED: &[u8] = b"AIW MSIX package lifecycle\r\nAIW packaged validation\r\n";
    let saved = std::fs::read(stages.join("document.txt"))?;
    let document_input = get("document-input.json")?;
    let document_output = get("document-output.json")?;
    if saved != EXPECTED
        || document_input["sha256"] != hex::encode(Sha256::digest(INITIAL))
        || document_input["sizeBytes"] != INITIAL.len()
        || document_output["sha256"] != hex::encode(Sha256::digest(&saved))
        || document_output["sizeBytes"] != saved.len()
        || document_output["exactExpectedBytes"] != true
    {
        return Err("Exact document input/output binding differs".into());
    }
    let configurations = get("config-after.json")?;
    let configurations = configurations
        .as_array()
        .ok_or("Configuration observation missing")?;
    if configurations.is_empty()
        || configurations.len() > 16
        || !configurations.iter().any(|file| {
            file["path"]
                .as_str()
                .is_some_and(|path| path.ends_with(r"\config.xml"))
        })
    {
        return Err("Per-user configuration not observed".into());
    }
    for (index, file) in configurations.iter().enumerate() {
        let retained = file["retainedFile"]
            .as_str()
            .ok_or("Configuration retained file missing")?;
        let original = file["path"]
            .as_str()
            .ok_or("Configuration source path missing")?;
        let filename = original
            .rsplit('\\')
            .next()
            .ok_or("Configuration filename missing")?;
        if retained != format!("configuration/{index}-{filename}")
            || filename.contains(['/', ':'])
            || !original.starts_with(r"C:\Users\AiwStandardUser\AppData\")
        {
            return Err("Configuration export path differs".into());
        }
        let bytes = std::fs::read(stages.join(retained))?;
        if bytes.len() > 4 * 1024 * 1024
            || file["sizeBytes"] != bytes.len()
            || file["sha256"] != hex::encode(Sha256::digest(&bytes))
        {
            return Err("Configuration export identity differs".into());
        }
    }
    for name in [
        "package-processes-before.json",
        "package-processes-after-close.json",
        "package-processes-after-uninstall.json",
    ] {
        require_application_user_process_diagnostics(&get(name)?)?;
    }
    let cleanup = get("cleanup.json")?;
    if cleanup["registrationAbsent"] != true
        || cleanup["applicationProcessesAbsent"] != true
        || get("uninstall-started.json")?["packageFullName"] != installed["packageFullName"]
    {
        return Err("Exact registration/process cleanup missing".into());
    }
    Ok(())
}

fn export(source: &Path, target: &Path) -> TrialResult<()> {
    fn copy(source: &Path, target: &Path, count: &mut usize, depth: usize) -> TrialResult<()> {
        if depth > 3 {
            return Err("Research evidence depth exceeded".into());
        }
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Reparse evidence refused".into());
            }
            let destination = target.join(entry.file_name());
            if metadata.is_dir() {
                std::fs::create_dir(&destination)?;
                copy(&entry.path(), &destination, count, depth + 1)?;
            } else if metadata.is_file() {
                *count += 1;
                if *count > 64 || metadata.len() > 4 * 1024 * 1024 {
                    return Err("Evidence export bound exceeded".into());
                }
                std::fs::copy(entry.path(), destination)?;
            } else {
                return Err("Non-file evidence refused".into());
            }
        }
        Ok(())
    }
    copy(source, target, &mut 0, 0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn controller_job_observer_reads_current_native_context() {
        let value = super::controller_job_observation().unwrap();
        assert_eq!(value["processId"], std::process::id());
        assert_eq!(
            value["sessionId"],
            super::session_id(std::process::id()).unwrap()
        );
        assert_eq!(value["diagnosticOnly"], true);
        assert_eq!(value["queryScope"], "immediateJobOnly");
        if value["inAnyJob"].as_bool().unwrap() {
            assert!(value["limitFlags"].as_u64().is_some());
            assert!(value["uiRestrictions"].as_u64().is_some());
        } else {
            assert!(value["limitFlags"].is_null());
            assert!(value["uiRestrictions"].is_null());
        }
    }
    fn primary_preparation() -> serde_json::Value {
        serde_json::json!({"schemaVersion":"aiw.dev/research-primary-msix/v1","vmId":super::VM_ID,"sourceImageSha256":"a".repeat(64),"userSid":"S-1-5-21-3407263227-439785483-4249424476-1001","sessionId":3,"notBeforeFileTime":100,"notAfterFileTime":300,"runNonce":"b".repeat(64),"accountCreated":true,"accountName":"AiwStandardUser"})
    }
    #[test]
    fn primary_preparation_rejects_unowned_or_expired_run() {
        let hash = "a".repeat(64);
        let original = primary_preparation();
        let value = serde_json::from_value(original.clone()).unwrap();
        super::validate_preparation(&value, &hash, 200).unwrap();
        for (key, wrong) in [
            ("schemaVersion", serde_json::json!("unknown")),
            ("vmId", serde_json::json!("other-vm")),
            ("sourceImageSha256", serde_json::json!("c".repeat(64))),
            ("userSid", serde_json::json!(super::VM_OPERATOR_SID)),
            ("sessionId", serde_json::json!(0)),
            ("accountName", serde_json::json!("aiwoperator")),
            ("accountCreated", serde_json::json!(false)),
            ("runNonce", serde_json::json!("wrong")),
            (
                "runNonce",
                serde_json::json!("43cd415eb41808ba1396b52a69efec17"),
            ),
            ("runNonce", serde_json::json!("B".repeat(64))),
            ("notBeforeFileTime", serde_json::json!(201)),
            ("notAfterFileTime", serde_json::json!(199)),
            ("notAfterFileTime", serde_json::json!(i64::MAX)),
        ] {
            let mut candidate = original.clone();
            candidate[key] = wrong;
            let value = serde_json::from_value(candidate).unwrap();
            assert!(
                super::validate_preparation(&value, &hash, 200).is_err(),
                "{key}"
            );
        }
        let mut extra = original;
        extra["command"] = serde_json::json!("anything");
        assert!(serde_json::from_value::<super::PrimaryPreparation>(extra).is_err());
    }
    #[test]
    fn powershell_producer_matches_native_primary_preparation() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/research/test-msix-primary-preparation.ps1");
        let output = std::process::Command::new(super::POWERSHELL)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(script)
            .arg("-EmitNativeFixture")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value = serde_json::from_slice(&output.stdout).unwrap();
        super::validate_preparation(&value, &"a".repeat(64), 200).unwrap();
    }
    #[test]
    fn primary_script_parses_and_native_source_compiles_in_ps51() {
        let root = std::env::temp_dir().join(format!(
            "aiw-primary-source-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let script = root.join("observer.ps1");
        let native = root.join("observer.cs");
        std::fs::write(&script, super::primary_observation_script()).unwrap();
        std::fs::write(&native, super::primary_native_source()).unwrap();
        let command = format!(
            "$ErrorActionPreference='Stop'; $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile('{}',[ref]$tokens,[ref]$errors);if($errors.Count){{throw ($errors|Out-String)}};Add-Type -Path '{}';@{{parsed=$true;nativeCompiled=$true;applicationExecuted=$false}}|ConvertTo-Json",
            script.to_string_lossy().replace('\'', "''"),
            native.to_string_lossy().replace('\'', "''")
        );
        let output = std::process::Command::new(super::POWERSHELL)
            .args(["-NoProfile", "-NonInteractive", "-Command", &command])
            .output()
            .unwrap();
        std::fs::write(root.join("stdout.log"), &output.stdout).unwrap();
        std::fs::write(root.join("stderr.log"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "PS5.1 parse/compile failed; retained {}",
            root.display()
        );
        let quoted = aiw_windows_command_line::join_arguments([
            super::POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &super::primary_observation_script(),
        ]);
        assert!(quoted.encode_utf16().count() < 32767);
    }
    const SID: &str = "S-1-5-21-1-2-3-1000";
    struct Fixture {
        root: std::path::PathBuf,
        assembly: serde_json::Value,
    }
    impl Fixture {
        fn new() -> Self {
            use serde_json::json;
            let root = std::env::temp_dir().join(format!(
                "aiw-msix-validation-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            let stages = root.join("msix-lifecycle");
            std::fs::create_dir(&stages).unwrap();
            std::fs::create_dir(stages.join("driver-control")).unwrap();
            std::fs::create_dir(stages.join("configuration")).unwrap();
            for name in super::LIFECYCLE_RECEIPTS {
                super::record(&stages, name, json!({})).unwrap();
            }
            let token = json!({"UserSid":SID,"TokenSessionId":1,"IsElevated":false,"AdministratorsEnabled":false,"IsAppContainer":false,"IntegritySid":"S-1-16-8192"});
            super::record(&stages,"worker.json",json!({"operatorSid":SID,"sessionId":1,"inInheritedJob":true,"operatorToken":token})).unwrap();
            for name in ["config-before.json", "config-installed-before-launch.json"] {
                super::record(&stages, name, json!([])).unwrap();
            }
            super::record(
                &stages,
                "preflight-inventory.json",
                json!({"packages":[],"processes":[]}),
            )
            .unwrap();
            let controls=["success","failure","deadline"].into_iter().enumerate().map(|(i,mode)|json!({"mode":mode,"heldHandle":true,"inInheritedJob":true,"exited":true,"imagePath":super::POWERSHELL,"pid":100+i,"startTime":"2026-10-08T00:00:00Z","deadlineHit":mode=="deadline","exitCode":([0,42,-1][i])})).collect::<Vec<_>>();
            super::record(
                &stages,
                "driver-control/control.json",
                json!({"passed":true,"sessionId":1,"controls":controls}),
            )
            .unwrap();
            for mode in ["success", "failure", "deadline"] {
                for (stream, body) in [
                    ("stdout", "aiw-owned-control-out\r\n"),
                    ("stderr", "aiw-owned-control-error\r\n"),
                ] {
                    std::fs::write(
                        stages.join(format!("driver-control/{mode}.{stream}.log")),
                        body,
                    )
                    .unwrap();
                }
            }
            super::record(
                &stages,
                "driver-controls-completed.json",
                json!({"controlsPassed":true}),
            )
            .unwrap();
            super::record(&stages,"package-input.json",json!({"signedSha256":super::INPUTS[0].1,"publisher":"CN=Nathan McNulty, O=Nathan McNulty, L=Soldotna, S=Alaska, C=US","sourceSha256":"b269383239464a945d17cfabfccf53935b83d80d907922310fdfd50d80274c66","sizeBytes":8641353,"signatureStatus":"Valid","signerThumbprint":"AD05F224A248CE998FEF1EF6EA75CBF72747EE38","timestampThumbprint":"recorded"})).unwrap();
            let inventory=(0..220).map(|i|json!({"path":match i {0=>"AppxManifest.xml".to_owned(),1=>"Application/notepad++.exe".to_owned(),_=>format!("Application/file-{i}")},"sha256":"fixture hash"})).collect::<Vec<_>>();
            let assembly = json!({"payloadInventory":inventory});
            super::record(
                &stages,
                "payload-before.json",
                assembly["payloadInventory"].clone(),
            )
            .unwrap();
            super::record(
                &stages,
                "payload-after.json",
                json!({"matchesOriginalInventory":true,"filesChecked":220}),
            )
            .unwrap();
            for name in ["manifest-before.json", "manifest-after.json"] {
                super::record(&stages, name, json!({"sha256":"fixture hash"})).unwrap();
            }
            std::fs::write(stages.join("installed-manifest.xml"), "<Package/>").unwrap();
            let package = "AIWResearch.NotepadPP_8.9.8.0_x64__q1fhfzcjv9wt6";
            let location = format!("C:\\Program Files\\WindowsApps\\{package}");
            super::record(&stages,"installed.json",json!({"packageFullName":package,"packageFamilyName":"AIWResearch.NotepadPP_q1fhfzcjv9wt6","installLocation":location})).unwrap();
            super::record(
                &stages,
                "post-install-inventory.json",
                json!([{"PackageFullName":package}]),
            )
            .unwrap();
            let mut app_token = token;
            app_token["PackageFullName"] = json!(package);
            let mut activated = json!({"processId":300,"sessionId":1,"imageSha256":"fixture hash","imagePath":location+r"\Application\notepad++.exe","packageObservation":app_token,"applicationUserModelId":"AIWResearch.NotepadPP_q1fhfzcjv9wt6!Notepad","inAnyJob":true,"launchMethod":"fixedInstalledExecutableSuspended"});
            super::record(&stages, "activation-suspended.json", activated.clone()).unwrap();
            activated["identityVerifiedBeforeResume"] = json!(true);
            super::record(&stages, "activated.json", activated).unwrap();
            super::record(
                &stages,
                "activation-returned.json",
                json!({"processId":300,"resumed":true,"launchMethod":"fixedInstalledExecutableSuspended"}),
            )
            .unwrap();
            super::record(
                &stages,
                "application-window.json",
                json!({"processId":300,"visible":true,"ownedProcessHandle":true,"window":1234}),
            )
            .unwrap();
            super::record(
                &stages,
                "editor-exit.json",
                json!({"processId":300,"closed":true,"exitCode":0}),
            )
            .unwrap();
            let initial = b"AIW MSIX package lifecycle\r\n";
            let saved = b"AIW MSIX package lifecycle\r\nAIW packaged validation\r\n";
            std::fs::write(stages.join("document.txt"), saved).unwrap();
            super::record(&stages,"document-input.json",json!({"sha256":hex::encode(<sha2::Sha256 as sha2::Digest>::digest(initial)),"sizeBytes":initial.len()})).unwrap();
            super::record(&stages,"document-output.json",json!({"sha256":hex::encode(<sha2::Sha256 as sha2::Digest>::digest(saved)),"sizeBytes":saved.len(),"exactExpectedBytes":true})).unwrap();
            let config = b"<config/>";
            std::fs::write(stages.join("configuration/0-config.xml"), config).unwrap();
            super::record(&stages,"config-after.json",json!([{"path":r"C:\Users\AiwStandardUser\AppData\Roaming\Notepad++\config.xml","retainedFile":"configuration/0-config.xml","sizeBytes":config.len(),"sha256":hex::encode(<sha2::Sha256 as sha2::Digest>::digest(config))}])).unwrap();
            for name in [
                "package-processes-before.json",
                "package-processes-after-close.json",
                "package-processes-after-uninstall.json",
            ] {
                super::record(
                    &stages,
                    name,
                    json!({"matches":[],"queryErrors":[],"nonPackageImageUnavailable":[],"queryAuthority":"applicationUserDiagnostic","globalAbsenceVerified":false}),
                )
                .unwrap();
            }
            super::record(
                &stages,
                "uninstall-started.json",
                json!({"packageFullName":package}),
            )
            .unwrap();
            super::record(
                &stages,
                "cleanup.json",
                json!({"registrationAbsent":true,"applicationProcessesAbsent":true}),
            )
            .unwrap();
            Self { root, assembly }
        }
        fn validate(&self) -> super::TrialResult<()> {
            super::validate_lifecycle(&self.root, &self.assembly, SID, 1)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let (Ok(path), Ok(temp)) = (
                self.root.canonicalize(),
                std::env::temp_dir().canonicalize(),
            ) {
                if path.starts_with(temp)
                    && path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("aiw-msix-validation-")
                {
                    let _ = std::fs::remove_dir_all(path);
                }
            }
        }
    }
    #[test]
    fn every_required_receipt_is_needed_for_terminal_acceptance() {
        let fixture = Fixture::new();
        fixture.validate().unwrap();
        for name in super::LIFECYCLE_RECEIPTS {
            let path = fixture.root.join("msix-lifecycle").join(name);
            let bytes = std::fs::read(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            assert!(
                fixture.validate().is_err(),
                "Missing {name} must prevent terminal success"
            );
            std::fs::write(path, bytes).unwrap();
        }
    }
    #[test]
    fn unpackaged_unidentified_or_unverified_launch_cannot_pass() {
        let fixture = Fixture::new();
        fixture.validate().unwrap();
        let stages = fixture.root.join("msix-lifecycle");
        let original = super::read_receipt(&stages, "activated.json").unwrap();
        let suspended = super::read_receipt(&stages, "activation-suspended.json").unwrap();
        for (key, value) in [
            ("applicationUserModelId", serde_json::Value::Null),
            (
                "applicationUserModelId",
                serde_json::json!("AIWResearch.NotepadPP_q1fhfzcjv9wt6!Other"),
            ),
            ("inAnyJob", serde_json::Value::Null),
            ("identityVerifiedBeforeResume", serde_json::json!(false)),
            ("launchMethod", serde_json::json!("unpackagedFallback")),
        ] {
            let mut changed = original.clone();
            let mut changed_suspended = suspended.clone();
            changed[key] = value.clone();
            changed_suspended[key] = value;
            super::record(&stages, "activated.json", changed).unwrap();
            super::record(&stages, "activation-suspended.json", changed_suspended).unwrap();
            assert!(fixture.validate().is_err(), "Must reject {key}");
        }
        let mut diagnostic = original;
        let mut diagnostic_suspended = suspended;
        diagnostic["inAnyJob"] = serde_json::json!(false);
        diagnostic_suspended["inAnyJob"] = serde_json::json!(false);
        super::record(&stages, "activated.json", diagnostic).unwrap();
        super::record(&stages, "activation-suspended.json", diagnostic_suspended).unwrap();
        // Any-job membership does not establish project-job ownership or identity.
        fixture.validate().unwrap();
        let mut returned = super::read_receipt(&stages, "activation-returned.json").unwrap();
        returned["resumed"] = serde_json::json!(false);
        super::record(&stages, "activation-returned.json", returned).unwrap();
        assert!(fixture.validate().is_err());
    }
    #[test]
    fn token_session_document_and_unknown_process_drift_preclude_acceptance() {
        let fixture = Fixture::new();
        fixture.validate().unwrap();
        let stages = fixture.root.join("msix-lifecycle");
        let activated = super::read_receipt(&stages, "activated.json").unwrap();
        let mut changed = activated.clone();
        changed["packageObservation"]["TokenSessionId"] = serde_json::json!(2);
        super::record(&stages, "activated.json", changed).unwrap();
        assert!(fixture.validate().is_err());
        super::record(&stages, "activated.json", activated).unwrap();
        std::fs::write(stages.join("document.txt"), b"Different saved content").unwrap();
        assert!(fixture.validate().is_err());
        std::fs::write(
            stages.join("document.txt"),
            b"AIW MSIX package lifecycle\r\nAIW packaged validation\r\n",
        )
        .unwrap();
        super::record(
            &stages,
            "package-processes-after-uninstall.json",
            serde_json::json!({"matches":[],"queryErrors":[{"pid":500,"error":"access denied"}]}),
        )
        .unwrap();
        assert!(fixture.validate().is_err());
    }
    #[test]
    fn unknown_queries_are_diagnostic_only_under_application_user_authority() {
        let mut inventory = serde_json::json!({"matches":[],"queryErrors":[{"pid":680,"name":"csrss","error":"Access is denied"}],"nonPackageImageUnavailable":[],"queryAuthority":"applicationUserDiagnostic","globalAbsenceVerified":false});
        super::require_application_user_process_diagnostics(&inventory).unwrap();
        assert!(
            super::require_global_inventory(
                &serde_json::json!({"packages":[],"provisioned":[],"processes":inventory})
            )
            .is_err()
        );
        inventory["queryErrors"][0]["name"] = serde_json::json!("Notepad++");
        assert!(super::require_application_user_process_diagnostics(&inventory).is_err());
        inventory["queryErrors"][0]["name"] = serde_json::json!("csrss");
        inventory["globalAbsenceVerified"] = serde_json::json!(true);
        assert!(super::require_application_user_process_diagnostics(&inventory).is_err());
        inventory["globalAbsenceVerified"] = serde_json::json!(false);
        inventory["matches"] = serde_json::json!([{"PackageFullName":"AIWResearch.NotepadPP"}]);
        assert!(super::require_application_user_process_diagnostics(&inventory).is_err());
        inventory["matches"] = serde_json::json!([]);
        inventory["queryErrors"][0]
            .as_object_mut()
            .unwrap()
            .remove("error");
        assert!(super::require_application_user_process_diagnostics(&inventory).is_err());
        let clear =
            serde_json::json!({"matches":[],"queryErrors":[],"nonPackageImageUnavailable":[]});
        super::require_global_inventory(
            &serde_json::json!({"packages":[],"provisioned":[],"processes":clear}),
        )
        .unwrap();
        assert!(super::require_global_inventory(&serde_json::json!({"packages":[{"PackageFullName":"AIWResearch.NotepadPP"}],"provisioned":[],"processes":clear})).is_err());
    }
    #[test]
    fn image_diagnostics_require_positive_no_package_observation() {
        let mut inventory = serde_json::json!({"matches":[],"queryErrors":[],
            "nonPackageImageUnavailable":[{"Pid":180,"Name":"Registry","PackageIdentityStatus":"noPackage","PackageFullName":null,
                "ImagePath":null,"ImageQueryError":31}]});
        super::require_empty_process_inventory(&inventory).unwrap();
        inventory["nonPackageImageUnavailable"][0]["Name"] = serde_json::json!("notepad++");
        assert!(super::require_empty_process_inventory(&inventory).is_err());
        inventory["nonPackageImageUnavailable"][0]["Name"] = serde_json::json!("Registry");
        inventory["nonPackageImageUnavailable"][0]["PackageFullName"] =
            serde_json::json!("unknown");
        assert!(super::require_empty_process_inventory(&inventory).is_err());
        inventory["nonPackageImageUnavailable"][0]
            .as_object_mut()
            .unwrap()
            .remove("PackageFullName");
        assert!(super::require_empty_process_inventory(&inventory).is_err());
        inventory["nonPackageImageUnavailable"] = serde_json::json!([]);
        inventory["queryErrors"] = serde_json::json!([{"pid":180,"error":"package query denied"}]);
        assert!(super::require_empty_process_inventory(&inventory).is_err());
    }
    #[test]
    fn ordinary_test_process_cannot_enter_the_research_lifecycle() {
        let error=super::run().expect_err("An ordinary host test process must stop before mapped inputs, account creation or launch");
        assert!(
            error
                .to_string()
                .contains("Fixed mapped executable required")
        );
    }
    #[test]
    fn closed_launches_fit_their_distinct_native_limits() {
        let logon = aiw_windows_command_line::join_arguments([super::EXE, "lifecycle-child"]);
        assert!(
            logon.encode_utf16().count() < crate::guest_msi::MAX_STANDARD_USER_COMMAND_LINE_UNITS
        );
        let command = aiw_windows_command_line::join_arguments([
            super::POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &super::script(),
        ]);
        assert!(command.encode_utf16().count() < 32767);
    }
}
