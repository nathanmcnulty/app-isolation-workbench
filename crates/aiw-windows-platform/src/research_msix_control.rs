//! Closed research control. Compiled only with the explicit research feature.
use crate::guest_msi::GuestProcess;
use crate::guest_standard_user::StandardUserSession;
use std::path::Path;
use std::time::Duration;
#[link(name = "Advapi32")]
unsafe extern "system" {
    fn GetUserNameW(buffer: *mut u16, length: *mut u32) -> i32;
}
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().count() != 1 {
        return Err("Closed control accepts no commands or paths".into());
    }
    let mut name = [0u16; 256];
    let mut count = name.len() as u32;
    // SAFETY: bounded writable buffer and length remain live through the call.
    if unsafe { GetUserNameW(name.as_mut_ptr(), &mut count) } == 0
        || count == 0
        || count as usize > name.len()
        || String::from_utf16(&name[..count as usize - 1])? != "WDAGUtilityAccount"
    {
        return Err("Control requires the Sandbox WDAGUtilityAccount operator".into());
    }
    let output = Path::new(r"C:\AIW-Msix-Control-Output");
    if !output.is_dir() {
        return Err("Required research output mapping is absent".into());
    }
    let evidence = output.join("standard-user-control");
    std::fs::create_dir(&evidence)?;
    let result = run_child(&evidence);
    if let Err(error) = &result {
        std::fs::write(
            evidence.join("failure.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"error":error.to_string(),"researchOnly":true}),
            )?,
        )?;
    }
    result
}
fn run_child(evidence: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let standard = StandardUserSession::establish()?;
    std::fs::write(
        evidence.join("context.json"),
        serde_json::to_vec_pretty(standard.context())?,
    )?;
    standard.impersonate(|| {
        std::fs::create_dir_all(standard.document_root())
            .map_err(|e| crate::GuestMsiExecutionError::Process(e.to_string()))
    })?;
    let script = r#"$ErrorActionPreference='Stop'
try {
Start-Transcript -LiteralPath 'C:\Users\AiwStandardUser\AppData\Local\AIW\msix-control-transcript.txt' | Out-Null
Add-Type -AssemblyName System.Windows.Forms
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$profile=[Environment]::GetFolderPath('UserProfile')
if($env:USERPROFILE -cne $profile -or $profile -cne 'C:\Users\AiwStandardUser'){throw 'Standard profile mismatch'}
if(!(Test-Path ('Registry::HKEY_USERS\'+$identity.User.Value))){throw 'User hive is not loaded'}
$form=New-Object Windows.Forms.Form
$form.Text='AIW standard-user research control'; $form.Width=560; $form.Height=160
$label=New-Object Windows.Forms.Label; $label.Dock='Fill'; $label.Text='Project-owned control only. This window closes automatically.'
$form.Controls.Add($label)
$timer=New-Object Windows.Forms.Timer; $timer.Interval=30000
$timer.Add_Tick({$timer.Stop();$form.Close()}); $form.Add_Shown({$timer.Start()})
$form.ShowDialog() | Out-Null
$timer.Dispose(); $form.Dispose()
@{sid=$identity.User.Value;profile=$profile;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;guiLoopCompleted=$true} | ConvertTo-Json -Compress | Set-Content -LiteralPath 'C:\Users\AiwStandardUser\AppData\Local\AIW\msix-control.json' -Encoding UTF8
Stop-Transcript | Out-Null
} catch {
@{message=$_.Exception.Message;detail=$_.ToString();line=$_.InvocationInfo.PositionMessage} | ConvertTo-Json -Compress | Set-Content -LiteralPath 'C:\Users\AiwStandardUser\AppData\Local\AIW\msix-control-failure.json' -Encoding UTF8
try { Stop-Transcript | Out-Null } catch {}
exit 1
}
"#;
    let executable = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let arguments = ["-NoProfile", "-NonInteractive", "-Command", script].map(str::to_owned);
    // Actual production launcher: one-use secret, validated suspended child,
    // exact-SID desktop grant/access preflight, held handles and owned kill job.
    let child = GuestProcess::start_standard_user(executable, &arguments, &standard)?;
    let operation = (|| -> Result<i32, Box<dyn std::error::Error>> {
        std::fs::write(
            evidence.join("child-started.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"pid":child.process_id(),"heldHandle":true,"deadlineMs":60000}),
            )?,
        )?;
        std::fs::write(
            evidence.join("child-token.json"),
            serde_json::to_vec_pretty(&child.collect_token()?)?,
        )?;
        let window = child.wait_for_window(Duration::from_secs(15))?;
        std::fs::write(
            evidence.join("child-window.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"pid":child.process_id(),"window":window.0 as usize,"observedOnAgentDesktop":true}),
            )?,
        )?;
        let exit = child.wait_for_exit(Duration::from_secs(60))?;
        if exit != 0 {
            return Err(format!("Control exited with {exit}").into());
        }
        let bytes = std::fs::read(standard.document_root().join("msix-control.json"))?;
        // Admit only the documented PowerShell 5.1 UTF-8 BOM, retaining raw bytes.
        let json = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
        let record: serde_json::Value = serde_json::from_slice(json)?;
        if record["sid"] != standard.context().user_sid || record["guiLoopCompleted"] != true {
            return Err("Control result identity differs".into());
        }
        std::fs::write(evidence.join("child-result.json"), bytes)?;
        Ok(exit)
    })();
    // Retain the useful inventory before either success verification or cleanup
    // can terminate descendants. Evidence-export errors must not skip cleanup.
    let before_active = child.active_processes();
    let before_inventory = child.diagnostic_processes();
    let normal_cleanup = if operation.is_ok() {
        child.verify_empty_after_success()
    } else {
        Ok(())
    };
    let cleanup = child.cleanup();
    let active = child.active_processes();
    let mut exports = Vec::new();
    for name in ["msix-control-transcript.txt", "msix-control-failure.json"] {
        let path = standard.document_root().join(name);
        if path.is_file() {
            if let Err(error) = std::fs::copy(path, evidence.join(name)) {
                exports.push(format!("{name}: {error}"));
            }
        }
    }
    std::fs::write(
        evidence.join("cleanup.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"verified":cleanup.is_ok() && active.as_ref().is_ok_and(|n|*n==0),"operationError":operation.as_ref().err().map(ToString::to_string),"normalCleanupError":normal_cleanup.as_ref().err().map(ToString::to_string),"error":cleanup.as_ref().err().map(ToString::to_string),"beforeActiveJobProcesses":before_active.as_ref().ok(),"beforeInventory":before_inventory.as_ref().ok(),"beforeInventoryError":before_inventory.as_ref().err().map(ToString::to_string),"activeJobProcesses":active.as_ref().ok(),"readbackError":active.as_ref().err().map(ToString::to_string),"inventory":child.diagnostic_processes().ok(),"exportErrors":exports}),
        )?,
    )?;
    if cleanup.is_err()
        || !active.as_ref().is_ok_and(|n| *n == 0)
        || normal_cleanup.is_err()
        || !exports.is_empty()
    {
        return Err(format!("operation={:?}; normalCleanup={normal_cleanup:?}; cleanup={cleanup:?}; readback={active:?}; export={exports:?}", operation.as_ref().err().map(ToString::to_string)).into());
    }
    let exit = operation?;
    std::fs::write(
        evidence.join("result.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"researchOnly":true,"passed":true,"exitCode":exit,"jobEmpty":true,"applicationTrial":"notRun","accountCleanup":"dispose exact owned Sandbox"}),
        )?,
    )?;
    Ok(())
}
