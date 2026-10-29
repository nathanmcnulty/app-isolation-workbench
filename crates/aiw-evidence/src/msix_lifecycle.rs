//! Pure receipt verification shared by the guest, host importer and research harness.
//! Fixed supported Notepad++ recipe; no execution, filesystem access or inferred isolation.
use serde_json::Value;
use sha2::{Digest, Sha256};
const MSIX_PACKAGE_SHA256: &str =
    "2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437";
// Historical read-only receipts retain their original supervisor identity.
const LEGACY_POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const POWERSHELL: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";

fn read<'a>(
    files: &'a std::collections::BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<&'a [u8], String> {
    files
        .get(name)
        .map(Vec::as_slice)
        .filter(|bytes| bytes.len() <= 4 * 1024 * 1024)
        .ok_or_else(|| format!("Missing or oversized MSIX evidence: {name}"))
}
fn read_receipt(
    files: &std::collections::BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<Value, String> {
    let bytes = read(files, name)?;
    let value: Value =
        serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
            .map_err(|e| e.to_string())?;
    if !value.is_object() && !value.is_array() {
        return Err("Structured MSIX receipt required".into());
    }
    Ok(value)
}
fn require_empty_process_inventory(value: &serde_json::Value) -> Result<(), String> {
    for key in ["matches", "queryErrors"] {
        if !value[key].as_array().is_some_and(Vec::is_empty) {
            return Err(format!("Package process {key} is not proven empty"));
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
fn require_application_user_process_diagnostics(value: &serde_json::Value) -> Result<(), String> {
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
pub fn verify_notepad_msix_lifecycle(
    files: &std::collections::BTreeMap<String, Vec<u8>>,
    assembly: &serde_json::Value,
    sid: &str,
    session: u32,
) -> Result<(), String> {
    let stages = "msix-lifecycle";
    for name in LIFECYCLE_RECEIPTS {
        read_receipt(files, &format!("{stages}/{name}"))?;
    }
    if read(files, &format!("{stages}/installed-manifest.xml"))?.is_empty() {
        return Err("Installed manifest evidence absent".into());
    }
    for name in ["native-child-failure.json", "failure.json"] {
        if files.contains_key(name) {
            return Err("Failure evidence precludes terminal success".into());
        }
    }
    if files.contains_key(&format!("{stages}/failure.json")) {
        return Err("Failed application trial cannot publish success".into());
    }
    let get = |name: &str| read_receipt(files, &format!("{stages}/{name}"));
    let worker = get("worker.json")?;
    let expected_supervisor = if worker.get("powerShellRuntime").is_some() {
        let runtime = &worker["powerShellRuntime"];
        let version = runtime["version"]
            .as_str()
            .ok_or("Runtime version missing")?
            .split('.')
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Stable numeric runtime required")?;
        if version.len() < 3
            || version.len() > 4
            || version[0] < 7
            || (version[0] == 7 && version[1] < 6)
            || runtime["edition"] != "Core"
            || runtime["prerelease"] != ""
            || runtime["architecture"] != "X64"
            || runtime["executable"] != POWERSHELL
            || runtime["psHome"] != r"C:\Program Files\PowerShell\7"
            || runtime["compatibilitySessionCount"] != 0
            || runtime["executableSha256"].as_str().is_none_or(|hash| {
                hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            })
        {
            return Err("Current lifecycle runtime proof invalid".into());
        }
        POWERSHELL
    } else {
        LEGACY_POWERSHELL
    };
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
            || record["imagePath"].as_str() != Some(expected_supervisor)
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
            return Err(format!("Closed {mode} control differs"));
        }
        for (stream, expected) in [
            ("stdout", "aiw-owned-control-out"),
            ("stderr", "aiw-owned-control-error"),
        ] {
            let bytes = read(
                files,
                &format!("{stages}/driver-control/{mode}.{stream}.log"),
            )?;
            if bytes.len() > 1024
                || std::str::from_utf8(bytes)
                    .map_err(|e| e.to_string())?
                    .trim()
                    != expected
            {
                return Err("Control stream identity differs".into());
            }
        }
    }
    if get("driver-controls-completed.json")?["controlsPassed"] != true {
        return Err("Pre-install control checkpoint missing".into());
    }
    let input = get("package-input.json")?;
    if input["signedSha256"] != MSIX_PACKAGE_SHA256
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
        || activated["inAnyJob"] != true
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
    let saved = read(files, &format!("{stages}/document.txt"))?;
    let document_input = get("document-input.json")?;
    let document_output = get("document-output.json")?;
    if saved != EXPECTED
        || document_input["sha256"] != hex::encode(Sha256::digest(INITIAL))
        || document_input["sizeBytes"] != INITIAL.len()
        || document_output["sha256"] != hex::encode(Sha256::digest(saved))
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
        let bytes = read(files, &format!("{stages}/{retained}"))?;
        if bytes.len() > 4 * 1024 * 1024
            || file["sizeBytes"] != bytes.len()
            || file["sha256"] != hex::encode(Sha256::digest(bytes))
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

#[cfg(test)]
mod fixture_tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        io::{Cursor, Read},
    };
    fn fixture() -> (BTreeMap<String, Vec<u8>>, Value, String, u32) {
        let mut archive = zip::ZipArchive::new(Cursor::new(include_bytes!(
            "../../../fixtures/msix-lifecycle/worker107-r5.zip"
        )))
        .unwrap();
        let mut files = BTreeMap::new();
        let mut assembly = Value::Null;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).unwrap();
            let name = entry.name().unwrap().into_owned();
            if entry.is_dir() {
                continue;
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            if name == "worker/assembly.json" {
                assembly = serde_json::from_slice(&bytes).unwrap();
            }
            if let Some(name) = name.strip_prefix("0/standard-user-lifecycle/") {
                files.insert(name.to_owned(), bytes);
            }
        }
        let worker: Value = serde_json::from_slice(
            files["msix-lifecycle/worker.json"]
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&files["msix-lifecycle/worker.json"]),
        )
        .unwrap();
        let sid = worker["operatorSid"].as_str().unwrap().to_owned();
        let session = worker["sessionId"].as_u64().unwrap() as u32;
        (files, assembly, sid, session)
    }
    #[test]
    fn archived_native_lifecycle_still_verifies_through_shared_verifier() {
        let (files, assembly, sid, session) = fixture();
        verify_notepad_msix_lifecycle(&files, &assembly, &sid, session).unwrap();
    }
    #[test]
    fn current_runtime_receipt_rejects_preview_wrong_image_and_compatibility() {
        let (mut files, assembly, sid, session) = fixture();
        let mut worker = read_receipt(&files, "msix-lifecycle/worker.json").unwrap();
        let runtime = serde_json::json!({"edition":"Core","version":"7.6.5","prerelease":"","architecture":"X64","executable":POWERSHELL,"psHome":r"C:\Program Files\PowerShell\7","executableSha256":"a".repeat(64),"compatibilitySessionCount":0});
        let mut control =
            read_receipt(&files, "msix-lifecycle/driver-control/control.json").unwrap();
        for mode in control["controls"].as_array_mut().unwrap() {
            mode["imagePath"] = POWERSHELL.into();
        }
        files.insert(
            "msix-lifecycle/driver-control/control.json".into(),
            serde_json::to_vec(&control).unwrap(),
        );
        worker["powerShellRuntime"] = runtime.clone();
        files.insert(
            "msix-lifecycle/worker.json".into(),
            serde_json::to_vec(&worker).unwrap(),
        );
        verify_notepad_msix_lifecycle(&files, &assembly, &sid, session).unwrap();
        for (key, value) in [
            ("version", serde_json::json!("7.6.0-preview.1")),
            ("executable", serde_json::json!(LEGACY_POWERSHELL)),
            ("compatibilitySessionCount", serde_json::json!(1)),
        ] {
            worker["powerShellRuntime"] = runtime.clone();
            worker["powerShellRuntime"][key] = value;
            files.insert(
                "msix-lifecycle/worker.json".into(),
                serde_json::to_vec(&worker).unwrap(),
            );
            assert!(verify_notepad_msix_lifecycle(&files, &assembly, &sid, session).is_err());
        }
    }
    #[test]
    fn shared_verifier_rejects_missing_receipt_document_drift_and_wrong_session() {
        let (files, assembly, sid, session) = fixture();
        assert!(verify_notepad_msix_lifecycle(&files, &assembly, &sid, session + 1).is_err());
        let mut missing = files.clone();
        missing.remove("msix-lifecycle/cleanup.json");
        assert!(verify_notepad_msix_lifecycle(&missing, &assembly, &sid, session).is_err());
        let mut changed = files;
        changed
            .get_mut("msix-lifecycle/document.txt")
            .unwrap()
            .push(b'!');
        assert!(verify_notepad_msix_lifecycle(&changed, &assembly, &sid, session).is_err());
    }
}
