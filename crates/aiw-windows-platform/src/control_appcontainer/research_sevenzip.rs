//! Closed 7-Zip experiment. Default-off; these files are research, not receipts.
//! Only the elevated Sandbox role installs. The workflow role is standard user.
use super::*;
use crate::HeldApplicationFile;
use crate::guest_document::paired_inputs::sevenzip::FixedSevenZipInputs;
use crate::guest_msi::GuestProcess;
use crate::guest_standard_user::StandardUserSession;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::windows::fs::MetadataExt;
use std::path::PathBuf;
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    LABEL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_WRITE,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const ROOT: &str = r"C:\AIW\SevenZip";
const INPUT_HELPER: &str = r"C:\AIW\Tools\sevenzip_assessment.exe";
const HELPER: &str = r"C:\AIW\SevenZip\sevenzip_assessment.exe";
const INSTALLER: &str = r"C:\AIW\SevenZip\7z2605-x64.exe";
const INSTALLER_HASH: &str = "fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0";
const INSTALLER_SIZE: u64 = 1_663_506;
const APP: &str = r"C:\AIW\SevenZip\App";
const IMAGE: &str = r"C:\AIW\SevenZip\App\7z.exe";
const DLL: &str = r"C:\AIW\SevenZip\App\7z.dll";
const WORK: &str = r"C:\AIW\SevenZip\Work";
const OUTPUT: &str = r"C:\AIW\SevenZipOutput";
const SEVENZIP_PROFILE: &str = "AIW.SevenZip.Research.v0alpha1";
const DRIVER_BYTES: &[u8] = b"AIW sevenzip driver control\r\n";
const DENIED_BYTES: &[u8] = b"AIW sevenzip ungranted canary";

/// All accepted roles are compiled and bound to fixed on-worker paths/identity.
pub fn run() -> Result<u8> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let exe = std::env::current_exe()?;
    let token = collect_current_process_token()?;
    if args == ["--output", r"C:\AIW\SevenZipOutput\result.json"] {
        if exe != Path::new(INPUT_HELPER)
            || !token.is_elevated
            || token.is_app_container
            || token.user_sid != fixed_account_sid("WDAGUtilityAccount")?
        {
            return Err("fixed elevated Sandbox research role required; nothing installed".into());
        }
        return setup();
    }
    if exe != Path::new(HELPER)
        || args.len() != 1
        || token.is_elevated
        || token.user_sid != fixed_account_sid(aiw_provider_wsb::STANDARD_USER_ACCOUNT_NAME)?
    {
        return Err("fixed standard-user research role required".into());
    }
    match args[0].to_str() {
        Some("--driver-control") => {
            std::io::stdout().write_all(DRIVER_BYTES)?;
            Ok(23)
        }
        Some("--deadline-control") => {
            thread::sleep(Duration::from_secs(5));
            Ok(0)
        }
        Some("--boundary-control") => boundary_control(&token),
        Some("--workflow") if !token.is_app_container => workflow(&token),
        _ => Err("unknown closed research role".into()),
    }
}

/// Production secondary roles cannot enter the installer/setup entrypoint.
pub(crate) fn run_production_role() -> Result<u8> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1
        || !matches!(
            args[0].to_str(),
            Some("--driver-control" | "--deadline-control" | "--boundary-control" | "--workflow")
        )
    {
        return Err("fixed 7-Zip secondary role rejected".into());
    }
    run()
}

pub(crate) fn execute_production(
    request: &aiw_provider_wsb::sevenzip::SevenZipRequest,
) -> (bool, Result<u8>) {
    // Raw on-worker stages are never mapped to the host or imported as receipts.
    if let Err(error) = fs::create_dir(OUTPUT) {
        return (false, Err(error.into()));
    }
    if let Err(error) = set_acl(
        Path::new(OUTPUT),
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        false,
    ) {
        return (true, Err(error));
    }
    (
        true,
        setup_bound(Some((
            &request.agent_sha256,
            request.profile.agent_size_bytes,
        ))),
    )
}

fn setup() -> Result<u8> {
    setup_bound(None)
}
fn setup_bound(expected_helper: Option<(&str, u64)>) -> Result<u8> {
    // Holding every named ancestor prevents root replacement; no recursive cleanup.
    let _output_dirs = hold_directory_chain(Path::new(OUTPUT))?;
    if fs::read_dir(OUTPUT)?.next().is_some() || Path::new(ROOT).try_exists()? {
        return Err("fresh empty output mapping and absent local research root required".into());
    }
    let mut inputs = FixedSevenZipInputs::open().map_err(fixed)?;
    if let Some((hash, size)) = expected_helper
        && (inputs.helper_hash() != hash || inputs.helper_size() != size)
    {
        return Err("production helper differs from approved agent bytes/size".into());
    }
    fs::create_dir(ROOT)?;
    let _root = hold_directory_chain(Path::new(ROOT))?;
    for (path, is_installer) in [(INSTALLER, true), (HELPER, false)] {
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        if is_installer {
            inputs.copy_installer(&mut output).map_err(fixed)?;
        } else {
            inputs.copy_helper(&mut output).map_err(fixed)?;
        }
    }
    // Mapped default streams were transported under basic identity custody.
    // Local execution still requires the full local NTFS/ADS/128-bit-ID checks.
    let installer = HeldApplicationFile::open_bounded(Path::new(INSTALLER), 2 * 1024 * 1024)?;
    if installer.observation().sha256 != INSTALLER_HASH
        || installer.observation().size_bytes != INSTALLER_SIZE
    {
        return Err("official 7-Zip 26.05 installer identity differs; nothing installed".into());
    }
    let helper = HeldApplicationFile::open(Path::new(HELPER))?;
    if helper.observation().sha256 != inputs.helper_hash() {
        return Err("local helper differs from held mapped bytes".into());
    }
    record(
        Path::new(OUTPUT),
        "00-start",
        &json!({
            "schemaVersion":"aiw.dev/research/sevenzip/v0alpha1", "productionEvidence":false,
            "installerSha256":INSTALLER_HASH,"installerSizeBytes":INSTALLER_SIZE,
            "helperSha256":helper.observation().sha256,"windows":crate::observe_windows_version()?,
            "scope":"7-Zip 26.05 CLI create/test/extract/integrity; classic AppContainer, zero capabilities",
            "gaps":["general compatibility","GUI and shell integration","registry and system-wide installation changes",
              "network/IPC/UI enforcement","all descendant tokens","production evidence receipt","host endpoint equivalence"]
        }),
    )?;
    let operation = setup_inner(&installer, &helper);
    let revalidated = inputs.revalidate().map_err(fixed);
    let result: Result<u8> = match (operation, revalidated) {
        (Ok(value), Ok(())) => Ok(value),
        (operation, revalidated) => Err(format!(
            "operation={operation:?}; mapped input revalidation={revalidated:?}"
        )
        .into()),
    };
    if let Err(error) = &result {
        record(
            Path::new(OUTPUT),
            "99-driver-error",
            &json!({"driverError":error.to_string(),
            "productionEvidence":false,"action":"preserve this exact worker/session and prior stages; do not reinstall blindly"}),
        )?;
    }
    publish_terminal(
        &json!({"schemaVersion":"aiw.dev/research/sevenzip-result/v0alpha1",
        "productionEvidence":false,"driverCompleted":result.is_ok(),
        "error":result.as_ref().err().map(ToString::to_string),
        "scope":"research observations; application functions are in workflow stage records; outer cleanup recorded only by host"}),
    )?;
    result
}

pub(crate) fn production_stage(name: &str) -> Result<Option<Vec<u8>>> {
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err("invalid internal stage name".into());
    }
    let _ancestors = hold_directory_chain(Path::new(OUTPUT))?;
    let path = Path::new(OUTPUT).join(format!("{name}.json"));
    if !path.try_exists()? {
        return Ok(None);
    }
    let held = HeldApplicationFile::open_bounded(&path, 128 * 1024)?;
    let bytes = held.read_bounded(128 * 1024)?;
    held.revalidate()?;
    Ok(Some(bytes))
}

fn setup_inner(installer: &HeldApplicationFile, helper: &HeldApplicationFile) -> Result<u8> {
    let standard = StandardUserSession::establish()?;
    let sid = &standard.context().user_sid;
    let _root = hold_directory_chain(Path::new(ROOT))?;
    let readable = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{sid})");
    set_acl(Path::new(ROOT), &readable, false)?;
    let held_helper = HeldApplicationFile::open(Path::new(HELPER))?;
    if held_helper.observation().sha256 != helper.observation().sha256 {
        return Err("staged helper bytes differ".into());
    }
    fs::create_dir(WORK)?;
    set_acl(
        Path::new(WORK),
        &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"),
        false,
    )?;
    set_acl(Path::new(WORK), "S:(ML;OICI;NW;;;LW)", true)?;
    write_new(&Path::new(ROOT).join("Denied.txt"), DENIED_BYTES)?;
    set_acl(
        &Path::new(ROOT).join("Denied.txt"),
        &format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;{sid})"),
        false,
    )?;
    record(Path::new(OUTPUT), "01-context", &json!(standard.context()))?;
    // One-use standard credentials launch once. Child proves the fixed native
    // capture/deadline controls before the parent installs the vendor software.
    let (child, held_token) =
        GuestProcess::start_standard_user_measured(HELPER, &["--workflow".into()], &standard)?;
    let operation = (|| -> Result<i32> {
        record(
            Path::new(OUTPUT),
            "02-launcher",
            &json!({"heldToken":held_token}),
        )?;
        wait_for_file(
            &Path::new(WORK).join("01-deadline-control.json"),
            Duration::from_secs(20),
        )?;
        let control: Value = serde_json::from_slice(&read_bounded(
            &Path::new(WORK).join("01-deadline-control.json"),
            128 * 1024,
        )?)?;
        if control["timedOut"] != true || control["jobEmpty"] != true {
            return Err("preinstall driver controls incomplete".into());
        }
        installer.revalidate()?;
        helper.revalidate()?;
        record(
            Path::new(OUTPUT),
            "03-install-start",
            &json!({"command":"fixed /S /D=C:\\AIW\\SevenZip\\App",
        "appRootBefore":"absent","installerSha256":INSTALLER_HASH}),
        )?;
        let process = GuestProcess::start(INSTALLER, &["/S".into(), format!("/D={APP}")])?;
        let install_exit = process.wait_for_exit(Duration::from_secs(90));
        let install_cleanup = process.cleanup();
        let exit = install_exit?;
        install_cleanup?;
        record(
            Path::new(OUTPUT),
            "04-install-exit",
            &json!({"exitCode":exit,"jobEmpty":true}),
        )?;
        if exit != 0 {
            return Err("installer failed; application comparison not reached".into());
        }
        record(
            Path::new(OUTPUT),
            "04-install-files",
            &json!({"appFilesAfter":inventory(Path::new(APP))?}),
        )?;
        installer.revalidate()?;
        let _app_dirs = hold_directory_chain(Path::new(APP))?;
        // Remove user write access even if installer introduced a different ACL.
        set_acl(Path::new(APP), &readable, false)?;
        let image = HeldApplicationFile::open(Path::new(IMAGE))?;
        let dll = HeldApplicationFile::open(Path::new(DLL))?;
        // The medium user cannot grant access to elevated-owned application code.
        // Derive only this compiled profile SID; the standard helper later verifies
        // its fresh profile equals this value. No caller-provided ACL principal.
        let package = DerivedProfileSid::new()?;
        for path in [ROOT, HELPER, APP, IMAGE, DLL, WORK] {
            grant_package_access(
                Path::new(path),
                package.0,
                (GENERIC_READ | GENERIC_EXECUTE).0,
            )?;
        }
        record(
            Path::new(WORK),
            "app-ready",
            &json!({"imageSha256":image.observation().sha256,
        "dllSha256":dll.observation().sha256,"profileSid":sid_string(package.0)?}),
        )?;
        let waited = child.wait_for_exit(Duration::from_secs(150));
        let exit = waited?;
        image.revalidate()?;
        dll.revalidate()?;
        let after_image = HeldApplicationFile::open(Path::new(IMAGE))?;
        let after_dll = HeldApplicationFile::open(Path::new(DLL))?;
        record(
            Path::new(OUTPUT),
            "05-workflow-exit",
            &json!({"exitCode":exit,
            "heldToken":held_token,"imageSha256":image.observation().sha256,"dllSha256":dll.observation().sha256,
            "codeBinding":{
                "imageBefore":{"sha256":image.observation().sha256,"sizeBytes":image.observation().size_bytes},
                "dllBefore":{"sha256":dll.observation().sha256,"sizeBytes":dll.observation().size_bytes},
                "imageAfter":{"sha256":after_image.observation().sha256,"sizeBytes":after_image.observation().size_bytes},
                "dllAfter":{"sha256":after_dll.observation().sha256,"sizeBytes":after_dll.observation().size_bytes}
            }}),
        )?;
        image.revalidate()?;
        dll.revalidate()?;
        Ok(exit)
    })();
    let cleanup = child.cleanup();
    // Never let output collection erase the original operation/cleanup failure.
    let cleanup_record = record(
        Path::new(OUTPUT),
        "05-launcher-cleanup",
        &json!({
        "jobEmpty":cleanup.is_ok(),"cleanupError":cleanup.as_ref().err().map(ToString::to_string),
        "operationError":operation.as_ref().err().map(ToString::to_string)}),
    );
    let collection = collect_stages();
    let exit=match (operation,cleanup,cleanup_record,collection) {
        (Ok(exit),Ok(()),Ok(()),Ok(()))=>exit,
        (operation,cleanup,record,collection)=>return Err(format!(
            "operation={operation:?}; launcher cleanup={cleanup:?}; cleanup record={record:?}; stage collection={collection:?}").into()),
    };
    held_helper.revalidate()?;
    helper.revalidate()?;
    installer.revalidate()?;
    record(
        Path::new(OUTPUT),
        "06-final",
        &json!({"productionEvidence":false,
        "workflowDriverExitCode":exit,"outerCleanup":"owned by host, not measured by guest",
        "launcherJobEmpty":true,
        "installationAndHelperBindingsUnchanged":true,"localResearchRootRetainedForOuterWorkerDisposal":ROOT}),
    )?;
    if exit != 0 {
        return Err(
            "workflow driver incomplete; retained stage records distinguish app failures".into(),
        );
    }
    Ok(0)
}

fn workflow(token: &TokenEvidence) -> Result<u8> {
    verify_token(token, std::process::id(), None, &token.user_sid)?;
    let _root_dirs = hold_directory_chain(Path::new(ROOT))?;
    let _work_dirs = hold_directory_chain(Path::new(WORK))?;
    let result = workflow_inner(token);
    if let Err(error) = &result {
        record(
            Path::new(WORK),
            "99-driver-error",
            &json!({"driverError":error.to_string(),
            "productionEvidence":false,"applicationIncompatibility":false}),
        )?;
    }
    result
}

fn workflow_inner(token: &TokenEvidence) -> Result<u8> {
    // Capture output/deadline/owned cleanup controls through the exact app process
    // authority, using a compiled self role rather than interpreting a script.
    let control = launch(Operation::Driver, None, Path::new(WORK), &token.user_sid)?;
    if control.exit_code != Some(23)
        || control.timed_out
        || control.output != DRIVER_BYTES
        || !control.job_empty
    {
        return Err("process/capture driver control failed".into());
    }
    record(Path::new(WORK), "00-driver-control", &json!(control))?;
    let deadline = launch(Operation::Deadline, None, Path::new(WORK), &token.user_sid)?;
    if !deadline.timed_out || !deadline.job_empty {
        return Err("deadline cleanup control failed".into());
    }
    record(Path::new(WORK), "01-deadline-control", &json!(deadline))?;
    wait_for_file(
        &Path::new(WORK).join("app-ready.json"),
        Duration::from_secs(100),
    )?;
    let image = HeldApplicationFile::open(Path::new(IMAGE))?;
    let dll = HeldApplicationFile::open(Path::new(DLL))?;
    // Fresh local roots; same input bytes and workflow operations in each mode.
    for name in ["Baseline", "Candidate"] {
        let root = Path::new(WORK).join(name);
        fs::create_dir(&root)?;
        fs::create_dir(root.join("Input"))?;
        fs::create_dir(root.join("Input").join("sub folder"))?;
        fs::create_dir(root.join("Extracted"))?;
        for (name, bytes) in fixture_bytes() {
            write_new(&root.join("Input").join(name), &bytes)?;
        }
    }
    let baseline = run_variant("Baseline", None, &token.user_sid)?;
    record(
        Path::new(WORK),
        "02-baseline",
        &json!({"functionsComplete":baseline}),
    )?;
    if !baseline {
        record(
            Path::new(WORK),
            "03-candidate-not-reached",
            &json!({"reason":"baseline function failed; no isolation attribution"}),
        )?;
        return Ok(0);
    }
    let mut profile = AppContainerProfile::create(SEVENZIP_PROFILE)?;
    let candidate = (|| -> Result<bool> {
        // Explicit traversal/read grants and one mutable candidate-data subtree.
        // No grants on unowned system paths or the Denied.txt canary.
        let expected = DerivedProfileSid::new()?;
        if profile.string_sid()? != sid_string(expected.0)? {
            return Err("fresh candidate profile differs".into());
        }
        let candidate_root = Path::new(WORK).join("Candidate");
        let package = profile.string_sid()?;
        let data_acl = format!(
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})(A;OICI;FA;;;{package})",
            sid = token.user_sid
        );
        // Root write permits archive creation, never DELETE_CHILD/WRITE_DAC
        // over the protected input subtree. Extracted output is mutable.
        let root_acl = format!(
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})(A;OICI;GRGWGX;;;{package})",
            sid = token.user_sid
        );
        set_acl(&candidate_root, &root_acl, false)?;
        set_acl(&candidate_root.join("Extracted"), &data_acl, false)?;
        let input_acl = format!(
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})(A;OICI;GRGX;;;{package})",
            sid = token.user_sid
        );
        for path in [
            candidate_root.join("Input"),
            candidate_root.join("Input").join("sub folder"),
        ] {
            set_acl(&path, &input_acl, false)?;
        }
        for name in fixture_bytes().keys() {
            set_acl(&candidate_root.join("Input").join(name), &input_acl, false)?;
        }
        // Baseline can read project-owned canary, candidate must report Win32 5.
        let baseline_canary = launch(Operation::Boundary, None, Path::new(WORK), &token.user_sid)?;
        let candidate_canary = launch(
            Operation::Boundary,
            Some(profile.sid),
            Path::new(WORK),
            &token.user_sid,
        )?;
        record(
            Path::new(WORK),
            "03-boundary",
            &json!({"baseline":baseline_canary,"candidate":candidate_canary,
            "profileSid":profile.string_sid()?,"capabilities":[],"grantScope":"read app/input, write candidate data only"}),
        )?;
        if baseline_canary.exit_code != Some(0)
            || baseline_canary.output != b"canary-readable"
            || candidate_canary.exit_code != Some(0)
            || candidate_canary.output != b"canary-denied-code5;input-write-delete-denied-code5"
            || !baseline_canary.job_empty
            || !candidate_canary.job_empty
        {
            return Err("boundary controls incomplete; no supported restriction claim".into());
        }
        run_variant("Candidate", Some(profile.sid), &token.user_sid)
    })();
    // Always attempt deletion after jobs stop; preserve both failures.
    let cleanup = profile.delete();
    let cleanup_record = record(
        Path::new(WORK),
        "04-profile-cleanup",
        &json!({"deleted":cleanup.is_ok(),
        "cleanupError":cleanup.as_ref().err().map(ToString::to_string),
        "candidateError":candidate.as_ref().err().map(ToString::to_string)}),
    );
    let candidate =
        match (candidate, cleanup, cleanup_record) {
            (Ok(value), Ok(()), Ok(())) => value,
            (candidate, cleanup, record) => return Err(format!(
                "candidate={candidate:?}; profile cleanup={cleanup:?}; cleanup record={record:?}"
            )
            .into()),
        };
    image.revalidate()?;
    dll.revalidate()?;
    let after_image = HeldApplicationFile::open(Path::new(IMAGE))?;
    let after_dll = HeldApplicationFile::open(Path::new(DLL))?;
    record(
        Path::new(WORK),
        "06-code-binding",
        &json!({
            "imageBefore":{"sha256":image.observation().sha256,"sizeBytes":image.observation().size_bytes},
            "dllBefore":{"sha256":dll.observation().sha256,"sizeBytes":dll.observation().size_bytes},
            "imageAfter":{"sha256":after_image.observation().sha256,"sizeBytes":after_image.observation().size_bytes},
            "dllAfter":{"sha256":after_dll.observation().sha256,"sizeBytes":after_dll.observation().size_bytes}
        }),
    )?;
    record(
        Path::new(WORK),
        "05-comparison",
        &json!({"productionEvidence":false,
        "baselineFunctionsComplete":baseline,"candidateFunctionsComplete":candidate,
        "selectedFileCanaryDenied":true,"profileDeleted":true,
        "verdict":"research observations only; general compatibility and effective isolation unmeasured"}),
    )?;
    Ok(0)
}

fn boundary_control(token: &TokenEvidence) -> Result<u8> {
    match fs::read(Path::new(ROOT).join("Denied.txt")) {
        Ok(bytes) if !token.is_app_container && bytes == DENIED_BYTES => {
            std::io::stdout().write_all(b"canary-readable")?;
            Ok(0)
        }
        Err(error) if token.is_app_container && error.raw_os_error() == Some(5) => {
            // Open only; never mutate bytes or remove a file even if a faulty
            // policy unexpectedly grants access. DELETE also detects a parent
            // DELETE_CHILD grant that would bypass the input file's own ACL.
            let input = Path::new(WORK).join(r"Candidate\Input\hello.txt");
            let input_dir = Path::new(WORK).join(r"Candidate\Input");
            for (path, access, flags) in [
                (&input, GENERIC_WRITE.0, FILE_FLAG_OPEN_REPARSE_POINT.0),
                (&input, 0x0001_0000, FILE_FLAG_OPEN_REPARSE_POINT.0),
                (
                    &input_dir,
                    0x0001_0000,
                    FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0,
                ),
            ] {
                match fs::OpenOptions::new()
                    .access_mode(access)
                    .custom_flags(flags)
                    .open(path)
                {
                    Err(error) if error.raw_os_error() == Some(5) => (),
                    _ => return Err("candidate input write/delete access was not denied".into()),
                }
            }
            std::io::stdout().write_all(b"canary-denied-code5;input-write-delete-denied-code5")?;
            Ok(0)
        }
        _ => Err("unexpected boundary canary observation".into()),
    }
}

fn fixture_bytes() -> BTreeMap<&'static str, Vec<u8>> {
    BTreeMap::from([
        (
            "hello.txt",
            b"App Isolation Workbench archive verification\r\n".to_vec(),
        ),
        (
            "sub folder\\Unicode-\u{65e5}\u{672c}.txt",
            "7-Zip UTF-8 text: \u{e9}\u{65e5}\u{672c}\r\n"
                .as_bytes()
                .to_vec(),
        ),
        ("binary.bin", (0..=255).cycle().take(4096).collect()),
        ("empty.txt", vec![]),
    ])
}

fn run_variant(name: &str, profile: Option<PSID>, sid: &str) -> Result<bool> {
    let root = Path::new(WORK).join(name);
    let expected = fixture_inventory();
    let input_before = inventory(&root.join("Input"))?;
    record(
        Path::new(WORK),
        &format!("{}-input-before", name.to_ascii_lowercase()),
        &json!(input_before),
    )?;
    if input_before != expected {
        return Err("input fixture differs".into());
    }
    for (index, operation) in [Operation::Create, Operation::Test, Operation::Extract]
        .into_iter()
        .enumerate()
    {
        let observed = launch(operation, profile, &root, sid)?;
        let success = observed.exit_code == Some(0) && !observed.timed_out && observed.job_empty;
        record(
            Path::new(WORK),
            &format!("{}-{index}", name.to_ascii_lowercase()),
            &json!({
            "function":operation.label(),"observation":observed,"passed":success}),
        )?;
        if !success {
            return Ok(false);
        }
    }
    let actual = inventory(&root.join("Extracted"))?;
    let input_after = inventory(&root.join("Input"))?;
    let passed = actual == expected && input_after == expected;
    record(
        Path::new(WORK),
        &format!("{}-3", name.to_ascii_lowercase()),
        &json!({
        "function":"verify","passed":passed,"expected":expected,"actual":actual,"inputAfter":input_after,
        "archive":inventory_one(&root.join("archive.7z"))?}),
    )?;
    Ok(passed)
}

fn fixture_inventory() -> BTreeMap<String, Value> {
    fixture_bytes()
        .into_iter()
        .map(|(name, bytes)| {
            (
                name.replace('\\', "/"),
                json!({"sha256":hex::encode(Sha256::digest(&bytes)),"sizeBytes":bytes.len()}),
            )
        })
        .collect()
}

#[derive(Clone, Copy)]
enum Operation {
    Driver,
    Deadline,
    Boundary,
    Create,
    Test,
    Extract,
}
impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::Driver => "driver",
            Self::Deadline => "deadline",
            Self::Boundary => "boundary",
            Self::Create => "create",
            Self::Test => "test",
            Self::Extract => "extract",
        }
    }
    fn command(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Self::Driver => (HELPER, &["--driver-control"]),
            Self::Deadline => (HELPER, &["--deadline-control"]),
            Self::Boundary => (HELPER, &["--boundary-control"]),
            Self::Create => (
                IMAGE,
                &["a", "-t7z", "-mx=1", "-y", "archive.7z", ".\\Input\\*"],
            ),
            Self::Test => (IMAGE, &["t", "-y", "archive.7z"]),
            Self::Extract => (IMAGE, &["x", "-y", "-o.\\Extracted", "archive.7z"]),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Invocation {
    token: TokenEvidence,
    exit_code: Option<u32>,
    timed_out: bool,
    job_empty: bool,
    output: Vec<u8>,
}

fn launch(
    operation: Operation,
    profile: Option<PSID>,
    directory: &Path,
    sid: &str,
) -> Result<Invocation> {
    let (image, arguments) = operation.command();
    let capture = directory.join(format!(
        "{}-{}-capture.txt",
        operation.label(),
        if profile.is_some() {
            "candidate"
        } else {
            "baseline"
        }
    ));
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&capture)?;
    let output_handle = HANDLE(output.as_raw_handle());
    unsafe { SetHandleInformation(output_handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }?;
    let inherited = [output_handle];
    let mut capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.unwrap_or_default(),
        ..Default::default()
    };
    let mut attributes = Attributes::new(if profile.is_some() { 2 } else { 1 })?;
    attributes.handles(&inherited)?;
    if profile.is_some() {
        attributes.security_capabilities(&mut capabilities)?;
    }
    let image_wide = wide(OsStr::new(image))?;
    let mut command = wide(OsStr::new(&aiw_windows_command_line::join_arguments(
        std::iter::once(image).chain(arguments.iter().copied()),
    )))?;
    let cwd = wide(directory.as_os_str())?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = windows::Win32::System::Threading::STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdOutput = output_handle;
    startup.StartupInfo.hStdError = output_handle;
    startup.lpAttributeList = attributes.list;
    let job = Job::create()?;
    let mut info = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(image_wide.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT
                | CREATE_NO_WINDOW,
            None,
            PCWSTR(cwd.as_ptr()),
            (&startup as *const STARTUPINFOEXW).cast(),
            &mut info,
        )
    }?;
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess.0) };
    let _thread = unsafe { OwnedHandle::from_raw_handle(info.hThread.0) };
    if let Err(error) = unsafe { AssignProcessToJobObject(job.handle(), info.hProcess) } {
        let stopped = unsafe { TerminateProcess(info.hProcess, 1) };
        let waited = wait(info.hProcess, Duration::from_secs(2));
        return Err(
            format!("assign app job: {error}; stopped={stopped:?}; waited={waited:?}").into(),
        );
    }
    let observed = (|| -> Result<Invocation> {
        let token = collect_process_token(process.as_handle())?;
        verify_token(&token, info.dwProcessId, profile, sid)?;
        if unsafe { ResumeThread(info.hThread) } != 1 {
            return Err("unexpected suspended count".into());
        }
        let timeout = if matches!(operation, Operation::Deadline) {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(25)
        };
        let completed = wait_completion(info.hProcess, timeout)?;
        let mut exit = 0;
        let exit_code = if completed {
            unsafe { GetExitCodeProcess(info.hProcess, &mut exit) }?;
            Some(exit)
        } else {
            None
        };
        job.terminate_and_verify_empty()?;
        output.sync_all()?;
        drop(output);
        let bytes = read_bounded(&capture, 128 * 1024)?;
        Ok(Invocation {
            token,
            exit_code,
            timed_out: !completed,
            job_empty: true,
            output: bytes,
        })
    })();
    let cleanup = job.terminate_and_verify_empty();
    match (observed, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), cleanup) => Err(format!("{error}; owned job cleanup={cleanup:?}").into()),
        (_, Err(error)) => Err(error.into()),
    }
}

fn record(root: &Path, name: &str, value: &Value) -> Result<()> {
    publish_new(
        &root.join(format!("{name}.pending")),
        &root.join(format!("{name}.json")),
        value,
    )
}
fn collect_stages() -> Result<()> {
    let stages = [
        "00-driver-control",
        "01-deadline-control",
        "app-ready",
        "baseline-0",
        "baseline-input-before",
        "baseline-1",
        "baseline-2",
        "baseline-3",
        "02-baseline",
        "03-candidate-not-reached",
        "03-boundary",
        "candidate-0",
        "candidate-input-before",
        "candidate-1",
        "candidate-2",
        "candidate-3",
        "04-profile-cleanup",
        "05-comparison",
        "06-code-binding",
        "99-driver-error",
    ];
    let mut missing = vec![];
    let mut failures = vec![];
    for stage in stages {
        let source = Path::new(WORK).join(format!("{stage}.json"));
        match source.try_exists() {
            Ok(false) => {
                missing.push(stage);
                continue;
            }
            Err(error) => {
                failures.push(format!("{stage}: {error}"));
                continue;
            }
            Ok(true) => {}
        }
        let result = (|| -> Result<()> {
            let held = HeldApplicationFile::open_bounded(&source, 128 * 1024)?;
            let bytes = read_bounded(&source, 128 * 1024)?;
            let _: Value = serde_json::from_slice(&bytes)?;
            held.revalidate()?;
            write_new(
                &Path::new(OUTPUT).join(format!("workflow-{stage}.json")),
                &bytes,
            )
        })();
        if let Err(error) = result {
            failures.push(format!("{stage}: {error}"));
        }
    }
    let recorded = record(
        Path::new(OUTPUT),
        "07-stage-collection",
        &json!({"missingStages":missing,
        "collectionErrors":failures,"missingMayBeNotReached":true}),
    );
    if !failures.is_empty() || recorded.is_err() {
        return Err(format!(
            "stage collection errors={failures:?}; collection record={recorded:?}"
        )
        .into());
    }
    Ok(())
}
fn publish_terminal(value: &Value) -> Result<()> {
    let pending = Path::new(OUTPUT).join("result.pending");
    let destination = Path::new(OUTPUT).join("result.json");
    publish_new(&pending, &destination, value)
}
fn publish_new(pending: &Path, destination: &Path, value: &Value) -> Result<()> {
    write_new(pending, &serde_json::to_vec_pretty(value)?)?;
    let pending = wide(pending.as_os_str())?;
    let destination = wide(destination.as_os_str())?;
    // MoveFileW has no replace-existing flag. A failed publication retains the
    // flushed pending file and never turns an earlier marker into today's result.
    unsafe {
        windows::Win32::Storage::FileSystem::MoveFileW(
            PCWSTR(pending.as_ptr()),
            PCWSTR(destination.as_ptr()),
        )
    }?;
    Ok(())
}
fn wait_for_file(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while !path.try_exists()? {
        if Instant::now() >= deadline {
            return Err("fixed stage deadline expired".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn inventory_one(path: &Path) -> Result<Value> {
    let file = HeldApplicationFile::open_bounded(path, 32 * 1024 * 1024)?;
    Ok(json!({"sha256":file.observation().sha256,"sizeBytes":file.observation().size_bytes}))
}
fn inventory(root: &Path) -> Result<BTreeMap<String, Value>> {
    let mut files = BTreeMap::new();
    let mut todo = vec![(root.to_path_buf(), 0)];
    let mut entries = 0usize;
    let mut total_bytes = 0u64;
    while let Some((directory, depth)) = todo.pop() {
        if depth > 8 || files.len() > 512 {
            return Err("bounded inventory exceeded".into());
        }
        let _held = hold_directory_chain(&directory)?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            entries += 1;
            if entries > 512 {
                return Err("bounded inventory entry count exceeded".into());
            }
            let meta = fs::symlink_metadata(entry.path())?;
            if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                return Err("reparse in inventory".into());
            }
            if meta.is_dir() {
                todo.push((entry.path(), depth + 1));
            } else if meta.is_file() {
                total_bytes = total_bytes
                    .checked_add(meta.len())
                    .ok_or("inventory size overflow")?;
                if total_bytes > 64 * 1024 * 1024 {
                    return Err("bounded inventory byte budget exceeded".into());
                }
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)?
                    .to_str()
                    .ok_or("non-Unicode inventory")?
                    .replace('\\', "/");
                files.insert(relative, inventory_one(&path)?);
            } else {
                return Err("non-file inventory object".into());
            }
        }
    }
    if files.len() > 512 {
        return Err("bounded inventory exceeded".into());
    }
    Ok(files)
}
fn hold_directory_chain(path: &Path) -> Result<Vec<fs::File>> {
    let mut current = PathBuf::from(r"C:\");
    let mut held = vec![];
    if !path.starts_with(&current) {
        return Err("research directory outside C drive".into());
    }
    for component in
        std::iter::once(None).chain(path.strip_prefix(&current)?.components().map(Some))
    {
        if let Some(component) = component {
            current.push(component.as_os_str());
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(&current)?;
        let meta = file.metadata()?;
        if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err("research ancestry contains non-directory/reparse object".into());
        }
        held.push(file);
    }
    Ok(held)
}
fn set_acl(path: &Path, sddl: &str, label: bool) -> Result<()> {
    let text = wide(OsStr::new(sddl))?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }?;
    let path = wide(path.as_os_str())?;
    let information = if label {
        LABEL_SECURITY_INFORMATION
    } else {
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
    };
    let result = unsafe { SetFileSecurityW(PCWSTR(path.as_ptr()), information, descriptor) };
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    result.ok()?;
    Ok(())
}

struct DerivedProfileSid(PSID);
impl DerivedProfileSid {
    fn new() -> Result<Self> {
        let name = wide(OsStr::new(SEVENZIP_PROFILE))?;
        let sid = unsafe {
            windows::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName(PCWSTR(
                name.as_ptr(),
            ))
        }?;
        Ok(Self(sid))
    }
}
impl Drop for DerivedProfileSid {
    fn drop(&mut self) {
        unsafe { windows::Win32::Security::FreeSid(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sevenzip_fixture_verification_includes_empty_binary_nested_unicode_and_exact_inventory() {
        let bytes = fixture_bytes();
        let inventory = fixture_inventory();
        assert_eq!(inventory.len(), 4);
        assert_eq!(bytes["binary.bin"].len(), 4096);
        assert_eq!(inventory["empty.txt"]["sizeBytes"], 0);
        assert!(inventory.contains_key("sub folder/Unicode-\u{65e5}\u{672c}.txt"));
        let mut missing = inventory.clone();
        missing.remove("empty.txt");
        assert_ne!(missing, inventory);
        let mut extra = inventory.clone();
        extra.insert("extra.txt".into(), json!({}));
        assert_ne!(extra, inventory);
        let mut changed = inventory.clone();
        changed.get_mut("hello.txt").unwrap()["sha256"] = json!("0".repeat(64));
        assert_ne!(changed, inventory);
    }
    #[test]
    fn sevenzip_operations_are_fixed_and_extraction_cannot_overwrite_input() {
        assert_eq!(Operation::Create.command().0, IMAGE);
        assert_eq!(
            Operation::Extract.command().1,
            ["x", "-y", "-o.\\Extracted", "archive.7z"]
        );
        assert_eq!(
            Operation::Driver.command(),
            (HELPER, &["--driver-control"][..])
        );
        assert!(!Operation::Create.command().1.contains(&"-sfx"));
    }
    #[test]
    fn sevenzip_research_writer_refuses_existing_destinations_and_preserves_original() {
        let root = std::env::temp_dir().join(format!("aiw-sevenzip-write-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let path = root.join("stage.json");
        write_new(&path, b"first").unwrap();
        assert!(write_new(&path, b"second").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn sevenzip_actual_inventory_detects_missing_extra_and_changed_payloads() {
        let root =
            std::env::temp_dir().join(format!("aiw-sevenzip-inventory-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("sub folder")).unwrap();
        for (name, bytes) in fixture_bytes() {
            write_new(&root.join(name), &bytes).unwrap();
        }
        let expected = fixture_inventory();
        assert_eq!(inventory(&root).unwrap(), expected);
        fs::remove_file(root.join("empty.txt")).unwrap();
        assert_ne!(inventory(&root).unwrap(), expected);
        write_new(&root.join("empty.txt"), b"").unwrap();
        write_new(&root.join("extra.txt"), b"extra").unwrap();
        assert_ne!(inventory(&root).unwrap(), expected);
        fs::remove_file(root.join("extra.txt")).unwrap();
        fs::write(root.join("hello.txt"), b"changed").unwrap();
        assert_ne!(inventory(&root).unwrap(), expected);
        for name in fixture_bytes().keys() {
            fs::remove_file(root.join(name)).unwrap();
        }
        fs::remove_dir(root.join("sub folder")).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn sevenzip_host_role_is_rejected_before_installation_or_account_creation() {
        assert!(
            run()
                .unwrap_err()
                .to_string()
                .contains("fixed standard-user research role")
        );
    }
}
