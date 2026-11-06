use aiw_probe::WorkspaceBindingEvidence;
use aiw_provider_wsb::{GoldenProbe, MappedFolder, MappingPurpose, WindowsSandboxPlan};
use aiw_windows_platform::{CanonicalSandboxId, HeldApplicationFile, HeldRunWorkspace};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    io::Write,
    path::Path,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const ROOT: &str = r"C:\AIW-SevenZip-Trial-20261105";
const PROVIDER: &str = "247e092b5c5bd37820f225a7dd3ddf10ae37a67e2751a19c24b802c84769c441";
const INSTALLER: &str = "fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0";
const SESSION: &str = "61e939ef-1e05-4b59-9593-3df457b10428";
const SCHEMA: &str = "aiw.dev/research/sevenzip-trial/v0alpha1";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proposal {
    schema_version: String,
    workspace: WorkspaceBindingEvidence,
    plan: WindowsSandboxPlan,
    helper_sha256: String,
    helper_size_bytes: u64,
    installer_sha256: String,
    provider_sha256: String,
    session_id: String,
    operator_sid: String,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn recovery_allowed(record: Option<&serde_json::Value>, hash: &str, recovered: bool) -> bool {
    if recovered {
        return false;
    }
    record.is_none_or(|record| {
        record["schemaVersion"] == SCHEMA
            && record["researchOnly"] == true
            && record["planSha256"] == hash
            && record["sessionId"] == SESSION
            && record["outerCleanupVerified"] == false
    })
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuestMarker {
    schema_version: String,
    production_evidence: bool,
    driver_completed: bool,
    error: Option<String>,
    scope: String,
}
fn completed_marker(workspace: &HeldRunWorkspace) -> Result<String> {
    let file =
        HeldApplicationFile::open_bounded(&workspace.output_path().join("result.json"), 16 * 1024)?;
    let bytes = file.read_bounded(16 * 1024)?;
    let hash = marker_digest(&bytes)?;
    file.revalidate()?;
    Ok(hash)
}
fn marker_digest(bytes: &[u8]) -> Result<String> {
    if bytes.len() > 16 * 1024 {
        return Err("guest marker exceeds bound".into());
    }
    let marker: GuestMarker = serde_json::from_slice(bytes)?;
    if marker.schema_version != "aiw.dev/research/sevenzip-result/v0alpha1"
        || marker.production_evidence
        || marker.scope.len() > 1024
        || marker.error.as_ref().is_some_and(|s| s.len() > 8192)
        || marker.driver_completed == marker.error.is_some()
    {
        return Err("invalid untrusted guest completion marker".into());
    }
    Ok(digest(bytes))
}
fn helper_hash() -> Result<&'static str> {
    let value = option_env!("AIW_SEVENZIP_HELPER_SHA256")
        .ok_or("build must enroll the separately verified helper SHA-256")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid build-time helper commitment".into());
    }
    Ok(value)
}
fn fixed_os_and_actor() -> Result<String> {
    let os = aiw_windows_platform::observe_windows_version()?;
    if (
        os.major,
        os.minor,
        os.build,
        os.revision,
        os.observer_architecture.as_str(),
    ) != (10, 0, 26300, 9711, "x86_64")
    {
        return Err("host differs from the reviewed VM107 OS; no dispatch".into());
    }
    let token = aiw_token::collect_current_process_token()?;
    if token.is_elevated || token.is_app_container {
        return Err("existing non-elevated ordinary operator account is required".into());
    }
    Ok(token.user_sid)
}
fn publish(workspace: &HeldRunWorkspace, leaf: &str, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = workspace.create_root_file_new(leaf)?;
    file.as_file_mut().write_all(&bytes)?;
    file.as_file_mut().sync_all()?;
    Ok(())
}
fn read_protected<T: for<'a> Deserialize<'a>>(
    workspace: &HeldRunWorkspace,
    leaf: &str,
) -> Result<T> {
    let bound = workspace.reopen_root_file_readonly(leaf)?;
    let held = HeldApplicationFile::open_bounded(bound.final_path(), 1024 * 1024)?;
    let value = serde_json::from_slice(&held.read_bounded(1024 * 1024)?)?;
    bound.revalidate()?;
    held.revalidate()?;
    Ok(value)
}
fn normalized(path: &Path) -> String {
    path.to_string_lossy()
        .strip_prefix(r"\\?\")
        .unwrap_or(&path.to_string_lossy())
        .to_owned()
}
fn plan(workspace: &HeldRunWorkspace) -> WindowsSandboxPlan {
    WindowsSandboxPlan {
        schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.into(),
        workspace_root: normalized(workspace.root_path()),
        mappings: vec![
            MappedFolder {
                purpose: MappingPurpose::Tools,
                host_folder: normalized(&workspace.tools_path()),
                sandbox_folder: r"C:\AIW\Tools".into(),
            },
            MappedFolder {
                purpose: MappingPurpose::Output,
                host_folder: normalized(&workspace.output_path()),
                sandbox_folder: r"C:\AIW\SevenZipOutput".into(),
            },
        ],
        probe: GoldenProbe {
            executable: r"C:\AIW\Tools\sevenzip_assessment.exe".into(),
            request: None,
            output: r"C:\AIW\SevenZipOutput\result.json".into(),
        },
        memory_mb: Some(2048),
    }
}
fn stage(workspace: &HeldRunWorkspace, name: &str, expected: &str) -> Result<u64> {
    let source = HeldApplicationFile::open(Path::new(ROOT).join("Inputs").join(name).as_path())?;
    if source.observation().sha256 != expected {
        return Err("input hash differs from build commitment".into());
    }
    if name == "7z2605-x64.exe" && source.observation().size_bytes != 1_663_506 {
        return Err("installer size mismatch".into());
    }
    let mut writer = workspace.create_tools_file_new(name)?;
    source.copy_to(writer.as_file_mut())?;
    writer.as_file_mut().sync_all()?;
    let size = source.observation().size_bytes;
    source.revalidate()?;
    drop(writer);
    let file = workspace.reopen_tools_file_readonly(name)?;
    let held = HeldApplicationFile::open(file.final_path())?;
    if held.observation().sha256 != expected || held.observation().size_bytes != size {
        return Err("staged input mismatch".into());
    }
    Ok(size)
}
fn verify_tools(
    workspace: &HeldRunWorkspace,
    proposal: &Proposal,
) -> Result<
    Vec<(
        aiw_windows_platform::BoundWorkspaceFile,
        HeldApplicationFile,
    )>,
> {
    let mut held = vec![];
    let mut names = std::fs::read_dir(workspace.tools_path())?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    if names
        != [
            std::ffi::OsString::from("7z2605-x64.exe"),
            std::ffi::OsString::from("sevenzip_assessment.exe"),
        ]
    {
        return Err("fixed Tools inventory differs".into());
    }
    for (name, hash, size) in [
        ("7z2605-x64.exe", INSTALLER, 1_663_506),
        (
            "sevenzip_assessment.exe",
            helper_hash()?,
            proposal.helper_size_bytes,
        ),
    ] {
        let bound = workspace.reopen_tools_file_readonly(name)?;
        let file = HeldApplicationFile::open(bound.final_path())?;
        if file.observation().identity != *bound.identity()
            || file.observation().sha256 != hash
            || file.observation().size_bytes != size
        {
            return Err("protected input identity drift".into());
        }
        held.push((bound, file));
    }
    Ok(held)
}
pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let actor = fixed_os_and_actor()?;
    helper_hash()?;
    if args == ["--prepare"] {
        let workspace = HeldRunWorkspace::create(Path::new(ROOT), "Trial")?;
        let helper_size = stage(&workspace, "sevenzip_assessment.exe", helper_hash()?)?;
        stage(&workspace, "7z2605-x64.exe", INSTALLER)?;
        let proposal = Proposal {
            schema_version: SCHEMA.into(),
            workspace: workspace.evidence().clone(),
            plan: plan(&workspace),
            helper_sha256: helper_hash()?.into(),
            helper_size_bytes: helper_size,
            installer_sha256: INSTALLER.into(),
            provider_sha256: PROVIDER.into(),
            session_id: SESSION.into(),
            operator_sid: actor,
        };
        let rendered = aiw_provider_wsb::render_config(&proposal.plan)?;
        publish(&workspace, "proposal.json", &proposal)?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"researchOnly":true,"planSha256":digest(&serde_json::to_vec(&proposal)?),"proposal":proposal,"rendered":rendered,"effects":"Installs the pinned unsigned vendor7Zip installer only in a fresh offline Sandbox. Runs project-owned driver controls then fixed standard-user archive functions in ordinary and classicAppContainer modes. Retains untrusted research observations. Exact owned session stop; no production report or general isolation verdict."})
            )?
        );
        return Ok(());
    }
    if args.len() != 2 || !matches!(args[0].as_str(), "--approve" | "--start" | "--recover") {
        return Err("expected --prepare, --approve HASH, --start HASH, or --recover HASH".into());
    }
    // Bootstrap reads no executable authority; reopening the exact protected
    // workspace below re-reads this same proposal through bound held handles.
    let proposal_file = HeldApplicationFile::open_bounded(
        &Path::new(ROOT).join(r"Trial\proposal.json"),
        1024 * 1024,
    )?;
    let proposal: Proposal = serde_json::from_slice(&proposal_file.read_bounded(1024 * 1024)?)?;
    let workspace = HeldRunWorkspace::reopen_bound(&proposal.workspace)?;
    if normalized(workspace.root_path()) != format!(r"{ROOT}\Trial")
        || proposal != read_protected::<Proposal>(&workspace, "proposal.json")?
        || proposal.schema_version != SCHEMA
        || proposal.plan != plan(&workspace)
        || proposal.helper_sha256 != helper_hash()?
        || proposal.provider_sha256 != PROVIDER
        || proposal.installer_sha256 != INSTALLER
        || proposal.session_id != SESSION
        || proposal.operator_sid != actor
    {
        return Err("proposal drift or foreign original workspace".into());
    }
    let hash = digest(&serde_json::to_vec(&proposal)?);
    if args[1] != hash {
        return Err("exact proposal hash required".into());
    }
    if args[0] == "--approve" {
        let _tools = verify_tools(&workspace, &proposal)?;
        publish(&workspace, "approval.json", &hash)?;
        println!("Approved research proposal {hash}; Start remains separate.");
        return Ok(());
    }
    if read_protected::<String>(&workspace, "approval.json")? != hash {
        return Err("matching approval required".into());
    }
    let id = CanonicalSandboxId::parse(SESSION)?;
    if args[0] == "--recover" {
        let prior = if workspace
            .root_path()
            .join("host-result.json")
            .try_exists()?
        {
            Some(read_protected::<serde_json::Value>(
                &workspace,
                "host-result.json",
            )?)
        } else {
            None
        };
        let cleanup = if workspace
            .root_path()
            .join("cleanup-observation.json")
            .try_exists()?
        {
            Some(read_protected::<serde_json::Value>(
                &workspace,
                "cleanup-observation.json",
            )?)
        } else {
            None
        };
        if read_protected::<String>(&workspace, "start-intent.json")? != hash
            || !recovery_allowed(
                prior.as_ref(),
                &hash,
                workspace.root_path().join("recovery.json").try_exists()?,
            )
            || !recovery_allowed(cleanup.as_ref(), &hash, false)
        {
            return Err("only unresolved original trial can be recovered once".into());
        }
        // A crash during recovery needs review of this exact transaction. Never
        // retry a mutation against a later session reusing the original UUID.
        publish(&workspace, "recovery-intent.json", &hash)?;
        let mut lease = aiw_windows_platform::acquire_windows_sandbox_recovery(PROVIDER, id)?;
        let result = lease.reconcile()?;
        let record = json!({"schemaVersion":SCHEMA,"planSha256":hash,"sessionId":result.session_id,"outerCleanupVerified":true,"disposition":format!("{:?}",result.disposition),"providerDrifted":result.provider_drifted,"sessionIdsBefore":result.session_ids_before,"sessionIdsAfter":result.session_ids_after});
        publish(&workspace, "recovery.json", &record)?;
        println!("{}", serde_json::to_string_pretty(&record)?);
        return Ok(());
    }
    let tools = verify_tools(&workspace, &proposal)?;
    if std::fs::read_dir(workspace.output_path())?.next().is_some() {
        return Err("output must be empty; preserve existing evidence".into());
    }
    if Path::new(ROOT).join(r"Trial\recovery.json").exists() {
        return Err("recovered trial cannot Start".into());
    }
    let mut lease = aiw_windows_platform::acquire_windows_sandbox(PROVIDER)?;
    if !lease.list()?.session_ids.is_empty() {
        return Err("worker provider is in use".into());
    }
    // Durable create-new transaction precedes the mutating call. Any interruption
    // requires exact recovery, never another installation attempt in this root.
    publish(&workspace, "start-intent.json", &hash)?;
    let execution = (|| -> Result<()> {
        workspace.revalidate()?;
        for (bound, file) in &tools {
            bound.revalidate()?;
            file.revalidate()?;
        }
        lease.start(&id, &proposal.plan)?;
        lease.connect_owned()?;
        let deadline = Instant::now() + Duration::from_secs(420);
        while Instant::now() < deadline {
            if completed_marker(&workspace).is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("research observation deadline; application compatibility remains unknown".into())
    })();
    let cleanup = lease.stop_owned();
    let cleanup_verified = cleanup.is_ok();
    // Persist cleanup independently before touching any returned guest bytes.
    publish(
        &workspace,
        "cleanup-observation.json",
        &json!({"schemaVersion":SCHEMA,"researchOnly":true,"planSha256":hash,"sessionId":SESSION,"outerCleanupVerified":cleanup_verified,"cleanupError":cleanup.as_ref().err().map(ToString::to_string)}),
    )?;
    let output = completed_marker(&workspace);
    let record = json!({"schemaVersion":SCHEMA,"researchOnly":true,"planSha256":hash,"sessionId":SESSION,"guestMarkerObserved":execution.is_ok(),"executionError":execution.as_ref().err().map(ToString::to_string),"outerCleanupVerified":cleanup_verified,"cleanupError":cleanup.as_ref().err().map(ToString::to_string),"outputSha256":output.as_ref().ok(),"outputError":output.as_ref().err().map(ToString::to_string),"applicationCompatibility":"unmeasuredByHostDriver","isolationVerdict":"unmeasuredByHostDriver"});
    publish(&workspace, "host-result.json", &record)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    execution?;
    cleanup?;
    output?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guest_marker_rejects_partial_production_unknown_and_contradictory_claims() {
        let marker = json!({"schemaVersion":"aiw.dev/research/sevenzip-result/v0alpha1","productionEvidence":false,"driverCompleted":true,"error":null,"scope":"research"});
        assert!(marker_digest(&serde_json::to_vec(&marker).unwrap()).is_ok());
        assert!(marker_digest(b"{\"schemaVersion\":").is_err());
        for (key, value) in [
            ("productionEvidence", json!(true)),
            ("driverCompleted", json!(false)),
            ("error", json!("failed")),
            ("unknown", json!(true)),
        ] {
            let mut invalid = marker.clone();
            invalid[key] = value;
            assert!(
                marker_digest(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                "{key}"
            );
        }
        let mut failed = marker;
        failed["driverCompleted"] = json!(false);
        failed["error"] = json!("driver incomplete");
        assert!(marker_digest(&serde_json::to_vec(&failed).unwrap()).is_ok());
    }
    #[test]
    fn unresolved_cleanup_remains_recoverable_but_completed_and_reused_transactions_do_not() {
        let hash = "a".repeat(64);
        let unresolved = json!({"schemaVersion":SCHEMA,"researchOnly":true,"planSha256":hash,"sessionId":SESSION,"outerCleanupVerified":false});
        assert!(recovery_allowed(Some(&unresolved), &hash, false));
        assert!(recovery_allowed(None, &hash, false));
        assert!(!recovery_allowed(Some(&unresolved), &hash, true));
        for field in [
            "schemaVersion",
            "researchOnly",
            "planSha256",
            "sessionId",
            "outerCleanupVerified",
        ] {
            let mut invalid = unresolved.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(!recovery_allowed(Some(&invalid), &hash, false), "{field}");
        }
        let mut completed = unresolved;
        completed["outerCleanupVerified"] = json!(true);
        assert!(!recovery_allowed(Some(&completed), &hash, false));
    }
}
