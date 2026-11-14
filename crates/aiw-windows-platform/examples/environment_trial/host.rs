//! Closed research transaction: observe a fresh worker, never install an app.
use aiw_probe::{
    WindowsSandboxStaticIdentity, WindowsVersionObservation, WorkspaceBindingEvidence,
};
use aiw_provider_wsb::{GoldenProbe, MappedFolder, MappingPurpose, WindowsSandboxPlan};
use aiw_windows_platform::environment_probe::{self as contract, EnvironmentReport, FileFact};
use aiw_windows_platform::{CanonicalSandboxId, HeldApplicationFile, HeldRunWorkspace};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const ROOT: &str = r"C:\AIW-Environment-Probe-20261114-R1";
const SESSION: &str = "5f87471d-7325-4118-ac51-d5b691470391";
const SCHEMA: &str = "aiw.dev/research/environment-host-trial/v0alpha1";
const HELPER: &str = "environment_probe.exe";
const VM_UUID: &str = "e5cecc90-35c2-4831-bf9c-424be23f7d4e";
const EXPECTED_HOST: &str = "10.0.26300.9974/x86_64";
const API_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proposal {
    schema_version: String,
    workspace: WorkspaceBindingEvidence,
    plan: WindowsSandboxPlan,
    helper_sha256: String,
    helper_size_bytes: u64,
    source_sha256: String,
    host_windows: WindowsVersionObservation,
    provider: WindowsSandboxStaticIdentity,
    rendered_config_sha256: String,
    session_id: String,
    worker_uuid: String,
    operator_sid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Marker {
    file: FileFact,
    report: EnvironmentReport,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn normalized(path: &Path) -> String {
    path.to_string_lossy()
        .strip_prefix(r"\\?\")
        .unwrap_or(&path.to_string_lossy())
        .into()
}
fn windows_label(value: &WindowsVersionObservation) -> String {
    format!(
        "{}.{}.{}.{}/{}",
        value.major, value.minor, value.build, value.revision, value.observer_architecture
    )
}
fn source_hash() -> String {
    let shared = aiw_probe::seven_zip_source_sha256();
    let sources = [
        shared.as_str(),
        include_str!("host.rs"),
        include_str!("../environment_sandbox_trial.rs"),
        include_str!("../environment_probe.rs"),
        include_str!("../../src/environment_probe.rs"),
        include_str!("../../src/research_publication.rs"),
        include_str!("../../src/windows_platform.rs"),
        include_str!("../../src/workspace.rs"),
        include_str!("../../src/source_inspection.rs"),
        include_str!("../../src/exact_dispose.rs"),
        include_str!("../../src/coordination.rs"),
        include_str!("../../src/powershell.rs"),
        include_str!("../../../aiw-token/src/lib.rs"),
        include_str!("../../../aiw-probe/src/lib.rs"),
        include_str!("../../../aiw-provider-wsb/src/lib.rs"),
        include_str!("../../../aiw-provider-wsb/Cargo.toml"),
        include_str!("../../Cargo.toml"),
        include_str!("../../../../Cargo.lock"),
    ];
    let mut hash = Sha256::new();
    for source in sources {
        hash.update((source.len() as u64).to_le_bytes());
        hash.update(source.as_bytes());
    }
    hex::encode(hash.finalize())
}
fn helper_hash() -> Result<&'static str> {
    let value = option_env!("AIW_ENVIRONMENT_HELPER_SHA256")
        .ok_or("build must enroll independently verified environment helper")?;
    if !contract::valid_hash(value) {
        return Err("invalid environment helper commitment".into());
    }
    Ok(value)
}
fn fixed_plan(root: &str) -> WindowsSandboxPlan {
    WindowsSandboxPlan {
        schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.into(),
        workspace_root: root.into(),
        mappings: vec![
            MappedFolder {
                purpose: MappingPurpose::Tools,
                host_folder: format!(r"{root}\tools"),
                sandbox_folder: r"C:\AIW\Tools".into(),
            },
            MappedFolder {
                purpose: MappingPurpose::Output,
                host_folder: format!(r"{root}\output"),
                sandbox_folder: contract::OUTPUT.into(),
            },
        ],
        probe: GoldenProbe {
            executable: contract::IMAGE.into(),
            request: None,
            output: contract::RESULT.into(),
        },
        memory_mb: Some(2048),
    }
}
fn plan(workspace: &HeldRunWorkspace) -> WindowsSandboxPlan {
    fixed_plan(&normalized(workspace.root_path()))
}
fn publish(workspace: &HeldRunWorkspace, name: &str, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() > 1024 * 1024 {
        return Err("host record exceeds bound".into());
    }
    let mut file = workspace.create_root_file_new(name)?;
    file.as_file_mut().write_all(&bytes)?;
    file.as_file_mut().sync_all()?;
    Ok(())
}
fn read_protected<T: for<'a> Deserialize<'a>>(
    workspace: &HeldRunWorkspace,
    name: &str,
) -> Result<T> {
    let bound = workspace.reopen_root_file_readonly(name)?;
    let file = HeldApplicationFile::open_bounded(bound.final_path(), 1024 * 1024)?;
    if file.observation().identity != *bound.identity() {
        return Err("host record binding differs".into());
    }
    let result = serde_json::from_slice(&file.read_bounded(1024 * 1024)?)?;
    bound.revalidate()?;
    file.revalidate()?;
    Ok(result)
}
fn exact_inventory(path: &Path, expected: &[&str]) -> Result<()> {
    let mut names = std::fs::read_dir(path)?
        .take(expected.len() + 1)
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    let mut expected = expected
        .iter()
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
    expected.sort();
    if names != expected {
        return Err("fixed directory inventory differs".into());
    }
    Ok(())
}
fn verify_tool(
    workspace: &HeldRunWorkspace,
    proposal: &Proposal,
) -> Result<(
    aiw_windows_platform::BoundWorkspaceFile,
    HeldApplicationFile,
)> {
    exact_inventory(&workspace.tools_path(), &[HELPER])?;
    let bound = workspace.reopen_tools_file_readonly(HELPER)?;
    let file = HeldApplicationFile::open_bounded(bound.final_path(), 128 * 1024 * 1024)?;
    if file.observation().identity != *bound.identity()
        || file.observation().sha256 != proposal.helper_sha256
        || file.observation().size_bytes != proposal.helper_size_bytes
    {
        return Err("held environment helper differs".into());
    }
    bound.revalidate()?;
    file.revalidate()?;
    Ok((bound, file))
}
fn read_marker(workspace: &HeldRunWorkspace) -> Result<(Marker, Vec<u8>)> {
    exact_inventory(&workspace.output_path(), &["RESULT.DAT"])?;
    let bound = workspace.reopen_output_file_readonly("RESULT.DAT")?;
    let file = HeldApplicationFile::open_bounded(bound.final_path(), contract::OUTPUT_BOUND)?;
    if file.observation().identity != *bound.identity() {
        return Err("environment marker binding differs".into());
    }
    let bytes = file.read_bounded(contract::OUTPUT_BOUND)?;
    if digest(&bytes) != file.observation().sha256 {
        return Err("environment marker bytes differ from held hash".into());
    }
    let report: EnvironmentReport = serde_json::from_slice(&bytes)?;
    report.validate()?;
    let result = Marker {
        file: FileFact::from_held(&file),
        report,
    };
    bound.revalidate()?;
    file.revalidate()?;
    workspace.revalidate()?;
    Ok((result, bytes))
}
fn completed(workspace: &HeldRunWorkspace) -> Result<Marker> {
    read_marker(workspace).map(|(marker, _)| marker)
}
fn print_json(value: &serde_json::Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() > 1024 * 1024 {
        return Err("complete host output exceeds bound; no truncation".into());
    }
    let mut output = std::io::stdout().lock();
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    Ok(())
}
fn retained_binding(
    record: &serde_json::Value,
    hash: &str,
    approval: Option<&str>,
    start: Option<&str>,
    dispatch: Option<&str>,
) -> bool {
    record["schemaVersion"] == SCHEMA
        && record["planSha256"] == hash
        && record["sessionId"] == SESSION
        && record["startDispatched"] == true
        && approval == Some(hash)
        && start == Some(hash)
        && dispatch == Some(hash)
}

// Same bounded, held-machine-Core VM/ordinary-console guard as the prior native
// fixtures, without inheriting their obsolete OS/root/session constants.
fn vm_guard() -> Result<String> {
    let token = aiw_token::collect_current_process_token()?;
    if token.is_elevated
        || token.is_app_container
        || token.token_type != aiw_token::TokenType::Primary
        || token.impersonation_level.is_some()
        || token.integrity.rid != 8192
    {
        return Err("ordinary medium primary operator required".into());
    }
    let runtime = aiw_windows_platform::HeldPowerShell::observe()?;
    runtime.revalidate()?;
    let script = concat!(
        "$ErrorActionPreference='Stop';",
        "if((Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 15).UUID -ine 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'){throw 'Wrong existing VM'};",
        "if([Security.Principal.WindowsIdentity]::GetCurrent().Name -ine 'AIW\\labadmin' -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 1){throw 'Wrong ordinary console'};",
        "[Console]::Out.Write('VM107-ENVIRONMENT-GUARD-OK')"
    );
    let mut child = Command::new(aiw_probe::powershell::POWERSHELL_EXECUTABLE)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("guard stdout absent")?;
    let stderr = child.stderr.take().ok_or("guard stderr absent")?;
    let (tx_out, out) = std::sync::mpsc::channel();
    let (tx_err, err) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(4097).read_to_end(&mut bytes).map(|_| bytes);
        let _ = tx_out.send(result);
    });
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stderr.take(4097).read_to_end(&mut bytes).map(|_| bytes);
        let _ = tx_err.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let cleanup = Instant::now() + Duration::from_secs(5);
            while child.try_wait()?.is_none() {
                if Instant::now() >= cleanup {
                    return Err("guard cleanup unconfirmed; preserve owned process".into());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            return Err("fixed VM guard deadline".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = out.recv_timeout(Duration::from_secs(1))??;
    let errors = err.recv_timeout(Duration::from_secs(1))??;
    runtime.revalidate()?;
    if !status.success() || output != b"VM107-ENVIRONMENT-GUARD-OK" || !errors.is_empty() {
        return Err("fixed VM/operator guard refused".into());
    }
    Ok(token.user_sid)
}
fn host_identity() -> Result<(WindowsVersionObservation, WindowsSandboxStaticIdentity)> {
    let windows = contract::observe_windows()?;
    if windows_label(&windows) != EXPECTED_HOST {
        return Err(format!(
            "host API version {} differs from reviewed {EXPECTED_HOST}; inspect without dispatch",
            windows_label(&windows)
        )
        .into());
    }
    let provider = aiw_windows_platform::inspect_windows_sandbox_static()?;
    if provider.os_version != windows {
        return Err("host version drift during static provider observation".into());
    }
    Ok((windows, provider))
}

fn load() -> Result<(HeldRunWorkspace, Proposal, String)> {
    let file = HeldApplicationFile::open_bounded(
        &Path::new(ROOT).join(r"Trial\proposal.json"),
        1024 * 1024,
    )?;
    let proposal: Proposal = serde_json::from_slice(&file.read_bounded(1024 * 1024)?)?;
    // Refuse caller-nominated workspace paths before reopening any such path.
    if normalized(Path::new(&proposal.workspace.root.final_path)) != format!(r"{ROOT}\Trial")
        || proposal.schema_version != SCHEMA
        || proposal.source_sha256 != source_hash()
        || proposal.helper_sha256 != helper_hash()?
        || proposal.helper_size_bytes == 0
        || proposal.helper_size_bytes > 128 * 1024 * 1024
        || proposal.session_id != SESSION
        || proposal.worker_uuid != VM_UUID
        || windows_label(&proposal.host_windows) != EXPECTED_HOST
        || proposal.provider.os_version != proposal.host_windows
        || !contract::valid_hash(&proposal.provider.provider.sha256)
    {
        return Err(
            "environment proposal source, workspace, helper or exact environment differs".into(),
        );
    }
    let workspace = HeldRunWorkspace::reopen_bound(&proposal.workspace)?;
    if proposal.plan != plan(&workspace)
        || proposal.rendered_config_sha256
            != aiw_provider_wsb::render_config(&proposal.plan)?.sha256
        || proposal != read_protected::<Proposal>(&workspace, "proposal.json")?
    {
        return Err("environment proposal binding differs".into());
    }
    file.revalidate()?;
    let hash = digest(&serde_json::to_vec(&proposal)?);
    Ok((workspace, proposal, hash))
}
fn stable(before: &Result<Marker>, after: &Result<Marker>) -> bool {
    matches!((before,after),(Ok(left),Ok(right)) if left==right)
}
fn recovery_allowed(dispatch: bool, already_attempted: bool, cleanup_verified: bool) -> bool {
    dispatch && !already_attempted && !cleanup_verified
}

pub fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["--identity"] {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"schemaVersion":SCHEMA,"sourceSha256":source_hash(),"compiledStaticCrt":cfg!(target_feature="crt-static"),"helperSha256":option_env!("AIW_ENVIRONMENT_HELPER_SHA256"),"providerCalls":0,"applicationExecutions":0})
            )?
        );
        return Ok(());
    }
    if !cfg!(target_feature = "crt-static") || std::env::consts::ARCH != "x86_64" {
        return Err("static-CRT x64 research artifact required".into());
    }
    if args == ["--read"] {
        let (workspace, proposal, hash) = load()?;
        let mut records = serde_json::Map::new();
        for name in [
            "approval.json",
            "start-intent.json",
            "dispatch-intent.json",
            "cleanup-observation.json",
            "host-result.json",
            "recovery-intent.json",
            "recovery.json",
        ] {
            if workspace.root_path().join(name).try_exists()? {
                let value = read_protected::<serde_json::Value>(&workspace, name);
                records.insert(name.into(),json!({"record":value.as_ref().ok(),"readError":value.as_ref().err().map(ToString::to_string)}));
            }
        }
        let raw = read_marker(&workspace);
        let observation = raw.as_ref().map(|(marker, _)| marker);
        let retained = read_protected::<serde_json::Value>(&workspace, "host-result.json");
        let approval = read_protected::<String>(&workspace, "approval.json");
        let start = read_protected::<String>(&workspace, "start-intent.json");
        let dispatch = read_protected::<String>(&workspace, "dispatch-intent.json");
        let binding = retained.as_ref().is_ok_and(|record| {
            retained_binding(
                record,
                &hash,
                approval.as_deref().ok(),
                start.as_deref().ok(),
                dispatch.as_deref().ok(),
            )
        });
        let retained_match = match (&observation, &retained) {
            (Ok(current), Ok(record)) if binding => record
                .get("observations")
                .map(|value| serde_json::to_value(current).is_ok_and(|current| current == *value)),
            _ => None,
        };
        print_json(
            &json!({"schemaVersion":SCHEMA,"readOnly":true,"providerCalls":0,"applicationExecutions":0,"planSha256":hash,"proposal":proposal,"records":records,
            "observations":observation.as_ref().ok(),"observationError":raw.as_ref().err().map(ToString::to_string),
            "originalMarkerHex":raw.as_ref().ok().map(|(_,bytes)|hex::encode(bytes)),
            "retainedBindingVerified":binding,"retainedObservationsMatch":retained_match}),
        )?;
        return Ok(());
    }
    let inspect = args == ["--inspect-host"];
    let prepare = args == ["--prepare"];
    if !inspect
        && !prepare
        && (args.len() != 2
            || !matches!(args[0].as_str(), "--approve" | "--start" | "--recover")
            || !contract::valid_hash(&args[1]))
    {
        return Err("closed environment action and exact plan hash required".into());
    }
    let actor = vm_guard()?;
    if inspect {
        let windows = contract::observe_windows();
        let provider = aiw_windows_platform::inspect_windows_sandbox_static();
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"schemaVersion":SCHEMA,"readOnly":true,"sourceSha256":source_hash(),"compiledStaticCrt":true,"actorSid":actor,"workerUuid":VM_UUID,"windows":windows.as_ref().ok(),"windowsError":windows.as_ref().err(),"staticProvider":provider.as_ref().ok(),"staticProviderError":provider.as_ref().err(),"cliProtocol":"unmeasured","providerCalls":0,"applicationExecutions":0})
            )?
        );
        return Ok(());
    }
    helper_hash()?;
    if prepare {
        let (host_windows, provider) = host_identity()?;
        aiw_provider_wsb::render_config(&fixed_plan(&format!(r"{ROOT}\Trial")))?;
        let source = HeldApplicationFile::open_bounded(
            &Path::new(ROOT).join("Inputs").join(HELPER),
            128 * 1024 * 1024,
        )?;
        if source.observation().sha256 != helper_hash()? {
            return Err("environment helper input differs".into());
        }
        let workspace = HeldRunWorkspace::create(Path::new(ROOT), "Trial")?;
        let mut writer = workspace.create_tools_file_new(HELPER)?;
        source.copy_to(writer.as_file_mut())?;
        writer.as_file_mut().sync_all()?;
        source.revalidate()?;
        drop(writer);
        let rendered = aiw_provider_wsb::render_config(&plan(&workspace))?;
        let proposal = Proposal {
            schema_version: SCHEMA.into(),
            workspace: workspace.evidence().clone(),
            plan: plan(&workspace),
            helper_sha256: helper_hash()?.into(),
            helper_size_bytes: source.observation().size_bytes,
            source_sha256: source_hash(),
            host_windows,
            provider,
            rendered_config_sha256: rendered.sha256,
            session_id: SESSION.into(),
            worker_uuid: VM_UUID.into(),
            operator_sid: actor,
        };
        let _tool = verify_tool(&workspace, &proposal)?;
        publish(&workspace, "proposal.json", &proposal)?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"schemaVersion":SCHEMA,"planSha256":digest(&serde_json::to_vec(&proposal)?),"proposal":proposal,"effects":"One fresh offline owned Sandbox observes actual guest Windows, its fixed first-party utility-account token and fixed System32 data-file observations. No installer, MXC DLL, accounts, grants, host/VM security changes or application use. Loader compatibility and isolation remain unmeasured. Review/Approve/Start separate; exact owned stop, no replay."})
            )?
        );
        return Ok(());
    }
    let (workspace, proposal, hash) = load()?;
    if args[1] != hash || proposal.operator_sid != actor {
        return Err("exact plan hash and original actor required".into());
    }
    if args[0] == "--approve" {
        let (windows, provider) = host_identity()?;
        if windows != proposal.host_windows || provider != proposal.provider {
            return Err("host/provider identity changed before approval".into());
        }
        let _tool = verify_tool(&workspace, &proposal)?;
        publish(&workspace, "approval.json", &hash)?;
        println!("Approved {hash}; Start remains separate.");
        return Ok(());
    }
    if read_protected::<String>(&workspace, "approval.json")? != hash {
        return Err("matching approval required".into());
    }
    if args[0] == "--recover" {
        let dispatch = workspace
            .root_path()
            .join("dispatch-intent.json")
            .try_exists()?
            && read_protected::<String>(&workspace, "dispatch-intent.json")? == hash;
        let cleanup = read_protected::<serde_json::Value>(&workspace, "cleanup-observation.json");
        let verified = cleanup.as_ref().is_ok_and(|value| {
            value["schemaVersion"] == SCHEMA
                && value["planSha256"] == hash
                && value["sessionId"] == SESSION
                && value["outerCleanupVerified"] == true
        });
        if read_protected::<String>(&workspace, "start-intent.json")? != hash
            || !recovery_allowed(
                dispatch,
                workspace
                    .root_path()
                    .join("recovery-intent.json")
                    .try_exists()?,
                verified,
            )
        {
            return Err("only unresolved original dispatched probe may recover once".into());
        }
        publish(&workspace, "recovery-intent.json", &hash)?;
        let mut lease = aiw_windows_platform::acquire_windows_sandbox_recovery(
            &proposal.provider.provider.sha256,
            CanonicalSandboxId::parse(SESSION)?,
        )?;
        let result = lease.reconcile_with_timeout(API_TIMEOUT)?;
        let record = json!({"schemaVersion":SCHEMA,"planSha256":hash,"sessionId":SESSION,"outerCleanupVerified":true,"disposition":format!("{:?}",result.disposition),"providerDrifted":result.provider_drifted,"sessionIdsBefore":result.session_ids_before,"sessionIdsAfter":result.session_ids_after,"applicationExecutions":0});
        publish(&workspace, "recovery.json", &record)?;
        println!("{}", serde_json::to_string_pretty(&record)?);
        return Ok(());
    }
    if workspace
        .root_path()
        .join("recovery-intent.json")
        .try_exists()?
    {
        return Err("recovery intent prevents Start".into());
    }
    let (windows, provider) = host_identity()?;
    if windows != proposal.host_windows || provider != proposal.provider {
        return Err("approved host/provider drift; no Start".into());
    }
    let tool = verify_tool(&workspace, &proposal)?;
    exact_inventory(&workspace.output_path(), &[])?;
    publish(&workspace, "start-intent.json", &hash)?;
    let acquired =
        aiw_windows_platform::acquire_windows_sandbox(&proposal.provider.provider.sha256);
    let mut lease = match acquired {
        Ok(lease) => lease,
        Err(error) => {
            let record = json!({"schemaVersion":SCHEMA,"planSha256":hash,"sessionId":SESSION,"startDispatched":false,"outerCleanupVerified":false,"cleanupRequired":false,"executionError":error.to_string(),"applicationExecutions":0});
            println!("{}", serde_json::to_string_pretty(&record)?);
            publish(&workspace, "host-result.json", &record)?;
            return Err(error.into());
        }
    };
    let deadline = Instant::now() + Duration::from_secs(420);
    let mut dispatched = false;
    let execution = (|| -> Result<Marker> {
        if !lease
            .list_with_timeout(Duration::from_secs(30))?
            .session_ids
            .is_empty()
        {
            return Err("provider is already in use; no dispatch".into());
        }
        workspace.revalidate()?;
        tool.0.revalidate()?;
        tool.1.revalidate()?;
        publish(&workspace, "dispatch-intent.json", &hash)?;
        dispatched = true;
        lease.start_with_timeout(
            &CanonicalSandboxId::parse(SESSION)?,
            &proposal.plan,
            API_TIMEOUT,
        )?;
        lease.connect_owned_with_timeout(API_TIMEOUT)?;
        while Instant::now() < deadline {
            // The known final name is observed without following a reparse
            // target. A published but invalid marker is a failure, not a retry.
            match std::fs::symlink_metadata(workspace.output_path().join("RESULT.DAT")) {
                Ok(_) => return completed(&workspace),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("environment observation deadline; final RESULT.DAT was not observed".into())
    })();
    let cleanup = if dispatched {
        Some(lease.stop_owned_with_timeout(API_TIMEOUT))
    } else {
        None
    };
    let cleanup_verified = cleanup.as_ref().is_some_and(|result| result.is_ok());
    let cleanup_record = json!({"schemaVersion":SCHEMA,"planSha256":hash,"sessionId":SESSION,"startDispatched":dispatched,"cleanupRequired":dispatched,"outerCleanupVerified":cleanup_verified,"cleanupError":cleanup.as_ref().and_then(|result|result.as_ref().err()).map(ToString::to_string)});
    let cleanup_publication = publish(&workspace, "cleanup-observation.json", &cleanup_record);
    let after = completed(&workspace);
    let stable = stable(&execution, &after);
    let record = json!({"schemaVersion":SCHEMA,"planSha256":hash,"sessionId":SESSION,"startDispatched":dispatched,"cleanupRequired":dispatched,"outerCleanupVerified":cleanup_verified,"cleanupError":cleanup.as_ref().and_then(|result|result.as_ref().err()).map(ToString::to_string),"cleanupPublicationError":cleanup_publication.as_ref().err().map(ToString::to_string),"executionError":execution.as_ref().err().map(ToString::to_string),"observationsBeforeCleanup":execution.as_ref().ok(),"observations":after.as_ref().ok(),"observationsStable":stable,"observationError":after.as_ref().err().map(ToString::to_string),"applicationExecutions":0,"runtimeLoadsRequested":false,"isolationEnforcement":"unmeasured"});
    println!("{}", serde_json::to_string_pretty(&record)?);
    let publication = publish(&workspace, "host-result.json", &record);
    tool.0.revalidate()?;
    tool.1.revalidate()?;
    execution?;
    if let Some(cleanup) = cleanup {
        cleanup?;
    }
    cleanup_publication?;
    publication?;
    after?;
    if !stable {
        return Err("environment marker identity/bytes changed across cleanup".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_environment_plan_uses_only_readonly_tools_and_one_output() {
        let plan = fixed_plan(&format!(r"{ROOT}\Trial"));
        let rendered = aiw_provider_wsb::render_config(&plan).unwrap();
        assert!(
            rendered
                .xml
                .contains(r"environment_probe.exe --output C:\AIW\EnvironmentOutput\RESULT.DAT")
        );
        assert!(rendered.xml.contains("<Networking>Disable</Networking>"));
        assert!(
            rendered
                .xml
                .contains("<ClipboardRedirection>Disable</ClipboardRedirection>")
        );
        assert_eq!(plan.mappings.len(), 2);
        assert!(plan.probe.request.is_none());
    }
    #[test]
    fn mere_start_intent_or_completed_cleanup_never_authorizes_recovery() {
        assert!(recovery_allowed(true, false, false));
        for values in [
            (false, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            assert!(!recovery_allowed(values.0, values.1, values.2));
        }
    }
    #[test]
    fn source_identity_and_helper_commitment_are_not_interchangeable() {
        let hash = source_hash();
        assert!(contract::valid_hash(&hash));
        assert_ne!(hash, aiw_probe::seven_zip_source_sha256());
        assert!(!contract::valid_hash(&hash.to_uppercase()));
    }
    #[test]
    fn retained_match_cannot_borrow_an_observation_from_another_plan_or_session() {
        let hash = "ab".repeat(32);
        let record = json!({"schemaVersion":SCHEMA,"planSha256":hash,"sessionId":SESSION,"startDispatched":true});
        assert!(retained_binding(
            &record,
            &hash,
            Some(&hash),
            Some(&hash),
            Some(&hash)
        ));
        for field in [
            "schemaVersion",
            "planSha256",
            "sessionId",
            "startDispatched",
        ] {
            let mut changed = record.clone();
            changed[field] = json!("different");
            assert!(
                !retained_binding(&changed, &hash, Some(&hash), Some(&hash), Some(&hash)),
                "field {field}"
            );
        }
        for values in [
            (None, Some(hash.as_str()), Some(hash.as_str())),
            (Some(hash.as_str()), None, Some(hash.as_str())),
            (Some(hash.as_str()), Some(hash.as_str()), None),
        ] {
            assert!(!retained_binding(
                &record, &hash, values.0, values.1, values.2
            ));
        }
        assert!(!retained_binding(
            &record,
            &hash,
            Some("different"),
            Some(&hash),
            Some(&hash)
        ));
    }
}
