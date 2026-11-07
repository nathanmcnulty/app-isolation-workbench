//! Fixed first-party debugger-tree trial. Custody is not control acceptance.
#[path = "tree_verify.rs"]
mod verification;
use super::{
    EXPECTED_GUEST, EXPECTED_HOST, PROVIDER, Result, VM_UUID, aiw_source_hash, digest,
    fixed_os_and_actor, normalized, publish, read_protected, windows_label,
};
use aiw_probe::{WindowsFileIdentity, WorkspaceBindingEvidence};
use aiw_provider_wsb::{GoldenProbe, MappedFolder, MappingPurpose, WindowsSandboxPlan};
use aiw_windows_platform::{CanonicalSandboxId, HeldApplicationFile, HeldRunWorkspace};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::os::windows::fs::MetadataExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};

type ToolHolds = Vec<(
    aiw_windows_platform::BoundWorkspaceFile,
    HeldApplicationFile,
)>;
const ROOT: &str = r"C:\AIW-SevenZip-Tree-Control-20261106-R1";
const SESSION: &str = "4656bd40-c62b-4b5b-8c77-f38942ddde7a";
const SCHEMA: &str = "aiw.dev/research/sevenzip-tree-host-trial/v0alpha1";
const HELPER: &str = "sevenzip_assessment.exe";
const INSTALLER: &str = "7z2605-x64.exe";
const INSTALLER_SHA256: &str = "fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0";
const INSTALLER_SIZE: u64 = 1_663_506;
const MARKER_BOUND: u64 = 1024 * 1024;
const STAGES: [&str; 17] = [
    "owner-00-start",
    "owner-01-context",
    "owner-02-launcher",
    "owner-05-workflow-exit",
    "owner-05-launcher-cleanup",
    "owner-06-final",
    "owner-99-driver-error",
    "tree-baseline",
    "tree-candidate",
    "tree-baseline-binding",
    "tree-candidate-binding",
    "tree-baseline-error",
    "tree-candidate-error",
    "tree-candidate-profile",
    "tree-profile-cleanup",
    "tree-complete",
    "workflow-99-driver-error",
];
const OUTPUT_NAMES: [&str; 19] = [
    "RESULT.DAT",
    "00-start.json",
    "01-context.json",
    "02-launcher.json",
    "05-workflow-exit.json",
    "05-launcher-cleanup.json",
    "06-final.json",
    "99-driver-error.json",
    "07-stage-collection.json",
    "workflow-tree-baseline.json",
    "workflow-tree-candidate.json",
    "workflow-tree-baseline-binding.json",
    "workflow-tree-candidate-binding.json",
    "workflow-tree-baseline-error.json",
    "workflow-tree-candidate-error.json",
    "workflow-tree-candidate-profile.json",
    "workflow-tree-profile-cleanup.json",
    "workflow-tree-complete.json",
    "workflow-99-driver-error.json",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileFact {
    identity: WindowsFileIdentity,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proposal {
    schema_version: String,
    workspace: WorkspaceBindingEvidence,
    plan: WindowsSandboxPlan,
    helper_sha256: String,
    helper_size_bytes: u64,
    installer_sha256: String,
    installer_size_bytes: u64,
    aiw_source_sha256: String,
    expected_host: String,
    expected_guest: String,
    worker_uuid: String,
    rendered_config_sha256: String,
    provider_sha256: String,
    session_id: String,
    operator_sid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuestReport {
    schema_version: String,
    windows: aiw_probe::WindowsVersionObservation,
    observer_token: aiw_token::TokenEvidence,
    driver_completed: bool,
    error: Option<String>,
    first_party_controls_only: bool,
    vendor_installer_executed: bool,
    application_executed: bool,
    stages: BTreeMap<String, serde_json::Value>,
    stage_read_errors: BTreeMap<String, String>,
}

fn helper_hash() -> Result<&'static str> {
    let value = option_env!("AIW_SEVENZIP_TREE_HELPER_SHA256")
        .ok_or("build must enroll independently verified tree helper SHA256")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid fixed tree helper commitment".into());
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
                sandbox_folder: r"C:\AIW\SevenZipOutput".into(),
            },
        ],
        probe: GoldenProbe {
            executable: format!(r"C:\AIW\Tools\{HELPER}"),
            request: None,
            output: r"C:\AIW\SevenZipOutput\RESULT.DAT".into(),
        },
        memory_mb: Some(2048),
    }
}
fn plan(workspace: &HeldRunWorkspace) -> WindowsSandboxPlan {
    fixed_plan(&normalized(workspace.root_path()))
}
fn fact(file: &HeldApplicationFile) -> FileFact {
    let o = file.observation();
    FileFact {
        identity: o.identity.clone(),
        size_bytes: o.size_bytes,
        sha256: o.sha256.clone(),
    }
}
fn stage_installer(workspace: &HeldRunWorkspace) -> Result<()> {
    let source = HeldApplicationFile::open_bounded(
        &Path::new(ROOT).join("Inputs").join(INSTALLER),
        INSTALLER_SIZE,
    )?;
    if source.observation().size_bytes != INSTALLER_SIZE
        || source.observation().sha256 != INSTALLER_SHA256
    {
        return Err("inert official installer pin differs".into());
    }
    let mut writer = workspace.create_tools_file_new(INSTALLER)?;
    source.copy_to(writer.as_file_mut())?;
    writer.as_file_mut().sync_all()?;
    source.revalidate()?;
    Ok(())
}
fn verify_tools(workspace: &HeldRunWorkspace, proposal: &Proposal) -> Result<ToolHolds> {
    let mut names = std::fs::read_dir(workspace.tools_path())?
        .take(3)
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    if names != [INSTALLER, HELPER].map(std::ffi::OsString::from) {
        return Err("exact two tree Tools entries required".into());
    }
    let mut held = vec![];
    for (name, hash, size) in [
        (
            HELPER,
            proposal.helper_sha256.as_str(),
            proposal.helper_size_bytes,
        ),
        (INSTALLER, INSTALLER_SHA256, INSTALLER_SIZE),
    ] {
        let bound = workspace.reopen_tools_file_readonly(name)?;
        let file = HeldApplicationFile::open_bounded(bound.final_path(), 128 * 1024 * 1024)?;
        if file.observation().identity != *bound.identity()
            || file.observation().sha256 != hash
            || file.observation().size_bytes != size
        {
            return Err("tree input identity/hash/size drift".into());
        }
        bound.revalidate()?;
        file.revalidate()?;
        held.push((bound, file));
    }
    Ok(held)
}
fn validate_report(report: &GuestReport) -> Result<()> {
    report.windows.validate()?;
    let token = &report.observer_token;
    if report.schema_version != "aiw.dev/research/sevenzip-tree-result/v0alpha1"
        || windows_label(&report.windows) != EXPECTED_GUEST
        || !token.is_elevated
        || token.is_app_container
        || token.schema_version != aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
        || token.process_id == 0
        || token.token_type != aiw_token::TokenType::Primary
        || token.impersonation_level.is_some()
        || !token.user_sid.starts_with("S-1-5-21-")
        || !token.user_sid.ends_with("-504")
        || !report.first_party_controls_only
        || report.vendor_installer_executed
        || report.application_executed
        || report.driver_completed == report.error.is_some()
        || report
            .error
            .as_ref()
            .is_some_and(|e| e.is_empty() || e.len() > 2048)
    {
        return Err("tree marker fixed envelope differs".into());
    }
    let known = STAGES.into_iter().collect::<BTreeSet<_>>();
    if report.stages.len() + report.stage_read_errors.len() != known.len()
        || report
            .stages
            .keys()
            .any(|k| !known.contains(k.as_str()) || report.stage_read_errors.contains_key(k))
        || report
            .stage_read_errors
            .iter()
            .any(|(k, e)| !known.contains(k.as_str()) || e.is_empty() || e.len() > 2048)
        || report
            .stages
            .values()
            .any(|v| serde_json::to_vec_pretty(v).map_or(true, |b| b.len() > 128 * 1024))
        || serde_json::to_vec_pretty(&report.stages)?.len()
            + serde_json::to_vec_pretty(&report.stage_read_errors)?.len()
            > 768 * 1024
    {
        return Err("tree embedded stage partition/budget differs".into());
    }
    // Missing/refused stages and driverCompleted=false remain valid research
    // observations. No root binding or native-control success is inferred here.
    Ok(())
}
fn exact_output_names(names: &[std::ffi::OsString]) -> bool {
    names.len() <= OUTPUT_NAMES.len()
        && names.iter().any(|n| n == "RESULT.DAT")
        && names
            .iter()
            .all(|n| n.to_str().is_some_and(|s| OUTPUT_NAMES.contains(&s)))
        && names.iter().collect::<BTreeSet<_>>().len() == names.len()
}
fn capture_marker(workspace: &HeldRunWorkspace) -> Result<(FileFact, Vec<u8>, GuestReport)> {
    let entries = std::fs::read_dir(workspace.output_path())?
        .take(OUTPUT_NAMES.len() + 1)
        .collect::<std::io::Result<Vec<_>>>()?;
    let names = entries.iter().map(|e| e.file_name()).collect::<Vec<_>>();
    if !exact_output_names(&names) {
        return Err("tree output closed namespace differs".into());
    }
    for entry in entries {
        // Diagnostic JSON names are never opened/adopted. Metadata is no-follow;
        // a directory/reparse entry cannot hide behind an allowed filename.
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
            return Err("tree diagnostic namespace contains nonordinary entry".into());
        }
    }
    let bound = workspace.reopen_output_file_readonly("RESULT.DAT")?;
    let file = HeldApplicationFile::open_bounded(bound.final_path(), MARKER_BOUND)?;
    let bytes = file.read_bounded(MARKER_BOUND)?;
    if file.observation().identity != *bound.identity() {
        return Err("tree strict marker identity differs".into());
    }
    let report: GuestReport = serde_json::from_slice(&bytes)?;
    validate_report(&report)?;
    let observed = fact(&file);
    bound.revalidate()?;
    file.revalidate()?;
    workspace.revalidate()?;
    Ok((observed, bytes, report))
}
fn completed(workspace: &HeldRunWorkspace, proposal: &Proposal) -> Result<serde_json::Value> {
    let (marker, bytes, report) = capture_marker(workspace)?;
    let verified = verification::verify(
        &report.stages,
        report.driver_completed,
        &proposal.helper_sha256,
        proposal.helper_size_bytes,
    );
    // Root host records stay small enough for read_protected's one-MiB bound.
    // Original marker bytes remain in output; Read exports them separately.
    Ok(
        json!({"markerSha256":digest(&bytes),"markerFact":marker,"driverCompleted":report.driver_completed,
        "driverError":report.error,"retainedStageKeys":report.stages.keys().collect::<Vec<_>>(),
        "stageReadErrors":report.stage_read_errors,"strictMarkerCustodyAccepted":true,
        "controlVerification":verified.as_ref().ok(),"controlVerificationError":verified.as_ref().err(),
        "nativeControlEvidence":if verified.is_ok() {"fixed positive control facts verified; native chain-reset negative still pending"} else {"unverified"},
        "applicationExecutionRequested":false,"vendorRuntimeLoadsRequested":false}),
    )
}
fn checked_marker_hex(actual: &FileFact, bytes: &[u8], expected: &FileFact) -> Result<String> {
    if actual != expected
        || digest(bytes) != expected.sha256
        || bytes.len() as u64 != expected.size_bytes
    {
        return Err("retained tree raw marker identity, size or hash differs".into());
    }
    Ok(hex::encode(bytes))
}
fn marker_hex(workspace: &HeldRunWorkspace, expected: &FileFact) -> Result<String> {
    let (actual, bytes, _) = capture_marker(workspace)?;
    checked_marker_hex(&actual, &bytes, expected)
}
fn stable_observations(
    before: &Result<serde_json::Value>,
    after: &Result<serde_json::Value>,
) -> bool {
    matches!((before,after),(Ok(a),Ok(b)) if a==b)
}
fn recovery_allowed(record: Option<&serde_json::Value>, hash: &str, recovered: bool) -> bool {
    !recovered
        && record.is_none_or(|v| {
            v["schemaVersion"] == SCHEMA
                && v["treeControlOnly"] == true
                && v["planSha256"] == hash
                && v["sessionId"] == SESSION
                && v["outerCleanupVerified"] == false
        })
}
pub fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let actor = fixed_os_and_actor()?;
    helper_hash()?;
    if args == ["--prepare"] {
        // Refuse an unsupported fixed renderer contract before creating any
        // workspace objects. Actual bound paths are rendered again below.
        aiw_provider_wsb::render_config(&fixed_plan(&format!(r"{ROOT}\Trial")))?;
        let workspace = HeldRunWorkspace::create(Path::new(ROOT), "Trial")?;
        let source = HeldApplicationFile::open_bounded(
            &Path::new(ROOT).join("Inputs").join(HELPER),
            128 * 1024 * 1024,
        )?;
        if source.observation().sha256 != helper_hash()? || source.observation().size_bytes == 0 {
            return Err("tree input differs from build commitment".into());
        }
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
            installer_sha256: INSTALLER_SHA256.into(),
            installer_size_bytes: INSTALLER_SIZE,
            aiw_source_sha256: aiw_source_hash(),
            expected_host: EXPECTED_HOST.into(),
            expected_guest: EXPECTED_GUEST.into(),
            worker_uuid: VM_UUID.into(),
            rendered_config_sha256: rendered.sha256.clone(),
            provider_sha256: PROVIDER.into(),
            session_id: SESSION.into(),
            operator_sid: actor,
        };
        stage_installer(&workspace)?;
        let _tools = verify_tools(&workspace, &proposal)?;
        publish(&workspace, "proposal.json", &proposal)?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"treeControlOnly":true,"planSha256":digest(&serde_json::to_vec(&proposal)?),"proposal":proposal,"rendered":rendered,
            "effects":"One fresh offline owned Sandbox runs only pinned first-party ordinary/classic AppContainer three-process tree controls. The pinned vendor installer is transported inertly and never executed; no vendor application or MXC DLL. Fresh guest-local standard account, owned test-path/profile grants, debugger trees and owned watchdog/jobs; exact owned outer cleanup, no replay, no host or VM security changes. Marker custody is not native control acceptance."})
            )?
        );
        return Ok(());
    }
    let read_only = args == ["--read"];
    if !read_only
        && (args.len() != 2 || !matches!(args[0].as_str(), "--approve" | "--start" | "--recover"))
    {
        return Err("expected closed tree action/hash".into());
    }
    let held = HeldApplicationFile::open_bounded(
        &Path::new(ROOT).join(r"Trial\proposal.json"),
        1024 * 1024,
    )?;
    let proposal: Proposal = serde_json::from_slice(&held.read_bounded(1024 * 1024)?)?;
    let workspace = HeldRunWorkspace::reopen_bound(&proposal.workspace)?;
    held.revalidate()?;
    if normalized(workspace.root_path()) != format!(r"{ROOT}\Trial")
        || proposal != read_protected::<Proposal>(&workspace, "proposal.json")?
        || proposal.schema_version != SCHEMA
        || proposal.plan != plan(&workspace)
        || proposal.helper_sha256 != helper_hash()?
        || proposal.helper_size_bytes == 0
        || proposal.helper_size_bytes > 128 * 1024 * 1024
        || proposal.aiw_source_sha256 != aiw_source_hash()
        || proposal.expected_host != EXPECTED_HOST
        || proposal.expected_guest != EXPECTED_GUEST
        || proposal.worker_uuid != VM_UUID
        || proposal.rendered_config_sha256
            != aiw_provider_wsb::render_config(&proposal.plan)?.sha256
        || proposal.provider_sha256 != PROVIDER
        || proposal.session_id != SESSION
        || proposal.operator_sid != actor
        || proposal.installer_sha256 != INSTALLER_SHA256
        || proposal.installer_size_bytes != INSTALLER_SIZE
    {
        return Err("tree proposal/source/environment drift".into());
    }
    let hash = digest(&serde_json::to_vec(&proposal)?);
    if read_only {
        let mut records = serde_json::Map::new();
        for leaf in [
            "approval.json",
            "start-intent.json",
            "cleanup-observation.json",
            "host-result.json",
            "recovery-intent.json",
            "recovery.json",
        ] {
            if workspace.root_path().join(leaf).try_exists()? {
                records.insert(
                    leaf.into(),
                    read_protected::<serde_json::Value>(&workspace, leaf)?,
                );
            }
        }
        let observation = completed(&workspace, &proposal);
        let accepted_fact = records
            .get("host-result.json")
            .and_then(|r| r["observations"].get("markerFact"));
        let raw: Result<String> = match accepted_fact {
            Some(fact) => serde_json::from_value::<FileFact>(fact.clone())
                .map_err(Into::into)
                .and_then(|fact| marker_hex(&workspace, &fact)),
            None => Err("no previously accepted marker identity; raw read unverified".into()),
        };
        let retained_match = records
            .get("host-result.json")
            .and_then(|record| record.get("observations"))
            .filter(|value| !value.is_null())
            .map(|retained| {
                raw.is_ok()
                    && observation
                        .as_ref()
                        .is_ok_and(|current| current == retained)
            });
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"schemaVersion":SCHEMA,"treeControlOnly":true,"readOnly":true,"providerCalls":0,
            "planSha256":hash,"proposal":proposal,"hostRecords":records,"observations":observation.as_ref().ok(),"retainedObservationsMatch":retained_match,"guestOutputHex":raw.as_ref().ok(),"guestOutputHexError":raw.as_ref().err().map(ToString::to_string),"nativeControlEvidence":"unverified","observationError":observation.as_ref().err().map(ToString::to_string)})
            )?
        );
        return Ok(());
    }
    if args[1] != hash {
        return Err("exact tree plan hash required".into());
    }
    if args[0] == "--approve" {
        let _tool = verify_tools(&workspace, &proposal)?;
        publish(&workspace, "approval.json", &hash)?;
        println!("Approved tree control {hash}; Start remains separate.");
        return Ok(());
    }
    if read_protected::<String>(&workspace, "approval.json")? != hash {
        return Err("matching tree approval required".into());
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
            return Err("only unresolved original tree trial can recover once".into());
        }
        publish(&workspace, "recovery-intent.json", &hash)?;
        let mut lease = aiw_windows_platform::acquire_windows_sandbox_recovery(PROVIDER, id)?;
        let result = lease.reconcile()?;
        let record = json!({"schemaVersion":SCHEMA,"treeControlOnly":true,"planSha256":hash,"sessionId":result.session_id,"outerCleanupVerified":true,
            "disposition":format!("{:?}",result.disposition),"providerDrifted":result.provider_drifted,"sessionIdsBefore":result.session_ids_before,"sessionIdsAfter":result.session_ids_after});
        publish(&workspace, "recovery.json", &record)?;
        println!("{}", serde_json::to_string_pretty(&record)?);
        return Ok(());
    }
    let tools = verify_tools(&workspace, &proposal)?;
    if workspace.root_path().join("recovery.json").try_exists()? {
        return Err("recovered tree trial cannot Start".into());
    }
    let names = std::fs::read_dir(workspace.output_path())?
        .take(2)
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if !names.is_empty() {
        return Err("fresh tree output differs".into());
    }
    let mut lease = aiw_windows_platform::acquire_windows_sandbox(PROVIDER)?;
    if !lease.list()?.session_ids.is_empty() {
        return Err("worker provider is in use".into());
    }
    publish(&workspace, "start-intent.json", &hash)?;
    let execution = (|| -> Result<serde_json::Value> {
        workspace.revalidate()?;
        for (bound, file) in &tools {
            bound.revalidate()?;
            file.revalidate()?;
        }
        lease.start(&id, &proposal.plan)?;
        lease.connect_owned()?;
        let deadline = Instant::now() + Duration::from_secs(300);
        while Instant::now() < deadline {
            if workspace.output_path().join("RESULT.DAT").try_exists()? {
                return completed(&workspace, &proposal);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("tree control deadline; preserve pending/partial output".into())
    })();
    let cleanup = lease.stop_owned();
    let cleanup_verified = cleanup.is_ok();
    let cleanup_record = json!({"schemaVersion":SCHEMA,"treeControlOnly":true,"planSha256":hash,"sessionId":SESSION,"outerCleanupVerified":cleanup_verified,"cleanupError":cleanup.as_ref().err().map(ToString::to_string)});
    publish(&workspace, "cleanup-observation.json", &cleanup_record)?;
    let after = completed(&workspace, &proposal);
    let observations_stable = stable_observations(&execution, &after);
    let record = json!({"schemaVersion":SCHEMA,"treeControlOnly":true,"planSha256":hash,"sessionId":SESSION,"outerCleanupVerified":cleanup_verified,
        "cleanupError":cleanup.as_ref().err().map(ToString::to_string),"executionError":execution.as_ref().err().map(ToString::to_string),
        "observations":after.as_ref().ok(),"observationsBeforeCleanup":execution.as_ref().ok(),"observationsStable":observations_stable,"observationError":after.as_ref().err().map(ToString::to_string),"applicationExecutionRequested":false,"vendorRuntimeLoadsRequested":false});
    publish(&workspace, "host-result.json", &record)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    execution?;
    cleanup?;
    after?;
    if !observations_stable {
        return Err("tree observations changed across cleanup".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_raw_export_requires_original_identity_even_when_bytes_match() {
        let bytes = b"retained marker";
        let expected = FileFact {
            identity: WindowsFileIdentity {
                final_path: r"C:\owned\output\RESULT.DAT".into(),
                volume_serial_number: "1".repeat(16),
                file_id: "2".repeat(32),
            },
            size_bytes: bytes.len() as u64,
            sha256: digest(bytes),
        };
        assert!(checked_marker_hex(&expected, bytes, &expected).is_ok());
        let mut replacement = expected.clone();
        replacement.identity.file_id = "3".repeat(32);
        assert!(checked_marker_hex(&replacement, bytes, &expected).is_err());
        assert!(checked_marker_hex(&expected, b"different marker", &expected).is_err());
    }

    fn marker_fixture() -> serde_json::Value {
        let errors = STAGES
            .into_iter()
            .map(|key| (key.to_owned(), "not reached or capture refused".to_owned()))
            .collect::<BTreeMap<_, _>>();
        json!({"schemaVersion":"aiw.dev/research/sevenzip-tree-result/v0alpha1",
            "windows":{"major":10,"minor":0,"build":26100,"revision":9711,"observerArchitecture":"x86_64"},
            "observerToken":{"schemaVersion":aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,"processId":42,
                "tokenType":"primary","isAppContainer":false,"userSid":"S-1-5-21-1-2-3-504",
                "integrity":{"sid":"S-1-16-12288","rid":12288,"level":"high"},"elevationType":"full",
                "isElevated":true,"capabilities":[],"restrictedSidCount":0},
            "driverCompleted":false,"error":"owned worker failed after partial observations",
            "firstPartyControlsOnly":true,"vendorInstallerExecuted":false,"applicationExecuted":false,
            "stages":{},"stageReadErrors":errors})
    }
    fn valid(value: serde_json::Value) -> bool {
        serde_json::from_value::<GuestReport>(value)
            .is_ok_and(|report| validate_report(&report).is_ok())
    }

    #[test]
    fn fixed_tree_plan_has_only_two_mappings_and_no_caller_command() {
        let plan = fixed_plan(&format!(r"{ROOT}\Trial"));
        assert_eq!(plan.mappings.len(), 2);
        assert_eq!(
            plan.probe.executable,
            r"C:\AIW\Tools\sevenzip_assessment.exe"
        );
        assert_eq!(plan.probe.output, r"C:\AIW\SevenZipOutput\RESULT.DAT");
        assert!(plan.probe.request.is_none());
        // Parent enables the exact default-off publication pair before wiring.
        let rendered = aiw_provider_wsb::render_config(&plan).unwrap();
        assert!(
            rendered
                .xml
                .contains(r"sevenzip_assessment.exe --output C:\AIW\SevenZipOutput\RESULT.DAT")
        );
        assert!(rendered.xml.contains("<Networking>Disable</Networking>"));
        assert!(rendered.xml.contains("<ReadOnly>true</ReadOnly>"));
        assert!(rendered.xml.contains("<ReadOnly>false</ReadOnly>"));
        assert!(!rendered.xml.contains("--tree-workflow"));
    }

    #[test]
    fn partial_markers_are_retained_without_control_acceptance() {
        let mut marker = marker_fixture();
        assert!(valid(marker.clone()));
        marker["stageReadErrors"]
            .as_object_mut()
            .unwrap()
            .remove("tree-baseline");
        marker["stages"]["tree-baseline"] = json!({"partial":true,"rootProcessId":42});
        assert!(valid(marker.clone()));
        let report: GuestReport = serde_json::from_value(marker).unwrap();
        assert!(!report.driver_completed);
        assert_eq!(report.stages["tree-baseline"]["rootProcessId"], 42);
    }

    #[test]
    fn marker_partition_identity_authority_and_byte_limits_are_closed() {
        let fixture = marker_fixture();
        for (key, value) in [
            ("driverCompleted", json!(true)),
            ("firstPartyControlsOnly", json!(false)),
            ("vendorInstallerExecuted", json!(true)),
            ("applicationExecuted", json!(true)),
            ("unexpected", json!(true)),
        ] {
            let mut invalid = fixture.clone();
            invalid[key] = value;
            assert!(!valid(invalid), "{key}");
        }
        let mut wrong_actor = fixture.clone();
        wrong_actor["observerToken"]["userSid"] = json!("S-1-5-21-1-2-3-1000");
        assert!(!valid(wrong_actor));
        let mut unknown = fixture.clone();
        unknown["stages"]["arbitrary"] = json!({});
        assert!(!valid(unknown));
        let mut overlap = fixture.clone();
        overlap["stages"]["tree-baseline"] = json!({});
        assert!(!valid(overlap));
        let mut missing = fixture.clone();
        missing["stageReadErrors"]
            .as_object_mut()
            .unwrap()
            .remove("tree-baseline");
        assert!(!valid(missing));
        let mut escaped = fixture.clone();
        escaped["stageReadErrors"]
            .as_object_mut()
            .unwrap()
            .remove("tree-baseline");
        escaped["stages"]["tree-baseline"] = json!("\0".repeat(22000));
        assert!(!valid(escaped));
        let mut unicode = fixture;
        unicode["stageReadErrors"]["tree-baseline"] = json!("😀".repeat(513));
        assert!(!valid(unicode));
    }

    #[test]
    fn output_names_refuse_pending_unknown_wrong_case_and_duplicates() {
        let names = vec![
            std::ffi::OsString::from("RESULT.DAT"),
            "workflow-tree-baseline.json".into(),
        ];
        assert!(exact_output_names(&names));
        for name in ["RESULT.TMP", "result.dat", "arbitrary.json"] {
            assert!(!exact_output_names(&["RESULT.DAT".into(), name.into()]));
        }
        assert!(!exact_output_names(&[
            "RESULT.DAT".into(),
            "RESULT.DAT".into()
        ]));
        assert!(!exact_output_names(&[]));
    }

    #[test]
    fn recovery_and_stability_are_bound_to_original_unresolved_transaction() {
        let hash = "a".repeat(64);
        let mut record = json!({"schemaVersion":SCHEMA,"treeControlOnly":true,"planSha256":hash,"sessionId":SESSION,"outerCleanupVerified":false});
        assert!(recovery_allowed(Some(&record), &hash, false));
        assert!(!recovery_allowed(Some(&record), &hash, true));
        assert!(!recovery_allowed(Some(&record), "foreign", false));
        record["outerCleanupVerified"] = json!(true);
        assert!(!recovery_allowed(Some(&record), &hash, false));
        record["outerCleanupVerified"] = json!(false);
        record["sessionId"] = json!("foreign");
        assert!(!recovery_allowed(Some(&record), &hash, false));
        let first = json!({"markerSha256":"a".repeat(64),"markerFact":{"identity":"original"}});
        assert!(stable_observations(&Ok(first.clone()), &Ok(first.clone())));
        let changed = json!({"markerSha256":"a".repeat(64),"markerFact":{"identity":"replaced"}});
        assert!(!stable_observations(&Ok(first), &Ok(changed)));
    }
}
