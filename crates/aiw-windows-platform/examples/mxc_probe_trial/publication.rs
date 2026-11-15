//! Closed first-party mapped-publication control. No vendor/runtime dispatch.
use super::{
    EXPECTED_GUEST, EXPECTED_HOST, PROVIDER, Result, VM_UUID, aiw_source_hash, digest,
    fixed_os_and_actor, normalized, publish, read_protected, windows_label,
};
use aiw_probe::{WindowsFileIdentity, WorkspaceBindingEvidence};
use aiw_provider_wsb::{GoldenProbe, MappedFolder, MappingPurpose, WindowsSandboxPlan};
use aiw_windows_platform::research_publication as control;
use aiw_windows_platform::{CanonicalSandboxId, HeldApplicationFile, HeldRunWorkspace};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::Write,
    path::Path,
    time::{Duration, Instant},
};

const ROOT: &str = r"C:\AIW-Publication-Control-20261106-R2";
const SESSION: &str = "5e622f23-656f-42fa-a6ae-57c48542a54d";
const SCHEMA: &str = "aiw.dev/research/publication-host-trial/v0alpha1";
const HELPER: &str = "publication_control_guest.exe";

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
    occupied_before: FileFact,
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
    legacy_published: bool,
    occupied_move_rejected: bool,
    occupied_move_win32_code: Option<u32>,
    occupied_unchanged: bool,
    pending_retained: bool,
    partial_final_absent: bool,
    requested_application_execution: bool,
    enforcement: String,
}

fn helper_hash() -> Result<&'static str> {
    let value = option_env!("AIW_PUBLICATION_CONTROL_HELPER_SHA256")
        .ok_or("build must enroll the independently verified publication helper")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid publication helper commitment".into());
    }
    Ok(value)
}

fn plan(workspace: &HeldRunWorkspace) -> WindowsSandboxPlan {
    fixed_plan(&normalized(workspace.root_path()))
}

fn fixed_plan(workspace_root: &str) -> WindowsSandboxPlan {
    WindowsSandboxPlan {
        schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.into(),
        workspace_root: workspace_root.into(),
        mappings: vec![
            MappedFolder {
                purpose: MappingPurpose::Tools,
                host_folder: format!(r"{workspace_root}\tools"),
                sandbox_folder: r"C:\AIW\Tools".into(),
            },
            MappedFolder {
                purpose: MappingPurpose::Output,
                host_folder: format!(r"{workspace_root}\output"),
                sandbox_folder: control::CONTROL_OUTPUT.into(),
            },
        ],
        probe: GoldenProbe {
            executable: format!(r"C:\AIW\Tools\{HELPER}"),
            request: None,
            output: control::CONTROL_RESULT.into(),
        },
        memory_mb: Some(2048),
    }
}

fn fact(file: &HeldApplicationFile) -> FileFact {
    FileFact {
        identity: file.observation().identity.clone(),
        size_bytes: file.observation().size_bytes,
        sha256: file.observation().sha256.clone(),
    }
}

fn read_fact(workspace: &HeldRunWorkspace, leaf: &str, bytes: &[u8]) -> Result<FileFact> {
    let bound = workspace.reopen_output_file_readonly(leaf)?;
    let file = HeldApplicationFile::open_bounded(bound.final_path(), 65536)?;
    if file.observation().identity != *bound.identity() || file.read_bounded(65536)? != bytes {
        return Err("publication artifact identity/content differs".into());
    }
    let observed = fact(&file);
    bound.revalidate()?;
    file.revalidate()?;
    Ok(observed)
}

fn verify_tool(
    workspace: &HeldRunWorkspace,
    proposal: &Proposal,
) -> Result<(
    aiw_windows_platform::BoundWorkspaceFile,
    HeldApplicationFile,
)> {
    let names = std::fs::read_dir(workspace.tools_path())?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if names != [std::ffi::OsString::from(HELPER)] {
        return Err("publication Tools inventory differs".into());
    }
    let bound = workspace.reopen_tools_file_readonly(HELPER)?;
    let file = HeldApplicationFile::open_bounded(bound.final_path(), 128 * 1024 * 1024)?;
    if file.observation().identity != *bound.identity()
        || file.observation().sha256 != proposal.helper_sha256
        || file.observation().size_bytes != proposal.helper_size_bytes
    {
        return Err("publication helper drift".into());
    }
    bound.revalidate()?;
    file.revalidate()?;
    Ok((bound, file))
}

fn validate_report(report: &GuestReport) -> Result<()> {
    report.windows.validate()?;
    if report.schema_version != control::CONTROL_SCHEMA
        || windows_label(&report.windows) != EXPECTED_GUEST
        || !report.observer_token.is_elevated
        || report.observer_token.is_app_container
        || !report.legacy_published
        || !report.occupied_move_rejected
        || !report.occupied_unchanged
        || !matches!(report.occupied_move_win32_code, Some(80 | 183))
        || !report.pending_retained
        || !report.partial_final_absent
        || report.requested_application_execution
        || report.enforcement != "unmeasured"
    {
        return Err("publication control report differs from closed contract".into());
    }
    Ok(())
}

fn exact_final_inventory(mut names: Vec<std::ffi::OsString>) -> bool {
    names.sort();
    names
        == [
            "OCCUPY.DAT",
            "OCCUPY.TMP",
            "PARTIAL.TMP",
            "RESULT.DAT",
            "legacy.json",
        ]
        .map(std::ffi::OsString::from)
}

fn stable_observations(
    before: &Result<serde_json::Value>,
    after: &Result<serde_json::Value>,
) -> bool {
    matches!((before, after), (Ok(a), Ok(b)) if a == b)
}

fn completed(workspace: &HeldRunWorkspace, proposal: &Proposal) -> Result<serde_json::Value> {
    // Enumerating names does not follow a dangling reparse entry. Unexpected
    // output is refused without opening a path nominated by that output.
    let names = std::fs::read_dir(workspace.output_path())?
        .take(16)
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if !exact_final_inventory(names) {
        return Err("publication output namespace differs".into());
    }
    let bound = workspace.reopen_output_file_readonly("RESULT.DAT")?;
    let file = HeldApplicationFile::open_bounded(bound.final_path(), 65536)?;
    let bytes = file.read_bounded(65536)?;
    if file.observation().identity != *bound.identity() {
        return Err("control marker identity differs".into());
    }
    let report: GuestReport = serde_json::from_slice(&bytes)?;
    validate_report(&report)?;
    let occupied = read_fact(workspace, "OCCUPY.DAT", control::OCCUPIED_BYTES)?;
    if occupied != proposal.occupied_before {
        return Err("occupied destination identity or bytes changed".into());
    }
    let pending = read_fact(workspace, "OCCUPY.TMP", control::PENDING_BYTES)?;
    let partial = read_fact(workspace, "PARTIAL.TMP", control::PARTIAL_BYTES)?;
    // The old long-name protocol must remain a strict custody refusal. Do not
    // clear/adopt this file or use a less strict path as an accepted completion.
    let legacy =
        HeldApplicationFile::open_bounded(&workspace.output_path().join("legacy.json"), 65536)?;
    if legacy.read_bounded(65536)? != control::LEGACY_BYTES {
        return Err("legacy control bytes differ".into());
    }
    let legacy_error = workspace
        .reopen_output_file_readonly("legacy.json")
        .err()
        .ok_or("legacy alias unexpectedly accepted; preserve observations")?
        .to_string();
    if !legacy_error.contains("case drift or a short-name alias") {
        return Err("legacy refusal was not an exact-entry refusal".into());
    }
    let legacy_fact = fact(&legacy);
    legacy.revalidate()?;
    bound.revalidate()?;
    file.revalidate()?;
    workspace.revalidate()?;
    Ok(
        json!({"markerSha256":digest(&bytes),"markerFact":fact(&file),"guestReport":serde_json::from_slice::<serde_json::Value>(&bytes)?,
        "occupiedBefore":proposal.occupied_before,"occupiedAfter":occupied,"pending":pending,"partial":partial,
        "legacyDiagnosticOnly":legacy_fact,"legacyStrictRefusal":legacy_error,"partialFinalAbsent":true,"pendingMarkerAbsent":true,
        "strictMarkerAndArtifactsAccepted":true,"applicationExecutionRequested":false,"runtimeLoadsRequested":false,"enforcement":"unmeasured"}),
    )
}

fn recovery_allowed(record: Option<&serde_json::Value>, hash: &str, recovered: bool) -> bool {
    !recovered
        && record.is_none_or(|v| {
            v["schemaVersion"] == SCHEMA
                && v["publicationControlOnly"] == true
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
        if source.observation().sha256 != helper_hash()? {
            return Err("publication input differs from build commitment".into());
        }
        let mut writer = workspace.create_tools_file_new(HELPER)?;
        source.copy_to(writer.as_file_mut())?;
        writer.as_file_mut().sync_all()?;
        source.revalidate()?;
        drop(writer);
        let mut occupied = workspace.create_output_file_new("OCCUPY.DAT")?;
        occupied.as_file_mut().write_all(control::OCCUPIED_BYTES)?;
        occupied.as_file_mut().sync_all()?;
        drop(occupied);
        let rendered = aiw_provider_wsb::render_config(&plan(&workspace))?;
        let proposal = Proposal {
            schema_version: SCHEMA.into(),
            workspace: workspace.evidence().clone(),
            plan: plan(&workspace),
            helper_sha256: helper_hash()?.into(),
            helper_size_bytes: source.observation().size_bytes,
            occupied_before: read_fact(&workspace, "OCCUPY.DAT", control::OCCUPIED_BYTES)?,
            aiw_source_sha256: aiw_source_hash(),
            expected_host: EXPECTED_HOST.into(),
            expected_guest: EXPECTED_GUEST.into(),
            worker_uuid: VM_UUID.into(),
            rendered_config_sha256: rendered.sha256.clone(),
            provider_sha256: PROVIDER.into(),
            session_id: SESSION.into(),
            operator_sid: actor,
        };
        let _tool = verify_tool(&workspace, &proposal)?;
        publish(&workspace, "proposal.json", &proposal)?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"publicationControlOnly":true,"planSha256":digest(&serde_json::to_vec(&proposal)?),"proposal":proposal,"rendered":rendered,
            "effects":"One fresh offline owned Sandbox runs only the pinned first-party publication helper. It reproduces the legacy alias and tests uppercase atomic publication, no-overwrite and incomplete output against fixed owned test data. No MXC DLL, account creation, application, host security or VM setting changes. Exact owned stop; no replay."})
            )?
        );
        return Ok(());
    }
    let read_only = args == ["--read"];
    if !read_only
        && (args.len() != 2 || !matches!(args[0].as_str(), "--approve" | "--start" | "--recover"))
    {
        return Err("expected closed publication action/hash".into());
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
        || proposal.occupied_before.sha256 != digest(control::OCCUPIED_BYTES)
        || proposal.occupied_before.size_bytes != control::OCCUPIED_BYTES.len() as u64
    {
        return Err("publication proposal/source/environment drift".into());
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
        let retained_match = records
            .get("host-result.json")
            .and_then(|record| record.get("observations"))
            .filter(|value| !value.is_null())
            .map(|retained| {
                observation
                    .as_ref()
                    .is_ok_and(|current| current == retained)
            });
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"schemaVersion":SCHEMA,"publicationControlOnly":true,"readOnly":true,"providerCalls":0,
            "planSha256":hash,"proposal":proposal,"hostRecords":records,"observations":observation.as_ref().ok(),"retainedObservationsMatch":retained_match,"observationError":observation.as_ref().err().map(ToString::to_string)})
            )?
        );
        return Ok(());
    }
    if args[1] != hash {
        return Err("exact publication plan hash required".into());
    }
    if args[0] == "--approve" {
        let _tool = verify_tool(&workspace, &proposal)?;
        publish(&workspace, "approval.json", &hash)?;
        println!("Approved publication control {hash}; Start remains separate.");
        return Ok(());
    }
    if read_protected::<String>(&workspace, "approval.json")? != hash {
        return Err("matching publication approval required".into());
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
            return Err("only unresolved original publication trial can recover once".into());
        }
        publish(&workspace, "recovery-intent.json", &hash)?;
        let mut lease = aiw_windows_platform::acquire_windows_sandbox_recovery(PROVIDER, id)?;
        let result = lease.reconcile()?;
        let record = json!({"schemaVersion":SCHEMA,"publicationControlOnly":true,"planSha256":hash,"sessionId":result.session_id,"outerCleanupVerified":true,
            "disposition":format!("{:?}",result.disposition),"providerDrifted":result.provider_drifted,"sessionIdsBefore":result.session_ids_before,"sessionIdsAfter":result.session_ids_after});
        publish(&workspace, "recovery.json", &record)?;
        println!("{}", serde_json::to_string_pretty(&record)?);
        return Ok(());
    }
    let tool = verify_tool(&workspace, &proposal)?;
    if workspace.root_path().join("recovery.json").try_exists()? {
        return Err("recovered publication trial cannot Start".into());
    }
    let names = std::fs::read_dir(workspace.output_path())?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if names != [std::ffi::OsString::from("OCCUPY.DAT")]
        || read_fact(&workspace, "OCCUPY.DAT", control::OCCUPIED_BYTES)? != proposal.occupied_before
    {
        return Err("fresh publication output differs".into());
    }
    // read_fact released the occupied handle: sharing denial must not be the
    // reason the guest's no-replace move refuses an existing destination.
    let mut lease = aiw_windows_platform::acquire_windows_sandbox(PROVIDER)?;
    if !lease.list()?.session_ids.is_empty() {
        return Err("worker provider is in use".into());
    }
    publish(&workspace, "start-intent.json", &hash)?;
    let execution = (|| -> Result<serde_json::Value> {
        workspace.revalidate()?;
        tool.0.revalidate()?;
        tool.1.revalidate()?;
        lease.start(&id, &proposal.plan)?;
        lease.connect_owned()?;
        let deadline = Instant::now() + Duration::from_secs(300);
        while Instant::now() < deadline {
            if workspace.output_path().join("RESULT.DAT").try_exists()? {
                return completed(&workspace, &proposal);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("publication control deadline; preserve pending/partial output".into())
    })();
    let cleanup = lease.stop_owned();
    let cleanup_verified = cleanup.is_ok();
    let cleanup_record = json!({"schemaVersion":SCHEMA,"publicationControlOnly":true,"planSha256":hash,"sessionId":SESSION,"outerCleanupVerified":cleanup_verified,"cleanupError":cleanup.as_ref().err().map(ToString::to_string)});
    publish(&workspace, "cleanup-observation.json", &cleanup_record)?;
    let after = completed(&workspace, &proposal);
    let observations_stable = stable_observations(&execution, &after);
    let record = json!({"schemaVersion":SCHEMA,"publicationControlOnly":true,"planSha256":hash,"sessionId":SESSION,"outerCleanupVerified":cleanup_verified,
        "cleanupError":cleanup.as_ref().err().map(ToString::to_string),"executionError":execution.as_ref().err().map(ToString::to_string),
        "observations":after.as_ref().ok(),"observationsBeforeCleanup":execution.as_ref().ok(),"observationsStable":observations_stable,"observationError":after.as_ref().err().map(ToString::to_string),"applicationExecutionRequested":false,"runtimeLoadsRequested":false});
    publish(&workspace, "host-result.json", &record)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    execution?;
    cleanup?;
    after?;
    if !observations_stable {
        return Err("publication observations changed across cleanup".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_publication_plan_renders_before_any_workspace_or_provider_effect() {
        let rendered =
            aiw_provider_wsb::render_config(&fixed_plan(&format!(r"{ROOT}\Trial"))).unwrap();
        assert!(rendered.xml.contains(
            r"publication_control_guest.exe --output C:\AIW\PublicationOutput\RESULT.DAT"
        ));
        assert!(rendered.xml.contains("<Networking>Disable</Networking>"));
    }
    fn report_fixture() -> serde_json::Value {
        json!({"schemaVersion":control::CONTROL_SCHEMA,
            "windows":{"major":10,"minor":0,"build":26100,"revision":9711,"observerArchitecture":"x86_64"},
            "observerToken":{"schemaVersion":"aiw.dev/token-evidence/v0alpha1","processId":42,
                "tokenType":"primary","isAppContainer":false,"userSid":"S-1-5-21-1-2-3-1000",
                "integrity":{"sid":"S-1-16-12288","rid":12288,"level":"high"},
                "elevationType":"full","isElevated":true,"capabilities":[],"restrictedSidCount":0},
            "legacyPublished":true,"occupiedMoveRejected":true,"occupiedMoveWin32Code":183,
            "occupiedUnchanged":true,"pendingRetained":true,"partialFinalAbsent":true,
            "requestedApplicationExecution":false,"enforcement":"unmeasured"})
    }

    #[test]
    fn publication_report_rejects_sharing_denials_incomplete_controls_and_unknowns() {
        let valid = report_fixture();
        validate_report(&serde_json::from_value(valid.clone()).unwrap()).unwrap();
        for (key, value) in [
            ("occupiedMoveWin32Code", json!(32)),
            ("occupiedMoveWin32Code", json!(5)),
            ("occupiedMoveWin32Code", json!(null)),
            ("occupiedUnchanged", json!(false)),
            ("pendingRetained", json!(false)),
            ("partialFinalAbsent", json!(false)),
            ("requestedApplicationExecution", json!(true)),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value;
            assert!(
                validate_report(&serde_json::from_value(invalid).unwrap()).is_err(),
                "{key}"
            );
        }
        let mut unknown = valid;
        unknown["unexpected"] = json!(true);
        assert!(serde_json::from_value::<GuestReport>(unknown).is_err());
    }

    #[test]
    fn exact_namespace_refuses_incomplete_extra_and_wrong_case_entries() {
        let expected = [
            "RESULT.DAT",
            "OCCUPY.DAT",
            "OCCUPY.TMP",
            "PARTIAL.TMP",
            "legacy.json",
        ]
        .map(std::ffi::OsString::from)
        .to_vec();
        assert!(exact_final_inventory(expected.clone()));
        let mut partial = expected.clone();
        partial[0] = "RESULT.TMP".into();
        assert!(!exact_final_inventory(partial));
        let mut extra = expected.clone();
        extra.push("PARTIAL.DAT".into());
        assert!(!exact_final_inventory(extra));
        let mut case = expected;
        case[0] = "result.dat".into();
        assert!(!exact_final_inventory(case));
    }

    #[test]
    fn cleanup_and_retained_read_cannot_hide_changed_bytes_or_identity() {
        let observed = json!({"markerSha256":"a".repeat(64),"occupied":{"identity":"original","sha256":"b".repeat(64)}});
        assert!(stable_observations(
            &Ok(observed.clone()),
            &Ok(observed.clone())
        ));
        let mut altered = observed.clone();
        altered["markerSha256"] = json!("c".repeat(64));
        assert!(!stable_observations(&Ok(observed.clone()), &Ok(altered)));
        let mut replaced = observed.clone();
        replaced["occupied"]["identity"] = json!("replacement");
        assert!(!stable_observations(&Ok(observed.clone()), &Ok(replaced)));
        assert!(!stable_observations(
            &Ok(observed),
            &Err("missing artifact".into())
        ));
    }

    #[test]
    fn publication_recovery_requires_the_unresolved_original_transaction() {
        let h = "a".repeat(64);
        let mut r = json!({"schemaVersion":SCHEMA,"publicationControlOnly":true,"planSha256":h,"sessionId":SESSION,"outerCleanupVerified":false});
        assert!(recovery_allowed(Some(&r), &h, false));
        assert!(!recovery_allowed(Some(&r), &h, true));
        r["outerCleanupVerified"] = json!(true);
        assert!(!recovery_allowed(Some(&r), &h, false));
        r["outerCleanupVerified"] = json!(false);
        r["sessionId"] = json!("foreign");
        assert!(!recovery_allowed(Some(&r), &h, false));
    }
}
