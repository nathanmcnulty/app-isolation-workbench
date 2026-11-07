//! Pure interpretation of source-pinned first-party controls. Not launch authority.
use aiw_provider_wsb::StandardUserRuntimeContext;
use aiw_provider_wsb::sevenzip_code_control::{SevenZipCodeControlTrace, verify_code_control};
use aiw_provider_wsb::sevenzip_process_tree::SevenZipExpectedRootBinding;
use aiw_provider_wsb::sevenzip_tree_control::SevenZipConsoleSupportObservation;
use aiw_token::{IntegrityLevel, TokenEvidence, TokenType};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const HELPER: &str = r"C:\AIW\SevenZip\sevenzip_assessment.exe";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    process_id: u32,
    creation_time_100ns: u64,
    held_token: TokenEvidence,
    held_image: Image,
    profile_deletion: String,
    console_support: SevenZipConsoleSupportObservation,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Invocation {
    token: TokenEvidence,
    exit_code: Option<u32>,
    timed_out: bool,
    job_empty: bool,
    output: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Image {
    canonical_path: String,
    sha256: String,
    size_bytes: u64,
    identity: aiw_probe::WindowsFileIdentity,
}

fn path(actual: &str) -> bool {
    actual
        .strip_prefix(r"\\?\")
        .unwrap_or(actual)
        .eq_ignore_ascii_case(HELPER)
}
fn decode<T: serde::de::DeserializeOwned>(
    stages: &BTreeMap<String, Value>,
    key: &str,
) -> Result<T, String> {
    serde_json::from_value(
        stages
            .get(key)
            .ok_or_else(|| format!("missing {key}"))?
            .clone(),
    )
    .map_err(|e| format!("{key}: {e}"))
}
fn field<'a>(
    stages: &'a BTreeMap<String, Value>,
    stage: &str,
    key: &str,
) -> Result<&'a Value, String> {
    stages
        .get(stage)
        .and_then(|s| s.get(key))
        .ok_or_else(|| format!("missing {stage}.{key}"))
}
fn exact(
    stages: &BTreeMap<String, Value>,
    stage: &str,
    key: &str,
    expected: Value,
) -> Result<(), String> {
    if field(stages, stage, key)? != &expected {
        return Err(format!("{stage}.{key} differs"));
    }
    Ok(())
}

pub(super) fn verify(
    stages: &BTreeMap<String, Value>,
    driver_completed: bool,
    helper_hash: &str,
    helper_size: u64,
) -> Result<Value, String> {
    if !driver_completed {
        return Err("driver incomplete; controls are not accepted".into());
    }
    for (key, expected) in [
        ("schemaVersion", json!("aiw.dev/research/sevenzip/v0alpha1")),
        ("productionEvidence", json!(false)),
        (
            "installerSha256",
            json!("fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0"),
        ),
        ("installerSizeBytes", json!(1_663_506)),
        ("helperSha256", json!(helper_hash)),
        (
            "scope",
            json!(
                "first-party process-tree driver controls; ordinary and classic AppContainer, zero capabilities; no vendor execution"
            ),
        ),
    ] {
        exact(stages, "owner-00-start", key, expected)?;
    }
    let windows: aiw_probe::WindowsVersionObservation =
        serde_json::from_value(field(stages, "owner-00-start", "windows")?.clone())
            .map_err(|e| format!("owner-00-start.windows: {e}"))?;
    if windows.major != 10
        || windows.minor != 0
        || windows.build != 26100
        || windows.revision != 9711
        || windows.observer_architecture != "x86_64"
    {
        return Err("owner-00-start Windows environment differs".into());
    }
    let context: StandardUserRuntimeContext = decode(stages, "owner-01-context")?;
    context.validate()?;
    let launcher: TokenEvidence =
        serde_json::from_value(field(stages, "owner-02-launcher", "heldToken")?.clone())
            .map_err(|e| e.to_string())?;
    context.validate_token(&launcher)?;
    if launcher.process_id == 0 {
        return Err("zero workflow observer PID".into());
    }
    let after_launcher: TokenEvidence =
        serde_json::from_value(field(stages, "owner-05-workflow-exit", "heldToken")?.clone())
            .map_err(|e| e.to_string())?;
    if after_launcher != launcher {
        return Err("workflow owner-held token changed".into());
    }
    for (stage, key, value) in [
        ("owner-05-workflow-exit", "exitCode", json!(0)),
        (
            "owner-05-workflow-exit",
            "firstPartyTreeControlsOnly",
            json!(true),
        ),
        (
            "owner-05-workflow-exit",
            "vendorInstallerExecuted",
            json!(false),
        ),
        (
            "owner-05-workflow-exit",
            "applicationExecuted",
            json!(false),
        ),
        ("owner-05-launcher-cleanup", "jobEmpty", json!(true)),
        ("owner-05-launcher-cleanup", "cleanupError", Value::Null),
        ("owner-05-launcher-cleanup", "operationError", Value::Null),
        ("owner-06-final", "workflowDriverExitCode", json!(0)),
        ("owner-06-final", "launcherJobEmpty", json!(true)),
        ("owner-06-final", "helperBindingsUnchanged", json!(true)),
        ("owner-06-final", "installationExecuted", json!(false)),
        ("tree-profile-cleanup", "deleted", json!(true)),
        ("tree-profile-cleanup", "cleanupError", Value::Null),
        ("tree-profile-cleanup", "candidateError", Value::Null),
        ("tree-complete", "firstPartyControlsOnly", json!(true)),
        ("tree-complete", "ordinaryAndClassicPassed", json!(true)),
        ("tree-complete", "profileDeleted", json!(true)),
    ] {
        exact(stages, stage, key, value)?;
    }
    for key in [
        "owner-99-driver-error",
        "workflow-99-driver-error",
        "tree-baseline-error",
        "tree-candidate-error",
    ] {
        if stages.contains_key(key) {
            return Err(format!("retained {key} prevents acceptance"));
        }
    }
    let profile = field(stages, "tree-candidate-profile", "ownedFreshProfileSid")?
        .as_str()
        .ok_or("profile SID not string")?;
    if !profile.starts_with("S-1-15-2-") || profile.len() > 256 {
        return Err("invalid candidate profile SID".into());
    }
    let mut summaries = vec![];
    for (name, candidate) in [("tree-baseline", false), ("tree-candidate", true)] {
        let binding: Binding = decode(stages, &format!("{name}-binding"))?;
        let token = &binding.held_token;
        if binding.process_id == 0
            || binding.creation_time_100ns == 0
            || token.process_id != binding.process_id
            || token.token_type != TokenType::Primary
            || token.impersonation_level.is_some()
            || token.is_elevated
            || token.schema_version != aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
            || token.user_sid != context.user_sid
            || !token.capabilities.is_empty()
            || token.is_app_container != candidate
            || binding.profile_deletion != "not yet attempted"
            || !path(&binding.held_image.canonical_path)
            || !path(&binding.held_image.identity.final_path)
            || binding.held_image.sha256 != helper_hash
            || binding.held_image.size_bytes != helper_size
            || binding.held_image.identity.volume_serial_number.len() != 16
            || binding.held_image.identity.file_id.len() != 32
            || !binding
                .held_image
                .identity
                .volume_serial_number
                .bytes()
                .chain(binding.held_image.identity.file_id.bytes())
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!("{name} independent root binding/policy differs"));
        }
        if candidate {
            if token.integrity.level != IntegrityLevel::Low
                || token.integrity.rid != 0x1000
                || token.integrity.sid != "S-1-16-4096"
                || token.app_container_sid.as_deref() != Some(profile)
            {
                return Err(
                    "candidate root is not the held fresh low-integrity AppContainer".into(),
                );
            }
        } else {
            context.validate_token(token)?;
        }
        binding.console_support.validate_pinned()?;
        let trace: SevenZipCodeControlTrace = decode(stages, name)?;
        let verified = verify_code_control(
            &trace,
            &SevenZipExpectedRootBinding {
                process_id: binding.process_id,
                creation_time_100ns: binding.creation_time_100ns,
                held_token: token,
                fixed_image_path: HELPER,
                image_sha256: helper_hash,
                image_size_bytes: helper_size,
                expected_control_processes: None,
            },
            &binding.console_support,
        )?;
        let denied: Invocation = decode(
            stages,
            if candidate {
                "tree-owner-candidate"
            } else {
                "tree-owner-baseline"
            },
        )?;
        if denied.token.process_id == 0
            || denied.exit_code != Some(0)
            || denied.timed_out
            || !denied.job_empty
            || denied.output != b"owner-journal-denied-code5"
        {
            return Err(format!("{name} protected owner journal denial incomplete"));
        }
        // These are separate invocations; PID reuse after an exit is legal.
        // Compare all token boundary fields after normalizing only that PID.
        let mut denied_boundary = denied.token;
        denied_boundary.process_id = token.process_id;
        if denied_boundary != *token {
            return Err(format!(
                "{name} owner journal observer token boundary differs"
            ));
        }
        summaries.push(
            json!({"mode":if candidate {"classicAppContainer"} else {"ordinary"},
            "observedProcesses":verified.observed_processes,"pairedExits":verified.paired_exits,
            "helperProcesses":verified.helper_processes,"consoleSupportProcesses":verified.console_support_processes,
            "rootExitedBeforeChild":verified.root_exited_before_helper_child,
            "rootExitedBeforeGrandchildCreate":verified.root_exited_before_grandchild_create,
            "independentRootBindingMatched":true,"sameBoundaryObservedBeforeContinue":true,
            "ownerJournalReadDeniedCode5":true,
            "codeCheckedBeforeContinue":verified.code_checked_before_continue,
            "sameEventImageRevalidated":verified.same_event_image_revalidated,
            "consoleIdentityRelation":verified.console_identity_relation,
            "physicalObjectEquivalence":verified.physical_object_equivalence,
            "exactJobReconciled":verified.exact_job_reconciled,"scope":verified.scope}),
        );
    }
    Ok(json!({"fixedControlFactsVerified":true,"modes":summaries,
        "ownedProfileDeleted":true,"workflowJobEmpty":true,
        "applicationCompatibility":"unmeasured","brokerAndAllHostCoverage":"unmeasured",
        "deliberateChainResetNegative":"not yet measured","productionAcceptance":false}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiw_provider_wsb::sevenzip_code_control::SEVENZIP_CODE_CONTROL_TRACE_SCHEMA;
    use aiw_provider_wsb::sevenzip_process_tree::{
        SEVENZIP_PROCESS_CHAIN_SCHEMA, SEVENZIP_PROCESS_CHAIN_SCOPE,
    };
    use aiw_provider_wsb::sevenzip_tree_control::{
        SEVENZIP_CONSOLE_SUPPORT_PATH, SEVENZIP_CONSOLE_SUPPORT_SCHEMA,
        SEVENZIP_CONSOLE_SUPPORT_SHA256, SEVENZIP_CONSOLE_SUPPORT_SIZE,
    };

    fn code_envelope(chain: Value) -> Value {
        let evidence = chain["processes"].as_array().unwrap().iter().map(|process| {
            json!({"ordinal":process["ordinal"],"processId":process["processId"],
                "createEventSequence":process["createEventSequence"],
                "codeClassBeforeContinue":if process["imageBeforeContinue"]["processImagePath"] == HELPER {
                    "rootCode"
                } else { "consoleSupport" },
                "imageAfterExit":process["imageBeforeContinue"]})
        }).collect::<Vec<_>>();
        json!({"schemaVersion":SEVENZIP_CODE_CONTROL_TRACE_SCHEMA,"chain":chain,"codeEvidence":evidence})
    }

    fn token(pid: u32, candidate: bool) -> Value {
        let rid = if candidate { 4096 } else { 8192 };
        json!({"schemaVersion":aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,"processId":pid,
            "tokenType":"primary","userSid":"S-1-5-21-1-2-3-1001","isElevated":false,
            "elevationType":"default","isAppContainer":candidate,
            "appContainerSid":if candidate {json!("S-1-15-2-1-2-3-4-5-6-7")} else {Value::Null},
            "integrity":{"sid":format!("S-1-16-{rid}"),"rid":rid,"level":if candidate {"low"} else {"medium"}},
            "capabilities":[],"restrictedSidCount":0})
    }
    fn fixture() -> BTreeMap<String, Value> {
        let mut stages = BTreeMap::new();
        stages.insert("owner-00-start".into(),json!({
            "schemaVersion":"aiw.dev/research/sevenzip/v0alpha1","productionEvidence":false,
            "installerSha256":"fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0",
            "installerSizeBytes":1663506,"helperSha256":"a".repeat(64),
            "windows":{"major":10,"minor":0,"build":26100,"revision":9711,"observerArchitecture":"x86_64"},
            "scope":"first-party process-tree driver controls; ordinary and classic AppContainer, zero capabilities; no vendor execution"}));
        stages.insert("owner-01-context".into(),json!({"userSid":"S-1-5-21-1-2-3-1001",
            "profilePath":r"C:\Users\AiwStandardUser","roamingAppData":r"C:\Users\AiwStandardUser\AppData\Roaming",
            "localAppData":r"C:\Users\AiwStandardUser\AppData\Local","administratorsEnabled":false}));
        stages.insert(
            "owner-02-launcher".into(),
            json!({"heldToken":token(90,false)}),
        );
        stages.insert("owner-05-workflow-exit".into(),json!({"heldToken":token(90,false),"exitCode":0,
            "firstPartyTreeControlsOnly":true,"vendorInstallerExecuted":false,"applicationExecuted":false}));
        stages.insert(
            "owner-05-launcher-cleanup".into(),
            json!({"jobEmpty":true,"cleanupError":null,"operationError":null}),
        );
        stages.insert(
            "owner-06-final".into(),
            json!({"workflowDriverExitCode":0,"launcherJobEmpty":true,
            "helperBindingsUnchanged":true,"installationExecuted":false}),
        );
        stages.insert(
            "tree-candidate-profile".into(),
            json!({"ownedFreshProfileSid":"S-1-15-2-1-2-3-4-5-6-7"}),
        );
        stages.insert(
            "tree-profile-cleanup".into(),
            json!({"deleted":true,"cleanupError":null,"candidateError":null}),
        );
        stages.insert("tree-complete".into(),json!({"firstPartyControlsOnly":true,"ordinaryAndClassicPassed":true,"profileDeleted":true}));
        for (name, candidate, base) in [
            ("tree-baseline", false, 100u32),
            ("tree-candidate", true, 200u32),
        ] {
            let created = (1u64 << 55) + 123;
            stages.insert(format!("{name}-binding"),json!({"processId":base,"creationTime100ns":created,
                "heldToken":token(base,candidate),"profileDeletion":"not yet attempted",
                "consoleSupport":{"schemaVersion":SEVENZIP_CONSOLE_SUPPORT_SCHEMA,
                    "windows":{"major":10,"minor":0,"build":26100,"revision":9711,"observerArchitecture":"x86_64"},
                    "canonicalPath":SEVENZIP_CONSOLE_SUPPORT_PATH,
                    "identity":{"finalPath":SEVENZIP_CONSOLE_SUPPORT_PATH,"volumeSerialNumber":"0123456789abcdef","fileId":"0123456789abcdef0123456789abcdef"},
                    "sha256":SEVENZIP_CONSOLE_SUPPORT_SHA256,"sizeBytes":SEVENZIP_CONSOLE_SUPPORT_SIZE,"volumeSerialNumber":7,"fileIndex":99},
                "heldImage":{"canonicalPath":HELPER,"sha256":"a".repeat(64),"sizeBytes":100,
                    "identity":{"finalPath":HELPER,"volumeSerialNumber":"0123456789abcdef","fileId":"0123456789abcdef0123456789abcdef"}}}));
            stages.insert(if candidate {"tree-owner-candidate"} else {"tree-owner-baseline"}.into(),
                json!({"token":token(base+50,candidate),"exitCode":0,"timedOut":false,"jobEmpty":true,
                    "output":b"owner-journal-denied-code5".as_slice()}));
            let processes=(0..3u32).map(|ordinal|json!({"ordinal":ordinal,"processId":base+ordinal,
                "createEventSequence":([1,3,8][ordinal as usize]),"exitEventSequence":([4,10,15][ordinal as usize]),"creationTime100ns":created+u64::from(ordinal),
                "tokenBeforeContinue":token(base+ordinal,candidate),"imageBeforeContinue":{
                    "processImagePath":HELPER,"sha256":"a".repeat(64),"sizeBytes":100,"volumeSerialNumber":1,"fileIndex":9},
                "exitCode":ordinal+31})).collect::<Vec<_>>();
            stages.insert(name.into(),code_envelope(json!({"schemaVersion":SEVENZIP_PROCESS_CHAIN_SCHEMA,"scope":SEVENZIP_PROCESS_CHAIN_SCOPE,
                "rootProcessId":base,"eventsProcessed":16,"processes":processes,"timedOut":false,
                "ownedJobTerminationRequested":false,"ownedJobTerminationSucceeded":false,
                "jobTotalProcesses":3,"jobActiveProcesses":0,"jobLimitTerminatedProcesses":0,
                "jobAccountingReconciled":true,"debuggerChainComplete":true,"requiresDebuggerProcessExit":false,"gaps":[]})));
        }
        stages
    }

    #[test]
    fn exact_positive_controls_recompute_facts_without_claiming_application_or_negative_coverage() {
        let observed = verify(&fixture(), true, &"a".repeat(64), 100).unwrap();
        assert_eq!(observed["fixedControlFactsVerified"], true);
        assert_eq!(observed["applicationCompatibility"], "unmeasured");
        assert_eq!(observed["deliberateChainResetNegative"], "not yet measured");
        assert_eq!(observed["productionAcceptance"], false);
    }

    #[test]
    fn incomplete_or_contradictory_measurements_cannot_pass_using_summary_flags() {
        let mutations: Vec<fn(&mut BTreeMap<String, Value>)> = vec![
            |s| {
                s.get_mut("tree-baseline").unwrap()["codeEvidence"][0]["codeClassBeforeContinue"] =
                    Value::Null
            },
            |s| {
                s.get_mut("tree-baseline").unwrap()["codeEvidence"][0]["imageAfterExit"]["sha256"] =
                    json!("b".repeat(64))
            },
            |s| s.get_mut("tree-baseline").unwrap()["codeEvidence"][0]["processId"] = json!(99),
            |s| s.get_mut("tree-baseline").unwrap()["schemaVersion"] = json!("historical"),
            |s| {
                s.remove("owner-00-start");
            },
            |s| {
                s.insert("owner-00-start".into(), json!({"stageRefused":true}));
            },
            |s| s.get_mut("owner-00-start").unwrap()["schemaVersion"] = json!("wrong"),
            |s| s.get_mut("owner-00-start").unwrap()["productionEvidence"] = json!(true),
            |s| s.get_mut("owner-00-start").unwrap()["installerSha256"] = json!("b".repeat(64)),
            |s| s.get_mut("owner-00-start").unwrap()["installerSizeBytes"] = json!(1663507),
            |s| s.get_mut("owner-00-start").unwrap()["helperSha256"] = json!("b".repeat(64)),
            |s| s.get_mut("owner-00-start").unwrap()["scope"] = json!("ordinary app workflow"),
            |s| s.get_mut("owner-00-start").unwrap()["windows"]["major"] = json!(11),
            |s| s.get_mut("owner-00-start").unwrap()["windows"]["minor"] = json!(1),
            |s| s.get_mut("owner-00-start").unwrap()["windows"]["build"] = json!(26101),
            |s| s.get_mut("owner-00-start").unwrap()["windows"]["revision"] = json!(9712),
            |s| {
                s.get_mut("owner-00-start").unwrap()["windows"]["observerArchitecture"] =
                    json!("aarch64")
            },
            |s| {
                s.remove("tree-baseline-binding");
            },
            |s| s.get_mut("owner-05-launcher-cleanup").unwrap()["jobEmpty"] = json!(false),
            |s| s.get_mut("tree-profile-cleanup").unwrap()["deleted"] = json!(false),
            |s| s.get_mut("owner-06-final").unwrap()["installationExecuted"] = json!(true),
            |s| {
                s.get_mut("tree-baseline-binding").unwrap()["heldImage"]["sha256"] =
                    json!("b".repeat(64))
            },
            |s| {
                s.get_mut("tree-candidate-binding").unwrap()["heldToken"]["appContainerSid"] =
                    json!("S-1-15-2-999")
            },
            |s| {
                s.get_mut("tree-candidate").unwrap()["chain"]["processes"][1]["tokenBeforeContinue"]
                    ["userSid"] = json!("S-1-5-21-1-2-3-9999")
            },
            |s| s.get_mut("tree-candidate").unwrap()["chain"]["jobTotalProcesses"] = json!(4),
            |s| {
                s.get_mut("tree-candidate").unwrap()["chain"]["processes"][2]["exitEventSequence"] =
                    Value::Null
            },
            |s| s.get_mut("tree-baseline").unwrap()["chain"]["processes"][1]["exitCode"] = json!(0),
            |s| {
                s.insert(
                    "tree-baseline-error".into(),
                    json!({"driverError":"retained"}),
                );
            },
            |s| {
                s.remove("tree-owner-baseline");
            },
            |s| s.get_mut("tree-owner-candidate").unwrap()["output"] = json!([]),
            |s| s.get_mut("tree-owner-candidate").unwrap()["exitCode"] = json!(1),
            |s| s.get_mut("tree-owner-candidate").unwrap()["timedOut"] = json!(true),
            |s| s.get_mut("tree-owner-candidate").unwrap()["jobEmpty"] = json!(false),
            |s| {
                s.get_mut("tree-owner-candidate").unwrap()["token"]["userSid"] =
                    json!("S-1-5-21-1-2-3-9999")
            },
            |s| {
                s.get_mut("tree-owner-candidate").unwrap()["token"]["isAppContainer"] = json!(false)
            },
            |s| s.get_mut("tree-owner-baseline").unwrap()["token"]["processId"] = json!(0),
            |s| {
                s.get_mut("tree-owner-candidate").unwrap()["token"]["appContainerSid"] =
                    json!("S-1-15-2-999")
            },
            |s| {
                s.get_mut("tree-candidate-binding").unwrap()["consoleSupport"]["sha256"] =
                    json!("b".repeat(64))
            },
            |s| {
                s.get_mut("tree-candidate-binding").unwrap()["consoleSupport"]["fileIndex"] =
                    json!(0)
            },
            |s| {
                s.get_mut("tree-candidate-binding").unwrap()["consoleSupport"]["windows"]["revision"] =
                    json!(9712)
            },
            |s| {
                s.get_mut("tree-candidate-binding")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove("consoleSupport");
            },
        ];
        for (index, mutation) in mutations.into_iter().enumerate() {
            let mut stages = fixture();
            mutation(&mut stages);
            assert!(
                verify(&stages, true, &"a".repeat(64), 100).is_err(),
                "mutation {index}"
            );
        }
        assert!(verify(&fixture(), false, &"a".repeat(64), 100).is_err());
        assert!(verify(&fixture(), true, &"a".repeat(64), 101).is_err());
    }

    #[test]
    fn full_width_creation_times_are_compared_losslessly_and_unknown_trace_fields_refused() {
        let mut stages = fixture();
        let bytes = serde_json::to_vec(&stages).unwrap();
        stages = serde_json::from_slice(&bytes).unwrap();
        assert!(verify(&stages, true, &"a".repeat(64), 100).is_ok());
        stages.get_mut("tree-baseline-binding").unwrap()["creationTime100ns"] =
            json!((1u64 << 55) + 124);
        assert!(verify(&stages, true, &"a".repeat(64), 100).is_err());
        let mut stages = fixture();
        stages.get_mut("tree-baseline").unwrap()["unknown"] = json!(true);
        assert!(verify(&stages, true, &"a".repeat(64), 100).is_err());
        let mut stages = fixture();
        let historical = stages["tree-baseline"]["chain"].clone();
        stages.insert("tree-baseline".into(), historical);
        assert!(verify(&stages, true, &"a".repeat(64), 100).is_err());
    }

    #[test]
    fn code_bound_console_support_is_counted_and_never_exempted_from_candidate_boundary() {
        let mut stages = fixture();
        for (name, candidate, base) in [
            ("tree-baseline", false, 100u32),
            ("tree-candidate", true, 200u32),
        ] {
            let envelope = stages.get_mut(name).unwrap();
            let chain = &mut envelope["chain"];
            let helpers = chain["processes"].as_array().unwrap().clone();
            let mut processes = vec![];
            for i in 0..3u32 {
                let mut helper = helpers[i as usize].clone();
                helper["ordinal"] = json!(i * 2);
                helper["processId"] = json!(base + i * 2);
                helper["tokenBeforeContinue"] = token(base + i * 2, candidate);
                helper["creationTime100ns"] = json!((1u64 << 55) + 123 + u64::from(i * 2));
                processes.push(helper);
                let mut support = helpers[0].clone();
                support["ordinal"] = json!(i * 2 + 1);
                support["processId"] = json!(base + i * 2 + 1);
                support["tokenBeforeContinue"] = token(base + i * 2 + 1, candidate);
                support["createEventSequence"] = json!([2, 6, 9][i as usize]);
                support["exitEventSequence"] = json!([5, 11, 16][i as usize]);
                support["creationTime100ns"] = json!((1u64 << 55) + 123 + u64::from(i * 2 + 1));
                support["imageBeforeContinue"] = json!({"processImagePath":SEVENZIP_CONSOLE_SUPPORT_PATH,
                    "sha256":SEVENZIP_CONSOLE_SUPPORT_SHA256,"sizeBytes":SEVENZIP_CONSOLE_SUPPORT_SIZE,
                    "volumeSerialNumber":8,"fileIndex":199});
                support["exitCode"] = json!(0);
                processes.push(support);
            }
            chain["processes"] = json!(processes);
            chain["eventsProcessed"] = json!(16);
            chain["jobTotalProcesses"] = json!(6);
            let updated = chain.clone();
            *envelope = code_envelope(updated);
        }
        let observed = verify(&stages, true, &"a".repeat(64), 100).unwrap();
        for mode in observed["modes"].as_array().unwrap() {
            assert_eq!(mode["observedProcesses"], 6);
            assert_eq!(mode["consoleSupportProcesses"], 3);
            assert_eq!(mode["ownerJournalReadDeniedCode5"], true);
            assert_eq!(mode["codeCheckedBeforeContinue"], true);
            assert_eq!(mode["sameEventImageRevalidated"], true);
            assert_eq!(mode["consoleIdentityRelation"], "atLeastOnePairDifferent");
            assert_eq!(mode["physicalObjectEquivalence"], "unproved");
        }
        let mut drift = stages.clone();
        drift.get_mut("tree-candidate").unwrap()["chain"]["processes"][3]["tokenBeforeContinue"] =
            token(203, false);
        assert!(verify(&drift, true, &"a".repeat(64), 100).is_err());
        let mut drift = stages;
        drift.get_mut("tree-baseline").unwrap()["chain"]["processes"][3]["imageBeforeContinue"]["fileIndex"] =
            json!(100);
        assert!(verify(&drift, true, &"a".repeat(64), 100).is_err());
    }
}
