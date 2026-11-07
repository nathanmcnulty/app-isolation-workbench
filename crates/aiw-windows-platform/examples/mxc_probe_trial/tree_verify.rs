//! Pure interpretation of source-pinned first-party controls. Not launch authority.
use aiw_provider_wsb::StandardUserRuntimeContext;
use aiw_provider_wsb::sevenzip_process_tree::{SevenZipExpectedRootBinding, SevenZipProcessChain};
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
        let chain: SevenZipProcessChain = decode(stages, name)?;
        chain.verify_complete(&SevenZipExpectedRootBinding {
            process_id: binding.process_id,
            creation_time_100ns: binding.creation_time_100ns,
            held_token: token,
            fixed_image_path: HELPER,
            image_sha256: helper_hash,
            image_size_bytes: helper_size,
            expected_control_processes: Some(3),
        })?;
        if chain
            .processes
            .iter()
            .map(|p| p.exit_code)
            .collect::<Vec<_>>()
            != [Some(31), Some(32), Some(33)]
            || chain.processes[0].exit_event_sequence >= chain.processes[1].exit_event_sequence
        {
            return Err(format!("{name} role exits/root-first order differs"));
        }
        summaries.push(
            json!({"mode":if candidate {"classicAppContainer"} else {"ordinary"},
            "observedProcesses":3,"pairedExits":3,"rootExitedBeforeChild":true,
            "independentRootBindingMatched":true,"sameBoundaryObservedBeforeContinue":true,
            "exactJobReconciled":true,"scope":chain.scope}),
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
    use aiw_provider_wsb::sevenzip_process_tree::{
        SEVENZIP_PROCESS_CHAIN_SCHEMA, SEVENZIP_PROCESS_CHAIN_SCOPE,
    };

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
                "heldImage":{"canonicalPath":HELPER,"sha256":"a".repeat(64),"sizeBytes":100,
                    "identity":{"finalPath":HELPER,"volumeSerialNumber":"0123456789abcdef","fileId":"0123456789abcdef0123456789abcdef"}}}));
            let processes=(0..3u32).map(|ordinal|json!({"ordinal":ordinal,"processId":base+ordinal,
                "createEventSequence":ordinal+1,"exitEventSequence":ordinal+4,"creationTime100ns":created+u64::from(ordinal),
                "tokenBeforeContinue":token(base+ordinal,candidate),"imageBeforeContinue":{
                    "processImagePath":HELPER,"sha256":"a".repeat(64),"sizeBytes":100,"volumeSerialNumber":1,"fileIndex":9},
                "exitCode":ordinal+31})).collect::<Vec<_>>();
            stages.insert(name.into(),json!({"schemaVersion":SEVENZIP_PROCESS_CHAIN_SCHEMA,"scope":SEVENZIP_PROCESS_CHAIN_SCOPE,
                "rootProcessId":base,"eventsProcessed":6,"processes":processes,"timedOut":false,
                "ownedJobTerminationRequested":false,"ownedJobTerminationSucceeded":false,
                "jobTotalProcesses":3,"jobActiveProcesses":0,"jobLimitTerminatedProcesses":0,
                "jobAccountingReconciled":true,"debuggerChainComplete":true,"requiresDebuggerProcessExit":false,"gaps":[]}));
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
                s.get_mut("tree-candidate").unwrap()["processes"][1]["tokenBeforeContinue"]["userSid"] =
                    json!("S-1-5-21-1-2-3-9999")
            },
            |s| s.get_mut("tree-candidate").unwrap()["jobTotalProcesses"] = json!(4),
            |s| {
                s.get_mut("tree-candidate").unwrap()["processes"][2]["exitEventSequence"] =
                    Value::Null
            },
            |s| s.get_mut("tree-baseline").unwrap()["processes"][1]["exitCode"] = json!(0),
            |s| {
                s.insert(
                    "tree-baseline-error".into(),
                    json!({"driverError":"retained"}),
                );
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
    }
}
