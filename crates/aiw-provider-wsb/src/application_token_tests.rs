use aiw_evidence::{EvidenceEvent, EvidenceLog};
use aiw_token::{
    ElevationType, IntegrityEvidence, IntegrityLevel, TOKEN_EVIDENCE_SCHEMA_VERSION, TokenEvidence,
    TokenType,
};

use crate::{
    CompiledMsiScenario, ImportedMsiApplicationToken, ImportedMsiGuestRequest,
    ImportedMsiScenarioResult, MSI_APPLICATION_TOKEN_EVENT, MSI_APPLICATION_TOKEN_SCHEMA,
    verify_msi_application_token,
};

fn scenario() -> CompiledMsiScenario {
    CompiledMsiScenario {
        schema_version: "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha2".to_owned(),
        profile: "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha2".to_owned(),
        scenario_id: "first-run".to_owned(),
        application_sha256: "a".repeat(64),
        installer_path: r"C:\AIW\Tools\application.msi".to_owned(),
        install_arguments: vec![
            "/i".to_owned(),
            r"C:\AIW\Tools\application.msi".to_owned(),
            "/qn".to_owned(),
            "/norestart".to_owned(),
        ],
        install_timeout_seconds: 120,
        launch_path: r"C:\Program Files\Notepad++\notepad++.exe".to_owned(),
        launch_arguments: Vec::new(),
        process_image: "notepad++.exe".to_owned(),
        process_wait_timeout_seconds: 30,
        graceful_close_timeout_seconds: 15,
        expected_exit_code: 0,
    }
}

fn legacy_scenario() -> CompiledMsiScenario {
    let mut value = scenario();
    value.schema_version = "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha1".to_owned();
    value.profile = "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha1".to_owned();
    value
}

fn request_with_scenario(scenario: CompiledMsiScenario) -> ImportedMsiGuestRequest {
    ImportedMsiGuestRequest::new(
        "run-one",
        "11111111-1111-1111-1111-111111111111",
        "b".repeat(64),
        "c".repeat(64),
        scenario,
        "a".repeat(64),
        1024,
        "d".repeat(64),
    )
    .unwrap()
}

fn request() -> ImportedMsiGuestRequest {
    request_with_scenario(scenario())
}

fn legacy_request() -> ImportedMsiGuestRequest {
    request_with_scenario(legacy_scenario())
}

fn token(process_id: u32) -> TokenEvidence {
    TokenEvidence {
        schema_version: TOKEN_EVIDENCE_SCHEMA_VERSION.to_owned(),
        process_id,
        token_type: TokenType::Primary,
        impersonation_level: None,
        is_app_container: false,
        app_container_sid: None,
        user_sid: "S-1-5-21-1".to_owned(),
        integrity: IntegrityEvidence {
            sid: "S-1-16-8192".to_owned(),
            rid: 0x2000,
            level: IntegrityLevel::Medium,
        },
        elevation_type: ElevationType::Default,
        is_elevated: false,
        capabilities: Vec::new(),
        restricted_sid_count: 0,
    }
}

fn log_bytes(events: Vec<(&str, &str, serde_json::Value)>) -> (Vec<u8>, String) {
    let mut log = EvidenceLog::new();
    for (kind, source, payload) in events {
        log.append(EvidenceEvent {
            observed_utc: "2026-09-07T00:00:00Z".to_owned(),
            kind: kind.to_owned(),
            source: source.to_owned(),
            payload,
        })
        .unwrap();
    }
    let root = log.manifest().unwrap().root_hash;
    let mut bytes = Vec::new();
    for record in log.records() {
        serde_json::to_writer(&mut bytes, record).unwrap();
        bytes.push(b'\n');
    }
    (bytes, root)
}

fn token_payload(
    request: &ImportedMsiGuestRequest,
    result: &ImportedMsiScenarioResult,
    token: TokenEvidence,
) -> serde_json::Value {
    serde_json::to_value(ImportedMsiApplicationToken::new(request, result, token).unwrap()).unwrap()
}

#[test]
fn accepts_one_exact_primary_process_token_observation() {
    let request = request();
    let result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
    let (bytes, root) = log_bytes(vec![(
        MSI_APPLICATION_TOKEN_EVENT,
        "aiw-guest-agent",
        token_payload(&request, &result, token(42)),
    )]);
    let observed = verify_msi_application_token(&bytes, &root, &request, &result)
        .unwrap()
        .unwrap();
    assert_eq!(observed.token.process_id, 42);
    assert_eq!(observed.schema_version, MSI_APPLICATION_TOKEN_SCHEMA);
}

#[test]
fn absent_legacy_token_event_is_observationally_missing() {
    let request = legacy_request();
    let result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
    let (bytes, root) = log_bytes(vec![(
        "legacyScenarioEvidence",
        "aiw-guest-agent",
        serde_json::json!({"completed": true}),
    )]);
    assert!(
        verify_msi_application_token(&bytes, &root, &request, &result)
            .unwrap()
            .is_none()
    );
}

#[test]
fn missing_current_v2_token_event_is_rejected() {
    let request = request();
    let result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
    let (bytes, root) = log_bytes(vec![(
        "legacyScenarioEvidence",
        "aiw-guest-agent",
        serde_json::json!({"completed": true}),
    )]);
    assert!(verify_msi_application_token(&bytes, &root, &request, &result).is_err());
}

#[test]
fn current_and_legacy_scenario_pairs_validate_with_distinct_hashes_and_requirements() {
    let current = scenario();
    let legacy = legacy_scenario();
    current.validate().unwrap();
    legacy.validate().unwrap();
    assert!(current.requires_application_token());
    assert!(!legacy.requires_application_token());
    assert_ne!(
        current.canonical_sha256().unwrap(),
        legacy.canonical_sha256().unwrap()
    );
    assert_ne!(request().scenario_sha256, legacy_request().scenario_sha256);
}

#[test]
fn duplicate_foreign_and_binding_tamper_are_rejected() {
    let request = request();
    let result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
    let payload = token_payload(&request, &result, token(42));

    let (duplicate, duplicate_root) = log_bytes(vec![
        (
            MSI_APPLICATION_TOKEN_EVENT,
            "aiw-guest-agent",
            payload.clone(),
        ),
        (
            MSI_APPLICATION_TOKEN_EVENT,
            "aiw-guest-agent",
            payload.clone(),
        ),
    ]);
    assert!(verify_msi_application_token(&duplicate, &duplicate_root, &request, &result).is_err());

    let (foreign, foreign_root) = log_bytes(vec![(
        MSI_APPLICATION_TOKEN_EVENT,
        "other-agent",
        payload.clone(),
    )]);
    assert!(verify_msi_application_token(&foreign, &foreign_root, &request, &result).is_err());

    let mut wrong_pid = ImportedMsiApplicationToken::new(&request, &result, token(42)).unwrap();
    wrong_pid.token.process_id = 43;
    let (wrong_pid_bytes, wrong_pid_root) = log_bytes(vec![(
        MSI_APPLICATION_TOKEN_EVENT,
        "aiw-guest-agent",
        serde_json::to_value(wrong_pid).unwrap(),
    )]);
    assert!(
        verify_msi_application_token(&wrong_pid_bytes, &wrong_pid_root, &request, &result).is_err()
    );

    let mut wrong_schema = ImportedMsiApplicationToken::new(&request, &result, token(42)).unwrap();
    wrong_schema.schema_version = "aiw.dev/msi-application-token/v0alpha0".to_owned();
    let (wrong_schema_bytes, wrong_schema_root) = log_bytes(vec![(
        MSI_APPLICATION_TOKEN_EVENT,
        "aiw-guest-agent",
        serde_json::to_value(wrong_schema).unwrap(),
    )]);
    assert!(
        verify_msi_application_token(&wrong_schema_bytes, &wrong_schema_root, &request, &result)
            .is_err()
    );

    let mut wrong_run = ImportedMsiApplicationToken::new(&request, &result, token(42)).unwrap();
    wrong_run.run_id = "other-run".to_owned();
    let (wrong_run_bytes, wrong_run_root) = log_bytes(vec![(
        MSI_APPLICATION_TOKEN_EVENT,
        "aiw-guest-agent",
        serde_json::to_value(wrong_run).unwrap(),
    )]);
    assert!(
        verify_msi_application_token(&wrong_run_bytes, &wrong_run_root, &request, &result).is_err()
    );

    let mut tampered = log_bytes(vec![(
        MSI_APPLICATION_TOKEN_EVENT,
        "aiw-guest-agent",
        payload,
    )])
    .0;
    tampered[0] = b' ';
    assert!(verify_msi_application_token(&tampered, &"0".repeat(64), &request, &result).is_err());
}

#[test]
fn recomputed_valid_chain_with_wrong_external_root_is_rejected() {
    let request = request();
    let result = ImportedMsiScenarioResult::succeeded(&request, 0, 42, 0).unwrap();
    let (bytes, _root) = log_bytes(vec![(
        MSI_APPLICATION_TOKEN_EVENT,
        "aiw-guest-agent",
        token_payload(&request, &result, token(42)),
    )]);
    assert!(verify_msi_application_token(&bytes, &"0".repeat(64), &request, &result).is_err());
}
