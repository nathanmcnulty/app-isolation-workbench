use aiw_provider_wsb::{
    CompiledMsiScenario, ImportedMsiGuestRequest, ImportedMsiScenarioResult,
    compile_notepad_plus_plus_msi_scenario,
};

fn project() -> aiw_schema::Project {
    serde_yaml::from_str(include_str!(
        "../../../examples/notepad-plus-plus-interactive.aiw.yaml"
    ))
    .unwrap()
}

fn request(scenario: CompiledMsiScenario) -> ImportedMsiGuestRequest {
    ImportedMsiGuestRequest::new(
        "interactive-test",
        "00112233-4455-6677-8899-aabbccddeeff",
        &"a".repeat(64),
        &"b".repeat(64),
        scenario.clone(),
        &scenario.application_sha256,
        100,
        &"c".repeat(64),
    )
    .unwrap()
}

#[test]
fn interactive_lifetime_and_scratch_semantics_are_bound_without_assessment_claims() {
    let mut source = project();
    let compiled = compile_notepad_plus_plus_msi_scenario(&source, "install-launch-close").unwrap();
    assert_eq!(compiled.interactive_session_seconds, Some(300));
    assert!(compiled.requires_standard_user());
    assert!(compiled.requires_application_token());
    assert!(!compiled.requires_application_exercise());
    assert!(!compiled.requires_registry_observations());
    let first = request(compiled.clone());
    let result = ImportedMsiScenarioResult::succeeded(&first, 0, 123, 0).unwrap();
    assert!(!result.graceful_close_requested);
    result.validate_for_request(&first).unwrap();
    let mut altered = result.clone();
    altered.graceful_close_requested = true;
    assert!(altered.validate_for_request(&first).is_err());
    let mut changed = compiled.clone();
    changed.interactive_session_seconds = Some(120);
    let second = request(changed);
    assert_ne!(first.request_sha256, second.request_sha256);
    assert!(result.validate_for_request(&second).is_err());
    for duration in [None, Some(0), Some(29), Some(601), Some(u32::MAX)] {
        let mut changed = compiled.clone();
        changed.interactive_session_seconds = duration;
        assert!(changed.validate().is_err());
    }
    let mut changed = compiled.clone();
    changed.profile = "aiw.dev/windows-sandbox/notepad-plus-plus-msi/v0alpha6".into();
    assert!(changed.validate().is_err());
    source.isolation_intent.allow_host_file_access = true;
    assert!(compile_notepad_plus_plus_msi_scenario(&source, "install-launch-close").is_err());
}
