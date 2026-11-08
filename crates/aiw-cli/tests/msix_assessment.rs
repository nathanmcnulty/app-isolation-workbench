#[test]
#[ignore = "requires original external archive in AIW_MSIX_RESEARCH_ARCHIVE"]
fn shared_assessment_cli_projects_the_real_reviewed_fixture() {
    let archive = std::env::var_os("AIW_MSIX_RESEARCH_ARCHIVE")
        .expect("set AIW_MSIX_RESEARCH_ARCHIVE to the original reviewed external archive");
    let archive = std::path::PathBuf::from(archive);
    let input = serde_json::json!({
        "schemaVersion": "aiw.dev/application-assessment-input/v0alpha1",
        "msixResearch": [{"id":"notepad-r5","profile":"worker107NotepadR5","archive":archive}]
    });
    let path = std::env::temp_dir().join(format!(
        "aiw-msix-assessment-cli-{}.json",
        std::process::id()
    ));
    std::fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_aiw"))
        .args(["run", "report-assessment", "--input"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["outcome"], "insufficientEvidence");
    assert_eq!(report["isolation"], "notMeasured");
    assert_eq!(report["entries"][0]["functions"]["uninstall"], true);
    assert_eq!(report["entries"][0]["source"]["kind"], "msixResearch");
    assert_eq!(
        report["entries"][0]["source"]["evidence"]["document"]["bytes"],
        53
    );
}

#[test]
fn shared_assessment_cli_rejects_missing_and_synthetic_archives_without_functions() {
    let root = std::env::temp_dir().join(format!(
        "aiw-msix-rejected-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    // Same length as the reviewed archive, but wholly synthetic and untrusted.
    let synthetic = vec![0u8; 285340];
    let tampered = root.join("tampered.zip");
    std::fs::write(&tampered, &synthetic).unwrap();
    let input = serde_json::json!({
        "schemaVersion": "aiw.dev/application-assessment-input/v0alpha1",
        "msixResearch": [
            {"id":"missing","profile":"worker107NotepadR5","archive":root.join("missing.zip")},
            {"id":"tampered","profile":"worker107NotepadR5","archive":tampered}
        ]
    });
    let path = root.join("selection.json");
    let input_bytes = serde_json::to_vec(&input).unwrap();
    std::fs::write(&path, &input_bytes).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_aiw"))
        .args(["run", "report-assessment", "--input"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["outcome"], "insufficientEvidence");
    assert_eq!(report["isolation"], "notMeasured");
    assert_eq!(report["compatibility"], "notMeasured");
    let entries = report["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    for entry in entries {
        assert_eq!(entry["source"]["kind"], "unavailable");
        assert_eq!(entry["source"]["evidence"], "evidenceRejected");
        let functions = entry["functions"].as_object().unwrap();
        assert!(!functions.is_empty());
        assert!(functions.values().all(serde_json::Value::is_null));
    }
    assert_eq!(std::fs::read(&tampered).unwrap(), synthetic);
    assert_eq!(std::fs::read(&path).unwrap(), input_bytes);
    assert!(!root.join("missing.zip").exists());
    std::fs::remove_dir_all(root).unwrap();
}
