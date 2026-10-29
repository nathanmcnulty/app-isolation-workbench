#[test]
fn shared_assessment_cli_projects_the_real_reviewed_fixture() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = serde_json::json!({
        "schemaVersion": "aiw.dev/application-assessment-input/v0alpha1",
        "msixResearch": [{"id":"notepad-r5","profile":"worker107NotepadR5","archive":root.join("fixtures/msix-lifecycle/worker107-r5.zip")}]
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
