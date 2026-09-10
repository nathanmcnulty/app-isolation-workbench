#![cfg(windows)]
#![forbid(unsafe_code)]

use aiw_probe::ApplicationInspectionKind;
use aiw_runner::{
    export_notepad_plus_plus_msi_bundle, import_notepad_plus_plus_msi_bundle,
    verify_notepad_plus_plus_msi_bundle,
};
use aiw_windows_platform::{HeldApplicationFile, import_application_file};
use sha2::{Digest, Sha256};
use std::fs;

#[test]
fn bundle_relocation_and_drift_rejection_without_executing_payload() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "aiw-bundle-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let source = root.join("synthetic.msi");
    // Pure file-intake fixture, deliberately not an MSI and never executed.
    let bytes = b"AIW synthetic packaging bytes: not an installer";
    fs::write(&source, bytes).unwrap();
    let held = HeldApplicationFile::open(&source).unwrap();
    let receipt = import_application_file(
        &root,
        "source-intake",
        ApplicationInspectionKind::Msi,
        &held,
    )
    .unwrap();
    let mut project: aiw_schema::Project = serde_yaml::from_str(include_str!(
        "../../../examples/notepad-plus-plus-msi.aiw.yaml"
    ))
    .unwrap();
    let aiw_schema::ApplicationSource::Msi(application) = &mut project.application else {
        unreachable!()
    };
    application.sha256 = hex::encode(Sha256::digest(bytes));
    let exported = export_notepad_plus_plus_msi_bundle(
        &root,
        "bundle",
        &project,
        "install-launch-close",
        &receipt,
    )
    .unwrap();
    assert!(
        export_notepad_plus_plus_msi_bundle(
            &root,
            "bundle",
            &project,
            "install-launch-close",
            &receipt
        )
        .is_err()
    );
    let relocated = root.join("relocated");
    fs::create_dir(&relocated).unwrap();
    for leaf in ["manifest.aiw", "project.aiw", "app.msi"] {
        fs::copy(root.join("bundle").join(leaf), relocated.join(leaf)).unwrap();
    }
    let verify = || verify_notepad_plus_plus_msi_bundle(&relocated, &exported.manifest_sha256);
    verify().unwrap();
    assert!(verify_notepad_plus_plus_msi_bundle(&relocated, &"0".repeat(64)).is_err());
    let imported = import_notepad_plus_plus_msi_bundle(
        &relocated,
        &root,
        "replay-intake",
        &exported.manifest_sha256,
    )
    .unwrap();
    assert_eq!(imported.import_receipt.sha256, receipt.sha256);
    assert_ne!(imported.import_receipt.intake_root, receipt.intake_root);
    assert_eq!(imported.project, project);
    for leaf in ["app.msi", "project.aiw", "manifest.aiw"] {
        let path = relocated.join(leaf);
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"changed").unwrap();
        assert!(verify().is_err(), "accepted {leaf} drift");
        fs::write(path, original).unwrap();
    }
    fs::write(relocated.join("unexpected.ps1"), b"unexpected file").unwrap();
    assert!(verify().is_err());
    fs::remove_file(relocated.join("unexpected.ps1")).unwrap();
    let path = relocated.join("manifest.aiw");
    let original = fs::read(&path).unwrap();
    for field in [
        "profile",
        "runtime",
        "dataContract",
        "scenarioId",
        "sourceImportReceiptSha256",
        "arbitraryCommand",
    ] {
        let mut manifest: serde_json::Value = serde_json::from_slice(&original).unwrap();
        manifest[field] = serde_json::json!("unsupported");
        let changed = serde_json::to_vec(&manifest).unwrap();
        fs::write(&path, &changed).unwrap();
        let changed_hash = hex::encode(Sha256::digest(&changed));
        assert!(
            verify_notepad_plus_plus_msi_bundle(&relocated, &changed_hash).is_err(),
            "accepted rehashed {field}"
        );
    }
    fs::write(&path, original).unwrap();
    let application = relocated.join("app.msi");
    fs::rename(&application, root.join("moved-payload.msi")).unwrap();
    fs::hard_link(root.join("moved-payload.msi"), &application).unwrap();
    assert!(verify().is_err(), "accepted multiply linked payload");
}
