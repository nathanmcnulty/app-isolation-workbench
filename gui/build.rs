fn main() {
    #[cfg(windows)]
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "get_state",
            "choose_input",
            "analyze_package",
            "create_package",
            "prepare_workflow",
            "submit_approval",
            "start_approved_workflow",
            "cancel_pending",
            "export_document",
            "load_retained_report",
        ]),
    ))
    .expect("desktop configuration failed");
}
