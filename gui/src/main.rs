#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("Application Isolation Workbench desktop requires Windows.");
}

#[cfg(windows)]
mod desktop {
    use aiw_admin_workflow::{self as service, ApprovalGate, ApprovalReview};
    use aiw_desktop::{Controller, ErrorView, Phase, ResultOutcome, ResultView, Review, Snapshot};
    use anyhow::{Context, Result};
    use std::{
        path::{Path, PathBuf},
        time::Duration,
    };
    use tauri::{Manager, State};
    use tauri_plugin_dialog::DialogExt;

    fn path_text(path: &Path) -> Result<String> {
        Ok(path
            .to_str()
            .context("Path must contain valid Unicode")?
            .into())
    }
    fn review_json<T: serde::Serialize>(value: &T) -> Result<String> {
        let mut bytes = Vec::new();
        service::approval_review::write_review_json(&mut bytes, value)?;
        Ok(String::from_utf8(bytes)?)
    }
    fn public_error(error: anyhow::Error) -> ErrorView {
        let error = service::public_error(error);
        if let Some(e) = error.downcast_ref::<aiw_orchestrator::AiwError>() {
            ErrorView {
                code: e.code.to_string(),
                summary: e.summary.to_string(),
                remediation: e.remediation.to_string(),
                detail: e.detail.to_string(),
                run_id: e.run_id.as_ref().map(ToString::to_string),
            }
        } else {
            ErrorView { code: "AIW_DESKTOP_FAILED".into(), summary: "The workflow needs attention".into(), remediation: "Preserve the retained evidence and inspect the exact run status before retrying.".into(), detail: error.to_string(), run_id: None }
        }
    }
    struct GuiGate {
        controller: Controller,
        id: String,
        workflow_name: String,
    }
    impl ApprovalGate for GuiGate {
        fn review(&self, r: &ApprovalReview) -> Result<Option<String>> {
            let review = Review {
                workflow_name: self.workflow_name.clone(),
                challenge_id: String::new(),
                plan_hash: r.proposed_approval.plan_hash.to_string(),
                exact_confirmation: format!("approve {}", r.proposed_approval.plan_hash),
                operator_identity: r.proposed_approval.approved_by.to_string(),
                recipe_json: review_json(&r.recipe)?,
                plan_json: review_json(&r.plan)?,
                approval_json: review_json(&r.proposed_approval)?,
                evidence_root: path_text(&r.evidence_root)?,
                workspace: path_text(&r.workspace)?,
            };
            let rx = self
                .controller
                .offer_review(&self.id, review)
                .map_err(anyhow::Error::msg)?;
            match rx.recv_timeout(Duration::from_secs(1800)) {
                Ok(value) => Ok(value),
                Err(_) => {
                    let _ = self.controller.cancel(&self.id);
                    Ok(None)
                }
            }
        }
        fn wait_for_start(&self, _: &ApprovalReview) -> Result<bool> {
            let rx = self
                .controller
                .offer_start(&self.id)
                .map_err(anyhow::Error::msg)?;
            match rx.recv_timeout(Duration::from_secs(1800)) {
                Ok(value) => Ok(value),
                Err(_) => {
                    let _ = self.controller.cancel(&self.id);
                    Ok(false)
                }
            }
        }
    }
    fn complete(
        app: &tauri::AppHandle,
        controller: &Controller,
        id: &str,
        outcome: Result<(Phase, ResultView)>,
    ) {
        let closing = match outcome {
            Ok((phase, result)) => controller.finish(id, phase, Some(result), None),
            Err(error) => controller.finish(id, Phase::Failed, None, Some(public_error(error))),
        };
        if closing && let Some(window) = app.get_webview_window("main") {
            let _ = window.destroy();
        }
    }
    fn spawn_work(
        app: tauri::AppHandle,
        c: Controller,
        id: String,
        work: impl FnOnce() -> Result<(Phase, ResultView)> + Send + 'static,
    ) {
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).unwrap_or_else(|_| Err(anyhow::anyhow!("Worker panicked. Retained status must be inspected; cleanup is not established.")));
            complete(&app, &c, &id, result);
        });
    }
    #[tauri::command]
    fn get_state(c: State<'_, Controller>) -> Snapshot {
        c.snapshot()
    }
    #[tauri::command]
    async fn choose_input(
        app: tauri::AppHandle,
        kind: String,
    ) -> std::result::Result<Option<String>, String> {
        tauri::async_runtime::spawn_blocking(move || {
            let builder = app.dialog().file();
            let path = match kind.as_str() {
                "installer" => builder
                    .add_filter("Supported MSI", &["msi"])
                    .blocking_pick_file(),
                "bambu-installer" => builder
                    .add_filter("Supported Bambu Studio EXE", &["exe"])
                    .blocking_pick_file(),
                "document" => builder
                    .add_filter("UTF-8 text", &["txt"])
                    .blocking_pick_file(),
                "evidence" | "workspace" | "package-output" => builder.blocking_pick_folder(),
                "destination" => builder
                    .add_filter("Text document", &["txt"])
                    .set_file_name("edited-document.txt")
                    .blocking_save_file(),
                _ => return Err("Unknown file selection kind.".to_owned()),
            };
            path.map(|p| {
                p.into_path()
                    .map_err(|_| "An ordinary local file path is required.".to_owned())
                    .and_then(|p| path_text(&p).map_err(|e| e.to_string()))
            })
            .transpose()
        })
        .await
        .map_err(|e| e.to_string())?
    }
    async fn package_action<T: Send + 'static>(
        app: tauri::AppHandle,
        c: Controller,
        id: String,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> std::result::Result<T, String> {
        let outcome = tauri::async_runtime::spawn_blocking(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("Packaging worker panicked. Preserve evidence and partial output before retrying.")))
        }).await.map_err(|error| anyhow::anyhow!(error)).and_then(|result| result);
        let (returned, error) = match outcome {
            Ok(value) => (Ok(value), None),
            Err(error) => {
                let view = public_error(error);
                (
                    Err(format!("{}: {}", view.summary, view.detail)),
                    Some(view),
                )
            }
        };
        let phase = if returned.is_ok() {
            Phase::Idle
        } else {
            Phase::Failed
        };
        if c.finish(&id, phase, None, error)
            && let Some(window) = app.get_webview_window("main")
        {
            let _ = window.destroy();
        }
        returned
    }
    #[tauri::command]
    async fn analyze_package(
        app: tauri::AppHandle,
        c: State<'_, Controller>,
        installer: String,
    ) -> std::result::Result<service::packaging::PackageAnalysis, String> {
        let c = c.inner().clone();
        let id = c.begin_analysis()?;
        package_action(app, c, id, move || {
            service::packaging::analyze_notepad_installer(Path::new(&installer))
        })
        .await
    }
    #[tauri::command]
    async fn create_package(
        app: tauri::AppHandle,
        c: State<'_, Controller>,
        request: service::packaging::NotepadPackageRequest,
    ) -> std::result::Result<service::packaging::PackageResult, String> {
        let c = c.inner().clone();
        let id = c.begin_packaging()?;
        package_action(app, c, id, move || {
            service::packaging::create_notepad_package(&request)
        })
        .await
    }
    #[tauri::command]
    fn prepare_workflow(
        app: tauri::AppHandle,
        c: State<'_, Controller>,
        kind: String,
        installer: String,
        document_input: Option<String>,
        evidence: String,
        operator_identity: String,
    ) -> std::result::Result<(), String> {
        if !matches!(kind.as_str(), "assessment" | "interactive" | "bambu") {
            return Err("Unsupported workflow.".into());
        }
        if installer.is_empty() || evidence.is_empty() || operator_identity.trim().is_empty() {
            return Err(
                "Choose the supported installer, evidence folder, and operator identity.".into(),
            );
        }
        if kind == "interactive" && document_input.as_deref().is_none_or(str::is_empty) {
            return Err("Choose a UTF-8 text input.".into());
        }
        let c = c.inner().clone();
        let id = c.begin()?;
        let gate = GuiGate {
            controller: c.clone(),
            id: id.clone(),
            workflow_name: if kind == "interactive" {
                "Interactive Notepad++ document transfer"
            } else if kind == "bambu" {
                "Fixed Bambu Studio STL-to-3MF export"
            } else {
                "Fixed Notepad++ assessment"
            }
            .into(),
        };
        spawn_work(app, c, id, move || {
            let result = if kind == "interactive" {
                service::launch_document_with_gate(
                    Path::new(&installer),
                    Path::new(
                        document_input
                            .as_deref()
                            .context("Missing document input")?,
                    ),
                    Path::new(&evidence),
                    &operator_identity,
                    &gate,
                    false,
                )?
            } else if kind == "bambu" {
                service::assess_bambu_with_gate(
                    Path::new(&installer),
                    Path::new(&evidence),
                    &operator_identity,
                    &gate,
                    false,
                )?
            } else {
                service::assess_with_gate(
                    Path::new(&installer),
                    Path::new(&evidence),
                    &operator_identity,
                    &gate,
                    false,
                )?
            };
            let phase = if result.execution_started {
                Phase::Completed
            } else {
                Phase::Cancelled
            };
            if result.execution_started && kind == "bambu" {
                let report = service::report_bambu(&result.workspace, &result.run_id)?;
                return Ok((
                    phase,
                    ResultView {
                        outcome: bambu_report_outcome(&report),
                        run_id: result.run_id.clone(),
                        workspace: path_text(&result.workspace)?,
                        evidence_root: path_text(&result.evidence_root)?,
                        summary: result
                            .summary_text()
                            .unwrap_or("No verified summary is available.")
                            .into(),
                        can_export_document: false,
                        report_markdown: aiw_runner::render_bambu_run_report_markdown(&report),
                    },
                ));
            }
            let report = if result.execution_started {
                if kind == "interactive" {
                    service::report_document(&result.workspace, &result.run_id)?
                } else {
                    service::report_assessment(&result.workspace, &result.run_id)?
                }
            } else {
                return Ok((
                    phase,
                    ResultView {
                        outcome: ResultOutcome::NotRun,
                        run_id: result.run_id.clone(),
                        workspace: path_text(&result.workspace)?,
                        evidence_root: path_text(&result.evidence_root)?,
                        summary: result.next.into(),
                        can_export_document: false,
                        report_markdown: String::new(),
                    },
                ));
            };
            let can_export = export_eligible(&report);
            Ok((
                phase,
                ResultView {
                    outcome: report_outcome(&report),
                    run_id: result.run_id.clone(),
                    workspace: path_text(&result.workspace)?,
                    evidence_root: path_text(&result.evidence_root)?,
                    summary: result
                        .summary_text()
                        .unwrap_or("No verified summary is available.")
                        .into(),
                    can_export_document: can_export,
                    report_markdown: report.to_markdown(),
                },
            ))
        });
        Ok(())
    }
    fn export_eligible(report: &aiw_runner::WsbMsiRunReport) -> bool {
        matches!(report, aiw_runner::WsbMsiRunReport::InteractiveSession(r) if r.recorded_cleanup_verified && r.document_transfer.is_some())
    }
    fn report_outcome(report: &aiw_runner::WsbMsiRunReport) -> ResultOutcome {
        match report {
            aiw_runner::WsbMsiRunReport::CompletedAssessment(r)
                if r.recorded_cleanup_verified
                    && r.administrator_function_results()
                        .iter()
                        .all(|(_, v)| *v == Some(true)) =>
            {
                ResultOutcome::Verified
            }
            aiw_runner::WsbMsiRunReport::InteractiveSession(r)
                if r.recorded_cleanup_verified && r.document_transfer.is_some() =>
            {
                ResultOutcome::Verified
            }
            _ => ResultOutcome::Incomplete,
        }
    }
    fn bambu_report_outcome(report: &aiw_runner::WsbBambuRunReport) -> ResultOutcome {
        if report.verified_workflow_completed() {
            ResultOutcome::Verified
        } else {
            ResultOutcome::Incomplete
        }
    }
    #[tauri::command]
    fn submit_approval(
        c: State<'_, Controller>,
        workflow_id: String,
        challenge_id: String,
        confirmation: String,
    ) -> std::result::Result<(), String> {
        c.approve(&workflow_id, &challenge_id, &confirmation)
    }
    #[tauri::command]
    fn start_approved_workflow(
        c: State<'_, Controller>,
        workflow_id: String,
        challenge_id: String,
    ) -> std::result::Result<(), String> {
        c.start(&workflow_id, &challenge_id)
    }
    #[tauri::command]
    fn cancel_pending(
        c: State<'_, Controller>,
        workflow_id: String,
    ) -> std::result::Result<(), String> {
        c.cancel(&workflow_id)
    }
    #[tauri::command]
    fn export_document(
        app: tauri::AppHandle,
        c: State<'_, Controller>,
        destination: String,
    ) -> std::result::Result<(), String> {
        if destination.is_empty() {
            return Err("Choose a new destination first.".into());
        }
        let c = c.inner().clone();
        let (id, mut result) = c.begin_export()?;
        // Destination rejection retains the verified result; every export re-verifies evidence.
        std::thread::spawn(move || {
            let export = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                service::export_document(
                    Path::new(&result.workspace),
                    &result.run_id,
                    Path::new(&destination),
                )
            }));
            let error = match export {
                Ok(Ok(_)) => {
                    result.summary.push_str(&format!(
                        "\nDocument exported to {destination}. No existing file was overwritten."
                    ));
                    None
                }
                Ok(Err(e)) => {
                    let error = public_error(e);
                    if error.code != "AIW_WSB_EXPORT_DESTINATION_REJECTED" {
                        result.can_export_document = false;
                        result.outcome = ResultOutcome::Incomplete;
                        result.summary.push_str("\nExport re-verification failed. Preserve the evidence and any destination file; no current export is available.");
                    }
                    Some(error)
                }
                Err(_) => {
                    result.can_export_document = false;
                    Some(public_error(anyhow::anyhow!(
                        "Export worker panicked. Preserve any destination file before retrying."
                    )))
                }
            };
            let closing = c.finish(&id, Phase::Completed, Some(result), error);
            if closing && let Some(w) = app.get_webview_window("main") {
                let _ = w.destroy();
            }
        });
        Ok(())
    }
    #[tauri::command]
    fn load_retained_report(
        app: tauri::AppHandle,
        c: State<'_, Controller>,
        kind: String,
        workspace: String,
        run_id: String,
    ) -> std::result::Result<(), String> {
        if !matches!(kind.as_str(), "assessment" | "interactive" | "bambu")
            || workspace.is_empty()
            || run_id.is_empty()
        {
            return Err("Select a retained workflow kind, workspace, and run ID.".into());
        }
        let c = c.inner().clone();
        let id = c.begin()?;
        spawn_work(app, c, id, move || {
            if kind == "bambu" {
                let report = service::report_bambu(Path::new(&workspace), &run_id)?;
                return Ok((Phase::Completed, ResultView {
                    outcome: bambu_report_outcome(&report),
                    run_id,
                    evidence_root: "Not recorded by this retained-report selection".into(),
                    workspace,
                    summary: "Retained Bambu report reverified. Loading did not start or recover Sandbox. Read the verified function, artifact, and cleanup results below.".into(),
                    can_export_document: false,
                    report_markdown: aiw_runner::render_bambu_run_report_markdown(&report),
                }));
            }
            let report = if kind == "interactive" {
                service::report_document(Path::new(&workspace), &run_id)?
            } else {
                service::report_assessment(Path::new(&workspace), &run_id)?
            };
            let markdown = report.to_markdown();
            Ok((Phase::Completed, ResultView { outcome: report_outcome(&report), run_id, evidence_root: "Not recorded by this retained-report selection".into(), workspace, summary: "Retained report reverified. Loading did not start or recover Sandbox. Read the verified function and cleanup results below.".into(), can_export_document: export_eligible(&report), report_markdown: markdown }))
        });
        Ok(())
    }
    pub fn run() -> Result<()> {
        let parent =
            PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?)
                .join("AppIsolationWorkbench")
                .join("Evidence");
        std::fs::create_dir_all(&parent)?;
        let c = Controller::new(path_text(&parent)?);
        tauri::Builder::default()
            .manage(c)
            .plugin(tauri_plugin_dialog::init())
            .invoke_handler(tauri::generate_handler![
                get_state,
                choose_input,
                analyze_package,
                create_package,
                prepare_workflow,
                submit_approval,
                start_approved_workflow,
                cancel_pending,
                export_document,
                load_retained_report
            ])
            .setup(|app| {
                tauri::WebviewWindowBuilder::new(
                    app,
                    "main",
                    tauri::WebviewUrl::App("index.html".into()),
                )
                .title("Application Isolation Workbench — Development preview")
                .inner_size(1080.0, 820.0)
                .min_inner_size(760.0, 600.0)
                .devtools(false)
                .on_navigation(|url| {
                    url.port().is_none()
                        && ((url.scheme() == "tauri" && url.host_str() == Some("localhost"))
                            || (url.scheme() == "http"
                                && url.host_str() == Some("tauri.localhost")))
                })
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .build()?;
                Ok(())
            })
            .on_window_event(|window, event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event
                    && !window.state::<Controller>().request_close()
                {
                    api.prevent_close();
                }
            })
            .run(tauri::generate_context!())
            .context("Desktop application failed")?;
        Ok(())
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = desktop::run() {
        let mut message = format!("Application Isolation Workbench could not start.\n\n{error:#}");
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            let folder = std::path::PathBuf::from(local)
                .join("AppIsolationWorkbench")
                .join("Diagnostics");
            if std::fs::create_dir_all(&folder).is_ok() {
                let file = folder.join(format!("startup-{}.txt", uuid::Uuid::new_v4()));
                if std::fs::write(&file, &message).is_ok() {
                    message.push_str(&format!("\n\nDiagnostics: {}", file.display()));
                }
            }
        }
        let text: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
        let title: Vec<u16> = "Application Isolation Workbench"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // Startup can fail before there is a WebView or IPC surface to display diagnostics.
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                windows_sys::Win32::UI::WindowsAndMessaging::MB_OK
                    | windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
            );
        }
        std::process::exit(1);
    }
}
