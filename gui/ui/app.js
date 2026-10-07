(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const invoke = window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke;
  const state = { current: null, polling: false, timer: null, startedAt: null, reviewChallenge: null, busy: false, localError: null, analysis: null, analyzedPath: null, packageResult: null };
  const clean = window.AiwDisplay.clean;
  const text = (id, value) => { $(id).textContent = clean(value); };
  const show = (id, visible) => $(id).classList.toggle("hidden", !visible);
  const value = (id) => $(id).value.trim();
  const kind = () => document.querySelector("input[name=workflowKind]:checked").value;
  const phaseLabel = (phase) => ({ idle: "Ready", preparing: "Preparing", review: "Review required", approved: "Approved · Start required", running: "Running", completed: "Completed", cancelled: "Cancelled", failed: "Needs attention", exporting: "Exporting", analyzing: "Analyzing installer", packaging: "Creating package" }[phase] || "Loading state");

  function errorText(error) {
    if (!error) return "The backend did not provide an error.";
    if (typeof error === "string") return error;
    if (error.message) return error.message;
    try { return JSON.stringify(error); } catch (_) { return "The backend returned an unreadable error."; }
  }

  async function call(name, args) {
    if (!invoke) throw new Error("The desktop backend is unavailable. Open this page from the packaged application.");
    try { return await invoke(name, args); } catch (error) { throw new Error(errorText(error)); }
  }

  async function choose(target, inputId) {
    try {
      const selected = await call("choose_input", { kind: target });
      state.localError = null;
      renderError(state.current && state.current.error);
      if (selected != null) text(inputId, selected), $(inputId).value = clean(selected);
      if (selected != null && inputId === "packageInstaller") {
        state.analysis = null; state.analyzedPath = null; state.packageResult = null;
        text("packageStatus", "Installer changed. Analyze before selecting a recipe.");
        renderPackage();
      }
      applyControls(state.current, state.busy);
    } catch (error) { displayLocalError(error); }
  }

  function renderMode() {
    const bambu = kind() === "bambu";
    show("documentField", kind() === "interactive");
    text("installerLabel", bambu ? "Supported Bambu Studio installer" : "Supported Notepad++ installer");
    text("chooseInstaller", bambu ? "Choose EXE" : "Choose MSI");
    $("installer").placeholder = bambu ? "Choose the exact supported EXE" : "Choose the exact supported MSI";
    text("setupHint", bambu
      ? "Select the exact supported Bambu Studio EXE and identify the operator before preparing. The fixed STL input is package supplied."
      : "Select the exact supported MSI and identify the operator before preparing.");
    $("installer").value = "";
  }

  function displayLocalError(error) {
    const newlyVisible = state.localError == null;
    state.localError = error;
    text("errorSummary", "The desktop action could not be completed");
    text("errorRemediation", errorText(error));
    text("errorDetail", "");
    text("errorLocation", "Check the current workflow state and retained evidence before retrying.");
    show("errorCard", true);
    if (newlyVisible) $("errorCard").scrollIntoView({ block: "nearest" });
  }

  function setBusy(busy) {
    ["prepare", "approve", "start", "cancel", "chooseInstaller", "chooseDocument", "chooseEvidence", "chooseDestination", "chooseWorkspace", "operatorIdentity", "export", "loadRetained"].forEach((id) => { if ($(id)) $(id).disabled = busy; });
    document.querySelectorAll("input[name=workflowKind]").forEach((radio) => { radio.disabled = busy; });
  }

  function applyControls(snapshot, busy) {
    const phase = snapshot ? snapshot.phase : "idle";
    const editable = ["idle", "cancelled", "failed", "completed"].includes(phase);
    const pending = ["preparing", "review", "approved"].includes(phase);
    const locked = busy || ["preparing", "running", "exporting", "analyzing", "packaging"].includes(phase);
    ["chooseInstaller", "chooseDocument", "chooseEvidence", "operatorIdentity", "prepare"].forEach((id) => { $(id).disabled = locked || !editable; });
    $("chooseWorkspace").disabled = !!busy;
    $("loadRetained").disabled = !!busy;
    document.querySelectorAll("input[name=workflowKind]").forEach((radio) => { radio.disabled = locked || !editable; });
    $("approve").disabled = busy || phase !== "review";
    $("start").disabled = busy || phase !== "approved";
    $("cancel").disabled = busy || !pending;
    show("cancel", pending);
    $("export").disabled = busy || phase !== "completed" || !(snapshot && snapshot.result && snapshot.result.canExportDocument);
    $("chooseDestination").disabled = busy || phase !== "completed" || !(snapshot && snapshot.result && snapshot.result.canExportDocument);
    ["choosePackageInstaller", "choosePackageOutput", "choosePackageDocument", "packageProfile", "packageIsolation"].forEach((id) => { $(id).disabled = locked || !editable; });
    $("analyzePackage").disabled = locked || !editable || !value("packageInstaller");
    $("createPackage").disabled = locked || !editable || !selectedPackageOption() || !value("packageOutput");
    $("validatePackage").disabled = locked || !editable || !state.packageResult;
  }

  function selectedPackageOption() {
    return state.analysis && state.analyzedPath === value("packageInstaller") &&
      state.analysis.options.find((option) => option.profile === value("packageProfile") && option.isolationPreset === value("packageIsolation"));
  }

  function renderPackage() {
    const options = state.analysis ? state.analysis.options : [];
    show("packageSelection", options.length > 0);
    show("packageAdvanced", !!state.analysis || !!state.packageResult);
    show("packageResult", !!state.packageResult);
    show("packageDocumentField", !!state.packageResult && state.packageResult.profile === "interactiveDocument");
    text("packageDescription", (selectedPackageOption() || {}).description || "");
    text("packageLimits", state.analysis ? state.analysis.limitations.join("\n\n") : "");
    text("packageAnalysisJson", state.analysis ? JSON.stringify(state.analysis, null, 2) : "");
    text("packageResultJson", state.packageResult ? JSON.stringify(state.packageResult, null, 2) : "");
    if (state.packageResult) {
      text("packageResultSummary", state.packageResult.next);
      text("packageResultPath", "Workflow: " + state.packageResult.profile + "\n" + state.packageResult.bundle.bundlePath);
      text("packageResultHash", "Manifest SHA-256: " + state.packageResult.bundle.manifestSha256);
    }
  }

  async function packageAction(create) {
    if (state.busy) return;
    const option = selectedPackageOption();
    if (create && !option) return;
    state.busy = true; setBusy(true); applyControls(state.current, true); state.localError = null;
    text("packageStatus", create ? "Creating and verifying a fresh package. No Sandbox is started." : "Analyzing installer identity. No installer is executed.");
    try {
      if (create) {
        state.packageResult = null; renderPackage();
        state.packageResult = await call("create_package", { request: {
          installer: state.analyzedPath, profile: option.profile, isolationPreset: option.isolationPreset,
          analyzedInstallerSha256: state.analysis.installer.sha256, analyzedProjectSha256: option.projectSha256,
          evidenceParent: value("evidence"), outputParent: value("packageOutput"),
        } });
        text("packageStatus", "Package created. Compatibility still requires an approved disposable-worker trial.");
      } else {
        const path = value("packageInstaller");
        state.analysis = null; state.packageResult = null; state.analyzedPath = null; renderPackage();
        const analysis = await call("analyze_package", { installer: path });
        state.analysis = analysis; state.analyzedPath = path;
        if (analysis.options.length) $("packageProfile").value = analysis.options[0].profile;
        $("packageAssessmentOption").disabled = !analysis.options.some((option) => option.profile === "localSettingsAssessment");
        $("packageInteractiveOption").disabled = !analysis.options.some((option) => option.profile === "interactiveDocument");
        text("packageStatus", analysis.options.length ? "Supported installer identity. Choose an isolation preset and workflow." : "These installer bytes have no supported package recipe. Analysis is not a compatibility verdict.");
      }
      renderPackage(); await poll();
    } catch (error) { text("packageStatus", "Packaging action stopped. Read the error and preserve retained evidence before retrying."); displayLocalError(error); }
    finally { state.busy = false; applyControls(state.current, false); }
  }

  function renderReview(review) {
    show("reviewCard", !!review);
    if (!review) { state.reviewChallenge = null; return; }
    const newReview = state.reviewChallenge !== review.challengeId;
    if (newReview) { $("confirmation").value = ""; state.reviewChallenge = review.challengeId; }
    const summary = window.AiwDisplay.reviewSummary(review.recipeJson);
    show("reviewSummary", !!summary);
    show("reviewSummaryUnavailable", !summary);
    text("reviewExecution", summary ? summary.execution : "");
    text("reviewChanges", summary ? summary.changes : "");
    text("reviewLifetime", summary ? summary.lifetime : "");
    if (newReview || !summary) $("reviewDetails").open = !summary;
    text("reviewWorkflow", review.workflowName);
    text("reviewOperator", review.operatorIdentity);
    text("reviewEvidence", review.evidenceRoot);
    text("reviewWorkspace", review.workspace);
    text("reviewPlanHash", review.planHash);
    text("reviewChallenge", review.challengeId);
    text("exactConfirmation", review.exactConfirmation);
    text("recipeJson", pretty(review.recipeJson)); text("planJson", pretty(review.planJson)); text("approvalJson", pretty(review.approvalJson));
  }

  function pretty(input) {
    if (input == null) return "(not provided)";
    if (typeof input === "string") { try { return clean(JSON.stringify(JSON.parse(input), null, 2)); } catch (_) { return clean(input); } }
    try { return clean(JSON.stringify(input, null, 2)); } catch (_) { return "(unavailable)"; }
  }

  function renderResult(result) {
    show("resultCard", !!result);
    if (!result) return;
    const verified = result.outcome === "verified";
    text("resultEyebrow", verified ? "Verified workflow result" : "Retained workflow state");
    text("result-title", verified ? "Supported workflow verified" : result.outcome === "notRun" ? "Sandbox was not started" : "Workflow not fully verified");
    text("resultBadge", verified ? "Verified" : result.outcome === "notRun" ? "Not run" : "Needs review");
    $("resultBadge").classList.toggle("success", verified);
    text("resultRun", result.runId); text("resultWorkspace", result.workspace); text("resultEvidence", result.evidenceRoot); text("resultSummary", result.summary); text("reportMarkdown", result.reportMarkdown || "(report not included in this state)");
    $("export").disabled = !result.canExportDocument;
  }

  function renderError(error) {
    if (!error && state.localError) { displayLocalError(state.localError); return; }
    show("errorCard", !!error);
    if (!error) return;
    text("errorSummary", error.summary || "The workflow needs attention"); text("errorRemediation", error.remediation || "Inspect the retained evidence before taking another action."); text("errorDetail", error.detail || "No technical details were retained."); text("errorLocation", error.runId ? "Retained run: " + error.runId : "");
  }

  function renderProgress(snapshot) {
    const active = ["preparing", "review", "approved", "running", "exporting"].includes(snapshot.phase);
    show("progressCard", active || ["completed", "cancelled", "failed"].includes(snapshot.phase));
    show("progressTrack", ["preparing", "running", "exporting"].includes(snapshot.phase));
    const messages = { preparing: "Preparing or recording the reviewed plan. No Sandbox has started.", review: "Review the exact plan and type the literal confirmation.", approved: "Approval recorded. Sandbox has not started; press Start when ready.", running: "Start accepted. The backend is validating and executing the workflow. Wait for the retained result and cleanup.", exporting: "Exporting the last verified document to the selected new file.", completed: "The workflow finished; inspect its retained result below.", cancelled: "The workflow was cancelled; inspect the retained state before retrying.", failed: "The workflow failed; inspect the retained diagnostic and remediation." };
    text("progressSummary", messages[snapshot.phase] || "Ready.");
    const editing = snapshot.phase === "running" && snapshot.review && snapshot.review.workflowName === "Interactive Notepad++ document transfer";
    show("editingInstructions", editing);
    const running = snapshot.phase === "running";
    if (running && !state.startedAt) state.startedAt = Date.now();
    if (!running) state.startedAt = null;
    show("reviewCard", !!snapshot.review || ["approved"].includes(snapshot.phase));
    show("startBox", snapshot.phase === "approved");
    show("closeWarning", !!snapshot.closeRefused);
    if (snapshot.defaults && snapshot.defaults.evidence) {
      if (!value("evidence")) $("evidence").value = clean(snapshot.defaults.evidence);
      if (!value("packageOutput")) $("packageOutput").value = clean(snapshot.defaults.evidence);
    }
    if (snapshot.review) renderReview(snapshot.review);
  }

  function render(snapshot) {
    if (!snapshot) return;
    const previousPhase = state.current && state.current.phase;
    const previousCloseRefused = state.current && state.current.closeRefused;
    if (!state.current || state.current.workflowId !== snapshot.workflowId) {
      state.startedAt = null;
      text("elapsed", "Elapsed 00:00");
    }
    state.current = snapshot; text("phaseBadge", phaseLabel(snapshot.phase)); renderProgress(snapshot); renderResult(snapshot.result); renderError(snapshot.error);
    applyControls(snapshot, state.busy);
    if (previousPhase !== snapshot.phase) {
      const target = snapshot.error ? "errorCard" : snapshot.phase === "review" ? "reviewCard" : snapshot.phase === "approved" ? "startBox" : ["running", "exporting"].includes(snapshot.phase) ? "progressCard" : snapshot.result ? "resultCard" : null;
      if (target) $(target).scrollIntoView({ block: "start" });
    }
    if (snapshot.closeRefused && !previousCloseRefused) $("closeWarning").scrollIntoView({ block: "start" });
  }

  async function poll() {
    if (state.polling) return; state.polling = true;
    try { render(await call("get_state")); } catch (error) { displayLocalError(error); } finally { state.polling = false; }
  }

  async function action(name, args) { state.localError = null; state.busy = true; setBusy(true); try { await call(name, args); await poll(); } catch (error) { displayLocalError(error); } finally { state.busy = false; applyControls(state.current, false); } }

  function elapsed() { if (state.startedAt) { const seconds = Math.floor((Date.now() - state.startedAt) / 1000); text("elapsed", "Elapsed " + String(Math.floor(seconds / 60)).padStart(2, "0") + ":" + String(seconds % 60).padStart(2, "0")); } }

  $("chooseInstaller").addEventListener("click", () => choose(kind() === "bambu" ? "bambu-installer" : "installer", "installer"));
  $("chooseDocument").addEventListener("click", () => choose("document", "documentInput"));
  $("chooseEvidence").addEventListener("click", () => choose("evidence", "evidence"));
  $("chooseDestination").addEventListener("click", () => choose("destination", "destination"));
  $("chooseWorkspace").addEventListener("click", () => choose("workspace", "retainedWorkspace"));
  $("prepare").addEventListener("click", () => action("prepare_workflow", { kind: kind(), installer: value("installer"), documentInput: value("documentInput") || null, evidence: value("evidence"), operatorIdentity: value("operatorIdentity") }));
  $("approve").addEventListener("click", () => { const review = state.current && state.current.review; if (review) action("submit_approval", { workflowId: state.current.workflowId, challengeId: review.challengeId, confirmation: value("confirmation") }); });
  $("start").addEventListener("click", () => { const snapshot = state.current; if (snapshot) action("start_approved_workflow", { workflowId: snapshot.workflowId, challengeId: snapshot.startChallengeId }); });
  $("cancel").addEventListener("click", () => { const snapshot = state.current; if (snapshot && ["preparing", "review", "approved"].includes(snapshot.phase)) action("cancel_pending", { workflowId: snapshot.workflowId }); });
  $("export").addEventListener("click", () => action("export_document", { destination: value("destination") }));
  $("loadRetained").addEventListener("click", () => action("load_retained_report", { kind: value("retainedKind"), workspace: value("retainedWorkspace"), runId: value("retainedRunId") }));
  $("choosePackageInstaller").addEventListener("click", () => choose("installer", "packageInstaller"));
  $("choosePackageOutput").addEventListener("click", () => choose("package-output", "packageOutput"));
  $("choosePackageDocument").addEventListener("click", () => choose("document", "packageDocumentInput"));
  $("analyzePackage").addEventListener("click", () => packageAction(false));
  $("createPackage").addEventListener("click", () => packageAction(true));
  $("validatePackage").addEventListener("click", () => {
    const result = state.packageResult;
    if (!result || state.busy) return;
    return action("prepare_workflow", { kind: result.profile === "interactiveDocument" ? "interactive" : "assessment", installer: "",
      documentInput: result.profile === "interactiveDocument" ? value("packageDocumentInput") : null,
      evidence: value("evidence"), operatorIdentity: value("operatorIdentity"),
      package: { bundleRoot: result.bundle.bundlePath, manifestSha256: result.bundle.manifestSha256 } });
  });
  ["packageProfile", "packageIsolation"].forEach((id) => $(id).addEventListener("change", () => { renderPackage(); applyControls(state.current, state.busy); }));
  document.querySelectorAll("input[name=workflowKind]").forEach((radio) => radio.addEventListener("change", renderMode));
  setInterval(poll, 1000); setInterval(elapsed, 1000); poll();
}());
