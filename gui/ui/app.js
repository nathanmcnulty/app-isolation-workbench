(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const invoke = window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke;
  const state = { current: null, polling: false, timer: null, startedAt: null };
  const forbidden = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g;
  const clean = (value) => String(value == null ? "" : value).replace(forbidden, "�");
  const text = (id, value) => { $(id).textContent = clean(value); };
  const show = (id, visible) => $(id).classList.toggle("hidden", !visible);
  const value = (id) => $(id).value.trim();
  const kind = () => document.querySelector("input[name=workflowKind]:checked").value;
  const phaseLabel = (phase) => ({ idle: "Ready", preparing: "Preparing", review: "Review required", approved: "Approved · Start required", running: "Running", completed: "Completed", cancelled: "Cancelled", failed: "Needs attention", exporting: "Exporting" }[phase] || "Loading state");

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
      if (selected != null) text(inputId, selected), $(inputId).value = clean(selected);
    } catch (error) { displayLocalError(error); }
  }

  function displayLocalError(error) {
    text("errorSummary", "The desktop action could not be completed");
    text("errorRemediation", errorText(error));
    text("errorDetail", "");
    text("errorLocation", "No workflow state was changed.");
    show("errorCard", true);
  }

  function setBusy(busy) {
    ["prepare", "approve", "start", "chooseInstaller", "chooseDocument", "chooseEvidence", "chooseDestination", "export", "loadRetained"].forEach((id) => { if ($(id)) $(id).disabled = busy; });
  }

  function renderReview(review) {
    show("reviewCard", !!review);
    if (!review) return;
    text("reviewWorkflow", kind() === "interactive" ? "Interactive document" : "Assessment");
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
    text("resultRun", result.runId); text("resultWorkspace", result.workspace); text("resultEvidence", result.evidenceRoot); text("resultSummary", result.summary); text("reportMarkdown", result.reportMarkdown || "(report not included in this state)");
    $("export").disabled = !result.canExportDocument;
  }

  function renderError(error) {
    show("errorCard", !!error);
    if (!error) return;
    text("errorSummary", error.summary || "The workflow needs attention"); text("errorRemediation", error.remediation || "Inspect the retained evidence before taking another action."); text("errorDetail", error.detail || "No technical details were retained."); text("errorLocation", error.runId ? "Retained run: " + error.runId : "");
  }

  function renderProgress(snapshot) {
    const active = ["preparing", "review", "approved", "running", "exporting"].includes(snapshot.phase);
    show("progressCard", active || ["completed", "cancelled", "failed"].includes(snapshot.phase));
    const messages = { preparing: "Preparing a reviewable plan. No Sandbox has started.", review: "Review the exact plan and type the literal confirmation.", approved: "Approval recorded. Sandbox has not started; press Start when ready.", running: "Sandbox is running. Wait for the backend to finish and record cleanup.", exporting: "Exporting the last verified document to the selected new file.", completed: "The workflow completed and the retained result is available.", cancelled: "The workflow was cancelled; inspect the retained state before retrying.", failed: "The workflow failed; inspect the retained diagnostic and remediation." };
    text("progressSummary", messages[snapshot.phase] || "Ready.");
    const running = snapshot.phase === "running";
    if (running && !state.startedAt) state.startedAt = Date.now();
    if (!running) state.startedAt = null;
    show("reviewCard", !!snapshot.review || ["approved"].includes(snapshot.phase));
    show("startBox", snapshot.phase === "approved");
    $("start").disabled = snapshot.phase !== "approved";
    $("approve").disabled = snapshot.phase !== "review";
    if (snapshot.defaults && snapshot.defaults.evidence && !value("evidence")) $("evidence").value = clean(snapshot.defaults.evidence);
    if (snapshot.review) renderReview(snapshot.review);
  }

  function render(snapshot) {
    if (!snapshot) return;
    state.current = snapshot; text("phaseBadge", phaseLabel(snapshot.phase)); renderProgress(snapshot); renderResult(snapshot.result); renderError(snapshot.error);
    const locked = ["preparing", "running", "exporting"].includes(snapshot.phase); setBusy(locked);
    if (snapshot.phase === "idle" || snapshot.phase === "cancelled" || snapshot.phase === "failed") $("prepare").disabled = false;
  }

  async function poll() {
    if (state.polling) return; state.polling = true;
    try { render(await call("get_state")); } catch (error) { displayLocalError(error); } finally { state.polling = false; }
  }

  async function action(name, args) { setBusy(true); try { await call(name, args); await poll(); } catch (error) { displayLocalError(error); } finally { setBusy(false); if (state.current) setBusy(["preparing", "running", "exporting"].includes(state.current.phase)); } }

  function elapsed() { if (state.startedAt) { const seconds = Math.floor((Date.now() - state.startedAt) / 1000); text("elapsed", "Elapsed " + String(Math.floor(seconds / 60)).padStart(2, "0") + ":" + String(seconds % 60).padStart(2, "0")); } }

  $("chooseInstaller").addEventListener("click", () => choose("installer", "installer"));
  $("chooseDocument").addEventListener("click", () => choose("document", "documentInput"));
  $("chooseEvidence").addEventListener("click", () => choose("evidence", "evidence"));
  $("chooseDestination").addEventListener("click", () => choose("destination", "destination"));
  $("chooseWorkspace").addEventListener("click", () => choose("workspace", "retainedWorkspace"));
  $("prepare").addEventListener("click", () => action("prepare_workflow", { kind: kind(), installer: value("installer"), documentInput: value("documentInput") || null, evidence: value("evidence"), operatorIdentity: value("operatorIdentity") }));
  $("approve").addEventListener("click", () => { const review = state.current && state.current.review; if (review) action("submit_approval", { workflowId: state.current.workflowId, challengeId: review.challengeId, confirmation: value("confirmation") }); });
  $("start").addEventListener("click", () => { const snapshot = state.current; if (snapshot) action("start_approved_workflow", { workflowId: snapshot.workflowId, challengeId: snapshot.startChallengeId }); });
  $("export").addEventListener("click", () => action("export_document", { destination: value("destination") }));
  $("loadRetained").addEventListener("click", () => action("load_retained_report", { kind: value("retainedKind"), workspace: value("retainedWorkspace"), runId: value("retainedRunId") }));
  document.querySelectorAll("input[name=workflowKind]").forEach((radio) => radio.addEventListener("change", () => { show("documentField", kind() === "interactive"); }));
  setInterval(poll, 1000); setInterval(elapsed, 1000); poll();
}());
