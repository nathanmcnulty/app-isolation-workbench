(function (root) {
  "use strict";
  const clean = value => String(value == null ? "" : value).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, " ").slice(0, 4096);
  const label = value => ({
    insufficientEvidence: "Insufficient evidence", notReached: "Not reached", unmeasured: "Unmeasured", passed: "Passed", failed: "Failed", cancelled: "Cancelled", partial: "Partial", unavailable: "Unavailable",
    install: "Install", launch: "Launch", openDocument: "Open document", editSaveDocument: "Edit / save document", close: "Close", uninstall: "Uninstall", stlTo3mfExport: "STL to 3MF export",
    beforeInstallCapture: "Capture before installation", afterInstallCapture: "Capture after installation", prepareDocument: "Prepare document", afterExerciseCapture: "Capture after use", prepareFixture: "Prepare fixture", export: "Export", collectArtifact: "Collect artifact",
    duplicateRun: "Duplicate run", evidenceRejected: "Missing or rejected evidence", projectUnreadable: "Project unavailable", projectInvalid: "Invalid project", interactiveSessionNotAssessment: "Interactive session is outside this assessment profile",
    ordinaryBaseline: "Ordinary baseline", independentHostMeasurements: "Independent host measurements", filesystemRegistryChanges: "Filesystem and registry changes", networkUiIpcObservations: "Network, UI and IPC observations", persistenceResidue: "Persistence residue", descendantCoverage: "Descendant coverage", offlineCanary: "Offline canary", effectiveBackendVerification: "Effective boundary verification", captureCompleteness: "Capture completeness", targetToken: "Target token"
  }[value] || clean(value));
  function filterRows(rows, filters) {
    return rows.filter(row => (!filters.application || row.application === filters.application) &&
      (!filters.outcome || row.outcome === filters.outcome) &&
      (!filters.function || (filters.status ? row.functions[filters.function] === filters.status : row.functions[filters.function] !== "unmeasured")) &&
      (filters.function || !filters.status || Object.values(row.functions).includes(filters.status)));
  }
  // Each controller serializes its native dialog/read/export. Epochs also reject stale completions.
  function controller(invoke, update) {
    let busy = false, epoch = 0, loaded = null;
    const emit = message => update({ busy, loaded, message });
    return {
      async open() {
        if (busy) return;
        busy = true; const request = ++epoch; emit("Verifying explicit retained selections…");
        try {
          const next = await invoke("open_results", {});
          if (request !== epoch) return;
          if (next) loaded = next;
          emit(next ? "Selection loaded. All results are historical observations." : "Selection cancelled; previous results retained.");
        } catch (error) { if (request === epoch) emit("Could not open selection: " + clean(error && error.message || error) + ". Previous results retained; no run action was requested."); }
        finally { if (request === epoch) { busy = false; emit(); } }
      },
      async export(format) {
        if (busy || !loaded) return;
        busy = true; const request = ++epoch; emit("Choose a new summary file outside retained locations…");
        try {
          const saved = await invoke("export_results", { token: loaded.token, format });
          if (request === epoch) emit(saved ? "Summary exported to the chosen new file." : "Export cancelled.");
        } catch (error) { if (request === epoch) emit("Export failed: " + clean(error && error.message || error)); }
        finally { if (request === epoch) { busy = false; emit(); } }
      },
      invalidate() { ++epoch; busy = false; loaded = null; emit("No selection loaded."); }
    };
  }
  const api = { clean, filterRows, controller };
  if (typeof module !== "undefined") module.exports = api;
  if (!root.document) return;
  const $ = id => root.document.getElementById(id);
  let loaded = null, rendered = null;
  const node = (tag, content) => { const n = root.document.createElement(tag); if (content != null) n.textContent = clean(content); return n; };
  function render() {
    const rows = loaded ? loaded.summary.rows : [];
    const filtered = filterRows(rows, { application: $("resultsApplication").value, outcome: $("resultsOutcome").value, function: $("resultsFunction").value, status: $("resultsFunctionStatus").value });
    $("resultsRows").replaceChildren();
    $("resultsCount").textContent = `${filtered.length} of ${rows.length} selections shown.`;
    if (!filtered.length) { const tr = node("tr"), td = node("td", rows.length ? "No results match these filters." : "No retained selections loaded."); td.colSpan = 6; tr.append(td); $("resultsRows").append(tr); }
    for (const row of filtered) {
      const tr = node("tr"), first = node("td"), details = node("details"), summary = node("summary", "Selection " + row.selection + (loaded.selectionLabels ? " · " + loaded.selectionLabels[row.selection - 1] : ""));
      details.append(summary);
      details.append(node("p", "Failure evidence: " + row.failureEvidence));
      if (row.unavailableReason) details.append(node("p", "Unavailable: " + label(row.unavailableReason)));
      details.append(node("p", "Stage progress (separate from function results)"));
      const stages = node("ul");
      for (const stage of row.stages) stages.append(node("li", label(stage.stage) + ": " + label(stage.status)));
      if (!row.stages.length) stages.append(node("li", "Stage progress unmeasured or not exposed by this report profile."));
      details.append(stages);
      details.append(node("p", "Evidence references — hashes only; no artifact is opened or executed"));
      const refs = node("ul");
      for (const ref of row.evidenceReferences) refs.append(node("li", ref.kind + ": " + ref.sha256));
      if (!row.evidenceReferences.length) refs.append(node("li", "No verified reference available."));
      details.append(refs); first.append(details); tr.append(first);
      tr.append(node("td", row.application + " / " + row.workflow), node("td", label(row.outcome)));
      const functions = node("td"), list = node("ul");
      for (const [name, result] of Object.entries(row.functions)) list.append(node("li", label(name) + ": " + label(result)));
      functions.append(list); tr.append(functions, node("td", row.evidenceGaps.map(label).join("; ")), node("td", row.historicalCleanupVerified === true ? "Verified in historical receipt" : row.historicalCleanupVerified === false ? "Not verified in historical receipt" : "Unmeasured"));
      $("resultsRows").append(tr);
    }
  }
  const invoke = (name, args) => {
    if (!root.__TAURI__?.core?.invoke) throw new Error("Desktop backend unavailable");
    return root.__TAURI__.core.invoke(name, args);
  };
  const controls = controller(invoke, state => {
    loaded = state.loaded;
    $("openResults").disabled = state.busy;
    $("resultsPanel").setAttribute("aria-busy", String(state.busy));
    $("exportResultsJson").disabled = $("exportResultsMarkdown").disabled = state.busy || !loaded;
    if (state.message) $("resultsStatus").textContent = clean(state.message);
    if (loaded !== rendered) { rendered = loaded; render(); }
  });
  $("openResults").addEventListener("click", async () => { await controls.open(); $("openResults").focus(); });
  $("exportResultsJson").addEventListener("click", async () => { await controls.export("json"); $("exportResultsJson").focus(); });
  $("exportResultsMarkdown").addEventListener("click", async () => { await controls.export("markdown"); $("exportResultsMarkdown").focus(); });
  for (const id of ["resultsApplication", "resultsOutcome", "resultsFunction", "resultsFunctionStatus"]) $(id).addEventListener("change", render);
  function view(results) {
    $("resultsPanel").classList.toggle("hidden", !results); $("workflowPanel").classList.toggle("hidden", results);
    $("resultsView").setAttribute("aria-pressed", String(results)); $("workflowView").setAttribute("aria-pressed", String(!results));
    $(results ? "resultsHeading" : "workflowView").focus();
  }
  $("resultsView").addEventListener("click", () => view(true));
  $("workflowView").addEventListener("click", () => view(false));
  render();
})(typeof window !== "undefined" ? window : globalThis);
