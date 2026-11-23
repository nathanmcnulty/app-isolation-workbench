(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const invoke = window.__TAURI__?.core?.invoke;
  const clean = window.AiwDisplay.clean;
  const changeLabels = {
    manifestBytes: "manifest bytes",
    project: "project",
    compiledPlan: "compiled plan",
    portablePayload: "portable payload",
    inputs: "inputs",
    steps: "workflow steps",
    expectedOutputs: "expected outputs",
    requestedRunConditions: "requested run conditions",
  };
  const chooseCandidate = $("chooseReplayCandidate");
  const chooseBaseline = $("chooseReplayBaseline");
  const clearBaseline = $("clearReplayBaseline");
  const reviewButton = $("reviewReplay");
  const candidate = $("replayCandidate");
  const baseline = $("replayBaseline");
  const result = $("replayReviewResult");
  const status = $("replayReviewStatus");
  const pin = $("replayReviewPin");
  const changes = $("replayReviewChanges");
  let busy = false;

  function updateControls() {
    chooseCandidate.disabled = chooseBaseline.disabled = busy || !invoke;
    clearBaseline.disabled = busy || !baseline.value;
    reviewButton.disabled = busy || !invoke || !candidate.value;
  }

  function clearReview(message) {
    result.classList.toggle("hidden", true);
    changes.classList.toggle("hidden", true);
    changes.textContent = "";
    $("replayReviewMode").textContent = "";
    $("replayReviewDetails").textContent = "";
    pin.value = "";
    status.textContent = message;
  }

  async function withBusy(work) {
    if (busy || !invoke) return;
    busy = true;
    updateControls();
    try {
      await work();
    } catch (error) {
      clearReview(clean(error?.message || error));
    } finally {
      busy = false;
      updateControls();
    }
  }

  function selectionChanged() {
    clearReview(candidate.value ? "Ready to verify the selected packages." : "Choose a candidate package to begin.");
    updateControls();
  }

  function choose(input) {
    return withBusy(async () => {
      const selected = await invoke("choose_input", { kind: "workspace" });
      if (selected != null) {
        input.value = selected;
        selectionChanged();
      }
    });
  }

  chooseCandidate.addEventListener("click", () => choose(candidate));
  chooseBaseline.addEventListener("click", () => choose(baseline));
  clearBaseline.addEventListener("click", () => {
    if (busy) return;
    baseline.value = "";
    selectionChanged();
  });
  reviewButton.addEventListener("click", () => {
    if (!candidate.value) return;
    return withBusy(async () => {
      clearReview("Verifying the selected packages…");
      const response = await invoke("review_replay_packages", {
        candidate: candidate.value,
        baseline: baseline.value || null,
      });
      const review = response.candidateReview || response;
      const mode = { ordinary: "Ordinary user", classicAppContainer: "Classic AppContainer" }[review.mode] || review.mode;
      $("replayReviewMode").textContent = clean("Requested mode: " + mode + " · Scenario: " + review.scenarioId);
      if (response.changes) {
        const labels = Object.keys(changeLabels).filter((key) => response.changes[key]).map((key) => changeLabels[key]);
        changes.textContent = labels.length ? "Changed: " + labels.join(", ") : "The verified package declarations are identical.";
        changes.classList.toggle("hidden", false);
      }
      pin.value = review.packageManifestSha256;
      $("replayReviewDetails").textContent = clean(JSON.stringify(review, null, 2));
      status.textContent = baseline.value ? "Both packages verified." : "Candidate package verified.";
      result.classList.toggle("hidden", false);
    });
  });
  if (!invoke) status.textContent = "Open the Workbench desktop app to verify a package.";
  updateControls();
}());
