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
  const packageType = $("replayType");
  const expectedHash = $("replayExpectedHash");
  const isMsi = () => packageType.value === "msi";
  const manifestPin = () => expectedHash.value.trim().toLowerCase();
  const installer = $("replayMsiInstaller");
  const entryPoint = $("replayMsiEntryPoint");
  const result = $("replayReviewResult");
  const status = $("replayReviewStatus");
  const pin = $("replayReviewPin");
  const changes = $("replayReviewChanges");
  const generateCommand = $("generateReplayCommand");
  const handoffCommand = $("replayHandoffCommand");
  const handoffStatus = $("replayHandoffStatus");
  const handoffFields = {
    cli: $("replayHandoffCli"),
    guestAgent: $("replayHandoffGuestAgent"),
    guestAgentSha256: $("replayHandoffAgentSha256"),
    evidenceParent: $("replayHandoffEvidence"),
    operator: $("replayHandoffOperator"),
  };
  let busy = false;
  let reviewedCandidate = null;

  function clearCommand() {
    handoffCommand.value = "";
    $("replayHandoffOutput").classList.toggle("hidden", true);
    handoffStatus.textContent = "";
  }

  function updateControls() {
    const msi = isMsi();
    packageType.disabled = expectedHash.disabled = busy || !invoke;
    $("replayExpectedHashField").classList.toggle("hidden", !msi);
    $("replayBaselineField").classList.toggle("hidden", msi);
    $("replayHandoffOperatorField").classList.toggle("hidden", msi);
    clearBaseline.classList.toggle("hidden", msi);
    chooseCandidate.disabled = chooseBaseline.disabled = busy || !invoke;
    chooseBaseline.disabled ||= msi;
    clearBaseline.disabled = busy || msi || !baseline.value;
    reviewButton.disabled = busy || !invoke || !candidate.value || (msi && !/^[a-f0-9]{64}$/.test(manifestPin()));
    generateCommand.disabled = busy || !reviewedCandidate;
  }

  function clearReview(message) {
    reviewedCandidate = null;
    clearCommand();
    result.classList.toggle("hidden", true);
    changes.classList.toggle("hidden", true);
    changes.textContent = "";
    $("replayReviewMode").textContent = "";
    $("replayReviewDetails").textContent = "";
    for (const field of [installer, entryPoint]) {
      field.textContent = "";
      field.classList.toggle("hidden", true);
    }
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
  packageType.addEventListener("change", selectionChanged);
  expectedHash.addEventListener("input", selectionChanged);
  chooseBaseline.addEventListener("click", () => choose(baseline));
  clearBaseline.addEventListener("click", () => {
    if (busy) return;
    baseline.value = "";
    selectionChanged();
  });
  Object.values(handoffFields).forEach((field) => field.addEventListener("input", clearCommand));
  generateCommand.addEventListener("click", () => {
    if (busy || !reviewedCandidate) return;
    clearCommand();
    try {
      const inputs = Object.fromEntries(Object.entries(handoffFields).map(([name, field]) => [name, field.value]));
      handoffCommand.value = window.AiwReplayHandoff.buildCommand(reviewedCandidate, inputs);
      $("replayHandoffOutput").classList.toggle("hidden", false);
      handoffStatus.textContent = "Preparation command ready for manual review.";
    } catch (error) {
      handoffStatus.textContent = clean(error.message);
    }
  });

  reviewButton.addEventListener("click", () => {
    if (reviewButton.disabled) return;
    return withBusy(async () => {
      clearReview("Verifying the selected packages…");
      if (isMsi()) {
        const review = await invoke("review_msi_replay_package", {
          candidate: candidate.value, expectedManifestSha256: manifestPin(),
        });
        const manifest = review.manifest;
        const selection = manifest.originalSelection;
        reviewedCandidate = { type: "msi", path: candidate.value, manifestSha256: review.manifestSha256 };
        $("replayReviewMode").textContent = clean("Install-only preparation · Scenario: " + manifest.installScenario);
        installer.textContent = clean(`Installer: app.msi · ${manifest.installerSizeBytes} bytes · SHA-256 ${selection.installerSha256}`);
        entryPoint.textContent = clean(`Reviewed entry point: ${selection.candidate.relativePath} · SHA-256 ${selection.candidate.sha256}`);
        installer.classList.toggle("hidden", false);
        entryPoint.classList.toggle("hidden", false);
        pin.value = review.manifestSha256;
        $("replayReviewDetails").textContent = clean(JSON.stringify(review, null, 2));
        status.textContent = "MSI package verified. A fresh install must match the reviewed entry point before launch.";
        result.classList.toggle("hidden", false);
        return;
      }
      const selection = { candidate: candidate.value, baseline: baseline.value || null };
      const response = await invoke("review_replay_packages", selection);
      const review = response.candidateReview || response;
      reviewedCandidate = { path: selection.candidate, manifestSha256: review.packageManifestSha256 };
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
