const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const display = require("../ui/display.js");

for (const profile of ["localSettingsAssessment", "interactiveDocument"]) test(`package ${profile} binds analysis and changing installer invalidates it without execution`, async () => {
  const elements = new Map(), scrolled = [];
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "", textContent: "", innerHTML: "untouched", disabled: false, hidden: false, handlers: {},
      classList: { toggle(name, on) { if (name === "hidden") element(id).hidden = on; } },
      scrollIntoView() { scrolled.push(id); }, addEventListener(event, handler) { this.handlers[event] = handler; },
    });
    return elements.get(id);
  };
  const calls = [], intervals = [];
  let finishAnalysis;
  const analysisGate = new Promise((resolve) => { finishAnalysis = resolve; });
  let selected = "C:\\input\\notepad.msi";
  let failCreation = false;
  let phase = "completed";
  const analysis = {
    installer: { sha256: "installer-hash" },
    options: [{ profile, isolationPreset: "offlineWindowsSandbox", projectSha256: "project-hash", description: "<script>inert recipe</script>" }],
    limitations: ["Not a compatibility verdict"],
  };
  const context = {
    document: { getElementById: element, querySelector: () => ({ value: "assessment" }), querySelectorAll: () => [] },
    window: { AiwDisplay: display, __TAURI__: { core: { invoke: async (name, args) => {
      calls.push({ name, args });
      if (name === "choose_input") return selected;
      if (name === "analyze_package") return analysisGate;
      if (name === "create_package") {
        if (failCreation) throw new Error("Retain partial output");
        phase = "packaging";
        await intervals.find((callback) => callback.name === "poll")();
        phase = "completed";
        return { profile, next: "Not compatibility-certified", bundle: { bundlePath: "C:\\out\\bundle", manifestSha256: "manifest-hash" } };
      }
      return { phase, result: { outcome: "verified", runId: "previous-trial" }, defaults: { evidence: "C:\\evidence" } };
    } } } },
    setInterval: (callback) => intervals.push(callback),
  };
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/app.js"), "utf8"), context);
  await new Promise(setImmediate);
  element("packageIsolation").value = "offlineWindowsSandbox";
  await element("choosePackageInstaller").handlers.click();
  const analyzing = element("analyzePackage").handlers.click();
  assert.equal(element("choosePackageInstaller").disabled, true);
  assert.equal(element("analyzePackage").disabled, true);
  await element("analyzePackage").handlers.click();
  assert.equal(calls.filter((call) => call.name === "analyze_package").length, 1);
  finishAnalysis(analysis);
  await analyzing;
  assert.equal(element("packageSelection").hidden, false);
  assert.equal(element("packageInteractiveOption").disabled, profile !== "interactiveDocument");
  assert.equal(element("packageDescription").textContent, "<script>inert recipe</script>");
  assert.equal(element("packageDescription").innerHTML, "untouched");
  selected = "C:\\out";
  await element("choosePackageOutput").handlers.click();
  scrolled.length = 0;
  await element("createPackage").handlers.click();
  assert.deepEqual(scrolled, ["packageResult"]);
  assert.equal(element("resultRun").textContent, "previous-trial");
  const request = calls.find((call) => call.name === "create_package").args.request;
  assert.equal(request.installer, "C:\\input\\notepad.msi");
  assert.equal(request.analyzedInstallerSha256, "installer-hash");
  assert.equal(request.analyzedProjectSha256, "project-hash");
  assert.equal(request.isolationPreset, "offlineWindowsSandbox");
  assert.equal(request.profile, profile);
  assert.equal(element("packageResult").hidden, false);
  assert.equal(element("packageResultHash").textContent, "Manifest SHA-256: manifest-hash");
  assert.equal(calls.some((call) => call.name === "prepare_workflow"), false);
  assert.equal(element("packageDocumentField").hidden, profile !== "interactiveDocument");
  selected = "C:\\input\\document.txt";
  await element("choosePackageDocument").handlers.click();
  await element("validatePackage").handlers.click();
  const validation = calls.find((call) => call.name === "prepare_workflow").args;
  assert.equal(validation.package.bundleRoot, "C:\\out\\bundle");
  assert.equal(validation.package.manifestSha256, "manifest-hash");
  assert.equal(validation.kind, profile === "interactiveDocument" ? "interactive" : "assessment");
  assert.equal(validation.documentInput, profile === "interactiveDocument" ? selected : null);
  failCreation = true;
  await element("createPackage").handlers.click();
  assert.equal(element("packageResult").hidden, true);
  assert.match(element("packageStatus").textContent, /stopped/);
  await element("validatePackage").handlers.click();
  assert.equal(calls.filter((call) => call.name === "prepare_workflow").length, 1);
  selected = "C:\\input\\changed.msi";
  await element("choosePackageInstaller").handlers.click();
  assert.equal(element("packageSelection").hidden, true);
  assert.equal(element("createPackage").disabled, true);
  await element("createPackage").handlers.click();
  assert.equal(calls.filter((call) => call.name === "create_package").length, 2);
  assert.equal(calls.some((call) => ["submit_approval", "start_approved_workflow"].includes(call.name)), false);
});

test("packaging IPC has both generated commands and local-window permissions", () => {
  const manifest = fs.readFileSync(require.resolve("../build.rs"), "utf8");
  const capability = JSON.parse(fs.readFileSync(require.resolve("../capabilities/administrator.json"), "utf8"));
  assert.deepEqual(capability.windows, ["main"]);
  for (const command of ["analyze_package", "create_package"]) {
    assert.ok(manifest.includes('"' + command + '"'));
    assert.ok(capability.permissions.includes("allow-" + command.replaceAll("_", "-")));
  }
});
