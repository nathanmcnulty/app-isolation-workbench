const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { clean } = require("../ui/display.js");
const display = require("../ui/display.js");

test("verified transfer restores destination selection after a busy action", async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "", disabled: false, handlers: {},
      classList: { toggle() {} }, scrollIntoView() {},
      addEventListener(event, handler) { this.handlers[event] = handler; },
    });
    return elements.get(id);
  };
  const intervals = [];
  let snapshot = { phase: "idle", workflowId: null };
  const context = {
    document: {
      getElementById: element,
      querySelector: () => ({ value: "interactive" }),
      querySelectorAll: () => [],
    },
    window: { AiwDisplay: { clean }, __TAURI__: { core: { invoke: async (name) => {
      if (name === "prepare_workflow") snapshot = { phase: "preparing", workflowId: "first" };
      return snapshot;
    } } } },
    setInterval: (callback) => intervals.push(callback),
  };
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/app.js"), "utf8"), context);
  await new Promise(setImmediate);
  await element("prepare").handlers.click();
  assert.equal(element("chooseDestination").disabled, true);
  snapshot = { phase: "completed", workflowId: "first", result: { outcome: "verified", canExportDocument: true } };
  await intervals.find((callback) => callback.name === "poll")();
  assert.equal(element("chooseDestination").disabled, false);
  assert.equal(element("export").disabled, false);
  snapshot.result.canExportDocument = false;
  await intervals.find((callback) => callback.name === "poll")();
  assert.equal(element("chooseDestination").disabled, true);
  assert.equal(element("export").disabled, true);
});

test("review overview stays inert, preserves expanded details, and resets on a new challenge", async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "", textContent: "", innerHTML: "untouched", open: false, disabled: false, hidden: false, handlers: {},
      classList: { toggle(name, on) { if (name === "hidden") element(id).hidden = on; } },
      scrollIntoView() {}, addEventListener(event, handler) { this.handlers[event] = handler; },
    });
    return elements.get(id);
  };
  const recipe = { schemaVersion: "aiw.dev/admin-bambu-recipe/v0alpha1", executionIdentity: "<img src=x>\u202eexecution", dataLifetime: "Export is explicit", limits: "No printing", runPlan: { trustDeltas: ["Tools read-only; output untrusted"] } };
  let snapshot = { phase: "review", workflowId: "fixed", review: { challengeId: "one", recipeJson: JSON.stringify(recipe), planJson: '{"fixed":true}', approvalJson: "{}", exactConfirmation: "approve exact-hash", planHash: "exact-hash" } };
  const intervals = [], calls = [];
  const context = {
    document: { getElementById: element, querySelector: () => ({ value: "bambu" }), querySelectorAll: () => [] },
    window: { AiwDisplay: display, __TAURI__: { core: { invoke: async (name, args) => { calls.push({ name, args }); return snapshot; } } } },
    setInterval: (callback) => intervals.push(callback),
  };
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/app.js"), "utf8"), context);
  await new Promise(setImmediate);
  const poll = intervals.find((callback) => callback.name === "poll");
  assert.equal(element("reviewDetails").open, false);
  assert.equal(element("reviewExecution").textContent, "<img src=x>\\u202eexecution");
  assert.equal(element("reviewExecution").innerHTML, "untouched");
  assert.equal(element("exactConfirmation").textContent, "approve exact-hash");
  element("reviewDetails").open = true;
  element("confirmation").value = "approve exact-hash";
  await poll();
  assert.equal(element("reviewDetails").open, true);
  assert.equal(element("confirmation").value, "approve exact-hash");
  await element("approve").handlers.click();
  const approval = calls.find((call) => call.name === "submit_approval");
  assert.equal(approval.args.confirmation, "approve exact-hash");
  assert.equal(approval.args.challengeId, "one");
  assert.equal(calls.some((call) => call.name === "start_approved_workflow"), false);
  snapshot.review = { ...snapshot.review, challengeId: "two", recipeJson: "{}" };
  await poll();
  assert.equal(element("reviewDetails").open, true);
  assert.equal(element("reviewSummary").hidden, true);
  assert.equal(element("reviewSummaryUnavailable").hidden, false);
  assert.equal(element("reviewExecution").textContent, "");
  assert.equal(element("confirmation").value, "");
  assert.match(element("planJson").textContent, /"fixed": true/);
});

test("Bambu mode selects the EXE path and dispatches the fixed workflow without export", async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "", textContent: "", placeholder: "", disabled: false, handlers: {},
      classList: { toggle() {} }, scrollIntoView() {},
      addEventListener(event, handler) { this.handlers[event] = handler; },
    });
    return elements.get(id);
  };
  let selectedKind = "assessment";
  const radios = ["assessment", "interactive", "bambu"].map((value) => ({ value, disabled: false, handlers: {}, addEventListener(event, handler) { this.handlers[event] = handler; } }));
  const calls = [];
  const intervals = [];
  let snapshot = { phase: "idle", workflowId: null };
  const context = {
    document: {
      getElementById: element,
      querySelector: () => ({ value: selectedKind }),
      querySelectorAll: () => radios,
    },
    window: { AiwDisplay: { clean }, __TAURI__: { core: { invoke: async (name, args) => {
      calls.push({ name, args });
      if (name === "choose_input") return "C:\\input\\BambuStudio.exe";
      if (name === "prepare_workflow") snapshot = { phase: "preparing", workflowId: "bambu-run" };
      return snapshot;
    } } } },
    setInterval: (callback) => intervals.push(callback),
  };
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/app.js"), "utf8"), context);
  await new Promise(setImmediate);
  selectedKind = "bambu";
  radios[2].handlers.change();
  assert.equal(element("chooseInstaller").textContent, "Choose EXE");
  assert.match(element("setupHint").textContent, /fixed STL input is package supplied/);
  await element("chooseInstaller").handlers.click();
  assert.equal(calls.at(-1).args.kind, "bambu-installer");
  element("evidence").value = "C:\\evidence";
  element("operatorIdentity").value = "operator";
  await element("prepare").handlers.click();
  const dispatch = calls.find((call) => call.name === "prepare_workflow");
  assert.equal(dispatch.args.kind, "bambu");
  assert.equal(dispatch.args.documentInput, null);
  snapshot = { phase: "completed", workflowId: "bambu-run", result: { outcome: "verified", canExportDocument: false } };
  await intervals.find((callback) => callback.name === "poll")();
  assert.equal(element("chooseDestination").disabled, true);
  assert.equal(element("export").disabled, true);
});
