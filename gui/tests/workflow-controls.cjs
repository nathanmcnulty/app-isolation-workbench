const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { clean } = require("../ui/display.js");

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
