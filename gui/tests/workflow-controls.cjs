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
