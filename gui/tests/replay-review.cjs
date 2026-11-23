const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const display = require("../ui/display.js");

test("replay review uses only read-only package commands and invalidates the pin on input changes", async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "", textContent: "", innerHTML: "untouched", disabled: false, hidden: false,
      handlers: {},
      classList: { toggle(name, on) { if (name === "hidden") element(id).hidden = on; } },
      addEventListener(name, handler) { this.handlers[name] = handler; },
    });
    return elements.get(id);
  };
  const click = (id) => element(id).handlers.click();
  const review = {
    packageManifestSha256: "a".repeat(64), scenarioId: "inert-fixture",
    mode: "ordinary", inputs: [], steps: [{type: "observeFile", path: "<b>local fixture</b>"}],
    expectedOutputs: [],
  };
  const calls = [];
  const candidate = "C:\\fixtures\\candidate", baseline = "C:\\fixtures\\baseline";
  let selected = candidate, finish;
  let pending = new Promise((resolve) => { finish = resolve; });
  const context = {
    document: { getElementById: element },
    window: { AiwDisplay: display, __TAURI__: { core: { invoke: async (name, args) => {
      calls.push({name, args});
      if (name === "choose_input") return selected;
      assert.equal(name, "review_replay_packages");
      return pending;
    } } } },
  };
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/replay-review.js"), "utf8"), context);
  assert.equal(element("reviewReplay").disabled, true);
  await click("chooseReplayCandidate");
  assert.equal(element("reviewReplay").disabled, false);
  const verifying = click("reviewReplay");
  assert.equal(element("chooseReplayCandidate").disabled, true);
  assert.equal(element("reviewReplay").disabled, true);
  await click("reviewReplay");
  assert.equal(calls.filter(({name}) => name === "review_replay_packages").length, 1);
  assert.equal(calls.at(-1).args.candidate, candidate);
  assert.equal(calls.at(-1).args.baseline, null);
  finish(review);
  await verifying;

  assert.equal(element("replayReviewPin").value, review.packageManifestSha256);
  assert.equal(element("replayReviewResult").hidden, false);
  assert.equal(element("replayReviewChanges").hidden, true);
  assert.match(element("replayReviewDetails").textContent, /<b>local fixture<\/b>/);
  assert.equal(element("replayReviewDetails").innerHTML, "untouched");

  selected = null;
  await click("chooseReplayCandidate");
  assert.equal(element("replayReviewPin").value, review.packageManifestSha256);

  selected = baseline;
  await click("chooseReplayBaseline");
  assert.equal(element("replayReviewPin").value, "");
  assert.equal(element("replayReviewResult").hidden, true);
  pending = Promise.resolve({ candidateReview: review, changes: { inputs: true, steps: false } });
  await click("reviewReplay");
  assert.equal(calls.at(-1).args.baseline, baseline);
  assert.equal(element("replayReviewPin").value, review.packageManifestSha256);
  assert.equal(element("replayReviewChanges").textContent, "Changed: inputs");
  assert.equal(element("replayReviewChanges").hidden, false);

  pending = { then(_, reject) { reject(new Error("replay file content differs")); } };
  await click("reviewReplay");
  assert.equal(element("replayReviewPin").value, "");
  assert.equal(element("replayReviewResult").hidden, true);
  assert.equal(element("replayReviewStatus").textContent, "replay file content differs");

  await click("clearReplayBaseline");
  assert.equal(element("replayBaseline").value, "");
  assert.equal(element("clearReplayBaseline").disabled, true);
  assert.equal(calls.every(({name}) => ["choose_input", "review_replay_packages"].includes(name)), true);
});
