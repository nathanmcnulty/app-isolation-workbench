const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const vm = require("node:vm");
const display = require("../ui/display.js");
const handoff = require("../ui/replay-handoff.js");

function requestData(command) {
  const json = command.match(/-InputObject @'\n([\s\S]+)\n'@/)[1];
  return JSON.parse(json);
}

const preparationInputs = {
  cli: "C:\\Tools & review\\aiw.exe",
  guestAgent: "C:\\Measured tools\\aiw-guest-agent.exe",
  guestAgentSha256: "B".repeat(64),
  evidenceParent: "D:\\Evidence set\\",
  operator: "--operator=O’Neil\u202e & $(kept literal); ' \"",
};

test("handoff carries exact reviewed arguments as PowerShell data", () => {
  const path = "C:\\Replay \\O'Neil & $(literal)\\";
  const manifestSha256 = "a".repeat(64);
  const command = handoff.buildCommand({path, manifestSha256}, preparationInputs);
  assert.doesNotMatch(command, /\u202e/u);
  assert.match(command, /\\u202e/u);
  assert.deepEqual(requestData(command), {
    cli: preparationInputs.cli,
    arguments: [
      "application", "prepare-assessment-package", "--package=" + path,
      "--expected-manifest-sha256=" + manifestSha256,
      "--guest-agent=" + preparationInputs.guestAgent,
      "--guest-agent-sha256=" + "b".repeat(64),
      "--evidence-parent=" + preparationInputs.evidenceParent,
      "--operator=" + preparationInputs.operator,
    ],
  });
  assert.doesNotMatch(command, /review-approval|approve|run start/);
  assert.throws(() => handoff.buildCommand(null, preparationInputs), /Verify the candidate/);
  assert.throws(() => handoff.buildCommand({path, manifestSha256}, {
    ...preparationInputs, guestAgentSha256: "0".repeat(64),
  }), /independently enrolled/);
  assert.throws(() => handoff.buildCommand({path, manifestSha256}, {
    ...preparationInputs, cli: "relative\\aiw.exe",
  }), /absolute Windows path/);
  assert.throws(() => handoff.buildCommand({path, manifestSha256}, {
    ...preparationInputs, operator: "name\n'@",
  }), /one line/);
});

test("Windows PowerShell passes the handoff arguments exactly to a native recorder", {
  skip: process.platform !== "win32",
}, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aiw-replay-arguments-"));
  const recorder = path.join(directory, "application");
  const script = path.join(directory, "prepare-text.ps1");
  const candidatePath = "C:\\Replay folders\\O'Neil & $(literal)\\";
  const manifestSha256 = "a".repeat(64);
  try {
    // Node receives "application" as an owned fixture script in this cwd.
    // The fixture only returns its arguments. No AIW binary is invoked.
    fs.writeFileSync(recorder, "process.stdout.write(JSON.stringify(process.argv.slice(2)));");
    fs.writeFileSync(script, handoff.buildCommand({ path: candidatePath, manifestSha256 }, {
      ...preparationInputs, cli: process.execPath,
    }));
    const observed = spawnSync("pwsh.exe", [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-File", script,
    ], { cwd: directory, encoding: "utf8", timeout: 15_000 });
    assert.ifError(observed.error);
    assert.equal(observed.status, 0, observed.stderr);
    assert.deepEqual(JSON.parse(observed.stdout), [
      "prepare-assessment-package",
      "--package=" + candidatePath,
      "--expected-manifest-sha256=" + manifestSha256,
      "--guest-agent=" + preparationInputs.guestAgent,
      "--guest-agent-sha256=" + "b".repeat(64),
      "--evidence-parent=" + preparationInputs.evidenceParent,
      "--operator=" + preparationInputs.operator,
    ]);
  } finally {
    fs.rmSync(recorder, { force: true });
    fs.rmSync(script, { force: true });
    fs.rmdirSync(directory);
  }
});

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
    window: { AiwDisplay: display, AiwReplayHandoff: handoff, __TAURI__: { core: { invoke: async (name, args) => {
      calls.push({name, args});
      if (name === "choose_input") return selected;
      assert.ok(["review_replay_packages", "review_msi_replay_package"].includes(name));
      return pending;
    } } } },
  };
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/replay-review.js"), "utf8"), context);
  assert.equal(element("reviewReplay").disabled, true);
  assert.equal(element("generateReplayCommand").disabled, true);
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
  assert.equal(element("generateReplayCommand").disabled, false);
  for (const [id, input] of Object.entries({
    replayHandoffCli: "cli",
    replayHandoffGuestAgent: "guestAgent",
    replayHandoffAgentSha256: "guestAgentSha256",
    replayHandoffEvidence: "evidenceParent",
    replayHandoffOperator: "operator",
  })) element(id).value = preparationInputs[input];

  const callsBeforeHandoff = calls.length;
  await click("generateReplayCommand");
  assert.equal(calls.length, callsBeforeHandoff);
  assert.equal(element("replayHandoffOutput").hidden, false);
  const command = element("replayHandoffCommand");
  assert.ok(requestData(command.value).arguments.includes("--package=" + candidate));
  assert.ok(requestData(command.value).arguments.includes("--expected-manifest-sha256=" + review.packageManifestSha256));
  element("replayHandoffOperator").value = "new operator";
  element("replayHandoffOperator").handlers.input();
  assert.equal(command.value, "");
  assert.equal(element("replayHandoffOutput").hidden, true);
  await click("generateReplayCommand");

  selected = null;
  await click("chooseReplayCandidate");
  assert.equal(element("replayReviewPin").value, review.packageManifestSha256);

  selected = baseline;
  await click("chooseReplayBaseline");
  assert.equal(element("replayReviewPin").value, "");
  assert.equal(element("replayReviewResult").hidden, true);
  assert.equal(command.value, "");
  assert.equal(element("generateReplayCommand").disabled, true);
  pending = Promise.resolve({ candidateReview: review, changes: { inputs: true, steps: false } });
  await click("reviewReplay");
  assert.equal(calls.at(-1).args.baseline, baseline);
  assert.equal(element("replayReviewPin").value, review.packageManifestSha256);
  assert.equal(element("replayReviewChanges").textContent, "Changed: inputs");
  assert.equal(element("replayReviewChanges").hidden, false);

  await click("generateReplayCommand");
  assert.ok(requestData(command.value).arguments.includes("--package=" + candidate));
  pending = { then(_, reject) { reject(new Error("replay file content differs")); } };
  await click("reviewReplay");
  assert.equal(element("replayReviewPin").value, "");
  assert.equal(element("replayReviewResult").hidden, true);
  assert.equal(element("replayReviewStatus").textContent, "replay file content differs");
  assert.equal(command.value, "");
  assert.equal(element("generateReplayCommand").disabled, true);

  await click("clearReplayBaseline");
  assert.equal(element("replayBaseline").value, "");
  assert.equal(element("clearReplayBaseline").disabled, true);
  assert.equal(calls.every(({name}) => ["choose_input", "review_replay_packages"].includes(name)), true);

  const type = element("replayType");
  const hash = element("replayExpectedHash");
  type.value = "msi";
  type.handlers.change();
  assert.equal(element("reviewReplay").disabled, true);
  assert.equal(element("chooseReplayBaseline").disabled, true);
  hash.value = "b".repeat(64);
  hash.handlers.input();
  pending = { then(_, reject) { reject(new Error("MSI replay package inventory or manifest hash differs")); } };
  await click("reviewReplay");
  assert.equal(calls.at(-1).name, "review_msi_replay_package");
  assert.equal(calls.at(-1).args.expectedManifestSha256, "b".repeat(64));
  assert.equal(element("generateReplayCommand").disabled, true);
  assert.match(element("replayReviewStatus").textContent, /manifest hash differs/);

  hash.value = "A".repeat(64);
  hash.handlers.input();
  pending = Promise.resolve({
    manifestSha256: "a".repeat(64),
    manifest: {
      installerSizeBytes: 4096, installScenario: "discover",
      originalSelection: {
        installerSha256: "c".repeat(64),
        candidate: { relativePath: "Example\\Tool.exe", sha256: "d".repeat(64) },
      },
    },
  });
  await click("reviewReplay");
  assert.equal(calls.at(-1).args.expectedManifestSha256, "a".repeat(64));
  assert.equal(calls.at(-1).args.baseline, undefined);
  assert.match(element("replayMsiInstaller").textContent, /app\.msi.*4096.*c{64}/);
  assert.match(element("replayMsiEntryPoint").textContent, /Example\\Tool\.exe.*d{64}/);
  const callsBeforeMsiHandoff = calls.length;
  await click("generateReplayCommand");
  assert.equal(calls.length, callsBeforeMsiHandoff);
  const args = requestData(command.value).arguments;
  assert.deepEqual(args.slice(0, 4), [
    "application", "prepare-msi-replay-package", "--package=" + candidate,
    "--expected-manifest-sha256=" + "a".repeat(64),
  ]);
  assert.equal(args.some((arg) => arg.startsWith("--operator=")), false);

  hash.value = "b".repeat(64);
  hash.handlers.input();
  assert.equal(command.value, "");
  assert.equal(element("generateReplayCommand").disabled, true);
  pending = { then(_, reject) { reject(new Error("MSI replay package payload or project differs")); } };
  await click("reviewReplay");
  assert.equal(element("replayReviewResult").hidden, true);
  assert.equal(element("replayMsiInstaller").hidden, true);
  assert.equal(command.value, "");
  assert.equal(element("generateReplayCommand").disabled, true);
  assert.equal(element("replayReviewStatus").textContent, "MSI replay package payload or project differs");
});
