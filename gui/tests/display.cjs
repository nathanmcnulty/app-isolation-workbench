const { test } = require("node:test");
const assert = require("node:assert/strict");
const { clean, reviewSummary } = require("../ui/display.js");

test("VM MSIX review names the dedicated target, network, sign-in and recovery boundary", () => {
  const value={profile:"notepad-plus-plus-msix-vm107",worker:{vmId:107,checkpoint:"aiw-msix-worker107-tls-clean-r1"},workflow:"Install, edit, uninstall, collect, restore"};
  const summary=reviewSummary(value);
  assert.match(summary.execution,/dedicated VM107/);
  assert.match(summary.changes,/lab network/);
  assert.match(summary.changes,/automatic sign-in is cleared/);
  assert.match(summary.changes,/cold restore/);
  assert.match(summary.lifetime,/aiw-msix-worker107-tls-clean-r1/);
  assert.equal(reviewSummary({...value,worker:{vmId:106}}),null);
});

test("all bidi controls and terminal controls stay visibly identifiable", () => {
  for (const code of [0, 7, 8, 11, 12, 27, 31, ...Array.from({ length: 33 }, (_, i) => 127 + i), 0x061c, 0x200e, 0x200f,
    0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]) {
    assert.equal(clean("before" + String.fromCharCode(code) + "after"),
      "before\\u" + code.toString(16).padStart(4, "0") + "after");
  }
});
test("ordinary text, whitespace, Unicode and inert markup remain exact", () => {
  const value = "Résumé 中文\n\t<script>alert('test')</script>";
  assert.equal(clean(value), value);
  assert.equal(clean(null), "");
});

test("recipe overviews preserve backend access, data and scope prose", () => {
  const recipe = { schemaVersion: "aiw.dev/wsb-msi-recipe-inspection/v0alpha1", recipe: {
    data: { lifetime: "Output stays in the workspace; export is explicit." },
    limitations: ["Inspection only", "Elevated guest installation; standard-user application."],
    trustDeltas: ["300-second interactive document session", "Tools read-only; output untrusted"],
  } };
  assert.deepEqual(reviewSummary(JSON.stringify(recipe)), {
    execution: recipe.recipe.limitations[1], changes: recipe.recipe.trustDeltas.join("\n\n"), lifetime: recipe.recipe.data.lifetime,
  });
  const bambu = { schemaVersion: "aiw.dev/admin-bambu-recipe/v0alpha1", executionIdentity: "Standard-user export", dataLifetime: "No automatic host export", limits: "No slicing or printing", runPlan: { trustDeltas: ["Tools read-only; output untrusted"] } };
  assert.deepEqual(reviewSummary(bambu), { execution: bambu.executionIdentity, changes: "Tools read-only; output untrusted\n\nNo slicing or printing", lifetime: bambu.dataLifetime });
  delete bambu.runPlan;
  assert.equal(reviewSummary(bambu), null);
});

test("unknown or incomplete recipes do not get a guessed overview", () => {
  for (const value of [null, "{", [], {}, { schemaVersion: "future" },
    { schemaVersion: "aiw.dev/admin-bambu-recipe/v0alpha1", executionIdentity: "elevated", dataLifetime: "temporary" },
    { schemaVersion: "aiw.dev/wsb-msi-recipe-inspection/v0alpha1", recipe: { data: { lifetime: "temporary" }, limitations: ["", "execution"], trustDeltas: ["known", {}] } }]) {
    assert.equal(reviewSummary(value), null);
  }
});
