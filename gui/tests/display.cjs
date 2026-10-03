const { test } = require("node:test");
const assert = require("node:assert/strict");
const { clean } = require("../ui/display.js");

test("all bidi controls and terminal controls stay visibly identifiable", () => {
  for (const code of [0, 7, 8, 11, 12, 27, 31, 127, 0x061c, 0x200e, 0x200f,
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
