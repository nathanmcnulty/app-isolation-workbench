(function (root) {
  "use strict";
  // Escape controls visibly rather than silently removing or interpreting them.
  const controls = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
  function clean(value) {
    return String(value == null ? "" : value).replace(controls, (character) =>
      "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"));
  }
  const api = Object.freeze({ clean });
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.AiwDisplay = api;
}(globalThis));
