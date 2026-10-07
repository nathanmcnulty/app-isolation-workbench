(function (root) {
  "use strict";
  // Escape controls visibly rather than silently removing or interpreting them.
  const controls = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
  function clean(value) {
    return String(value == null ? "" : value).replace(controls, (character) =>
      "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"));
  }
  // Project existing backend prose only; this view grants no execution authority.
  function reviewSummary(input) {
    let source;
    try { source = typeof input === "string" ? JSON.parse(input) : input; } catch (_) { return null; }
    const prose = (value) => typeof value === "string" && value.trim().length > 0;
    if (source && source.schemaVersion === "aiw.dev/wsb-msi-recipe-inspection/v0alpha1") {
      const recipe = source.recipe;
      if (!recipe || !recipe.data || !prose(recipe.data.lifetime) ||
          !Array.isArray(recipe.trustDeltas) || !recipe.trustDeltas.length || !recipe.trustDeltas.every(prose) ||
          !Array.isArray(recipe.limitations) || !prose(recipe.limitations[1])) return null;
      return { execution: recipe.limitations[1], changes: recipe.trustDeltas.join("\n\n"), lifetime: recipe.data.lifetime };
    }
    if (source && source.schemaVersion === "aiw.dev/admin-bambu-recipe/v0alpha1" &&
        prose(source.executionIdentity) && prose(source.dataLifetime) && prose(source.limits) &&
        source.runPlan && Array.isArray(source.runPlan.trustDeltas) && source.runPlan.trustDeltas.length && source.runPlan.trustDeltas.every(prose)) {
      return { execution: source.executionIdentity, changes: source.runPlan.trustDeltas.join("\n\n") + "\n\n" + source.limits, lifetime: source.dataLifetime };
    }
    return null;
  }
  const api = Object.freeze({ clean, reviewSummary });
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.AiwDisplay = api;
}(globalThis));
