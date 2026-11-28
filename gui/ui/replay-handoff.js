(function (root) {
  "use strict";

  function requiredText(value, description) {
    if (typeof value !== "string" || !value.trim() || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(value)) {
      throw new Error(description + " is required and must fit on one line.");
    }
    return value;
  }

  function absolutePath(value, description) {
    const path = requiredText(value, description);
    if (!/^(?:[a-z]:[\\/]|\\\\[^\\/]+\\[^\\/]+(?:[\\/]|$))/i.test(path)) {
      throw new Error(description + " must be an absolute Windows path.");
    }
    return path;
  }

  function buildCommand(review, inputs) {
    if (!review || !/^[a-f0-9]{64}$/.test(review.manifestSha256)) {
      throw new Error("Verify the candidate package before generating a command.");
    }
    const cli = absolutePath(inputs.cli.trim(), "The trusted AIW CLI");
    if (!/\.exe$/i.test(cli)) throw new Error("Choose the AIW CLI executable.");
    const guestAgent = absolutePath(inputs.guestAgent.trim(), "The enrolled guest agent");
    const guestAgentSha256 = inputs.guestAgentSha256.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(guestAgentSha256) || /^0{64}$/.test(guestAgentSha256)) {
      throw new Error("Enter the independently enrolled guest agent SHA-256.");
    }
    const evidenceParent = absolutePath(inputs.evidenceParent.trim(), "The evidence parent");
    const msi = review.type === "msi";
    const request = {
      cli,
      arguments: [
        "application", msi ? "prepare-msi-replay-package" : "prepare-assessment-package",
        "--package=" + absolutePath(review.path, "The reviewed package"),
        "--expected-manifest-sha256=" + review.manifestSha256,
        "--guest-agent=" + guestAgent,
        "--guest-agent-sha256=" + guestAgentSha256,
        "--evidence-parent=" + evidenceParent,
      ],
    };
    if (!msi) request.arguments.push("--operator=" + requiredText(inputs.operator.trim(), "The operator identity"));

    // Operator values enter PowerShell as JSON data and then native arguments.
    // Quoting and other shell syntax inside a value remain literal.
    const json = JSON.stringify(request, null, 2).replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
      (character) => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"));
    return [
      "& {",
      "  if ($args.Count -ne 0) {",
      "    throw 'Unexpected handoff arguments. Put CLI options inside the embedded JSON arguments array.'",
      "  }",
      "  $PSNativeCommandArgumentPassing = 'Standard'",
      "  $aiwPreparation = ConvertFrom-Json -InputObject @'",
      json,
      "'@",
      "  [string[]]$aiwPreparationArguments = $aiwPreparation.arguments",
      "  & $aiwPreparation.cli @aiwPreparationArguments",
      "}",
    ].join("\n");
  }

  const api = Object.freeze({ buildCommand });
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.AiwReplayHandoff = api;
}(globalThis));
