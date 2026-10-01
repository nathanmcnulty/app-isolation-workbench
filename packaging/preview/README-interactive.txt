App Isolation Workbench {{VERSION}} interactive document preview
=============================================================

This unsigned package supports one exact workflow: {{WORKFLOW_DESCRIPTION}}
It does not support other installer bytes, persistent application state, or a
general compatibility or isolation verdict. {{PROFILE_BOUNDARY}}

Source revision: {{SOURCE_REVISION}}
Target: {{TARGET}}

Integrity and host requirements
-------------------------------
This development preview is unsigned. Obtain the archive SHA-256, receipt file
SHA-256, and package receipt SHA-256 from the separately delivered distribution
manifest. Hashes detect changed bytes but do not authenticate the publisher.
Compare receipt.json and verify-preview-package.ps1 to their independently
retained hashes, then run:

  .\verify-preview-package.ps1 -PackageRoot . `
    -ReceiptSha256 <independently-retained-package-receipt-sha256>

Success prints exactInventory: true and the verified file count. This PowerShell
script throws on failure. Do not check $LASTEXITCODE afterward: it can contain
an unrelated earlier program's exit code. AIW executable commands do use it.

Use Windows 11 24H2 x64 build 26100 or later, with Windows Sandbox installed
and available to the signed-in operator. Only the exact Notepad++ 8.9.8 x64 MSI
with SHA-256 c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80
is supported. AIW records host readiness before protected intake and never stops
another operator's Sandbox session.

Launch and export
-----------------
Create a new evidence parent. Use a separate existing ordinary UTF-8 text file,
at most 1 MiB, with no NUL bytes. From an interactive terminal:

  New-Item -ItemType Directory C:\AIW-Document-Evidence
  .\aiw.exe admin launch-document `
    --installer <absolute-path-to-supported-msi> `
    --document-input <absolute-path-to-text-file> `
    --evidence C:\AIW-Document-Evidence --identity <operator-name>

Review the full recipe and type its exact plan hash only if approved. In the
Sandbox, edit the working document in Notepad++, save, and close the editor
within five minutes. Closing the viewer alone does not finish the workflow.
The worker is disposable. Network and clipboard are disabled; no host folder
is mapped for editing. AIW retains the verified output in its protected run
workspace and creates no user-facing output file automatically.

Read report.md and report.json in the new evidence directory. The retained
bytes prove the transfer result, not who typed or whether the text changed.
If the report contains a verified document transfer and exact-session cleanup,
explicitly export to a new host file with the values from that run:

  .\aiw.exe admin export-document `
    --workspace <workspace-path-from-result> --run-id <run-id-from-result> `
    --destination <new-absolute-output-path>

The package supplies its checked project and guest identities. Use the same
verified interactive package as the launch; a different guest or project is
rejected. The lower-level run export-wsb-msi-document remains an advanced route.

Export refuses overwrite and workspace destinations, and verifies copied bytes.
This administrator command defaults to a summary; use --format json for details.
Destination refusals ask for a new path. Evidence failures require reviewing the
retained run before retrying. If the file was exported but console output failed,
preserve it and verify its bytes; do not repeat export just to obtain console text.
Keep the evidence directory. On failure, inspect the exact retained run status;
recover only if it says recovery is required. Never guess a Sandbox session ID.
Installation has a separate five-minute deadline before the editor's five-minute
editing period begins. Installation failures identify the process and deadline.
After approval, the default console view prints elapsed waiting every 30 seconds.
These messages do not indicate verified installer progress or editor readiness.
Use --format json on the administrator command for the structured result without
waiting messages; full approval review is still required.
If present, output\guest-msi-install-unverified.log inside the retained workspace
contains at most the final 64 KiB of raw MSI diagnostics. This may be truncated
and is untrusted diagnostic text, not a verified result or export artifact.
AIW performs no telemetry or upload. The separate-host operator trial is still
required for this package; this package is not a signed public release.
