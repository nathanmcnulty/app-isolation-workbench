App Isolation Workbench {{VERSION}} Bambu Studio assessment preview
===================================================================

This unsigned package supports one exact workflow:
{{WORKFLOW_DESCRIPTION}}
{{PROFILE_BOUNDARY}}
It does not support arbitrary EXEs, slicing, printing, cloud sign-in, graphical
editing, persistent application state, or a complete isolation verdict.

Build identity
--------------
Source revision: {{SOURCE_REVISION}}
Target: {{TARGET}}

Authenticity and integrity
--------------------------
This preview is unsigned. Hashes detect changed bytes but do not prove the
publisher. Obtain the archive SHA-256, receipt-file SHA-256, and package-receipt
SHA-256 from the separately delivered distribution manifest. After extracting
to a new directory, compare receipt.json and verify the exact inventory:

  Get-FileHash .\receipt.json -Algorithm SHA256
  .\verify-preview-package.ps1 -PackageRoot . `
    -ReceiptSha256 <independently-retained-package-receipt-sha256>

Host requirements and installer
-------------------------------
- Windows 11 24H2 x64, build 26100 or later, with usable Windows Sandbox.
- No other Windows Sandbox session active.
- Exact Bambu Studio 02.08.02.60 EXE, SHA-256
  cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7.

Run from a visible, interactive terminal:

  New-Item -ItemType Directory C:\AIW-Bambu-Evidence
  .\aiw.exe admin assess --product bambu-studio-export `
    --installer <absolute-path-to-supported-exe> `
    --evidence C:\AIW-Bambu-Evidence --identity <operator-name>

AIW checks readiness before protected intake. Review the complete fixed recipe,
including the command, Sandbox restrictions, data lifetime, and output handling.
Enter the exact displayed plan hash only if you approve it. Any other response
cancels without starting Sandbox.

The default console output is a short result. Read report.md for the detailed
operator view, and report.json and stage files for advanced evidence. The fixed
tetrahedron 3MF is reverified after exact-session cleanup and remains in the
retained workspace; it is not automatically exported to another host path.
A passing export remains insufficient evidence for broader isolation.

Failure and recovery
--------------------
Keep the evidence directory. Inspect aiw.exe run status for the exact workspace
and run ID. Use run recover only when that status says recovery is required.
Never guess a session ID or stop another operator's Sandbox. A cancelled approval
has approval-cancelled.json, not report.md.

The installer and fixed tools are mapped read-only into a disposable worker.
Worker output is untrusted until verified. AIW performs no telemetry or upload.
This package still needs a fresh independent operator trial before release.
