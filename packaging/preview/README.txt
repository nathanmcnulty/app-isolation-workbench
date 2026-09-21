App Isolation Workbench {{VERSION}} clean-host preview
========================================================

This unsigned preview supports one exact workflow: the recorded Notepad++ 8.9.8
x64 MSI in Windows Sandbox, using the packaged fixed project, guest agent, and
validated local-settings replay profile. It does not support arbitrary installers,
general EXE conversion, persistent application state, or a complete containment
verdict.

Build identity
--------------
Source revision: {{SOURCE_REVISION}}
Target: {{TARGET}}

Authenticity and integrity
--------------------------
This development preview is unsigned. SHA-256 values detect changed bytes but do
not prove who published them. Obtain the archive SHA-256, receipt file SHA-256,
and package receipt SHA-256 from the separately delivered distribution manifest.
Do not continue if any value differs.

After extracting the archive to a new local directory:

1. Compare receipt.json with the independently retained receipt file SHA-256:
   Get-FileHash .\receipt.json -Algorithm SHA256
2. Read receipt.json, find the record for verify-preview-package.ps1, and compare:
   Get-FileHash .\verify-preview-package.ps1 -Algorithm SHA256
3. Verify the exact inventory with the independently retained package receipt:
   .\verify-preview-package.ps1 -PackageRoot . `
     -ReceiptSha256 <independently-retained-package-receipt-sha256>

Host requirements
-----------------
- Windows 11 24H2 x64, build 26100 or later.
- Windows Sandbox installed and usable for the signed-in operator.
- No other Windows Sandbox session active.
- The exact supported MSI bytes, SHA-256
  c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80.

AIW checks host readiness and records host-readiness.json before protected intake.
It never enables Windows features, stops an unrelated Sandbox, or falls back to a
different recipe. Follow normal Microsoft Windows Sandbox installation policy for
the target organization if the prerequisite is missing.

Run the assessment
------------------
Create a new evidence parent and run from an interactive terminal:

  New-Item -ItemType Directory C:\AIW-Evidence
  .\aiw.exe admin assess --installer <absolute-path-to-supported-msi> `
    --evidence C:\AIW-Evidence --identity <operator-name>

Review the complete recipe and data lifetime shown by AIW. Approval requires the
exact displayed plan hash. Any other response cancels without launching Sandbox.
When the run completes, read report.md in the new run directory. A passing fixed
document workflow can still report insufficientEvidence for broader isolation;
the report lists every missing measurement.

Failure and recovery
--------------------
Keep the evidence directory. Use aiw.exe run status with the exact retained
workspace and run ID. Use run recover only when that status says recovery is
required. Never guess a session ID or stop another operator's Sandbox.

Data contract
-------------
The installer and fixed tools are mapped read-only into a disposable worker. The
worker output mapping is treated as untrusted. The fixed document and application
settings are discarded with the worker. Receipt-bound evidence remains under the
operator-selected host directory. AIW performs no telemetry or upload.

Known limits
------------
This same-host package construction is not the clean-host release proof. The
second-operator trial must record the exact archive, host/provider identity,
approval, report, and cleanup. Code signing, timestamping, SBOM publication, and
publisher authentication remain production release requirements.
