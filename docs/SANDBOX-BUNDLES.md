# Reusable Sandbox application bundles

The first packaging target is the fixed Notepad++ MSI workflow. A directory bundle carries `app.msi`, `project.aiw`, and `manifest.aiw` (the latter two contain JSON). These 8.3-compatible names avoid secondary DOS aliases when copied on Windows. It is a reusable input to Workbench's existing Sandbox execution path. It is not an MSIX, a host installer, an interactive desktop launcher, or an AppContainer compatibility certificate.

The manifest identifies the exact payload, project, scenario, and runtime/data contract. Export requires a verified protected application intake. The bundle carries provenance, not an approval or a completed execution result. Preserve the manifest hash returned by export separately; a recipient supplies that expected hash when verifying or importing.

```powershell
aiw package export-wsb-msi --project .\examples\notepad-plus-plus-msi.aiw.yaml `
  --import-receipt <verified-intake-receipt.json> --scenario install-launch-close `
  --output-parent <existing-directory> --bundle-id notepad-bundle

aiw package verify --bundle <bundle-directory> --manifest-sha256 <exported-hash>

$imported = aiw package import --bundle <bundle-directory> `
  --manifest-sha256 <exported-hash> --intake-parent <existing-directory> `
  --intake-id notepad-replay | ConvertFrom-Json
$imported.project | ConvertTo-Json -Depth 64 | Set-Content .\replay-project.json
$imported.importReceipt | ConvertTo-Json -Depth 64 | Set-Content .\replay-intake.json
```

Use new output files when saving the import result. Keep intake and run workspaces under separate parent directories (for example, `C:\AIW\intakes` and `C:\AIW\runs`): preparation holds the intake parent against writes while staging. Continue with `run prepare-wsb-msi`, using the imported project and receipt, the fixed scenario, and a separately verified current guest agent. Import that preparation and review its fresh plan before approval and start. Export, bundle verification, and intake import execute neither the installer nor the application. Failed exports can leave an incomplete output directory; use a new bundle ID when retrying.

The supported workflow installs inside a disposable Windows Sandbox, then runs the standard-user document open/edit/save/close checks. The session is stopped after the test; there is no persistent application installation or personal-document preservation contract. The new run's verified report is the authority for what worked. Source evidence references and a successful bundle verification cannot substitute for that report.

The bundle format admits no additional commands, scripts, host mappings, or runtime grants. Changed bytes, unsupported recipes, extra files, and unsafe file shapes must be rejected before preparation. New versions or profiles require explicit support, not interpretation of arbitrary manifest instructions. Download metadata normalization from the source intake is provenance; replaying the packaged bytes does not test the original download's SmartScreen behavior.
