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
$imported | ConvertTo-Json -Depth 64 | Set-Content .\replay-import.json
```

Use new output files when saving the import result. Keep intake and run workspaces under separate parent directories (for example, `C:\AIW\intakes` and `C:\AIW\runs`): preparation holds the intake parent against writes while staging. Continue with `run prepare-wsb-msi`, using the imported project and receipt, the fixed scenario, and a separately verified current guest agent. Import that preparation and review its fresh plan before approval and start. Export, bundle verification, and intake import execute neither the installer nor the application. Failed exports can leave an incomplete output directory; use a new bundle ID when retrying.

The supported workflow installs inside a disposable Windows Sandbox, then runs the standard-user document open/edit/save/close checks. The session is stopped after the test; there is no persistent application installation or personal-document preservation contract. The new run's verified report is the authority for what worked. Source evidence references and a successful bundle verification cannot substitute for that report.

The bundle format admits no additional commands, scripts, host mappings, or runtime grants. Changed bytes, unsupported recipes, extra files, and unsafe file shapes must be rejected before preparation. New versions or profiles require explicit support, not interpretation of arbitrary manifest instructions. Download metadata normalization from the source intake is provenance; replaying the packaged bytes does not test the original download's SmartScreen behavior.

## Recorded replay, 2026-09-10

`live_packaged_msi_import_replay_and_cleanup` passed in a fresh Sandbox after export, ordinary file-copy relocation, and fresh protected intake import. The MSI installed successfully; the application ran as the verified standard user and opened, edited, saved, and closed the document. All nine stages, expected document hash, filesystem/registry observations, MSI registration, retained report validation, and exact worker cleanup passed. The overall assessment still reports insufficient evidence for an inner application-isolation claim.

- Application: Notepad++ 8.9.8 x64 MSI, SHA-256 `c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80`.
- Bundle manifest: `0be45c2665ddf6a8aa63393cb9638099e575287c4d466e2ce490e9559c830608`.
- Guest agent: `b63101b2906849c7660ab162ca768a6415d6d28d7132b27adbfe6c609eb4342e`.
- Scenario: Notepad++ MSI v6, SHA-256 `f7e600d8823b7c3f327a437e45517172f2d210b7eeed699f43ef3b70b6e50645`.
- Local evidence workspace: `%TEMP%\aiw-msi-live-11100-1789082137454847600`; bundle and relocated bundle use the same stem with `-bundle` and `-bundle-relocated`; the adjacent `.bundle-import.json` records fresh import provenance. Full test log: `%TEMP%\aiw-package-live-2.log`.

Automated file-only checks cover relocation, no-overwrite export, fresh intake identity, wrong manifest hash, payload/project/manifest drift, unsupported rehashed manifest fields, extra files, oversized payload, and hardlinks. These checks never execute their synthetic payload.

This proof covers the fixed ephemeral workflow only, not uninstall/update, interactive launch, persistent personal data, or MSIX conversion.

## Match a bundle to a verified run report

After the run completes and cleanup is verified, keep the complete import result, then generate JSON or Markdown:

```powershell
aiw package report-wsb-msi --bundle <bundle-directory> `
  --manifest-sha256 <exported-hash> --import-record .\replay-import.json `
  --root <retained-run-workspace> --run-id <run-id> `
  --guest-agent-sha256 <independently-retained-agent-hash> --format markdown
```

The `aiw.dev/sandbox-bundle-run-report/v0alpha1` envelope includes the verified manifest, its hash, the replay intake receipt hash, and the existing terminal run report. The verifier matches the project, compiled scenario, exact import receipt (including intake identity), payload size and hash. It holds the bundle through retained-workspace verification; an application hash match alone cannot substitute another intake. The original intake and current provider executable are not required. Bundle files and the retained run evidence must still be available.

This is a verified association of the supplied bundle/import record with the run, not independent proof of when export or import happened. Historical source provenance does not establish replay success. The enclosed report retains its completed/unsuccessful kind, measured functions, failures and evidence gaps. Interrupted or pending-recovery runs reject, and this command never repairs, approves, starts, or reruns anything. Existing standalone and report-set schemas remain unchanged; bundle provenance is currently available through this package report command.

The retained replay above passed the package-report regression without installation or worker startup: deterministic output, unchanged bundle/workspace file inventories, preserved insufficient-evidence verdict, and rejection of a wrong manifest hash, wrong guest hash, changed project/scenario/source provenance, and a different intake identity despite identical application bytes. Local test log: `%TEMP%\aiw-bundle-report-retained.log`.
