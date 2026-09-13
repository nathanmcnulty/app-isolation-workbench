# Inspectable MSI packaging recipes

`package inspect-wsb-msi-recipe` exposes the fixed Notepad++ preparation as a
read-only recipe snapshot before execution. It is the inspection foundation for
Roadmap Benchmark 3. It does not yet implement an adaptation comparison or a
portable launch profile.

Prepare normally with `run prepare-wsb-msi`, optionally supplying a bounded
document input. Then inspect the preparation before `run import-prepared-wsb`:

```powershell
aiw package inspect-wsb-msi-recipe --root <prepared-workspace> `
  --project <project.json> --guest-agent-sha256 <independently-retained-agent-hash> `
  --format markdown

aiw schema wsb-msi-recipe-inspection
```

JSON is the default output. Save output outside the protected workspace, whose
file inventory is deliberately closed. Already imported preparations are rejected,
including unsuccessful attempts with no output. For a completed run, use the
retained run or bundle report instead.

The command reuses held preparation verification: protected directory/file
identity, source intake, staged MSI and optional input bytes, project revision,
compiled scenario, guest agent, current provider identity, and plan hashes must
still match. It does not install, approve, acquire a provider lease, or launch a
worker. Output fields are not accepted as instructions by any executor.

The versioned inspection includes:

- The full preparation receipt: source provenance, payload size/hash, provider
  protocol/package/catalog identity, agent identity, workspace, and plan hashes.
- The fixed scenario and effective launch argument array, including the document
  path supplied by the guest when applicable; working directory and user profile.
- The existing renderer's exact Sandbox XML and hash, exposing all mappings,
  read/write settings, resource settings, and requested restrictions.
- Scratch, fixed-assessment, or bounded-transfer data locations and lifetime,
  including host retention and explicit export for transfers.
- The bound approval disclosures and explicit validation gaps.

`recipeSha256` hashes canonical JSON of the `recipe` property. It identifies this
complete inspection snapshot, including workspace-specific paths and descriptive
fields. It is not a signature, approval, stable cross-workspace recipe identifier,
or compatibility verdict. Preparation readiness does not establish deployment OS
compatibility. The original preparation and run plan remain execution authority
inputs; approval and start still perform their existing checks.

The next slice must introduce one explicit, narrow adaptation, bind its changed
authority, and compare fresh-worker behavior and affected boundary canaries.
Successful human document transfer is useful baseline evidence but cannot be
relabeled as that comparison.

## Inspection evidence, 2026-09-13

A fresh protected transfer preparation was inspected without approval or worker
startup in `%TEMP%\aiw-recipe-inspection-20260913-155120`. JSON output was identical
across repeated inspection, matched the generated schema, and left all workspace
file hashes/inventory unchanged. Markdown displayed the actual fixed document
argument and working directory. Wrong agent hash, project drift, already-imported
preparation, and the completed human-trial workspace were rejected. The final
provider list was empty. `recipe.json`, `recipe.md`, `inspection-checks.json`, and
`negative-checks.json` retain the inspection evidence; this is not an adaptation
execution result.
