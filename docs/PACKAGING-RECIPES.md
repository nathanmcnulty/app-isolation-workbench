# Inspectable MSI packaging recipes

`package inspect-wsb-msi-recipe` exposes the fixed Notepad++ preparation as a
read-only recipe snapshot before execution. It is the inspection foundation for
Roadmap Benchmark 3. The fixed local-settings experiment below adds one narrow
adaptation; portable launch validation and boundary canaries remain separate.

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

Successful human document transfer is useful baseline evidence but cannot be
relabeled as an adaptation comparison.

## Fixed local-settings experiment

The new example `examples/notepad-plus-plus-local-settings.aiw.yaml` keeps the
automated install/open/edit/save/close workflow and adds exactly one argument:
`-settingsDir=C:\Users\AiwStandardUser\AppData\Local\Notepad++`. The native guest
and recipe inspector share the resolved argument array, including the fixed
document path. No additional directory ACLs, capabilities, host mappings, or
network access are granted. The guest creates this one fresh directory under the
standard-user profile while impersonating that user, retains its non-reparse
ancestry/identity, and rejects existing entries. Notepad++ writes settings there;
the worker remains ephemeral.

Notepad++ documents both the [settings-directory switch](https://github.com/notepad-plus-plus/npp-usermanual/blob/master/content/docs/command-prompt.md)
and [configuration creation and fallback behavior](https://github.com/notepad-plus-plus/npp-usermanual/blob/master/content/docs/config-files.md).
The [pinned 8.9.8 implementation](https://github.com/notepad-plus-plus/notepad-plus-plus/blob/v8.9.8/PowerEditor/src/Parameters.cpp#L1376-L1395)
requires the override directory to exist before launch; otherwise a modal
invalid-directory message blocks the automated document workflow.
This experiment asks whether settings move to local application data while the
document function remains intact; it does not assert that the default location
is a compatibility failure or that redirecting settings restricts access.

The compiled scenario has schema `windows-sandbox-compiled-msi-scenario/v0alpha9`
and profile `windows-sandbox/notepad-plus-plus-local-settings/v0alpha1` (both with
the `aiw.dev/` prefix). It is separately hashed and disclosed in approval. The
compiler accepts only that exact argument in the automated scenario; altered
paths, extra flags, and interactive use are rejected. Existing no-argument and
interactive profiles retain their wire hashes. Bundles preserve the typed
scenario through ordinary export, relocation, fresh intake, and replay.

After building the CLI and production static guest, an explicitly approved
three-worker trial can be run with:

```powershell
.\scripts\test-local-settings-replay.ps1 `
  -ImportReceipt <verified-intake-receipt.json> `
  -GuestAgent <static-production-guest.exe> `
  -GuestAgentSha256 <independently-verified-hash> `
  -EvidenceParent <canonical-existing-local-directory> `
  -ApprovedBy <approving-operator> -Approve
```

The driver retains preparation, recipe inspection, bound approval, execution,
run report, and bundle report for baseline, candidate, and relocated replay.
It requires the fixed saved-document hash, verified cleanup, complete settings
capture, and nonempty `config.xml` exclusively in roaming application data for
baseline or local application data for candidate/replay. It preserves evidence
and stops on failure. `comparison.json` is a bounded experiment observation;
the underlying CLI reports remain the reverified evidence source. There is no
new compatibility verdict or reusable host-launch authorization.

### Retained settings comparison

`run report-wsb-settings-comparison --input <report-set-input.json>` reopens the
retained workspaces and verifies their evidence using the production report
reader. The input uses the existing report-set schema with exactly three entries
named `baseline`, `candidate`, and `replay`, in that order. It accepts workspace references, not
previously rendered reports or the script's observations. Obtain the output
schema with `schema wsb-settings-comparison`.

This command starts no provider or application and writes no run state. Missing,
failed, duplicated, drifted, or incomplete required evidence rejects the whole
comparison. Its result describes the fixed settings adaptation and measured
workflow; it is not launch authority or an effective-isolation verdict. The v0alpha2
comparison requires matching recorded provider binary/package/protocol identities
and normalized requested Sandbox configuration. It carries those identities per
trial. Comparison v0alpha3 additionally rejects recorded host/guest OS version
differences or partial guest coverage. `matchedRecordedVersion` requires all three
host and guest observations; historical absence remains `unmeasured`. The fresh
trial driver requires this version coverage. Complete environment equivalence
and effective boundary enforcement remain unmeasured. The trial driver now uses this command for
its final `comparison.json`; historical script-only comparisons retain their
original observation schema.


Retained verification on September 13 used
`%TEMP%\aiw-settings-comparison-cb9dfd45cd964e2f91dcc1ecbaaa962c`.
The two comparison outputs were byte-identical. Five altered inputs (missing
trial, duplicate trial, wrong guest hash, swapped roles, and changed project)
were rejected without partial output. All 75 retained workspace files kept their
original hashes and inventory. The proof contains `comparison.json`, the output
schema, per-case diagnostics, and before/after inventories. No Sandbox was
started for these reporting checks. Focused runner and CLI tests also passed.
### Recorded provider/configuration proof, 2026-09-13

Rechecking the same three completed workspaces with comparison `v0alpha2`
matched provider binary SHA-256
`247e092b5c5bd37820f225a7dd3ddf10ae37a67e2751a19c24b802c84769c441`,
package/CLI version `0.8.107.0`, and normalized requested configuration SHA-256
`e8daf47abe678d2414f1bf68944bb382ce05c8e8f9894de00b02faf40389ef1b`.
The recorded preparation identities were exposed through assessment report
`v0alpha8`; no provider was queried or started.

Proof: `%TEMP%\aiw-recorded-context-14241b03abfe4b9c97e610b8196fdaaa`.
Two outputs matched exactly, five altered selectors were rejected, the output
passed its generated JSON schema, and all 75 evidence files retained their
original content and inventory. Unit checks reject provider hash/package/protocol
or configuration drift and show that normalization preserves resource and mapping
suffix differences while rejecting outside mappings. OS equivalence and actual
boundary enforcement remain unmeasured.

### Required guest file ACL observation

Fresh automated preparations bind `standardUserAclV1` to approval and execution.
Recipe inspection includes the requirement in its complete preparation and
trust delta. The guest probes a fixed protected file and a writable local-data
control using the launched application's token, retaining identities and exact
bytes through application exit. Only access-denied error 5 counts as the
negative result; a missing file or sharing violation fails. See
[the report contract](ASSESSMENT-REPORT.md) for version and downgrade rules.

Settings comparison v0alpha4 includes each verified `standardUserAcl` and reports
`measuredStandardUserFileAclOnly` only when all three trials supply the bound
control. Mixed requirements or missing required evidence are rejected. Historical
runs without the requirement remain unmeasured. The fresh-trial driver requires
this limited coverage alongside matched recorded OS versions. Broader boundary
and deployment-environment validation remain open.

The initial required-ACL trial was blocked before worker startup by existing
session `b3e5b36e-e181-4e2d-8111-721e4c3f0959`; its preparation error is retained
in `%TEMP%\aiw-local-settings-f0f9d6c216354bc1add9300626525ef4`.
The driver now saves `host-readiness.json` before creating any intake or run.
The focused blocked-preflight check in
`%TEMP%\aiw-local-settings-ead6fe44669e443cb9e45043b1c6fdc2` retained that exact
session and left bundles, intakes, and runs empty. This session has no verified
ownership record in these trials and was not stopped. Fresh ACL execution
remains pending its identification/closure; this is not a successful live result.

Local validation passed 514 workspace tests (25 explicit live/privileged skips),
warnings-as-errors clippy, Rust 1.85 all-target checking, formatting, governance,
and static x64 guest build. Guest SHA-256:
`121daa7e6b93212037813dea948675431d1a1680bbb106cd396a2647454cfee5`.
Historical comparison checks in
`%TEMP%\aiw-acl-historical-4cfaf41c39d7440995ab7ebeb49b6c40` passed seven
positive/negative cases, generated-schema validation, deterministic output,
and unchanged inventories for 75 files. Their ACL coverage remains unmeasured.

### Recorded OS versions and fresh replay, 2026-09-19

The complete driver passed uninterrupted in three fresh workers:
`%TEMP%\aiw-local-settings-12e8f7b0e7604106add72305a1c30f2d`.
Static guest SHA-256 was
`a979b8b51680fb6fdde9615c307c3df86ffe30147ddc368df2dc9ba430775331`.
Each trial passed document open/edit/save/close, bound saved bytes, registry
verification, and exact-session cleanup. The final provider list was empty.

| Trial | Run ID | Observed config.xml location |
|---|---|---|
| Baseline | `baseline-1d27ff088d74436283194d09a5ce27aa` | Roaming application data |
| Candidate | `candidate-8b1975719bbb47b9b97a53e1b8974dd7` | Local application data |
| Relocated replay | `replay-07ce0c0a2c844da296a8c0438a6b0346` | Local application data |

All three recorded host and guest version `10.0.28000.2956` with x86_64
observers. Comparison v0alpha3 reports `matchedRecordedVersion`; effective
isolation and boundary canaries remain unmeasured. Each `config.xml` was 9,184
bytes with SHA-256
`f59bbed50f1d00f798fc09caa24911016ae07c1c26681e8442c09a532a9dff37`.

Final retained verification is in `%TEMP%\aiw-os-final-proof-20260919`.
The fresh comparison was deterministic, five altered selectors were rejected,
all 75 workspace files retained their hashes/inventory, and the comparison and
all three re-rendered v0alpha9 assessment reports passed their generated schemas.

Historical verification in
`%TEMP%\aiw-os-retained-f1bed0b4929e43e59f6bb000c2d71015` produced identical
repeated comparison output, rejected five altered inputs without partial output,
passed the generated JSON schema, and preserved all 75 workspace files and
hashes. Its old OS observations remain absent and coverage stays `unmeasured`.

Local validation passed the workspace tests outside the native crate, then all
155 native tests in a separate rerun with a short private TEMP root. The initial
native attempt rejected the shared TEMP directory's excessive entry count;
the first private-root layout also exposed existing Win32 path-length limits.
Production guards were unchanged. The harness now creates short private roots.
Doctests, warnings-as-errors Clippy, Rust 1.85 all-target checks, formatting,
PowerShell parsing, and governance checks passed. Final native/compiler logs:
`%TEMP%\aiw-local-checks-c2f7d70a-1f41-4006-892a-bac6a2eff360`.
Hosted CI was not run.

### Development failures retained

The first OS-capture trial on September 19 retained evidence in
`%TEMP%\aiw-local-settings-7b016eb355e840a9a19cc1925e741e23`.
Baseline completion was rejected because the registry verifier still required
runtime context v0alpha1 while the guest emitted the OS-bearing v0alpha2.
The verifier now shares the runtime context's version/coverage validation;
regression checks accept v0alpha2 and reject missing OS data and version
downgrades. The failed report records verified cleanup, and the provider list
was empty afterward. This rejected trial is not a completed assessment.

The first trial in `%TEMP%\aiw-local-settings-22d32e8a4fe644169739d2570b48a7bd`
passed baseline but failed candidate document readiness. The pinned Notepad++
source identifies the missing settings directory as a blocking modal precondition;
the guest now creates the directory as described above. That attempt used guest
`f7426ef8caeca4d85783bfb7efedd2cba0c589354cbb00d9a502f5ffc61e35e1`.

With corrected guest `a27bc46b1a7b6498895eae4e5e95616b47b08a0df653a436ea61dc633a32d065`,
the next trial in `%TEMP%\aiw-local-settings-ef41124bb9564ab48e27edde7dfed866`
passed baseline document readiness but failed during editing when a bounded
`WM_CHAR` call exceeded the existing 250 ms deadline (`ERROR_TIMEOUT`). The
driver retained `baseline-failed-report.json` automatically. Both attempts
verified worker cleanup. Timeouts were not relaxed; these failures remain
distinct from subsequent successful trials and do not establish settings placement.

### Live comparison and relocated replay, 2026-09-13

Retained evidence: `%TEMP%\aiw-local-settings-64d5d7f4b05a45c08655a5954e59560a`.
All three fresh workers passed the bound document open/edit/save/close workflow,
verified saved bytes, and recorded verified cleanup with the corrected guest
hash above. `report-set.json` reverified the three reports; `comparison.json`
records the limited settings-placement observation.

| Trial | Run ID | Observed config.xml location |
|---|---|---|
| Baseline | `baseline-9f518cf1489e4bdb9e274ab7742fc647` | Roaming application data |
| Candidate | `candidate-23e5767ad4314715b8de7ae0a9c9e1f0` | Local application data |
| Relocated replay | `replay-698ee03ae3d54bcdb4623c9c3ab7a32f` | Local application data |

Each retained `config.xml` was 9,184 bytes with SHA-256
`7cf189ed2e50a9372bab419e7a31d1baeed5123b48376669fa09b20e19461862`.
Candidate and replay shared manifest
`2ab7e567da5f7d106ac10755892fce546656886c8dc8aba8ea687a48b3d2de2e`
and scenario `41cd25921cbb42b97846192b64342e10b1375be1f996023b41c2765d6d527d66`.
Their receipt hashes were respectively
`99acf6436f33c5bea140d4e8f9fa56bbfcf1e217ac8bac2b38622745243cd492` and
`8c379e02ee562abf7e5f9601db432b592fb1801936974b88c00df6212bf4555e`.

The first relocated import failed before worker start after leaving an intake.
Its old CLI error was generic, so the cause remains unresolved. The CLI now
preserves bounded bundle error detail as `AIW_SANDBOX_BUNDLE_REJECTED`, with a
contract test. A new intake ID imported the unchanged relocated bundle
successfully; the failed intake was preserved, not adopted. Replay resumed from
that successful import without repeating baseline/candidate. Thus these are
three successful bound runs, not an uninterrupted successful driver invocation.
`replay-initial-import.stderr.log` preserves the original failure.

The driver and native checks preserve failed trials. This result does not close
Benchmark 3: affected-boundary canaries and deployment-environment validation
remain unmeasured, and no host installation or persistent launch was tested.
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
