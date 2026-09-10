# Working state

Updated 2026-09-09. This is a compact handoff, not a run receipt or authorization.

## Where to resume

- Active development branch: `codex/wsb-typed-scenarios`. Locate it with `git worktree list` if this checkout differs. The main checkout has historically been behind this worktree.
- Last application milestone: `1c9a9fd` (Bambu compiler and disposable-worker feasibility). Use `scripts/work-status.ps1` for current HEAD, dirty files, and locally known upstream state.
- Goal: report tested functions for exact application bytes and measured isolation configurations, then use the evidence for adaptation/repackaging. Free community project; feedback collection is not a development gate.

## Implemented versus exploratory

- Production path: protected intake; approved Windows Sandbox execution and recovery; fixed Notepad++ MSI v6 install/open/edit/save/close as a standard user after privileged install. Bound token, runtime, file/registry, stage, failure-snapshot, and MSI ProductCode observations feed retained JSON/Markdown reports and explicit report sets.
- Bambu: metadata-only fixed `--info` compiler, `executionSupported: false`. Separate research trials proved silent offline install and non-admin STL-to-3MF export; bounded ZIP/XML inspection found the expected tetrahedron. No production Bambu preparation, guest execution, or report integration exists yet.
- No application-level baseline/candidate isolation comparison or reusable repackaging capability is complete. Outer Sandbox containment is distinct from an inner application boundary.

## Next coherent slice

Implement a separately typed Bambu STL-to-3MF export profile through the existing approved lifecycle, with bounded artifact verification and failed-stage reporting. Reuse lifecycle mechanisms; do not widen the MSI schema, execute caller commands, or infer success from exit 0 alone. Start by agreeing the artifact/result contract and minimal negative checks. Do not add slicing/printer/cloud support to this slice.

## Read only what the slice needs

- [Bambu profile and actual research results](BAMBU-STUDIO-PROFILE.md): hashes, exact command, limitations, retained research location.
- [Roadmap](ROADMAP.md): benchmark completion criteria and later isolation/adaptation work.
- [Report sets](REPORT-SETS.md), [assessment reports](ASSESSMENT-REPORT.md): existing verified reporting contracts.
- [Notepad++ fixture](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md), [MSI ProductCode observation](MSI-PRODUCT-REGISTRATION.md): existing live controls and retained evidence.
- Code entry points: provider `scenario.rs`/`bambu_scenario.rs`/`imported_msi.rs`; runner `preparation.rs`/`lib.rs`/`assessment_report.rs`; guest-agent `main.rs`; native `guest_msi.rs`/`guest_standard_user.rs`.

## Operational constraints

Use local checks first and CI sparingly. Push completed authorized changes; avoid incidental workflow triggers. Installer corpus is locally available in `%USERPROFILE%\Downloads\installers`; original files are not execution authority. Reverify retained intake/artifact bindings when used. Keep research evidence outside production report sets. Never install on the host or remove unrelated worktrees/evidence.
