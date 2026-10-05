# App Isolation Workbench

App Isolation Workbench (AIW) helps Windows administrators test supported application workflows inside Windows Sandbox and retain understandable, inspectable results. It is free research software in alpha development. The product is working toward two capability stages:

1. **Workbench v1** assesses MSI, EXE, and portable-directory applications, compares ordinary and isolated execution, records inspectable evidence, makes deterministic recommendations, and replays validated profiles on demand.
2. **Studio v1** retains Workbench and adds first-party MSIX/AppContainer authoring, narrowly scoped remediation, signing, and final-package validation.

The delivery loop is `Assess -> Adapt -> Package -> Validate`. We will complete it for a narrow application class before expanding every provider and collector. The [roadmap](docs/ROADMAP.md) prioritizes a standard-user baseline, one measured isolation candidate, a reviewed adaptation and reusable launch, then the first validated package; experimental providers do not block that loop.

## Current status

AIW has an experimental CLI and Windows desktop preview. Fixed Notepad++ assessment and interactive document edit/save/export, plus Bambu Studio's fixed STL-to-3MF export, have completed GUI acceptance for the identified unsigned packages on a separate supported VM. Isolated publisher signing is proven for the CLI; complete signed desktop and public-download acceptance remain release gates. The CLI also provides retained reports, reusable MSI Sandbox bundles, and evidence-bound local-settings replay. General application coverage, broader isolation measurements, and Studio authoring remain future work. The [first administrator preview gates](docs/RELEASE-GATES.md) separate demonstrated capabilities from remaining release work. Projects use `aiw.dev/v0alpha2`; legacy `v0alpha1` projects remain readable and migrate non-destructively with an explicit review gate.

## Administrator quick start

When the signed alpha is published, use the [release downloads](https://github.com/nathanmcnulty/app-isolation-workbench/releases). Each release provides `START-HERE.md` with exact hashes, a fresh extraction path, and copy-and-paste verification and launch commands for that build. A compiler is not required.

1. Download the five release assets into one folder and follow its `START-HERE.md`.
2. Open the verified desktop on a supported Windows 11 24H2+ host with Windows Sandbox enabled. The app checks readiness before preparation.
3. Choose a workflow and its exact supported installer: Notepad++ 8.9.8 x64 MSI, or Bambu Studio 02.08.02.60 x64 EXE. Interactive Notepad++ also takes a bounded text input.
4. Review the recipe and temporary-data behavior, confirm the displayed approval literal, then press **Start** separately.
5. Read the concise result; open details when needed. Export required output explicitly before discarding temporary Sandbox data, and retain the evidence and cleanup result.

For interactive transfer, edit the document, save it, and close the editor when finished. The fixed assessment/export workflows complete automatically. A passing function workflow does not establish broader isolation or compatibility for another installer version. The alpha tests these fixed workflows; it does not yet convert arbitrary applications into deployable sandbox packages.

For the desktop preview, verify the identified package and open `aiw-desktop.exe`.
Choose the supported Notepad++ MSI or fixed Bambu Studio EXE and, for a Notepad++ interactive session, a text input;
prepare the review, confirm its exact plan, and separately click Start. The GUI
shows a concise result with optional retained details and explicitly exports a
verified document to a new file. A passing function workflow does not establish
broader isolation. See [Notepad++ GUI acceptance](docs/GUI-FIRST-FINISH-LINE.md#completed-packaged-gui-acceptance-2026-10-03), [the current three-product package and exact VM paths](docs/BAMBU-ADMIN-ENTRY.md#completed-desktop-acceptance-2026-10-03), and [verified ZIP extraction with exact operator commands](docs/DESKTOP-DISTRIBUTION.md).

| Capability | Current boundary |
|---|---|
| Application intake | Read-only MSI/EXE/portable inspection and protected, receipt-last import and verification. Existing or incomplete intake IDs are preserved; retry requires a new ID. |
| Signature observation | MSI/EXE inspection validates embedded Authenticode against the held file using cache-only whole-chain policy. Signer identity, timestamp, and installer-aware metadata are not yet recorded. Signature observation is not execution approval. |
| Windows Sandbox preparation | `prepare-wsb`, `prepare-wsb-msi`, `verify-prepared-wsb`, and `import-prepared-wsb` bind a fixed agent, provider, protected workspace, plans, and import provenance before separate approval. |
| Public execution and recovery | `run start` dispatches the imported and explicitly approved golden probe or fixed Notepad++ MSI profile. `run recover` reconciles and, if needed, stops only the persisted session. Neither accepts arbitrary execution authority. |
| Evidence | The MSI profile returns bound install/open/edit/save/close results, a launched-root token snapshot, scoped filesystem changes, and stage progress. The current v6 profile separates elevated installation from standard-user application execution inside Sandbox and binds the runtime account/profile. Scoped registry snapshots distinguish installation/use changes and incomplete capture; failed v5/v6 runs can retain completed snapshot phases under a separate receipt-bound event. The v6 profile adds live-tested, receipt-bound [machine ProductCode state metadata](docs/MSI-PRODUCT-REGISTRATION.md); it is not a dependency or isolation claim. Function results remain distinct from a complete containment verdict. |
| Assessment report | `run report-wsb-msi` exports reverified completed observations; `run report-wsb-msi-run` also reports terminal failures with receipt-bound stages when available. `run report-wsb-msi-set` re-verifies up to 32 explicitly selected retained workspaces and preserves unavailable entries without making comparison or isolation claims. JSON/Markdown preserve function results, file changes, requirements, and missing baseline/isolation evidence. See [report semantics](docs/ASSESSMENT-REPORT.md) and [report sets](docs/REPORT-SETS.md). |
| Workspace discard | Exact-object revocation, depublish, disposition, and terminal receipt transactions exist privately for the fixed preparation tree. Public discard and general intake cleanup are not implemented. |
| Other providers | MXC is a pinned, non-executing planning adapter. |

[PR #50](https://github.com/nathanmcnulty/app-isolation-workbench/pull/50) records live public-command success and interruption/recovery proofs. The [Notepad++ fixture](docs/FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md) records EXE/MSI intake, signature observations, and a live approved MSI Sandbox scenario. These are dated proofs, not evidence that every host or application is supported. Hosted CI checks contracts and native code but does not establish containment.

Downloaded MSI/EXE inspection supports bounded `Zone.Identifier` and `SmartScreen` metadata. Importing these files requires `--archive-download-metadata`: raw metadata is retained in protected sidecars and the receipt records the policy that creates and verifies an unnamed-stream-only payload for later approved Sandbox execution. Originals stay intact. This does not test Windows download warnings or grant signer trust. See [download metadata intake](docs/DOWNLOAD-METADATA-INTAKE.md).

Protected intake copies bytes only from retained native handles into create-new owner-and-SYSTEM storage. Verification checks the externally retained receipt, exact identities, namespace, content hashes, ACLs, links, streams, and semantic extended attributes. Missing `intake.json` means incomplete; its presence alone grants no authority. File flush is provided, but parent-directory and power-loss durability are not claimed. See [Architecture](docs/ARCHITECTURE.md) and [Threat model](docs/THREAT-MODEL.md) for the execution and recovery boundaries.

The initial live target is Windows 11 24H2 (build 26100+) x64. Provider support is capability-gated and requires live evidence. Windows 10 and ARM64 are deferred. There is no automatic telemetry, persistent privileged service, automatic feature enablement, or model authority over verdicts.

## Product boundaries

- Evidence is authoritative; optional local-AI prose is cited, advisory, and non-executing.
- Raw installers, project fields, worker output, provider output, and model content are untrusted.
- Provider execution uses the shared run boundary: a typed hash-bound plan, exact approval, append-only journal, fail-closed recovery, and terminal cleanup evidence. Non-executing intake and preparation use explicit create-new commands and protected receipt-bound state; they do not grant execution authority.
- Unsupported, degraded, incomplete, or ambiguous isolation remains `insufficientEvidence`, never success.
- Workbench launches validated applications on demand; it is not a background application-management service.
- Studio keeps delivery (`containedMsix`) separate from runtime boundary (`mediumIlFullTrust`, `appContainer`, or preview `appSiloPreview`). A converted full-trust MSIX is not an isolation claim.
- Master Packager is a manual export/import handoff. AIW will not call, embed, or automate it without a separate vendor authorization.

## Advanced CLI and developer examples

These Rust-based examples exercise the internal contracts and fixed Windows Sandbox proof. The desktop quick start above is the administrator entry path. `run start` starts the approved prepared profile; `run recover` can stop its persisted session:

```powershell
cargo run -p aiw-cli -- project validate --path .\examples\minimal.aiw.yaml
cargo run -p aiw-cli -- application inspect --source <path> --kind <msi|exe|portable-directory>
cargo run -p aiw-cli -- application import --source <absolute-msi-or-exe> --kind <msi|exe> --intake-parent <canonical-existing-local-directory> --intake-id <new-id>
cargo run -p aiw-cli -- application import-portable --source <absolute-directory> --intake-parent <canonical-existing-local-directory> --intake-id <new-id>
cargo run -p aiw-cli -- application verify-portable-import --receipt <saved-portable-import-receipt.json>
cargo run -p aiw-cli -- application verify-import --receipt <saved-import-receipt.json>
cargo run -p aiw-cli -- probe host
cargo run -p aiw-cli -- probe token
cargo run -p aiw-cli -- run prepare-wsb --run-id <fresh-id> --project .\examples\minimal.aiw.yaml --guest-agent <absolute-path> --guest-agent-sha256 <lowercase-sha256> --workspace-parent <canonical-existing-local-directory> --created-at <timestamp>
cargo run -p aiw-cli -- run verify-prepared-wsb --workspace <workspace-from-prepare> --project .\examples\minimal.aiw.yaml --guest-agent-sha256 <same-independently-obtained-lowercase-sha256>
cargo run -p aiw-cli -- run import-prepared-wsb --workspace <workspace-from-prepare> --project .\examples\minimal.aiw.yaml --guest-agent-sha256 <same-independently-obtained-lowercase-sha256> --imported-at <timestamp>
cargo run -p aiw-cli -- run approve --root <workspace-from-prepare> --run-id <fresh-id> --approval <approval-record.json>
cargo run -p aiw-cli -- run start --root <workspace-from-prepare> --run-id <fresh-id> --project .\examples\minimal.aiw.yaml --guest-agent-sha256 <same-independently-obtained-lowercase-sha256> --timeout-seconds 300
cargo run -p aiw-cli -- run status --root <workspace-from-prepare> --run-id <fresh-id>
cargo run -p aiw-cli -- run recover --root <workspace-from-prepare> --run-id <fresh-id>
cargo run -p aiw-cli -- provider wsb --plan .\examples\windows-sandbox-plan.json
cargo run -p aiw-cli -- provider compile-msi-scenario --project .\examples\notepad-plus-plus-msi.aiw.yaml --scenario install-launch-close
cargo run -p aiw-cli -- provider mxc --plan .\examples\mxc-golden-probe-plan.json
cargo run -p aiw-cli -- schema project
cargo run -p aiw-cli -- evidence verify --log .\run\evidence.jsonl
cargo run -p aiw-cli -- bundle verify --root . --manifest .\assessment-bundle-manifest.json
cargo run -p aiw-cli -- canary evaluate --plan .\examples\canary-plan.json --observations .\examples\canary-observations.json --evidence-log .\examples\canary-evidence.jsonl
cargo run -p aiw-cli -- compare --left .\baseline.json --right .\candidate.json
```

All successful commands emit JSON. Diagnostics go to standard error and a nonzero exit code indicates failure. Preparation requires an independently obtained agent hash, leaves the run `pendingApproval`, never writes approval or provider-session state, and preserves incomplete workspaces for explicit inspection. Provider planning commands remain non-executing. `run start` accepts no arbitrary execution input, fails closed on drift, and may require `run recover` after an interrupted provider attempt.

`provider compile-msi-scenario` produces a strict, versioned Notepad++ MSI install/launch/observe/close plan for review. It does not read the installer, verify an intake, approve a run, or start a process. The example binds the recorded 8.9.8 MSI content hash and uses a placeholder provider identity. `run prepare-wsb-msi` connects verified intake to separate import, approval, and guest execution; see [the scenario integration contract](docs/TYPED-MSI-SCENARIO.md).

The [Bambu Studio export profile](docs/BAMBU-STUDIO-PROFILE.md) now supports protected EXE preparation, approved Sandbox execution as a standard user, and retained JSON/Markdown reporting with bounded 3MF geometry verification. Use `examples/bambu-studio-export.json` and `run report-wsb-bambu-run`. Its original information-query compiler remains metadata-only. [Mixed application report sets](docs/REPORT-SETS.md) combine its export results with Notepad++ editing; application-level isolation comparisons remain future work.

## Local validation

For focused development, start with `scripts/work-status.ps1` and the [short handoff](docs/WORKING-STATE.md). Use `scripts/check-local.ps1 -Check Format,Provider` for selected local checks with concise results and full logs on disk. See the [development workflow](docs/DEVELOPMENT-WORKFLOW.md); the full verification entry point remains below.

```powershell
.\scripts\verify.ps1
.\scripts\audit-dependencies.ps1
```

`verify.ps1` runs formatting, Clippy with warnings denied, the workspace tests, representative contract/plan commands, schema generation, and governance-file checks. `verify.ps1 -GovernanceOnly` checks the Apache-2.0 license, required documentation/templates, required status language, and that every GitHub Action is pinned to a full commit SHA. `audit-dependencies.ps1` validates the locked metadata and runs RustSec `cargo audit`.

## Architecture and roadmap

The CLI and Tauri desktop call the shared `aiw-admin-workflow` service directly; the desktop does not automate the CLI as a subprocess. The existing `aiw-orchestrator` boundary provides the `AssessmentRun`, `LaunchRun`, and `AuthoringRun` lifecycles. Authoritative state remains inspectable on disk: immutable plans, per-run journals and evidence JSONL, content-addressed artifacts, approvals, and terminal receipts.

See [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md), and [Threat model](docs/THREAT-MODEL.md) for the detailed contracts and release gates. Supporting contracts are documented in [Assessment bundles](docs/ASSESSMENT-BUNDLES.md), [Boundary denial canaries](docs/DENIAL-CANARIES.md), [Local analyst report contract](docs/LOCAL-ANALYST-CONTRACT.md), [Retained MSI report sets](docs/REPORT-SETS.md), [Windows Sandbox automation](docs/WINDOWS-SANDBOX-AUTOMATION.md), and [Windows Sandbox completion receipts](docs/WINDOWS-SANDBOX-COMPLETION.md).

## Repository layout

```text
crates/             Rust contracts, probes, evidence, planners, CLI, and native probe
powershell/         Thin administration wrapper over the CLI
examples/           Non-sensitive project and evidence examples
schemas/            Schema generation guidance
docs/               Architecture, threat model, research notes, and roadmap
third-party/        Reviewed external source pins
scripts/            Local verification, dependency, and provider-pin checks
```

## Licensing and security

The project is licensed under the [Apache License 2.0](LICENSE). Third-party components retain their own licenses; model/runtime licenses will be reviewed separately before distribution. See [CONTRIBUTING.md](CONTRIBUTING.md) for focused vertical-slice guidance and [SECURITY.md](SECURITY.md) for private vulnerability reporting and non-negotiable boundaries.

Terminal MSI runs can also be exported with `run report-wsb-msi-run --format json|markdown`. Unsuccessful attempts report their recorded lifecycle, exact cleanup, and receipt-bound passed/failed/not-reached stages when available; v5 failures may also retain completed filesystem/registry snapshot phases, while missing phases remain unmeasured. They never become passed application assessments. See [reporting semantics and current limits](docs/ASSESSMENT-REPORT.md#unsuccessful-terminal-attempts).
