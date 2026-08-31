# App Isolation Workbench

App Isolation Workbench (AIW) is free, open-source research software for assessing existing Windows applications under stronger isolation boundaries. The product has two milestones:

1. **Workbench v1** assesses MSI, EXE, and portable-directory applications, compares ordinary and isolated execution, records inspectable evidence, makes deterministic recommendations, and replays validated profiles on demand.
2. **Studio v1** retains Workbench and adds first-party MSIX/AppContainer authoring, narrowly scoped remediation, signing, and final-package validation.

The delivery sequence is `contracts -> live runner -> evidence/scenarios -> recommendations/launch -> Workbench -> package authoring -> package validation -> Studio`.

## Current status

Public-start update: `aiw run start` now exposes only the imported and explicitly approved Windows Sandbox golden probe. Provider, workspace, mappings, agent, plan, approval, and deterministic session authority come from persisted state; the command accepts no executable, provider path, WSB plan, policy, command, or session ID. A live public-command proof completed receipt verification, exact stop, and final absence, and correctly returned `insufficientEvidence`. A separate live interruption after confirmed start was reported as `recoveryRequired`; public `run recover` stopped only the persisted session and verified final absence. This supersedes older implementation-history statements below that describe public start as disabled; imported-application execution and containment evidence remain future work.

W2 intake now includes read-only `aiw application inspect` plus file-only `aiw application import` and `verify-import`. On Windows, MSI/EXE sources are held without write/delete sharing while AIW verifies a local fixed volume, ordinary non-reparse shape, single link, unnamed data stream only, stable volume/file ID, bounded hash/size, and same-held-file PE architecture. File import copies only from that retained handle into new owner-and-SYSTEM storage, flushes and independently reopens the payload, writes `intake.json` last, and returns an external receipt that binds the exact semantic SmartLocker EA evidence for the root, source directory, and payload and can detect later identity, ACL, namespace, stream, size, or content drift. Missing `intake.json` always means incomplete, but its presence is not trusted without the externally returned receipt and a successful `verify-import`; the receipt file's own kernel EAs are allowlisted but are not receipt-bound because writing the self-describing receipt can change them. Existing or incomplete intake IDs are preserved and never adopted or removed; retry currently requires a new intake ID. File handles are flushed, but parent-directory and power-loss durability are not claimed. Portable sources are enumerated from held directory handles and every child is reopened relative to its held parent, identity-checked, bounded, hashed, retained, and revalidated into a sorted manifest. A directory can still gain a new child after final enumeration, so protected portable copying remains required. Import never grants execution or provider authority, and Authenticode is not implemented yet.

The repository implements the W0 contract-and-governance foundation plus the W1 Windows Sandbox native proof boundary. It validates the typed `aiw.dev/v0alpha2` project contract, reads `v0alpha1`, and migrates legacy projects to a new file with an explicit review gate. It contains three validated run lifecycles, a shared file-backed orchestrator, hash-bound plans and approvals, append-only run journals, versioned schemas, hash-chained evidence, deterministic comparison and canary contracts, read-only host/token probes, secure Windows Sandbox and MXC plan adapters, completion-receipt verification, and JSON CLI/PowerShell surfaces. `aiw host assess` verifies the installed Windows Sandbox Store package, catalog membership, held file identity, pinned CLI protocol, and bounded current-session observation. Opt-in Windows tests prove the typed leased start/list/connect/exact-stop lifecycle and the measured guest agent's token evidence, evidence chain, bound completion receipt, and cleanup on a real host. The private runner additionally binds the canonical identity of a protected owner-and-SYSTEM-only workspace into its approved action, start request, durable session transaction, status observation, and terminal execution evidence, while retaining the workspace handles throughout the live attempt. Native WSB calls use an exact verified image and shell-free command line, start suspended, receive only an explicit standard-handle list, join a kill-on-close job before any provider code runs, and obey bounded output, an invocation deadline, and a fixed cleanup allowance. The pinned packaged CLI requires its provider-managed process topology to survive successful calls, so the launcher removes kill-on-close only after the exact CLI root exits zero and both output streams complete within the deadline. Launch/wait failure, timeout, nonzero exit, and output-capture failure retain whole-job cleanup; later protocol-validation failures on mutating calls remain governed by the durable exact-session transaction. The public start path remains deliberately disabled until an approved start, crash, and exact recovery pass their production CLI live gate. The project does **not** yet run a model, install or launch imported applications, elevate, execute Windows Sandbox/MXC through `aiw run start`, provision canaries, create archives, provide the Tauri UI, author MSIX packages, sign packages, or prove that an imported application ran inside an isolation boundary.

Preparation and recovery update: `aiw run prepare-wsb` now creates a fresh protected workspace, holds and hash-pins the explicitly selected fixed-function guest agent, observes an empty trusted provider state, and writes `plan.json`, `wsb-plan.json`, and a final `preparation.json` completeness marker without acquiring or mutating Windows Sandbox. `aiw run verify-prepared-wsb` reopens the exact workspace after process exit and revalidates its ACL/file identities, artifact allowlist and hashes, empty output, project revision, agent, provider, package, catalog, protocol, and empty session state. `aiw run import-prepared-wsb` retains those authority handles while atomically publishing the plan, receipt-bound genesis journal, and `wsb-planning-import.json` into authoritative `PendingApproval` state. `--imported-at` is an operator-supplied receipt timestamp and must be reused exactly for an idempotent retry. Exact retries are non-mutating; generic `run plan` cannot import a WSB action. After irreversible logical revocation and protected-intent publication, the private discard workflow retains the exact intent handle and outer coordination while a held read-only snapshot blocks tree writes, delete, and rename through publication. It materializes a portable semantic inventory of exactly 19 objects with stable IDs, canonical paths, types, ACL/link/stream/attribute policy, file sizes and hashes, and EA names/flags/lengths/hashes; unstable queried-byte counts are excluded. A deterministic protected external checkpoint beside the workspace uses a schema binding the v2 revocation record, exact inventory and hashes, checkpoint parent/file identity, cleanup ID, and `.aiw-discarded-v1-<cleanupId>` tombstone. The completed private depublish transaction classifies the root as exact original, tombstone, absent, foreign, or ambiguous; creates and flushes an immutable commit before the exact non-replacing root rename, then flushes and strictly reopens it. Its private child-first disposition covers the fixed 19-object tree: each exact object gets an immutable external canonical pre-disposition record hash-chained from the depublish commit, published before handle-only deletion. Recovery accepts only a contiguous published prefix with at most one pending record and the exact physical prefix; root absence after ordinal 19 is not terminal cleanup. After the exact 19-record published chain and physical absence are proven, the private terminal workspace-cleanup transaction creates a canonical owner/SYSTEM-protected receipt in a create-new deterministic pending name, self-bound to its own parent/file identity, flushes and strictly reopens it, and publishes the final receipt. Retries require the exact same operator-supplied completion timestamp and all intermediate authority files remain retained. The receipt records physical absence separately from an unrelated replacement at the original name and never deletes that replacement. No provider, CLI, RunResult, or public cleanup UX is exposed, and this is not a broad cleanup-complete claim. File flush is provided; parent-directory flush and power-loss durability are not claimed. Approval remains a separate command. `aiw run recover --root <root> --run-id <id>` derives its mutation authority only from persisted hash-bound state. The disabled runner statement now applies specifically to `aiw run start`.

The initial live target is Windows 11 24H2 (build 26100+) x64. Provider support is capability-gated and must be established by live evidence; hosted CI validates contracts and code only. Windows 10 and ARM64 are deferred. There is no automatic telemetry, persistent privileged service, automatic feature enablement, or model authority over verdicts.

## Product boundaries

- Evidence is authoritative; optional local-AI prose is cited, advisory, and non-executing.
- Raw installers, project fields, worker output, provider output, and model content are untrusted.
- Every mutating operation uses the shared run boundary: a typed hash-bound plan, exact approval, append-only journal, fail-closed recovery, and terminal cleanup evidence. Provider execution remains disabled until its later slice proves the same invariants live.
- Unsupported, degraded, incomplete, or ambiguous isolation remains `insufficientEvidence`, never success.
- Workbench launches validated applications on demand; it is not a background application-management service.
- Studio keeps delivery (`containedMsix`) separate from runtime boundary (`mediumIlFullTrust`, `appContainer`, or preview `appSiloPreview`). A converted full-trust MSIX is not an isolation claim.
- Master Packager is a manual export/import handoff. AIW will not call, embed, or automate it without a separate vendor authorization.

## Current CLI

These commands exercise the current contracts and fixed Windows Sandbox proof. Only `run start` acquires and mutates the provider:

```powershell
cargo run -p aiw-cli -- project validate --path .\examples\minimal.aiw.yaml
cargo run -p aiw-cli -- application inspect --source <path> --kind <msi|exe|portable-directory>
cargo run -p aiw-cli -- application import --source <absolute-msi-or-exe> --kind <msi|exe> --intake-parent <canonical-existing-local-directory> --intake-id <new-id>
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
cargo run -p aiw-cli -- provider mxc --plan .\examples\mxc-golden-probe-plan.json
cargo run -p aiw-cli -- schema project
cargo run -p aiw-cli -- evidence verify --log .\run\evidence.jsonl
cargo run -p aiw-cli -- bundle verify --root . --manifest .\assessment-bundle-manifest.json
cargo run -p aiw-cli -- canary evaluate --plan .\examples\canary-plan.json --observations .\examples\canary-observations.json --evidence-log .\examples\canary-evidence.jsonl
cargo run -p aiw-cli -- compare --left .\baseline.json --right .\candidate.json
```

All successful commands emit JSON. Diagnostics go to standard error and a nonzero exit code indicates failure. Preparation requires an independently obtained agent hash, leaves the run `pendingApproval`, never writes approval or provider-session state, and preserves incomplete workspaces for explicit inspection. Provider planning commands remain non-executing. `run start` accepts no arbitrary execution input, fails closed on drift, and may require `run recover` after an interrupted provider attempt.

## Local validation

```powershell
.\scripts\verify.ps1
.\scripts\audit-dependencies.ps1
```

`verify.ps1` runs formatting, Clippy with warnings denied, the workspace tests, representative contract/plan commands, schema generation, and governance-file checks. `verify.ps1 -GovernanceOnly` checks the Apache-2.0 license, required documentation/templates, required status language, and that every GitHub Action is pinned to a full commit SHA. `audit-dependencies.ps1` validates the locked metadata and runs RustSec `cargo audit`.

## Architecture and roadmap

The shared `aiw-orchestrator` service boundary is called directly by the CLI and will also be called by the future Tauri backend; the desktop application will not automate the CLI as a subprocess. The implemented lifecycles are `AssessmentRun`, `LaunchRun`, and `AuthoringRun`. Authoritative state remains inspectable on disk: immutable plans, per-run journals and evidence JSONL, content-addressed artifacts, approvals, and terminal receipts.

See [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md), and [Threat model](docs/THREAT-MODEL.md) for the detailed contracts and release gates. Supporting contracts are documented in [Assessment bundles](docs/ASSESSMENT-BUNDLES.md), [Boundary denial canaries](docs/DENIAL-CANARIES.md), [Local analyst report contract](docs/LOCAL-ANALYST-CONTRACT.md), [Windows Sandbox automation](docs/WINDOWS-SANDBOX-AUTOMATION.md), and [Windows Sandbox completion receipts](docs/WINDOWS-SANDBOX-COMPLETION.md).

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
