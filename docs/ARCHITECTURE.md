# Architecture

## Product shape

AIW is an administrator-led comparison laboratory. Workbench will run the same application and typed scenarios across an ordinary baseline and one or more isolation candidates, then produce normalized evidence and a deterministic recommendation. Studio will consume an accepted assessment and author, inspect, sign, and revalidate an MSIX candidate.

```text
CLI / PowerShell / future Tauri UI (ordinary user)
                         |
                 aiw-orchestrator
          /          |          |           \
   read-only probe  evidence  approvals   provider adapters
                                             |
                                  disposable worker boundary
                                             |
                              measured guest agent + untrusted app
```

The shared `aiw-orchestrator` application-service crate is the boundary used by both the current CLI and future Tauri backend. It currently owns strict file-backed run creation, approval, cancellation, recovery, lifecycle/event journaling, terminal results, and cross-file validation. Generic creation rejects Windows Sandbox actions; those plans can enter authoritative state only through the narrow atomic preparation-import operation, which publishes the plan, import receipt, genesis event, and journal head together. The UI will call services directly rather than automate the CLI as a subprocess. The W1 Windows Sandbox golden-probe executor is capability-gated; UI work and all other provider execution remain unimplemented.

## Lifecycles and contracts

The current code separates the product into three explicit lifecycles:

- `AssessmentRun`: intake, baseline, isolated candidate, scenarios, canaries, evidence, comparison, and recommendation.
- `LaunchRun`: replay of a previously validated profile after application, provider, OS, and policy drift checks.
- `AuthoringRun`: Studio recipe approval, disposable capture, adaptation, package inspection, signing, and final validation.

The `aiw.dev/v0alpha2` project contract implements typed `ApplicationSource` (`msi`, `exe`, `portableDirectory`), `IsolationIntent`, versioned `ExecutionProvider`, typed `Scenario`, immutable hash-bound `RunPlan`, `ApprovalRecord`, append-only `RunEvent`, and `RunResult`. Existing `v0alpha1` projects remain readable through a non-destructive migrator that writes a new revision and requires review before planning. Candidate configuration is typed; namespaced extensions cannot control privileged or executable behavior. The current `aiw.dev/run-plan/v0alpha3` contract binds the canonical validated project revision hash and, for the Windows Sandbox action, the complete inspectable workspace evidence plus its canonical hash. The former unbound `v0alpha1` and workspace-unbound `v0alpha2` plan shapes remain published for offline inspection and fail closed if supplied for mutation. `run status` is observational, while `run recover` is the explicit journal-repair operation. `AssessmentReport`, `ValidatedLaunchProfile`, and the complete Studio recipe/receipt family remain later-slice contracts.

Authoritative state is file-based and inspectable: immutable project revisions, one directory per run, hash-bound plan/approval files, append-only event/evidence JSONL, content-addressed artifacts, and terminal receipts/reports. A disposable local index may accelerate the UI but is never authoritative.

On Windows, WSB import and revocation publication use the held workspace authority rather than path-created descendants. Revocation is deliberately two-phase: the owner-scoped outer coordination lease and inner run lock are acquired before preparation descendants are reopened, then recovery and publication of the revocation artifact, event journal, and heads are performed relative to those revalidated handles. The generic path-backed orchestrator methods remain for portable contract tests and non-WSB callers; they are not the Windows runner authority.

The private checkpoint-bound depublish transaction is complete. It classifies the checkpoint-bound root as exact `Original`, `Tombstone`, `Absent`, `Foreign`, or `Ambiguous`; writes and flushes an immutable external commit before the exact non-replacing handle-relative root rename; then flushes the commit file and strictly reopens it. Recovery validates the commit and handles either the pre-rename or post-rename state, preserving foreign and ambiguous states and failing closed. The child-first disposition phase covers all 19 fixed objects: each exact object is authorized by an immutable external canonical pre-disposition record hash-chained from the depublish commit and published before handle-only deletion. Recovery accepts only a contiguous published prefix with at most one pending record and the exact physical prefix; root absence after ordinal 19 is not terminal cleanup. No provider, CLI, `RunResult`, or public cleanup UX is exposed; the terminal receipt is limited to this exact workspace transaction. File flush is provided, but no parent-directory flush or power-loss durability guarantee is made.

After the exact 19-record published chain and physical absence are proven, the private terminal workspace-cleanup transaction creates a canonical owner/SYSTEM-protected receipt in a create-new deterministic pending name, self-bound to its parent/file identity, flushes and strictly reopens it, and publishes the final receipt. An exact retry must reuse the same operator-supplied completion timestamp; all intermediate authority files remain retained. The receipt distinguishes absent original name from an unrelated replacement and never deletes that replacement. No provider, CLI, `RunResult`, or public cleanup UX is exposed, and this is not a broad cleanup-complete claim.

## Current components

The current public execution boundary is `aiw run start` for one fixed imported-and-approved Windows Sandbox golden probe. Its executable, provider, mappings, plan, workspace, approval, and deterministic session ID are persisted-derived; caller inputs are limited to identity/revision checks and a bounded timeout. Live public proofs cover both successful receipt/cleanup and interruption after confirmed start followed by exact-session `run recover`. Successful completion remains `insufficientEvidence`, not a containment verdict. Older component-history text below that calls public start disabled describes the preceding checkpoint.

- `aiw-schema`: strict project/model-pack parsing and semantic validation.
- `aiw-evidence`: canonical JSON, append-only hash chains, and deterministic allowlisted assessment manifests.
- `aiw-core`: legal state transitions, deterministic comparison, conservative canary evaluation, and advisory-report validation.
- `aiw-probe`: read-only environment and executable discovery, plus a conservative Windows Sandbox readiness report. Unknown feature, virtualization, signature, or session state is a blocker; it never enables a feature or elevates.
- `aiw-token`: audited native Win32 target-token evidence boundary.
- `aiw-golden-probe`: fixed in-target token evidence probe used by the narrow live W1 mapping/logon proof.
- `aiw-provider-wsb`: hardened `.wsb` rendering, lifecycle planning, and completion-receipt verification.
- `aiw-guest-agent`: fixed-function token collector for the W1 golden probe. Its strict request has no command, script, URL, glob, or policy fields and it writes the completion receipt last.
- `aiw-runner`: fail-closed W1 preparation, import, lifecycle, and recovery kernel. Preparation validates the project and trusted empty provider state before creating a protected workspace, holds an explicitly expected-hash guest-agent source through staging, binds provider/workspace/agent identities into fixed WSB and run plans, and writes the strict preparation receipt last. Import reopens and retains the exact workspace, receipt, plans, and agent while the orchestrator atomically publishes a provenance-bound pristine `PendingApproval` run. On Windows every mutating `RunLayout` operation first acquires an owner-and-SYSTEM-only Global kernel mutex bound to the canonical original root and run ID, then checks external discard control before opening the inspectable descendant lock file. The private discard workflow retains the exact intent handle and outer coordination, then holds a read-only tree snapshot that blocks writes, delete, and rename through publication. It materializes and verifies a portable semantic inventory of exactly 19 objects and publishes a deterministic protected external checkpoint beside the workspace. The checkpoint schema binds the v2 revocation record, exact inventory and hashes, checkpoint parent/file identity, cleanup ID, and tombstone. It uses create-new deterministic pending publication, write-through/flush, strict reopen, non-replacing handle-relative rename, and final flush/reopen. Exact pending/final recovery preserves partial, conflicting, hardlinked, and drifted state and fails closed. There is no parent-directory flush or power-loss durability claim, and no run-tree, journal/head, provider, CLI, `RunResult`, or public cleanup UX; child-first disposition is bounded to the 19 fixed objects. The execution kernel uses a strict persisted provider-session transaction, exact-ID recovery, and a private native test adapter. Its native launcher creates the exact verified provider image suspended, restricts inherited handles, assigns the CLI process to a kill-on-close job before resume, and enforces bounded output, an invocation deadline, and a fixed cleanup allowance. The live proof covers start, exact-session reconciliation, connect-triggered user logon, receipt verification, stop, and absence. Production provider start remains unavailable. A verified W1 receipt remains insufficient evidence for a containment verdict.
- `aiw-runner` recovery: new `v0alpha3` transactions bind the complete workspace evidence, request path relative to the held tools directory, and pinned provider protocol into each transition hash. `aiw run recover` reopens that exact workspace, rereads unchanged transaction authority while its handles are held, independently validates the current Store provider, and performs only list/optional exact-stop/list reconciliation. Legacy `v0alpha2` records remain readable for exact provider cleanup but cannot authorize request deletion. General provider start remains private pending its separate live recovery gate.
- `aiw-windows-platform` fixed-tree inventory and checkpoint: a crate-private read-only primitive holds the exact tree snapshot through publication, blocking tree writes, delete, and rename, and materializes a portable semantic inventory for exactly 19 objects. It records stable IDs, canonical paths, types, ACL/link/stream/attribute policy, file sizes and hashes, and EA names/flags/lengths/hashes; unstable queried-byte counts are excluded. A deterministic protected external checkpoint beside the workspace binds the v2 revocation record, exact inventory/hashes, parent/file identity, cleanup ID, and `.aiw-discarded-v1-<cleanupId>` tombstone. Create-new pending, write-through/flush, strict reopen, non-replacing handle-relative rename, final flush/reopen, and exact pending/final recovery preserve partial, conflicting, hardlinked, or drifted state and fail closed. No parent-directory flush or power-loss durability claim is made; no run-tree, journal/head, provider, CLI, `RunResult`, or public cleanup UX is present; child-first disposition is bounded to the 19 fixed objects.
- `aiw-provider-mxc`: pinned non-executing MXC dry-run/execution plans; it does not run MXC.
- `aiw-orchestrator`: strict run-plan, approval, journal, cancellation, recovery, result, and on-disk transaction boundary; it does not execute provider actions.
- `aiw-windows-command-line`: shell-free Windows argument quoting.
- `aiw-cli`: stable JSON command surface consumed by PowerShell and future UI. `run prepare-wsb`, `run verify-prepared-wsb`, and `run import-prepared-wsb` expose the non-provider preparation boundary; approval remains an explicit later step, and `run start` remains disabled.

## Planned execution boundary

```text
ordinary-user orchestrator
        |
        +-- short-lived elevated helper (fixed typed verbs only)
        |      owner-bound IPC, caller validation, canonical handles
        |
        +-- Windows Sandbox provider or checkpointed Hyper-V authoring worker
                 |
                 +-- fixed-function guest agent
                 +-- untrusted installer/application
```

The helper will be launched only for an approved fixed operation, use bounded messages, and exit after the operation. There will be no persistent SYSTEM service, arbitrary shell/script/path/registry/query verb, or automatic Windows feature/provider installation. A fresh workspace and provider lease are required for every mutating run; cancellation, crash recovery, reboot continuation (when declared), and idempotent cleanup are first-class states.

## Evidence and provider rules

Provider configuration is intent, not proof. A complete result must correlate host observations with guest evidence and record requested/effective backend, provider and OS provenance, target and descendant process tokens, policy/configuration hash, trace completeness, scenario results, boundary canaries, terminal receipt, and cleanup. Missing evidence, fallback, timeout, drift, or incomplete cleanup invalidates an isolation conclusion.

Provider order is Windows Sandbox, then experimental MXC ProcessContainer, with CreateProcessInSandbox research outside the Workbench release gate. Workbench v1 requires live end-to-end proof for Windows Sandbox and MXC; current adapters are plans only.

## Studio boundary

Studio uses disposable, checkpointed Hyper-V workers and pinned Microsoft packaging tooling. It keeps `deliveryModel: containedMsix` separate from `runtimeBoundary: mediumIlFullTrust | appContainer | appSiloPreview`. A converted full-trust MSIX is a compatibility baseline, not an isolation verdict. Capability Profiler output and narrowly scoped PSF remediation are proposals requiring explicit review and a complete Workbench revalidation. Signing occurs outside the untrusted worker, never exposes private-key material, and binds the final package hash to the final validation receipt. Master Packager is manual export/import only.

## Local AI and telemetry

An optional host-side Analyst consumes bounded verified evidence and returns cited plain text. It has no tools, credentials, network, execution, signing, deployment, or authority to alter deterministic findings. Model, runtime, and knowledge artifacts are separate trust classes, signed/hashed/versioned when introduced, and independently revocable. AIW has no automatic telemetry.

The initial supported host target is Windows 11 24H2/build 26100+ x64. Windows 10, ARM64, enterprise compliance certification, fleet management, and background application management are outside the first release.
