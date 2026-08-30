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

## Current components

- `aiw-schema`: strict project/model-pack parsing and semantic validation.
- `aiw-evidence`: canonical JSON, append-only hash chains, and deterministic allowlisted assessment manifests.
- `aiw-core`: legal state transitions, deterministic comparison, conservative canary evaluation, and advisory-report validation.
- `aiw-probe`: read-only environment and executable discovery, plus a conservative Windows Sandbox readiness report. Unknown feature, virtualization, signature, or session state is a blocker; it never enables a feature or elevates.
- `aiw-token`: audited native Win32 target-token evidence boundary.
- `aiw-golden-probe`: fixed in-target token evidence probe used by the narrow live W1 mapping/logon proof.
- `aiw-provider-wsb`: hardened `.wsb` rendering, lifecycle planning, and completion-receipt verification.
- `aiw-guest-agent`: fixed-function token collector for the W1 golden probe. Its strict request has no command, script, URL, glob, or policy fields and it writes the completion receipt last.
- `aiw-runner`: fail-closed W1 preparation, import, lifecycle, and recovery kernel. Preparation validates the project and trusted empty provider state before creating a protected workspace, holds an explicitly expected-hash guest-agent source through staging, binds provider/workspace/agent identities into fixed WSB and run plans, and writes the strict preparation receipt last. Import reopens and retains the exact workspace, receipt, plans, and agent while the orchestrator atomically publishes a provenance-bound pristine `PendingApproval` run. The orchestrator also contains a private opaque revocation guard: it holds the run lock across future protected external discard-intent publication and internal hash-bound revocation, and external control presence fail-closes every ordinary mutation or recovery path. It performs no deletion and is not wired to the CLI. A separate verifier reopens the exact pre-import workspace after process exit and rejects ACL/file-ID, artifact, output, project, agent, provider, catalog, protocol, or session drift without acquiring the provider. The execution kernel uses a strict persisted provider-session transaction, exact-ID recovery, and a private native test adapter. Its native launcher creates the exact verified provider image suspended, restricts inherited handles, assigns the CLI process to a kill-on-close job before resume, and enforces bounded output, an invocation deadline, and a fixed cleanup allowance. The live proof covers start, exact-session reconciliation, connect-triggered user logon, receipt verification, stop, and absence. Production provider start remains unavailable. A verified W1 receipt remains insufficient evidence for a containment verdict.
- `aiw-runner` recovery: new `v0alpha3` transactions bind the complete workspace evidence, request path relative to the held tools directory, and pinned provider protocol into each transition hash. `aiw run recover` reopens that exact workspace, rereads unchanged transaction authority while its handles are held, independently validates the current Store provider, and performs only list/optional exact-stop/list reconciliation. Legacy `v0alpha2` records remain readable for exact provider cleanup but cannot authorize request deletion. General provider start remains private pending its separate live recovery gate.
- `aiw-windows-platform` exact-dispose benchmark: a crate-private issue #30 primitive observes the fixed 19-object imported WSB tree, reopens every object by stable ID with delete-capable handles, atomically depublishes only the held root to a non-replacing tombstone, and applies classic disposition in a fixed child-first order. Every mutation is preceded by full remaining-tree revalidation of IDs, type, owner/SYSTEM ACL mode, hard links, streams, content, directory namespace, short aliases, and the bounded SmartLocker kernel-EA policy. EA evidence retains only names, flags, lengths, and SHA-256 digests, never values. A live shared RunLock can coexist with observation and exact reopen, but NTFS rejects the ancestor rename until that handle is released; the failed attempt proves no namespace mutation and restores/revalidates the descendant handles for an exact retry. This primitive contains no path-recursive deletion and is not authority: protected external intent, durable checkpoints, crash-prefix classification/resume, runner integration, and CLI exposure remain issue #28 work.
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
