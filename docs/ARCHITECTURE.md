# Architecture

Updated 2026-11-08 against main `b27942a` and the repository-scope cleanup.
The [roadmap](ROADMAP.md) defines the recovery sequence; the
[source migration audit](APPLICATION-AGNOSTIC-MIGRATION.md) names coupling and
removal work. Proposed generic contracts below are not implemented merely by
being documented. Historical evidence remains bound to its original source.

## Product shape

AIW is an administrator-led laboratory for application installation/use assessment,
comparison and optional adaptation/authoring. **Workbench -> Wizard** is the
product progression; older records use Studio for the latter. Assessment must
stand alone before general packaging. A Windows desktop and CLI already exist,
but their end-to-end application workflows remain product-specific.

The target architecture is one capability-selected path for an administrator's
application, not one adapter per application. Extend existing typed concepts and
services. Names are descriptive; exact payload identities bind authority. A known
product name or compiled installer hash must not be admission to the new engine.
Unsupported operations produce specific blockers without discarding useful evidence.

```text
Windows desktop / CLI / PowerShell
                |
       shared application services
      /          |             \
protected     verified      plan/review/approval
intake        reporting           |
                          orchestrator + runner
                                  |
                      disposable Windows worker
                                  |
                    typed guest operations + untrusted app
                                  |
                      bounded evidence and terminal receipts
```

The outer worker and selected application-level isolation are separate. An ordinary
process in Sandbox is an in-worker baseline, not ordinary execution on every endpoint.

## Current components and limits

| Component | Implemented role | Recovery work / explicit limit |
| --- | --- | --- |
| `aiw-schema` | Typed project source (`msi`, `exe`, `portableDirectory`), entry points, intent, scenarios and versioned migration. | Schema recognition is broader than runtime support. Compile/validate supported operations coherently rather than introduce a parallel project format. |
| `aiw-probe`, `aiw-token`, `aiw-windows-platform` | Host/token/source observations; protected native intake and held-object authority; Windows execution helpers. | Generic source import is not generic installation. Product workflow code is mixed with reusable native mechanisms and must be extracted carefully. |
| `aiw-orchestrator` | Plans, approvals, lifecycle/event journals, cancellation, results, cross-file validation and recovery authority. | It does not itself execute providers. Windows Sandbox authority enters through validated preparation/import, not generic caller-created state. |
| `aiw-runner`, `aiw-provider-wsb` | Preparation, import, exact provider sessions, receipt verification, fixed app/control execution and recovery; retained reports, bundles and profiles. | Fixed MSI/Bambu/7-Zip and other closed paths must become generic capability-selected preparation/operations; do not generalize by accepting arbitrary commands. |
| `aiw-admin-workflow` | Shared operator services, complete approval review, separate Start, progress, fixed assessment/packaging and export workflows. | Replace product assets/recipe selection with one reviewed generic application plan while keeping authoritative services shared by GUI/CLI. |
| `aiw-guest-agent`, native helpers | Measured guest execution, stage observations, process/token/output checks and receipt-last completion for closed workloads. | Product request variants and workflow-specific executors remain. Target one typed operation protocol with explicit evidence and limits. |
| `aiw-core`, `aiw-evidence` | Comparison/evidence primitives, canonical identity and verification support. | Reuse them behind verified evidence. Existing core statuses include `Passed`, `Failed`, `Skipped`, `Incomplete`; broader result semantics require explicit version/mapping, not a new unreviewed verdict engine. |
| `aiw-control-fixture`, `aiw-control-appcontainer`, `aiw-golden-probe` | Project-owned controls and scoped token/file/registry/child boundary evidence. | Validate collection/enforcement mechanisms; do not substitute controls for a vendor application's own target/descendant observations. |
| `aiw-cli`, `powershell`, `gui` | CLI/PowerShell and actual Tauri desktop surfaces; offline retained Results browsing/export. | Product selections/projections remain. Offline Results opens verified selections, not trusted caller report JSON, and does not execute/recover runs. |
| `aiw-msix-worker`, VM helpers | Fixed MSIX worker lifecycle and retained report integration. | Fixed lifecycle evidence is not arbitrary conversion or a containment verdict. Generic packaging is optional later work. |
| `aiw-provider-mxc` | Non-executing, pinned MXC dry-run/planning adapter. | No MXC execution acceptance; current upstream contracts require a separately reviewed pin/adapter migration before adoption. |

Source details and deletion criteria are in the [migration audit](APPLICATION-AGNOSTIC-MIGRATION.md).
Retained implemented behavior is documented in [reports](ASSESSMENT-REPORT.md),
[Results](RESULTS-EXPLORER.md), [paired controls](PAIRED-NATIVE-APPROVAL.md),
[7-Zip assessment](SEVENZIP-ASSESSMENT.md) and [MSIX execution](MSIX-EXECUTION.md).
Their limits are not relaxed by this architecture.

## Lifecycles and contracts

Keep three conceptual lifecycles distinct:

- **Assessment:** source/intake, reviewed installation/use, optional baseline and
  candidate, observations, comparison and recommendations.
- **Replay:** drift-checked execution of a validated plan/profile with fresh
  run-specific approval and explicit runtime/data lifetime.
- **Authoring:** reviewed adaptations/capture, package inspection, signing outside
  the worker and validation of the final artifact. Packaging is not required to assess.

These are architectural responsibilities, not a claim that one generic
`AssessmentRun`, `LaunchRun` or `AuthoringRun` type implements the whole journey.

Existing `aiw.dev/v0alpha2` projects use typed `ApplicationSource`, `IsolationIntent`,
`ExecutionProvider` and `Scenario`. Legacy projects migrate non-destructively into
new reviewed revisions. The `aiw.dev/run-plan/v0alpha3` contract binds the canonical
project revision and WSB workspace evidence; earlier unbound plans remain readable
but cannot authorize mutation. Namespaced metadata/extensions cannot execute code
or control privileged behavior.

The generic extension must bind source identity, supported install mechanism,
entry-point discovery/review, argument vector, working directory, user context,
inputs, output assertions, requested boundary, observation scopes, budgets and
cleanup. Discovery may produce candidates but cannot grant new authority. Resolve
ambiguity and bind newly selected executable/policy authority before launch.

Authoritative state remains inspectable files: immutable project revisions,
hash-bound plans/approvals, append-only events/evidence, artifacts and terminal
receipts. Any UI index is disposable, never authority. Preserve held-file identity,
exact plan/session binding, complete provenance and receipt-last publication.

## Execution and recovery boundary

Installers and applications run only in approved disposable Windows Sandbox/VM
workers. The host performs protected intake, planning, review, reporting and
bounded orchestration. Do not expose a general privileged shell, script/path/query
verb or persistent SYSTEM service to implement the generic workflow.

Use reusable MSI/reviewed EXE/portable mechanisms. Unknown install semantics require
a bounded operator checkpoint or a capability blocker, not guessed flags. Catalog
metadata, scripts, application output, AI text and window titles are untrusted data.
Acquisition/dependencies/network/device permissions are separate explicit inputs.

Keep native process image/handle checks, safe shell-free argument quoting, bounded
output, deadlines, job ownership and exact cleanup. A driver control must prove
exit/output/timeout behavior before vendor trials. Fresh controlled state is needed
for each comparison role. Cancellation or recovery may act only on the exact owned
session, never another session with a similar name.

Windows mutations use held workspace authority and owner/SYSTEM-protected
coordination. Preserve lock/lease ordering and persisted provider transactions.
Read-only `run status`/reporting must not repair state; `run recover` is explicit.
Legacy recovery remains limited to the authority its original version recorded.

The private discard proof is still bounded to an exact 19-object tree: protected
external checkpoint, immutable depublish commit, exact non-replacing rename,
hash-chained pre-disposition records, handle-only deletion and terminal receipt.
Foreign/ambiguous state is preserved. Root absence alone is not complete cleanup.
File flushes do not establish parent-directory/power-loss durability. Do not expose
that proof as general workspace deletion; public discard and real retained workspace
shapes need their own design and verification.

## Evidence and comparison rules

Keep raw artifacts, normalized observations, function assertions, boundary checks
and recommendations distinct. The report must answer independently:

- Which exact app/input/workflow was exercised, and what passed, failed or did not run?
- Were baseline and candidate comparable, and which differences were intentional?
- What boundary/policy was requested, and what was actually measured on the target
  and required descendants? Which allowed/denied controls support each claim?
- Which collectors/scopes were available, incomplete, missing or inapplicable?
- What lifecycle/cleanup was observed, and what remains to recover or preserve?
- If requested, what adaptation/package is feasible and what additional checks remain?

Hash/receipt consistency is not authenticity against an administrator inside the
guest. State collector trust and corroboration limits; independently observed
process/boundary evidence is still required for claims the guest cannot establish.

Do not compress these into an `isolation-ready` boolean. A function pass does not
prove safety, a file change does not prove a dependency, and an absent event does
not prove denied access when capture is incomplete. UI/operator statements are
not automatically verified output assertions. Preserve valid completed observations
when another stage fails. Never infer incompatibility from driver/preflight failure.

Version semantic extensions explicitly and map historical fields conservatively.
Keep old evidence verifiable without changing its bytes or filling missing
observations. Legacy readers may project historical facts but cannot authorize
new execution or satisfy a new claim absent from the old evidence.

## Provider and packaging boundaries

Direct Windows Sandbox is the implemented outer worker. Classic AppContainer,
MXC ProcessContainer/BaseContainer/PSEC, MXC IsolationSession, Linux/WSLc and
experimental micro-VM backends have different capabilities; a shared schema does
not make them interchangeable. An unavailable or wrong-OS provider is a useful
capability result, not an app failure. [Selection research](MXC-ASSESSMENT-SELECTION.md)
and the [roadmap](ROADMAP.md#provider-research-and-later-expansion) explain the scope.

Declare minimum claim-specific controls before running. Preserve requested and
effective tier/policy, target/descendant evidence, denial/allowed controls,
completeness and cleanup. No silent fallback, automatic host-DACL mutation or
capability widening may produce an isolation pass. Outer offline Sandbox settings
do not prove inner network enforcement.

MSIX delivery is separate from `mediumIlFullTrust`, classic AppContainer and preview
App Silo runtime boundaries. Full-trust fallback cannot satisfy an isolation claim.
Optional package capture uses approved disposable workers and pinned tooling;
include capture drivers and other setup side effects in the plan. Reviewed PSF
remediation is not arbitrary script authority. Master Packager is manual handoff
only. Sign outside the untrusted worker and bind final signed bytes to fresh
validation. Outputs and third-party content stay outside this repository/releases.

## Intake version boundary

File and portable-directory intake receipts emit `v0alpha2`. After validating the
complete native EA set, intake excludes only the kernel-managed
`$KERNEL.PURGE.SEC.FILEHASH` cache from canonical EA authority and independently
verifies payload SHA-256. Other allowed EA values, identities, ACLs, names, streams
and payload hashes remain authoritative. Unknown EAs and standalone FILEHASH on
directories are rejected. `v0alpha1` requires fresh import, not reinterpretation.
The fixed-tree discard contract retains exact cache binding. Download-stream
normalization has its own [versioned policy](DOWNLOAD-METADATA-INTAKE.md).

## Local AI, distribution and host scope

Optional local analysis consumes bounded verified evidence and returns cited
advisory text. It has no authority to change deterministic results, execute an
adaptation, grant permissions, sign or deploy. No automatic telemetry is required.
If a chosen dependency/provider has diagnostics behavior, review its exact version
and disclose it before adoption; a roadmap does not opt the user in.

Publish AIW tools, contracts, project-owned controls and applicable dependency
notices, not vendor applications/configuration or generated product bundles.
The [repository scope](REPOSITORY-SCOPE.md) and [release gates](RELEASE-GATES.md)
apply to source and built artifacts. Current desktop publication remains paused.

The initial host target is Windows 11 24H2+ x64, with exact servicing build/runtime
and request-specific capability checks. Windows 10, broad ARM64, fleet management
and enterprise compliance certification are outside the first generic release.
