# Roadmap

Updated 2026-11-08. This is the current product direction and delivery order.
[Issue #108](https://github.com/nathanmcnulty/app-isolation-workbench/issues/108)
tracks the application-neutral recovery. [Repository scope](REPOSITORY-SCOPE.md)
sets publication and licensing boundaries. This plan does not implement the
capabilities below, authorize live trials, or change a provider/runtime pin.

## Product decision

Build a free, community Windows workbench that helps IT administrators assess
**an application they supply**, understand observed requirements and failures,
compare ordinary and isolated behavior, and decide what to do next. It is not an
application store, a repackaged-app collection, or a supported-product catalog.

**Workbench -> Wizard** describes the progression from useful assessment to
guided adaptation and optional packaging. Earlier documents call the latter
Studio. No repository rename is required. Keep **Assess -> Adapt -> Package ->
Validate**, but make assessment useful without a package, known product recipe,
complete containment verdict, or every backend being implemented first.

The recovery decision is to build one generic path and retire product-specific
execution after its reusable mechanisms and regression coverage are transferred.
Do not add another named application adapter, rename fixed adapters to make them
look generic, or replace them with an executable plugin registry. During migration,
label existing fixed paths honestly; they are not the generic path.

An unknown application name is never a rejection reason in the new engine.
A supported source/operation may run under a reviewed plan; a missing capability
must yield a precise blocker and any useful completed observations. Application
identity, payload hashes and approved authority remain mandatory, but hashes are
per-run inputs, not a compiled catalog admitting only known applications.

## Intended administrator journey

This is the target journey, not a claim that today's desktop implements it.

1. **Supply an application and goal.** Select a locally acquired MSI, EXE or
   portable directory, representative inputs and the workflows that matter.
   Record provenance and exact bytes. Acquisition is separate from execution;
   an online bootstrapper is not the installed application. Keep vendor payloads,
   generated packages and private evidence outside the source repository.
2. **Inspect and scope.** Inspect source metadata, host/worker capabilities and
   dependencies without running the application on the host. Declare what the
   test can measure, what requires an operator and what will remain unknown.
3. **Prepare and review a bounded plan.** Choose the installation mechanism,
   entry point, argument vector, user context, inputs, output checks, observation
   scopes, deadlines, cleanup and candidate policy. Resolve ambiguous discovery
   explicitly. Review authority, data lifetime/export, network/device requests
   and prerequisites; bind approval to the exact plan. Start remains separate.
4. **Exercise normal use in a disposable worker.** Install or stage the app,
   discover/review entry points, and perform real tasks, not only launch/exit.
   Typed automation, agents using approved worker controls, and human checkpoints
   can complement each other. Record which method supplied each observation.
   A new executable target or authority outside the reviewed plan needs a fresh
   bound review before launch; discovery is not blanket execution permission.
5. **Read a useful assessment.** Show installation/use results, actual processes,
   scoped changes, observable requirements, artifacts, failures and gaps. An
   observed file access or installer dependency is not proof of a minimal runtime
   requirement. The report can be useful before any isolation candidate runs.
6. **Compare when supported.** Repeat the same workflow in clean comparable
   baseline/candidate states with identical app/input identities and application
   user context, varying only declared candidate policy. Keep function, effective
   boundary, capture completeness and cleanup separate. A failed baseline or
   driver prevents attributing a difference to isolation.
7. **Adapt, package or stop.** If evidence identifies a concrete problem, propose
   a small reviewed change and rerun affected workflows and boundary checks.
   A report alone is a completed useful outcome. Optional replay/package output
   consumes the same validated plan; packaging limitations do not block assessment.
8. **Retain and reuse evidence safely.** Reopen results without execution, inspect
   evidence and export only explicitly selected allowed data. Preserve incomplete
   attempts and precise recovery state. Relevant app/policy/provider drift requires
   fresh approval and revalidation, not reuse of an old successful label.

## Current implementation and evidence

The reviewed source base is main `b27942a6a71561395ff462083a79d350aac93d15`
(PR #106), with the README and distribution cleanup layered above it. The
[architecture](ARCHITECTURE.md) and [migration audit](APPLICATION-AGNOSTIC-MIGRATION.md)
identify concrete code to reuse or remove.

- Generic building blocks exist: `ApplicationSource`, typed `ScenarioStep`,
  protected intake, approval/session binding, evidence/journal transactions,
  provider planning, scoped observations, recovery and project-owned controls.
  A schema accepting a source or step does not mean execution implements it.
- The desktop and CLI exist. Their end-to-end application paths still dispatch
  fixed Notepad++, Bambu Studio and 7-Zip workflows, with product-specific guest,
  platform, packaging and report branches. General assessment is not complete.
- Retained Notepad++/Bambu workflow and MSIX records, project-owned paired controls,
  and the fixed 7-Zip comparison are useful scoped regression evidence. The
  [7-Zip record](SEVENZIP-NATIVE-ACCEPTANCE.md) includes a successful exact run
  and an earlier incomplete attempt; neither certifies an arbitrary app.
- The [Results Explorer](RESULTS-EXPLORER.md) verifies retained inputs and exports
  bounded summaries. It is not a generic live assessment or a second verdict engine.
- MXC remains planning-only at the checked-in pin. Classic AppContainer has scoped
  controls and a fixed app comparison; general descendant, policy and repeatability
  coverage remain work. MSIX delivery does not establish an isolation boundary.
- Third-party application publication is retired/paused as described in
  [scope](REPOSITORY-SCOPE.md). Existing desktop assets/builders still need an
  application-neutral replacement. Prior releases and native evidence are unchanged.

## Current delivery sequence

Milestones are ordered by dependency and useful outcome, not dates or app count.
Small completed slices may ship with explicit limits. The generic release gate
requires R1-R5; R6 is optional later work. R0's source/distribution safeguards also
apply throughout. A candidate that truthfully fails is a valid assessment result.

### R0 - Establish the recovery boundary

**Deliver:** one source inventory, ownership of the current slice, and a release
policy that cannot accidentally publish vendor content or extend fixed adapters.

- Classify product names/hashes/paths across CLI, schemas, services, provider,
  guest/platform code, runner, GUI, reports, examples, tests and build/release scripts.
- Use the [migration checklist](APPLICATION-AGNOSTIC-MIGRATION.md) to separate
  reusable mechanisms, declarative fixtures, read-only legacy readers and code
  to delete. Keep current runtime limitations visible.
- Retain project-owned controls and synthetic fixtures with unmistakable provenance.
  External native fixtures stay external; do not replace their exact trust pins
  with synthetic identities or call synthetic tests native acceptance.
- Keep application publishing paused until an AIW-only distribution inventory,
  target-specific dependency notices and clean-host validation are reviewed.

**Exit evidence:** reviewed inventory and deletion criteria; content/governance
checks; no vendor payload added; current docs and release claims agree. This
milestone alone does not make the engine generic.

### R1 - One application-neutral assessment contract

**Deliver:** an inspectable, versioned plan compiled from existing project/intake
and scenario concepts, plus capability diagnostics, without executing an app.

- Bind immutable source/payload identity, installer mechanism, reviewed entry-point
  selection rules, exact argument vector/working directory, application user,
  input/output contracts, observation scopes, limits and cleanup policy.
- Separate discovery from execution. Validate registration/shortcut/executable
  candidates against held identities; never select the first EXE or execute a
  catalog command string. Materially new discovered authority needs a new plan.
- Define reusable MSI, reviewed EXE and portable preparation. Installer-family
  mechanisms such as MSI/Inno/NSIS may be supported; product-name dispatch may not.
  Unknown silent semantics require a bounded operator-assisted checkpoint or
  an explicit missing-capability result, never guessed switches.
- Record capability decisions by source, operation, provider and environment.
  Unknown fields/verbs fail closed. Existing unsupported schema steps remain
  unsupported rather than becoming arbitrary shell execution.

**Exit evidence:** contract/negative tests; known and unlisted app data compile
through the same path when their requested capabilities are supported; a changed
payload invalidates approval; changing a descriptive name does not change behavior.

### R2 - Useful generic installation and normal-use assessment

**Deliver:** one end-to-end assessment path inside a disposable Windows worker,
initially using the existing Sandbox execution foundation, without packaging.

- Compile typed install/stage, launch, bounded readiness/wait, operator checkpoint,
  observe, graceful-close and output verification into one guest protocol.
- Reuse held-file checks, safe argument quoting, process/job control, exact sessions,
  bounded output, receipt-last publication and recovery. Validate the driver using
  project-owned success, output and timeout controls before vendor execution.
- Collect durable per-stage progress, actual target/process identities, scoped
  installation/use file and registry observations where supported, artifacts and
  cleanup. Record scope/collector failures; do not promise exhaustive tracing.
- Exercise representative real use. Distinguish automated checks, observed artifacts
  and operator statements. Checkpoint confirmation cannot assert unobserved output.
- Stop safely on timeouts, cancellation, drift, evidence loss or unsupported steps.
  Preserve completed observations and exact next recovery action without implicit
  reinstall, retry, policy widening or interference with another worker.

**Exit evidence:** independently reviewed generic path, authorized fresh-worker
MSI/EXE/portable trials selected incrementally from the corpus, useful retained
success/failure/interrupted reports, and a named capability blocker when needed.
Do not require every corpus case before completing the first useful slice.

### R3 - Comparable function and isolation evidence

**Deliver:** the generic scenario can be compared across a controlled ordinary-user
baseline and at least one supported isolation candidate without application dispatch.

- Use fresh comparable state for each mode and bind a pair descriptor to exact
  source, inputs, workflow, user context, environment and allowed policy differences.
  Reject accidental mismatches; do not require identical whole-plan hashes when
  the intended policy differs. An in-worker baseline is not endpoint equivalence.
- Start with the measured classic AppContainer mechanisms where applicable.
  Declare the minimum claim-specific checks before approval: actual target and
  required descendants, token/capability policy, allowed controls, denied resources,
  completeness and cleanup. File/registry/network/IPC/UI claims need their own
  relevant probes, not a generic green isolation badge.
- Keep outer worker containment separate from the inner candidate. Enforce exact
  grants; do not disable application sandboxes, accept full-trust fallback, or
  remove failed requirements after the run to manufacture success.
- Reuse verified comparison services. Missing measurements invalidate the claims
  that need them while leaving other observed workflow results available.

**Exit evidence:** a truthful baseline/candidate matrix, working controls and
negative cases, repeated fresh-worker cases, explicit descendant/collector gaps,
and no isolation conclusion from launch, exit code, package format or configuration
alone. Broader providers do not gate the first candidate.

### R4 - One administrator path and truthful reports

**Deliver:** GUI and CLI use shared application-neutral services for intake ->
plan -> review/approve -> separate Start -> results -> compare/export.

- Replace product pickers, fixed recipe choices, app-specific progress/result
  columns and compiled installer allowlists in the new path with validated records.
- Render exact application/workflow identities, observations, failures, scope,
  missing coverage and safe next steps from verified evidence. Keep backend
  verification authoritative; no trusted report-JSON import or GUI verdict engine.
- Cover missing prerequisites, ambiguous entry points, unsupported operations,
  approval cancellation, interrupted execution, retained reopen and export refusal.
  Opening results must not start, recover, retry or mutate a run.
- Retain read-only legacy receipt/report verification without silently upgrading
  historical evidence. Keep original versions, hashes, limitations and cleanup scope.

**Exit evidence:** an administrator uses the packaged generic path with an app
outside the fixture list, without compiler access, product-code changes or developer
paths; all error states have useful next actions and no fabricated function results.
Implementation can accompany R2/R3 rather than wait for every backend.

### R5 - Prove generality and retire fixed execution

**Deliver:** a regression matrix and completed deletion checklist demonstrating
that the product does not need to recognize an app to assess it.

- Run the [seven-fixture corpus](INSTALLER-CORPUS.md#application-neutral-recovery-corpus)
  through the same engine, using independently acquired and pinned inputs. Cover
  MSI, EXE, portable, per-user/machine, GUI, multiprocess and dependency variation.
- Publish per-stage outcomes and specific capability/evidence gaps. Exercise actual
  completed MSI, reviewed EXE, portable, multiprocess and GUI/operator-assisted
  ordinary-use workflows; a matrix made only of blockers does not prove generality.
  Some candidates may fail under isolation; this is not universal compatibility.
- Repeat representative MSI, EXE, portable and multiprocess cases in fresh workers
  and retain failed/interrupted attempts, not just successful summaries.
- After implementation is fixed, independently choose a holdout application absent
  from the corpus. Complete a declared normal-use workflow using intake/scenario
  data only, without rebuilding
  for its identity or adding an executable plugin. If it exposes a missing generic
  primitive, implement/review that mechanism and select another holdout afterward.
- Delete superseded product execution branches and fixed publication assets once
  their generic regressions pass. Keep only necessary read-only historical readers,
  exact recovery compatibility and declarative fixtures; test that they cannot
  authorize new execution or publish a product bundle.

**Exit evidence:** matrix, holdout record, no product-name/hash admission gates,
architecture/negative tests, reviewed deletion diff and required exact-head checks.
Ship an AIW-only package under [release gates](RELEASE-GATES.md), not an app bundle.

### R6 - Optional adaptation, replay and packaging

**Deliver:** evidence-backed changes and reusable administrator-owned outputs
using the same plan, when an actual workflow need justifies them.

- Propose the smallest settings/resource change explaining an observed failure.
  Show the grant diff and require fresh authority approval; rerun affected function
  checks and denial controls. No automatic broad ACL/capability grants.
- Produce drift-checked replay before requiring general MSIX conversion. Declare
  runtime boundary, app/agent/provider/OS identity, data lifetime and validation scope.
- Use free deterministic assembly or pinned Microsoft capture tooling where feasible.
  The [MSIX Packaging Tool workflow](https://learn.microsoft.com/en-us/windows/msix/packaging-tool/create-app-package)
  may enable a capture driver and temporarily disable Windows Update; declare
  these setup effects and confine capture to its approved disposable worker.
  Keep commercial tooling optional; Master Packager remains a manual export/import
  handoff, not an embedded/called dependency without separate vendor authorization.
- Validate install, function, data contract and uninstall on clean workers. Test
  update/reboot only when claimed. Sign outside the untrusted worker; validate the
  final signed bytes. Reproducibility means declared semantic equivalence, not an
  unconditional byte-identical signature/timestamp promise.

**Exit evidence:** exact output provenance and claim-specific lifecycle/boundary
checks. A full-trust MSIX is delivery, not an isolation pass. Users retain outputs
outside this repository and remain responsible for application distribution rights.

## Provider research and later expansion

Continue research across MXC's process, session, micro-VM and Linux-container
families, alongside classic AppContainer and separate MSIX/Win32 app isolation
work. Select by actual workload and available capability, not a mandatory provider
checklist. [Source-pinned selection research](MXC-ASSESSMENT-SELECTION.md) records
prior findings; recheck the selected release/platform before adoption. Current
Microsoft [platform support](https://learn.microsoft.com/en-us/windows/apps/develop/mxc/platform-support),
[architecture](https://learn.microsoft.com/en-us/windows/apps/develop/mxc/architecture)
and [policy](https://learn.microsoft.com/en-us/windows/apps/develop/mxc/policy)
documentation guide research, not AIW acceptance. MXC 1.0 does not accept the raw
retired 0.8.0-alpha policy contract: adoption needs an explicit versioned adapter
migration, not simply replacing the binary under the existing planning pin.

- Direct Windows Sandbox is the current outer disposable Windows worker; a
  checkpointed Windows VM may support capture or workflows requiring another worker.
- MXC ProcessContainer/BaseContainer/PSEC is not classic AppContainer. Prove actual
  tier, target/required-child policy and side effects before using its claims.
- MXC IsolationSession provides Windows identity/session separation; its documented
  filesystem/UI and required network policies do not meet every deny policy.
- WSLc runs Linux workloads. Linux execution is not the same native-Windows app
  comparison. Experimental MicroVM/Hyperlight and MXC WindowsSandbox are not general
  Windows-app providers merely because a shared schema names them.
- Win32 app isolation/App Silo is a distinct preview. Check its [overview](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-overview)
  and [release notes](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-release-notes)
  for the selected platform; reject full-trust fallback for isolation claims.
  MSIX is a delivery model, independent of the measured tier.

Add collectors, lifecycle functions, networking, printing, services, drivers, COM,
plugins and devices only for declared administrator needs and with their own safe
contracts. Optional AI may summarize cited evidence or propose a plan, never grant
permissions or change deterministic findings. Community feedback and sanitized,
opt-in evidence contributions are useful, not prerequisites or automatic telemetry.

## Evidence, safety and validation rules

All installer/application execution stays in approved disposable Windows workers,
never on the host. Retain protected intake, held identities, typed bounded actions,
exact approval/session binding, receipt-last publication, cancellation and exact
recovery. Do not replace these with free-form scripts to accelerate generality.

Distinguish acquisition/host prerequisites, driver failure, application workflow
failure, candidate restriction, collector incompleteness and cleanup failure.
Use explicit blocked, not-run/not-reached, not-applicable, failed and unmeasured
outcomes where appropriate; these are semantic requirements, not claims that a
new unified result schema is already implemented. State which recorded version's
fields express each meaning. Reports must not silently promote partial evidence.

Run proportional checks once against the completed slice. Documentation uses
link/content/governance review; execution and trust-boundary changes also require
negative tests and authorized disposable-worker evidence. Keep synthetic, portable,
Windows-only, native and hosted results distinct. Independent review and required
CI must cover the exact integration head. No new live trial is needed to reword
unchanged historical evidence. See [development workflow](DEVELOPMENT-WORKFLOW.md).

Public discard for real retained workspace shapes remains unfinished; the private
19-object proof is not general cleanup. Preserve user data/evidence and foreign
state. Retention, evidence deletion and recovery need explicit scopes.

## Not on the critical path

Universal compatibility, every isolation backend, arbitrary installer conversion,
all possible tracing, broad OS/ARM64 support, fleet services, mandatory cloud/AI,
central telemetry, commercial packaging, direct undocumented ABI research, automatic
feature/provider installation and an immediate rename are not prerequisites.
The initial target remains Windows 11 24H2+ x64 with exact build/provider capability
checks, not a promise that every such host supports every candidate.

## Historical milestones

The [previous roadmap](ROADMAP-HISTORY-2026-11-06.md) preserves fixed-profile
benchmarks and their original acceptance links. [Historical release gates](RELEASE-GATES-HISTORY-2026-11-08.md)
record exact prior preview/public-alpha proof. They explain retained evidence;
they do not define the next supported-app catalog or authorize new publication.
