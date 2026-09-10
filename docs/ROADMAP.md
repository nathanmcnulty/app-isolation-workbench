# Roadmap

Revised 2026-09-09 against the implemented runner and current Microsoft documentation. This replaces the former W0-W5/S0-S4 ordering; those labels remain historical references, not release dependencies.

The goal is a free community tool that answers **which tested application functions work under which measured isolation configuration**, helps an administrator adapt the application, and produces a launch profile or package that passes the same tests. Workbench evolves into Studio when authoring is useful; this is one product.

Deliver **Assess -> Adapt -> Package -> Validate** for a narrow application class before expanding every provider, collector, lifecycle, and UI. Community feedback is welcome whenever capabilities are usable, but a feedback round is not a development gate.

## What is already working

- Protected MSI/EXE and portable intake; held-file integrity and embedded signature observations.
- Approved Windows Sandbox golden-probe and fixed Notepad++ MSI execution; exact-session cleanup and recovery.
- A live document install/open/edit/save/close benchmark, launched-process token observations, and scoped installation/use file changes.
- Receipt-bound passed/failed/not-reached stages for completed and caught-failure scenarios; JSON/Markdown retained reports that reject drift and preserve missing evidence.
- Portable comparison/evidence primitives and an MXC planning adapter. These are not a live baseline/candidate comparison or an executable MXC provider.

The [fixture record](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md) records dated live proof. The current v6 workload installs with the elevated guest agent, then exercises the application as a verified standard user inside Windows Sandbox. The fixed document workflow has passed in multiple fresh standard-user runs; the v6 registration slice adds one recorded live execution. Historical elevated configurations remain separately readable. This is an in-worker function baseline, not a general endpoint compatibility claim. Scoped application registry capture and machine MSI product registration are implemented and live-tested; broader dependencies, reusable isolated launch and package generation remain unimplemented. Public workspace discard is unfinished; the private fixed-tree disposal proof is not general intake/MSI workspace cleanup.

## Changes in direction

| Previous ordering | Revised decision | Reason |
|---|---|---|
| Complete all assessment evidence before useful conclusions | Report function results, boundary verification, and capture completeness separately | A passing workflow is useful while a broader isolation verdict remains indeterminate. |
| Windows Sandbox and experimental MXC required before validated launch | Prove one application-level candidate and its replay first | An unfinished second provider must not block the first working mode. |
| Packaging starts only after a completely accepted isolation assessment | Allow evidence-bound experimental recipes; require final validation before calling a package validated | Adaptation or packaging may be necessary to make isolation work. |
| Broad collectors/general scenario engine before diverse applications | Add a second real application and a controlled fixture; extract primitives used by both | Expose Notepad++ assumptions without inventing an arbitrary command platform. |
| Large UI/release milestone at the end | Ship CLI, reports, and contribution fixtures with each capability; add UI over stable services | Community usefulness comes from working capabilities. |

## Supplied installer corpus

The [installer inventory](INSTALLER-CORPUS.md) now makes profile selection concrete: Notepad++ EXE/MSI controls, DriveManager for elevation/device dependencies, Bambu for a richer local-file workflow, and Signal/ChatGPT/Visual Studio for acquisition dependencies. Signal and ChatGPT are Store wrappers in this folder; DriveManager is an SK hynix disk utility. Do not select fixtures solely by installer size or apparent UI simplicity.

[Bambu Studio export](BAMBU-STUDIO-PROFILE.md) is now the second production execution/reporting consumer: a separately typed EXE profile uses approved start, standard-user STL-to-3MF export, bounded package/geometry verification, and retained JSON/Markdown reports. Its information-query compiler remains metadata-only. [Mixed application report sets](REPORT-SETS.md) now preserve distinct function columns and explicit unavailable/failure evidence. The [project-owned control](CONTROL-FIXTURE.md) now passes repeated standard-user/ACL/child/failure development checks in fresh workers. A paired ordinary-user/AppContainer file and child control now also passes in fresh workers; registry checks, real-application repeatability, and approved control integration remain open. Slicing remains a later function with version-sensitive printer/material settings.

The corpus exposed an intake requirement now addressed by [explicit download metadata archiving](DOWNLOAD-METADATA-INTAKE.md): all seven supplied files pass protected intake, with source identity and metadata unchanged. Retain this bounded policy when broadening profiles; arbitrary streams remain rejected. Separate networked payload acquisition from offline application assessment; bind downloaded payloads, not just launcher hashes. These are prerequisites for using the affected fixtures, not reasons to enable networking on the existing offline profile.

## Benchmark 1 - comparable application evidence (next)

**Deliverable:** a repeatable function report with an ordinary in-worker baseline, packaging-relevant state observations, and explicit comparison eligibility.

1. **Implemented and live-tested:** separate privileged installation from standard-user application execution, record actual identity/token/profile, and bind application-data file capture to that account. Preserve the elevated fixture as its own configuration. Scoped user-registry capture now uses the same account; comparison eligibility is still pending.
2. **Scoped registry snapshots implemented:** machine/user Notepad++ settings in both views, with explicit absence and incomplete-scope diff suppression. Machine Windows Installer product state is now bound to the approved MSI identity and live-tested. Next add static dependency hints alongside file observations. Record key/value identity, type, size/hash, registry view, phase, and incompleteness; raw values require an explicit capture policy. Distinguish installed state, observed runtime use, static references, and unresolved dependencies. A changed file/key or PE import alone does not prove a required dependency.
3. Add a second real application profile and a project-owned control fixture with expected success, denial, child-process, and failure cases. Use clean repetitions to identify unstable state; retain raw evidence and version normalization rules. Never hide a difference merely to make comparisons pass.
4. Preserve completed file/registry snapshots when a later application stage fails, bound to the failed receipt and stage prefix; missing phases must remain explicitly unmeasured. Implemented and live-tested: the optional v5 failed-snapshot event and unsuccessful report v0alpha4 retain this metadata. A controlled post-install failure preserved installation evidence while leaving later phases unmeasured; the production success path also passed. Report interrupted/pre-start/recovery states observationally, without repairing state or inferring uncommitted guest progress. Explicit bounded [report sets](REPORT-SETS.md) now summarize retained runs without an index, preserve unavailable entries and suppress duplicate verified identities. A persistent local index remains optional; it must be rebuildable and never execution authority.

**Completion criteria:** two clean repetitions of the selected standard-user scenario produce comparable function results; changed inputs, account, scenario, or environment are detected. A second application exercises shared collection/reporting code. Capture gaps remain visible, and a failed control fixture cannot become an application incompatibility claim.

General tracing, every installer type, printing, networking, updates, and reboot support are not prerequisites.

## Benchmark 2 - one real isolation comparison

**Deliverable:** the same approved workflow under an ordinary baseline and one application-level isolation candidate, with an explainable function matrix.

The bounded classic AppContainer feasibility control now passes a same-user file/child comparison in two fresh disposable workers, using documented profile/process APIs in the native authority layer. Complete the declared registry control and approved evidence integration next, then an appropriate real application. Unpackaged AppContainer launch is documented, so an MSIX converter need not precede this experiment. This is not a claim that Notepad++ will work unchanged. See [control proof and limits](CONTROL-FIXTURE.md), [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer), and [MSIX AppContainer apps](https://learn.microsoft.com/en-us/windows/msix/msix-container).

Also evaluate Microsoft's newly documented [experimental process-in-sandbox APIs](https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox) as a bounded alternative implementation. They offer a declarative AppContainer specification and an alternate-user entry point, but currently have an experimental ABI, no public header/schema source on the documentation page, and no precise minimum Windows build. First verify exports, specification availability and a project-owned control fixture inside a disposable worker. Keep the documented classic AppContainer path available; the presence of `processmodel.dll` alone is not a supported-provider result.

End the feasibility slice with a recorded supported/unsupported result for the exact fixture and environment. If a real application cannot run, preserve the control-fixture evidence and identify whether the limitation is in the adapter, driver, or still unknown. Choose the next application/candidate explicitly; do not leave the whole roadmap waiting on one AppContainer experiment or silently fall back to a weaker mode.

Use fresh instances of the same worker image with matching app bytes, input data, user context, scenario/driver version, network setting, and OS/tool provenance. Windows Sandbox can remain the outer boundary if the required semantics are verified there; otherwise use a checkpointed test VM and document the difference. Neither approach authorizes untrusted installers on the administrator's host.

An ordinary process inside a worker is an **in-worker baseline**, not proof of ordinary execution on every endpoint. Windows Sandbox containment and AppContainer inside it are separate boundaries; report both. Pair runs through an explicit descriptor binding their exact revisions and allowed candidate-policy differences. Requiring identical whole-project hashes is inappropriate when the candidate changes; accepting arbitrary mismatches is also inappropriate.

Declare the candidate's minimum check set before approval. For the first AppContainer profile it includes target/required-child AppContainer identity and capability checks, an allowed-access control and denied file/registry probes outside the grants, cleanup, and completeness of the observations supporting those claims. An offline/network-denial claim additionally requires its own controlled network probe. Canaries operate on project-owned fixtures inside the worker and report that scope. Other boundaries remain unmeasured. Do not remove a failing requirement after a run to label the same profile validated.

**Completion criteria:** target and required descendants have the intended effective boundary, selected denial canaries work, cleanup is verified, and identical scenarios produce a baseline/candidate matrix. A baseline or driver failure prevents attributing a difference to isolation. Missing evidence blocks the claims that require it and never becomes a passing isolation verdict.

Reuse `aiw-core` comparison primitives behind verification of bound run evidence. Do not introduce a competing verdict engine or trust caller-constructed summaries.

## Benchmark 3 - adaptation and reusable launch

**Deliverable:** an administrator can trial one narrow adaptation and rerun the failing scenario; a working candidate can be replayed through a drift-checked launch profile.

An inspectable recipe candidate binds source hashes, relevant evidence, target mode, exact resource grants, working directory/data locations, and required scenarios. Start with a small change such as a package-owned data directory or fixed working directory. Add targeted runtime access/module observations when they answer an actual failure; broad tracing is not the default prerequisite.

A recipe candidate is an experiment, not a compatibility certificate. Trial it inside the disposable worker, show the access change, and require new bound approval when authority changes. Rerun functions and affected boundary canaries. Never add broad ACL changes, capabilities, or full-trust fallback automatically to make a test succeed.

The first reusable output can be a launch profile; it need not be an MSIX. Bind app, launcher/agent, provider, OS compatibility constraints, policy, data contract, and validation evidence. A Windows Sandbox profile must declare session lifetime and data persistence; a process-isolation profile must prove its own boundary and descendants. Relevant drift invalidates the profile or requires explicit revalidation.

**Completion criteria:** one real application has a reproducible adaptation comparison and working replay; app/policy drift rejects replay, cleanup is recoverable, and access outside the declared grants remains denied. Validate replay in a fresh environment matching deployment: an inner-worker result alone cannot establish a host-launch claim.

## Benchmark 4 - first reproducible package

**Deliverable:** one supported application can be packaged, installed on a clean worker, and pass its declared workflows under the selected runtime boundary.

Start with deterministic assembly of an owned/portable payload or explicit recipe when sufficient. Use pinned Microsoft tooling for installer capture when needed; avoid building another general repackager. Reuse the disposable VM boundary for capture and validation. Microsoft's [Packaging Tool workflow](https://learn.microsoft.com/en-us/windows/msix/packaging-tool/create-app-package) supports clean local, remote, and Hyper-V conversion environments.

Keep delivery and runtime isolation separate. A full-trust MSIX is an intermediate packaging experiment, never an isolation result. Sign outside the untrusted worker, preserve upstream signatures, and bind the final signed hash to fresh validation. Reproducibility means declared semantic payload/manifest equivalence; do not promise byte-identical signed artifacts when timestamps/signatures differ.

**Completion criteria:** a declared application/version installs, launches, completes workflows, handles its supported data contract, and uninstalls on a fresh worker. The exact package/runtime profile must satisfy its predeclared function matrix and the minimum effective-boundary/canary checks for that runtime, plus any additional asserted restrictions. These checks pass for the exact signed output; unsupported checks remain gaps and cannot support a validated claim that requires them. Test update/reboot when those capabilities are claimed. Unsupported lifecycles remain explicit. Deliver recipe, provenance, coverage, limitations, and final validation together.

## Expansion after the first complete loop

- Broaden the fixture corpus and MSI/EXE/portable profiles. New executable behavior is reviewed code with a bounded, hash-bound contract; community metadata cannot inject commands, scripts, arbitrary paths, or privileged verbs.
- Add lifecycle functions and collectors for concrete application classes: persistence, update/uninstall, reboot, network, printing, shell/COM, services, and drivers. Each addition states the claim its evidence supports.
- Evaluate Win32 app isolation/App Silo and MXC as independent adapters. Classic AppContainer and Win32 app isolation are not interchangeable. Microsoft still labels [Win32 app isolation as preview](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-overview), and its [release notes describe full-trust fallback](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-release-notes); effective-boundary checks must reject that fallback for isolation claims. Neither adapter gates the first package or launch capability.
- Add Tauri flows over existing services as capabilities become stable: intake, run/recovery, function matrix, adaptation diff, and validated launch/package. UI work can accompany benchmarks; it need not wait for every provider.
- Add opt-in sanitized evidence export and community profile/fixture contributions. No central service or automatic telemetry is required. Optional AI may summarize cited evidence or suggest a recipe, but never alter deterministic findings, grant permissions, or execute adaptations.

## Implementation and validation rules

Preserve held-file authority, exact approval/session binding, receipt-last publication, recovery, and historical evidence semantics. Version contracts when meaning changes; absent observations stay unmeasured.

Keep raw evidence, normalized observations, function results, boundary assertions, and recommendations distinct. Reports should say which workflow passed for which bytes/configuration. A green summary must not hide missing functions, uncertain capture, or failed boundary checks.

Use bounded implementation slices and independent review where warranted. Validate locally first; run live Sandbox/VM tests when execution or boundary behavior changes, and retained fixtures for report changes. Batch hosted CI around reviewed integration milestones, avoid duplicate push/PR runs and unchanged reruns, and keep expensive matrices explicit. Saving worker hours must not bypass required merge checks.

Finish public discard for actual retained workspace shapes as repeated runs require it. Reuse disposal authority; do not generalize the private 19-object proof into recursive cleanup. Storage retention, user data, and evidence deletion need explicit policies.

## Not on the critical path

CreateProcessInSandbox research; mandatory MXC support; universal installer conversion; arbitrary PSF scripts; enterprise certificate/fleet services; centralized telemetry; broad OS/ARM64 support; automatic feature/provider installation; and a product rename. The initial host target remains Windows 11 24H2+ x64, with each actual provider capability checked independently.

Master Packager remains a manual, provider-neutral handoff. Existing research and pinned adapter work are retained. Revisit deferred work when a concrete application need or verified platform capability justifies it.
