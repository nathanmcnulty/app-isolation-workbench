# Release gates

Updated 2026-11-08. These are the gates for the application-neutral recovery in
[the roadmap](ROADMAP.md). Existing signed alphas and exact fixed-profile trials
remain [historical evidence](RELEASE-GATES-HISTORY-2026-11-08.md), not proof these
gates are complete. The desktop candidate workflow stays paused until its
application-neutral distribution layout and publication checks are reviewed.

## Documentation and source integration

A reviewed documentation/scope change may merge without claiming generic-engine
or release acceptance. Require exact-head independent review, link/content checks,
applicable repository governance and required hosted CI. A local unavailable tool
or Windows-only check is a disclosed limitation, not a pass. Do not start another
installer trial merely to rewrite historical findings.

Distribution cleanup also changes scripts/tests/assets; apply their checks in
addition to documentation checks. Preserve original native evidence and external
fixture trust pins. Do not relabel synthetic test fixtures as native acceptance.

## First generic assessment release

| Gate | Required evidence |
| --- | --- |
| Application-neutral authority | One shared plan/service/guest/report path. Unknown app names do not block supported mechanisms. Exact payload, inputs, operation/policy and environment bind approval. No product enum, compiled hash catalog or executable recipe plugin is needed for a new app. |
| Useful assessment before packaging | Administrator supplies an app and declared workflows, inspects/reviews/approves the plan, separately starts a disposable worker, and receives observed requirements, functions, failures, gaps and safe next steps without first creating a package. |
| Mechanism coverage | Actual completed ordinary-use workflows exercise MSI, reviewed EXE, portable, multiprocess and GUI/operator-assisted capabilities across the seven-fixture corpus. Every declared fixture is attempted through the same engine with per-stage outcomes; a table containing only blockers is not sufficient. Candidate incompatibility is a valid truthful result. |
| Independent holdout | After implementation is fixed, select an app absent from the fixture corpus and complete a declared normal-use workflow through the released path using only intake/scenario data, without product production changes or rebuilding for identity. If a generic capability must change, review it and choose another holdout afterward. |
| Meaningful comparison | At least one supported candidate runs the same generic workflow under comparable clean baseline/candidate conditions. Required target/descendant/policy controls, evidence completeness and cleanup support only the claims they measure. A broken baseline/driver cannot yield isolation incompatibility. |
| Truthful results | Function, comparability, effective restrictions, collector completeness and cleanup remain separate. Failure, interruption, not-run and unmeasured cases retain valid observations. Retained viewing/export cannot execute, recover or mutate a run; historical evidence is not upgraded to new-schema proof. |
| Safety and recovery | Negative tests cover unknown operations, unsafe/path-escaped input, substitution/drift, stale approval, missing evidence, unexpected descendants, cancellation, timeout and cleanup conflict. Exact ownership is preserved; no foreign-session stop, automatic widening or full-trust fallback. |
| Product adapter retirement | Reviewed deletion checklist removes superseded new-execution product paths and fixed publication assets. Any retained product reader/recovery path has a documented historical purpose and cannot admit a new run. |
| Usable GUI/CLI | Shared services implement intake -> plan -> review/approve -> separate Start -> run -> report/compare/export. Missing prerequisites, ambiguity and failure have understandable next actions. No compiler, internal JSON hand-editing or developer-specific paths are required for the normal UI flow. |
| Repeatability and limits | Repeat representative MSI, EXE, portable and multiprocess cases on fresh workers, record declared time/resource budgets and nondeterminism, preserve interrupted attempts, and publish exact supported host/provider limits. No universal performance or compatibility claim. |

Acceptance evidence must identify source revision, tool/package hashes, acquired
payload/input identities, OS/provider versions, approved plan, run/evidence roots,
completed stages, gaps and cleanup. Fresh worker evidence is not endpoint-wide
proof. Native Windows checks, project-owned controls, synthetic/unit tests and
operator statements are reported separately.

## AIW-only distribution gate

Before resuming a public desktop workflow:

- Replace fixed product assets/builders with an application-neutral inventory of
  AIW binaries, generic contracts, project-owned controls and necessary dependency
  notices. Runtime requires separately supplied app inputs; do not fetch/ship
  installers, extracted vendor content/configuration or generated app packages.
- Audit both tracked source and the assembled release archive. The repository
  content check is useful but does not inspect every encoding, historical commit,
  old release or generated artifact. Closed inventory/provenance checks remain
  necessary. Do not delete prior releases/history as a side effect of this gate.
- Resolve target/features in both Rust workspaces; review applicable dependency
  licenses/notices and source obligations. The Unlicense applies only to original
  project-owned material and does not relicense tested apps or earlier releases.
- Build from a clean exact source revision, bind binaries/guest/contracts/verifier
  identities, preserve upstream signatures and keep signing outside workers.
  Verify signed published bytes, authenticated provenance and inventory before
  claiming public-download acceptance.
- Have an independent operator use the packaged generic workflow on a separate
  supported clean environment with independently supplied app inputs. Cover one
  real-use success, a useful blocked/failed result, cancellation, retained reopen,
  export refusal and exact cleanup. Clearly label automation versus human evidence.
- Publish capabilities, evidence limits, ephemeral data/export warnings, retention
  and recovery instructions. Required integration CI must pass for the actual head;
  successful assembly or signing alone is not runtime acceptance.

The first generic release is still experimental. A precise unsupported operation
is acceptable; a product-name allowlist disguised as a capability check is not.

## Optional replay and package gate

Assessment release does not require this gate. When delivering an administrator's
replay profile or package, consume the same validated generic plan and require:

1. Exact app/agent/provider/policy/OS/input provenance and drift rejection, with
   new run-specific approval and explicit lifetime/data/export behavior.
2. Reviewed adaptation/grant differences and affected workflow/canary revalidation;
   no automatic permission expansion or disabled application protections.
3. Fresh-worker install, declared functions, data handling and uninstall for the
   final output. Update/reboot and other lifecycle claims need their own evidence.
4. Signing outside the untrusted worker and validation bound to final signed bytes.
   Full-trust MSIX is packaging, not an isolation result. Semantic reproducibility
   must state which differences are allowed.
5. Local/private output outside the source and AIW releases. The administrator
   obtains vendor inputs and is responsible for any redistribution rights.

## What does not gate useful assessment

Every app passing, every MXC/backend implemented, universal conversion, MSIX
creation, a commercial tool, central telemetry, community feedback, broad tracing,
fleet deployment and a repository rename are not release prerequisites. Only
claim capabilities actually implemented and measured for that release.
