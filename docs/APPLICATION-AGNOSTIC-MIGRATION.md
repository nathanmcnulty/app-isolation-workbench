# Application-neutral migration audit

Reviewed 2026-11-08 against main `b27942a6a71561395ff462083a79d350aac93d15`
and cleanup `df6f3295c43dbd6636e68526dd0c8d078abc8d68`. This is a source audit
and implementation checklist, not implemented generic support. It expands
[issue #108](https://github.com/nathanmcnulty/app-isolation-workbench/issues/108)
and [R0-R5 of the roadmap](ROADMAP.md#current-delivery-sequence).

## Boundary and migration strategy

Use one generic path, extending the existing project/intake/scenario and
orchestrator/runner boundary. Preserve working safety mechanisms; move application
facts into validated data; retire product dispatch. Do not delete retained evidence
or weaken its verifier to make migration easy. Existing fixed execution can remain
visible as a legacy path only while its replacement is built and reviewed; it may
not expand or become a gate on the new path. Freeze new product-specific adapters.

A new application may provide data: exact source identity, install mechanism and
reviewed arguments, entry-point candidates, input fixtures, declared operations,
output assertions and observation scopes. It may not supply executable plugins,
privileged callbacks, embedded scripts or a product-specific compiler. A generic
mechanism must be justified by reusable behavior, not a renamed brand branch.

## Source inventory and disposition

This is the concrete starting inventory. The implementation owner must finish a
repository-wide symbol/call-site audit and attach deletion evidence at R5; this
review does not claim every product string is an execution decision.

| Surface and inspected source | Current coupling | Replacement and retirement condition |
| --- | --- | --- |
| [Schema](../crates/aiw-schema/src/lib.rs) and [schemas](../schemas) | `ApplicationSource` and `ScenarioStep` are generic, but accepted steps exceed live executor coverage. | Extend/version these concepts; publish capability validation and reject unsupported steps explicitly. Preserve old wire meanings. |
| [CLI](../crates/aiw-cli/src/main.rs) | Product selection and separate MSI/Bambu/7-Zip command families. | One generic service entry; remove new-execution product selection after equivalent generic acceptance. Keep explicit retained-report/recovery compatibility. |
| [Admin service](../crates/aiw-admin-workflow/src/lib.rs), [packaging](../crates/aiw-admin-workflow/src/packaging.rs), [7-Zip](../crates/aiw-admin-workflow/src/sevenzip.rs), [MSIX](../crates/aiw-admin-workflow/src/msix.rs) | Fixed product IDs, asset manifests, scenarios and package recipes; closed installer expectations. | Generic intake/plan/review/start services and runtime assets; independent source identity supplied at run time. Preserve approval, separate Start and safe export services. |
| [Scenario compiler](../crates/aiw-provider-wsb/src/scenario.rs), [Bambu](../crates/aiw-provider-wsb/src/bambu_scenario.rs), [7-Zip](../crates/aiw-provider-wsb/src/sevenzip.rs), imported requests | Fixed paths/process names, stage sequences, installer hashes and result shapes. | One typed capability-selected compiler/protocol. Fixture paths/arguments/assertions become declarative data. Retain legacy validation only for old evidence/recovery. |
| [Guest dispatch](../crates/aiw-guest-agent/src/main.rs) and its workload modules | Product-specific request variants and execution. | Generic bounded operations and version dispatch. Remove legacy new-execution variants after regression transfer; retain no arbitrary shell verb. |
| [Windows platform](../crates/aiw-windows-platform/src) `guest_msi`, `guest_document`, `guest_bambu`, `guest_sevenzip`, `guest_standard_user`, `control_appcontainer` | Reusable native safety and file/process primitives mixed with fixed application logic. | Extract held installer/image validation, reviewed MSI/EXE preparation, standard-user launch, job/deadline/output/cleanup, and measured policy controls. Delete product workflow assembly only after portable and native negative tests cover extracted behavior. |
| [Runner](../crates/aiw-runner/src) preparation/session/report/bundle/profile modules | Shared custody/recovery core plus product-specific preparation, report, package and replay contracts. | Generic preparation and verified observation/report projection; reuse transaction authority. Keep legacy readers separate from any new run authorization. Package/replay later consumes the same plan. |
| [Core](../crates/aiw-core/src), [orchestrator](../crates/aiw-orchestrator/src), [evidence](../crates/aiw-evidence/src), [probe](../crates/aiw-probe/src) | Reusable comparison, approvals, journals, hashes and host/intake observations; some actions bind fixed WSB workspaces. | Reuse rather than create another verdict engine. Review contract changes that let generic preparation enter authoritative state; never accept caller summaries as verified results. |
| [Desktop backend](../gui/src/main.rs), [Results](../gui/src/results.rs), [frontend](../gui) | Product pickers, package branches, hard-coded application/function projections. | Generic action/identity/function data from shared services; keep read-only versioned historical projections. UI selections cannot bypass service validation. |
| [MSIX worker](../crates/aiw-msix-worker/src), [VM scripts](../scripts/vm-msix), [packaging](../packaging) | Fixed Notepad++ capture/execution/manifest assets. | Defer generic authoring to R6. Preserve existing historical verification and exact recovery, not a new fixed app distribution route. |
| [Fixtures](../fixtures), [examples](../examples), [PowerShell](../powershell), [tests/scripts](../scripts) | Fixed workflow inputs, test assertions, developer/operator handoffs. | Project-owned fixture data and generic mechanism tests. Keep historical application instructions dated; external vendor payloads stay external. Audit generated fixtures as well as source. |
| [Hosted workflows](../.github/workflows), desktop builders and verifiers | Prior release layout still expects product assets. App-MSIX workflow and installer-bundling builder removed; desktop candidate jobs paused. | AIW-only tools/contracts/project-owned controls and required dependency notices. Review output inventories, archive contents, signing and publication before resuming. Never treat a passing source-content scan as a release-archive audit. |

## Required contracts before implementation broadens

1. **Source and acquisition record:** exact local file or portable manifest hash;
   catalog/publisher provenance, observed signature, architecture/scope, dependencies
   and input hashes. A rolling URL or bootstrapper identity does not bind later bytes.
   Catalog metadata cannot authorize switches, networking or downloaded execution.
2. **Plan and discovery:** source identity, supported installation mechanism, bounded
   entry-point discovery, validated executable/argument vector/working directory,
   user context, requested boundary, observation scopes, deadlines and cleanup.
   Ambiguity or new authority requires review; no automatic first-EXE selection.
3. **Worker operations:** closed typed operations with held paths/identities and
   resource limits. Operator checkpoints have a bounded purpose and deadline, not
   unrestricted host access. Newly supported generic primitives need their own
   tests, not an escape hatch for a difficult fixture.
4. **Evidence:** durable stage records, actual executable/process identities,
   assertions and their sources, collector availability/completeness, output identity,
   provenance, failure and cleanup. Separate observed artifacts from operator claims.
5. **Comparison:** bind baseline/candidate revisions and explicitly allowed policy
   differences, with comparable clean environments and source/inputs/workflow/user.
   Baseline failure, driver failure and incomplete capture cannot be isolation blame.
6. **Results:** render facts from verified retained evidence. Preserve not-run,
   failed, unmeasured and not-applicable distinctions; version changes must not
   silently create observations absent from historical records.

These are design obligations. They do not introduce new wire schemas in this
change; each implementation slice must specify its actual versions and migration.

## Deletion checklist

- [ ] Trace every product enum/name/hash/path decision to fixture data, mechanism,
  historical reader/recovery or a specific production deletion.
- [ ] Implement one generic intake/plan/service/guest/report path without requiring
  fixture-registry membership, product hash allowlists or per-app compilation.
- [ ] Transfer ordinary-user launch, custody, timeout, output, denied-access and
  cleanup regressions from existing paths before removing their mechanisms.
- [ ] Exercise current reference workflows as data on the generic path; compare
  declared semantics, not rewritten old receipts or fabricated identical history.
- [ ] Remove app-specific new-execution CLI/UI selections, request dispatch,
  compilers, fixed recipe/package assembly and product publication assets.
- [ ] Keep needed legacy receipt readers and exact recovery narrowly separated;
  verify that old records cannot authorize new generic runs or bypass new approval.
- [ ] Preserve frozen historical schema meanings and original hashes. Legacy data
  may be displayed or migrated into a new reviewed project, never upgraded to proof.
- [ ] Audit source and generated release inventory for vendor binaries/configuration,
  installer download/bundle steps, opaque archives and accidentally public evidence.
- [ ] Add contract/architecture checks: fixture display-name changes do not change
  acceptance; payload drift invalidates approval; unlisted identities can use
  supported capabilities; unknown operations and executable recipe hooks are rejected.
- [ ] Complete the seven-fixture matrix and independently chosen post-implementation
  holdout with a completed declared normal-use workflow and no product code change.
  Exercise the required mechanism classes; blockers alone are not a passing matrix.
  Record genuine unsupported mechanisms.
- [ ] Reconcile docs, examples, help text and released UI with the final capabilities;
  pass required checks and independent exact-head review before calling R5 done.

## Test plan and evidence expectations

Use project-owned controls to verify the driver before any vendor application.
Test unknown operations, unsafe arguments/path escape, reparse/link substitution,
changed payloads, stale/tampered approvals, child-process surprises, output/evidence
loss, timeouts, cancellation, interrupted receipt publication and cleanup conflicts.
Do not delete foreign state during recovery. Driver controls, unit/synthetic results
and real-app trials are different evidence classes.

Run representative MSI, EXE, portable and multiprocess workflows in fresh workers;
retain exact inputs/environment and repeat selected cases for nondeterminism.
An output content comparison need not require byte-identical archive containers
when timestamps/metadata are outside the declared semantic assertion. Report an
unexplained difference rather than invent its cause.

For GUI steps, verify open/edit/save/reopen or another observable task outcome,
not a window appearing. Browser local-content tests do not cover internet access,
authentication, updates, extensions, downloads or every browser child. Printers,
physical devices and live accounts require separate authorized scenarios.

A release review must inspect both the generic path and what was actually deleted.
A new generic facade over the same product switch fails this migration even if
all original fixture tests stay green.
