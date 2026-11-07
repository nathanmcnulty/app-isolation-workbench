# Multi-mode 7-Zip assessment

Active work started 2026-11-06 from main `b27942a` (merged #106), branch
`codex/multimode-assessment`. This document is an implementation/acceptance map,
not proof that the new source has passed native acceptance.

The deliverable is one administrator workflow comparing the same pinned 7-Zip
installation and create/test/extract/content verification under an ordinary
baseline, classic AppContainer and MXC ProcessContainer when available. Retained
Results must distinguish function results, measured restrictions, unsupported
requirements, missing evidence, coverage and owned cleanup across modes.

## Required evidence

| Requirement | Proof required before completion |
|---|---|
| MXC adoption | Official release/source/native asset identities, dependency and signature review; explicit approved acquisition/installation scope; exact request-aware capability observation in the actual worker |
| Safe execution | Exact runtime, policy, environment and application binding; no implicit recovery, DACL mutation, weaker fallback or automatic grant widening; effective tier and supported restrictions measured |
| Comparable workflow | Same vendor bytes and automated representative operations for all supported modes; unavailable/unsupported MXC remains explicit and does not block independent work |
| Application tree | Actual root and descendant image/token identity with collection completeness and owned job boundaries; absence of observed children must not imply comprehensive capture without a validated mechanism |
| Registry controls | Project-owned positive ordinary-user control and candidate denial, bound to the tested profile/process; no modification of unrelated registry keys |
| Archive investigation | Retained bounded actual archives and extracted bytes plus relevant metadata; independent rehash and inspection, with byte equality separate from content equality and hypotheses separate from measured cause |
| Repeatability | Repeated comparisons in fresh disposable environments on the new source; same policy/workflow/inputs and source-pinned outcomes, with differences retained |
| Failure/recovery | Native interruption, invalid output, missing output and owned recovery on new source; useful failure evidence retained, unrelated resources preserved, recovery does not rerun the app |
| Administrator flow | Review/Approve/Run, multi-mode function/control/coverage/cleanup/failure presentation, retained reopen and sanitized export with no app/provider execution |
| Engineering finish | Focused regressions, authorized native proof, independent consequential review/fixes, concise documentation, clean branch and PR; criterion-by-criterion Benchmark 2 mapping with W4/W5 limits |

Previous #106 native observations remain valid only for their recorded source,
profile and environment. Reuse those records for context and historical Results
compatibility, not as acceptance of this new source. Keep private raw records
outside Git. Installers/application trials stay inside disposable workers. Ask
before runtime installation or VM/security-setting changes.

## Current implementation

The first increment adds private bounded archive/extracted bytes and input
FILETIME/attribute observations to new 7-Zip results. Historical results omit the
optional fields without changing canonical serialization. Current source binds
the new collector and validator into the approved workflow hash. This does not
yet establish an archive-difference cause, new native acceptance, MXC execution,
descendant completeness or registry enforcement.

The existing MXC adapter remains the old non-executing pin until the new
versioned native contract and artifact custody are reviewed. The official
v1.0.1 CLI's startup recovery and typed SDK's omitted fallback policy require a
direct-interface review; do not treat CLI `--probe` as a read-only operation.

The default-off capability helper and host harness now use the exact JSON C ABI
and existing owned Sandbox lease. They preserve separate Prepare/Approve/Start,
bounded failed/partial observations, atomic final publication, exact cleanup and
non-replaying recovery. They do not dispatch an MXC workload or 7-Zip, and cannot
be imported as verified production application results. The user approved the
pinned runtime for this goal's fresh Sandboxes on existing VM107 through reviewed
Proxmox-console scripts. Parent runtime installation and VM/host security changes
are excluded. The first [native capability trial](MXC-PROBE-NATIVE-20261106.md)
captured five native-tier support reports but failed the host output custody
check; owned outer cleanup passed. No workload creation/enforcement or application
acceptance is established. The corrected publication path subsequently passed
its fresh first-party control, including stable custody across cleanup and Read.

The default-off creation control now uses the exact Driver request and a
cooperative first-party child. It requires ordinary positive file controls,
same-account held child identity/token observations and an owner-held exact job
check before a protected gate releases candidate controls. Fixed phase records
survive later wait/free/cleanup failures. Its separate host profile retains raw
bytes with an accepted-hash check, without turning research observations into
product verdicts. Source `55068e6` reached SDK spawn success in one
[fresh native trial](MXC-CREATION-NATIVE-20261106.md), then refused at a combined
token guard before retaining the actual child token. Ordinary positives and owned
cleanup passed; the gate stayed closed and enforcement remains unmeasured.
The fresh `9093182` correction retained actual token evidence and passed
cross-observer identity/exact-job checks before gate release, then timed out
without contained SELF or filesystem controls. Cleanup and retained Read passed;
enforcement remains unmeasured. An early-entry diagnostic correction removes
redundant contained WinRT/account lookups while preserving outside authorization
and the full protected gate. Its fresh `53e1d9b` trial also timed out without
final ENTRY/SELF/controls, despite matching outside identity/job checks and gate
release. Cleanup and Read passed. Pending publication bytes were not collected,
so neither timeout locates the failure or proves MXC unavailable. Bounded raw
diagnostics now preserve complete bytes or explicit refusals for eight fixed
final/pending names after owned child cleanup. Serialized component and aggregate
budgets keep the combined report below the publisher limit while preserving
earlier parsed facts and the actual owner binding error. This correction has
focused negative tests and independent review; its native validation and the
independent ordinary/classic application tree work remain next.
No 7-Zip ran in these controls.

Process-tree controls are default-off research only; registry foundations remain
test-compiled only. A closed tree-only entry runs fixed ordinary/classic
root/child/grandchild roles without executing the staged vendor installer or
application. It retains independently bound suspended-root measurements and
atomically publishes traces before required helper fail-stop. Actual serialized
traces are capped at the 128 KiB stage-reader limit; oversize becomes an explicit
non-trace refusal preserving digest, byte count and actual cleanup facts.
The collector's five-second control deadline and three-second drain fit the
unchanged preinstall watchdog. The dedicated host harness now binds fresh
session/source/environment/input identities and approval to one-shot Start and
exact recovery. The 8.3 terminal marker embeds bounded fixed stages, preserving
failed measurements independently. Retained Read makes no provider calls and
requires the original full marker identity, size and digest before raw export.
A Rust verifier recomputes positive control facts without rounding identifiers;
native positives, deliberate chain-reset-negative proof, application tracing and product receipt wiring
remain incomplete. The collector
records an inherited debugger chain, not broker-created processes or invented
parent edges; any gap requires the dedicated helper to fail-stop. The registry
canary uses an exact newly-created key handle for deletion and suppresses hidden
Drop retries after explicit cleanup. Registry-link/create-only semantics still
need focused disposable-worker proof before production wiring; freshness of a
dedicated account before application launch is a prerequisite, not proof of
general race-safe registry creation. No parent registry ACL is changed.

The fresh source `191ac276` [native tree trial](SEVENZIP-TREE-NATIVE-20261106.md)
retained an ordinary six-process trace: three helpers and three console hosts,
with paired events and reconciled exact-job counts. It correctly failed the
predeclared three-helper contract before the candidate. Seven mapped owner-stage
reads separately returned unsupported FileIdInfo; local trace/binding records
survived. Strict marker custody, owned outer cleanup and provider-zero retained
Read passed. Preserve this partial result. The correction must keep strict
general custody and all observed process coverage, with fresh owner journaling,
explicit code-bound support roles and new native proof; it cannot turn this
historical failure into a pass.

The `f27dda8` [correction trial](SEVENZIP-TREE-CORRECTION-NATIVE-20261106.md)
retained all seven local owner stages and the ordinary code-5 journal denial.
Its six-process ordinary trace was refused because preheld and debug-event
console volume/file identities differ despite matching path, hash, size and exit.
The candidate was not reached. Custody, outer cleanup and retained Read passed;
the identity source remains under investigation, with no retrospective exception.

Private raw metadata contains full-width FILETIME/process/file identifiers.
Audit it with Rust or another lossless JSON parser; ordinary JavaScript numbers
cannot preserve these integers. Sanitized JSON/Markdown omits raw bytes and
metadata. The old Node audit must not be reused on new raw events without
lossless integer handling.
