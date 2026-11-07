# Working state

Updated 2026-11-06 (America/Anchorage). Checkout `C:\aiw\app-isolation-workbench`,
fresh branch `codex/multimode-assessment` from current main `b27942a` after #106.
Start with `scripts/work-status.ps1` and the active
[multi-mode acceptance map](MULTIMODE-ASSESSMENT.md). The full multi-mode goal is
active; neither implementation nor native acceptance is complete.

## Current increment

- New private bounded archive/extracted-byte and FILETIME/attribute observations
  are bound into the 7-Zip source identity. Historical absent fields preserve
  canonical serialization. Verification facts are durably published before
  optional capture, so capture failure does not erase the measured prefix.
- The official MXC v1.0.1 source and release ZIP were acquired inertly and reviewed.
  Exact x64 `mxc_ffi.dll`: 6,123,320 bytes, SHA-256
  `bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c`;
  acquisition Authenticode Valid, Microsoft Corporation. Private provenance and
  dependency/SBOM limits: `C:/aiw/mxc-multimode-20261106/PROCESSCONTAINER-INTEGRATION-REVIEW.md`.
- A separate closed v1.0.1 ProcessContainer contract rejects DACL fallback,
  non-native tiers, BFS, degradation and missing requested controls. The old
  planning-only MXC pin is preserved separately. Probe success is capability
  evidence, never enforcement or execution approval.
- The user approved this pinned runtime for the goal's fresh Sandboxes on VM107
  through reviewed Proxmox-console scripts; parent runtime installation and
  VM/host security changes remain excluded. The source `2e77e4f` capability trial
  loaded MXC only as an ordinary guest user. All five captured probes reported
  native-tier request support, independently audited, but host custody rejected
  the marker's short-name alias (`RESULT~1.JSO`). Start failed at its deadline; owned
  outer cleanup passed and retained Read made zero provider calls. Preserve this
  failed run; no workload creation/enforcement was measured. The
  [native record](MXC-PROBE-NATIVE-20261106.md) binds the packet, launcher correction,
  authorization, source and evidence outside Git.
- The separate host capability harness binds two payloads, exact policies and
  embedded source/environment identities to Prepare/Approve/Start. It preserves
  failed child/partial collection/cleanup facts and publishes guest markers
  atomically without overwrite. Read and exact recovery cannot replay Start.
- A default-off first-party publication control now tests the unchanged strict
  reader against `RESULT.TMP` to `RESULT.DAT`, the old long-name alias, occupied
  destination identity/bytes and incomplete output. Source framing includes the
  exact-entry validator and token/schema/entry code. Independent review fixes
  remove sharing-denial and dangling-entry confounders; observations must match
  across cleanup and retained reads. Source `b66cf4e` staged but Prepare rejected
  `.DAT` under the generic JSON-only renderer; no proposal/provider/Sandbox ran.
  Preserve that partial root. A default-off exact-pair renderer/55-byte seed gate
  now keeps all other modes unchanged. The fresh R2 trial at source `e702ec3`
  passed strict marker/artifact acceptance, Win32 183 no-overwrite with original
  occupied identity/bytes unchanged, partial-output retention and stable
  observations across verified owned cleanup. Retained Read matched with zero
  provider calls. No MXC or application ran in this publication control.
- Creation-time debugger-chain controls are now wired only behind the default-off
  `research-sevenzip` feature; owned registry-canary foundations remain test-only.
  Neither has production role wiring or native acceptance.
  Registry deletion uses the exact retained key handle; debugger gaps require
  the dedicated helper to fail-stop even if job accounting later reconciles.
- A bounded typed process-chain contract now validates create/exit sequences,
  PID reuse intervals, externally supplied held-root token/image/time binding
  and exact-job accounting. The native collector emits exit-event
  sequences and checks token schema/event PID. Both sources are now included
  in the application source commitment. This foundation is not production wiring
  or native descendant coverage; fast-child/grandchild proof remains required.
- A closed research-only `--output C:\AIW\SevenZipOutput\RESULT.DAT` entry runs ordinary and classic
  first-party root/child/grandchild controls without vendor execution. The
  installer is held and staged inertly under existing intake rules. Suspended
  root token/time/image bindings are retained independently; PI/job ownership
  transfers once on the creator thread. Partial traces are published before
  required helper fail-stop; profile deletion then stays explicitly unverified.
  Five-second collection plus three-second drain fits the unchanged preinstall
  owner watchdog. A trace exceeding the 128 KiB stage limit becomes a separate
  bounded refusal with exact serialized digest/size and actual cleanup facts,
  never a truncated accepted trace. A separate fixed host harness now binds its
  fresh session, exact two held inputs, source, environment and approval to
  single-use execution and exact non-replaying recovery. Its marker embeds 17
  fixed stage/data-error keys under actual serialized budgets. Read strict-opens
  only `RESULT.DAT`; raw export must match the original full file identity, size
  and digest. A Rust verifier recomputes positive root/chain/job/profile facts
  without rounding full-width identifiers; custody and failed measurements stay
  separate from verified control facts. Native positive/chain-reset-negative
  proof remains next; this entry is not an administrator product flow.
- The default-off creation control now dispatches only the fixed cooperative
  Driver request. Matching ordinary filesystem positives precede spawn; an
  ordinary held-process observation and an owner-held exact-job check precede
  a protected release gate. It retains failure prefixes across SDK wait/free
  and owned cleanup. A separate closed host profile binds its root/session,
  Driver-only policy and raw retained output to approval. Independent execution
  and custody reviews passed after fixes. Source `55068e6` then completed one
  [fresh native creation trial](MXC-CREATION-NATIVE-20261106.md): ordinary positives
  passed and SDK spawn returned status 0/PID, but the combined token guard refused
  before retaining the child token or releasing the gate. Actual mismatch and
  candidate enforcement remain unmeasured. Owned worker/outer cleanup passed;
  original marker bytes stayed stable and retained Read made zero provider calls.
  Preserve this run. The fresh `9093182` trial retained full token evidence,
  passed ordinary/owner identity and exact-job checks and released the gate. It
  then timed out without SELF or filesystem controls. Cleanup/Read custody passed;
  enforcement remains unmeasured. The contained-entry correction now publishes
  preauthorization diagnostics before token queries and delegates redundant
  WinRT/account checks to the verified outside owner chain. Its fresh `53e1d9b`
  trial again passed outside identity/job/gate checks but timed out without final
  ENTRY/SELF or controls. Cleanup and Read custody passed. Final-only collection
  misses pending/invalid publication bytes. The new collector retains all eight
  fixed final/pending diagnostic files as complete bounded bytes or explicit
  refusals, independently of parsed prefixes. No trial may be replayed, and neither timeout proves a cause,
  MXC unavailability or application incompatibility.

Focused checks so far: 11 provider retention tests, 9 existing/new 7-Zip native
file tests, 7 preparation/retained-reader tests, 7 MXC contract tests, 7 probe/
mapped-transport tests, 5 host marker/recovery tests, 5 debugger-state tests,
4 pure registry tests and the GUI private-artifact JSON/Markdown projection test
passed. Consequential independent review fixes include output-prefix preservation,
normalized Unicode names, System32-only dependency search, actual loaded-module
identity, atomic final markers and full emitted-shape parsing. Native tests are
pending for the application path. Logs are `C:/aiw/multimode-*.log`, outside Git.
Publication checks: 2 guest, 10 host (including the 5 prior capability host tests),
7 MXC regressions and focused all-target Clippy passed. New logs are
`C:/aiw/publication-*.log`. All 101 default and 102 research-feature provider tests
passed, including physical seeded-output negatives. The R2 publication control
passed in a fresh Sandbox; original outputs and independently audited private
received envelopes remain outside Git. See the native record for pins and limits.
Creation slice: 11 focused platform and 13 host tests, 101 default/102 research
provider tests and all-target research Clippy passed. Logs: `C:/aiw/creation-*.log`.
Token-observer correction: 12 focused platform and 13 host tests passed; all-target
research Clippy passed. Independent execution-boundary and native-record reviews
found no remaining blockers. Logs: `C:/aiw/creation-token-*.log`. A fresh fixed
creation root/session prevents adoption or replay of the previous trial.
Contained-entry correction: 13 focused platform and 13 host tests and all-target
research Clippy passed. Independent execution-boundary review found no remaining
blockers. Logs: `C:/aiw/creation-entry-*.log`; its fresh native trial is a retained
partial result, not enforcement acceptance.
Raw-diagnostic/process-chain foundation: 106 provider tests, 17 focused platform
tests, 15 host-harness tests and all-target research Clippy passed. The earlier
full platform run passed 216 tests with 10 ignored; subsequent budget changes
were covered by the focused rerun. Independent reviews passed after fixes for
serialized aggregate limits and preservation of the actual owner binding error.
Logs: `C:/aiw/process-tree-provider-final-tests.log` and
`C:/aiw/raw-diagnostic-*-final*.log`. That correction framed 15 shared files;
the subsequent control-only module brings the current count to 16. Historical
trial packages retain their original 13-file commitment. Raw capture
and the process-chain contract still require their own disposable native proof.
Control-only wiring: 2 profile tests, 16 focused 7-Zip/platform tests, 5 debugger
state tests, research all-target Clippy and default-feature all-target compilation
passed. Independent execution/custody review passed after watchdog, control-only
scope and serialized trace-limit fixes. Logs: `C:/aiw/process-tree-control-*.log`.
No new native session or application trial ran for this increment.
Tree-host custody/verification: 106 default and 107 research-feature provider
tests, 20 focused platform tests, all 24 host-harness tests and all-target
Clippy with both research features passed. Independent reviews passed after
exact preexecution guest-version gating, cached owner context, escaped-error
reserve and original-identity raw-export fixes. Logs:
`C:/aiw/tree-harness-*.log`. Formatting/governance passed. This is build/test
evidence; the new host profile has not yet run in a native Sandbox.
Raw FILETIME identifiers require lossless/Rust auditing; do not round them through
JavaScript numbers. Registry-link/create-only native semantics remain open before
production wiring, and explicit cleanup cannot trigger a hidden Drop retry.

## Required next work

Validate the new bounded raw final/pending MXC diagnostics without treating them
as completion, and investigate a separately pinned minimal contained driver if
needed. Package and validate the independent ordinary/classic tree-control host
harness in a fresh Sandbox, including native fast-child/grandchild and deliberate
chain-reset-negative proof, then wire application tracing to typed receipts/results.
The harness uses a fresh source-bound root/session, one exact default-off renderer
route and 8.3 terminal publication with bounded embedded observations. Long JSON
output names remain unadopted diagnostics; strict custody is unchanged.
MXC startup must not become a
gate on that work. Future trials still require fresh source-pinned proposals
under the existing Sandbox-only runtime authorization.
Keep the outer watchdog/job unchanged and preserve exact failures without
fallback. Never repair/adopt or replay the failed capability run. Continue with
shared application process-tree
instrumentation, registry controls, fresh-environment repeats, retained archive
investigation, new-source interruption/invalid/missing-output/recovery, desktop
multi-mode Results and sanitized retained export. No weaker fallback or automatic
permission widening. See the acceptance map for completion requirements.

## Reuse and preserve

#106 native source `593281a` demonstrated the fixed baseline/AppContainer pair,
Results reopen/export with all32 files unchanged, and separate owned cancellation.
Its exact source/environment, earlier incomplete attempt and limits remain in
[the native record](SEVENZIP-NATIVE-ACCEPTANCE.md). They are not acceptance of the
new source. #105 six-control/29-file evidence is reused without repeating it.
Private audits remain at `C:/aiw/sevenzip-assessment-20261105` and
`C:/aiw/paired-directory-sharing-native-65b084f3-5d85-4dda-83a1-12754bbda14f`.
Preserve VM106, VM107 original packages/runs, accidental `C:\Evidence` and unrelated
work. Management TLS is expired; do not bypass it or change access settings.

Broad Benchmark2, W4/W5 and production acceptance remain open. The native worker
and package approvals must remain separate from read-only acquisition/research,
source checks and build-only artifacts.
