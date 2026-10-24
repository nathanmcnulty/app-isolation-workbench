# Order-independent embedded worker identity guards

Owning implementation baseline: `e7ac98715f173d74da674519418ee0bda1850fa6`,
PR #103 branch `codex/new-vm-handoff-20261021`. This corrects the P1 in
[Dot's review at 96b5a12](https://github.com/nathanmcnulty/app-isolation-workbench/blob/96b5a12a6e5c4cabd9fabdc16f7738ed1d584fe3/docs/handoffs/2026-10-24-powershell76/INDEPENDENT-GUARD-REVIEW-e7ac987.md).
The review branch was read, not adopted as an implementation baseline.

## Repair

The generated SYSTEM and lifecycle scripts previously compared compressed JSON
text. Production PowerShell observation and Rust struct serialization place
properties in different orders, so equal identities failed before operations.
Both scripts now call the same compiled identity helper before their operations.

The helper checks the complete closed worker and nested engine property sets
with case-sensitive names. It rejects missing/extra fields, nulls, wrong types,
non-string capabilities, scalar/changed capability arrays, alternate executable
identities and malformed engine identities. Capability order and exact string
values remain significant. Object property order is ignored by constructing
both closed operands in the same explicit order. The observed Int32 and JSON
Int64 zero compatibility counts normalize identically; strings, booleans,
floating-point/decimal and nonzero values are rejected before normalization.
Worker and engine fields are retained, including hashes and MVID.

The binding must retain host, worker, explicit endpoint and WSMan object presence.
Full WSMan validation remains in the native agent before script launch. The
helper independently checks direct worker operands; an endpoint identity cannot
substitute for either worker. Normal HTTPS, explicit PowerShell.7.6, same-session
file transfer, held files, compatibility rejection, no replay and approved
input/raw-evidence completeness checks remain unchanged. Rust models, serialized
request bytes/hashes and historical readback are unchanged; absent engine/WSMan
fields cannot authorize new execution.

The existing common/direct observation construction is factored into pure
functions in the shared proof, preserving its property order and inputs. The
actual machine proof calls those functions with its actual process/engine
observations; fixed PSHOME and executable checks are unchanged. This makes the
production construction testable with inert observations without substituting
machine runtime paths or installing a runtime. All three proof blocks remain
identical.

## Exact-consumer regressions

The Rust test writes request bytes directly with
`serde_json::to_vec(&MsixWorkerRequest)` after typed execution validation. It
does not serialize a JSON Value map in place of the production writer. It writes
the actual generated SYSTEM and lifecycle scripts and extracts their actual
guard calls, helper definitions, request reads and production constructors.
The extracted request read retains its generated source filename, preserving
PSScriptRoot. No account, task, package or application operation is evaluated.

For both consumers, matching unmodified request/observation pairs pass. The test
explicitly witnesses that the old raw JSON strings differ, so restoring the old
guard fails the regression. Top-level and nested engine property reorders pass;
capability reorders do not. Ten acceptance checks and 292 rejection checks cover
every worker/engine field on both operands (drift, missing, null, wrong type),
extra/cased fields, array semantics, integer types, alternate direct images,
missing/invalid bindings, old omissions and WSMan-as-worker substitution.
The Rust test independently verifies the original request file bytes afterward.

The first inert harness attempt lost PSScriptRoot when creating a standalone
script block for the lifecycle request read. Retaining the real generated source
filename fixed the harness; the exact production expression was not rewritten.
That failed attempt remains distinct in private logs.

## Independent source review and evidence boundary

A separate read-only review examined the repair, actual generated consumers,
constructor factoring and regression path. It reported no remaining blocking
finding. The reviewer did not execute suites, builds or a VM; regression results
are producer evidence. Local verification uses the existing bundled Core 7.6.5
and Rust/Cargo 1.99.1 on Windows 10.0.26300.9711. Logs and fresh package bytes
remain outside Git under `C:\AIW-Resume-20261021\guard-order-*`.

Completed local aggregate checks: formatting, workspace/all-target Clippy with
warnings denied, governance including shared-proof/runtime policy regressions,
22 probe/model tests (including historical byte/hash and execution refusal), four
generated-worker tests (including the exact consumers), three direct-proof/
subprocess tests, and 16 MSIX raw-evidence recovery/export/readiness tests. All
passed; no ignored tests are counted in these focused selections. This is not
a new local full-workspace test run; fresh hosted verification covers that scope.

Fresh CI must identify its actual tested PR merge separately from the owning
head. The fresh clean-source unsigned static-CRT worker/desktop package must
have all six payloads size/hash verified and its desktop compiled worker pin
matched. Final run, source, worker and receipt identities are recorded in the
checkpoint handoff/PR body after building from the clean commit, avoiding a
self-referential source hash. Prior binary hashes do not attest this guard fix.
Hosted desktop release evidence is a release-configuration `cargo check`, not
a hosted release build; the producer's local package build is separate. Hosted
workspace success does not expose per-case totals hidden in runner-temp logs.

Stages A–D and merge remain blocked. No runtime installation, endpoint/security,
firewall/WinRM change, VM contact, baseline change or native application/Sandbox
trial is included. Historical provider/baseline pins, evidence and completed
nonces remain unchanged; do not replay completed runs. Real endpoint and native
lifecycle/cold-clean acceptance remain unproven. Keep PR #103 unmerged.
