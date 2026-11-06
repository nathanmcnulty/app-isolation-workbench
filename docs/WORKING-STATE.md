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
- Creation-time debugger-chain and owned registry-canary foundations are
  test-compiled only, with no production role wiring or native acceptance.
  Registry deletion uses the exact retained key handle; debugger gaps require
  the dedicated helper to fail-stop even if job accounting later reconciles.

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
Raw FILETIME identifiers require lossless/Rust auditing; do not round them through
JavaScript numbers. Registry-link/create-only native semantics remain open before
production wiring, and explicit cleanup cannot trigger a hidden Drop retry.

## Required next work

The corrected alias-free publisher has fresh native proof. Never repair/adopt or
replay the failed capability run. Preserve native evidence outside Git. Verify actual guest
creation/enforcement, not host build/API presence. Continue independently with
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
