# Working state

Updated 2026-11-22 (UTC). Effective goal #108 is one application-neutral
assessment and replay path for two different external administrator-supplied
fixtures. #111 evidence is preserved and its legacy application-specific work is
paused. Draft PR #112 uses `codex/application-neutral-assessment` in
`C:\aiw\app-isolation-workbench-108`.

Start with `scripts/work-status.ps1`, [assessment](APPLICATION-ASSESSMENT.md) and
[channel design](ASSESSMENT-EVIDENCE-CHANNEL.md). Private evidence and source pins
remain in `C:\aiw\generic-assessment-108`; never commit payloads or raw evidence.

## Current result

Production source `315391e` and the same pinned CLI/agent/common harness served
both external fixtures without rebuilding or adding product-specific code.
Protected intake, replay export/verification, separate preparation/approval/Start,
authenticated retained reports and comparisons completed in fresh Sandboxes on VM107.

| External run data | Ordinary | Classic AppContainer |
| --- | --- | --- |
| Stateless JSON transformation | 3 steps /2 assertions passed; exact 20-byte output | Same assertions/output passed |
| Seeded persistent database, two launches | 6 steps /5 assertions passed; 8,192-byte database | Same assertions/query output and full-file hash/extent passed |

Independent review verified 29/30 signatures for the JSON runs and 36/37 for the
database runs. Root tokens were Medium standard user or Low AppContainer with
empty capabilities. Jobs, accounts, owned profiles and exact Sandbox cleanup
passed, including two final empty lists for each of the four passing external
runs. Both comparisons
are comparable and retain every coverage gap. Database equality is observed full-file
hash/extent equality; complete database bytes were not retained for direct comparison.

An earlier database baseline failed with its missing-file initial condition.
Preserve that authenticated failed baseline separately. Its unused original Classic
candidate remains approved NotRun/superseded. The new condition supplies an explicit
zero-byte seed, retains the same
payload/SQL/protection flags and uses new plans/approvals; it is not a replay or a
rewritten success. The read-only collector's long-path repair also recollected
existing evidence without rerunning the application or original retained Read.

Repeated retained Read returned matching full-report hashes and lengths for all
four passing runs.
Six exact production sanitized report/comparison JSON files were exported from
admitted retained bytes with no application/provider calls. This is CLI evidence,
not native desktop acceptance. The private checkpoint records precise receipts,
failed attempts and consumed invocations.

Current source passed focused creation regression, Clippy, format, governance and
independent boundary reviews. CI 44977826307 passed all three jobs; Workspace
verification exited 0 in 427.47 seconds with the tested merge tree matching source.
Documentation-only reconciliation does not require rebuilding those images.

## Dependent MSI preview

PR #112 review fix `9de43ed` requires authenticated local Start in both comparison
lanes and preserves the portable payload depth under the replay wrapper.
`codex/generic-msi-install-preflight` depends on that draft. The Windows CLI now
reopens protected MSI intake and previews one bounded offline per-machine install
from a typed scenario. The preview requests flushed guest-local MSI logging.
The diagnostic CLI summarizes captured logs without publishing raw text. Matched
VM107 trials with a known-good small MSI and CMake reached server-side package
policy verification, then the 120-second deadline with neither ProductCode
registered. Controlled installer completion and installed entry-point discovery
remain open. See [installer diagnostics](APPLICATION-ASSESSMENT.md#installer-diagnostics).

## Remaining scope

The supported slice is portable, offline x64 CLI assessment. Desktop intake,
installers/GUI automation, complete descendants/registry/network/DLL/memory/broker
coverage, the broader fixture matrix and broad acceptance remain open. Root-token
and collector-denial measurements do not establish all effective restrictions.
Benchmark 2, W4/W5 and production acceptance are not closed by these results.

## Storage and execution

Reuse only `C:\aiw\environment-probe-20261114\target-static-r1`: >=10 GiB starting
free and <=8 GiB cache prebuild. Normal scripts use `scripts/build-storage.ps1`,
honor the caller's target and reject unsafe profile/config/compiler overrides.
Direct Cargo must copy the normal target/flags: `--target x86_64-pc-windows-msvc`
and target-specific `-C target-feature=+crt-static`. Both workspace dev/test
manifests use debug=0/incremental=false.

Consecutive normal dev builds each ended at 4,627,812,528 bytes /4,096 paths,
identical images and zero second-pass compiler calls. Release ended at
4,627,905,102 bytes; the strict post-trial sample remained identical, with no
compiler running. All 16 actual compiler commands and three selected images
passed independent admission. File-length totals may count hard-link aliases;
free-volume samples/PDB totals are separate. Keep selected images and receipts,
not repeated build trees. No new build cache was created for fixture trials.

Policy-blocked legacy cleanup and three blocked empty fixtures remain untouched.
Automatic approval review also blocked deletion of one unused 53,734-byte QA
projection; retain it and its blocked-cleanup receipt, with no retry/bypass.
Owned native-test TEMP fixtures were removed after releasing handles.

Use pinned SSH/SCP and reviewed one-shot InteractiveToken/LUA session1 controller
tasks. The authorized SYSTEM collector stays only inside fresh VM107 Sandboxes;
applications remain standard user/AppContainer. No admin SSH application run,
unknown process termination, consumed Start replay or unrelated cleanup.
