# Working state

Updated 2026-11-26 (UTC). Effective goal #108 is one application-neutral
assessment and replay path for two different external administrator-supplied
fixtures. #111 evidence is preserved and its legacy application-specific work is
paused. Merged PR #112 used `codex/application-neutral-assessment` in
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

The exact #112 portable head cb77844f200f82dff47860c87b881805041a069a passed the
focused comparison and replay tests, the desktop dependency audit, and all
three jobs in CI run 45087985035. The dependency fix is present in #114 as well.

The prior source passed focused creation regression, Clippy, format, governance and
independent boundary reviews. CI 44977826307 passed all three jobs; Workspace
verification exited 0 in 427.47 seconds with the tested merge tree matching source.
Documentation-only reconciliation does not require rebuilding those images.

## Offline replay review

CLI and desktop review verify the candidate in place and support an optional
baseline. The desktop generates the pinned preparation command for manual use.
Preparation, terminal approval and Start remain separate. The offline checks
cover comparison, exact argument forwarding and retained provenance on inert
fixtures. Native validation on the AIW operator account is blocked by a missing
Windows Sandbox Store registration. See the [live handoff checklist](APPLICATION-ASSESSMENT.md#verify-the-replay-handoff-before-a-live-trial).

## MSI assessment

The portable assessment merged through #112. The installer slice in #114
uses protected intake, an exact prepared plan, separate approval, Start and
retained reporting. Notepad++ and 7-Zip each returned installer exit 0,
verified fresh machine registration and exact Sandbox cleanup, and reproduced
two and three hashed executable candidates respectively in retained reports.
The bounded scan covers registered executable component key paths in Program
Files. See [installer diagnostics](APPLICATION-ASSESSMENT.md#installer-diagnostics)
for the earlier timing and CMake observations.

[PR #130](https://github.com/nathanmcnulty/app-isolation-workbench/pull/130)
adds a separately approved run from the retained install-only selection.
In native VM107 testing, a repository-built control MSI passed the two
fresh offline Sandbox runs: installation and executable discovery, then
reinstallation, exact executable verification, standard-user window
readiness, graceful close and exact Sandbox cleanup.

The same merged binaries passed with the signed x64 PuTTY 0.85 MSI,
without any PuTTY-specific production code. The first fresh Sandbox
discovered six registered executable candidates. A separately approved
fresh run verified the same component and hash for `PuTTY\putty.exe`,
observed its window under a standard-user token, closed it with exit 0,
and verified cleanup. No connection was attempted. This measures window
startup and closure, not operator interaction or MSI package replay.

## Remaining scope

The measured slices are portable CLI assessment, offline MSI install discovery,
and reviewed MSI window smoke checks. A generic operator-controlled GUI
session, MSI packaging and clean-worker replay, in-desktop preparation and
approval, complete descendants/registry/network/DLL/memory/broker coverage,
the broader fixture matrix, and broad acceptance remain open. Root-token
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
