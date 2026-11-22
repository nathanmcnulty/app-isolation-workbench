# Working state

Updated 2026-11-21 (America/Anchorage). Effective goal #108 is one application-neutral
assessment and packaging path demonstrated with two behaviorally different external
administrator-supplied fixtures through unchanged production code. Preserve #111
evidence; its legacy application-specific work is paused. Neither external fixture
has executed.

Checkout `C:\aiw\app-isolation-workbench-108`, branch
`codex/application-neutral-assessment`, draft PR #112. Start with
`scripts/work-status.ps1`, [assessment](APPLICATION-ASSESSMENT.md) and
[channel design](ASSESSMENT-EVIDENCE-CHANNEL.md).

## Current slice

The portable offline x64 CLI path covers protected intake, compilation,
preparation, separate approval/Start, signed retained reporting/comparison and
replay packages. Names, payloads and operations are run inputs. Installers/GUI
workflows, complete descendants/registry/network/DLL/memory coverage, W4/W5 and
production acceptance remain open.

Committed candidate cf8568a passed 770 affected tests (21 ignored), Clippy, format,
governance and independent consequential reviews. CI 43968485273 passed all three
jobs; the tested merge has the same tree, and workspace verification exited 0 in
403.85 seconds. Its immutable selected tools and original receipts are private in
`C:\aiw\generic-assessment-108`; raw evidence must stay out of Git.

R13 used those exact tools for separate limited-user Prepare, approval, Start and
retained Read on VM107. Independent admission verified 46 final originals
(156,959 bytes), 23 signatures, trusted Start/session/key/request bindings, all
15 file and 14 process/thread denial observations, exact outer Sandbox stop,
two empty final lists and account cleanup. SYSTEM/token/process session0 and the
fresh standard token/session0 were observed. Protection v4 refused before app
creation because inherited descriptors contain Owner Rights and 34 service SIDs.
Retained Read is authenticated NotRun / insufficientEvidence. There is no
CreateProcessAsUser/PSS/application/job/workflow compatibility credit.

The working diff adds protection v5 with measured held primary TOKEN_OWNER,
explicit SY/BA owner resolution and collector-only service SID provenance.
Historical v4 policy is unchanged. No ACL, rights, session or service changes.
Independent source review and focused addenda passed. All 646 affected library
tests passed (19 ignored), combining the suite with the corrected owner-test rerun;
two integration tests also passed. All-target Clippy and format passed. Fresh v5
exact-source tools and native qualification are still required.
The user-approved fixed SYSTEM collector role remains restricted to fresh Windows
Sandboxes on existing VM107; applications remain ordinary user/AppContainer.

Preserve consumed R6-R13 evidence, including R12's 42 originals/25 signatures and
pre-child WithToken error87. Actor-only R4 admitted 13 originals/16,765 bytes and
basic Tools/Output visibility. These do not qualify application creation.
Detailed admission receipts and the current checkpoint remain in the private goal
directory; do not replay a consumed Start.

## Next gates

Finish the v5 affected tests/checks and review fixes, commit and build exact-source
tools using the existing cache. Qualify ordinary/classic first-party positives,
negative controls, interruption/exact recovery and provider-zero retained Read.
Reopen R12 with the new reader. Then run both external recipes using unchanged
production code and produce comparisons/packages. A broken baseline is not
candidate incompatibility.

## Storage and execution

Use only `C:\aiw\environment-probe-20261114\target-static-r1`, >=10 GiB starting
free and <=8 GiB cache prebuild. Run `scripts/build-storage.ps1` preflight, select
CARGO_TARGET_DIR explicitly, use --target x86_64-pc-windows-msvc and only the
canonical target-specific `-C target-feature=+crt-static` flags. Routine dev/test
profiles disable incremental/full compiler symbols; reject unsafe overrides.

cf8568a's consecutive normal dev builds both measured 4,331,519,319 bytes /4,015
paths with identical images and zero second-pass compiler calls. Release ended
at 4,618,166,098 bytes /4,071 paths in the same cache; all20 actual compiler calls
and three selected images passed independent admission. File-length totals can
count hard-link aliases twice; free-volume samples are separate. PDBs are measured
separately. Retain selected immutable images and receipts, not build/PDB trees.

Policy-blocked legacy incremental cleanup and three blocked empty fixtures remain
untouched; never retry/bypass. Clean owned temporary fixtures in finally after
releasing leases. No new build cache has been created for the v5 change.

Use pinned SSH/SCP for data and reviewed one-shot InteractiveToken/LUA session1
tasks for controller execution. Verify exact VM/operator and before/after Medium,
non-elevated actor. No admin SSH assessment, unknown process termination, consumed
Start replay or unrelated cleanup.
