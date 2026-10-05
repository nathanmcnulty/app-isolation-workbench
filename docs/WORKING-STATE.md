# Working state

Updated 2026-10-04. Verify this checkout with `scripts/work-status.ps1`.
This handoff is a pointer, not execution authority or a run receipt.

## Current slice

The repository is public under Nathan's authorization. Public signed alpha
`desktop-alpha-6c7873c4e80c` is published as a prerelease from exact source
`6c7873c4e80c889394ec43b27138cc52fc7df1c2`; all four jobs in release run
`37254512259` succeeded. This validation branch's later documentation commits
are not its build source. See [public acceptance](PUBLIC-ALPHA-ACCEPTANCE.md).

PR #86 integrated the reviewed publication workflow; PR #87 fixed draft API
lookup. All three exact-head CI checks passed for each; merged main trees match
tested PR trees. The final public-exposure scan covered 463 commits with no
findings. Main-only environments, profile-only signer authority and immutable
OIDC subject were read back; public visibility did not change the subject.
See [CI review](RELEASE-CI-REVIEW-2026-10-04.md) and RELEASE-SIGNING.md.

Independent public downloads verified all five asset attestations against exact
source, workflow, invocation and public visibility. Timestamped Nathan McNulty
signatures, closed inventory, receipt and extraction passed on host and dedicated
VM. No candidate executable ran on the host. VM public package is
`C:\AIW-Desktop-Alpha-6c7873c`; distribution and operator GUI launch proof are
under `C:\AIW-Public-Distribution-Proof-6c7873c` and
`C:\AIW-Public-GUI-Proof-6c7873c`. Host evidence pointer:
`%TEMP%\aiw-public-alpha-proof-root.txt`.

Public interactive GUI run `admin-1791167847046734900` completed actual guest
edit/save/close, verified 183-byte retained output, cleanup and explicit export.
Wrong plan confirmation and repeat export to an existing file were refused.
Original input is unchanged; retained/exported bytes match the observed `aiw`
append exactly. Broader isolation remains insufficient evidence. This is an
automated RDP control, not a new human trial. Full typed records are retained.
A SYSTEM-context provider query failed to locate WindowsSandboxServer.exe; its
failure is preserved and is not an empty-session observation. The final operator-
context read-only check succeeded with zero sessions at `2026-10-05T03:34:42Z`;
VM `07-post-trial-provider.json` and host `post-trial-provider-proof.json` retain it.

Public fixed assessment GUI run `admin-1791169556266470800` completed all five
functions and guest ACL controls after full recipe review, exact approval and
separate Start. Typed records confirm cleanup and unchanged installer. Evidence parent:
`C:\Users\aiwoperator\AppData\Local\AppIsolationWorkbench\Evidence`.
Host `assessment-review.json` and `assessment-terminal-proof.json` bind its plan
and terminal report. Bambu public run `admin-1791170118731201300` also completed
all five checks after full review, exact approval and separate Start. The 9,063-byte
3MF, four-vertex/four-triangle geometry, unchanged installer and recorded cleanup
were independently checked against terminal records. All three public-byte modes
passed; broader isolation remains insufficient evidence. The package remains
an alpha; stable promotion is a separate decision.

## Preserved milestones

- PR #85 established full isolated signed desktop CI. Private signed control
  `37250759217` passed; signing authority never executes built payloads.
- PR #82 integrated Bambu GUI after exact-head CI and matched-tree merge.
  Historical unsigned acceptance: BAMBU-ADMIN-ENTRY.md and DESKTOP-DISTRIBUTION.md.
- PR #80/#81 integrated/documented the two Notepad++ GUI modes; historical
  acceptance and negative controls: GUI-FIRST-FINISH-LINE.md.
- PR #78/#79 corrected PowerShell success handling and packaged explicit export.
  Nathan's retained interactive run `admin-1790887375232888400` is preserved;
  INTERACTIVE-SANDBOX.md records the separate human proof.
- Old unsigned `desktop-preview-e08115b` draft remains unpublished. Automatic
  policy review rejected approved cleanup of two host handoffs. Do not bypass
  or retry that deletion; retained evidence and handoffs remain preserved.

## Environment and next step

Dedicated VM: `aiw-clean-host-0921`, resource group `RG-AIW-CLEAN-HOST-20260921`,
subscription `43babb60-9e73-4dc8-b769-4401c01aad73`; aiwoperator session 2.
RDP computer use is working and authorized. Verified input identities are in
`%TEMP%\aiw-public-acceptance-input-records.json`. File-based Azure Run Command
(`--scripts @<saved-file>`) with marker/error/typed-record checks is proven;
inline transport success with empty output is not execution proof.

Public downloaded-artifact acceptance is complete. No trial is active and no
application rerun is needed for these docs.
Follow ROADMAP and EXECUTION-PLAN for the next slice: simplify approval presentation
with complete advanced details, then select a concrete administrator workflow.
Keep generic application conversion, Studio authoring and broader isolation
measurements separate from the narrow alpha acceptance.

One build owner per target. Core cache: `%LOCALAPPDATA%\Temp\aiw-os-validation-20260919`;
desktop cache: `%LOCALAPPDATA%\Temp\aiw-desktop-validation-20261002`.
Use explicit Windows target and target-scoped static CRT for packages.

## Boundaries

No host installer execution, generic execution interface, implicit approval,
automatic export/overwrite or unrelated Sandbox recovery. Never device-code auth.
Use a fresh evidence directory after diagnosed failures. Commit/push milestones;
merge only after required exact-head CI and review, then verify merged main tree.
