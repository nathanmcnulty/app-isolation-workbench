# Working state

Updated 2026-10-07. Verify this checkout with `scripts/work-status.ps1`.
This handoff is a pointer, not execution authority or a run receipt.

## Completed milestone

PR #93 integrated Bambu Studio reusable Sandbox packaging at `4e39c787e63a43cbeb07976117288d059be9818e`.
Independent final review approved `0815cbb`; all three required PR checks passed
(`37693018289`). Main has the identical tree and passed CI `37694385449`.
Signed release run `37695560530` published `desktop-alpha-4e39c787e63a`.
Fresh host and dedicated-VM downloads verified asset identities, attestations on
host, publisher signatures, closed inventory and receipt. Native GUI analysis,
assembly, fresh approval and replay passed for Bambu and both Notepad++ recipes.
Independent canonical checks verified every exact package/import/run association;
both MSI associations also passed separate signed CLI reporting.
Interactive edit/save/export and overwrite refusal passed with independently
verified bytes. All three trials recorded cleanup; the provider list is empty.
Broader isolation remains `insufficientEvidence`. Detailed identities, corrections
and limits: [signed acceptance](BAMBU-PUBLIC-ACCEPTANCE.md).

Acceptance documentation and tested-download update merged in PR #94 at `922d0a7`.
Independent review approved `08a44c5`; all three required checks passed in CI
`37704549006`, and merged main passed `37705606165`. The release binaries remain
built from exact `4e39c78`, not the acceptance documentation head.

## Next bounded work

The [October 7 containment review](MXC-TRAJECTORY-REVIEW-2026-10-07.md) prioritizes
one real-application baseline/candidate isolation comparison after this MSIX
lifecycle slice: classic AppContainer first, then MXC against the same workflow.
Review exact MXC v1.0.0 source/SDK and disposable controls independently; no
runtime pin or containment claim changed in this review.

Active branch: `codex/msix-worker-lifecycle`. The [first MSIX lifecycle contract](NOTEPAD-MSIX-LIFECYCLE.md)
targets a real signed Notepad++ package: fresh-worker install, package-identity/token
observation, document edit/save, per-user configuration and exact uninstall.
PR #95's closed research assembler/signing workflow merged at `9c25780` after
independent review and all three exact-head required checks passed (`37709435055`).
Signing run `37710593027` stopped before assembly/signing on hosted SDK drift.
PR #96 merged the identical approved tool supply from a byte-pinned Microsoft
NuGet archive at `bcf6f82`; required PR/main CI passed. Signing run `37711841372`
succeeded. Independent signed payload verification and VM installation passed.
Actual activation had correct package/image identity but a high elevated token:
the VM operator is the renamed built-in Administrator. The driver stopped before
editing; failure evidence is retained. Exact editor closure and operator-context
uninstall are independently verified, including absent registration/process/config.
The next trial needs a proven fresh standard-user context and new evidence;
edit/save, final payload verification and normal lifecycle remain open.
The feature-gated closed control reuses the production standard-user launcher.
Live control-only attempts diagnosed a Restricted-policy file bootstrap and an
oversized `CreateProcessWithLogonW` command. The direct executable launch holds
its input against replacement; the shorter fixed control and shared UTF-16 length
guard are validated locally. Live control success is still open. Provider inventory
must be queried in the owned operator's context; SYSTEM absence is not global proof.
Local/hosted manifest line-ending drift also prompted canonical LF generation;
LF/CRLF source assembly checks cover that correction. See the lifecycle document
for exact package identities and evidence; unsigned package byte identity is not claimed.
Generic conversion, broader isolation and Studio authoring remain open.
PR #92's shared held-file observations already inform assessment and packaging;
see [shared observations](ADMIN-PACKAGING.md#shared-assessment-observations).

## Environment and evidence

Dedicated VM: `aiw-clean-host-0921`, resource group `RG-AIW-CLEAN-HOST-20260921`,
subscription `43babb60-9e73-4dc8-b769-4401c01aad73`; aiwoperator RDP session 2.
The VM is running. Sandbox workers close after trial completion; that does not
shut down the VM. The actual host operator token is administrator; guest standard
user execution is separately verified. RDP computer use/file transfer and terminal
use are authorized. Drive redirection is unavailable; do not grant Azure roles
merely for development transfer. Use cached authentication; never device code.

Current host proof pointer: `%TEMP%\aiw-bambu-public-proof-root.txt`.
Development proof pointer: `%TEMP%\aiw-bambu-package-proof-root.txt`.
Earlier signed milestones: [Notepad packaging](PUBLIC-PACKAGING-ACCEPTANCE.md)
and [public alpha](PUBLIC-ALPHA-ACCEPTANCE.md). Historical human editing and failures
remain in [interactive evidence](INTERACTIVE-SANDBOX.md) and retained directories.
Automatic policy review previously rejected cleanup of two host handoffs; do not
bypass or retry those deletions. Preserve evidence after diagnosed failures.

One build owner per target. Core cache: `%LOCALAPPDATA%\Temp\aiw-os-validation-20260919`;
desktop cache: `%LOCALAPPDATA%\Temp\aiw-desktop-validation-20261002`.
Use explicit Windows target and target-scoped static CRT for packages.

## Boundaries

No host installer execution, generic execution interface, implicit approval,
automatic export/overwrite or unrelated Sandbox recovery. Commit/push milestones;
merge only after required exact-head CI and review, then verify merged main tree.
