# Working GUI: first finish line

User-authorized on 2026-10-02: finish and validate the desktop workflow without
requiring the user to drive terminals, approve test runs, or edit test documents.
The dedicated Azure VM and its existing RDP session are the disposable acceptance
environment. Agent-driven actions are recorded as automated acceptance, never as
another human operator's proof. Public publisher identity/signing is a separate
distribution decision; it does not block a clearly unsigned development GUI.

## Product outcome

An administrator launches a packaged Windows GUI, selects the exact supported
Notepad++ installer and optional bounded text input, checks readiness, reviews
the complete recipe and plan, explicitly approves that plan, and separately
starts the Sandbox workflow. The app remains responsive during installation and
editing. It presents verified function/transfer and cleanup results separately
from unmeasured broader isolation, offers advanced details, and explicitly
exports a verified document to a new file. No compiler, internal JSON editing,
CLI flags, or assistant is needed to complete that loop.

The supported assessment and interactive document workflows both use the same
existing Rust services as the CLI. This is the first GUI finish line, not a
generic installer converter or a new isolation-provider implementation.

The next bounded desktop slice adds the existing fixed Bambu Studio export
assessment as an explicit EXE mode. It preserves the same approval and Start
controller, uses package-bound retained report verification, and cannot export
a document. Package contract `v0alpha2` binds all three products; historical
`v0alpha1` remains the exact two-product contract. This source implementation
still requires fresh package and disposable-worker GUI evidence.

## Architecture and delivery

1. Extract the existing administrator workflow into a shared Rust crate. Keep
   protected intake, fixed package assets, held identities, imported planning,
   authoritative approval, execution, retained reports, and export unchanged.
   CLI terminal confirmation and progress become adapters. Input authority is
   an explicit approval/start gate; progress observers have no authority.
2. Add Tauri 2 with embedded local HTML/CSS/JS, native narrowly typed file
   selection, and Rust-owned one-active-workflow state. No shell, generic file
   access, HTTP, updater, remote navigation, or remote content is exposed.
   Display untrusted strings as inert text. Use a restrictive CSP.
3. Keep one-shot review and start challenges in backend memory. Match the
   workflow, challenge, operator, and literal `approve <plan hash>`, consume
   each response once, and use the existing locked approval validation. Approval
   alone must not acquire Sandbox. Separate Start requires an explicit action.
   GUI closure cancels pending gates; running-workflow closure must preserve
   execution/cleanup and durable evidence rather than abandon a worker.
4. Build an exact identified Windows GUI package with fixed product/guest
   assets and inventory verification. Provide a direct launch entry and retain
   clean-source/build identities. Preserve the existing CLI distribution.
5. Deploy to the dedicated VM and validate through Computer Use. Use project-
   owned process controls before any experimental driver; keep durable stage,
   result, diagnostic, screenshot, and cleanup records. Do not weaken approval
   for tests or inject a generic execution interface.
6. Review consequential service and IPC boundaries independently, fix findings,
   run proportional local tests and required integration CI, PR and merge stable
   milestones, and verify the integrated tree. Finish only after the actual
   GUI acceptance matrix below passes, with limitations explicitly recorded.

## Acceptance evidence

- Fresh GUI assessment: select supported MSI, prepare, review, approve, verify
  approval did not start Sandbox, explicitly start, and obtain truthful function
  results, retained advanced evidence, verified cleanup, and an empty provider.
- Fresh GUI transfer: select MSI and bounded UTF-8 text, approve and explicitly
  start, visibly edit/save/close Notepad++ through RDP, then export through the
  GUI. Independently reverify receipt, output size/hash/content, unchanged input,
  overwrite refusal, and exact cleanup. No terminal approval or export step.
- Negative controls: unsupported installer/type, missing prerequisites or
  occupied provider, invalid/oversized/drifted text, product/guest/project drift,
  cancelled/malformed/stale/duplicate approval, changed plan after display,
  duplicate Start/concurrent mutation, close before approval/Start, failed or
  timed-out execution, rejected/unmeasured evidence, and export before cleanup
  or to an existing/workspace/reparse destination. Use service tests and retained
  fixtures where they establish the claim; use live GUI controls for actual
  interaction and disposable-worker evidence for execution boundaries.
- Render/control checks: untrusted control and direction characters cannot
  disguise approval fields or verdicts; failures name the retained evidence and
  safe next action. Busy UI remains responsive and never invents progress.
- Restart/read-only report viewing never restarts, repairs, recovers, or approves
  a run implicitly. Cached recent-run paths are pointers, not authority.

Detailed proof belongs here or in focused fixtures. WORKING-STATE stays a short
resume pointer. Missing live/rendered evidence means the goal remains active.

## Development startup proof (2026-10-02)

Unsigned package `f00b2b2c61540c6dacecdca52139a761bd65464c` built from
clean source and verified its 11-file payload inventory on PowerShell 7.
Desktop SHA-256: `538d47668559586231e75b978dfe50dff6b773e686dce9309083d0338af1ca11`.
Archive SHA-256: `132d6c40b997ad33be1c32024eaaeb37efd52c7d5a8e12c3fba38d252a9542b0`.
The dedicated VM retained the package at `C:\AIW-Desktop-Preview-f00b2b2`.
PowerShell 5.1 rejected its culture-sorted receipt; this prompted explicit
ordinal ordering and a same-package cross-shell verifier fixture. That old
package is preserved, not rewritten as evidence for the corrected contract.

A startup-only diagnostic independently checked every deployed file against
host-supplied identities, then launched as `aiwoperator`. Through RDP Computer
Use, the desktop visibly rendered Ready, maximized, and refused preparation
without installer/operator inputs. The missing-input error appeared below the
fold; UI fixes bring new errors and workflow steps into view and correct radio
button sizing. Launch-control records are under `C:\AIW-GUI-Proof-f00b2b2`.
No Sandbox assessment, approval, document edit, or export was performed by this
startup probe. Fresh assessment and interactive acceptance remain pending on
the corrected package.

The corrected clean-source package is `7667acda1fd319032090d9d6eb87ce857bbfcf91`.
It verified on the VM under Windows PowerShell 5.1 and opened visibly in the
operator session. Independent identities:

- Canonical receipt: `eb4da4f6ef13cd2122a77db84441aa1de489da56b5324be744de0b78dbd7e300`.
- Desktop: `bf5f5c73b164d6401b6a5657264a47f582bd3f833945ee86474af6a09b1495d3`.
- Archive: `815f31caab0abac13ece1a8e833e8b0c313b9bbfe49416d74139796112e82347`.
- Verifier: `9899d3b75d9ba3458cd8bafb69bbae8fbec98ae62ea56a0b63db1f448594a540`.

At this historical startup checkpoint, the GUI opened from
`C:\AIW-Desktop-Preview-7667acd\aiw-desktop.exe`. Its launch controls passed,
provider session count was zero, and the evidence folder had no run directories.
All CI jobs passed at that code head in run `37103146981`. An unrelated passkey
prompt temporarily blocked input; its owner subsequently dismissed it.

If the GUI has closed, the exact VM launch command is:

```powershell
& 'C:\AIW-Desktop-Preview-7667acd\aiw-desktop.exe'
```

Choose `C:\AIW-Interactive-Input-738ea6e\npp.8.9.8.Installer.x64.msi` and, for the
interactive workflow, `C:\AIW-Interactive-Input-738ea6e\document.txt`. Reverify
installer SHA-256 `c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80`
and input SHA-256 `3e266d6a75e56727e3ab1703230fc0a6566e6410c57aa13f871fcc0bfb4aaa4c`
before starting. Use operator identity
`aiw-automated-acceptance`, the existing GUI evidence default (fresh run children),
and new export destination `C:\AIW-GUI-Edited-7667acd.txt`. Derive the approval
literal and run ID from the displayed review/retained typed records.

Launch diagnostics are at `C:\AIW-GUI-Proof-7667acd`, with deployment status at
`C:\AIW-GUI-Deployment-7667acd.json`. A text-only diagnostic backup preserves both
startup probes as `C:\AIW-GUI-Startup-Proof-7667acd.zip`, 17,375 bytes, SHA-256
`f0f8ef1b9c68c8f7900a61dfbd347db0b02e96c96986c95f855456f9e3baa577`.
It is also retained in the private handoff container as
`evidence/gui-startup-7667acd.zip`; it is not a portable execution authority or
application-compatibility proof. PR #80 remains draft until live acceptance.

## GUI acceptance in progress (2026-10-03)

The unrelated passkey prompt was dismissed by its owner. RDP input resumed and
the packaged GUI `7667acd` completed assessment run
`admin-1791016406004205400` through actual selection, review, approval, and Start.
The malformed confirmation `approve wrong-plan` was rejected. An independent
operator-session provider query after approval and before Start reported zero
sessions; approval alone did not launch a worker. Closing the GUI during execution
was refused and execution continued. The GUI displayed all five fixed function
checks and cleanup as verified, while broader isolation remained insufficient
evidence. A separate operator-session provider query after completion also
reported zero sessions. Control records are retained under
`C:\AIW-GUI-PreStart-admin-1791016406004205400` and
`C:\AIW-GUI-PostAssessment-admin-1791016406004205400`.

Interactive run `admin-1791017360314238000` opened Notepad++ with the approved
180-byte document visibly inside Sandbox. Automated text input over the nested
RDP connection did not appear in the editor; it was not saved or closed before
the 300-second deadline. The retained failed status records terminal failure and
verified exact-session cleanup. No verified transfer or export is claimed. The
original failure evidence is preserved under the operator's default evidence
root; this driver failure must be addressed before a new interactive trial.

These live observations also exposed provider console flashes, an offscreen
close-refusal warning, and an elapsed counter carried into a new workflow. A
focused correction hides provider consoles without changing captured handles or
job containment, scrolls to a newly raised close warning once, and resets the
timer on workflow identity changes. Fresh package acceptance remains required.

The retry `admin-1791018718356210200` used physical keys to append `aiw`, saved
the visibly edited document, and closed Notepad++. The GUI verified the 183-byte
retained output and cleanup, preserving the 180-byte input identity and the
insufficient broader-isolation verdict. Automated Unicode text injection was
the failed input path; physical keys and explicit RDP clipboard paste work.
The result exposed a separate GUI defect: destination selection stayed disabled
after the earlier busy action, blocking explicit export. Its fix restores the
chooser only when the backend supplies an export-eligible result and the GUI is
not busy. A regression test exercises preparation followed by an eligible result
and revocation of eligibility. This retry is transfer proof, not export proof.

Fresh package assembly for `9e88181` failed with Rust E0463 while loading
`tauri_macros`. The full log is retained as `aiw-desktop-package-9e88181.log`
under host TEMP. This is an unresolved build failure, not application evidence.
The builder supports opt-in `-KeepFailedBuild` for diagnostic retention of failed
temporary staging trees; default cleanup and all package identity gates remain.
Successful builds clean staging even with that switch. Retained failed staging
is never a verified package and requires deliberate cleanup after investigation.

## Completed packaged GUI acceptance (2026-10-03)

Clean-source package `343d380a3fef4e8734ea25c693ac99d4ac6f2a6a` built successfully
with two build jobs and verified its exact 11-file inventory on Windows PowerShell
5.1 in the dedicated VM. No compiler/configuration defect was established for
the earlier `tauri_macros` build failure; its underlying transient cause remains
unproven. Current independent identities:

- Canonical package receipt: `1c9e8fb63e2d2d795d7b0c36adacd9929aaa6cfda5071ab98d029a8995ba4a67`.
- Desktop: `bdd93ae0d57ec08837cd6670ddac49a6a137b86871892f4c9394866b98d1e642`.
- CLI: `7df17ceb7b384c3849b654eb1bdcae1553867a77b25f65d48d99826d538a472f`.
- Guest: `85cfe36b3f3926553601227eadd748e4c2404e30ee89ca8c8e999469dd150a04`.
- Archive: `7cf8ffeb8c2623d5761ae6d0d54af4857f7425f3e29ecf3667ae947219b31cfb`.

Launch `C:\AIW-Desktop-Preview-343d380\aiw-desktop.exe` on the VM. The supported
MSI/input and their independent hashes are the unchanged paths recorded above.
Review each fresh displayed plan and separately Start; historical plan hashes
and run IDs are evidence, not approval for another run.

| Acceptance | Observed result |
|---|---|
| Fresh assessment | `admin-1791022076187823100`: all five supported function checks passed, exact cleanup verified, broader isolation retained as `insufficientEvidence`. Completion receipt: `540a9a70e22b1d247f4497906f9720c46d8f1de1b40d70ab65abfabad0b06b84`. |
| Fresh interactive transfer and GUI export | `admin-1791022515798013900`: visibly appended `gui`, saved, and closed Notepad++; GUI verified the 183-byte output and cleanup, then explicitly exported to new `C:\AIW-GUI-Fresh-343d380.txt`. |
| Independent transfer binding | Export exactly equals original 180-byte input plus UTF-8 `gui`; original SHA-256 remains `3e266d6a75e56727e3ab1703230fc0a6566e6410c57aa13f871fcc0bfb4aaa4c`. Output/export SHA-256 is `dbb9ed84d47483b5c75246bc666315a0b643b9d4df396d442ef68f25ff16f63c`. Independently canonicalized receipt `9f7ec2866623bafd0fb6b6c7a3aac1cca79b385e4aa701da4c2da3cff44f56c4` matches the report and binds the same output size/hash. |
| Approval and worker lifetime | Independent operator-session queries returned zero sessions after approval and before each Start, and after each completed run. Closing during assessment visibly raised the warning and preserved execution through cleanup. A new workflow reset elapsed time to zero. |
| Retained report after restart | Loaded historical successful transfer `admin-1791018718356210200` read-only, inspected advanced evidence, and explicitly exported its independently matching 183-byte output to `C:\AIW-GUI-Edited-343d380.txt`. Provider remained empty. |
| Export refusals | Missing destination refused; repeated export to the existing file refused with its hash and modification time unchanged; a new file inside the retained workspace refused and remained absent. |
| Cancel and close before Start | `admin-1791023221399651500` cancelled before approval: GUI showed Not run and disabled export, retained `approval-cancelled.json` has `approvalRecorded=false`. `admin-1791023275400573100` closed after approval without Start: retained `execution-not-started.json` has `approvalRecorded=true`, `providerAcquired=false`; no execution/completion receipt exists for either run. GUI exited, then restarted Ready with an independently empty provider. |

These are agent-driven Computer Use observations as `aiw-automated-acceptance`,
not Nathan's human proof. The live observations complement the controller tests
for malformed/stale/duplicate challenges, concurrent mutation, pending closure,
and cancelled preparation, and existing service/runner tests for input/package
drift, unsupported or occupied hosts, receipt rejection, and unsafe exports.
Historical timeout evidence remains a failed driver attempt with verified cleanup;
it is not promoted into an application incompatibility verdict.

All three hosted CI jobs passed at exact source `343d380` in run `37113254300`.
Consequential shared-service/IPC and focused platform/control changes received
independent review. This closes the unsigned development GUI acceptance slice;
publisher-authenticated distribution, generic conversion, additional application
coverage, and measured broader isolation remain separate release work.

The desktop lockfile audit passes with two allowed warnings: unmaintained
`proc-macro-error` and `glib` 0.18.5 unsoundness
([RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html)).
GitHub raised the corresponding `glib` alert after merge. A locked
`cargo tree --manifest-path gui/Cargo.toml --target x86_64-pc-windows-msvc -i glib`
found no Windows dependency on that crate. This is a Windows-only preview;
the warning remains visible and Linux support would require separate dependency
remediation and validation. An audit exit of zero is not a claim of no warnings.

VM records are preserved in `C:\AIW-GUI-Acceptance-343d380.zip`: 164 files,
63,004,779 bytes, SHA-256
`373641a90056146a9c0949083d5c7c9b478b0a3a792c9227e70d4baf015a363a`.
The archive contains the four fresh run roots, operator controls, deployment and
independent verification records, and both exported files. Host screenshots and
canonical binding observations are under `%TEMP%\aiw-gui-acceptance-343d380`.
Both are backed up in the private handoff container as
`evidence/gui-acceptance-343d380.zip` and
`evidence/gui-acceptance-screens-343d380.zip`. The screenshot/observation archive
is 1,341,577 bytes, SHA-256
`531ee0675d7024cd8c2cdba4ae8615dc8859a9fd90228a80802a42c291d39d4b`.
Diagnostic copies preserve evidence for review; they are not portable execution
authority and must never be substituted for the original retained workspace.
