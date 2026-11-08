# 7-Zip application assessment

Historical fixed-application workflow: the [repository scope](REPOSITORY-SCOPE.md)
takes precedence. This document is retained as a record of testing, not current
publishing guidance. Hosted app-specific publication is retired or paused;
remaining local fixed-app builders are part of the unfinished migration.

Selected 2026-11-05 (America/Anchorage). The declared
experiment completed its [native research trial](SEVENZIP-NATIVE-ACCEPTANCE.md).
Production desktop/kernel/Results integration is implemented. The exact
`593281a` package completed the fixed application comparison and native retained
Results reopen/export on VM107. The earlier `614bb0e` attempt remains a retained
`DriverIncomplete` result. This is a demonstrated pinned workflow, not broad
application compatibility or isolation certification.
Start from [working state](WORKING-STATE.md); the [candidate review](MXC-ASSESSMENT-SELECTION.md)
records the current MXC research and why classic AppContainer is selected first.

## Application and acquisition

7-Zip 26.05 x64, released 2026-10-21. Follow the project's
[download page](https://www.7-zip.org/download.html), which links to the official
[`ip7z/7zip` release](https://github.com/ip7z/7zip/releases/tag/26.05).
The selected EXE is the vendor's recommended installer form. No winget display
name or search result is acquisition authority.

| Observation | Selected bytes |
|---|---|
| Asset | `https://github.com/ip7z/7zip/releases/download/26.05/7z2605-x64.exe` |
| Size | 1,663,506 bytes |
| SHA-256 | `fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0` |
| Independent comparison | Local hash matches the digest retrieved separately from GitHub's release API |
| Embedded identity | Product `7-Zip`, file version `26.05` |
| Authenticode | `NotSigned`; no publisher-signature assertion |

Acquisition records and inert installer are retained at
`C:/aiw/sevenzip-assessment-20261105`. Inspecting PE metadata or hashing does not
execute the installer. Installation and all vendor application processes are
limited to a fresh offline Windows Sandbox within VM107. Preserve VM106 and all
existing VM107 packages, retained results and unrelated files.

## Fixed workflow and measurements

First validate the process driver using a project-owned child with known output
and exit status, then a deliberately sleeping child that must hit its deadline
and leave an empty owned job. Driver failure prevents installation. Record each
completed stage durably; inspect those stages after interruption before any new
trial, rather than blindly installing again.

Install once as the elevated Sandbox account into the fixed guest-local app
directory. Hold the installed console executable and DLL while exercising the
workflow as the same verified standard user. Retain the scoped installed-file
inventory, hashes and actual process observations. This is not a complete
machine/registry installation-change collector.

Create the same fixed inputs for each mode: text, binary bytes, an empty file,
and a Unicode filename within a directory containing a space. Run the compiled
create, test and extract commands. Independently compare extracted names, lengths
and SHA-256 hashes with the expected input inventory. Exit zero alone cannot pass
content verification. Retain failures and not-reached functions. A failed baseline
prevents attributing a candidate difference to isolation.

The ordinary baseline is inside the disposable worker. It is not proof of normal
execution on every administrator endpoint. The candidate is classic AppContainer
with zero capability SIDs and explicit code/input reads and candidate-output
writes. No broad capability, host grant, policy widening or ordinary-process
fallback is permitted to obtain success. Measure held suspended target tokens
for all three console invocations and check their user, integrity, AppContainer
SID and capabilities before resuming them.

Declare a project-owned readable canary outside candidate grants: the ordinary
user must read the exact bytes; the candidate must report native access-denied
code 5. Separately probe candidate input-file write access, input-file delete
access and input-directory delete access; each open must return code 5 without
changing bytes or deleting objects. These checks measure the read-only input
grant separately from the mutable candidate output. All four selected denial
checks passed in the research pair and the successful `593281a` production pair;
they remain unmeasured in the older incomplete result. Verify the candidate
profile is deleted and every owned job is empty.
The existing six-case control evidence remains separate: it cannot substitute
for missing observations on this application or its children.

## Research versus the supported product

The default-off `research-sevenzip` platform examples established native feasibility
before production integration. The fixed host driver prepares protected
inputs and a proposal, records exact-hash approval, and requires a separate Start.
It persists a preselected-session intent before provider mutation and uses the
existing held Store provider, exclusive lease and exact-session cleanup. It never
installs 7-Zip on the parent VM or development host. Guest records are untrusted
research observations, not production receipts and not importable verified Results.

The implemented product path binds the fixed application request to the existing
production preparation/approval/session kernel, cancellation and owned recovery.
It binds app bytes, workflow revision, environments, user and allowed
candidate-policy differences, with receipt-last publication and the existing
verified assessment/reporting services. The desktop prepares and starts it without
internal JSON authoring. Results reopens explicit retained runs and exports
allowlisted sanitized JSON/Markdown. The first native attempt exercised the
approval/Start and cleanup path, then retained an incomplete driver result;
reopening and JSON export preserved that result. The later `593281a` native run
completed all four application functions in both modes and reopened/exported the
verified comparison. These source-specific records remain separately inspectable.

Independent review and focused negative tests cover input/policy drift, partial
or altered output, missing baseline measurements, failure prefixes, cancellation
and cleanup uncertainty. Native acceptance remains source-specific. Retained reads
must preserve source bytes and make zero execution/provider calls; the first
production run's retained Results check establishes this for its incomplete result.
The successful run additionally preserves all 32 retained files across two native
Results opens and deterministic JSON/Markdown exports.

## Administrator workflow for the tested package

Only the pinned 7-Zip 26.05 x64 installer and compiled archive recipe are supported
by this entry. It does not accept an arbitrary installer, command, input directory
or policy. The package includes the verified vendor bytes; do not install 7-Zip
directly on the controller or parent VM to use this workflow.

The exact tested source is `593281a64dda9b233a25e3f3262d7e1751c01a6b`.
Controller package: `C:\aiw\sevenzip-product-593281a`.
Separately verified VM107 package: `C:\AIW-SevenZip-Product-593281a`.

| Package identity | Recorded value |
|---|---|
| ZIP | 15,593,383 bytes; SHA-256 `06aa338e2138acc2eab579cfa0f2b09dea8f5ea886ec05e5e1d7abd5fa31b834` |
| Receipt SHA-256 | `e2ac4e76611ceeb9253e8b7c7402c8b7311e0648c0125462f0b9b5dcca393dee` |
| Guest agent SHA-256 | `b4601d5d7ade703654c1e6e9f669c05a40bd44384c20273649db06a913797eab` |
| Workflow source SHA-256 | `e8a51b506de74442b22f7e9e7fd2c26ec4cf3d8a25f0feae11d9a4ad213ed2ff` |

For the controller copy, this exact read-only verification checks the receipt,
closed inventory, all file hashes, vendor pin and CLI workflow identity. It does
not install or assess an application:

```powershell
& 'C:\aiw\app-isolation-workbench\scripts\verify-sevenzip-desktop-package.ps1' `
  -PackageRoot 'C:\aiw\sevenzip-product-593281a' `
  -ReceiptSha256 'e2ac4e76611ceeb9253e8b7c7402c8b7311e0648c0125462f0b9b5dcca393dee' `
  -SourceRevision '593281a64dda9b233a25e3f3262d7e1751c01a6b' `
  -CliExe 'C:\aiw\sevenzip-product-593281a\aiw.exe' `
  -GuestAgentSha256 'b4601d5d7ade703654c1e6e9f669c05a40bd44384c20273649db06a913797eab' `
  -WorkflowSourceSha256 'e8a51b506de74442b22f7e9e7fd2c26ec4cf3d8a25f0feae11d9a4ad213ed2ff'
```

On the supported VM107 controller, use the already verified package:

1. Open `C:\AIW-SevenZip-Product-593281a\aiw-desktop.exe` and select **7-Zip archive assessment**.
2. Choose an existing evidence parent with space for a fresh run, enter the operator identity and exact guest Windows version `10.0.26100.9711`, then **Prepare**. The tested host version is `10.0.26300.9711`; preparation records it separately. Do not substitute an OS marketing version or guess an unknown guest build.
3. Review the fixed installer, archive workflow, AppContainer grants, data lifetime, exact environment commitments and plan. Confirm the displayed plan hash through **Approve**. This records approval without starting an assessment.
4. Use the separate **Start** action. Installation, driver controls and archive use are automated inside one fresh offline Sandbox. Read any incomplete/failed result and cleanup status before considering another run; never replay an old approval to retry it.
5. After completion, open **Results → Open selection…** and choose the generated `results-selection.json` in that run's evidence root. No internal JSON authoring is required. Inspect the four baseline/candidate rows, selected controls, separate historical cleanup, evidence status and explicit gaps.
6. Export JSON and Markdown to new names in an existing folder outside every selected retained location. Existing files are refused. Reopen the same selection whenever needed; viewing/exporting does not Start, recover, reinstall or invoke a provider.

The demonstrated success selection is
`C:\AIW-SevenZip-Product-Transfer-593281a\sevenzip-1793956275430444300\results-selection.json`.
Keep that original evidence and every earlier run. This completed run needs no
recovery. During an active run, cancellation requests cleanup of its original
owned session; if cleanup remains unresolved, use the separate owned recovery
action for that exact run. A separate fresh approved `593281a` trial exercised
Cancel after the owned boot window appeared: one exact-session stop, verified
post-stop absence and kernel `cancelled` with no application evidence. Neither
retained completed trial needs recovery. Native forced-fault recovery remains
unexercised; see the [cancellation record](SEVENZIP-NATIVE-ACCEPTANCE.md#native-owned-cancellation-at-593281a).

The [native record](SEVENZIP-NATIVE-ACCEPTANCE.md) identifies the exact tested
bytes. Later documentation or presentation-label changes are not retroactive
acceptance of a different package. The source is under review in
[PR #106](https://github.com/nathanmcnulty/app-isolation-workbench/pull/106);
the three CI jobs passed at `5c12df0dae756a427170e71b79220dd80fe7b491`
([run 42200833485](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/42200833485)).
Those hosted checks do not replace the separate native record.

## Coverage limits and acceptance

The initial workflow automates local console archive operations. GUI archive
manager interaction, Explorer shell extensions, encrypted or adversarial archives,
updates, uninstall, reboot, network, registry dependencies, IPC/UI controls and
every descendant's token remain outside this workflow. An administrator can
identify additional coverage needs; that feedback cannot silently change this
approved fixed trial. It requires a separately reviewed workflow extension.

Benchmark 2 requires the same approved application workflow, measured target and
required-descendant boundaries, selected denial canaries, verified cleanup and an
explainable baseline/candidate matrix. Missing evidence blocks the relevant
claims. Native research alone does not satisfy production approval/reporting or
desktop acceptance. W4/W5 and broad production acceptance remain open.

| Acceptance scope | Advanced by this slice | Still open |
|---|---|---|
| [Benchmark 2](ROADMAP-HISTORY-2026-11-06.md#benchmark-2---one-real-isolation-comparison) | The same approved fixed app/workflow now has a receipt-bound production matrix: all four functions passed in both modes, measured target tokens, selected file denials and verified inner/outer cleanup. Missing/broken-driver observations stay separate, as the earlier incomplete run demonstrates. | Application required-descendant evidence, registry denial for this profile and fresh-instance repeatability. Inner network/IPC/UI and endpoint claims require their own measurements. Archive bytes differ; the cause remains unmeasured. |
| [W4: secure export and diagnostics](https://github.com/nathanmcnulty/app-isolation-workbench/issues/9) | Receipt-bound facts, bounded private failure diagnostics and actual allowlisted JSON/Markdown export. The successful Results reload/export is deterministic and preserves all 32 retained files; incomplete JSON export preserves its earlier 26 files. | Full sanitized assessment bundle and archive/signature-envelope round trip/tamper acceptance; deterministic recommendation and optional cited analyst flow with no verdict authority. Product-package checksums are not assessment-bundle acceptance. |
| [W5: desktop and release hardening](https://github.com/nathanmcnulty/app-isolation-workbench/issues/10) | Actual fixed desktop preparation, exact-plan approval/separate Start, application comparison, retained reopen/export and truthful failed-driver handling. A separately approved native cancellation reaches exact owned cleanup without application findings; recovery services and bindings are implemented. | Native forced-fault recovery and accessibility acceptance, plus signed release, clean-machine acceptance and supported-host coverage for this profile. Earlier signed-alpha evidence retains its earlier recipe scope. |
