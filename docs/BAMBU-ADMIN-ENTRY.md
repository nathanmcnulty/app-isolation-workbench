# Bambu Studio administrator entry: acceptance boundary

The next supported application candidate is the exact Bambu Studio 02.08.02.60
EXE already covered by the fixed STL-to-3MF export profile. This is a second
application workflow, not general EXE support. The existing [Bambu profile](BAMBU-STUDIO-PROFILE.md)
defines the installer hash, fixed tetrahedron input, bounded 3MF verifier, and
retained production evidence. The [first administrator workflow](ADMINISTRATOR-WORKFLOW.md)
remains the Notepad++ MSI reference until this entry passes its own package and
operator gates.

## Supported operator task

An administrator selects the Bambu export assessment explicitly, supplies the
installer and an existing evidence directory, reviews a complete fixed recipe,
and types the exact bound plan hash in a visible terminal. The package supplies
the project, scenario, guest agent, and their identities. The application is
installed only in a disposable Windows Sandbox worker and the fixed export runs
under the established standard user with networking disabled. The operator
receives a short function summary by default, with retained Markdown, JSON,
artifact identity, and stage diagnostics for deeper review.

The result can say that this exact installer completed or failed the fixed
export workflow. It cannot claim slicing, printing, cloud sign-in, graphical
editing, broad application compatibility, or effective application isolation.
Missing or rejected evidence is unmeasured, not a failed application function.
An artifact is passed only after the retained 3MF graph and tetrahedron geometry
are reverified. Recorded cleanup is historical and does not answer whether a
provider session is active now.

## Acceptance cases

1. **Package identity.** A deterministic package inventory binds the CLI,
   static guest agent, exact project and scenario, and supported installer
   SHA-256. A fresh extraction verifies these bytes independently. Changed,
   missing, extra, or path-escaping product assets fail before intake or worker
   acquisition. No installer is shipped inside the package.
2. **Preflight and rejection.** Unsupported input type or installer bytes,
   missing host prerequisites, and an occupied Sandbox yield specific retained
   diagnostics without protected intake or provider acquisition. No other
   session is stopped. Source drift fails before a worker starts.
3. **Approval.** The complete recipe exposes privileged install, exact export
   command and fixture, standard-user runtime, Sandbox restrictions, data
   lifetime, output collection, and cleanup. The existing exact-plan approval
   service remains authoritative; cancellation records its stage and starts no
   Sandbox. A changed project, guest, recipe, plan, or package fails closed.
4. **Execution and report.** An approved disposable worker runs the existing
   typed Bambu scenario. The retained report distinguishes passed, failed,
   not-reached, and unmeasured stages; separately verifies the 3MF artifact;
   records the runtime and exact cleanup; and preserves `insufficientEvidence`
   for broader isolation. Console output remains short, with explicit advanced
   evidence paths and safe next actions.
5. **Failure and recovery.** A worker, installer, application, output, or
   reporting failure cannot be presented as general incompatibility. Retained
   status identifies whether exact recovery is required. A console write error
   after a retained result cannot suggest repeating the trial; a cancelled
   approval points to its cancellation record rather than a nonexistent report.
   An installer wait failure records the fixed process ID, elapsed wait, job
   process identities, fixed entry-point metadata, and bounded guest-local VC
   setup-log excerpts before contained cleanup;
   those are diagnostics, not evidence that installation completed.
6. **Independent proof.** Static and negative contract tests, package
   verification, and hosted checks precede a fresh separate-host operator run.
   That trial records the package and verifier hashes, approval, complete
   stage/artifact report, negative control, terminal status, and absence of an
   active session. It requires a human to review and enter the displayed plan
   hash. Until then, the entry is development-only.

Implement this as a fixed second product path over the existing protected
intake, approval, runner, report, and cleanup services. Keep product selection
explicit; do not infer a trusted profile from a filename or turn the Bambu
command into a caller-supplied execution interface. A profile-bound adaptation
and reusable launch package are later steps after this assessment works.

## Desktop implementation boundary

The development desktop now exposes Bambu Studio export as an explicit third
mode with an EXE-only chooser. It reuses the fixed administrator service,
package-bound retained reporting, and the existing separate approval and Start
gates. A Bambu result is shown as Verified only when its typed report has
verified evidence and cleanup, a successful fixed scenario, and a verified 3MF
artifact. The desktop never enables document export for this mode.

Desktop package schema `aiw.dev/desktop-package/v0alpha2` closes the inventory
over the two historical Notepad++ products plus `bambu-studio`, whose project is
the fixed `project.json` used by the preview builder. The verifier continues to
recognize `v0alpha1` only as its exact historical two-product contract. The exact desktop
acceptance below records its fresh worker and corrected retained result.

## Completed desktop acceptance (2026-10-03)

Fresh GUI run `admin-1791052004563329100` used packaged source
`170caab558a57fc6d1150128bdd87ed86a81c581` on the dedicated VM. The automated
operator identity was `aiw-development-agent`; this is not another human trial.
Preparation's operator-session control reported zero Sandbox sessions. The GUI
showed privileged installation, standard-user export, data lifetime, fixed
limits, and no automatic host export. Exact-plan approval was recorded while
Start remained a separate action; the agent then explicitly started the worker.

Install, fixture preparation, export, collection, and geometry verification all
passed. The 9,061-byte 3MF contains four vertices and four triangles; its
independent SHA-256 is
`237b7b87e5a509d275e83b5c4f5ea09050a42a6a2b725ac33fab4c9f4aceb33c`.
Native retained reporting bound the same scenario/artifact and completion receipt
`3f3bedac99fdb39813b34412eaab411c6170bd0efa5437cd5e40faca4378fb4e`.
Cleanup verified, the provider was empty afterward, and the original installer
hash remained unchanged. The report retains `insufficientEvidence` for broader
isolation; slicing, printing, cloud, and graphical editing remain untested.

The live trial found a GUI classification defect: it required overall
`Succeeded`, although successful Bambu reports deliberately use
`InsufficientEvidence` for the separate isolation verdict. Corrected source
`e08115b50fb0ee37fba1f923b377985dc3f1bc94` uses the runner's typed workflow
predicate, requiring verified cleanup/evidence, receipt/root identities, a
successful scenario, and matching artifact hash/size. Its typed regression
covers the original mapping and absent/rejected/drifting evidence. Independent
review found no further actionable issue. The rebuilt GUI reopened the completed
run as Verified, preserved the isolation limitation, and disabled document
export. Both fresh and retained GUI paths use this same predicate. This report
correction was tested against retained evidence without repeating installation.

The same new package reopened interactive Notepad++ run
`admin-1791022515798013900` as Verified and explicitly exported to fresh
`C:\AIW-GUI-Nopp-Regress-e08115b.txt`. Independent verification matched the
183-byte retained output, SHA-256
`dbb9ed84d47483b5c75246bc666315a0b643b9d4df396d442ef68f25ff16f63c`,
and confirmed it equals the unchanged original input plus UTF-8 `gui`.
No Notepad++ installation or Sandbox replay was needed for this regression.

### Current package and exact VM paths

The unsigned `v0alpha2` package has an exact 14-file payload inventory and
verified on the VM under Windows PowerShell 5.1. Independent identities:

| Item | SHA-256 |
|---|---|
| Canonical package receipt | `be54677224b29ff608f7a222d27c463d06e205ac224d680b0a96c2619acab492` |
| Desktop | `a1bcf8653d11c82f75c49050464371c3f7eae675ae0bad8b695273d303838bc2` |
| CLI | `4c0dd9dde673ced406daa421dd911dba7459fc1ad5931cea85d21c32c2454c9a` |
| Guest agent | `85cfe36b3f3926553601227eadd748e4c2404e30ee89ca8c8e999469dd150a04` |
| Verifier | `e0ebf395c19aae71db4dd773f255a7260401977abcb1aceab6b5893d50a81687` |
| Package ZIP | `a938eab95e9b986723d0a81163fbd1baef1d0f886be62823a2f3345db69531e0` |

For a new operator session on the VM, these exact PowerShell commands verify
and launch the current development package from its deployed location:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location C:\AIW-Desktop-Preview-e08115b
.\verify-desktop-package.ps1 -PackageRoot . `
  -ReceiptSha256 be54677224b29ff608f7a222d27c463d06e205ac224d680b0a96c2619acab492 `
  -SourceRevision e08115b50fb0ee37fba1f923b377985dc3f1bc94
Start-Process -FilePath C:\AIW-Desktop-Preview-e08115b\aiw-desktop.exe -Verb RunAs
```

Do not check stale `$LASTEXITCODE` after that in-process verifier; its terminating
errors and structured output are authoritative. Choose Bambu Studio export and
`C:\AIW-Bambu-Input-20261003\Bambu_Studio_win-v02.08.02.60.exe`, whose supported
SHA-256 remains `cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7`.
Keep the default evidence parent, identify yourself, Prepare, review the complete
recipe, type the newly displayed exact approval, and separately Start. This
fixed assessment requires no editing tasks; wait for the retained result and
cleanup. Historical hashes/run IDs do not approve a new trial.

For read-only Bambu viewing, select Bambu Studio export, workspace
`C:\Users\aiwoperator\AppData\Local\AppIsolationWorkbench\Evidence\admin-1791052004563329100\admin-1791052004563329100`,
and run ID `admin-1791052004563329100`. Loading does not start or recover Sandbox.

Local service/controller, verifier, JavaScript, format, governance, and the typed
outcome regression passed. Exact-head hosted CI remains the integration gate.
The first read-only wait helper watched the wrong administrator filename, and
an independent hash helper initially used the wrong output subdirectory. Both
failed observations remain separate from the successful native report; corrected
checks used the existing completed run. No diagnostic mistake triggered a new
application installation. Package source guards also preserved an earlier build
refusal when reviewed source changed during assembly.

### Evidence preservation

The original protected workspace remains on the VM. Diagnostic archive
`C:\AIW-GUI-Bambu-Acceptance-e08115b.zip` preserves the fresh run, exact inputs,
operator controls, package receipts, native retained verification, and export
regression: 93 files, 858,008,236 bytes, SHA-256
`019a12b799a5b380ad55cf5ed7eb60ec7da2baf8ebc6d30797ad66a5fd2adf38`.
Every archived entry was checked against its size/hash inventory, normalizing
Windows ZIP separators for comparison. It is backed up in the private handoff
container as `evidence/gui-bambu-acceptance-e08115b.zip`.

Screenshots, package identities, independent result records, review, and local
logs are under `%TEMP%\aiw-gui-bambu-acceptance-170caab`; the folder records both
initial execution and corrected-package acceptance. Its 1,669,561-byte archive
has SHA-256 `11d5c188e64ec578076331ebc202d8be5cae7b5f2f3a10f609290084b26d5767`
and is backed up as `evidence/gui-bambu-screens-e08115b.zip`. These copies are
review evidence, never portable execution authority or substitutes for the
original retained workspace.
