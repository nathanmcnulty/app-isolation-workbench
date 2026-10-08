# Bambu Studio reusable Sandbox package

## Delivery contract

The next milestone is a reusable bundle for the existing Bambu Studio 2.8.2.60
x64 fixed STL-to-3MF export workflow. This extends the administrator package loop
to its second application without adding installer arguments, new resource grants,
slicing, printer/cloud access or arbitrary manifest commands.

The closed bundle contains `app.exe`, `project.aiw` and `manifest.aiw`. The exact
EXE hash remains `cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7`;
the 512 MiB bound matches existing Bambu preparation. A manifest binds payload,
project, compiled scenario, runtime, ephemeral data contract and source intake.
The manifest hash must be preserved separately. Existing Notepad++ bundles and
their typed records remain unchanged and cannot be interpreted as Bambu input.
The original two-profile Notepad administrator API and v0alpha1 records remain
closed to Notepad values. The expanded administrator analysis/result records use
separate `SandboxPackage*` types and v0alpha2 identifiers.

Reuse held closed-inventory file transport and protected receipt-last publication.
Keep profile-specific compilation, import and report types separate. Replay must
match the selected installed recipe, create fresh protected intake, review the
fresh complete recipe, collect exact approval and require a separate Start.
Package analysis/assembly must never start Sandbox or execute an installer.

## Milestone acceptance

1. Closed export, verify and import APIs reject changed payload/project/manifest,
   wrong expected hash, rehashed unsupported profile/runtime/data contract,
   extra files, links/streams/reparse shapes, oversized inputs and overwrite.
2. A package report revalidates the supplied bundle/import against the retained
   run's exact receipt and scenario inside the held preparation boundary. Matching
   application bytes alone cannot substitute another intake or a successful run.
   Failed verified runs retain their failures and evidence gaps.
3. Administrator analysis/creation and desktop selection use the installed fixed
   Bambu assets and reuse the operation lock. Installer or recipe drift invalidates
   creation. Failure retains intake/partial output; retries use fresh locations.
4. Dedicated-VM native assembly, relocation and fresh approved package replay
   complete all five export checks with independently hashed output, matched
   package report and exact cleanup. Existing Notepad++ package flows still pass.
5. Independent exact-head review and required CI pass before integration. A new
   signed public candidate is built by CI and separately verified/tested before
   changing the tested download recommendation.

Broader isolation stays insufficient evidence. This is an ephemeral Sandbox
recipe, not an MSIX conversion, persistent installation or verified uninstall.
No milestone item is completed by this design document alone.

## Development proof

Independent review of the implementation and final corrections through `284cd58`
found no remaining actionable issue. It caught two compatibility defects: widening
the old Notepad enum, and returning a legacy result while saving the expanded
schema. The original nominal types/domain and retained v0alpha1 records now remain
unchanged; both-profile regression tests compare returned and saved records.

On Windows, 36 administrator tests, two Bambu bundle tests, the existing MSI
relocation regression, 30 CLI contracts and 11 UI tests passed. Focused core and
desktop warnings-as-errors Clippy, governance, formatting and explicit Windows
static-CRT CLI/desktop release builds passed. Inert fixtures never execute an
installer and are not compatibility proof.

The dedicated VM `aiw-clean-host-0921` completed ten file-contract stages under
the active limited `aiwoperator` session. Actual supported EXE export, relocation,
verification and two fresh imports passed; wrong expected hash, wrong MSI layout
and intake overwrite were rejected. Both new receipts bind the same 429,037,864
application bytes while retaining distinct intake identities. The independently
hashed source and relocated payload match the supported installer SHA-256 above.

The same CLI first reverified successful historical fixed assessment
`admin-1791365433522265300`, including recorded cleanup, against the installed
project. Package reporting with a new same-byte intake then returned
`AIW_SANDBOX_BUNDLE_REJECTED` at the preparation/approval binding boundary.
This proves rejection of cross-intake association; it does not establish a
successful fresh package replay. No installer or Sandbox was started by this proof.

- Source: `284cd585e9c5b18999fb9090315af5d35258d299`.
- CLI SHA-256: `c9988a29adbb9f40fad123babe18b72a602d2f9494ff0c977883582f03f65e67`.
- Installed project SHA-256: `c622de4d1a993c7653ddae823695eae7ac3cce86c4baea1160f2d5f8f1b377f4`.
- Bundle manifest SHA-256: `8aef5b201df0b65d64e799bc5492dfe5517c1cace3c38d42eae5789dfa2a5771`.
- VM evidence: `C:\Users\aiwoperator\AppData\Local\Temp\AIW-Bambu-Package-284cd58-34a6211e`.
- Host evidence pointer: `%TEMP%\aiw-bambu-package-proof-root.txt`; independently
  checked `accepted-file-contract.json`, with separate native stdout/stderr logs
  and exit status for every stage. The driver terminated with exit code zero.

Failed transport-script preparation and the initial SYSTEM-context import remain
preserved. SYSTEM collapses the required distinct owner-and-SYSTEM ACL entries;
the retry used the normal operator context and a fresh evidence directory without
weakening the protection. Required integration CI `37681516883` passed all three
jobs on exact `b8ad8e1`. The updated bundled computer-use runtime restored RDP
automation. The VM independently verified the development archive and all eleven
payload files before launching the desktop as `aiwoperator`; this unsigned stage
does not replace public signed-byte acceptance.

Native installer selection, analysis and Bambu package assembly passed. The
retained v0alpha2 result names `bundle-package-1791408150475946000` under the
operator's Workbench evidence directory. Its manifest SHA-256 is
`6e880f03a22fed3d2fb236941f01cb3205877da20b233277d2987f8fe7c7a11e`,
independently read from the VM file.

Native preparation created fresh run `admin-1791408579808193500`. The complete
retained recipe was reviewed, then literal plan approval and the separate Start
action were exercised through RDP. All five fixed export checks passed. The
retained `report-bundle.json` matches this manifest and the complete fresh intake;
its canonical replay receipt SHA-256 was independently recomputed as
`ac3b90a5134e96e6ed82589272490e19ef29572153a18701412a0c2120159225`.
This canonical bundle-report digest is distinct from the preparation's typed
receipt serialization digest; the underlying receipt identity matches exactly.

The independently hashed `output\aiw-tetrahedron.3mf` is 9,063 bytes, with SHA-256
`4f26886a98af377b280b476957129fe898765019926635be2fcb8727fe055ff6`.
The verified artifact contains four vertices and four triangles. The run records
cleanup complete, its exact session is disposed, and the provider list is empty.
The native result presents all five function checks and the separate broader
isolation limitation. No graphical Bambu editing, slicing or printer workflow
was tested.

Host proof is `native-complete-review.json`, `native-reviewed-identities.json`
and `native-replay-terminal.json` under the evidence pointer above. VM evidence
remains under the operator Workbench Evidence directory for the stated run.
The initial oversized diagnostic response and a collector's incorrect status
filename remain preserved. Bounded readback of the existing `result.json`
corrected collection without repeating installation or execution.
Signed public-download acceptance subsequently passed for Bambu and both
Notepad++ package regressions at exact release source `4e39c78`. See
[signed acceptance](BAMBU-PUBLIC-ACCEPTANCE.md) for distribution identities,
fresh runs, independent package/report checks and claim limits.

The current CLI also reverified both retained Notepad++ package/report
associations as the recorded operator: fixed assessment
`admin-1791363728884366700` and interactive session
`admin-1791364558757379700`. Both commands exited zero, retained the correct
report kinds, successful scenario evidence and verified cleanup. These are
read-only regressions against historical evidence, not new installations or
signed-candidate execution proof. VM results remain in
`C:\Users\aiwoperator\AppData\Local\Temp\AIW-MSI-Regression-b8ad8e1-7d6bf1a8-r2`;
host readback is `msi-regression-terminal-cleanup-r2.json`. The first collector
incorrectly expected an assessment outcome field on the interactive report;
its failure and outputs remain preserved separately. All three owned staging/
regression registrations were removed only after exact action and terminal exit
verification; no evidence directory or unrelated task was removed.
