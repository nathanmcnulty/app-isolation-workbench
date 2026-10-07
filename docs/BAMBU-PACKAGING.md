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
weakening the protection. Signed-candidate acceptance and fresh native desktop
assembly/replay remain open: computer-use initialization fails before application
inventory with `failed to write kernel assets`, including after documented reset.
Keep the existing tested signed download recommendation until those gates pass.
