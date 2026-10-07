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
