# Working state

Updated 2026-10-26. Owning checkout `C:\aiw\app-isolation-workbench`, branch
`codex/new-vm-handoff-20261021`, PR103 open and unmerged. Start with
`scripts/work-status.ps1`. This file is a pointer, not execution authority.

## Current milestone

The approved Core7.6.7 runtime, restricted HTTPS endpoint and existing cold
VM107 baseline were revalidated. The separate bounded native acceptance passed
and its final cold clean/release evidence received independent review. Its queued
case remains an injected consumer regression, not a real scheduler observation.

The fresh full application trial failed before the editor appeared. Preserved
original stderr reports a source-observation access denial. Actual protected
input ACLs omitted the fresh standard user's read permission, although the run
root granted it. No application lifecycle success is established. Later runtime
drift to7.6.9 was observed separately; its cause remains unestablished.

Thirty original records and four immutable payload links were independently
verified before Nathan expressly approved exceptional cold recovery despite
missing authoritative application raw evidence. The existing VM107 baseline was
restored, exact7.6.7/production Clean reverified, and the same lease released.
That recovery preserves the full trial as failed; it does not satisfy the missing
raw-evidence gate or create application acceptance. Detailed evidence stays private.

The local repair grants only the exact fresh run SID read access to the separately
protected input directory. It verifies closed directory/file ACLs, ownership,
inheritance, three ordinary payloads and hashes before/after enrollment and before
later execution stages. Ancestor permissions and application write authority are
unchanged. Focused inert coverage includes actual Windows inheritance propagation
and negative ACL/layout/reparse cases without enrollment or application execution.
Independent source review and all five source qualification checks passed at
local commit c7ccb9d. The user subsequently clarified that stable Core7.6+ is
approved, including7.6.9; exact patch equality between controller and worker is
not required. Production keeps each run bound to its observed runtime bytes and
requires coherent worker/WSMan identities. The acceptance harness now uses that
same contract and records each observed version separately. A new coherent
package and fresh native trials remain required before claiming acceptance. Earlier
source/package/CI receipts apply only to their recorded bytes. No public push or
merge is authorized by this repair.

## Coordinated dependency finding

Read the coordination index at `61b0536e4090b58fe610e04dcfe3aa6b83fc5b30` and
AIW task at `431b9ba8e60c22ecca5bed0beb341b346c80420a` in private
`nathanmcnulty/agent-coordination`. Pinned goal SHA256 matches
`aabdd288e968fb689dfdd351ab4ee385551fe81d16343ec6803c491e4dd673bf`.
The same owning checkout was reconciled at92b1ab7 with the in-progress changes.
No active Python dependency cleanup blocker was established. Keep Rust, Tauri,
the Core7.6+ contract and fail-closed retired stubs. No dependencies were added.
The packet adds no native authority or acceptance clearance.

## Preserved boundaries

VM107 only: UUID `e5cecc90-35c2-4831-bf9c-424be23f7d4e`, MAC
`CC:34:21:B8:5A:31`, IP192.168.1.174. Never touch VM106 or restore VM203.
Normal HTTPS certificate `BC14DCC4E37F83161EBB55AF8624E36A79E19256` remains
required. No TLS bypass, legacy fallback, credential/key expansion, foreign lease
adoption, automatic dispatch retry or merge. Keep migration release draft.

Never replay/recover completed historical runs `msix-1792704525359564000` or
`msix-bounded-1792816990610240800`. Their former-runtime evidence does not prove
migrated acceptance. See docs/MSIX-EXECUTION.md for those retained records.
