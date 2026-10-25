# Working state

Updated 2026-10-25. Owning checkout `C:\aiw\app-isolation-workbench`, branch
`codex/new-vm-handoff-20261021`, PR103 open and unmerged. Start with
`scripts/work-status.ps1`. This file is a pointer, not execution authority.

## Current milestone

Nathan approved the exact A–D scope in
`docs/handoffs/2026-10-24-powershell76/SETUP-AND-ACCEPTANCE.md`, followed by a
one-time Windows PowerShell 5.1 remoting bootstrap exception. That bootstrap is
complete. All subsequent observation, setup and validation use Core7.6.7 only.
Both VM203 and VM107 have the verified Microsoft machine runtime. VM107's
restricted PowerShell.7.6 endpoint passes actual WSMan host/loaded engine,
independent worker and same-session copy proof over normal HTTPS. The default
Microsoft.PowerShell endpoint is disabled. Native setup evidence was exported
before removing all seven temporary setup tasks and the exact setup directory.
The production clean check passes; no application trial has run in this milestone.

The new cold snapshot `aiw-msix-worker107-pwsh76-clean-r1` now exists, with OS,
EFI and TPM, no RAM and NIC down. Its observed configuration SHA256 is
`4d0e51d5c13d8ad77c200c5c7a7981cabb96611b761ff1770895b0221037dbb8`.
Historical snapshots remain intact. Cold rollback/start of all three volumes and
post-restore Core HTTPS, disabled legacy endpoint and production clean proof
passed. The fixed provider source now selects the new snapshot. Exact provider
deployment, a fresh verified package and separate full-app/bounded acceptance
remain required before A–D completion.
Read NATIVE-SETUP-PROGRESS.md for observations and limitations.

The current source fixes an async proof success-stream leak and adds its exact
child-observer regression. Fresh bounded acceptance is an ignored opt-in native
harness, never a claim of completed execution. Independent source review is
clear; automated checks, package evidence and native acceptance remain separate.

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
