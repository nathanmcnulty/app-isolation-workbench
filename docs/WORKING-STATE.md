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
passed. Exact reviewed provider bytes are deployed and their new snapshot/config
hashes verified by the existing restricted SSH probe, with no lease. A fresh
verified package and separate full-app/bounded acceptance remain required.
Read NATIVE-SETUP-PROGRESS.md for observations and limitations.

The current source retains the async proof success-stream and isolated queued-task
regressions. Objective0007 repairs raw collection's Win32 path spelling for held
directory opens and stream enumeration. An inert Core7.6.7 probe observed an
existing 270-character file fail stream enumeration without an extended prefix
and succeed with it. The actual collector's focused offline regression passed
after independent Astra review, including a forced long path, exact named-stream
rejection/removal, byte/hash export and the existing source/custody negatives.
Detailed evidence and preserved failed attempts remain private; consult the AIW
worker checkpoint for objective0007 in the coordination ledger.
Use separate rebuilt-source qualification and fresh package verification receipts
bound to the final commit; the focused disk-input test and historical hosted CI
do not establish either. Objective0007 grants no native/live execution authority.
The opt-in native harness remains unexecuted in this offline milestone.

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
